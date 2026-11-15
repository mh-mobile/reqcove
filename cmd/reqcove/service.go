package main

import (
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// `reqcove service install`: run at login without Homebrew, as `brew services`
// does with the formula: a LaunchAgent (macOS) or a systemd user unit (Linux)
// running `run --config FILE`, with no keep-alive (a missing or refused file
// ends it once, not in a loop).

const (
	serviceLabel = "io.github.mh-mobile.reqcove" // launchd's label (XPC_SERVICE_NAME under it)
	serviceUnit  = "reqcove.service"             // systemd's; the unit sets REQCOVE_SERVICE to it
	serviceLog   = "service.log"                 // macOS: in the state directory
)

// Homebrew's: launchd's labels (status.go), and its systemd units on Linux
// (from reading Homebrew, not tried).
var (
	brewLabels = []string{"sh.brew.reqcove", "homebrew.mxcl.reqcove"}
	brewUnits  = []string{"sh.brew.reqcove.service", "homebrew.reqcove.service"}
)

// serviceCtl runs launchctl or systemctl (args[0]); tests replace it, so they
// never reach the real launchd or systemd.
var serviceCtl = func(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// defaultConfig is the --config file service install runs with by default.
func defaultConfig() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "reqcove", "config")
}

func service(_ context.Context, args []string) error {
	const use = "reqcove service install [--config FILE] [--state DIR] | service restart | service uninstall"
	fls := flag.NewFlagSet("service", flag.ExitOnError)
	config := fls.String("config", defaultConfig(), "the `FILE` of run's flags, one a line, yours and readable by you only (chmod 600)")
	state := fls.String("state", defaultState(), "state directory")
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	if err := parseFlags(fls, args); err != nil {
		return err
	}
	given, configGiven := false, false
	fls.Visit(func(f *flag.Flag) {
		given = given || f.Name == "state"
		configGiven = configGiven || f.Name == "config"
	})
	switch {
	case sub == "install":
		c, s, g := installArgs(runtime.GOOS, *config, configGiven, *state, given)
		return serviceInstall(runtime.GOOS, c, s, g)
	case sub == "uninstall" && fls.NFlag() == 0:
		return serviceUninstall(runtime.GOOS)
	case sub == "restart" && fls.NFlag() == 0:
		return serviceRestart(runtime.GOOS)
	}
	return fmt.Errorf("usage: %s", use)
}

// serviceFile is where the LaunchAgent or the unit goes.
func serviceFile(goos string) (string, error) {
	home, err := os.UserHomeDir()
	switch {
	case err != nil:
		return "", err
	case goos == "darwin":
		return filepath.Join(home, "Library", "LaunchAgents", serviceLabel+".plist"), nil
	case goos == "linux":
		return filepath.Join(home, ".config", "systemd", "user", serviceUnit), nil
	}
	return "", fmt.Errorf("reqcove service: macOS (launchd) and Linux (systemd) only, not %s", goos)
}

// installArgs are install's --config and --state: those given, else those of
// the service installed already (installing again re-points it at this
// binary and changes nothing else), else the file a bare run reads.
func installArgs(goos, config string, configGiven bool, state string, stateGiven bool) (string, string, bool) {
	var old []string
	if file, err := serviceFile(goos); err == nil {
		old = serviceArgv(goos, file)
	}
	for i := 1; i+1 < len(old); i++ {
		switch {
		case old[i] == "--config" && !configGiven:
			config, configGiven = old[i+1], true
		case old[i] == "--state" && !stateGiven:
			state, stateGiven = old[i+1], true
		}
	}
	if !configGiven {
		if c, _ := bareConfig(); c != "" {
			config = c
		}
	}
	return config, state, stateGiven
}

func serviceInstall(goos, config, state string, stateGiven bool) error {
	file, err := serviceFile(goos)
	if err != nil {
		return err
	}
	_, err = os.Stat(file)
	again := err == nil // installed already: re-pointed and restarted below
	was := ""
	if old := serviceArgv(goos, file); len(old) > 0 {
		was = old[0]
	}
	exe, err := selfExe()
	if err != nil {
		return err
	}
	// Homebrew's binary is under a Cellar directory that brew upgrade deletes:
	// the service runs its opt path instead, which follows the upgrades.
	brew := brewPrefix()
	if brew != "" {
		exe = brewOpt(brew)
		if _, err := os.Stat(exe); err != nil {
			return fmt.Errorf("this reqcove is Homebrew's, but %s is not there (%v): brew reinstall reqcove, or use brew services: reqcove setup (it writes %s), then brew services start reqcove", exe, err, shellWord(setupConfig(brew)))
		}
	}
	if err := brewService(goos); err != nil {
		return err
	}
	if config, err = filepath.Abs(config); err != nil {
		return err
	}
	fileState, err := checkConfig(config)
	if err != nil {
		return err
	}
	if !stateGiven && fileState != "" { // run takes it from the file: the log and the hints too
		if !filepath.IsAbs(fileState) {
			return fmt.Errorf("--config %s: --state %s: give it in full or from ~/ (a service does not start in this directory)", config, fileState)
		}
		state = fileState
	}
	if state, err = filepath.Abs(state); err != nil {
		return err
	}
	argv := []string{exe, "run", "--config", config}
	if stateGiven {
		argv = append(argv, "--state", state)
	}
	path, uvx := servicePath()
	if err := serviceArgs(goos, argv, path); err != nil {
		return err
	}
	// Refused as run would refuse it at each start; made reqcove's now, as
	// launchd opens the log in it (making no directory) before run starts.
	if err := claimState(state); err != nil {
		return err
	}
	var body string
	var start [][]string
	uid := strconv.Itoa(os.Getuid())
	if goos == "darwin" {
		if err := privateLog(filepath.Join(state, serviceLog)); err != nil {
			return err
		}
		body = launchAgent(argv, path, filepath.Join(state, serviceLog))
		start = [][]string{{"launchctl", "bootstrap", "gui/" + uid, file}}
	} else {
		body = systemdUnit(argv, path)
		start = [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", "--now", serviceUnit}}
		if again {
			start = append(start, []string{"systemctl", "--user", "restart", serviceUnit})
		}
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		return err
	}
	if again && goos == "darwin" {
		// launchd reads the file only as it loads it: out, then in again. Not
		// loaded (stopped until the next login): nothing to stop. bootout can
		// return before the old run lets go of the state's lock, which the
		// new one would then fail to take: waited for, a while.
		if serviceCtl("launchctl", "bootout", "gui/"+uid+"/"+serviceLabel) == nil && !waitStateFree(state, stateFreeWait) {
			fmt.Printf("note: %s is still in use %v after the old run was stopped (a run in a terminal?): the service may fail to start; %s shows it\n", state, stateFreeWait, withState(selfCmd()+" status", state))
		}
	}
	for _, c := range start {
		if err := serviceCtl(c...); err != nil {
			if again { // the old one is stopped already: the new file stays
				return fmt.Errorf("%w: %s is written, not started: %s service install again, or log out and in", err, file, selfCmd())
			}
			os.Remove(file) // so that install can be tried again
			return err
		}
	}
	var cmd []string
	for _, a := range argv {
		cmd = append(cmd, shellWord(a))
	}
	if again {
		fmt.Printf("installed again %s: it ran %s; now it runs %s, restarted now (its records started empty) and at each login\n", file, orDash(shellWord(was)), strings.Join(cmd, " "))
	} else {
		fmt.Printf("installed %s: it runs %s now and at each login\n", file, strings.Join(cmd, " "))
	}
	if brew != "" {
		fmt.Printf("this reqcove is Homebrew's: the service runs %s, which brew upgrade points at the new version; after an upgrade, %s service restart\n", shellWord(exe), selfCmd())
	}
	if goos == "darwin" {
		fmt.Printf("the log: %s\n", filepath.Join(state, serviceLog))
	} else {
		fmt.Println("the log: journalctl --user -u reqcove")
	}
	if !uvx {
		fmt.Println("note: uvx is not on this PATH; give --uvx /full/path/uvx in the config file, or install uv")
	}
	rc := selfCmd()
	fmt.Printf("then: %s (the login URL, the first time, in your terminal); %s; %[3]s service restart after it ended; %[3]s service uninstall stops and removes it\n", withState(rc+" links", state), withState(rc+" status", state), rc)
	return nil
}

// serviceArgs refuses what the files cannot carry: a control character
// (a line break would end a unit's line) or text that is not UTF-8 (the plist
// would get U+FFFD in its place), and on Linux a $ in the binary's path
// (systemd neither expands nor unescapes it there).
func serviceArgs(goos string, argv []string, path string) error {
	for _, a := range append(argv, path) {
		if !utf8.ValidString(a) || strings.ContainsFunc(a, unicode.IsControl) {
			return fmt.Errorf("a path with a control character, or not UTF-8: %q", a)
		}
	}
	if goos == "linux" && strings.Contains(argv[0], "$") {
		return fmt.Errorf("systemd cannot run a binary whose path has a $ (%s): move it", argv[0])
	}
	return nil
}

// privateLog makes a service's log, or makes it 0600 if it is there: launchd
// would make it 0644 (its umask), then append to it.
func privateLog(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	return errors.Join(f.Chmod(0o600), f.Close())
}

// brewLog is brew services' log for reqcove (the formula's log_path).
func brewLog(brew string) string { return filepath.Join(brew, "var", "log", "reqcove.log") }

// brewService refuses when Homebrew's service for reqcove is there: two
// services would fight over the state directory.
func brewService(goos string) error {
	home, _ := os.UserHomeDir()
	uid := strconv.Itoa(os.Getuid())
	if goos == "darwin" {
		for _, l := range brewLabels {
			_, err := os.Stat(filepath.Join(home, "Library", "LaunchAgents", l+".plist"))
			if err == nil || serviceCtl("launchctl", "print", "gui/"+uid+"/"+l) == nil {
				return fmt.Errorf("the service of Homebrew's formula (%s) is there: keep to brew services, or brew services stop reqcove first", l)
			}
		}
		return nil
	}
	for _, u := range brewUnits {
		_, err := os.Stat(filepath.Join(home, ".config", "systemd", "user", u))
		if err == nil || serviceCtl("systemctl", "--user", "is-active", "--quiet", u) == nil {
			return fmt.Errorf("the service of Homebrew's formula (%s) is there: keep to brew services, or brew services stop reqcove first", u)
		}
	}
	return nil
}

// checkConfig reads the file as run will, and refuses the flags run refuses
// there, so that the service does not end at its first start. It returns the
// file's --state, if any (the last one, as run takes it).
func checkConfig(path string) (state string, err error) {
	words, _, err := readConfig(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("no %s: write run's flags in it, one a line, such as --device iphone and --allow-hosts api.example.com; then chmod 600 %s (mkdir -p %s first)", path, shellWord(path), shellWord(filepath.Dir(path)))
	} else if err != nil {
		return "", err
	}
	for i, w := range words {
		if !strings.HasPrefix(w, "-") {
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(w, "-"), "=")
		if why, ok := configOnlyOnCommandLine[name]; ok {
			return "", fmt.Errorf("--config %s: --%s only on the command line (%s)", path, name, why)
		}
		if name == "state" {
			if !hasValue && i+1 < len(words) {
				value = words[i+1]
			}
			state = value
		}
	}
	return state, nil
}

// servicePath is the PATH the service gets, so that run finds uvx: uvx's
// directory here first, then where uv's installer and Homebrew put it.
func servicePath() (string, bool) {
	home, _ := os.UserHomeDir()
	dirs := []string{filepath.Join(home, ".local", "bin"), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"}
	uvx, err := exec.LookPath("uvx")
	if err == nil {
		if abs, err := filepath.Abs(uvx); err == nil {
			dirs = append([]string{filepath.Dir(abs)}, dirs...)
		}
	}
	var once []string // uvx in one of the others: listed once, first
	for _, d := range dirs {
		if !slices.Contains(once, d) {
			once = append(once, d)
		}
	}
	return strings.Join(once, ":"), err == nil
}

func xmlText(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func launchAgent(argv []string, path, log string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + serviceLabel + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, a := range argv {
		b.WriteString("\t\t<string>" + xmlText(a) + "</string>\n")
	}
	b.WriteString(`	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>` + xmlText(path) + `</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>StandardOutPath</key>
	<string>` + xmlText(log) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlText(log) + `</string>
</dict>
</plist>
`)
	return b.String()
}

// unitWord quotes s for a unit's line: % starts a specifier (%%), and in
// ExecStart $ starts a variable ($$).
func unitWord(s string, exec bool) string {
	s = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(s)
	if exec {
		s = strings.ReplaceAll(s, "$", "$$")
	}
	return `"` + s + `"`
}

func systemdUnit(argv []string, path string) string {
	var words []string
	for _, a := range argv {
		words = append(words, unitWord(a, true))
	}
	return `# Written by reqcove service install; reqcove service uninstall removes it.
[Unit]
Description=Reqcove

[Service]
ExecStart=` + strings.Join(words, " ") + `
Environment=` + unitWord("PATH="+path, false) + `
Environment=REQCOVE_SERVICE=` + serviceUnit + `

[Install]
WantedBy=default.target
`
}

func serviceUninstall(goos string) error {
	file, err := serviceFile(goos)
	if err != nil {
		return err
	}
	if _, err := os.Stat(file); err != nil {
		// Its file removed by hand: launchd may still have it.
		if goos == "darwin" && serviceCtl("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+serviceLabel) == nil {
			fmt.Printf("stopped %s (its file %s was gone)\n", serviceLabel, file)
			return nil
		}
		return fmt.Errorf("not installed (no %s)", file)
	}
	if goos == "darwin" {
		if err := serviceCtl("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+serviceLabel); err != nil {
			fmt.Printf("not running (%v)\n", err)
		}
		if err := os.Remove(file); err != nil {
			return err
		}
	} else {
		if err := serviceCtl("systemctl", "--user", "disable", "--now", serviceUnit); err != nil {
			return err
		}
		if err := os.Remove(file); err != nil {
			return err
		}
		if err := serviceCtl("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
	}
	fmt.Printf("stopped and removed %s\n", file)
	return nil
}

// serviceRestart starts the service again (it is not restarted when it ends).
func serviceRestart(goos string) error {
	file, err := serviceFile(goos)
	if err != nil {
		return err
	}
	if _, err := os.Stat(file); err != nil {
		return fmt.Errorf("not installed (no %s): reqcove service install", file)
	}
	if goos == "darwin" {
		// Stopped until the next login (launchctl bootout): launchd no longer
		// has the job, so kickstart cannot find it; loading it starts it
		// (RunAtLoad).
		domain := "gui/" + strconv.Itoa(os.Getuid())
		if serviceCtl("launchctl", "print", domain+"/"+serviceLabel) != nil {
			return serviceCtl("launchctl", "bootstrap", domain, file)
		}
		return serviceCtl("launchctl", "kickstart", "-k", domain+"/"+serviceLabel)
	}
	return serviceCtl("systemctl", "--user", "restart", serviceUnit)
}

// brewOpt is Homebrew's stable path to its reqcove, which brew upgrade
// points at the new version.
func brewOpt(brew string) string { return filepath.Join(brew, "opt", "reqcove", "bin", "reqcove") }

// installedService is a service file for reqcove found in this home: ours
// (reqcove service install's) or Homebrew's.
type installedService struct {
	name, file string
	ours       bool
}

// installedServices lists the service files for reqcove, ours first. Files
// only: status never asks launchctl or systemctl.
func installedServices(goos string) []installedService {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir, names := filepath.Join(home, ".config", "systemd", "user"), append([]string{serviceUnit}, brewUnits...)
	if goos == "darwin" {
		dir, names = filepath.Join(home, "Library", "LaunchAgents"), append([]string{serviceLabel}, brewLabels...)
	}
	var out []installedService
	for i, n := range names {
		file := filepath.Join(dir, n)
		if goos == "darwin" {
			file += ".plist"
		}
		if _, err := os.Stat(file); err == nil {
			out = append(out, installedService{name: n, file: file, ours: i == 0})
		}
	}
	return out
}

// serviceWarnings says what is wrong with the services installed: two at
// once, ours running a binary that is gone or, when self is given (this
// binary, its symlinks resolved), another one.
func serviceWarnings(goos string, svcs []installedService, self string) []string {
	var out []string
	if len(svcs) > 1 {
		var files []string
		for _, s := range svcs {
			files = append(files, s.file)
		}
		out = append(out, fmt.Sprintf("two services for reqcove are installed (%s): at login both start, and the second finds the state in use. Keep one: reqcove service uninstall removes reqcove's own, brew services stop reqcove Homebrew's", strings.Join(files, ", ")))
	}
	for _, s := range svcs {
		argv := serviceArgv(goos, s.file)
		if !s.ours || len(argv) == 0 {
			continue
		}
		bin, err := filepath.EvalSymlinks(argv[0])
		switch {
		case err != nil:
			out = append(out, fmt.Sprintf("%s runs %s, which is gone (brew upgrade removes an old version's files): it does not start at the next login; reqcove service install points it at this reqcove (its --config and --state kept)", s.file, argv[0]))
		case self != "" && bin != self:
			out = append(out, fmt.Sprintf("%s runs %s, not this reqcove (%s): reqcove service install points it at this one (its --config and --state kept)", s.file, argv[0], self))
		}
	}
	return out
}

// serviceState is the state directory a service file's run uses: its
// --state, else the default.
func serviceState(goos, file string) string {
	argv := serviceArgv(goos, file)
	for i := 1; i+1 < len(argv); i++ {
		if argv[i] == "--state" {
			return argv[i+1]
		}
	}
	return defaultState()
}

// oursStale: reqcove service install's service runs another binary than
// self, or one that is gone.
func oursStale(goos, self string) bool {
	file, err := serviceFile(goos)
	if err != nil {
		return false
	}
	argv := serviceArgv(goos, file)
	if len(argv) == 0 {
		return false
	}
	bin, err := filepath.EvalSymlinks(argv[0])
	return err != nil || bin != self
}

// serviceArgv is the command a LaunchAgent (ProgramArguments) or a systemd
// unit (ExecStart) runs; nil when the file does not read as one.
func serviceArgv(goos, file string) []string {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	if goos != "darwin" {
		for line := range strings.SplitSeq(string(b), "\n") {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "ExecStart="); ok {
				return unitArgv(rest)
			}
		}
		return nil
	}
	d := xml.NewDecoder(strings.NewReader(string(b)))
	d.Strict = false // the DOCTYPE
	var argv []string
	var text string
	key, inArgs := "", false
	for {
		tok, err := d.Token()
		if err != nil {
			return nil
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			text = ""
			inArgs = inArgs || tok.Name.Local == "array" && key == "ProgramArguments"
		case xml.CharData:
			text += string(tok)
		case xml.EndElement:
			switch {
			case tok.Name.Local == "key":
				key = text
			case inArgs && tok.Name.Local == "string":
				argv = append(argv, text)
			case inArgs && tok.Name.Local == "array":
				return argv
			}
		}
	}
}

// unitArgv splits an ExecStart line as systemd does for the units service
// install writes (unitWord) and Homebrew's (plain words).
func unitArgv(line string) []string {
	var argv []string
	for line = strings.TrimSpace(line); line != ""; line = strings.TrimSpace(line) {
		var w strings.Builder
		if line[0] == '"' {
			i := 1
			for ; i < len(line) && line[i] != '"'; i++ {
				if line[i] == '\\' && i+1 < len(line) {
					i++
				}
				w.WriteByte(line[i])
			}
			line = line[min(i+1, len(line)):]
		} else {
			i := strings.IndexAny(line, " \t")
			if i < 0 {
				i = len(line)
			}
			w.WriteString(line[:i])
			line = line[i:]
		}
		argv = append(argv, strings.NewReplacer("%%", "%", "$$", "$").Replace(w.String()))
	}
	return argv
}

// restartCmd is the command that restarts a run its service started
// (status' service), "" for none.
func restartCmd(service string) string {
	switch {
	case slices.Contains(brewLabels, service) || slices.Contains(brewUnits, service):
		return "brew services restart reqcove"
	case service == serviceLabel || service == serviceUnit:
		return "reqcove service restart"
	}
	return ""
}
