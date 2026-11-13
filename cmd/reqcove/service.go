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
	"strconv"
	"strings"
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
	const use = "reqcove service install [--config FILE] [--state DIR] | service uninstall"
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
	given := false
	fls.Visit(func(f *flag.Flag) { given = given || f.Name == "state" })
	switch {
	case sub == "install":
		return serviceInstall(runtime.GOOS, *config, *state, given)
	case sub == "uninstall" && fls.NFlag() == 0:
		return serviceUninstall(runtime.GOOS)
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

func serviceInstall(goos, config, state string, stateGiven bool) error {
	file, err := serviceFile(goos)
	if err != nil {
		return err
	}
	if _, err := os.Stat(file); err == nil {
		return fmt.Errorf("installed already (%s): reqcove service uninstall, then install again", file)
	}
	if err := brewService(goos); err != nil {
		return err
	}
	if config, err = filepath.Abs(config); err != nil {
		return err
	}
	if err := checkConfig(config); err != nil {
		return err
	}
	if state, err = filepath.Abs(state); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return err
	}
	argv := []string{exe, "run", "--config", config}
	if stateGiven {
		argv = append(argv, "--state", state)
	}
	path, uvx := servicePath()
	for _, a := range append(argv, path) {
		if strings.ContainsAny(a, "\n\r") { // would end a unit's line
			return fmt.Errorf("a path with a line break: %q", a)
		}
	}
	var body string
	var start [][]string
	uid := strconv.Itoa(os.Getuid())
	if goos == "darwin" {
		// launchd opens the log before run starts, but makes no directory.
		if err := os.MkdirAll(state, 0o700); err != nil {
			return err
		}
		body = launchAgent(argv, path, filepath.Join(state, serviceLog))
		start = [][]string{{"launchctl", "bootstrap", "gui/" + uid, file}}
	} else {
		body = systemdUnit(argv, path)
		start = [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", "--now", serviceUnit}}
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
		return err
	}
	for _, c := range start {
		if err := serviceCtl(c...); err != nil {
			os.Remove(file) // so that install can be tried again
			return err
		}
	}
	var cmd []string
	for _, a := range argv {
		cmd = append(cmd, shellWord(a))
	}
	fmt.Printf("installed %s: it runs %s now and at each login\n", file, strings.Join(cmd, " "))
	if goos == "darwin" {
		fmt.Printf("the log: %s\n", filepath.Join(state, serviceLog))
	} else {
		fmt.Println("the log: journalctl --user -u reqcove")
	}
	if !uvx {
		fmt.Println("note: uvx is not on this PATH; give --uvx /full/path/uvx in the config file, or install uv")
	}
	fmt.Printf("then: %s (the login URL, the first time, in your terminal); %s; reqcove service uninstall stops and removes it\n", withState("reqcove links", state), withState("reqcove status", state))
	return nil
}

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
// there, so that the service does not end at its first start.
func checkConfig(path string) error {
	words, _, err := readConfig(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("no %s: write run's flags in it, one a line, such as --device iphone and --allow-hosts api.example.com; then chmod 600 %s (mkdir -p %s first)", path, shellWord(path), shellWord(filepath.Dir(path)))
	} else if err != nil {
		return err
	}
	for _, w := range words {
		name, _, _ := strings.Cut(strings.TrimLeft(w, "-"), "=")
		if why, ok := configOnlyOnCommandLine[name]; ok && strings.HasPrefix(w, "-") {
			return fmt.Errorf("--config %s: --%s only on the command line (%s)", path, name, why)
		}
	}
	return nil
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
	return strings.Join(dirs, ":"), err == nil
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
