package main

import (
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
)

// No test reaches the real launchd or systemd: one that forgets fakeCtl panics.
func init() {
	serviceCtl = func(args ...string) error { panic("serviceCtl without fakeCtl: " + strings.Join(args, " ")) }
}

// fakeCtl records the commands; launchctl print and bootout and systemctl
// is-active succeed when loaded (Homebrew's service, or ours without its
// file), bootstrap and enable return start.
func fakeCtl(t *testing.T, loaded bool, start error) *[][]string {
	var got [][]string
	old := serviceCtl
	serviceCtl = func(args ...string) error {
		got = append(got, args)
		switch {
		case slices.Contains(args, "print") || slices.Contains(args, "is-active") || slices.Contains(args, "bootout"):
			if !loaded {
				return errors.New("not loaded")
			}
		case slices.Contains(args, "bootstrap") || slices.Contains(args, "enable"):
			return start
		}
		return nil
	}
	t.Cleanup(func() { serviceCtl = old })
	return &got
}

// serviceHome is a HOME with a 0600 config at dir/config and uvx on PATH.
func serviceHome(t *testing.T, dir string) (home, config string) {
	home = t.TempDir()
	t.Setenv("HOME", home)
	bin := filepath.Join(home, "uvbin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "uvx"), []byte("#!/bin/sh\n"), 0o755)
	t.Setenv("PATH", bin)
	config = filepath.Join(home, dir, "config")
	os.MkdirAll(filepath.Dir(config), 0o700)
	if err := os.WriteFile(config, []byte("--device iphone\n--allow-hosts api.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, config
}

func plistStrings(t *testing.T, file string) []string {
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d := xml.NewDecoder(f)
	d.Strict = false // the DOCTYPE
	var out []string
	in := false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return out
		} else if err != nil {
			t.Fatal(err)
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			in = tok.Name.Local == "string"
			if in {
				out = append(out, "")
			}
		case xml.CharData:
			if in {
				out[len(out)-1] += string(tok)
			}
		case xml.EndElement:
			in = false
		}
	}
}

func TestServiceInstallDarwin(t *testing.T) {
	home, config := serviceHome(t, "a & <b> c")
	state := filepath.Join(home, "st ate")
	got := fakeCtl(t, false, nil)
	if err := serviceInstall("darwin", config, state, true); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(home, "Library/LaunchAgents/io.github.mh-mobile.reqcove.plist")
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	log := filepath.Join(state, "service.log")
	path := filepath.Join(home, "uvbin") + ":" + filepath.Join(home, ".local/bin") + ":/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	want := []string{serviceLabel, exe, "run", "--config", config, "--state", state, path, log, log}
	if s := plistStrings(t, file); !slices.Equal(s, want) {
		t.Errorf("plist strings\n got %q\nwant %q", s, want)
	}
	b, _ := os.ReadFile(file)
	if strings.Contains(string(b), "KeepAlive") || !strings.Contains(string(b), "<key>RunAtLoad</key>\n\t<true/>") {
		t.Errorf("plist:\n%s", b)
	}
	if fi, err := os.Stat(state); err != nil || !fi.IsDir() { // launchd makes no directory for the log
		t.Errorf("state: %v", err)
	}
	if fi, err := os.Stat(log); err != nil || fi.Mode().Perm() != 0o600 { // launchd would make it 0644
		t.Errorf("log: %v %v", fi, err)
	}
	uid := strconv.Itoa(os.Getuid())
	wantCmds := [][]string{
		{"launchctl", "print", "gui/" + uid + "/sh.brew.reqcove"},
		{"launchctl", "print", "gui/" + uid + "/homebrew.mxcl.reqcove"},
		{"launchctl", "bootstrap", "gui/" + uid, file},
	}
	if !slices.EqualFunc(*got, wantCmds, slices.Equal) {
		t.Errorf("commands %q", *got)
	}
	// Installed: once only.
	if err := serviceInstall("darwin", config, state, true); err == nil || !strings.Contains(err.Error(), "installed already") {
		t.Errorf("again: %v", err)
	}
	// Installed again over a log made 0644 (an earlier install's, by launchd): 0600, kept.
	os.Remove(file)
	os.WriteFile(log, []byte("earlier\n"), 0o644)
	os.Chmod(log, 0o644)
	if err := serviceInstall("darwin", config, state, true); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(log); err != nil || string(b) != "earlier\n" {
		t.Errorf("log: %q %v", b, err)
	}
	if fi, err := os.Stat(log); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("log: %v %v", fi, err)
	}
	// Without --state, run's default is left to run.
	os.Remove(file)
	if err := serviceInstall("darwin", config, defaultState(), false); err != nil {
		t.Fatal(err)
	}
	if s := plistStrings(t, file); slices.Contains(s, "--state") || s[len(s)-1] != filepath.Join(home, ".reqcove/service.log") {
		t.Errorf("default state: %q", s)
	}
}

// The commands install prints name reqcove when PATH finds this binary,
// else this binary's path (none on PATH, or another file).
func TestServiceInstallPrintsBinary(t *testing.T) {
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	other := t.TempDir()
	os.WriteFile(filepath.Join(other, "reqcove"), []byte("#!/bin/sh\n"), 0o755)
	for _, c := range []struct {
		path, self string
	}{{selfOnPath(t, t.TempDir()), "reqcove"}, {t.TempDir(), shellWord(exe)}, {other, shellWord(exe)}} {
		_, config := serviceHome(t, "cfg")
		t.Setenv("PATH", c.path)
		fakeCtl(t, false, nil)
		out := captureStdout(t, func() error { return serviceInstall("linux", config, defaultState(), false) })
		if want := "then: " + c.self + " links (the login URL, the first time, in your terminal); " + c.self + " status; " + c.self + " service restart after it ended; " + c.self + " service uninstall"; !strings.Contains(out, want) {
			t.Errorf("PATH %s: no %q in\n%s", c.path, want, out)
		}
	}
}

func TestServiceInstallLinux(t *testing.T) {
	home, config := serviceHome(t, `50% "q" $x \y`)
	got := fakeCtl(t, false, nil)
	if err := serviceInstall("linux", config, defaultState(), false); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(home, ".config/systemd/user/reqcove.service")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	q := func(s string) string { // as systemd reads it back: \ " % $ escaped
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$").Replace(s) + `"`
	}
	execStart := "ExecStart=" + q(exe) + ` "run" "--config" ` + q(config) + "\n"
	if !strings.Contains(execStart, `50%% \"q\" $$x \\y`) {
		t.Fatalf("the test's own quoting: %s", execStart)
	}
	env := `Environment="PATH=` + filepath.Join(home, "uvbin") + ":" + filepath.Join(home, ".local/bin") + `:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"` + "\n"
	for _, line := range []string{execStart, env, "Environment=REQCOVE_SERVICE=reqcove.service\n", "WantedBy=default.target\n"} {
		if !strings.Contains(string(b), line) {
			t.Errorf("no %q in\n%s", line, b)
		}
	}
	if strings.Contains(string(b), "Restart") {
		t.Errorf("restarts:\n%s", b)
	}
	wantCmds := [][]string{
		{"systemctl", "--user", "is-active", "--quiet", "sh.brew.reqcove.service"},
		{"systemctl", "--user", "is-active", "--quiet", "homebrew.reqcove.service"},
		{"systemctl", "--user", "daemon-reload"},
		{"systemctl", "--user", "enable", "--now", "reqcove.service"},
	}
	if !slices.EqualFunc(*got, wantCmds, slices.Equal) {
		t.Errorf("commands %q", *got)
	}
}

func TestServiceInstallRefuses(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		home, config := serviceHome(t, "cfg")
		brewFile := filepath.Join(home, "Library/LaunchAgents/sh.brew.reqcove.plist")
		if goos == "linux" {
			brewFile = filepath.Join(home, ".config/systemd/user/homebrew.reqcove.service")
		}
		ours, _ := serviceFile(goos)
		check := func(what, config, want string, brewLoaded bool, start error) {
			t.Helper()
			got := fakeCtl(t, brewLoaded, start)
			err := serviceInstall(goos, config, defaultState(), false)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s %s: %v", goos, what, err)
			}
			if _, err := os.Stat(ours); err == nil {
				t.Errorf("%s %s: installed", goos, what)
			}
			for _, c := range *got {
				if (slices.Contains(c, "bootstrap") || slices.Contains(c, "enable")) && start == nil {
					t.Errorf("%s %s: %q", goos, what, c)
				}
			}
		}
		// Homebrew's service: its file, or loaded without one (brew services run).
		os.MkdirAll(filepath.Dir(brewFile), 0o755)
		os.WriteFile(brewFile, nil, 0o644)
		check("brew's file", config, "service of Homebrew's formula", false, nil)
		os.Remove(brewFile)
		check("brew's loaded", config, "service of Homebrew's formula", true, nil)
		// The config: missing, others can read it, a flag refused there.
		check("missing config", filepath.Join(home, "cfg/none"), "no "+filepath.Join(home, "cfg/none")+": write run's flags", false, nil)
		os.Chmod(config, 0o644)
		check("0644 config", config, "chmod 600", false, nil)
		os.Chmod(config, 0o600)
		os.WriteFile(config, []byte("--device x\n--lan\n"), 0o600)
		check("--lan", config, "--lan only on the command line", false, nil)
		os.WriteFile(config, []byte("--device x\n"), 0o600)
		// A line break would end a unit's line (and start another).
		nl := filepath.Join(home, "a\nExecStartPre=x")
		os.MkdirAll(nl, 0o700)
		os.WriteFile(filepath.Join(nl, "config"), []byte("--device x\n"), 0o600)
		check("newline", filepath.Join(nl, "config"), "control character", false, nil)
		// A directory with other files, never reqcove's: run would refuse it at each start.
		proj := filepath.Join(home, "proj")
		os.MkdirAll(proj, 0o755)
		os.WriteFile(filepath.Join(proj, "main.go"), nil, 0o644)
		got := fakeCtl(t, false, nil)
		if err := serviceInstall(goos, config, proj, true); err == nil || !strings.Contains(err.Error(), "not a reqcove state directory") || len(*got) > 2 {
			t.Errorf("%s other files: %v %q", goos, err, *got)
		}
		// A relative --state in the file: the service starts elsewhere.
		os.WriteFile(config, []byte("--device x\n--state rel\n"), 0o600)
		check("relative --state", config, "--state rel: give it in full", false, nil)
		os.WriteFile(config, []byte("--device x\n"), 0o600)
		// Starting fails: the file goes, so install can be tried again.
		check("start fails", config, "no session", false, errors.New("no session"))
	}
}

// Homebrew's binary: brew upgrade deletes its Cellar path, so install points
// to brew services (and setup, which writes brew's config), writing nothing
// and asking neither launchctl nor systemctl (the init guard panics).
func TestServiceInstallBrewBinary(t *testing.T) {
	prefix := t.TempDir()
	old := selfExe
	selfExe = func() (string, error) { return prefix + "/Cellar/reqcove/0.7.0/bin/reqcove", nil }
	t.Cleanup(func() { selfExe = old })
	for _, goos := range []string{"darwin", "linux"} {
		home, config := serviceHome(t, "cfg")
		state := filepath.Join(home, "st")
		err := serviceInstall(goos, config, state, true)
		if err == nil || !strings.Contains(err.Error(), "brew services start reqcove") || !strings.Contains(err.Error(), "reqcove setup (it writes "+filepath.Join(prefix, "etc/reqcove/config")) {
			t.Errorf("%s: %v", goos, err)
		}
		ours, _ := serviceFile(goos)
		if exists(ours) || exists(state) {
			t.Errorf("%s: wrote the service file or the state directory", goos)
		}
	}
}

func TestServiceUninstall(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		_, config := serviceHome(t, "cfg")
		fakeCtl(t, false, nil)
		if err := serviceUninstall(goos); err == nil || !strings.Contains(err.Error(), "not installed") {
			t.Errorf("%s none: %v", goos, err)
		}
		if err := serviceRestart(goos); err == nil || !strings.Contains(err.Error(), "not installed") {
			t.Errorf("%s restart none: %v", goos, err)
		}
		// Its file removed by hand, still loaded: launchd's job is stopped.
		fakeCtl(t, true, nil)
		if err := serviceUninstall(goos); (err == nil) != (goos == "darwin") {
			t.Errorf("%s none but loaded: %v", goos, err)
		}
		got := fakeCtl(t, false, nil)
		if err := serviceInstall(goos, config, defaultState(), false); err != nil {
			t.Fatal(err)
		}
		file, _ := serviceFile(goos)
		*got = nil
		if err := serviceRestart(goos); err != nil {
			t.Fatal(err)
		}
		restart := []string{"launchctl", "kickstart", "-k", "gui/" + strconv.Itoa(os.Getuid()) + "/" + serviceLabel}
		if goos == "linux" {
			restart = []string{"systemctl", "--user", "restart", "reqcove.service"}
		}
		if len(*got) != 1 || !slices.Equal((*got)[0], restart) {
			t.Errorf("%s restart: %q", goos, *got)
		}
		*got = nil
		if err := serviceUninstall(goos); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(file); err == nil {
			t.Errorf("%s: still there", goos)
		}
		want := [][]string{{"launchctl", "bootout", "gui/" + strconv.Itoa(os.Getuid()) + "/" + serviceLabel}}
		if goos == "linux" {
			want = [][]string{{"systemctl", "--user", "disable", "--now", "reqcove.service"}, {"systemctl", "--user", "daemon-reload"}}
		}
		if !slices.EqualFunc(*got, want, slices.Equal) {
			t.Errorf("%s commands %q", goos, *got)
		}
	}
}

// status names our service and says how to stop it, per label.
func TestStatusServiceInstalled(t *testing.T) {
	allow, _ := capture.ParseAllowHosts([]string{"api.example.com"})
	t.Setenv("XPC_SERVICE_NAME", serviceLabel)
	if s := statusOut(exitnode.Status{}, map[string]any{}, allow, capture.CA{}, nil).Service; s != serviceLabel {
		t.Errorf("launchd: %q", s)
	}
	t.Setenv("XPC_SERVICE_NAME", "")
	t.Setenv("REQCOVE_SERVICE", serviceUnit)
	if s := statusOut(exitnode.Status{}, map[string]any{}, allow, capture.CA{}, nil).Service; s != serviceUnit {
		t.Errorf("systemd: %q", s)
	}
	for label, want := range map[string]string{
		"sh.brew.reqcove":       "brew services stop reqcove; the log: $(brew --prefix)/var/log/reqcove.log",
		"homebrew.mxcl.reqcove": "brew services stop reqcove",
		serviceLabel:            "reqcove service uninstall stops and removes it; launchctl bootout gui/$(id -u)/io.github.mh-mobile.reqcove stops it until the next login; the log: /st/service.log",
		serviceUnit:             "systemctl --user stop reqcove stops it until it starts again at login; the log: journalctl --user -u reqcove",
	} {
		if h := serviceHint(label, "/st"); !strings.Contains(h, want) {
			t.Errorf("%s: %q", label, h)
		}
	}
}

// install makes the state reqcove's before launchd puts service.log in it;
// a directory holding only a service.log is not taken for one.
func TestServiceState(t *testing.T) {
	stray := t.TempDir()
	os.WriteFile(filepath.Join(stray, serviceLog), nil, 0o644)
	if _, err := openState(stray); err == nil {
		t.Error("a stray service.log taken for a state")
	}
	home, config := serviceHome(t, "cfg")
	os.WriteFile(config, []byte("--device x\n--state ~/svc\n"), 0o600) // run takes the file's --state
	fakeCtl(t, false, nil)
	if err := serviceInstall("darwin", config, defaultState(), false); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(home, "svc")
	s := plistStrings(t, filepath.Join(home, "Library/LaunchAgents", serviceLabel+".plist"))
	if slices.Contains(s, "--state") || s[len(s)-1] != filepath.Join(state, serviceLog) {
		t.Errorf("the file's --state: %q", s)
	}
	os.WriteFile(filepath.Join(state, serviceLog), nil, 0o644) // as launchd does
	unlock, err := openState(state)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}

// What the files cannot carry.
func TestServiceArgs(t *testing.T) {
	for _, c := range []struct {
		goos string
		argv []string
		ok   bool
	}{
		{"darwin", []string{"/a b/&<x>/reqcove", "run", "--config", "/50% $x"}, true},
		{"darwin", []string{"/bin/reqcove", "run", "--config", "/a\xffb"}, false},
		{"darwin", []string{"/bin/reqcove", "run", "--config", "/a\x01b"}, false},
		{"linux", []string{"/bin/reqcove", "run", "--config", "/a\nExecStartPre=x"}, false},
		{"linux", []string{"/opt/$x/reqcove", "run"}, false},
		{"darwin", []string{"/opt/$x/reqcove", "run"}, true},
		{"linux", []string{"/bin/reqcove", "run", "--config", "/$x"}, true},
	} {
		if err := serviceArgs(c.goos, c.argv, "/usr/bin"); (err == nil) != c.ok {
			t.Errorf("%s %q: %v", c.goos, c.argv, err)
		}
	}
}

// uvx in ~/.local/bin (uv's installer) puts it first, once.
func TestServicePathOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := filepath.Join(home, ".local", "bin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "uvx"), []byte("#!/bin/sh\n"), 0o755)
	t.Setenv("PATH", bin)
	if got, found := servicePath(); !found || got != bin+":/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" {
		t.Errorf("%q %v", got, found)
	}
}
