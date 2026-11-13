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

// fakeCtl records the commands; launchctl print and systemctl is-active say
// whether Homebrew's service is loaded, bootstrap and enable return start.
func fakeCtl(t *testing.T, brewLoaded bool, start error) *[][]string {
	var got [][]string
	old := serviceCtl
	serviceCtl = func(args ...string) error {
		got = append(got, args)
		switch {
		case slices.Contains(args, "print") || slices.Contains(args, "is-active"):
			if !brewLoaded {
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
	// Without --state, run's default is left to run.
	os.Remove(file)
	if err := serviceInstall("darwin", config, defaultState(), false); err != nil {
		t.Fatal(err)
	}
	if s := plistStrings(t, file); slices.Contains(s, "--state") || s[len(s)-1] != filepath.Join(home, ".reqcove/service.log") {
		t.Errorf("default state: %q", s)
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
		check("newline", filepath.Join(nl, "config"), "line break", false, nil)
		// Starting fails: the file goes, so install can be tried again.
		check("start fails", config, "no session", false, errors.New("no session"))
	}
}

func TestServiceUninstall(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		_, config := serviceHome(t, "cfg")
		got := fakeCtl(t, false, nil)
		if err := serviceUninstall(goos); err == nil || !strings.Contains(err.Error(), "not installed") {
			t.Errorf("%s none: %v", goos, err)
		}
		if err := serviceInstall(goos, config, defaultState(), false); err != nil {
			t.Fatal(err)
		}
		file, _ := serviceFile(goos)
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

// launchd makes service.log before the first run: the state is still taken.
func TestOpenStateServiceLog(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, serviceLog), nil, 0o644)
	unlock, err := openState(dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}
