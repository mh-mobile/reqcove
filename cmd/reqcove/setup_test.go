package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// setupHome is a temporary HOME (the real config and skill are never
// touched) with ~/.claude (an agent init finds) and no uvx on PATH; reqcove
// on PATH is this binary.
func setupHome(t *testing.T) (home, config string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", selfOnPath(t, t.TempDir()))
	os.Mkdir(filepath.Join(home, ".claude"), 0o700)
	return home, defaultConfig()
}

// selfOnPath links dir/reqcove to this binary, and returns dir.
func selfOnPath(t *testing.T, dir string) string {
	t.Helper()
	exe, _ := os.Executable()
	if err := os.Symlink(exe, filepath.Join(dir, "reqcove")); err != nil {
		t.Fatal(err)
	}
	return dir
}

// When reqcove on PATH is not this binary (none, or another file), the
// commands printed name this one by its path.
func TestSetupNotOnPath(t *testing.T) {
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	other := t.TempDir()
	os.WriteFile(filepath.Join(other, "reqcove"), []byte("#!/bin/sh\n"), 0o755)
	for _, path := range []string{t.TempDir(), other} {
		_, config := setupHome(t)
		t.Setenv("PATH", path)
		out, err := runSetup(t, "phone\na.example.com\nn\n", config, false)
		if err != nil {
			t.Fatal(err)
		}
		self := shellWord(exe)
		for _, want := range []string{"the command " + self + " mcp", "claude mcp add reqcove -- " + self + " mcp", self + " service install", self + " run (it reads", "`" + self + " links`", "`" + self + " status`", self + " run --lan"} {
			if !strings.Contains(out, want) {
				t.Errorf("PATH %s: no %q in:\n%s", path, want, out)
			}
		}
		if strings.Contains(out, "-- reqcove mcp") || strings.Contains(out, "`reqcove ") || strings.Contains(out, ": reqcove ") {
			t.Errorf("PATH %s: reqcove as a command:\n%s", path, out)
		}
	}
}

func runSetup(t *testing.T, input, config string, brew bool) (string, error) {
	t.Helper()
	var out strings.Builder
	err := setupIn(context.Background(), strings.NewReader(input), &out, config, brew)
	return out.String(), err
}

// Off a terminal (an agent's shell, a pipe): refused before anything is asked or written.
func TestSetupOffTerminal(t *testing.T) {
	_, config := setupHome(t)
	for _, term := range []func(*os.File) bool{func(*os.File) bool { return false }, func(f *os.File) bool { return f == os.Stdin }} {
		terminal = term
		err := setup(context.Background(), nil)
		terminal = isTerminal
		if err == nil || !strings.Contains(err.Error(), "only in a terminal") {
			t.Errorf("off a terminal: %v", err)
		}
	}
	if exists(config) {
		t.Error("off a terminal, a file written")
	}
}

// A full run: '*' and a flag typed as a device asked again, a pasted URL's
// host only, the file 0600 in a 0700 directory, read back as run reads it,
// the skill installed, and the lines to go on with.
func TestSetupWrites(t *testing.T) {
	home, config := setupHome(t)
	in := "--no-redact\n" + // a flag as the device: asked again
		"Taro's \"iPhone\" --no-redact\n" + // quoted as configWords reads it: one value
		"*\n" + // refused here
		"api.example.com,https://*.Example-cdn.com/path?token=secret\n" +
		"y\n"
	out, err := runSetup(t, in, config, false)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Count(out, "Device: ") != 2 || strings.Count(out, "Hosts: ") != 2 || !strings.Contains(out, "only on the command line") {
		t.Errorf("not asked again:\n%s", out)
	}
	// The hosts in their own file beside the config, which the config reads
	// with @: capture save writes it.
	hostsFile := filepath.Join(home, ".config/reqcove/hosts")
	words, _, err := readConfig(config)
	if want := []string{`--device=Taro's "iPhone" --no-redact`, "--allow-hosts=@" + hostsFile}; err != nil || !slices.Equal(words, want) {
		t.Errorf("read back %q, %v; want %q", words, err, want)
	}
	if got, err := hostList("@" + hostsFile); err != nil || got != "api.example.com,*.example-cdn.com" {
		t.Errorf("hosts file: %q, %v", got, err)
	}
	if b, _ := os.ReadFile(hostsFile); !strings.HasPrefix(string(b), hostsHead) || !strings.HasSuffix(string(b), "\napi.example.com\n*.example-cdn.com\n") {
		t.Errorf("hosts file:\n%s", b)
	}
	if fi, err := os.Stat(hostsFile); err != nil || fi.Mode().Perm() != 0o600 || !strings.Contains(out, "the hosts in "+shellWord(hostsFile)) {
		t.Errorf("hosts file: %v\n%s", err, out)
	}
	if _, err := checkConfig(config); err != nil {
		t.Error(err)
	}
	b, _ := os.ReadFile(config)
	if strings.Contains(string(b), "token") || strings.Contains(string(b), "--allow-hosts=\"*") {
		t.Errorf("file:\n%s", b)
	}
	if fi, _ := os.Stat(config); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Dir(config)); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", fi.Mode())
	}
	if ents, _ := os.ReadDir(filepath.Dir(config)); len(ents) != 2 { // config, hosts
		t.Errorf("left behind: %v", ents)
	}
	if !exists(filepath.Join(home, ".claude/skills/reqcove/SKILL.md")) || !strings.Contains(out, "installed ~/.claude/skills/reqcove/SKILL.md") {
		t.Errorf("no skill:\n%s", out)
	}
	for _, want := range []string{
		"not found: install it (brew install uv",
		"claude mcp add reqcove -- reqcove mcp",
		"in a terminal: reqcove run (it reads " + shellWord(config),
		"or to start it at login, in the background: reqcove service install",
		"`reqcove links` prints the login URL",
		"reqcove capture add HOST (or remove, set); reqcove capture save keeps them for the next start, in " + shellWord(setupHosts(config)),
		"edit " + shellWord(setupHosts(config)) + " or " + shellWord(config) + ", then restart it (Ctrl-C and run it again, or reqcove service restart): a restart empties the records",
		"--lan is not kept in a config file",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "brew services") {
		t.Errorf("brew without Homebrew:\n%s", out)
	}
}

// An existing file is shown and kept unless the answer is yes; then replaced
// whole, the old one kept as .old. No hosts: the --allow-hosts line stays a
// comment.
func TestSetupExisting(t *testing.T) {
	home, config := setupHome(t)
	os.MkdirAll(filepath.Dir(config), 0o700)
	mine := "--device mine\n--allow-hosts mine.example.com\n--rules ~/rules.yaml\n"
	os.WriteFile(config, []byte(mine), 0o600)
	for _, in := range []string{"\nn\n", "no\nno\n"} { // kept; the skill declined
		out, err := runSetup(t, in, config, false)
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(config); string(b) != mine || !strings.Contains(out, "| --device mine") || !strings.Contains(out, "kept") || exists(config+".old") {
			t.Errorf("%q: file %q\n%s", in, b, out)
		}
		if exists(filepath.Join(home, ".claude/skills")) {
			t.Errorf("%q: skill installed when declined", in)
		}
	}
	out, err := runSetup(t, "y\nphone\n\nn\n", config, false)
	if err != nil {
		t.Fatal(err)
	}
	words, _, err := readConfig(config)
	if err != nil || !slices.Equal(words, []string{"--device=phone"}) {
		t.Errorf("replaced: %q, %v\n%s", words, err, out)
	}
	if fi, _ := os.Stat(config); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	// The old one kept beside it, 0600, and said so.
	if b, _ := os.ReadFile(config + ".old"); string(b) != mine || !strings.Contains(out, "the old one: "+shellWord(config+".old")) {
		t.Errorf("old: %q\n%s", b, out)
	}
	if fi, err := os.Stat(config + ".old"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("old: %v", err)
	}
	// Not a plain file (a FIFO would hang a read): kept, nothing asked about it.
	_, config = setupHome(t)
	os.MkdirAll(filepath.Dir(config), 0o700)
	if err := syscall.Mkfifo(config, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runSetup(t, "n\n", config, false)
	if err != nil || !strings.Contains(out, "not a plain file): kept") || strings.Contains(out, "Device: ") {
		t.Errorf("fifo: %v\n%s", err, out)
	}
}

// Installed with Homebrew: the formula's own file, which brew services reads.
func TestSetupBrew(t *testing.T) {
	setupHome(t)
	prefix := t.TempDir()
	config := setupConfig(prefix)
	if config != filepath.Join(prefix, "etc/reqcove/config") || setupConfig("") != defaultConfig() {
		t.Fatalf("config: %s", config)
	}
	out, err := runSetup(t, "phone\na.example.com\nn\n", config, true)
	if err != nil {
		t.Fatal(err)
	}
	if words, _, err := readConfig(config); err != nil || len(words) != 2 {
		t.Errorf("brew's file: %q, %v", words, err)
	}
	for _, want := range []string{"brew services start reqcove", "reqcove run --config " + shellWord(config)} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "service install") || exists(defaultConfig()) {
		t.Errorf("service install's file under Homebrew:\n%s", out)
	}
	// Skipped: no file, the command line form, nothing else asked about the file.
	config = setupConfig(t.TempDir())
	out, err = runSetup(t, "\nn\n", config, true)
	if err != nil || exists(config) || !strings.Contains(out, "reqcove run --device NAME --allow-hosts HOSTS") || strings.Contains(out, "Hosts: ") {
		t.Errorf("skipped: %v, %v\n%s", err, exists(config), out)
	}
}

// setup's last lines with Homebrew: the terminal first, bare when a bare run
// reads that file, else with --config (a ~/.config/reqcove/config left there
// comes first); then the start at login; then changes while it runs.
func TestSetupStartLines(t *testing.T) {
	setupHome(t)
	prefix := t.TempDir()
	old := selfExe
	selfExe = func() (string, error) { return prefix + "/Cellar/reqcove/1.1.0/bin/reqcove", nil }
	t.Cleanup(func() { selfExe = old })
	config := setupConfig(prefix)
	rc := selfCmd()
	out, err := runSetup(t, "phone\na.example.com\nn\n", config, true)
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(out, "4. Start it")
	want := []string{
		"in a terminal: " + rc + " run (it reads " + shellWord(config) + "; Ctrl-C stops it)",
		"or to start it at login, in the background: brew services start reqcove",
		"Then `" + rc + " links`",
		rc + " capture add HOST (or remove, set); " + rc + " capture save keeps them for the next start, in " + shellWord(setupHosts(config)),
		"edit " + shellWord(setupHosts(config)) + " or " + shellWord(config) + ", then restart it (Ctrl-C and run it again, or brew services restart reqcove): a restart empties the records.\n",
	}
	at := start
	for _, w := range want { // in this order, the last at the end
		i := strings.Index(out[at:], w)
		if start < 0 || i < 0 {
			t.Fatalf("no %q after the earlier lines in:\n%s", w, out)
		}
		at += i
	}
	if !strings.HasSuffix(out, want[len(want)-1]) || strings.Contains(out, "reload") {
		t.Errorf("the last line, or reload:\n%s", out)
	}
	os.MkdirAll(filepath.Dir(defaultConfig()), 0o700)
	os.WriteFile(defaultConfig(), []byte("--device x\n"), 0o600)
	out, err = runSetup(t, "n\nn\n", config, true)
	if err != nil || !strings.Contains(out, "in a terminal: "+rc+" run --config "+shellWord(config)+" (it reads") {
		t.Errorf("another file first: %v\n%s", err, out)
	}
}

// Ctrl-C (ctx done) while a question waits: setup stops at once, writing nothing.
func TestSetupInterrupted(t *testing.T) {
	_, config := setupHome(t)
	ctx, cancel := context.WithCancel(context.Background())
	r, w := io.Pipe() // a terminal no one types into
	defer w.Close()
	done := make(chan error, 1)
	go func() { done <- setupIn(ctx, r, io.Discard, config, false) }()
	cancel()
	select {
	case err := <-done:
		if err != errStopped || exists(config) {
			t.Errorf("%v, file %v", err, exists(config))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still waiting for an answer after Ctrl-C")
	}
}

// The input ends (Ctrl-D): setup stops, writing nothing more.
func TestSetupEOF(t *testing.T) {
	_, config := setupHome(t)
	for _, in := range []string{"", "phone\n", "phone\n*\n"} {
		if _, err := runSetup(t, in, config, false); err != errNoAnswer || exists(config) {
			t.Errorf("%q: %v, file %v", in, err, exists(config))
		}
	}
}

// A hosts file there already: kept as hosts.old, its comments kept in the
// new one; no hosts answered: no hosts file, no @ line.
func TestSetupHostsFile(t *testing.T) {
	_, config := setupHome(t)
	hostsFile := filepath.Join(filepath.Dir(config), "hosts")
	os.MkdirAll(filepath.Dir(config), 0o700)
	mine := "# my note\nold.example.com\n"
	os.WriteFile(hostsFile, []byte(mine), 0o600)
	out, err := runSetup(t, "phone\nnew.example.com\nn\n", config, false)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(hostsFile); string(b) != "# my note\nnew.example.com\n" {
		t.Errorf("hosts file:\n%s", b)
	}
	if b, _ := os.ReadFile(hostsFile + ".old"); string(b) != mine || !strings.Contains(out, "the old hosts: "+shellWord(hostsFile+".old")) {
		t.Errorf("old: %q\n%s", b, out)
	}
	_, config = setupHome(t)
	if _, err := runSetup(t, "phone\n\nn\n", config, false); err != nil {
		t.Fatal(err)
	}
	if words, _, err := readConfig(config); err != nil || !slices.Equal(words, []string{"--device=phone"}) || exists(filepath.Join(filepath.Dir(config), "hosts")) {
		t.Errorf("no hosts: %q, %v", words, err)
	}
}
