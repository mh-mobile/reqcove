package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// setupHome is a temporary HOME (the real config and skill are never
// touched) with ~/.claude (an agent init finds) and no uvx on PATH.
func setupHome(t *testing.T) (home, config string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	os.Mkdir(filepath.Join(home, ".claude"), 0o700)
	return home, defaultConfig()
}

func runSetup(t *testing.T, input, config, brew string) (string, error) {
	t.Helper()
	var out strings.Builder
	err := setupIn(strings.NewReader(input), &out, config, brew)
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
	out, err := runSetup(t, in, config, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Count(out, "Device: ") != 2 || strings.Count(out, "Hosts: ") != 2 || !strings.Contains(out, "only on the command line") {
		t.Errorf("not asked again:\n%s", out)
	}
	words, _, err := readConfig(config)
	if want := []string{`--device=Taro's "iPhone" --no-redact`, "--allow-hosts=api.example.com,*.example-cdn.com"}; err != nil || !slices.Equal(words, want) {
		t.Errorf("read back %q, %v; want %q", words, err, want)
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
	if ents, _ := os.ReadDir(filepath.Dir(config)); len(ents) != 1 {
		t.Errorf("left behind: %v", ents)
	}
	if !exists(filepath.Join(home, ".claude/skills/reqcove/SKILL.md")) || !strings.Contains(out, "installed ~/.claude/skills/reqcove/SKILL.md") {
		t.Errorf("no skill:\n%s", out)
	}
	for _, want := range []string{
		"not found: install it (brew install uv",
		"claude mcp add reqcove -- reqcove mcp",
		"reqcove service install",
		"reqcove run --config " + shellWord(config),
		"`reqcove links` prints the login URL",
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
// whole. No hosts: the --allow-hosts line stays a comment.
func TestSetupExisting(t *testing.T) {
	home, config := setupHome(t)
	os.MkdirAll(filepath.Dir(config), 0o700)
	mine := "--device mine\n--allow-hosts mine.example.com\n"
	os.WriteFile(config, []byte(mine), 0o600)
	for _, in := range []string{"\nn\n", "no\nno\n"} { // kept; the skill declined
		out, err := runSetup(t, in, config, "")
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(config); string(b) != mine || !strings.Contains(out, "| --device mine") || !strings.Contains(out, "kept") {
			t.Errorf("%q: file %q\n%s", in, b, out)
		}
		if exists(filepath.Join(home, ".claude/skills")) {
			t.Errorf("%q: skill installed when declined", in)
		}
	}
	out, err := runSetup(t, "y\nphone\n\nn\n", config, "")
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
}

// Installed with Homebrew: brew services, which reads its own etc, after a link.
func TestSetupBrew(t *testing.T) {
	_, config := setupHome(t)
	out, err := runSetup(t, "phone\na.example.com\nn\n", config, "/opt/homebrew")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ln -s " + shellWord(config) + " /opt/homebrew/etc/reqcove/config", "brew services start reqcove"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "service install") {
		t.Errorf("service install under Homebrew:\n%s", out)
	}
	// The link brew services reads through: readConfig takes it.
	link := filepath.Join(t.TempDir(), "config")
	os.Symlink(config, link)
	if words, _, err := readConfig(link); err != nil || len(words) != 2 {
		t.Errorf("through a link: %q, %v", words, err)
	}
	// brew's file there already (as the guide wrote it before setup): named,
	// no link offered; a link to this file: nothing to do but start.
	brew := t.TempDir()
	etc := filepath.Join(brew, "etc", "reqcove")
	os.MkdirAll(etc, 0o700)
	os.WriteFile(filepath.Join(etc, "config"), []byte("--device x\n"), 0o600)
	out, _ = runSetup(t, "n\nn\n", config, brew)
	if !strings.Contains(out, "which is there already") || strings.Contains(out, "ln -s") || !strings.Contains(out, "brew services start reqcove") {
		t.Errorf("brew's file there:\n%s", out)
	}
	os.Remove(filepath.Join(etc, "config"))
	os.Symlink(config, filepath.Join(etc, "config"))
	out, _ = runSetup(t, "n\nn\n", config, brew)
	if strings.Contains(out, "which is there already") || strings.Contains(out, "ln -s") || !strings.Contains(out, "brew services start reqcove") {
		t.Errorf("linked already:\n%s", out)
	}
	// Skipped: no file, the command line form, nothing else asked about the file.
	_, config = setupHome(t)
	out, err = runSetup(t, "\nn\n", config, "/opt/homebrew")
	if err != nil || exists(config) || !strings.Contains(out, "reqcove run --device NAME --allow-hosts HOSTS") || strings.Contains(out, "Hosts: ") {
		t.Errorf("skipped: %v, %v\n%s", err, exists(config), out)
	}
}

// The input ends (Ctrl-D): setup stops, writing nothing more.
func TestSetupEOF(t *testing.T) {
	_, config := setupHome(t)
	for _, in := range []string{"", "phone\n", "phone\n*\n"} {
		if _, err := runSetup(t, in, config, ""); err != errNoAnswer || exists(config) {
			t.Errorf("%q: %v, file %v", in, err, exists(config))
		}
	}
}
