package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/skills"
)

func skillHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func initOut(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() error { err = initSkill(args); return nil })
	return out, err
}

// init puts the skill where the agents found in ~ read it, and only there.
func TestInitInstalls(t *testing.T) {
	home := skillHome(t)
	os.Mkdir(filepath.Join(home, ".claude"), 0o700)
	os.MkdirAll(filepath.Join(home, ".config", "devin"), 0o700) // Devin: ~/.agents/skills
	if _, err := initOut(t); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{".claude/skills/reqcove", ".agents/skills/reqcove"} {
		file := filepath.Join(home, dir, "SKILL.md")
		b, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(b, skills.Reqcove) {
			t.Fatalf("%s: %v", dir, err)
		}
		if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o644 {
			t.Errorf("%s mode %v", file, fi.Mode())
		}
		ents, _ := os.ReadDir(filepath.Join(home, dir))
		if len(ents) != 2 { // SKILL.md and the mark; no temporary file left
			t.Errorf("%s holds %v", dir, ents)
		}
	}
	if out, _ := initOut(t); strings.Count(out, "up to date") != 2 {
		t.Errorf("again:\n%s", out)
	}
	// Only the named agent's directory.
	home = skillHome(t)
	os.Mkdir(filepath.Join(home, ".claude"), 0o700)
	if _, err := initOut(t, "--client", "codex"); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(home, ".agents/skills/reqcove/SKILL.md")) || exists(filepath.Join(home, ".claude/skills")) {
		t.Error("--client codex: not ~/.agents/skills alone")
	}
}

// A skill another tool put there, one the user edited, or a link, is left
// alone; an older one of init's is updated, and said to be stale till then.
func TestInitLeavesOthers(t *testing.T) {
	home := skillHome(t)
	put := func(dir, body string, mark bool) string {
		d := filepath.Join(home, dir)
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "SKILL.md"), []byte(body), 0o644)
		if mark {
			os.WriteFile(filepath.Join(d, skillMark), []byte(hash([]byte(body))+"\n"), 0o644)
		}
		return d
	}
	old := "---\nname: reqcove\ndescription: an older version\n---\n"
	stale := put(".claude/skills/reqcove", old, true)
	gh := put(".agents/skills/reqcove", "---\nname: reqcove\nmetadata: {source: gh}\n---\n", false)
	if got := staleSkills(); len(got) != 1 || got[0] != "~/.claude/skills/reqcove" {
		t.Errorf("stale: %v", got)
	}
	if !strings.Contains(staleSkillNote(), "`reqcove init` updates it") {
		t.Errorf("note: %q", staleSkillNote())
	}
	out, err := initOut(t)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(stale, "SKILL.md")); !bytes.Equal(b, skills.Reqcove) {
		t.Error("init's older skill was not updated")
	}
	if b, _ := os.ReadFile(filepath.Join(gh, "SKILL.md")); !strings.Contains(string(b), "source: gh") || !strings.Contains(out, "left ~/.agents/skills/reqcove alone: not put there by reqcove init") {
		t.Errorf("another tool's skill:\n%s", out)
	}
	if staleSkills() != nil {
		t.Error("still stale after init")
	}
	// Edited by the user since: left, and not called stale.
	os.WriteFile(filepath.Join(stale, "SKILL.md"), append(bytes.Clone(skills.Reqcove), "my note\n"...), 0o644)
	if out, _ := initOut(t, "--uninstall"); !strings.Contains(out, "edited since reqcove init wrote it") || !exists(filepath.Join(stale, "SKILL.md")) || staleSkills() != nil {
		t.Errorf("an edited skill:\n%s", out)
	}
	// Links (dotfiles keep skills in a repo): neither followed nor replaced.
	home = skillHome(t)
	elsewhere := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".claude", "skills"), 0o755)
	os.Symlink(elsewhere, filepath.Join(home, ".claude/skills/reqcove"))
	os.MkdirAll(filepath.Join(home, ".agents/skills/reqcove"), 0o755)
	os.WriteFile(filepath.Join(elsewhere, "SKILL.md"), []byte(old), 0o644)
	os.WriteFile(filepath.Join(elsewhere, skillMark), []byte(hash([]byte(old))+"\n"), 0o644) // init's own, seen through the links
	os.Symlink(filepath.Join(elsewhere, "SKILL.md"), filepath.Join(home, ".agents/skills/reqcove/SKILL.md"))
	os.WriteFile(filepath.Join(home, ".agents/skills/reqcove", skillMark), []byte(hash([]byte(old))+"\n"), 0o644)
	out, _ = initOut(t)
	if b, _ := os.ReadFile(filepath.Join(elsewhere, "SKILL.md")); string(b) != old || strings.Count(out, "left ") != 2 {
		t.Errorf("links:\n%s", out)
	}
}

// --uninstall removes init's own skill, and its directory once empty.
func TestInitUninstall(t *testing.T) {
	home := skillHome(t)
	os.Mkdir(filepath.Join(home, ".codex"), 0o700)
	initOut(t)
	if _, err := initOut(t, "--uninstall"); err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(home, ".agents/skills/reqcove")) || !exists(filepath.Join(home, ".agents/skills")) {
		t.Error("not removed, or more than its own directory")
	}
}

func TestInitRefuses(t *testing.T) {
	home := skillHome(t)
	t.Chdir(t.TempDir()) // a relative HOME, should it be taken, writes here
	if _, err := initOut(t); err == nil || !strings.Contains(err.Error(), "no agent found") {
		t.Errorf("no agent: %v", err)
	}
	if _, err := initOut(t, "--print", "--uninstall"); err == nil {
		t.Error("--print with --uninstall")
	}
	for _, h := range []string{"", "relative-home"} {
		t.Setenv("HOME", h)
		if _, err := initOut(t, "--client", "claude"); err == nil || !strings.Contains(err.Error(), "no home directory") {
			t.Errorf("HOME %q: %v", h, err)
		}
	}
	if exists(filepath.Join(".claude")) {
		t.Error("wrote ./.claude without a home")
	}
	// --print needs no home: the skill, as embedded.
	if out, err := initOut(t, "--print"); err != nil || out != string(skills.Reqcove) {
		t.Errorf("--print: %v", err)
	}
	_ = home
}

// The skill is valid for the Agent Skills spec: name matching its directory,
// a description within 1024 characters, the start init's checks rely on.
func TestSkillFile(t *testing.T) {
	s := string(skills.Reqcove)
	if !strings.HasPrefix(s, "---\nname: reqcove\ndescription: ") {
		t.Fatalf("starts %.40q", s)
	}
	desc, _, _ := strings.Cut(strings.TrimPrefix(s, "---\nname: reqcove\ndescription: "), "\n")
	if n := len([]rune(desc)); n > 1024 || n < 100 {
		t.Errorf("description %d characters", n)
	}
	if n := strings.Count(s, "\n"); n > 500 {
		t.Errorf("%d lines: the spec suggests under 500", n)
	}
}

// Builds from source are told apart by their commit; a release keeps its version.
func TestBuildVersion(t *testing.T) {
	info := func(kv ...string) *debug.BuildInfo {
		b := &debug.BuildInfo{}
		for i := 0; i < len(kv); i += 2 {
			b.Settings = append(b.Settings, debug.BuildSetting{Key: kv[i], Value: kv[i+1]})
		}
		return b
	}
	for _, c := range []struct {
		v    string
		info *debug.BuildInfo
		want string
	}{
		{"dev", info("vcs.revision", "77e6706abcdef", "vcs.modified", "false"), "dev-77e6706"},
		{"dev", info("vcs.revision", "77e6706abcdef", "vcs.modified", "true"), "dev-77e6706-dirty"},
		{"dev", info(), "dev"}, // go run, or no .git (the container's build)
		{"0.2.0", info("vcs.revision", "77e6706abcdef"), "0.2.0"},
	} {
		if got := buildVersion(c.v, c.info); got != c.want {
			t.Errorf("%s %v: %q, want %q", c.v, c.info.Settings, got, c.want)
		}
	}
}
