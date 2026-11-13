package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mh-mobile/reqcove/skills"
)

// skillTarget is a skills directory agents read, and the agents' homes that
// say one of them is installed.
type skillTarget struct {
	dir     string   // under ~
	clients []string // --client names
	detect  []string // under ~
}

// skillTargets: Claude Code reads ~/.claude/skills; Codex, Cursor, Gemini CLI,
// Copilot CLI and Devin read ~/.agents/skills (their docs, 2026-11).
var skillTargets = []skillTarget{
	{".claude/skills/reqcove", []string{"claude"}, []string{".claude"}},
	{".agents/skills/reqcove", []string{"agents", "codex", "cursor", "gemini", "copilot", "devin"},
		[]string{".agents", ".codex", ".cursor", ".gemini", ".copilot", ".config/devin"}},
}

// skillMark, beside SKILL.md, holds the SHA-256 of the SKILL.md init wrote:
// init updates or removes only a file that is its own and unchanged since, not
// one the user edited or another tool (gh skill install) put there.
const skillMark = ".reqcove-init"

type skillState int

const (
	skillAbsent  skillState = iota
	skillCurrent            // ours, this binary's
	skillStale              // ours, another version's
	skillForeign            // a link, edited, or another tool's: left alone
)

func stateOf(dir string) (skillState, string) {
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return skillAbsent, ""
	} else if err != nil {
		return skillForeign, err.Error()
	}
	if !fi.IsDir() {
		return skillForeign, "not a directory (a link?)"
	}
	file := filepath.Join(dir, "SKILL.md")
	fi, err = os.Lstat(file)
	if errors.Is(err, fs.ErrNotExist) {
		return skillAbsent, ""
	} else if err != nil {
		return skillForeign, err.Error()
	}
	if !fi.Mode().IsRegular() {
		return skillForeign, "SKILL.md is not a plain file (a link?)"
	}
	mark, err := os.ReadFile(filepath.Join(dir, skillMark))
	if err != nil {
		return skillForeign, "not put there by reqcove init (another tool's, or by hand)"
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return skillForeign, err.Error()
	}
	switch {
	case bytes.Equal(b, skills.Reqcove): // ours as it is, whatever the mark says (a write cut short)
		return skillCurrent, ""
	case strings.TrimSpace(string(mark)) != hash(b):
		return skillForeign, "edited since reqcove init wrote it"
	}
	return skillStale, ""
}

func hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// initSkill is `reqcove init`: the skill this binary carries, into the agents'
// skills directories.
func initSkill(w io.Writer, args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	var clients []string
	var known []string
	for _, t := range skillTargets {
		known = append(known, t.clients...)
	}
	fs.Func("client", "only this agent's skills directory: "+strings.Join(known, ", ")+" (repeatable; default: each one found in ~)", func(v string) error {
		if !slices.Contains(known, v) {
			return fmt.Errorf("unknown agent %q: %s", v, strings.Join(known, ", "))
		}
		clients = append(clients, v)
		return nil
	})
	printOnly := fs.Bool("print", false, "write the skill to standard output instead (to install it yourself)")
	uninstall := fs.Bool("uninstall", false, "remove the skill reqcove init installed")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *printOnly && *uninstall {
		return errors.New("--print and --uninstall: one or the other")
	}
	if *printOnly {
		_, err := w.Write(skills.Reqcove)
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return fmt.Errorf("no home directory (HOME %q): set HOME, or use --print", os.Getenv("HOME"))
	}
	var targets []skillTarget
	for _, t := range skillTargets {
		switch {
		case len(clients) > 0 && slices.ContainsFunc(t.clients, func(c string) bool { return slices.Contains(clients, c) }):
			targets = append(targets, t)
		case len(clients) == 0 && slices.ContainsFunc(t.detect, func(d string) bool { _, err := os.Stat(filepath.Join(home, d)); return err == nil }):
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("no agent found in ~ (%s): name one with --client, or use --print", strings.Join(slices.Concat(skillTargets[0].detect, skillTargets[1].detect), ", "))
	}
	var failed []string
	for _, t := range targets {
		dir := filepath.Join(home, t.dir)
		shown := "~/" + t.dir
		state, why := stateOf(dir)
		switch {
		case state == skillForeign:
			fmt.Fprintf(w, "left %s alone: %s\n", shown, why)
		case *uninstall && state == skillAbsent:
			fmt.Fprintf(w, "%s: not installed\n", shown)
		case *uninstall:
			os.Remove(filepath.Join(dir, "SKILL.md"))
			os.Remove(filepath.Join(dir, skillMark))
			os.Remove(dir) // only if empty
			fmt.Fprintf(w, "removed %s\n", shown)
		case state == skillCurrent:
			fmt.Fprintf(w, "%s: up to date\n", shown)
		default:
			if err := writeSkill(dir); err != nil {
				failed = append(failed, fmt.Sprintf("%s: %v", shown, err))
				continue
			}
			fmt.Fprintf(w, "installed %s/SKILL.md\n", shown)
		}
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}

// writeSkill writes SKILL.md, whole or not at all, then its mark.
func writeSkill(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{{"SKILL.md", skills.Reqcove}, {skillMark, []byte(hash(skills.Reqcove) + "\n")}} {
		tmp, err := os.CreateTemp(dir, f.name+".tmp*")
		if err != nil {
			return err
		}
		_, err = tmp.Write(f.data)
		if err == nil {
			err = tmp.Chmod(0o644)
		}
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(tmp.Name(), filepath.Join(dir, f.name))
		}
		if err != nil {
			os.Remove(tmp.Name())
			return err
		}
	}
	return nil
}

// staleSkills are the skills reqcove init installed that are from another
// version, as ~/... paths, for `status` and `run` to mention.
func staleSkills() []string {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return nil
	}
	var out []string
	for _, t := range skillTargets {
		if s, _ := stateOf(filepath.Join(home, t.dir)); s == skillStale {
			out = append(out, "~/"+t.dir)
		}
	}
	return out
}

func staleSkillNote() string {
	if s := staleSkills(); len(s) > 0 {
		return fmt.Sprintf("the agent skill in %s is from another reqcove version: `reqcove init` updates it", strings.Join(s, ", "))
	}
	return ""
}
