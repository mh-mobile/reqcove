package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

// The config writer: the one way reqcove changes a --config file (capture
// save's hosts file lines; the console's local page later). Only the flags of
// configFlags, each value checked; the other lines and comments are kept, one
// flag a line, the file replaced whole (0600) after reading back as written,
// the one before kept as config.prev. Its errors never quote a value: a line
// may hold a --mask-values pattern.

// configFlags are the flags the writer writes, each with its check (a fixed
// text, never the value). Any other flag is never written: what v1 refuses in
// the file, what names a file or code to read or run (--rules, --uvx,
// --upstream-ca...), --mask-values (patterns can be secrets). --allow-hosts and
// --pass-hosts only as the hosts file beside the config (hostsFileLine).
var configFlags = map[string]func(string) error{
	"device": func(v string) error {
		if v == "" || strings.HasPrefix(v, "-") {
			return errors.New("a device's name, IP or StableID")
		}
		return nil
	},
	"keep-awake": func(v string) error {
		if !slices.Contains([]string{"always", "ac", "never"}, v) {
			return errors.New("always, ac or never")
		}
		return nil
	},
	"proxy-port": func(v string) error {
		if n, err := strconv.Atoi(v); err != nil || n < 0 || n > 65535 {
			return errors.New("a port, 1 to 65535 (0 turns the Remote Proxy off)")
		}
		return nil
	},
	"hostname": func(v string) error {
		if !dnsLabel.MatchString(v) {
			return errors.New("a name of lowercase letters, digits and -")
		}
		return nil
	},
	"verbose":     boolValue,
	"ui":          boolValue,
	"mcp-http":    boolValue,
	"local-proxy": boolValue,
	"dns": func(v string) error {
		if _, err := parseDNS(v); err != nil {
			return errors.New(`IP addresses with an optional :PORT, comma-separated, or "system"`)
		}
		return nil
	},
	"upstream-proxy": func(v string) error {
		_, err := upstreamAddr(v, "") // its error never quotes the value (a password)
		return err
	},
	"mask-names": func(v string) error {
		for n := range strings.SplitSeq(v, ",") {
			if !nameRE.MatchString(strings.TrimSpace(n)) {
				return errors.New("names (letters, digits, -, _ and .), comma-separated")
			}
		}
		return nil
	},
}

// clearOnly are flags the writer only takes out (their lines removed),
// never writes: --upstream-ca names a CA to trust.
var clearOnly = map[string]bool{"upstream-ca": true}

func boolValue(v string) error {
	if v != "true" && v != "false" {
		return errors.New("true or false")
	}
	return nil
}

// badValue: a value with a line break, NUL or another control character
// would end or split its line; one starting with @ would name a file to read.
func badValue(v string) bool {
	return !utf8.ValidString(v) || strings.HasPrefix(v, "@") || strings.ContainsFunc(v, unicode.IsControl)
}

// configEdit is one change to a --config file: Flag's lines replaced by a line
// for each of Values (none: its lines removed); with Add, Values added as
// lines at the end, its lines kept (never rewritten).
type configEdit struct {
	Flag   string
	Values []string
	Add    bool
}

// hostsFileLine is the edit adding --allow-hosts=@FILE (pass: --pass-hosts),
// FILE the hosts file beside config (hostsFileFor): the one value with an @
// the writer writes, made here, never given.
func hostsFileLine(config string, pass bool) configEdit {
	name := "allow-hosts"
	if pass {
		name = "pass-hosts"
	}
	return configEdit{Flag: name, Values: []string{"@" + hostsFileFor(config, pass)}, Add: true}
}

// hostsFileFor is the hosts file capture save creates beside config, when
// the config names none: setup's (hosts), or pass-hosts.
func hostsFileFor(config string, pass bool) string {
	if pass {
		return filepath.Join(filepath.Dir(config), "pass-hosts")
	}
	return setupHosts(config)
}

// configPlan is a change to a --config file worked out, not made: the file
// as read (rev: its hash), the text it would have, and the lines taken out
// and put in (the diff; the lines of the flags it changes only).
type configPlan struct {
	path, rev      string
	old, new       []byte
	removed, added []string
}

// diff is the plan's lines, - taken out, + put in.
func (p *configPlan) diff() string {
	var b strings.Builder
	for _, l := range p.removed {
		b.WriteString("- " + l + "\n")
	}
	for _, l := range p.added {
		b.WriteString("+ " + l + "\n")
	}
	return b.String()
}

// configRev is the revision of a config's bytes: their hash.
func configRev(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// flagUse is one flag among words: its name and value (a bool's "true" when
// given bare), the words it takes (from, to).
type flagUse struct {
	name, value string
	from, to    int
}

// flagUses reads words as fs (run's flags) parses them, flag by flag: a
// value may be the next word. Not a flag, or not run's: an error (no value
// in it).
func flagUses(fs *flag.FlagSet, words []string) ([]flagUse, error) {
	var out []flagUse
	for i := 0; i < len(words); i++ {
		w := words[i]
		if w == "--" {
			break
		}
		name, ok := strings.CutPrefix(w, "-")
		name = strings.TrimPrefix(name, "-")
		name, value, hasValue := strings.Cut(name, "=")
		f := fs.Lookup(name)
		if !ok || name == "" || f == nil {
			return nil, fmt.Errorf("word %d is not one of run's flags", i+1)
		}
		u := flagUse{name: name, value: value, from: i, to: i}
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); !hasValue && ok && b.IsBoolFlag() {
			u.value = "true"
		} else if !hasValue {
			if i+1 >= len(words) {
				return nil, fmt.Errorf("--%s has no value", name)
			}
			i++
			u.value, u.to = words[i], i
		}
		out = append(out, u)
	}
	return out, nil
}

// commandLine is args without --config FILE: the flags run was given on its
// command line, which win over the file's.
func commandLine(fs *flag.FlagSet, args []string) ([]flagUse, error) {
	uses, err := flagUses(fs, args)
	return slices.DeleteFunc(uses, func(u flagUse) bool { return u.name == "config" }), err
}

// configWord is v written so configWords reads it back as it is.
var plainWord = regexp.MustCompile(`^[A-Za-z0-9._:/,+=@-]+$`)

func configWord(v string) string {
	if plainWord.MatchString(v) {
		return v
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// planConfig works out edits to the --config file path, read through no link
// and this user's: refused when a flag is not the writer's, a value is bad,
// the flag is given on run's command line (args, run's arguments: it wins
// over the file; the hosts file lines, which add up, excepted), a line to
// change holds more than the flag or an @FILE, or the whole flag set (args
// with the new text and files: hosts files' texts by path) would not start.
func planConfig(path string, args []string, files map[string]string, edits ...configEdit) (*configPlan, error) {
	flags := runFlagSet()
	cmd, err := commandLine(flags, args)
	if err != nil {
		return nil, fmt.Errorf("run's arguments: %w", err)
	}
	if c, ok, _ := configFile(args); !ok || absPath(c) != path { // the file checkFlags reads in its place
		return nil, fmt.Errorf("run was not started from --config %s", path)
	}
	for _, e := range edits {
		if e.Flag == "allow-hosts" || e.Flag == "pass-hosts" {
			if want := hostsFileLine(path, e.Flag == "pass-hosts"); !e.Add || !slices.Equal(e.Values, want.Values) {
				return nil, fmt.Errorf("--%s: only the hosts file beside the config is written (%s)", e.Flag, want.Values[0][1:])
			}
			continue
		}
		check, ok := configFlags[e.Flag]
		if !ok && clearOnly[e.Flag] && len(e.Values) == 0 && !e.Add {
			check, ok = boolValue, true // no value to check: its lines removed
		}
		if !ok {
			return nil, fmt.Errorf("--%s is not written by reqcove: change it in the file yourself, in your terminal", e.Flag)
		}
		for _, v := range e.Values {
			if badValue(v) {
				return nil, fmt.Errorf("--%s: a value with a line break, a control character or a leading @ is refused", e.Flag)
			}
			if err := check(v); err != nil {
				return nil, fmt.Errorf("--%s: %w", e.Flag, err)
			}
		}
		if slices.ContainsFunc(cmd, func(u flagUse) bool { return u.name == e.Flag }) {
			return nil, fmt.Errorf("--%s is given on run's command line, which wins over the file: change it there", e.Flag)
		}
	}
	if fi, err := os.Lstat(path); err != nil {
		return nil, fmt.Errorf("--config: %w", err)
	} else if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("--config %s is a link: reqcove writes a plain file only (edit the file it points to yourself)", path)
	}
	old, err := configBytes(path, syscall.O_NOFOLLOW)
	if err != nil {
		return nil, err
	}
	uses, lines, err := configUses(flags, path, old)
	if err != nil {
		return nil, err
	}
	text := strings.SplitAfter(string(old), "\n")
	if text[len(text)-1] == "" {
		text = text[:len(text)-1]
	}
	if n := len(text); n > 0 && !strings.HasSuffix(text[n-1], "\n") {
		text[n-1] += "\n"
	}
	p := &configPlan{path: path, rev: configRev(old), old: old}
	drop := map[int]bool{} // line indexes
	at := map[int][]string{}
	for _, e := range edits {
		var put []string
		for _, v := range e.Values {
			put = append(put, "--"+e.Flag+"="+configWord(v))
		}
		p.added = append(p.added, put...)
		where := len(text)
		if !e.Add {
			for _, u := range uses {
				if u.name != e.Flag {
					continue
				}
				l := lines[u.from]
				if lines[u.to] != l || slices.ContainsFunc(uses, func(o flagUse) bool { return o != u && (lines[o.from] == l || lines[o.to] == l) }) {
					return nil, fmt.Errorf("--config %s, line %d: --%s shares its lines with another flag or value: change it there yourself (the writer changes a flag alone on its line)", path, l, e.Flag)
				}
				if strings.HasPrefix(u.value, "@") {
					return nil, fmt.Errorf("--config %s, line %d: --%s reads a file there (@FILE): change it in your terminal", path, l, e.Flag)
				}
				drop[l-1] = true
				where = min(where, l-1)
				p.removed = append(p.removed, strings.TrimRight(text[l-1], "\r\n"))
			}
		}
		at[where] = append(at[where], put...)
	}
	var b strings.Builder
	for i := 0; i <= len(text); i++ {
		for _, l := range at[i] {
			b.WriteString(l + "\n")
		}
		if i < len(text) && !drop[i] {
			b.WriteString(text[i])
		}
	}
	p.new = []byte(b.String())
	newUses, _, err := configUses(flags, path, p.new)
	if err != nil || !sameDelta(uses, newUses, edits) {
		return nil, fmt.Errorf("--config %s would not read back as old flags plus the change", path)
	}
	if _, err := checkFlags(args, p.new, files); err != nil {
		return nil, fmt.Errorf("the next start of run would refuse it: %w", err)
	}
	return p, nil
}

// absPath is p absolute ("" when it cannot be).
func absPath(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return ""
	}
	return a
}

// configUses is the flags in a config's text, and each word's line.
func configUses(fs *flag.FlagSet, path string, b []byte) ([]flagUse, []int, error) {
	words, lines, err := configText(path, b)
	if err != nil {
		return nil, nil, err
	}
	uses, err := flagUses(fs, words)
	if err != nil {
		return nil, nil, fmt.Errorf("--config %s: a flag or its value does not parse: %w", path, err)
	}
	return uses, lines, nil
}

// sameDelta: next is old with edits made, nothing else: the other flags as
// they were, in order, and each edited flag's values as asked.
func sameDelta(old, next []flagUse, edits []configEdit) bool {
	edited := func(u flagUse) bool {
		return slices.ContainsFunc(edits, func(e configEdit) bool { return e.Flag == u.name })
	}
	pairs := func(uses []flagUse, keep func(flagUse) bool) []string {
		var out []string
		for _, u := range uses {
			if keep(u) {
				out = append(out, u.name+"\x00"+u.value)
			}
		}
		return out
	}
	notEdited := func(u flagUse) bool { return !edited(u) }
	if !slices.Equal(pairs(old, notEdited), pairs(next, notEdited)) {
		return false
	}
	for _, e := range edits {
		of := func(u flagUse) bool { return u.name == e.Flag }
		var want []string
		if e.Add {
			want = pairs(old, of)
		}
		for _, v := range e.Values {
			want = append(want, e.Flag+"\x00"+v)
		}
		if !slices.Equal(pairs(next, of), want) {
			return false
		}
	}
	return true
}

// renameConfig puts the new config in place (a seam for the tests of a
// failed write).
var renameConfig = os.Rename

// commit writes the plan: the new text to a private temp file beside the
// config, read back through readConfig; the file still the one planned (its
// revision); the old one kept as config.prev (0600); then the rename.
func (p *configPlan) commit() error {
	tmp, err := os.CreateTemp(filepath.Dir(p.path), ".config.tmp*") // 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // nothing once renamed
	_, err = tmp.Write(p.new)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	want, _, err := configText(p.path, p.new)
	if err != nil {
		return err
	}
	if got, _, err := readConfig(tmp.Name()); err != nil || !slices.Equal(got, want) {
		return fmt.Errorf("--config %s would not read back as written", p.path)
	}
	if now, err := configBytes(p.path, syscall.O_NOFOLLOW); err != nil || configRev(now) != p.rev {
		return fmt.Errorf("--config %s changed since it was read (try again)", p.path)
	}
	if err := writePrivate(p.path+".prev", p.old); err != nil {
		return fmt.Errorf("%s.prev: %w", p.path, err)
	}
	return renameConfig(tmp.Name(), p.path)
}
