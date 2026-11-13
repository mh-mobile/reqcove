package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// reqcove mock add: a mock appended to a --rules file, for people. Go has no
// YAML library, so the mock is text (each value a JSON-style double-quoted
// scalar, which YAML reads the same) added after the file's own text, and the
// whole file is checked by the addon's loader before it is written. Only when
// stdin and stdout are a terminal, as lan and mark: a help against an agent
// running it unasked, not a guarantee.

const mockUse = "reqcove mock add --rules FILE --url URL [flags]"

type headerFlags []string

func (h *headerFlags) String() string     { return strings.Join(*h, ", ") }
func (h *headerFlags) Set(v string) error { *h = append(*h, v); return nil }

func mockCmd(ctx context.Context, args []string) error {
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fls := flag.NewFlagSet("mock add", flag.ExitOnError)
	rules := fls.String("rules", "", "the --rules file the mock goes in (made, 0600, when it is not there)")
	fls.String("url", "", "the URL the mock answers: http or https, no query (a * at the end matches any rest)")
	fls.String("method", "", "the request's method, such as POST (any when left out)")
	fls.String("operation", "", "the GraphQL operation's name it answers")
	fls.Int("status", 200, "the answer's status")
	var headers headerFlags
	fls.Var(&headers, "header", "'Name: value', a header of the answer (repeatable)")
	fls.String("body", "", "the answer's body, as text")
	fls.String("body-file", "", "a file whose bytes are the answer's body")
	fls.Int("delay-ms", 0, "wait this long before answering (at most 30000)")
	fls.String("fault", "", "close: close the connection instead of answering")
	fls.String("preset", "", "a name: the mock answers only while an agent has turned it on (activate_preset)")
	fls.String("description", "", "with --preset: one line saying what it is for")
	printOnly := fls.Bool("print", false, "show the mock as YAML, without writing or checking anything (works off a terminal too)")
	state := fls.String("state", defaultState(), "state directory: a running reqcove there checks the file with its --allow-hosts and --pass-hosts")
	uvx := fls.String("uvx", "uvx", "path to uvx, for the check while reqcove is not running (uv beside it runs mitmproxy's Python from its lock)")
	if err := parseFlags(fls, args); err != nil {
		return err
	}
	if sub != "add" {
		return fmt.Errorf("usage: %s", mockUse)
	}
	item, err := mockItem(fls, headers)
	if err != nil {
		return err
	}
	if *printOnly {
		fmt.Print(indent(item, "  ", "\n"))
		return nil
	}
	if *rules == "" {
		return fmt.Errorf("--rules FILE is needed (usage: %s)", mockUse)
	}
	return mockIn(ctx, os.Stdin, os.Stdout, *state, *uvx, *rules, item)
}

// terminal is isTerminal (tests stand in for it: go test has no terminal).
var terminal = isTerminal

func mockIn(ctx context.Context, in, out *os.File, state, uvx, path, item string) error {
	if !terminal(in) || !terminal(out) {
		return errors.New("reqcove mock add runs only in a terminal: the --rules file is yours to write. Run it in your own terminal (--print shows the mock without writing it)")
	}
	return addMock(ctx, out, state, uvx, path, item)
}

// mockFields are the flags a mock is made of, in the order written; those
// under match are indented under it.
var mockFields = []struct{ flag, key string }{
	{"url", "url"}, {"method", "method"}, {"operation", "operation"},
	{"status", "status"}, {"header", "headers"}, {"body", "body"}, {"body-file", "body_file"},
	{"delay-ms", "delay_ms"}, {"fault", "fault"}, {"preset", "preset"}, {"description", "description"},
}

// mockItem is the mock the flags given make, as a YAML list item at no indent
// ("- match:…", each line ending in \n). Only what was given goes in: the
// addon's loader checks the values.
func mockItem(fls *flag.FlagSet, headers []string) (string, error) {
	given := map[string]bool{}
	fls.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if !given["url"] {
		return "", fmt.Errorf("--url is needed (usage: %s)", mockUse)
	}
	var b strings.Builder
	b.WriteString("- match:\n")
	for _, f := range mockFields {
		if !given[f.flag] {
			continue
		}
		pad := "  "
		if f.key == "url" || f.key == "method" || f.key == "operation" {
			pad = "    "
		}
		v := fls.Lookup(f.flag).Value.String()
		switch f.flag {
		case "status", "delay-ms": // numbers, parsed by flag
			fmt.Fprintf(&b, "%s%s: %s\n", pad, f.key, v)
			continue
		case "header":
			b.WriteString("  headers:\n")
			seen := map[string]bool{}
			for _, h := range headers {
				name, value, ok := strings.Cut(h, ":")
				if !ok || strings.TrimSpace(name) == "" {
					return "", errors.New("--header takes 'Name: value'")
				}
				if k := strings.ToLower(strings.TrimSpace(name)); seen[k] {
					return "", errors.New("--header: one value per header name")
				} else {
					seen[k] = true
				}
				if !utf8.ValidString(h) {
					return "", errors.New("--header is not UTF-8 text")
				}
				fmt.Fprintf(&b, "    %s: %s\n", yamlQuote(strings.TrimSpace(name)), yamlQuote(strings.TrimSpace(value)))
			}
			continue
		case "body-file":
			abs, err := filepath.Abs(v) // the file the user means, from where they typed it
			if err != nil {
				return "", err
			}
			v = abs
		}
		if !utf8.ValidString(v) {
			return "", fmt.Errorf("--%s is not UTF-8 text (a body that is not goes in --body-file)", f.flag)
		}
		fmt.Fprintf(&b, "%s%s: %s\n", pad, f.key, yamlQuote(v))
	}
	return b.String(), nil
}

// yamlQuote is s as a double-quoted YAML scalar on one line: " and \ escaped,
// and every character YAML does not print as itself (controls, DEL, C1, line
// and paragraph separators, BOM, U+FFFE/U+FFFF) as \uXXXX, so no value ends
// its scalar or its line. s is valid UTF-8.
func yamlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r < 0x20 || r >= 0x7f && r <= 0x9f || r == 0x2028 || r == 0x2029 || r == 0xfeff || r == 0xfffe || r == 0xffff:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func indent(item, pad, eol string) string {
	return pad + strings.ReplaceAll(strings.TrimSuffix(item, "\n"), "\n", eol+pad) + eol
}

var mockKey = regexp.MustCompile(`^mock[ \t]*:(?:[ \t](.*))?$`)
var listItem = regexp.MustCompile(`^([ ]*)-(?:[ \t]|$)`)

// appendMock is text with item (mockItem's) added as the last of mock's
// items, the file's own text kept as it is; with no mock: key, mock: and the
// item go at the end. It refuses a mock: that is not the file's last
// top-level key, or whose items are not a block list.
func appendMock(text, item string) (string, error) {
	eol := "\n"
	if strings.Contains(text, "\r\n") {
		eol = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	mock, pad := -1, "  "
	for i, l := range lines {
		// A top-level key starts its line; comments, list items and indented lines do not.
		if l == "" || strings.ContainsAny(l[:1], "# \t-") {
			continue
		}
		if mock >= 0 {
			return "", errors.New("mock: is not the file's last block: move it, with its items, to the end of the file and run this again")
		}
		m := mockKey.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		mock = i
		if rest := strings.TrimSpace(m[1]); rest != "" && !strings.HasPrefix(rest, "#") {
			return "", errors.New("mock: holds its items on its own line (flow style, such as mock: []): write them as a block list, each under its own - match:, and run this again")
		}
	}
	if mock >= 0 {
		for _, l := range lines[mock+1:] {
			if t := strings.TrimSpace(l); t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			m := listItem.FindStringSubmatch(l)
			if m == nil {
				return "", errors.New("mock:'s items are not a block list (flow style, such as [ on the next line): write them each under its own - match:, and run this again")
			}
			pad = m[1]
			break
		}
	}
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += eol
	}
	if mock < 0 {
		text += "mock:" + eol
	}
	return text + indent(item, pad, eol), nil
}

// checkPython checks a rules file without a run (tests stand in for it).
var checkPython = capture.CheckRulesPython

// addMock appends item to the --rules file at path once the whole file, as it
// would be, loads: checked by the run in state when one is there (with its
// hosts), else by mitmproxy's Python. Written at once (a temp file beside it,
// renamed over it), keeping its mode; refused, nothing is written.
func addMock(ctx context.Context, w io.Writer, state, uvx, path, item string) error {
	if p, err := filepath.EvalSymlinks(path); err == nil {
		path = p // a link stays a link: the file it names gets the mock
	} else if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a link to a file that is not there: point it at one, or give the file itself", path)
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	mode := fs.FileMode(0o600)
	old, err := os.ReadFile(path)
	if err == nil {
		st, err := os.Stat(path)
		if err != nil {
			return err
		}
		mode = st.Mode().Perm()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	text, err := appendMock(string(old), item)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	// Beside it, so a relative body_file reads the same when checked, and the rename is one step.
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".reqcove-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // nothing there once renamed
	_, err = f.WriteString(text)
	err = errors.Join(err, f.Chmod(mode), f.Sync(), f.Close())
	if err != nil {
		return err
	}
	run, err := capture.CheckRules(ctx, state, f.Name(), path)
	up := !errors.Is(err, capture.ErrNoControl) // a run is there, even one that did not check
	why := ""
	if err == nil {
		why = *run.Why
	} else {
		if up {
			fmt.Fprintf(w, "the running reqcove did not check the file (%v): checking it with mitmproxy's Python, without --allow-hosts and --pass-hosts\n", err)
		} else {
			fmt.Fprintf(w, "reqcove is not running (%s): checking the file with mitmproxy's Python, without --allow-hosts and --pass-hosts\n", state)
		}
		why, err = checkPython(ctx, capture.Config{Uvx: uvx, Python: defaultPython, MitmSpec: defaultMitmSpec}, f.Name())
		if err != nil {
			return fmt.Errorf("the file could not be checked, so nothing was written: %w", err)
		}
	}
	if why != "" {
		return fmt.Errorf("%s would not load with this mock (%s): nothing written", path, why)
	}
	// A save made while the check ran (seconds, with Python) must not be lost.
	if now, err := os.ReadFile(path); (err == nil) != (old != nil) || string(now) != string(old) {
		return fmt.Errorf("%s changed meanwhile: nothing written; run it again", path)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	fmt.Fprintf(w, "added to %s\n", path)
	switch {
	case run.Reload:
		fmt.Fprintln(w, "The running reqcove takes it at once (--rules-reload), which turns every preset that is on off.")
	case run.Same:
		fmt.Fprintln(w, "Restart reqcove run for it to take effect: without --rules-reload it reads the file at start only.")
	case up && run.Why == nil:
		fmt.Fprintln(w, "If the running reqcove reads this file with --rules-reload, it takes it at once, which turns every preset that is on off; otherwise restart it with --rules "+path+".")
	default:
		fmt.Fprintf(w, "It takes effect when reqcove run starts, or restarts, with --rules %s.\n", path)
	}
	return nil
}
