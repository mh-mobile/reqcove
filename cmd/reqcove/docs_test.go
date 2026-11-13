package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The docs whose commands people copy and agents run as written. Not a glob:
// docs/ also holds local notes that git ignores.
var documented = []string{
	"skills/reqcove/SKILL.md",
	"README.md", "README.ja.md", "CONTRIBUTING.md",
	"docs/SECURITY.md",
	"docs/guide.md", "docs/guide.ja.md",
	"docs/another-mac.md", "docs/another-mac.ja.md",
	"docs/container.md", "docs/container.ja.md",
	"docs/several-exit-nodes.md", "docs/several-exit-nodes.ja.md",
}

// TestDocumentedCommandsParse: each `reqcove …` in the docs' code (fenced
// blocks but yaml/json/text ones, and inline code) is a command reqcove knows,
// with flags it takes, parsed by that command's own FlagSet.
func TestDocumentedCommandsParse(t *testing.T) {
	for _, doc := range documented {
		b, err := os.ReadFile("../../" + doc)
		if err != nil {
			t.Fatal(err)
		}
		checked := 0
		for _, c := range docCommands(string(b)) {
			checked++
			t.Logf("%s:%d: %q", doc, c.line, c.words)
			if err := parseDocumented(c.words); err != nil {
				t.Errorf("%s:%d: reqcove %s: %v", doc, c.line, strings.Join(c.words, " "), err)
			}
		}
		if checked < 2 { // the extraction still finds them
			t.Errorf("%s: only %d reqcove commands found", doc, checked)
		}
	}
}

type docCommand struct {
	line  int
	words []string // after "reqcove"
}

var (
	inlineCode = regexp.MustCompile("`([^`]+)`")
	// reqcove as a command: at the start, after a separator or a space (docker
	// run IMAGE, claude mcp add NAME --), followed by a word (its command).
	reqcoveCmd = regexp.MustCompile(`(?:^|[\s(;&|])reqcove\s+([a-z-][a-z-]*)`)
)

// docCommands finds the reqcove commands in text's code.
func docCommands(text string) []docCommand {
	type snippet struct {
		line int
		s    string
	}
	var code []snippet
	fence, inFence, cont, contLine := "", false, "", 0
	for i, line := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "```") {
			inFence, fence = !inFence, strings.TrimPrefix(t, "```")
			continue
		}
		if inFence {
			if fence == "yaml" || fence == "json" || fence == "text" {
				continue
			}
			if cont == "" {
				contLine = i + 1
			}
			if s, ok := strings.CutSuffix(line, `\`); ok { // goes on on the next line
				cont += s + " "
				continue
			}
			code = append(code, snippet{contLine, cont + line})
			cont = ""
			continue
		}
		for _, m := range inlineCode.FindAllStringSubmatch(line, -1) {
			code = append(code, snippet{i + 1, m[1]})
		}
	}
	var out []docCommand
	for _, c := range code {
		for _, m := range reqcoveCmd.FindAllStringSubmatchIndex(c.s, -1) {
			if strings.HasPrefix(c.s[m[2]:m[3]], "--") { // claude mcp add reqcove -- …: a name
				continue
			}
			out = append(out, docCommand{c.line, shellWords(c.s[m[2]:])})
		}
	}
	return out
}

// shellWords splits s as a shell would, up to the end of its first command
// (a pipe, redirection, ; & ) or comment). Placeholders become values: $NAME
// and <name> stand for one, ~ is the shell's, … and [flags] mean more flags.
func shellWords(s string) []string {
	var out []string
	var w strings.Builder
	in, quoted, tilde := false, rune(0), false
	end := func() {
		if in {
			word := w.String()
			switch {
			case strings.Contains(word, "$") || regexp.MustCompile(`^<[^<>]+>$`).MatchString(word):
				word = "x"
			case tilde:
				word = "/home/you" + strings.TrimPrefix(word, "~")
			}
			out = append(out, strings.Trim(word, "[]"))
		}
		w.Reset()
		in, tilde = false, false
	}
loop:
	for _, r := range s {
		switch {
		case quoted != 0:
			if r == quoted {
				quoted = 0
			} else {
				w.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quoted, in = r, true
		case !in && r == '#', strings.ContainsRune("|;&<>)", r):
			break loop
		case r == ' ' || r == '\t':
			end()
		default:
			if !in && r == '~' {
				tilde = true
			}
			w.WriteRune(r)
			in = true
		}
	}
	end()
	return out
}

// parseDocumented parses words (a command and its arguments) with the
// command's own flags, as main would.
func parseDocumented(words []string) error {
	if slices.Contains(noFlags, words[0]) {
		if len(words) > 1 {
			return fmt.Errorf("%s takes nothing", words[0])
		}
		return nil
	}
	c, ok := commands[words[0]]
	if !ok {
		return fmt.Errorf("unknown command %q", words[0])
	}
	var fs *flag.FlagSet
	takeFlags = func(f *flag.FlagSet) { fs = f }
	c(context.Background(), nil) // stops at parseFlags, handing over its FlagSet
	takeFlags = nil
	fs.Init(fs.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var args []string
	for i, a := range words[1:] {
		if a == "…" || a == "..." || a == "flags" {
			if i > 0 && takesValue(fs, words[i]) {
				args = append(args, "x") // --state …: a value
			}
			continue // more flags
		}
		if strings.HasPrefix(a, "@") { // --allow-hosts @FILE: a file the reader has, not this test
			a = "host.example.com"
		}
		args = append(args, a)
	}
	if words[0] == "lan" && len(args) > 0 { // lan allow ADDR: its subcommand and address come before the flags
		if !slices.Contains([]string{"allow", "deny", "list"}, args[0]) {
			return fmt.Errorf("lan takes allow, deny or list, not %q", args)
		}
		n := 1
		if args[0] != "list" && len(args) > 1 && !strings.HasPrefix(args[1], "-") {
			n = 2
		}
		args = args[n:]
	}
	for i := 1; i < len(args); i++ { // NAME, N: a placeholder, valid for its flag
		if regexp.MustCompile(`^[A-Z][A-Z_]*$`).MatchString(args[i]) && isInt(fs, args[i-1]) {
			args[i] = "1"
		}
	}
	err := parseFlags(fs, args)
	if err == flag.ErrHelp {
		return nil
	}
	return err
}

func lookup(fs *flag.FlagSet, arg string) *flag.Flag {
	name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
	if !strings.HasPrefix(arg, "-") || hasValue {
		return nil
	}
	return fs.Lookup(name)
}

func takesValue(fs *flag.FlagSet, arg string) bool {
	f := lookup(fs, arg)
	if f == nil {
		return false
	}
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return !ok || !b.IsBoolFlag()
}

func isInt(fs *flag.FlagSet, arg string) bool {
	f := lookup(fs, arg)
	if f == nil {
		return false
	}
	g, ok := f.Value.(flag.Getter)
	if !ok {
		return false
	}
	_, isInt := g.Get().(int)
	return isInt
}

// TestDocCommands: the extraction itself, on the forms the docs use; a doc
// command it lost would go unchecked without failing.
func TestDocCommands(t *testing.T) {
	for in, want := range map[string]string{
		"```sh\nreqcove run --device iphone \\\n  --ui\n```":                                           "run --device iphone --ui",
		"```sh\ndocker run -d -v $NAME:/home/nonroot/.reqcove reqcove \\\n  run --hostname $NAME\n```": "run --hostname x",
		"`claude mcp add reqcove -- reqcove mcp --state ~/x`":                                          "mcp --state /home/you/x",
		"`reqcove har --host 'a b' > flows.har`":                                                       "har --host a b",
		"```sh\nreqcove run --ui   # a comment\n```":                                                   "run --ui",
		"`gh skill install x reqcove --pin \"$(reqcove version | cut -d' ' -f2)\"`":                    "version",
		"`docker build -t reqcove .` `go build -o reqcove ./cmd/reqcove`":                              "",
		"```text\nreqcove run ──▶ mitmproxy\n```":                                                      "",
	} {
		var got []string
		for _, c := range docCommands(in) {
			got = append(got, strings.Join(c.words, " "))
		}
		if strings.Join(got, "|") != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// The check itself finds what is wrong: a flag no command has, a command
// reqcove does not have, a value missing, a stray word.
func TestParseDocumentedRefuses(t *testing.T) {
	for _, words := range [][]string{
		{"run", "--no-such-flag"},
		{"no-such-command"},
		{"status", "--state"},
		{"har", "--host", "a", "stray"},
		{"version", "--json"},
		{"lan", "permit", "1.2.3.4"},
		{"lan", "allow", "1.2.3.4", "--no-such-flag"},
	} {
		if err := parseDocumented(words); err == nil {
			t.Errorf("reqcove %s: no error", strings.Join(words, " "))
		}
	}
}
