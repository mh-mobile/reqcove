package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// --config FILE: run's flags, one a line, for a service (brew services takes
// no arguments). The command line's come after them: a flag given once is the
// command line's, a repeatable one (--device, --allow-hosts) adds up. Flags
// that take masking off, record everything, show traffic unmasked or let a
// file change where requests go while running are refused there: they stay on
// the command line, where someone typed them. Never read unless named.

// configOnlyOnCommandLine are refused in a --config file.
var configOnlyOnCommandLine = map[string]string{
	"no-redact":    "it keeps secrets unmasked",
	"web":          "mitmweb shows traffic unmasked",
	"rules-reload": "whatever can write the rules file could then change where requests go",
	"config":       "one file only",
}

// configFile returns the path given with --config (or -config) in args, if any.
func configFile(args []string) (string, bool, error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "config" {
			continue
		}
		if hasValue {
			return value, true, nil
		}
		if i+1 >= len(args) {
			return "", false, errors.New("--config needs a file")
		}
		return args[i+1], true, nil
	}
	return "", false, nil
}

// readConfig reads a --config file into flags: blank lines and lines starting
// with # are skipped; words split at spaces, kept together in '…' (as they
// are) or "…" (\" and \\ inside), as a shell would: --device "Taro's iPhone";
// a word starting with ~/ starts at the home directory.
// The file must be yours and not writable by others.
func readConfig(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("--config: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("--config %s: not a plain file", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return nil, fmt.Errorf("--config %s: not yours: its flags decide what is recorded", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("--config %s: writable by others (chmod 600 %s): its flags decide what is recorded", path, shellWord(path))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--config: %w", err)
	}
	var out []string
	for n, line := range strings.Split(string(b), "\n") {
		words, err := configWords(line)
		if err != nil {
			return nil, fmt.Errorf("--config %s, line %d: %w", path, n+1, err)
		}
		out = append(out, words...)
	}
	for i, w := range out {
		if rest, ok := strings.CutPrefix(w, "~/"); ok { // as a shell would: --state ~/x
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			out[i] = filepath.Join(home, rest)
		}
	}
	return out, nil
}

func configWords(line string) ([]string, error) {
	var words []string
	var w strings.Builder
	in := false // a word is under way (an empty '' is one too)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			if in {
				words = append(words, w.String())
				w.Reset()
				in = false
			}
		case c == '#' && !in:
			return words, nil
		case c == '\'':
			j := strings.IndexByte(line[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("a ' is not closed")
			}
			w.WriteString(line[i+1 : i+1+j])
			i += j + 1
			in = true
		case c == '"':
			i++
			for ; i < len(line) && line[i] != '"'; i++ {
				if line[i] == '\\' && i+1 < len(line) && (line[i+1] == '"' || line[i+1] == '\\') {
					i++
				}
				w.WriteByte(line[i])
			}
			if i >= len(line) {
				return nil, errors.New(`a " is not closed`)
			}
			in = true
		default:
			w.WriteByte(c)
			in = true
		}
	}
	if in {
		words = append(words, w.String())
	}
	return words, nil
}

// parseConfig parses a --config file's flags into fs before the command
// line's, and refuses those that stay on the command line. allowSpecs is
// --allow-hosts so far (the file's), checked after @FILE is read: '*' there
// is refused however it is spelled.
func parseConfig(fs *flag.FlagSet, path string, allowSpecs *[]string) error {
	words, err := readConfig(path)
	if err != nil {
		return err
	}
	if err := fs.Parse(words); err != nil {
		return fmt.Errorf("--config %s: %w", path, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("--config %s: %q is not a flag (quote values with spaces, such as --device \"Taro's iPhone\")", path, fs.Arg(0))
	}
	var refused error
	fs.Visit(func(f *flag.Flag) {
		if why, ok := configOnlyOnCommandLine[f.Name]; ok && refused == nil {
			refused = fmt.Errorf("--config %s: --%s only on the command line (%s)", path, f.Name, why)
		}
	})
	if refused != nil {
		return refused
	}
	if allow, err := capture.ParseAllowHosts(hostsOnly("--allow-hosts", *allowSpecs)); err == nil && allow.All {
		return fmt.Errorf("--config %s: --allow-hosts '*' only on the command line (it records every site)", path)
	}
	return nil
}
