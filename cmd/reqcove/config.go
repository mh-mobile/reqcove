package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
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

// configFile returns the path given with --config (or -config) in args, if
// any; more than one is refused (only one would be read).
func configFile(args []string) (string, bool, error) {
	path, found := "", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "config" {
			continue
		}
		if found {
			return "", false, errors.New("--config once only: put the flags in one file")
		}
		found = true
		if hasValue {
			path = value
			continue
		}
		if i+1 >= len(args) {
			return "", false, errors.New("--config needs a file")
		}
		path = args[i+1]
		i++
	}
	return path, found, nil
}

// readConfig reads a --config file into flags: blank lines and lines starting
// with # are skipped; words split at spaces, kept together in '…' (as they
// are) or "…" (\" and \\ inside), as a shell would: --device "Taro's iPhone";
// a word starting with ~/ starts at the home directory.
// The file must be yours and not writable by others.
func readConfig(path string) (words []string, lines []int, err error) {
	// Opened once, checked and read through the same descriptor: no swap
	// between the check and the read; O_NONBLOCK so a FIFO cannot hang it.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("--config: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("--config: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("--config %s: not a plain file", path)
	}
	if fi.Size() > 1<<20 {
		return nil, nil, fmt.Errorf("--config %s: over 1 MiB", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return nil, nil, fmt.Errorf("--config %s: not yours: its flags decide what is recorded", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, nil, fmt.Errorf("--config %s: others can read or write it (chmod 600 %s): its flags decide what is recorded, and may hold --mask-values patterns", path, shellWord(path))
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("--config: %w", err)
	}
	home, _ := os.UserHomeDir()
	for n, line := range strings.Split(string(b), "\n") {
		ws, err := configWords(line, home)
		if err != nil {
			return nil, nil, fmt.Errorf("--config %s, line %d: %w", path, n+1, err)
		}
		for range ws {
			lines = append(lines, n+1)
		}
		words = append(words, ws...)
	}
	return words, lines, nil
}

// configWords splits a line; an unquoted word starting with ~/ starts at home.
func configWords(line, home string) ([]string, error) {
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
			if !in && home != "" && strings.HasPrefix(line[i:], "~/") { // as a shell would: --state ~/x
				w.WriteString(home) // in place of the ~; the / comes next
				in = true
				continue
			}
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
	words, lines, err := readConfig(path)
	if err != nil {
		return err
	}
	// Errors say the line, never a value (it may be a --mask-values pattern),
	// and do not exit or print run's usage.
	fs.Init(fs.Name(), flag.ContinueOnError)
	out := fs.Output()
	fs.SetOutput(io.Discard)
	err = fs.Parse(words)
	fs.Init(fs.Name(), flag.ExitOnError)
	fs.SetOutput(out)
	if err != nil {
		// The word that failed: the last one taken, or for bad syntax the next.
		i := len(words) - len(fs.Args()) - 1
		if strings.HasPrefix(err.Error(), "bad flag syntax") {
			i++
		}
		i = min(max(i, 0), len(lines)-1)
		return fmt.Errorf("--config %s, line %d: a flag or its value does not parse (run -h lists the flags)", path, lines[i])
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("--config %s, line %d: a word that is no flag's value (quote values with spaces, such as --device \"Taro's iPhone\")", path, lines[len(words)-fs.NArg()])
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
	var hosts []string // as hostsOnly takes them, without its log line (run logs it once)
	for _, spec := range *allowSpecs {
		for _, h := range strings.Split(spec, ",") {
			hosts = append(hosts, hostOf(strings.TrimSpace(h)))
		}
	}
	if allow, err := capture.ParseAllowHosts([]string{strings.Join(hosts, ",")}); err == nil && allow.All {
		return fmt.Errorf("--config %s: --allow-hosts '*' only on the command line (it records every site)", path)
	}
	return nil
}
