package main

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// hostsOnly takes the hosts out of --allow-hosts values pasted as URLs or with
// a port, saying so: only hosts are matched, not schemes, paths or ports.
// hostList is a --allow-hosts or --pass-hosts value: as given, or with @FILE
// the hosts in the file, one a line (or comma-separated), # starting a
// comment. @~/ is the home directory: the shell expands no ~ after @.
func hostList(v string) (string, error) {
	path, ok := strings.CutPrefix(v, "@")
	if !ok {
		return v, nil
	}
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, rest)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err // the flag package names the flag and the value
	}
	var hosts []string
	for i, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		// Checked here, by line number only: a wrong file (.env, say) must not
		// have its lines, secrets maybe, printed back.
		for _, h := range strings.Split(line, ",") {
			if _, err := capture.ParseAllowHosts([]string{hostOf(strings.TrimSpace(h))}); err != nil {
				return "", fmt.Errorf("%s line %d is not a host list (one host a line, as the flag writes them)", path, i+1)
			}
		}
		hosts = append(hosts, line)
	}
	if len(hosts) == 0 {
		return "", fmt.Errorf("%s has no hosts", path)
	}
	return strings.Join(hosts, ","), nil
}

// hostOf is the host in a value given for one: a URL's, or host:port's.
func hostOf(h string) string {
	if u, err := url.Parse(h); err == nil && strings.Contains(h, "://") && u.Hostname() != "" {
		return u.Hostname()
	}
	if hh, port, err := net.SplitHostPort(h); err == nil && port != "" {
		return hh
	}
	return h
}

func hostsOnly(flagName string, specs []string) []string {
	var out []string
	for _, spec := range specs {
		var hosts []string
		for _, h := range strings.Split(spec, ",") {
			h = strings.TrimSpace(h)
			host, shown := hostOf(h), h
			if u, err := url.Parse(h); err == nil && strings.Contains(h, "://") && u.Hostname() != "" {
				shown = u.Scheme + "://" + u.Host + "/…" // a pasted URL's path and query can hold a token
			}
			if host != h {
				log.Printf("%s: %q taken as %q (hosts are matched, not paths or ports)", flagName, shown, host)
			}
			hosts = append(hosts, host)
		}
		out = append(out, strings.Join(hosts, ","))
	}
	return out
}

// nameRE is a --mask-names name: a header's, a parameter's or a field's.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// maskPolicy reads --mask-names and --mask-values: as given, or with @FILE
// one a line (# starting a comment line; names may also be comma-separated).
// Errors name a file's line by number only, and never quote a pattern.
func maskPolicy(nameSpecs, valueSpecs []string) (names, values []string, err error) {
	for _, v := range nameSpecs {
		lines, path, err := specLines(v, "--mask-names")
		if err != nil {
			return nil, nil, err
		}
		for i, line := range lines {
			for _, n := range strings.Split(line, ",") {
				if n = strings.TrimSpace(n); n == "" {
					continue
				}
				if !nameRE.MatchString(n) {
					if path != "" {
						return nil, nil, fmt.Errorf("--mask-names: %s line %d is not a list of names", path, i+1)
					}
					return nil, nil, fmt.Errorf("--mask-names: %q is not a name (letters, digits, -, _ and . only)", n)
				}
				names = append(names, n)
			}
		}
	}
	for _, v := range valueSpecs {
		lines, _, err := specLines(v, "--mask-values")
		if err != nil {
			return nil, nil, err
		}
		values = append(values, lines...)
	}
	return names, values, nil
}

// specLines is v itself, or with @FILE the file's lines that are not blank
// or a comment (#), and the file's path.
func specLines(v, flag string) ([]string, string, error) {
	path, ok := strings.CutPrefix(v, "@")
	if !ok {
		return []string{v}, "", nil
	}
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, "", err
		}
		path = filepath.Join(home, rest)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", flag, err)
	}
	var lines []string
	for line := range strings.Lines(string(b)) {
		if line = strings.TrimRight(line, "\r\n"); strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil, "", fmt.Errorf("%s: %s is empty", flag, path)
	}
	return lines, path, nil
}

// pythonBelow says a --python value names a version below major.minor
// ("3.12", "3.12.4", "python3.12"); anything else (a path) is not judged.
func pythonBelow(v string, major, minor int) bool {
	m := regexp.MustCompile(`(\d+)\.(\d+)`).FindStringSubmatch(v)
	if m == nil {
		return false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	return a < major || a == major && b < minor
}
