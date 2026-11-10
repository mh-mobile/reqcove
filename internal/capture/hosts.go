package capture

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// HostRules is which hosts reqcove decrypts and records (--allow-hosts).
// The zero value allows nothing.
type HostRules struct {
	All      bool     // "*": everything (except Apple's hosts)
	Patterns []string // anchored regexps over a lowercase host without port
	Hosts    []string // the specs as given, lowercased: what the status tool shows
	res      []*regexp.Regexp
	// Pass (--pass-hosts) are allowed hosts carried undecrypted: not recorded
	// as flows, only their connections' metadata. Set with WithPass.
	Pass      []string // anchored regexps, as Patterns
	PassHosts []string // the specs as given
	passRes   []*regexp.Regexp
}

// WithPass adds --pass-hosts specs (as --allow-hosts', but "*" is refused:
// passing everything is not recording anything).
func (r HostRules) WithPass(specs []string) (HostRules, error) {
	p, err := ParseAllowHosts(specs)
	if err != nil {
		return r, fmt.Errorf("--pass-hosts: %w", err)
	}
	if p.All {
		return r, errors.New("--pass-hosts: not \"*\": leave out --allow-hosts instead, and nothing is decrypted")
	}
	r.Pass, r.PassHosts, r.passRes = p.Patterns, p.Hosts, p.res
	return r, nil
}

// Passed reports whether host is one of --pass-hosts.
func (r HostRules) Passed(host string) bool {
	host = normHost(host)
	for _, re := range r.passRes {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

// Allowed reports whether host is in --allow-hosts, --pass-hosts or not:
// whether anything about it may be recorded.
func (r HostRules) Allowed(host string) bool {
	if r.All {
		return true
	}
	host = normHost(host)
	for _, re := range r.res {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

func normHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if h, _, ok := strings.Cut(host, ":"); ok && !strings.Contains(h, ":") {
		host = h // drop a port
	}
	return host
}

// ParseAllowHosts turns --allow-hosts specs into rules. A spec is a host
// ("api.example.com"), a wildcard for a domain and its subdomains
// ("*.example.com"), an IPv4 address, or "*" for everything.
func ParseAllowHosts(specs []string) (HostRules, error) {
	var r HostRules
	for _, spec := range specs {
		for _, h := range strings.Split(spec, ",") {
			raw := strings.ToLower(strings.TrimSpace(h))
			h = strings.TrimSuffix(raw, ".")
			if h != raw && (h == "*" || h == "") {
				return r, fmt.Errorf("--allow-hosts: bad host %q", raw) // "*." must not mean "*"
			}
			if h != "" {
				r.Hosts = append(r.Hosts, h)
			}
			switch {
			case h == "":
			case h == "*":
				r.All = true
			case strings.HasPrefix(h, "*."):
				if !validHost(h[2:]) {
					return r, fmt.Errorf("--allow-hosts: bad host %q", h)
				}
				r.Patterns = append(r.Patterns, `^(.+\.)?`+regexp.QuoteMeta(h[2:])+`$`)
			case strings.HasPrefix(h, "."):
				return r, fmt.Errorf("--allow-hosts: bad host %q (for the domain and its subdomains, write *%s)", h, h)
			default:
				if !validHost(h) {
					return r, fmt.Errorf("--allow-hosts: bad host %q", h)
				}
				r.Patterns = append(r.Patterns, `^`+regexp.QuoteMeta(h)+`$`)
			}
		}
	}
	for _, p := range r.Patterns {
		r.res = append(r.res, regexp.MustCompile(p))
	}
	return r, nil
}

func validHost(h string) bool {
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Is4()
	}
	if strings.Contains(h, "..") || strings.HasPrefix(h, ".") || strings.HasPrefix(h, "-") {
		return false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return h != ""
}

// Match reports whether host (as in the Host header or SNI) is recorded as
// flows: allowed, and not passed through.
func (r HostRules) Match(host string) bool {
	return r.Allowed(host) && !r.Passed(host)
}

// mitmAllowHosts is the value for mitmproxy's allow_hosts, which matches
// "host:port" strings with re.search: anchored, with an optional port.
// mitm.it, where iPhones get the CA, is always decrypted (and never recorded).
// nil means "decrypt everything" (All).
func (r HostRules) mitmAllowHosts() []string {
	if r.All {
		return nil
	}
	out := []string{`^mitm\.it(:\d+)?$`}
	for _, p := range r.Patterns {
		out = append(out, strings.TrimSuffix(p, "$")+`(:\d+)?$`)
	}
	return out
}
