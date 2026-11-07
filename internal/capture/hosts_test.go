package capture

import (
	"regexp"
	"testing"
)

func TestHostRules(t *testing.T) {
	r, err := ParseAllowHosts([]string{"api.example.com,*.example-cdn.com", "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"api.example.com":          true,
		"API.Example.COM.":         true,
		"api.example.com:443":      true,
		"apixexample.com":          false, // a bare "." would match any character
		"api.example.com.evil.net": false,
		"notapi.example.com":       false,
		"example.com":              false,
		"example-cdn.com":          true,
		"img.example-cdn.com":      true,
		"a.b.example-cdn.com":      true,
		"evilexample-cdn.com":      false,
		"10.0.0.5":                 true,
		"10.0.0.50":                false,
		"mitm.it":                  false, // decrypted for the CA page, never recorded
	} {
		if got := r.Match(host); got != want {
			t.Errorf("Match(%q) = %v, want %v", host, got, want)
		}
	}
	// The same rules as mitmproxy sees them: "host:port", re.search.
	for _, p := range r.mitmAllowHosts() {
		regexp.MustCompile(p)
	}
	mitm := func(hostport string) bool {
		for _, p := range r.mitmAllowHosts() {
			if regexp.MustCompile(p).MatchString(hostport) {
				return true
			}
		}
		return false
	}
	for hp, want := range map[string]bool{
		"api.example.com:443":          true,
		"api.example.com.evil.net:443": false,
		"apixexample.com:443":          false,
		"img.example-cdn.com:443":      true,
		"mitm.it:80":                   true,
		"github.com:443":               false,
		"1.2.3.4:443":                  false,
	} {
		if got := mitm(hp); got != want {
			t.Errorf("mitmproxy allow_hosts on %q = %v, want %v", hp, got, want)
		}
	}

	none, _ := ParseAllowHosts(nil)
	if none.Match("api.example.com") || len(none.mitmAllowHosts()) != 1 {
		t.Errorf("no --allow-hosts must record nothing and decrypt only mitm.it: %v", none.mitmAllowHosts())
	}
	all, _ := ParseAllowHosts([]string{"*"})
	if !all.Match("anything.example") || all.mitmAllowHosts() != nil {
		t.Error(`"*" must allow everything and pass no allow_hosts`)
	}
	for _, bad := range []string{"api.example.com/x", "*.", "a..b", "exa mple.com", "[::1]"} {
		if _, err := ParseAllowHosts([]string{bad}); err == nil {
			t.Errorf("ParseAllowHosts(%q) accepted a bad host", bad)
		}
	}
}
