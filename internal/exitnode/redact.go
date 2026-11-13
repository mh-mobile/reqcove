package exitnode

import (
	"io"
	"regexp"
	"strings"
	"sync"
)

// Redactor is run's log output: every secret added, and any login URL of the
// control server (tsnet logs it under --verbose before run's first poll learns
// it), replaced before a line is written.
type Redactor struct {
	W       io.Writer
	mu      sync.Mutex
	secrets []string
}

// loginURLs: Tailscale's (/a/<hex>), testcontrol's (/auth/<hex>) and
// Headscale's (/register/…, older ones /register?key=…) login URLs, as
// tsnet's lines quote them (authURL=…, "AuthURL is …", "go to: …"). A path
// such as /auth/login is not one.
var loginURLs = regexp.MustCompile(`https?://[^\s"'<>]*/(?:(?:a|auth)/[0-9a-f]{8,}|register/|register\?key=)[^\s"'<>]*`)

// RedactedLink replaces a login URL in the log.
const RedactedLink = "[a link: `reqcove links` prints it]"

// Add adds secrets; short ones (and "") are ignored.
func (r *Redactor) Add(secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range secrets {
		if len(s) >= 8 { // never "": ReplaceAll would put the mark between every byte
			r.secrets = append(r.secrets, s)
		}
	}
}

func (r *Redactor) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := loginURLs.ReplaceAllString(string(p), RedactedLink)
	for _, v := range r.secrets {
		s = strings.ReplaceAll(s, v, "[redacted]")
	}
	if _, err := io.WriteString(r.W, s); err != nil {
		return 0, err
	}
	return len(p), nil
}
