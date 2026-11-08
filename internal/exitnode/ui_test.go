package exitnode

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestUIGuard(t *testing.T) {
	phone := netip.MustParseAddr("100.64.0.1")
	p := &policy{
		devices: map[netip.Addr]Device{phone: {"nPHONE", "phone"}},
		self:    []netip.Addr{netip.MustParseAddr("100.64.0.9"), netip.MustParseAddr("fd7a:115c:a1e0::9")},
		names:   []string{"reqcove.tail-scale.ts.net", "reqcove"},
	}
	var got string
	g := uiGuard{policy: func() *policy { return p }, serve: func(w http.ResponseWriter, r *http.Request, id string) { got = id }}
	ask := func(method, host, from string) int {
		got = ""
		r := httptest.NewRequest(method, "/", nil)
		r.Host, r.RemoteAddr = host, from
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w.Code
	}
	for _, host := range []string{"reqcove", "REQCOVE", "reqcove.tail-scale.ts.net.", "reqcove:80", "100.64.0.9", "[fd7a:115c:a1e0::9]:80"} {
		if code := ask("GET", host, "100.64.0.1:5000"); code != 200 || got != "nPHONE" {
			t.Errorf("Host %q: %d, device %q", host, code, got)
		}
	}
	// A page the phone visits can point its own name at the node (DNS rebinding):
	// such a Host is refused before anything is read.
	for _, host := range []string{"evil.example", "evil.example:80", "100.64.0.1", "reqcove.evil.example", ""} {
		if code := ask("GET", host, "100.64.0.1:5000"); code != http.StatusMisdirectedRequest || got != "" {
			t.Errorf("Host %q: %d", host, code)
		}
	}
	if code := ask("POST", "reqcove", "100.64.0.1:5000"); code != http.StatusMethodNotAllowed || got != "" {
		t.Errorf("POST: %d", code)
	}
	if code := ask("GET", "reqcove", "100.64.0.7:5000"); code != http.StatusForbidden || got != "" {
		t.Errorf("not a --device: %d", code)
	}
}
