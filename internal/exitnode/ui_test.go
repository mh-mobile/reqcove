package exitnode

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
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

// A phone on the Remote Proxy sends the page's requests to it: requests for the
// node's port 80 reach the page, others to the node are still not carried.
func TestRemoteProxyServesPage(t *testing.T) {
	phone := netip.MustParseAddr("100.64.0.1")
	p := &policy{devices: map[netip.Addr]Device{phone: {"nPHONE", "phone"}}, allowSrc: []netip.Addr{phone},
		self: []netip.Addr{netip.MustParseAddr("100.64.0.9")}, names: []string{"reqcove"}}
	var got string
	rp := &remoteProxy{policy: func() *policy { return p },
		resolve: func(_ context.Context, h string) (netip.Addr, error) { return netip.ParseAddr(h) },
		dial: func(context.Context, verdict, string, netip.AddrPort) (net.Conn, error) {
			return nil, errors.New("no dialing in this test")
		},
		ui: uiGuard{policy: func() *policy { return p }, serve: func(w http.ResponseWriter, r *http.Request, id string) { got = id + " " + r.URL.RequestURI() }}}
	for _, c := range []struct {
		method, url string
		page        bool
	}{{"GET", "http://100.64.0.9/?k=x", true}, {"GET", "http://reqcove/flow?id=1", true}, {"GET", "http://100.64.0.9:80/", true}, {"GET", "http://100.64.0.9:8081/", false}, {"POST", "http://reqcove/", false}} {
		got = ""
		r := httptest.NewRequest(c.method, c.url, nil)
		r.RemoteAddr = "100.64.0.1:5000"
		w := httptest.NewRecorder()
		rp.ServeHTTP(w, r)
		if (got != "") != c.page || c.method == "POST" && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: page %q, status %d", c.method, c.url, got, w.Code)
		}
	}
}

// The page on the Remote Proxy has a write deadline, and it does not outlast
// the page: the next request on the same keep-alive connection, not a page and
// past that deadline, still gets its answer.
func TestRemoteProxyPageDeadline(t *testing.T) {
	old := pageWriteTimeout
	pageWriteTimeout = 300 * time.Millisecond // room for a slow CI under -race
	defer func() { pageWriteTimeout = old }()
	me := netip.MustParseAddr("127.0.0.1")
	p := &policy{devices: map[netip.Addr]Device{me: {"nPHONE", "phone"}}, allowSrc: []netip.Addr{me},
		self: []netip.Addr{netip.MustParseAddr("100.64.0.9")}}
	rp := &remoteProxy{policy: func() *policy { return p },
		resolve: func(_ context.Context, h string) (netip.Addr, error) { return netip.ParseAddr(h) },
		dial: func(context.Context, verdict, string, netip.AddrPort) (net.Conn, error) {
			return nil, errors.New("no dialing in this test")
		},
		ui: uiGuard{policy: func() *policy { return p }, serve: func(w http.ResponseWriter, r *http.Request, id string) {
			if r.URL.Path == "/slow" {
				time.Sleep(4 * pageWriteTimeout)
			}
			w.Write([]byte("page"))
		}}}
	srv := httptest.NewServer(rp)
	defer srv.Close()
	ask := func(c net.Conn, br *bufio.Reader, url string) error {
		if _, err := c.Write([]byte("GET " + url + " HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
			return err
		}
		r, err := http.ReadResponse(br, nil)
		if err == nil {
			r.Body.Close()
		}
		return err
	}
	dial := func() (net.Conn, *bufio.Reader) {
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c, bufio.NewReader(c)
	}
	c, br := dial()
	if err := ask(c, br, "http://100.64.0.9/slow"); err == nil {
		t.Error("a page written past its deadline was answered")
	}
	c, br = dial()
	if err := ask(c, br, "http://100.64.0.9/"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * pageWriteTimeout)
	if err := ask(c, br, "http://192.0.2.1/"); err != nil {
		t.Errorf("the next request on the connection: %v", err)
	}
}
