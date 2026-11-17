package exitnode

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// The tailnet page through the Remote Proxy (a phone whose Wi-Fi proxy is the
// node's :8080): a request to the page's address and port goes to the page's
// own handler in-process, as it came (its RemoteAddr the proxy client's, no
// header added), for one of this user's own devices alone. Another user's
// --device phone is refused, also with a forwarded header naming an own
// device; so are the local proxy, LAN mode and CONNECT to the page's port,
// none of them dialed. Once the run ends, nothing is relayed.
func TestRemoteProxyRelaysConsole(t *testing.T) {
	mine, other := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")
	devices := map[netip.Addr]Device{mine: {"nMINE", "iphone"}, other: {"nOTHER", "colleague"}}
	p := &policy{devices: devices, own: map[netip.Addr]Device{mine: devices[mine]}, allowSrc: []netip.Addr{mine, other, netip.MustParseAddr("127.0.0.1")},
		self: []netip.Addr{netip.MustParseAddr("100.64.0.9")}, names: []string{"reqcove"}, socks: true}
	var mu sync.Mutex
	var got []*http.Request
	var dials []netip.AddrPort
	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r)
		mu.Unlock()
		fmt.Fprint(w, "page")
	})
	rp := func(local bool) *remoteProxy {
		return &remoteProxy{local: local, policy: func() *policy { return p },
			resolve: func(_ context.Context, h string) (netip.Addr, error) { return netip.ParseAddr(h) },
			dial: func(_ context.Context, _ verdict, _ string, dst netip.AddrPort) (net.Conn, error) {
				mu.Lock()
				dials = append(dials, dst)
				mu.Unlock()
				return nil, errors.New("no dialing in this test")
			}}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	RelayConsole(ctx, "100.64.0.9:47001", page)
	ask := func(rp *remoteProxy, method, target, from string, h http.Header) (int, string, *http.Request) {
		t.Helper()
		mu.Lock()
		got, dials = nil, nil
		mu.Unlock()
		r := httptest.NewRequest(method, target, nil)
		if method == http.MethodConnect {
			r = httptest.NewRequest(method, "/", nil)
			r.Host, r.URL = target, &url.URL{Host: target}
		}
		maps.Copy(r.Header, h)
		r.RemoteAddr = from
		w := httptest.NewRecorder()
		rp.ServeHTTP(w, r)
		mu.Lock()
		defer mu.Unlock()
		if len(dials) > 0 {
			t.Errorf("%s %s from %s: dialed %v", method, target, from, dials)
		}
		var in *http.Request
		if len(got) > 0 {
			in = got[0]
		}
		return w.Code, w.Body.String(), in
	}

	// An own device: the page gets the request as it came.
	code, body, in := ask(rp(false), "GET", "http://100.64.0.9:47001/api/state", "100.64.0.1:5000", nil)
	if code != 200 || body != "page" || in == nil {
		t.Fatalf("own device: %d %q", code, body)
	}
	if in.RemoteAddr != "100.64.0.1:5000" || in.Host != "100.64.0.9:47001" || in.URL.Path != "/api/state" {
		t.Errorf("the page got %s %s %s", in.RemoteAddr, in.Host, in.URL)
	}
	for _, name := range []string{"X-Forwarded-For", "Forwarded", "X-Real-Ip", "Via"} {
		if v := in.Header.Values(name); len(v) > 0 {
			t.Errorf("a header added: %s: %v", name, v)
		}
	}
	// iOS sends the link's #fragment (the page's code) to the proxy: the page
	// gets the path without it, and nothing after # goes on.
	for target, want := range map[string]string{"http://100.64.0.9:47001/#c=abc": "/", "http://100.64.0.9:47001/api/state?x=1#c=abc": "/api/state?x=1"} {
		if code, _, in := ask(rp(false), "GET", target, "100.64.0.1:5000", nil); code != 200 || in == nil || in.URL.RequestURI() != want || strings.Contains(in.URL.String(), "abc") {
			t.Errorf("%s: %d, the page got %v", target, code, in)
		}
	}
	// By the node's name: the page itself refuses a name (its exact Host).
	if code, _, in := ask(rp(false), "GET", "http://reqcove:47001/", "100.64.0.1:5000", nil); code != 200 || in == nil {
		t.Errorf("by name: %d, to the page %v", code, in != nil)
	}

	forwarded := http.Header{"X-Forwarded-For": {"100.64.0.1"}, "Forwarded": {"for=100.64.0.1"}, "X-Real-Ip": {"100.64.0.1"}}
	for _, c := range []struct {
		what         string
		rp           *remoteProxy
		method, from string
		h            http.Header
		lan          bool
		want         string
	}{
		{"another user's --device phone", rp(false), "GET", "100.64.0.2:5000", nil, false, "your own devices only"},
		{"another user's, a forwarded header naming an own device", rp(false), "GET", "100.64.0.2:5000", forwarded, false, "your own devices only"},
		{"the local proxy", rp(true), "GET", "127.0.0.1:5000", nil, false, "not served through the local proxy"},
		{"the local proxy, CONNECT", rp(true), "CONNECT", "127.0.0.1:5000", nil, false, "never tunneled"},
		{"LAN mode", rp(false), "GET", "100.64.0.1:5000", nil, true, "not served through the local proxy or in LAN mode"},
		{"CONNECT", rp(false), "CONNECT", "100.64.0.1:5000", nil, false, "never tunneled"},
	} {
		p.lan = c.lan
		target := "http://100.64.0.9:47001/"
		if c.method == "CONNECT" {
			target = "100.64.0.9:47001"
		}
		code, body, in := ask(c.rp, c.method, target, c.from, c.h)
		if code != http.StatusForbidden || !strings.Contains(body, c.want) || in != nil {
			t.Errorf("%s: %d %q, to the page %v", c.what, code, body, in != nil)
		}
	}
	p.lan = false

	// Another port of the node is not the page's; after the run, nothing is relayed.
	if code, _, in := ask(rp(false), "GET", "http://100.64.0.9:47002/", "100.64.0.1:5000", nil); in != nil || code != http.StatusForbidden {
		t.Errorf("another port: %d, to the page %v", code, in != nil)
	}
	cancel()
	waitFor(t, func() bool { return consoleRelay.Load() == nil }, "the relay ended with its context")
	if code, _, in := ask(rp(false), "GET", "http://100.64.0.9:47001/", "100.64.0.1:5000", nil); in != nil || code != http.StatusForbidden {
		t.Errorf("after the run: %d, to the page %v", code, in != nil)
	}
}

// TestConsoleRelayNoFlowE2E (REQCOVE_E2E=1, real mitmproxy): under allow-all,
// a request to example.org through the Remote Proxy is recorded, and the
// tailnet page's through the same proxy is answered by the page and makes no
// flow (it never reaches mitmproxy). Live allow-all (capture allow-all's), its
// base example.com: example.org is recorded through allow-all alone.
func TestConsoleRelayNoFlowE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "rcvc-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	allow, _ := capture.ParseAllowHosts([]string{"example.com"})
	c, err := capture.Start(ctx, capture.Config{AllowHosts: allow,
		Dir: dir, Confdir: t.TempDir(), Uvx: "uvx", Python: "3.14", MitmSpec: "mitmproxy==12.3.1",
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes, Log: os.Stderr, ReadyTimeout: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	if _, _, err := c.SetAllowAll(ctx, "test", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	me := netip.MustParseAddr("127.0.0.1")
	p := &policy{devices: map[netip.Addr]Device{me: {"nMINE", "iphone"}}, own: map[netip.Addr]Device{me: {"nMINE", "iphone"}},
		allowSrc: []netip.Addr{me}, self: []netip.Addr{netip.MustParseAddr("100.64.0.9")}, socks: true}
	cfg := Config{SocksAddr: c.SocksAddr, SocksSecret: c.SocksSecret, SocksReady: c.WaitReady}
	srv := httptest.NewServer(&remoteProxy{policy: func() *policy { return p }, resolve: resolver(nil), dial: cfg.dial})
	defer srv.Close()
	rctx, rcancel := context.WithCancel(ctx)
	defer rcancel()
	RelayConsole(rctx, "100.64.0.9:47001", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "page")
	}))
	pu, _ := url.Parse(srv.URL)
	hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: time.Minute}
	get := func(u string, h http.Header) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", u, nil)
		maps.Copy(req.Header, h)
		r, err := hc.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	if code, body := get("http://100.64.0.9:47001/api/state", http.Header{capture.ConsoleSessionHeader: {"a-session-token"}}); code != 200 || body != "page" {
		t.Fatalf("the page through the proxy: %d %q", code, body)
	}
	if code, _ := get("http://example.org/?relay=control", nil); code >= 400 {
		t.Fatalf("example.org: %d", code)
	}
	waitFor(t, func() bool {
		fs, _ := c.Store.List(capture.Filter{Limit: 50})
		return slices.ContainsFunc(fs, func(f capture.Summary) bool { return strings.Contains(f.URL, "relay=control") })
	}, "example.org recorded under allow-all")
	fs, _ := c.Store.List(capture.Filter{Limit: 50})
	for _, f := range fs {
		if strings.Contains(f.URL, "100.64.0.9") || strings.Contains(f.URL, "47001") {
			t.Errorf("the page's request made a flow: %s", f.URL)
		}
	}
}

// dropFragment cuts the raw request-target at its first literal '#': a
// fragment holding '?' sends nothing on (Go would read it as the query), and
// an escaped %23 stays the path's.
func TestDropFragment(t *testing.T) {
	for target, want := range map[string]string{
		"http://example.com/#/callback?access_token=SECRET":  "/",
		"http://example.com/a?b=1#c?d=SECRET":                "/a?b=1",
		"http://example.com/files/report%23draft?download=1": "/files/report%23draft?download=1",
		"http://example.com/plain?q=1":                       "/plain?q=1",
	} {
		r := httptest.NewRequest("GET", target, nil)
		if !dropFragment(r) || r.URL.RequestURI() != want || strings.Contains(r.URL.String(), "SECRET") || r.URL.Host != "example.com" {
			t.Errorf("%s: %q (%s)", target, r.URL.RequestURI(), r.URL)
		}
	}
}
