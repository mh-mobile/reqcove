package exitnode

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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
	g := uiGuard{policy: func() *policy { return p }, serve: func(w http.ResponseWriter, r *http.Request, id string, _ bool) { got = id }}
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
	// One of the user's own devices, carried or not, sees all; a --device of
	// another user, its own.
	p.own = map[netip.Addr]Device{netip.MustParseAddr("100.64.0.7"): {"nMAC", "macbook"}}
	var all bool
	g.serve = func(w http.ResponseWriter, r *http.Request, id string, a bool) { got, all = id, a }
	if code := ask("GET", "reqcove", "100.64.0.7:5000"); code != 200 || got != "nMAC" || !all {
		t.Errorf("own device: %d %q all=%v", code, got, all)
	}
	if code := ask("GET", "reqcove", "100.64.0.1:5000"); code != 200 || got != "nPHONE" || all {
		t.Errorf("--device of another user: %d %q all=%v", code, got, all)
	}
}

// mitmweb through the node: the user's own devices only, by the node's name,
// with Host kept (mitmweb's WebSocket origin check compares it) and upgrades
// relayed; a --device of another user, or anyone else, never gets it.
func TestWebRelay(t *testing.T) {
	var hosts []string
	mitmweb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts = append(hosts, r.Host)
		if r.Header.Get("Upgrade") == "websocket" {
			c, rw, _ := http.NewResponseController(w).Hijack()
			rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nhello")
			rw.Flush()
			c.Close()
			return
		}
		w.Write([]byte("mitmweb " + r.Method + " " + r.URL.RequestURI()))
	}))
	defer mitmweb.Close()
	me, phone := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("100.64.0.1")
	p := &policy{devices: map[netip.Addr]Device{phone: {"nPHONE", "phone"}}, own: map[netip.Addr]Device{me: {"nMAC", "macbook"}},
		self: []netip.Addr{netip.MustParseAddr("100.64.0.9")}, names: []string{"reqcove"}}
	relay := webRelay(func() *policy { return p }, mitmweb.Listener.Addr().String())
	ask := func(method, host, from string) (int, string) {
		r := httptest.NewRequest(method, "/?token=x", nil)
		r.Host, r.RemoteAddr = host, from
		w := httptest.NewRecorder()
		relay.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	if code, b := ask("POST", "reqcove:8081", "127.0.0.1:5000"); code != 200 || b != "mitmweb POST /?token=x" || hosts[len(hosts)-1] != "reqcove:8081" {
		t.Errorf("own device: %d %q, Host %v", code, b, hosts)
	}
	if code, _ := ask("GET", "reqcove:8081", "100.64.0.1:5000"); code != http.StatusForbidden {
		t.Errorf("a --device of another user: %d", code)
	}
	if code, _ := ask("GET", "evil.example:8081", "127.0.0.1:5000"); code != http.StatusMisdirectedRequest {
		t.Errorf("another Host: %d", code)
	}
	// A WebSocket upgrade goes through (a real server: the recorder cannot hijack).
	srv := httptest.NewServer(relay)
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("GET /updates HTTP/1.1\r\nHost: 100.64.0.9:8081\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	if !strings.HasPrefix(string(b), "HTTP/1.1 101") || !strings.HasSuffix(string(b), "hello") {
		t.Errorf("upgrade: %q", b)
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
		ui: uiGuard{policy: func() *policy { return p }, serve: func(w http.ResponseWriter, r *http.Request, id string, _ bool) { got = id + " " + r.URL.RequestURI() }}}
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
		ui: uiGuard{policy: func() *policy { return p }, serve: func(w http.ResponseWriter, r *http.Request, id string, _ bool) {
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

// The listeners: the page's takes a --device of another user too; mitmweb's,
// the user's own devices only.
func TestOnlyViewers(t *testing.T) {
	me := netip.MustParseAddr("127.0.0.1")
	for _, c := range []struct {
		p       *policy
		ownOnly bool
		want    bool
	}{
		{&policy{devices: map[netip.Addr]Device{me: {"nPHONE", "phone"}}}, false, true},
		{&policy{devices: map[netip.Addr]Device{me: {"nPHONE", "phone"}}}, true, false},
		{&policy{own: map[netip.Addr]Device{me: {"nMAC", "macbook"}}}, true, true},
		{&policy{}, false, false},
	} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l := onlyViewers{ln, func() *policy { return c.p }, c.ownOnly}
		accepted := make(chan bool, 1)
		go func() {
			conn, err := l.Accept()
			if err == nil {
				conn.Close()
			}
			accepted <- err == nil
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		wait := 300 * time.Millisecond // refused: closed, and still waiting for another
		if c.want {
			wait = 10 * time.Second // room for a slow CI under -race
		}
		var got bool
		select {
		case got = <-accepted:
		case <-time.After(wait):
		}
		conn.Close()
		ln.Close()
		if got != c.want {
			t.Errorf("own=%v devices=%v ownOnly=%v: accepted %v", c.p.own, c.p.devices, c.ownOnly, got)
		}
	}
}

// mitmweb for a phone on the Remote Proxy: plain requests and CONNECT (Safari's
// ws://) to the node's mitmweb port reach mitmweb, for the user's own devices
// only; a --device of another user gets 403 both ways.
func TestRemoteProxyWeb(t *testing.T) {
	mitmweb, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer mitmweb.Close()
	go http.Serve(mitmweb, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("mitmweb " + r.Host)) }))
	_, port, _ := net.SplitHostPort(mitmweb.Addr().String())
	me := netip.MustParseAddr("127.0.0.1")
	own := &policy{devices: map[netip.Addr]Device{me: {"nPHONE", "phone"}}, own: map[netip.Addr]Device{me: {"nPHONE", "phone"}},
		self: []netip.Addr{netip.MustParseAddr("100.64.0.9")}, names: []string{"reqcove"}}
	other := &policy{devices: own.devices, self: own.self, names: own.names}
	for _, c := range []struct {
		p    *policy
		want bool
	}{{own, true}, {other, false}} {
		p := c.p
		rp := &remoteProxy{policy: func() *policy { return p }, web: webRelay(func() *policy { return p }, mitmweb.Addr().String()), webAddr: mitmweb.Addr().String(),
			resolve: func(_ context.Context, h string) (netip.Addr, error) { return netip.ParseAddr(h) },
			dial: func(context.Context, verdict, string, netip.AddrPort) (net.Conn, error) {
				return nil, errors.New("no dialing in this test")
			}}
		srv := httptest.NewServer(rp)
		ask := func(req string) string {
			conn, err := net.Dial("tcp", srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.Write([]byte(req))
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			b, _ := io.ReadAll(conn)
			return string(b)
		}
		plain := ask("GET http://100.64.0.9:" + port + "/ HTTP/1.1\r\nHost: 100.64.0.9:" + port + "\r\nConnection: close\r\n\r\n")
		tunnel := ask("CONNECT 100.64.0.9:" + port + " HTTP/1.1\r\nHost: 100.64.0.9:" + port + "\r\n\r\nGET / HTTP/1.1\r\nHost: 100.64.0.9:" + port + "\r\nConnection: close\r\n\r\n")
		if got := strings.Contains(plain, "mitmweb 100.64.0.9:"+port) && strings.Contains(tunnel, "mitmweb 100.64.0.9:"+port); got != c.want {
			t.Errorf("own=%v: plain %q, tunnel %q", c.want, plain, tunnel)
		}
		if !c.want && (!strings.HasPrefix(plain, "HTTP/1.1 403") || !strings.HasPrefix(tunnel, "HTTP/1.1 403")) {
			t.Errorf("another user's device: plain %q, tunnel %q", plain, tunnel)
		}
		srv.Close()
	}
}

// The local proxy: this computer's own apps, as the device Local. A name that
// leads to this computer itself (or link-local) is refused unless /etc/hosts
// gives it (DNS rebinding); the LAN, VPNs and the tailnet go on, an address
// the app gives too. IPv6 is refused; 80/443 go to mitmproxy.
func TestLocalProxy(t *testing.T) {
	hosts := filepath.Join(t.TempDir(), "hosts")
	os.WriteFile(hosts, []byte("127.0.0.1 localhost\n127.0.0.1\tdev.test  # mine\n"), 0o600)
	old := hostsFile
	hostsFile = hosts
	defer func() { hostsFile = old }()
	names := map[string]string{"rebind.example": "127.0.0.1", "meta.example": "169.254.169.254", "dev.test": "127.0.0.1",
		"api.staging.corp": "10.1.2.3", "nas.lan": "192.168.1.5", "api.example.com": "203.0.113.5"}
	type dialed struct {
		v      verdict
		device string
		dst    string
	}
	var got []dialed
	rp := &remoteProxy{local: true, policy: func() *policy { return nil }, // no tailnet yet: the local proxy works all the same
		resolve: func(_ context.Context, h string) (netip.Addr, error) {
			if ip, ok := names[h]; ok {
				return netip.MustParseAddr(ip), nil
			}
			return netip.ParseAddr(h)
		},
		dial: func(_ context.Context, v verdict, device string, dst netip.AddrPort) (net.Conn, error) {
			got = append(got, dialed{v, device, dst.String()})
			return nil, errors.New("recorded")
		}}
	for _, c := range []struct {
		url  string
		want *dialed
	}{
		{"http://rebind.example/", nil},
		{"http://meta.example/", nil},
		{"http://dev.test:3000/", &dialed{direct, "local", "127.0.0.1:3000"}},
		{"http://dev.test/", &dialed{socks, "local", "127.0.0.1:80"}},
		{"http://api.staging.corp/", &dialed{socks, "local", "10.1.2.3:80"}},
		{"http://nas.lan:5000/", &dialed{direct, "local", "192.168.1.5:5000"}},
		{"http://192.168.1.10/", &dialed{socks, "local", "192.168.1.10:80"}},
		{"http://api.example.com:443/", &dialed{socks, "local", "203.0.113.5:443"}},
		{"http://100.64.0.9/", &dialed{direct, "local", "100.64.0.9:80"}},
		{"http://17.253.144.10/", &dialed{direct, "local", "17.253.144.10:80"}},
		{"http://[2001:db8::1]/", nil},
	} {
		got = nil
		r := httptest.NewRequest("GET", c.url, nil)
		r.RemoteAddr = "127.0.0.1:5000"
		w := httptest.NewRecorder()
		rp.ServeHTTP(w, r)
		switch {
		case c.want == nil && (len(got) != 0 || w.Code != http.StatusForbidden):
			t.Errorf("%s: dialed %v, %d", c.url, got, w.Code)
		case c.want != nil && (len(got) == 0 || got[0] != *c.want):
			t.Errorf("%s: dialed %v, want %v (%d)", c.url, got, *c.want, w.Code)
		}
	}
}

// A link with mitmweb's token, once mitmweb took it, goes on to the URL
// without it (with mitmweb's cookie): the password does not stay in the
// address bar or history. A wrong token, or another request, is untouched.
func TestWebRelayDropsToken(t *testing.T) {
	mitmweb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") == "PW" {
			http.SetCookie(w, &http.Cookie{Name: "mitmproxy-auth-8081", Value: "signed"})
			http.SetCookie(w, &http.Cookie{Name: "_mitmproxy_xsrf", Value: "x"})
		} else if r.URL.Query().Has("token") {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		w.Write([]byte("mitmweb page"))
	}))
	defer mitmweb.Close()
	me := netip.MustParseAddr("127.0.0.1")
	p := &policy{own: map[netip.Addr]Device{me: {"nMAC", "macbook"}}, self: []netip.Addr{netip.MustParseAddr("100.64.0.9")}, names: []string{"reqcove"}}
	relay := webRelay(func() *policy { return p }, mitmweb.Listener.Addr().String())
	ask := func(url string, navigate ...bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", url, nil)
		r.Host, r.RemoteAddr = "reqcove:8081", "127.0.0.1:5000"
		if len(navigate) == 0 || navigate[0] {
			r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8") // Safari opening the link
		}
		w := httptest.NewRecorder()
		relay.ServeHTTP(w, r)
		return w
	}
	w := ask("/a%2Fb?z=2&token=PW&a=1")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/a%2Fb?z=2&a=1" || len(w.Header().Values("Set-Cookie")) != 2 || strings.Contains(w.Body.String(), "mitmweb page") {
		t.Errorf("with the token: %d %v %q", w.Code, w.Header(), w.Body.String())
	}
	if w := ask("/?token=PW", false); w.Code != 200 || w.Body.String() != "mitmweb page" {
		t.Errorf("an API call (no navigation): %d %q", w.Code, w.Body.String())
	}
	if w := ask("/?token=wrong"); w.Code != http.StatusForbidden {
		t.Errorf("a wrong token: %d", w.Code)
	}
	if w := ask("/flows"); w.Code != 200 || w.Body.String() != "mitmweb page" {
		t.Errorf("another request: %d %q", w.Code, w.Body.String())
	}
}
