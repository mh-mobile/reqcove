package capture

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// pinClient talks to the stand-in server through mitmproxy as device, with
// name as the SNI.
type pinClient struct {
	h     *harness
	addr  string // the stand-in server
	split bool   // the ClientHello arrives in two pieces, as over the tailnet's MTU
}

func (p pinClient) dial(ctx context.Context, device string) (net.Conn, error) {
	socks, _ := proxy.SOCKS5("tcp", p.h.c.SocksAddr, &proxy.Auth{User: device, Password: p.h.c.SocksSecret}, proxy.Direct)
	c, err := socks.(proxy.ContextDialer).DialContext(ctx, "tcp", p.addr)
	if err == nil && p.split {
		c = &splitConn{Conn: c}
	}
	return c, err
}

type splitConn struct {
	net.Conn
	done bool
}

func (c *splitConn) Write(b []byte) (int, error) {
	if c.done || len(b) < 100 {
		return c.Conn.Write(b)
	}
	c.done = true
	n, err := c.Conn.Write(b[:len(b)/3])
	if err != nil {
		return n, err
	}
	time.Sleep(50 * time.Millisecond)
	m, err := c.Conn.Write(b[len(b)/3:])
	return n + m, err
}

// get makes one request on a new connection; it returns the body and the issuer the client saw.
func (p pinClient) get(device, name string, cfg *tls.Config) (string, string, error) {
	cfg = cfg.Clone()
	cfg.ServerName = name
	c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext:       func(ctx context.Context, _, _ string) (net.Conn, error) { return p.dial(ctx, device) },
		TLSClientConfig:   cfg,
		DisableKeepAlives: true,
	}}
	r, err := c.Get("https://" + p.addr + "/")
	if err != nil {
		return "", "", err
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b), r.TLS.PeerCertificates[0].Issuer.String(), nil
}

func waitPass(st *Store, host string, done bool) []PassthroughView {
	var pt []PassthroughView
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		pt = st.Passthroughs(Filter{Host: host, Limit: 10})
		if len(pt) > 0 && pt[0].Open != done {
			return pt
		}
	}
	return pt
}

// TestPassHosts (REQCOVE_E2E=1): a --pass-hosts host is carried undecrypted to
// its own server, so an app that pins its certificate works; its connection
// is recorded (host, server, times, bytes, offered protocols) but no flow;
// the other allowed hosts are decrypted as before; a pass host outside
// --allow-hosts leaves nothing.
func TestPassHosts(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// The app's server, with its own certificate (httptest's: example.com, 127.0.0.1).
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			io.WriteString(w, strings.Repeat("d", 64<<10))
			return
		}
		fmt.Fprint(w, "real server")
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	pin := x509.NewCertPool()
	pin.AddCert(srv.Certificate())
	pinned := &tls.Config{RootCAs: pin, NextProtos: []string{"http/1.1"}} // the app pins: only its server's certificate

	h, err := tryHarness(t, ctx, []string{"*.example.com", "trusted.example.net", "*.apple.com"}, func(c *Config) {
		var err error
		if c.AllowHosts, err = c.AllowHosts.WithPass([]string{"example.com", "other.org", "www.apple.com"}); err != nil {
			t.Fatal(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := os.ReadFile(filepath.Join(h.confdir, "mitmproxy-ca-cert.pem"))
	mitm := x509.NewCertPool()
	mitm.AppendCertsFromPEM(ca)
	p := pinClient{h: h, addr: srv.Listener.Addr().String()}

	// The pass host: through to the real server, its own certificate.
	body, issuer, err := p.get("dev", "example.com", pinned)
	if err != nil || body != "real server" || strings.Contains(issuer, "mitmproxy") {
		t.Fatalf("pass host: %v %q (issuer %q)", err, body, issuer)
	}
	pt := waitPass(h.c.Store, "example.com", true)
	if len(pt) != 1 || pt[0].Open || pt[0].Server != p.addr || pt[0].Device != "dev" || pt[0].Time == "" || pt[0].End == "" ||
		pt[0].BytesUp < 100 || pt[0].BytesDown < int64(len("real server")) || !slices.Equal(pt[0].ALPNOffered, []string{"http/1.1"}) {
		t.Fatalf("pass record: %+v", pt)
	}
	if flows, _ := h.c.Store.List(Filter{Host: "example.com", Limit: 10}); len(flows) != 0 {
		t.Errorf("a pass host's flow recorded: %+v", flows)
	}
	if fs := h.c.Store.TLSFailures(Filter{Host: "example.com", Limit: 10}); len(fs) != 0 {
		t.Errorf("a pass host failed: %+v", fs)
	}
	// Seen while open: before the client sends anything more.
	c, err := p.dial(ctx, "dev")
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(c, &tls.Config{RootCAs: pin, ServerName: "example.com"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("held connection: %v", err)
	}
	if open := waitPass(h.c.Store, "example.com", false); len(open) != 2 || !open[0].Open || open[0].End != "" {
		t.Errorf("an open connection: %+v", open)
	}
	tc.Close()
	if closed := waitPass(h.c.Store, "example.com", true); len(closed) != 2 || closed[0].Open {
		t.Errorf("closed: %+v", closed)
	}
	// A ClientHello in two pieces (the tailnet's MTU): passed through all the same.
	if body, _, err := (pinClient{h: h, addr: p.addr, split: true}).get("dev", "example.com", pinned); err != nil || body != "real server" {
		t.Errorf("split ClientHello: %v %q", err, body)
	}
	// Another allowed host: decrypted, as before.
	if _, issuer, err := p.get("dev", "trusted.example.net", &tls.Config{RootCAs: mitm}); err != nil || !strings.Contains(issuer, "mitmproxy") {
		t.Errorf("allowed host: %v (issuer %q)", err, issuer)
	}
	// Bytes each way, the right way round: a 64 KiB answer is bytes_down.
	hc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext:     func(ctx context.Context, _, _ string) (net.Conn, error) { return p.dial(ctx, "dev") },
		TLSClientConfig: &tls.Config{RootCAs: pin, ServerName: "example.com"}, DisableKeepAlives: true,
	}}
	if r, err := hc.Get("https://" + p.addr + "/big"); err != nil {
		t.Fatal(err)
	} else {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	if big := waitPass(h.c.Store, "example.com", true); len(big) == 0 || big[0].BytesDown < 64<<10 || big[0].BytesUp > 8<<10 {
		t.Errorf("bytes: %+v", big)
	}
	// One of Apple's: mitmproxy passes it itself, before --pass-hosts; nothing recorded.
	if body, _, err := p.get("dev", "www.apple.com", &tls.Config{InsecureSkipVerify: true}); err != nil || body != "real server" {
		t.Errorf("Apple's: %v %q", err, body)
	}
	time.Sleep(300 * time.Millisecond)
	if pt := h.c.Store.Passthroughs(Filter{Host: "apple.com", Limit: 10}); len(pt) != 0 {
		t.Errorf("Apple's recorded: %+v", pt)
	}
	// A pass host outside --allow-hosts: mitmproxy passes it itself; nothing recorded.
	oos := h.c.Store.Stats()["out_of_scope"]
	if body, _, err := p.get("dev", "other.org", &tls.Config{InsecureSkipVerify: true}); err != nil || body != "real server" {
		t.Errorf("outside --allow-hosts: %v %q", err, body)
	}
	time.Sleep(300 * time.Millisecond)
	if pt := h.c.Store.Passthroughs(Filter{Host: "other.org", Limit: 10}); len(pt) != 0 || h.c.Store.Stats()["out_of_scope"] != oos {
		t.Errorf("outside --allow-hosts recorded: %+v", pt)
	}
	// A client that names no host (dials an address): passed by the address.
	h2, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.AllowHosts, _ = c.AllowHosts.WithPass([]string{"127.0.0.1"}) })
	if err != nil {
		t.Fatal(err)
	}
	p2 := pinClient{h: h2, addr: p.addr}
	if body, issuer, err := p2.get("dev", "", &tls.Config{RootCAs: pin}); err != nil || body != "real server" || strings.Contains(issuer, "mitmproxy") {
		t.Errorf("no SNI, by address: %v %q (issuer %q)", err, body, issuer)
	}
	if ip := waitPass(h2.c.Store, "127.0.0.1", true); len(ip) != 1 || ip[0].Host != "127.0.0.1" {
		t.Errorf("no SNI record: %+v", ip)
	}
}

// TestRawTCPE2E (REQCOVE_E2E=1): a client on an allowed host gets an ALPN
// mitmproxy does not know from a server that speaks first (as an HTTP/2
// server's SETTINGS did for grpc-swift's grpc-exp on the iPhone). mitmproxy
// decrypts it, then carries it as raw TCP: no flow, no TLS failure. It is
// listed as a connection (reason raw_tcp, its protocols, the bytes relayed
// inside TLS) and counted (raw_tcp), and the next HTTPS request is recorded
// as before. Without the addon's tcp_start, nothing at all is recorded. Then
// plain HTTP that a 101 upgrades: the request a flow, the connection after it
// a raw record named by the request's host.
func TestRawTCPE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "http") }))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		"x-reqcove-test": func(_ *http.Server, c *tls.Conn, _ http.Handler) { // a greeting, then one echo
			io.WriteString(c, "HELLO\n")
			b := make([]byte, 4)
			if _, err := io.ReadFull(c, b); err == nil {
				c.Write(b)
			}
		},
	}
	srv.TLS = &tls.Config{NextProtos: []string{"x-reqcove-test", "http/1.1"}}
	srv.StartTLS()
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "origin.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	h, err := tryHarness(t, ctx, []string{"*.example.com"}, func(c *Config) { c.trustCA = caFile })
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := os.ReadFile(filepath.Join(h.confdir, "mitmproxy-ca-cert.pem"))
	mitm := x509.NewCertPool()
	mitm.AppendCertsFromPEM(ca)
	p := pinClient{h: h, addr: srv.Listener.Addr().String()}

	raw, err := p.dial(ctx, "dev") // an address, as the exit node dials
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{ServerName: "raw.example.com", NextProtos: []string{"x-reqcove-test"}, RootCAs: mitm})
	tc.SetDeadline(time.Now().Add(20 * time.Second))
	if err := tc.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != "x-reqcove-test" {
		t.Fatalf("ALPN: %q", got)
	}
	greeting := make([]byte, 6) // read before writing: the server speaks first
	if _, err := io.ReadFull(tc, greeting); err != nil || string(greeting) != "HELLO\n" {
		t.Fatalf("greeting: %q %v", greeting, err)
	}
	io.WriteString(tc, "ping")
	echo, _ := io.ReadAll(tc)
	tc.Close()
	if string(echo) != "ping" {
		t.Fatalf("echo: %q", echo)
	}
	pt := waitPass(h.c.Store, "raw.example.com", true)
	if len(pt) != 1 || pt[0].Reason != "raw_tcp" || pt[0].Open || pt[0].Device != "dev" || pt[0].Server != p.addr ||
		pt[0].ALPN != "x-reqcove-test" || !slices.Equal(pt[0].ALPNOffered, []string{"x-reqcove-test"}) ||
		pt[0].BytesUp != 4 || pt[0].BytesDown != 10 || pt[0].Time == "" || pt[0].End == "" {
		t.Fatalf("raw record: %+v", pt)
	}
	if h.stat("raw_tcp") != 1 || h.stat("passed_through") != 0 {
		t.Errorf("raw_tcp %d, passed_through %d", h.stat("raw_tcp"), h.stat("passed_through"))
	}
	if r, _ := h.stats()["raw_tcp_hosts"].([]RawHost); len(r) != 1 || r[0].Host != "raw.example.com" || r[0].Device != "dev" {
		t.Errorf("raw_tcp_hosts: %+v", r)
	}
	if flows, _ := h.c.Store.List(Filter{Host: "raw.example.com", Limit: 10}); len(flows) != 0 {
		t.Errorf("a flow: %+v", flows)
	}
	if fs := h.c.Store.TLSFailures(Filter{Limit: 10}); len(fs) != 0 {
		t.Errorf("TLS failures: %+v", fs)
	}
	// HTTPS to an allowed host goes on as before, recorded.
	hc := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext:     func(ctx context.Context, _, _ string) (net.Conn, error) { return p.dial(ctx, "dev") },
		TLSClientConfig: &tls.Config{RootCAs: mitm}, DisableKeepAlives: true,
	}}
	r, err := hc.Get("https://web.example.com/after")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(b) != "http" {
		t.Errorf("HTTPS: %q", b)
	}
	if v := h.doneFlow("/after", false); v.Status != 200 {
		t.Errorf("the flow: %+v", v.Flow)
	}
	if h.stat("raw_tcp") != 1 {
		t.Errorf("raw_tcp after HTTPS: %d", h.stat("raw_tcp"))
	}

	// Plain HTTP upgraded with a 101 (not a WebSocket): the request is a flow,
	// and what the connection carries after it is a raw connection named by
	// the request's host (no SNI to name it). Without the addon's memory of
	// the 101's host, nothing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
			return
		}
		io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x-reqcove-test\r\nConnection: Upgrade\r\n\r\n")
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err == nil {
			c.Write(b)
		}
	}()
	up, err := (pinClient{h: h, addr: ln.Addr().String()}).dial(ctx, "dev")
	if err != nil {
		t.Fatal(err)
	}
	up.SetDeadline(time.Now().Add(20 * time.Second))
	io.WriteString(up, "GET /up-plain HTTP/1.1\r\nHost: plain.example.com\r\nConnection: Upgrade\r\nUpgrade: x-reqcove-test\r\n\r\n")
	br := bufio.NewReader(up)
	if r, err := http.ReadResponse(br, nil); err != nil || r.StatusCode != 101 {
		t.Fatalf("101: %v %v", r, err)
	}
	io.WriteString(up, "ping")
	echo = make([]byte, 4)
	if _, err := io.ReadFull(br, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo after the 101: %q %v", echo, err)
	}
	up.Close()
	if v := h.doneFlow("/up-plain", false); v.Status != 101 {
		t.Errorf("the 101's flow: %+v", v.Flow)
	}
	pt = waitPass(h.c.Store, "plain.example.com", true)
	if len(pt) != 1 || pt[0].Reason != "raw_tcp" || pt[0].Open || pt[0].Device != "dev" || pt[0].Server != ln.Addr().String() ||
		pt[0].BytesUp != 4 || pt[0].BytesDown != 4 {
		t.Fatalf("plain 101's raw record: %+v", pt)
	}
	if h.stat("raw_tcp") != 2 {
		t.Errorf("raw_tcp after the plain 101: %d", h.stat("raw_tcp"))
	}
}

// --pass-hosts: as --allow-hosts' syntax, not "*"; Match leaves them out,
// Allowed keeps them in; spaces around the hosts are fine.
func TestWithPass(t *testing.T) {
	allow, _ := ParseAllowHosts([]string{"*.example.com", "api.other.net"})
	r, err := allow.WithPass([]string{" *.cdn.example.com, api.other.net  "})
	if err != nil || !slices.Equal(r.PassHosts, []string{"*.cdn.example.com", "api.other.net"}) {
		t.Fatalf("%v %q", err, r.PassHosts)
	}
	for host, want := range map[string][2]bool{ // Match, Allowed
		"img.cdn.example.com": {false, true}, "API.other.net.": {false, true},
		"www.example.com": {true, true}, "other.net": {false, false},
	} {
		if r.Match(host) != want[0] || r.Allowed(host) != want[1] {
			t.Errorf("%s: Match %v Allowed %v, want %v", host, r.Match(host), r.Allowed(host), want)
		}
	}
	for _, bad := range []string{"*", "api.x.com; rm -rf ~", "a b.com"} {
		if _, err := allow.WithPass([]string{bad}); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}

// The Store keeps a pass connection from its start, closes it at its end or
// when mitmdump goes, records nothing outside --allow-hosts, and keeps at most
// maxPasses.
func TestStorePassthroughs(t *testing.T) {
	st := NewStore(10, 1<<20)
	allow, _ := ParseAllowHosts([]string{"*.example.com"})
	allow, _ = allow.WithPass([]string{"api.example.com"})
	st.SetScope(allow, true)
	ev := func(s string) { st.Apply([]byte(`{"v":2,` + s + `}`)) }
	ev(`"ev":"pass_open","conn":"c1","device":"d","sni":"api.example.com","server":"203.0.113.1:443","alpn":["h2"],"ts":1794000000`)
	ev(`"ev":"pass_open","conn":"c2","device":"d","sni":"api.other.org","server":"203.0.113.2:443","ts":1794000001`)
	p := st.Passthroughs(Filter{Limit: 10})
	if len(p) != 1 || !p[0].Open || p[0].Server != "203.0.113.1:443" || !slices.Equal(p[0].ALPNOffered, []string{"h2"}) {
		t.Fatalf("open: %+v", p)
	}
	ev(`"ev":"pass_close","conn":"c1","ts_end":1794000002.5,"up":1200,"down":56000`)
	if p = st.Passthroughs(Filter{Limit: 10}); p[0].Open || p[0].BytesUp != 1200 || p[0].BytesDown != 56000 || p[0].DurationMS != 2500 {
		t.Errorf("closed: %+v", p)
	}
	ev(`"ev":"pass_open","conn":"c3","device":"d","sni":"api.example.com","ts":1794000003`)
	st.mitmdumpExited("mitmdump exited")
	if p = st.Passthroughs(Filter{Limit: 10}); p[0].Open || !strings.HasPrefix(p[0].Note, "mitmdump exited") || !p[0].BytesUnknown {
		t.Errorf("after mitmdump went: %+v", p[0])
	}
	for i := range maxPasses + 5 {
		ev(fmt.Sprintf(`"ev":"pass_open","conn":"x%d","device":"d","sni":"api.example.com","ts":1794000004`, i))
	}
	if n := len(st.Passthroughs(Filter{Limit: 2 * maxPasses})); n != maxPasses || len(st.passByConn) != maxPasses {
		t.Errorf("%d kept, %d open", n, len(st.passByConn))
	}
	if s := st.Stats(); s["passed_through"] != maxPasses+7 || !slices.Equal(s["pass_hosts"].([]string), []string{"api.example.com"}) {
		t.Errorf("stats: %v %v", s["passed_through"], s["pass_hosts"])
	}
	// Raw TCP connections have their own bound: many do not push the pass
	// hosts' out, nor the reverse.
	kinds := func() map[string]int {
		n := map[string]int{}
		for _, p := range st.Passthroughs(Filter{Limit: 3 * maxPasses}) {
			n[p.Reason]++
		}
		return n
	}
	for i := range maxPasses + 5 {
		ev(fmt.Sprintf(`"ev":"pass_open","conn":"r%d","device":"d","sni":"grpc.example.com","raw":true,"ts":1794000005`, i))
	}
	if n := kinds(); n["pass_hosts"] != maxPasses || n["raw_tcp"] != maxPasses {
		t.Errorf("after raw TCP: %v", n)
	}
	for i := range 5 {
		ev(fmt.Sprintf(`"ev":"pass_open","conn":"y%d","device":"d","sni":"api.example.com","ts":1794000006`, i))
	}
	if n := kinds(); n["pass_hosts"] != maxPasses || n["raw_tcp"] != maxPasses || len(st.passByConn) != 2*maxPasses {
		t.Errorf("after more pass hosts: %v, %d open", n, len(st.passByConn))
	}
	if p := st.Passthroughs(Filter{Limit: 1}); p[0].Conn != "y4" {
		t.Errorf("newest: %+v", p)
	}
}

// Refused hosts: refused again and again (alerts or hang-ups) by a device that
// decrypts other hosts, never decrypted, not passed already; and only names
// that are host names: an SNI is the app's to choose, and these go into a
// command run suggests.
func TestRefusedHosts(t *testing.T) {
	st := NewStore(100, 1<<20)
	allow, _ := ParseAllowHosts([]string{"*"})
	allow, _ = allow.WithPass([]string{"passed.example.com"})
	st.SetScope(allow, true)
	n := 0
	fail := func(device, sni, msg string) {
		n++
		st.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"tls_failed","conn":"t%d","device":%q,"sni":%q,"msg":%q,"ts":1794000000}`, n, device, sni, msg)))
	}
	alert := "The client does not trust the proxy's certificate for X (tlsv1 alert unknown ca)"
	closed := "The client disconnected during the handshake. If this happens consistently for X, this may indicate that the client does not trust the proxy's certificate."
	st.Apply([]byte(`{"v":2,"ev":"request","id":"f1","device":"d","host":"ok.example.com","url":"https://ok.example.com/","ts":1794000000}`))
	st.Apply([]byte(`{"v":2,"ev":"request","id":"f2","device":"d","host":"seen.example.com","url":"https://seen.example.com/","ts":1794000000}`))
	for range 3 {
		fail("d", "pinned.example.com", alert)
		fail("d", "hangs.example.com", closed)
		fail("d", "seen.example.com", alert)   // decrypted before: not refused
		fail("d", "passed.example.com", alert) // passed already
		fail("d", "x'; rm -rf ~; echo '", alert)
		fail("other", "pinned.example.com", alert) // a device that decrypts nothing: the CA is not trusted there
		fail("d", "early.example.com", "connection closed early")
	}
	fail("d", "once.example.com", alert)
	fail("d", "once.example.com", alert)
	var got []string
	for _, r := range st.Stats()["refused_hosts"].([]RefusedHost) {
		got = append(got, r.Device+" "+r.Host)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"d hangs.example.com", "d pinned.example.com"}) {
		t.Errorf("refused: %q", got)
	}
	// example.com has recorded hosts on d (ok., seen.): a *.example.com would stop them.
	for _, r := range st.Stats()["refused_hosts"].([]RefusedHost) {
		if !r.SiblingsRecorded {
			t.Errorf("%s: siblings recorded not said", r.Host)
		}
	}
}

// The review's cases: a pass host's failure stays (pass-through did not
// apply: why it failed), marked; a pass_open for an allowed host that is not
// a pass host is refused; a long open connection counts for a later since;
// a host filter on a parent domain finds the pass host; mitm.it is never
// suggested.
func TestPassReviewCases(t *testing.T) {
	st := NewStore(10, 1<<20)
	allow, _ := ParseAllowHosts([]string{"*"})
	allow, _ = allow.WithPass([]string{"api.x.com"})
	st.SetScope(allow, true)
	ev := func(s string) { st.Apply([]byte(`{"v":2,` + s + `}`)) }
	ev(`"ev":"tls_failed","conn":"t1","device":"d","sni":"api.x.com","msg":"The client does not trust the proxy's certificate for api.x.com","ts":1794000000`)
	if fs := st.TLSFailures(Filter{Limit: 10}); len(fs) != 1 || !strings.HasPrefix(fs[0].Msg, "not passed through") {
		t.Errorf("pass host failure: %+v", fs)
	}
	ev(`"ev":"pass_open","conn":"c1","device":"d","sni":"img.other.com","ts":1794000000`)
	if p := st.Passthroughs(Filter{Limit: 10}); len(p) != 0 {
		t.Errorf("a pass_open for a host not in --pass-hosts: %+v", p)
	}
	ev(`"ev":"pass_open","conn":"c2","device":"d","sni":"api.x.com","ts":1794000000`)
	if p := st.Passthroughs(Filter{Since: 1794000600, Limit: 10}); len(p) != 1 {
		t.Errorf("a connection open since before since: %+v", p)
	}
	ev(`"ev":"pass_close","conn":"c2","ts_end":1794000100,"up":10,"down":20,"msg":"connect failed"`)
	if p := st.Passthroughs(Filter{Since: 1794000600, Limit: 10}); len(p) != 0 {
		t.Errorf("a connection closed before since: %+v", p)
	}
	if p := st.Passthroughs(Filter{Limit: 10}); p[0].Note != "connect failed" {
		t.Errorf("close reason: %+v", p[0])
	}
	if !st.PassHost("x.com") || !st.PassHost("API.x.com") || st.PassHost("other.com") {
		t.Error("PassHost by parent domain")
	}
	if d := st.Devices(); len(d) != 1 || d[0].Passthroughs != 1 || d[0].LastSeen == "" {
		t.Errorf("devices: %+v", d)
	}
	st.Apply([]byte(`{"v":2,"ev":"request","id":"f1","device":"d","host":"ok.example.com","url":"https://ok.example.com/","ts":1794000000}`))
	for i := range 3 {
		ev(fmt.Sprintf(`"ev":"tls_failed","conn":"m%d","device":"d","sni":"mitm.it","msg":"The client does not trust the proxy's certificate for mitm.it","ts":1794000000`, i))
	}
	for _, r := range st.Stats()["refused_hosts"].([]RefusedHost) {
		if r.Host == "mitm.it" || r.Host == "api.x.com" {
			t.Errorf("suggested %s", r.Host)
		}
	}
}

// An allowed host's connection mitmproxy decrypted but carried as raw TCP
// (not read as HTTP): listed with reason raw_tcp and the protocol the client
// got, counted apart from --pass-hosts (passed_through, a device's
// passthroughs), and only for a host recorded as flows.
func TestRawTCP(t *testing.T) {
	st := NewStore(10, 1<<20)
	allow, _ := ParseAllowHosts([]string{"*.example.com"})
	allow, _ = allow.WithPass([]string{"pinned.example.com"})
	st.SetScope(allow, true)
	ev := func(s string) { st.Apply([]byte(`{"v":2,` + s + `}`)) }
	ev(`"ev":"pass_open","conn":"c1","device":"d","sni":"grpc.example.com","raw":true,"alpn":["grpc-exp","h2"],"alpn_negotiated":"grpc-exp","server":"203.0.113.1:443","ts":1794000000`)
	ev(`"ev":"pass_open","conn":"c2","device":"d","sni":"other.org","raw":true,"ts":1794000000`)          // outside --allow-hosts
	ev(`"ev":"pass_open","conn":"c3","device":"d","sni":"pinned.example.com","raw":true,"ts":1794000000`) // a pass host's
	ev(`"ev":"pass_open","conn":"c4","device":"d","sni":"pinned.example.com","ts":1794000000`)            // passed through
	// c1 is open too, but no --pass-hosts connection.
	if n := st.Stats()["passed_through_open"]; n != 1 {
		t.Errorf("passed_through_open %v", n)
	}
	ev(`"ev":"pass_close","conn":"c1","ts_end":1794000002,"up":10,"down":20`)
	p := st.Passthroughs(Filter{Limit: 10})
	if len(p) != 2 || p[0].Reason != "pass_hosts" || p[0].ALPN != "" || !p[0].Open ||
		p[1].Reason != "raw_tcp" || p[1].Host != "grpc.example.com" || p[1].ALPN != "grpc-exp" || !slices.Equal(p[1].ALPNOffered, []string{"grpc-exp", "h2"}) ||
		p[1].Server != "203.0.113.1:443" || p[1].Open || p[1].BytesUp != 10 || p[1].BytesDown != 20 {
		t.Fatalf("connections: %+v", p)
	}
	s := st.Stats()
	if s["raw_tcp"] != 1 || s["passed_through"] != 1 {
		t.Errorf("raw_tcp %v passed_through %v", s["raw_tcp"], s["passed_through"])
	}
	if r := s["raw_tcp_hosts"].([]RawHost); len(r) != 1 || r[0].Device != "d" || r[0].Host != "grpc.example.com" || r[0].Connections != 1 || !slices.Equal(r[0].ALPN, []string{"grpc-exp"}) {
		t.Errorf("raw_tcp_hosts: %+v", r)
	}
	if d := st.Devices(); len(d) != 1 || d[0].Passthroughs != 1 || d[0].RawTCP != 1 {
		t.Errorf("devices: %+v", d)
	}
	// A device with raw TCP connections only, not carried now: listed all the same.
	ev(`"ev":"pass_open","conn":"c5","device":"r","sni":"grpc.example.com","raw":true,"ts":1794000003`)
	if d := st.Devices(); len(d) != 2 || d[1].ID != "r" || d[1].RawTCP != 1 || d[1].Passthroughs != 0 || d[1].LastSeen == "" {
		t.Errorf("raw TCP only: %+v", d)
	}
}
