package capture

import (
	"bufio"
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/textproto"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// upstreamProxy stands in for Burp: HTTPS in a CONNECT tunnel (not decrypted
// here), plain HTTP as a proxy request. It notes what it was asked for.
type upstreamProxy struct {
	ln   net.Listener
	mu   sync.Mutex
	seen []string
}

func (u *upstreamProxy) note(s string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.seen = append(u.seen, s)
}

func (u *upstreamProxy) all() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.seen)
}

func startUpstream(t *testing.T) *upstreamProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &upstreamProxy{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go u.serve(c)
		}
	}()
	return u
}

// serve notes the request line and the Host header as they came (Go's
// parser replaces Host with the URL's host for a proxy request). Like a real
// proxy, it keeps a connection alive for the next proxy request.
func (u *upstreamProxy) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for u.serveOne(c, br) {
	}
}

func (u *upstreamProxy) serveOne(c net.Conn, br *bufio.Reader) (again bool) {
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return false
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return false
	}
	method, target, _ := strings.Cut(line, " ")
	target, _, _ = strings.Cut(target, " ")
	if method == "CONNECT" {
		u.note("CONNECT " + target)
		s, err := net.Dial("tcp", target)
		if err != nil {
			fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer s.Close()
		fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		go io.Copy(s, br)
		io.Copy(c, s)
		return false
	}
	u.note(method + " " + target + " Host:" + hdr.Get("Host") + " Cookie:" + strings.Join(hdr.Values("Cookie"), "|"))
	var body io.Reader
	switch {
	case strings.EqualFold(hdr.Get("Transfer-Encoding"), "chunked"):
		body = httputil.NewChunkedReader(br)
	case hdr.Get("Content-Length") != "":
		n, _ := strconv.Atoi(hdr.Get("Content-Length"))
		body = io.LimitReader(br, int64(n))
	}
	var b []byte
	if body != nil {
		b, _ = io.ReadAll(body)
		if body != nil && strings.EqualFold(hdr.Get("Transfer-Encoding"), "chunked") {
			textproto.NewReader(br).ReadMIMEHeader() // the trailer's end
		}
	}
	req, err := http.NewRequest(method, target, bytes.NewReader(b))
	if err != nil {
		fmt.Fprint(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return false
	}
	req.Host = hdr.Get("Host")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return false
	}
	defer resp.Body.Close()
	resp.Write(c)
	return !strings.EqualFold(hdr.Get("Connection"), "close")
}

// TestUpstream: with --upstream-proxy, decrypted requests go on through it
// (HTTPS by CONNECT to the address, plain HTTP as a proxy request), never
// straight to the server; only --upstream-ca is trusted; the records stay;
// a resolve rule's name still reaches the server as SNI.
func TestUpstream(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var tlsConns atomic.Int32
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin %s %s", r.Host, r.URL.Path)
	}))
	origin.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			tlsConns.Add(1)
		}
	}
	origin.StartTLS()
	defer origin.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			fmt.Fprintf(w, "plain got %q", b)
			return
		}
		fmt.Fprintf(w, "plain %s %s", r.Host, r.URL.Path)
	}))
	defer plain.Close()
	up := startUpstream(t)
	defer up.ln.Close()

	// The upstream does not decrypt here, so its "CA" is the origin's test certificate.
	dir := t.TempDir()
	caFile := filepath.Join(dir, "upstream-ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0o600)
	o, p := origin.Listener.Addr().String(), plain.Listener.Addr().String()
	rules := filepath.Join(dir, "rules.yaml")
	os.WriteFile(rules, []byte(fmt.Sprintf(`keep_host_header: true
map_remote:
  - "|https://%[1]s/maph2/|http://%[2]s/landed/"
  - "|//%[1]s/badport/|//127.0.0.1:99999/"
`, o, p)), 0o600)

	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) {
		c.Upstream, c.UpstreamCA, c.Rules = up.ln.Addr().String(), caFile, rules
		var err error
		if c.AllowHosts, err = c.AllowHosts.WithPass([]string{"pass.example"}); err != nil {
			t.Fatal(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := h.stats()["upstream"]; got != up.ln.Addr().String() {
		t.Errorf("capture_stats upstream: %v", got)
	}
	hc := h.client("dev")
	get := func(url, host string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", url, nil)
		if host != "" {
			req.Host = host
		}
		r, err := hc.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		return r.StatusCode, string(b)
	}

	if code, body := get("https://"+o+"/tls", ""); code != 200 || body != "origin "+o+" /tls" {
		t.Errorf("HTTPS through the upstream: %d %q", code, body)
	}
	if !slices.Contains(up.all(), "CONNECT "+o) {
		t.Errorf("the upstream was not asked to CONNECT %s: %v", o, up.all())
	}
	if n := tlsConns.Load(); n != 1 {
		t.Errorf("the server got %d connections, want 1 (the upstream's): mitmproxy connected around it", n)
	}
	if v := h.doneFlow("/tls", false); v.Status != 200 || v.Host != "127.0.0.1" {
		t.Errorf("record: status %d host %q", v.Status, v.Host)
	}

	if code, body := get("http://"+p+"/plain", ""); code != 200 || body != "plain "+p+" /plain" {
		t.Errorf("plain HTTP through the upstream: %d %q", code, body)
	}
	if want := "GET http://" + p + "/plain Host:" + p + " "; !slices.ContainsFunc(up.all(), func(s string) bool { return strings.HasPrefix(s, want) }) {
		t.Errorf("the upstream did not get %q as a proxy request: %v", want, up.all())
	}

	// A request for a host outside --allow-hosts on a decrypted connection is
	// passed through unrecorded, but through the upstream all the same.
	if code, _ := get("http://"+p+"/oos", "elsewhere.example"); code != 200 {
		t.Errorf("out-of-scope request through the upstream: %d", code)
	}
	if want := "GET http://" + p + "/oos Host:elsewhere.example "; !slices.ContainsFunc(up.all(), func(s string) bool { return strings.HasPrefix(s, want) }) {
		t.Errorf("the out-of-scope request did not go through the upstream: %v", up.all())
	}
	// A --pass-hosts host's requests that mitmproxy decrypts all the same (plain
	// HTTP, or riding an allowed host's TLS connection): through the upstream too.
	if code, _ := get("http://"+p+"/passplain", "pass.example"); code != 200 {
		t.Errorf("a pass host's plain HTTP through the upstream: %d", code)
	}
	if want := "GET http://" + p + "/passplain Host:pass.example "; !slices.ContainsFunc(up.all(), func(s string) bool { return strings.HasPrefix(s, want) }) {
		t.Errorf("a pass host's plain HTTP did not go through the upstream: %v", up.all())
	}
	connects := func() int { return len(slices.DeleteFunc(up.all(), func(s string) bool { return s != "CONNECT "+o })) }
	beforeConnects := connects()
	// A new client: on hc's open connection mitmproxy would reuse the tunnel /tls made.
	preq, _ := http.NewRequest("GET", "https://"+o+"/passtls", nil)
	preq.Host = "pass.example"
	if r, err := h.client("dev").Do(preq); err != nil {
		t.Errorf("a pass host's request on an allowed host's connection: %v", err)
	} else {
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 || string(b) != "origin pass.example /passtls" {
			t.Errorf("a pass host's request on an allowed host's connection: %d %q", r.StatusCode, b)
		}
	}
	if connects() == beforeConnects {
		t.Errorf("a pass host's request on an allowed host's connection did not go through the upstream: %v", up.all())
	}

	// An HTTP/2 app whose request map_remote sends to a plain http:// server:
	// the proxy gets a whole proxy request, with the app's Host kept.
	tr := hc.Transport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = true
	h2 := &http.Client{Transport: tr, Timeout: time.Minute}
	if r, err := h2.Get("https://" + o + "/maph2/x"); err != nil {
		t.Errorf("HTTP/2 map_remote to http: %v", err)
	} else {
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.ProtoMajor != 2 || string(b) != "plain "+o+" /landed/x" {
			t.Errorf("HTTP/2 map_remote to http: HTTP/%d %q", r.ProtoMajor, b)
		}
	}
	if !slices.ContainsFunc(up.all(), func(s string) bool { return strings.HasPrefix(s, "GET http://"+p+"/landed/x Host:"+o+" ") }) {
		t.Errorf("the upstream did not get the HTTP/2 request as a proxy request: %v", up.all())
	}
	// More than five on one HTTP/2 connection, through a proxy that keeps
	// connections alive: none waits for a connection left open.
	for i := range 8 {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s/maph2/many%d", o, i), nil)
		if r, err := h2.Do(req); err != nil {
			t.Errorf("HTTP/2 request %d through a keep-alive proxy: %v", i, err)
		} else {
			r.Body.Close()
		}
		cancel()
	}
	// A body of unknown length, and two cookies, from an HTTP/2 app.
	req, _ := http.NewRequest("POST", "https://"+o+"/maph2/post", io.MultiReader(strings.NewReader("hello world")))
	req.Header.Add("Cookie", "a=1")
	req.Header.Add("Cookie", "b=2")
	if r, err := h2.Do(req); err != nil {
		t.Errorf("HTTP/2 POST of unknown length: %v", err)
	} else {
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if string(b) != `plain got "hello world"` {
			t.Errorf("HTTP/2 POST of unknown length: the server got %q", b)
		}
	}
	if !slices.ContainsFunc(up.all(), func(s string) bool {
		return strings.Contains(s, "/landed/post ") && strings.HasSuffix(s, "Cookie:a=1; b=2")
	}) {
		t.Errorf("cookies not joined into one header: %v", up.all())
	}

	// A rule that fails on a request (a bad port) stops it: it does not go on
	// to the server around the rule and the upstream.
	before := tlsConns.Load()
	if code, body := get("https://"+o+"/badport/y", ""); code != 502 || !strings.Contains(body, "rule failed") {
		t.Errorf("failed rule: %d %q", code, body)
	}
	if tlsConns.Load() != before {
		t.Error("a failed rule let the request go to the server")
	}
	if v := h.doneFlow("/badport/y", false); v.Status != 502 || !slices.ContainsFunc(v.Rewrites, func(s string) bool { return strings.HasPrefix(s, "rules failed") }) {
		t.Errorf("failed rule, record: status %d rewrites %v", v.Status, v.Rewrites)
	}

	// The upstream down: an error, and the server is not reached around it
	// (a new connection from the app: an open tunnel would still carry it).
	up.ln.Close()
	before = tlsConns.Load()
	hc = h.client("dev")
	if code, _ := get("https://"+o+"/down", ""); code != 502 {
		t.Errorf("upstream down: %d, want 502", code)
	}
	if tlsConns.Load() != before {
		t.Error("with the upstream down, mitmproxy went to the server itself")
	}
	if v := h.doneFlow("/down", false); v.Status != 502 && v.Error == "" {
		t.Errorf("upstream down, record: status %d error %q", v.Status, v.Error)
	}
}

// An upstream on an IPv6 address ([::1]:PORT) works as written in the flag.
func TestUpstreamIPv6(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	up := &upstreamProxy{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go up.serve(c)
		}
	}()
	defer ln.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer plain.Close()
	// and a server on [::1] that map_remote sends a request to
	v6, _ := net.Listen("tcp", "[::1]:0")
	v6srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "v6 "+r.URL.Path) })}
	go v6srv.Serve(v6)
	defer v6srv.Close()
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	os.WriteFile(rules, []byte(fmt.Sprintf("map_remote:\n  - \"|//%s/v6map/|//%s/\"\n", plain.Listener.Addr(), v6.Addr())), 0o600)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.Upstream, c.Rules = ln.Addr().String(), rules })
	if err != nil {
		t.Fatal(err)
	}
	r, err := h.client("dev").Get(plain.URL + "/v6")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 || !slices.ContainsFunc(up.all(), func(s string) bool { return strings.Contains(s, "/v6") }) {
		t.Errorf("through [::1]: %d, upstream saw %v", r.StatusCode, up.all())
	}
	// To an IPv6 server: the proxy request names it in brackets.
	r, err = h.client("dev").Get(plain.URL + "/v6map/x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(b) != "v6 /x" {
		t.Errorf("map_remote to [::1] through the upstream: %d %q, upstream saw %v", r.StatusCode, b, up.all())
	}
}

// resolve and an upstream proxy do not go together: Burp connects by the name
// in the SNI, looked up on this computer, so the rule would silently not apply.
func TestUpstreamRefusesResolve(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	os.WriteFile(rules, []byte("resolve: [\"127.0.0.1=192.0.2.1\"]\n"), 0o600)
	_, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.Rules, c.Upstream = rules, "127.0.0.1:9" })
	if err == nil || !strings.Contains(err.Error(), "resolve does not go with --upstream-proxy") {
		t.Errorf("Start: %v", err)
	}
}
