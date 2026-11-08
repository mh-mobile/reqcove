package capture

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"slices"
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

// serve notes the request line and the Host header as they came: Go's
// parser replaces Host with the URL's host for a proxy request.
func (u *upstreamProxy) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return
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
		return
	}
	u.note(method + " " + target + " Host:" + hdr.Get("Host"))
	req, err := http.NewRequest(method, target, nil) // GET only, in these tests
	if err != nil {
		return
	}
	req.Host = hdr.Get("Host")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer resp.Body.Close()
	resp.Write(c)
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
		fmt.Fprintf(w, "plain %s %s", r.Host, r.URL.Path)
	}))
	defer plain.Close()
	sni := make(chan string, 4)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	target.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni <- h.ServerName
		return nil, nil
	}}
	target.StartTLS()
	defer target.Close()
	up := startUpstream(t)
	defer up.ln.Close()

	// The upstream does not decrypt here, so its "CA" is the origin's test certificate.
	dir := t.TempDir()
	caFile := filepath.Join(dir, "upstream-ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0o600)
	rules := filepath.Join(dir, "rules.yaml")
	os.WriteFile(rules, []byte(fmt.Sprintf("resolve:\n  - \"tls.resolved.test=127.0.0.1:%d\"\n", target.Listener.Addr().(*net.TCPAddr).Port)), 0o600)

	h, err := tryHarness(t, ctx, []string{"127.0.0.1", "tls.resolved.test"}, func(c *Config) {
		c.Upstream, c.UpstreamCA, c.Rules = up.ln.Addr().String(), caFile, rules
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

	o := origin.Listener.Addr().String()
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

	p := plain.Listener.Addr().String()
	if code, body := get("http://"+p+"/plain", ""); code != 200 || body != "plain "+p+" /plain" {
		t.Errorf("plain HTTP through the upstream: %d %q", code, body)
	}
	if want := "GET http://" + p + "/plain Host:" + p; !slices.Contains(up.all(), want) {
		t.Errorf("the upstream did not get %q as a proxy request: %v", want, up.all())
	}

	// A request for a host outside --allow-hosts on a decrypted connection is
	// passed through unrecorded, but through the upstream all the same.
	if code, _ := get("http://"+p+"/oos", "elsewhere.example"); code != 200 {
		t.Errorf("out-of-scope request through the upstream: %d", code)
	}
	if want := "GET http://" + p + "/oos Host:elsewhere.example"; !slices.Contains(up.all(), want) {
		t.Errorf("the out-of-scope request did not go through the upstream: %v", up.all())
	}

	// resolve: through the upstream, the target is still asked for the name.
	tc := h.client("dev")
	tc.Transport.(*http.Transport).TLSClientConfig.ServerName = "tls.resolved.test"
	req, _ := http.NewRequest("GET", "https://"+o+"/resolved", nil)
	req.Host = "tls.resolved.test"
	if r, err := tc.Do(req); err != nil {
		t.Errorf("resolve through the upstream: %v", err)
	} else {
		r.Body.Close()
	}
	select {
	case got := <-sni:
		if got != "tls.resolved.test" {
			t.Errorf("resolve through the upstream: SNI %q", got)
		}
	case <-time.After(30 * time.Second):
		t.Error("resolve through the upstream never reached the target")
	}
	if want := fmt.Sprintf("CONNECT 127.0.0.1:%d", target.Listener.Addr().(*net.TCPAddr).Port); !slices.Contains(up.all(), want) {
		t.Errorf("resolve went around the upstream: %v", up.all())
	}

	// The upstream down: an error, and the server is not reached around it
	// (a new connection from the app: an open tunnel would still carry it).
	up.ln.Close()
	before := tlsConns.Load()
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.Upstream = ln.Addr().String() })
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
}
