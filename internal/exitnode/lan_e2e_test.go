package exitnode

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// TestLANEndToEnd: the LAN proxy on loopback (its network 127.0.0.0/8, the
// client 127.0.0.1 allowed) hands a public host's HTTP and HTTPS to real
// mitmproxy, which records them as the device lan:127.0.0.1; mitm.it serves
// the CA through it. Opt-in: it fetches mitmproxy with uvx and reaches
// example.org and mitm.it.
func TestLANEndToEnd(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "rcvl-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	confdir := t.TempDir()
	allow, _ := capture.ParseAllowHosts([]string{"example.org"})
	c, err := capture.Start(ctx, capture.Config{AllowHosts: allow,
		Dir: dir, Confdir: confdir, Uvx: "uvx", Python: "3.14", MitmSpec: "mitmproxy==12.3.1",
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes, Log: os.Stderr, ReadyTimeout: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	port := freePort(t)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{SocksAddr: c.SocksAddr, SocksSecret: c.SocksSecret, SocksReady: c.WaitReady, ProxyPort: port,
			LAN:       &LAN{Interface: loopbackName(t), Allowed: allowedAt("127.0.0.1"), Names: []string{"example.org"}},
			OnDevices: c.Store.SetDeviceNames})
	}()
	defer func() { cancel(); <-done }()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitFor(t, func() bool {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
		}
		return err == nil
	}, "listening on "+addr)

	pem, err := os.ReadFile(filepath.Join(confdir, "mitmproxy-ca-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	proxy, _ := url.Parse("http://" + addr)
	hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: time.Minute}
	get := func(u string) string {
		t.Helper()
		r, err := hc.Get(u)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		if r.StatusCode >= 400 {
			t.Fatalf("%s: %s", u, r.Status)
		}
		return string(b)
	}
	get("http://example.org/?lan=plain")
	get("https://example.org/?lan=tls") // decrypted: the CA is trusted here
	if served := get("http://mitm.it/cert/pem"); !strings.Contains(served, strings.TrimSpace(string(pem))) {
		t.Error("mitm.it through the LAN proxy hands out another CA")
	}
	// A client whose first write is 1 or 2 bytes of its ClientHello, or of its
	// request short of "HTTP/": mitmproxy, given that alone, passes it
	// through unrecorded (holdConn). Through a CONNECT tunnel, as an exit
	// node flow goes through dialVia too.
	tunnel := func(port string, n int) net.Conn {
		t.Helper()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "CONNECT example.org:%s HTTP/1.1\r\nHost: example.org:%s\r\n\r\n", port, port)
		br := bufio.NewReader(conn)
		if r, err := http.ReadResponse(br, nil); err != nil || r.StatusCode != 200 {
			t.Fatalf("CONNECT :%s: %v %v", port, r, err)
		}
		return &splitConn{Conn: conn, n: n}
	}
	for _, n := range []int{1, 2} {
		tc := tls.Client(tunnel("443", n), &tls.Config{ServerName: "example.org", RootCAs: roots})
		if err := tc.Handshake(); err != nil {
			t.Errorf("a ClientHello's first %d bytes alone: %v", n, err) // the real certificate: passed through
			tc.Close()
			continue
		}
		fmt.Fprintf(tc, "GET /?lan=split-tls%d HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n", n)
		io.Copy(io.Discard, tc)
		tc.Close()
	}
	for _, n := range []int{1, 14} {
		conn := tunnel("80", n)
		fmt.Fprintf(conn, "GET /?lan=split-http%02d HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n", n)
		io.Copy(io.Discard, conn)
		conn.Close()
	}
	for _, sub := range []string{"split-tls1", "split-tls2", "split-http01", "split-http14"} {
		found := false
		for range 100 {
			if fs, _ := c.Store.List(capture.Filter{Device: "lan:127.0.0.1", Limit: 50}); slices.ContainsFunc(fs, func(f capture.Summary) bool { return strings.Contains(f.URL, sub) }) {
				found = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !found {
			t.Errorf("%s: not recorded (passed through)", sub)
		}
	}
	for range 100 {
		if fs, _ := c.Store.List(capture.Filter{Device: "lan:127.0.0.1", Limit: 10}); len(fs) >= 2 {
			for _, f := range fs {
				if f.Device != "lan:127.0.0.1" || !strings.Contains(f.URL, "lan=") {
					t.Errorf("flow %+v", f)
				}
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	fs, _ := c.Store.List(capture.Filter{Limit: 10})
	t.Fatalf("not recorded as lan:127.0.0.1: %+v", fs)
}

// splitConn writes its first Write's first n bytes, pauses, then the rest.
type splitConn struct {
	net.Conn
	n    int
	done bool
}

func (c *splitConn) Write(p []byte) (int, error) {
	if c.done || len(p) <= c.n {
		return c.Conn.Write(p)
	}
	c.done = true
	if _, err := c.Conn.Write(p[:c.n]); err != nil {
		return 0, err
	}
	time.Sleep(300 * time.Millisecond)
	_, err := c.Conn.Write(p[c.n:])
	return len(p), err
}
