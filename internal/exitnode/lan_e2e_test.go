package exitnode

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
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
			LAN:       &LAN{Interface: loopbackName(t), Allowed: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("127.0.0.1")} }, Names: []string{"example.org"}},
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
