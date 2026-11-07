package capture

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// TestCANamed (REQCOVE_E2E=1): a new confdir gets a CA with reqcove's name,
// made by mitmproxy's own create_store (internal API, so this catches a
// change), mitm.it hands out that CA, and a later start keeps it.
func TestCANamed(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	const name = "Reqcove CA (test-host, 2026-11-07)"
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.CAName = name })
	if err != nil {
		t.Fatal(err)
	}
	ca := h.c.CA
	if ca.Name != name || len(ca.SHA256) != 64 || ca.NotAfter.Before(time.Now().AddDate(9, 0, 0)) {
		t.Fatalf("CA = %+v", ca)
	}
	if fi, err := os.Stat(h.confdir + "/mitmproxy-ca.pem"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("CA key file: %v %v", fi, err)
	}
	// mitm.it serves this CA.
	socks, _ := proxy.SOCKS5("tcp", h.c.SocksAddr, &proxy.Auth{User: "dev", Password: h.c.SocksSecret}, proxy.Direct)
	hc := &http.Client{Transport: &http.Transport{DialContext: socks.(proxy.ContextDialer).DialContext}, Timeout: 30 * time.Second}
	r, err := hc.Get("http://mitm.it/cert/pem")
	if err != nil {
		t.Fatal(err)
	}
	served, _ := io.ReadAll(r.Body)
	r.Body.Close()
	own, _ := os.ReadFile(h.confdir + "/mitmproxy-ca-cert.pem")
	if !strings.Contains(string(served), strings.TrimSpace(string(own))) {
		t.Error("mitm.it hands out a different CA")
	}
	// Restarting on the same confdir keeps the CA, whatever the name says now.
	h.c.Stop()
	confdir := h.confdir
	h2, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.Confdir = confdir; c.CAName = "Reqcove CA (other, 2030-01-01)" })
	if err != nil {
		t.Fatal(err)
	}
	if h2.c.CA != ca {
		t.Errorf("CA changed on restart: %+v, was %+v", h2.c.CA, ca)
	}
}
