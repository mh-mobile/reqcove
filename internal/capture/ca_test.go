package capture

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	// The certificate files lost, the key kept: never a new CA (the iPhone
	// trusts this one); they are written again from mitmproxy-ca.pem.
	h2.c.Stop()
	for _, name := range []string{"mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.p12"} {
		os.Remove(filepath.Join(confdir, name))
	}
	h2, err = tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.Confdir = confdir; c.CAName = "Reqcove CA (third, 2031-01-01)" })
	if err != nil {
		t.Fatal(err)
	}
	if h2.c.CA != ca {
		t.Errorf("certificate files lost: CA %+v, was %+v", h2.c.CA, ca)
	}
	for _, name := range []string{"mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.p12"} {
		if _, err := os.Stat(filepath.Join(confdir, name)); err != nil {
			t.Errorf("%s not written again: %v", name, err)
		}
	}
	// Another node's confdir with the CA copied (CopyCA): the same CA, and
	// mitm.it hands it out there too.
	h2.c.Stop()
	copied := filepath.Join(t.TempDir(), "mitmproxy")
	if ok, err := CopyCA(confdir, copied); !ok || err != nil {
		t.Fatalf("CopyCA: %v %v", ok, err)
	}
	h3, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.Confdir = copied; c.CAName = "Reqcove CA (other, 2030-01-01)" })
	if err != nil {
		t.Fatal(err)
	}
	if h3.c.CA != ca {
		t.Errorf("copied CA: %+v, was %+v", h3.c.CA, ca)
	}
	socks, _ = proxy.SOCKS5("tcp", h3.c.SocksAddr, &proxy.Auth{User: "dev", Password: h3.c.SocksSecret}, proxy.Direct)
	hc = &http.Client{Transport: &http.Transport{DialContext: socks.(proxy.ContextDialer).DialContext}, Timeout: 30 * time.Second}
	for _, ext := range []string{"pem", "p12", "cer"} {
		r, err := hc.Get("http://mitm.it/cert/" + ext)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		want, _ := os.ReadFile(filepath.Join(confdir, "mitmproxy-ca-cert."+ext))
		if r.StatusCode != 200 || string(b) != string(want) {
			t.Errorf("mitm.it/cert/%s from the copy: %d, %d bytes, want %d", ext, r.StatusCode, len(b), len(want))
		}
	}
}

// TestRulesKeepGoing: a rules file that does not load stops a start, and a
// restart without --rules-reload; under --rules-reload a restart goes on.
func TestRulesKeepGoing(t *testing.T) {
	for _, c := range []struct{ restarted, reload, want bool }{{false, false, false}, {false, true, false}, {true, false, false}, {true, true, true}} {
		if got := rulesKeepGoing(c.restarted, c.reload); got != c.want {
			t.Errorf("restarted=%v reload=%v: %v", c.restarted, c.reload, got)
		}
	}
}
