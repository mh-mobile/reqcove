package main

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseUpstream(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ok := "http://" + ln.Addr().String()
	if got, err := parseUpstream(ok, ""); err != nil || got != ln.Addr().String() {
		t.Errorf("%s: %q %v", ok, got, err)
	}
	if got, err := parseUpstream("", ""); err != nil || got != "" {
		t.Errorf("none: %q %v", got, err)
	}
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	for _, c := range []struct{ raw, ca, want string }{
		{"", "ca.pem", "needs --upstream-proxy"},
		{"https://" + ln.Addr().String(), "", "want http://HOST:PORT"},
		{ln.Addr().String(), "", "want http://HOST:PORT"},
		{"http://127.0.0.1", "", "want http://HOST:PORT"},
		{"http://user:pw@" + ln.Addr().String(), "", "want http://HOST:PORT"},
		{"http://" + deadAddr, "", "does not answer"},
	} {
		if _, err := parseUpstream(c.raw, c.ca); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q %q: %v, want %q", c.raw, c.ca, err, c.want)
		}
	}
}

// The upstream's CA as Burp exports it (DER) or as PEM becomes a PEM file
// mitmproxy can read; a leaf certificate or junk is refused.
func TestWriteUpstreamCA(t *testing.T) {
	srv := httptest.NewTLSServer(nil) // its test certificate is a CA
	defer srv.Close()
	der := srv.Certificate().Raw
	dir := t.TempDir()
	for name, b := range map[string][]byte{
		"der": der,
		"pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	} {
		in := filepath.Join(dir, name)
		os.WriteFile(in, b, 0o600)
		state := t.TempDir()
		out, err := writeUpstreamCA(in, state)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, _ := os.ReadFile(out)
		p, _ := pem.Decode(got)
		if p == nil {
			t.Fatalf("%s: written file is not PEM", name)
		}
		if c, err := x509.ParseCertificate(p.Bytes); err != nil || !c.IsCA {
			t.Errorf("%s: %v", name, err)
		}
		if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v", name, fi.Mode().Perm())
		}
	}
	junk := filepath.Join(dir, "junk")
	os.WriteFile(junk, []byte("not a certificate"), 0o600)
	if _, err := writeUpstreamCA(junk, t.TempDir()); err == nil {
		t.Error("junk accepted")
	}
}
