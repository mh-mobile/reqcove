package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	// A key before the certificate in one PEM file: the certificate is found.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	both := filepath.Join(dir, "key-and-ca.pem")
	os.WriteFile(both, append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...), 0o600)
	if _, err := writeUpstreamCA(both, t.TempDir()); err != nil {
		t.Errorf("key, then CA: %v", err)
	}
	// A leaf (not a CA) is refused.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "leaf.example"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	leafDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf := filepath.Join(dir, "leaf.der")
	os.WriteFile(leaf, leafDER, 0o600)
	if _, err := writeUpstreamCA(leaf, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Errorf("leaf: %v", err)
	}
}
