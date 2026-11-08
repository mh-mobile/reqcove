package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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

// Burp's CA is fetched from http://burp/cert through the proxy, when the proxy
// is on this computer; another proxy's error, or a remote proxy, gives none.
func TestFetchBurpCA(t *testing.T) {
	ca := httptest.NewTLSServer(nil)
	defer ca.Close()
	burp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host == "burp" && r.URL.Path == "/cert" {
			w.Write(ca.Certificate().Raw) // DER, as Burp serves it
			return
		}
		http.NotFound(w, r)
	}))
	defer burp.Close()
	b, err := fetchBurpCA(burp.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saveUpstreamCA(b, "http://burp/cert", t.TempDir()); err != nil {
		t.Errorf("fetched CA: %v", err)
	}
	other := httptest.NewServer(http.NotFoundHandler()) // a proxy without http://burp/cert
	defer other.Close()
	if _, err := fetchBurpCA(other.Listener.Addr().String()); err == nil {
		t.Error("a proxy answering 404 gave a CA")
	}
	if _, err := fetchBurpCA("192.0.2.1:8080"); err == nil || !strings.Contains(err.Error(), "not on this computer") {
		t.Errorf("remote proxy: %v", err)
	}
}

// A missing --device suggests this user's iPhones and iPads, online first.
func TestIOSDevices(t *testing.T) {
	old := tailscaleStatus
	defer func() { tailscaleStatus = old }()
	tailscaleStatus = func() ([]byte, error) {
		return []byte(`{"Self":{"UserID":1},"Peer":{
			"a":{"DNSName":"ipad-old.tail.ts.net.","OS":"iOS","UserID":1,"Online":false},
			"b":{"DNSName":"iphone-duo.tail.ts.net.","OS":"iOS","UserID":1,"Online":true},
			"c":{"DNSName":"mac.tail.ts.net.","OS":"macOS","UserID":1,"Online":true},
			"d":{"DNSName":"their-iphone.tail.ts.net.","OS":"iOS","UserID":2,"Online":true}}}`), nil
	}
	if got := strings.Join(iosDevices(), ", "); got != "iphone-duo (online), ipad-old" {
		t.Errorf("got %q", got)
	}
	tailscaleStatus = func() ([]byte, error) { return nil, os.ErrNotExist }
	if got := iosDevices(); got != nil {
		t.Errorf("without the CLI: %v", got)
	}
}

// --dns takes addresses with or without a port (53), comma-separated, or "system".
func TestParseDNS(t *testing.T) {
	got, err := parseDNS("1.1.1.1, 9.9.9.9:5353,2606:4700::1111,[2606:4700::1001]:53")
	if err != nil || fmt.Sprint(got) != "[1.1.1.1:53 9.9.9.9:5353 [2606:4700::1111]:53 [2606:4700::1001]:53]" {
		t.Errorf("got %v %v", got, err)
	}
	if got, err := parseDNS("system"); got != nil || err != nil {
		t.Errorf("system: %v %v", got, err)
	}
	for _, bad := range []string{"dns.google", "1.1.1.1:x", ""} {
		if _, err := parseDNS(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// --allow-hosts values pasted as URLs or with a port become their hosts.
func TestHostsOnly(t *testing.T) {
	got := hostsOnly([]string{"https://API.example.com/v1?x=1, api2.example.com:443", "*.example.org", "[2001:db8::1]:443"})
	if want := []string{"API.example.com,api2.example.com", "*.example.org", "2001:db8::1"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
