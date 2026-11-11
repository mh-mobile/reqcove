package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// parseUpstream checks --upstream-proxy (http://HOST:PORT, answering now) and
// returns HOST:PORT for mitmproxy.
func parseUpstream(raw, ca string) (string, error) {
	if raw == "" {
		if ca != "" {
			return "", errors.New("--upstream-ca needs --upstream-proxy")
		}
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" || u.Port() == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("--upstream-proxy %q: want http://HOST:PORT", raw)
	}
	c, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("--upstream-proxy %s does not answer (start it first): %w", u.Host, err)
	}
	c.Close()
	return u.Host, nil
}

// writeUpstreamCA reads the upstream's CA certificate, PEM or DER, and writes
// it as PEM into the state directory for mitmproxy (which cannot read DER).
func writeUpstreamCA(path, state string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("--upstream-ca: %w", err)
	}
	return saveUpstreamCA(b, path, state)
}

// fetchBurpCA gets Burp's CA from the proxy's own /cert, when the proxy is on
// this computer: over a network, plain HTTP could hand back someone else's CA.
// Other proxies answer with an error.
func fetchBurpCA(upstream string) ([]byte, error) {
	host, _, _ := net.SplitHostPort(upstream)
	if ip, err := netip.ParseAddr(host); (err != nil || !ip.IsLoopback()) && host != "localhost" {
		return nil, errors.New("not on this computer")
	}
	// Straight from the listener (Burp answers its own page there too), not
	// http://burp/cert through it: a proxy that is not Burp would look "burp"
	// up and fetch it from wherever the network's DNS says.
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := c.Get("http://" + upstream + "/cert")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http://%s/cert: %s", upstream, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	// Burp's own CA only: another proxy's answer must not become the CA trusted.
	if c, err := x509.ParseCertificate(b); err != nil || c.Subject.CommonName != "PortSwigger CA" {
		return nil, errors.New("not Burp's CA (PortSwigger CA)")
	}
	return b, nil
}

// saveUpstreamCA checks a CA certificate (PEM or DER) from src and writes it as
// PEM into the state directory for mitmproxy.
func saveUpstreamCA(b []byte, path, state string) (string, error) {
	// PEM: the first certificate (a file may hold a key first); else DER.
	for rest := b; ; {
		var p *pem.Block
		if p, rest = pem.Decode(rest); p == nil {
			break
		}
		if p.Type == "CERTIFICATE" {
			b = p.Bytes
			break
		}
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return "", fmt.Errorf("--upstream-ca %s: not a certificate (PEM or DER): %w", path, err)
	}
	if !cert.IsCA {
		return "", fmt.Errorf("--upstream-ca %s: %q is not a CA certificate", path, cert.Subject.CommonName)
	}
	out := filepath.Join(state, "upstream-ca.pem")
	if err := os.WriteFile(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		return "", err
	}
	return out, nil
}
