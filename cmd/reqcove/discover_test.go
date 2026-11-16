package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
	"golang.org/x/net/proxy"
)

// The arguments of capture discover: --for D or --end, no hosts.
func TestDiscoverArgs(t *testing.T) {
	if req, err := (ctlRequest{Cmd: "discover", For: "30m"}).normalized(); err != nil || req.String() != "capture discover --for 30m" {
		t.Errorf("%v %q", err, req.String())
	}
	if req, err := (ctlRequest{Cmd: "discover", End: true}).normalized(); err != nil || req.String() != "capture discover --end" {
		t.Errorf("%v %q", err, req.String())
	}
	for _, c := range []struct {
		req  ctlRequest
		want string
	}{
		{ctlRequest{Cmd: "discover"}, "capture discover takes --for D"},
		{ctlRequest{Cmd: "discover", For: "25h"}, "at most 24h"},
		{ctlRequest{Cmd: "discover", For: "1h", Hosts: []string{"a.com"}}, "takes no hosts"},
		{ctlRequest{Cmd: "add", Hosts: []string{"a.com"}, For: "1h"}, "go with capture allow-all and capture discover"},
	} {
		if _, err := c.req.normalized(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c.req, err)
		}
	}
	var b strings.Builder
	printSeen(&b, []mcpserver.OutHost{{Host: "a.example.net", Count: 2, Add: "reqcove capture add a.example.net"}, {Host: "[redacted].example.net", Count: 1}}, 40, true)
	if got := b.String(); !strings.Contains(got, "host discovery on; seen outside them so far (the 2 most seen of 40)") || !strings.Contains(got, "    a.example.net (2): reqcove capture add a.example.net\n") || !strings.Contains(got, "[redacted].example.net (1): (no command") {
		t.Errorf("printed:\n%s", got)
	}
}

// TestDiscoverE2E (REQCOVE_E2E=1, real mitmproxy): reqcove capture discover
// over ctl.sock. While on, a TLS connection outside the scope gives its SNI
// (counted once a connection), a request on an allowed connection its Host,
// none of Apple's, and nothing of what they carry is recorded; the names are
// in this computer's status (with the capture add command) and summarize,
// never in what --mcp-http and --ui read (liveStatus, capture_stats). Before
// and after it, no name is taken; one added since drops off the list.
func TestDiscoverE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "rcvd-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	state := filepath.Join(dir, "s")
	allow, _ := capture.ParseAllowHosts([]string{"localhost"})
	c, err := capture.Start(ctx, capture.Config{Dir: state, Confdir: filepath.Join(dir, "m"),
		Uvx: "uvx", Python: defaultPython, MitmSpec: defaultMitmSpec,
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
		Log: os.Stderr, ReadyTimeout: 2 * time.Minute, AllowHosts: allow})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	mcpserver.CaptureAddCmd = withState("reqcove capture add", state)
	defer func() { mcpserver.CaptureAddCmd = "" }()
	if _, err := serveCtl(ctx, state, c, &runOpts{}, nil); err != nil {
		t.Fatal(err)
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secret body") }))
	defer secure.Close()
	socks, _ := proxy.SOCKS5("tcp", c.SocksAddr, &proxy.Auth{User: "dev", Password: c.SocksSecret}, proxy.Direct)
	// tlsTo opens a TLS connection to the TLS server, named sni (outside the
	// scope: carried undecrypted), and sends a request on it.
	tlsTo := func(sni string) {
		t.Helper()
		conn, err := socks.Dial("tcp", strings.TrimPrefix(secure.URL, "https://"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err := tc.Handshake(); err != nil {
			t.Fatalf("%s: %v", sni, err)
		}
		io.WriteString(tc, "GET /path-secret HTTP/1.1\r\nHost: "+sni+"\r\nConnection: close\r\n\r\n")
		io.ReadAll(tc)
	}
	hc := &http.Client{Transport: &http.Transport{DialContext: socks.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}, Timeout: 30 * time.Second}
	viaHost := func(host string) { // on a connection to localhost, recorded
		t.Helper()
		req, _ := http.NewRequest("GET", strings.Replace(plain.URL, "127.0.0.1", "localhost", 1)+"/x", nil)
		req.Host = host
		r, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	node := exitnode.Status{Backend: "Running"}
	local := func() mcpserver.StatusOut { return withDiscovery(liveStatus(node, c), c) }
	count := func(host string) int {
		for _, h := range local().OutOfScopeHosts {
			if h.Host == host {
				return h.Count
			}
		}
		return 0
	}
	change := func(req ctlRequest) string {
		t.Helper()
		var out strings.Builder
		if err := sendCapture(ctx, &out, state, req); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	tlsTo("before.example.net")
	if out := change(ctlRequest{Cmd: "discover", For: "10m"}); !strings.HasPrefix(out, "applied: host discovery on until") || !strings.Contains(out, "never over --mcp-http or on the --ui page") || !strings.Contains(out, "ECH") {
		t.Errorf("on: %q", out)
	}
	tlsTo("out.example.net")
	tlsTo("out.example.net")
	tlsTo("gateway.icloud.com")
	viaHost("viahost.example.net")
	for deadline := time.Now().Add(10 * time.Second); count("out.example.net") < 2 || count("viahost.example.net") < 1; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("seen: %+v", local().OutOfScopeHosts)
		}
	}
	time.Sleep(300 * time.Millisecond) // a second count of a connection, if any, would be in by now
	s := local()
	if count("out.example.net") != 2 || count("before.example.net") != 0 || count("gateway.icloud.com") != 0 || s.OutOfScopeHostsKept != 2 || s.DiscoverUntil == "" {
		t.Errorf("seen: %+v, kept %d, until %q", s.OutOfScopeHosts, s.OutOfScopeHostsKept, s.DiscoverUntil)
	}
	if h := s.OutOfScopeHosts[0]; h.Add != withState("reqcove capture add", state)+" out.example.net" {
		t.Errorf("command: %q", h.Add)
	}
	if !strings.Contains(strings.Join(s.NextSteps, "\n"), "host discovery is on until") {
		t.Errorf("steps: %q", s.NextSteps)
	}
	// Nothing of what they carry; nothing of them where --mcp-http and --ui read.
	if st := c.Store.Stats(); st["flows"] != 0 {
		t.Errorf("flows: %v", st["flows"])
	}
	remote, _ := json.Marshal(liveStatus(node, c))
	stats, _ := json.Marshal(c.Store.Stats())
	for _, b := range [][]byte{remote, stats} {
		if strings.Contains(string(b), "example.net") || strings.Contains(string(b), "path-secret") {
			t.Errorf("names where --mcp-http or --ui reads: %s", b)
		}
	}

	if out := change(ctlRequest{Cmd: "discover", End: true}); !strings.HasPrefix(out, "applied: host discovery ended: no name is taken from now; the 2 names seen stay") {
		t.Errorf("end: %q", out)
	}
	tlsTo("after.example.net")
	viaHost("after2.example.net")
	time.Sleep(500 * time.Millisecond)
	if s := local(); count("after.example.net")+count("after2.example.net") != 0 || count("out.example.net") != 2 || s.DiscoverUntil != "" {
		t.Errorf("after the end: %+v, until %q", s.OutOfScopeHosts, s.DiscoverUntil)
	}
	change(ctlRequest{Cmd: "add", Hosts: []string{"out.example.net"}})
	if count("out.example.net") != 0 || count("viahost.example.net") != 1 {
		t.Errorf("after the add: %+v", local().OutOfScopeHosts)
	}
	if s := liveStatus(node, c); s.ScopeChange != "capture add out.example.net" {
		t.Errorf("trace: %q", s.ScopeChange)
	}
}
