package capture

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/net/websocket"
)

// Live scope changes with real mitmproxy (REQCOVE_E2E=1). a.example.com and
// b.example.com both go to one local TLS server, dialed by its address, which
// is in no scope: the SNI and Host alone decide.

type liveEnv struct {
	t     *testing.T
	h     *harness
	addr  string // the server, 127.0.0.1:port
	port  string
	roots *x509.CertPool // mitmproxy's CA and the server's own
	wsGot atomic.Int64   // messages the server received
	rules string         // the --rules file, if any
}

// newLiveEnv starts the server and mitmdump; rules, if not nil, is the
// --rules file's text for the server's port.
func newLiveEnv(t *testing.T, ctx context.Context, allow []string, rules func(port string) string) *liveEnv {
	t.Helper()
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	e := &liveEnv{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) {
		for {
			var m string
			if websocket.Message.Receive(ws, &m) != nil {
				return
			}
			e.wsGot.Add(1)
		}
	}))
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	e.addr = srv.Listener.Addr().String()
	_, e.port, _ = net.SplitHostPort(e.addr)
	caFile := filepath.Join(t.TempDir(), "origin.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	h, err := tryHarness(t, ctx, allow, func(c *Config) {
		c.trustCA = caFile
		if rules != nil {
			e.rules = filepath.Join(t.TempDir(), "rules.yaml")
			os.WriteFile(e.rules, []byte(rules(e.port)), 0o600)
			c.Rules = e.rules
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	ca, _ := os.ReadFile(filepath.Join(h.confdir, "mitmproxy-ca-cert.pem"))
	e.roots = x509.NewCertPool()
	e.roots.AppendCertsFromPEM(ca)
	e.roots.AddCert(srv.Certificate())
	return e
}

func (e *liveEnv) dial(ctx context.Context) (net.Conn, error) {
	socks, _ := proxy.SOCKS5("tcp", e.h.c.SocksAddr, &proxy.Auth{User: "dev", Password: e.h.c.SocksSecret}, proxy.Direct)
	return socks.(proxy.ContextDialer).DialContext(ctx, "tcp", e.addr)
}

// get makes one request to name on a new connection; it says whether
// mitmproxy decrypted it (its CA signed what the client saw).
func (e *liveEnv) get(name, path string) (decrypted bool) {
	e.t.Helper()
	c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext:     func(ctx context.Context, _, _ string) (net.Conn, error) { return e.dial(ctx) },
		TLSClientConfig: &tls.Config{RootCAs: e.roots, ServerName: name},
	}}
	req, _ := http.NewRequest("GET", "https://"+name+":"+e.port+path, nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	r, err := c.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", name, path, err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	return strings.Contains(r.TLS.PeerCertificates[0].Issuer.String(), "mitmproxy")
}

// recorded waits for a flow whose URL holds sub (want), or a second for none.
func (e *liveEnv) recorded(sub string, want bool) (FlowView, bool) {
	deadline := time.Now().Add(map[bool]time.Duration{true: 10 * time.Second, false: time.Second}[want])
	for ; ; time.Sleep(50 * time.Millisecond) {
		if v, ok := e.h.findFlow(sub, false); ok == want || time.Now().After(deadline) {
			return v, ok
		}
	}
}

func (e *liveEnv) ws(ctx context.Context, name, tag string) *websocket.Conn {
	e.t.Helper()
	raw, err := e.dial(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	tc := tls.Client(raw, &tls.Config{RootCAs: e.roots, ServerName: name, NextProtos: []string{"http/1.1"}})
	cfg, _ := websocket.NewConfig("wss://"+name+":"+e.port+"/ws?"+tag, "https://"+name)
	ws, err := websocket.NewClient(cfg, tc)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { ws.Close() })
	return ws
}

// send sends n messages and waits until the server has them all.
func (e *liveEnv) send(ws *websocket.Conn, n int) {
	e.t.Helper()
	want := e.wsGot.Load() + int64(n)
	for i := range n {
		websocket.Message.Send(ws, fmt.Sprintf("m-%d", i))
	}
	for deadline := time.Now().Add(20 * time.Second); e.wsGot.Load() < want; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			e.t.Fatalf("the server got %d of %d", e.wsGot.Load(), want)
		}
	}
}

// wsFlow is the socket tagged tag as the Store keeps it, once the addon's
// lines have had time to arrive.
func (e *liveEnv) wsFlow(tag string) FlowView {
	e.t.Helper()
	time.Sleep(500 * time.Millisecond)
	v, ok := e.h.findFlow("ws?"+tag, false)
	if !ok {
		e.t.Fatalf("no socket %s", tag)
	}
	return v
}

func (e *liveEnv) scope(ctx context.Context, hosts ...string) {
	e.t.Helper()
	r := HostRules{}
	if len(hosts) > 0 {
		r = rulesOf(e.t, hosts...)
	}
	if err := e.h.c.SetScope(ctx, r); err != nil {
		e.t.Fatalf("scope %v: %v", hosts, err)
	}
	if got := e.h.c.Scope().Hosts; !slices.Equal(got, r.Hosts) || e.h.c.ScopePending() != "" {
		e.t.Fatalf("scope %v: status shows %v, pending %q", hosts, got, e.h.c.ScopePending())
	}
}

// TestLiveScopeAddRestartE2E: a host added live is decrypted and recorded on
// new connections, its secrets masked as before; after mitmdump is killed,
// the restarted one keeps the change (its arguments carry the scope and its
// generation) and acknowledges it.
func TestLiveScopeAddRestartE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	e := newLiveEnv(t, ctx, []string{"a.example.com"}, nil)
	if e.get("b.example.com", "/before") {
		t.Error("b decrypted before it was added")
	}
	e.scope(ctx, "a.example.com", "b.example.com")
	check := func(phase string) {
		t.Helper()
		for _, host := range []string{"a.example.com", "b.example.com"} {
			path := "/" + phase + "-" + host + "?token=abc123"
			dec := e.get(host, path)
			v, rec := e.recorded("/"+phase+"-"+host, true)
			if !dec || !rec {
				t.Fatalf("%s %s: decrypted %v, recorded %v", phase, host, dec, rec)
			}
			if strings.Contains(v.URL, "abc123") || strings.Contains(fmt.Sprint(v.ReqHeaders), "s3cret") {
				t.Errorf("%s %s: not masked: %s %v", phase, host, v.URL, v.ReqHeaders)
			}
		}
	}
	check("added")
	b, err := os.ReadFile(filepath.Join(e.h.c.cfg.Dir, "mitmdump.pid"))
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		t.Fatalf("pid: %v", err)
	}
	syscall.Kill(-pid, syscall.SIGKILL)
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if s := e.h.stats(); s["state"] == "ready" && s["restarts"] == int64(1) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no restart: %v", e.h.stats())
		}
	}
	check("restarted")
	if got := e.h.c.Scope().Hosts; !slices.Equal(got, []string{"a.example.com", "b.example.com"}) || e.h.c.ScopePending() != "" {
		t.Errorf("after the restart: status shows %v, pending %q", got, e.h.c.ScopePending())
	}
}

// TestLiveScopeRemoveE2E: a removed host's open WebSocket records nothing
// more and is closed with the error; it does not resume when the host is back.
// Across a stop (nothing recorded) and a start, an open socket's later
// messages are not recorded either; a new one is.
func TestLiveScopeRemoveE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	e := newLiveEnv(t, ctx, []string{"a.example.com"}, nil)
	one := e.ws(ctx, "a.example.com", "one")
	e.send(one, 3)
	e.scope(ctx, "b.example.com")
	e.send(one, 3)
	if v := e.wsFlow("one"); v.WSMessages != 3 || v.State != "error" || v.Error != ScopeCut {
		t.Errorf("removed: %d messages, %s %q", v.WSMessages, v.State, v.Error)
	}
	e.scope(ctx, "a.example.com", "b.example.com")
	e.send(one, 3)
	if v := e.wsFlow("one"); v.WSMessages != 3 {
		t.Errorf("a back: the socket resumed, %d messages", v.WSMessages)
	}
	two := e.ws(ctx, "a.example.com", "two")
	e.send(two, 3)
	e.scope(ctx) // stop
	e.send(two, 3)
	e.scope(ctx, "a.example.com", "b.example.com") // start
	e.send(two, 3)
	if v := e.wsFlow("two"); v.WSMessages != 3 || v.Error != ScopeCut {
		t.Errorf("stop, start: %d messages (3 before the stop), %s %q", v.WSMessages, v.State, v.Error)
	}
	three := e.ws(ctx, "a.example.com", "three")
	e.send(three, 3)
	if v := e.wsFlow("three"); v.WSMessages != 3 || v.State != "open" {
		t.Errorf("a new socket after the start: %d messages, %s", v.WSMessages, v.State)
	}
}

// TestLiveScopeRulesE2E: removing a host a mock names is refused, naming the
// rule, and nothing changes: status, the socket open to it, the mock. The
// rules checked are the ones loaded: the file, changed on disk since (no
// --rules-reload) to name no host, is not read.
func TestLiveScopeRulesE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	e := newLiveEnv(t, ctx, []string{"a.example.com", "b.example.com"}, func(port string) string {
		return fmt.Sprintf("mock:\n  - match: {url: \"https://a.example.com:%s/mocked\"}\n    status: 418\n", port)
	})
	mocked := func(path string) {
		t.Helper()
		e.get("a.example.com", path)
		if v, _ := e.recorded(path, true); !v.Mocked || v.Status != 418 {
			t.Errorf("%s: mocked %v, status %d", path, v.Mocked, v.Status)
		}
	}
	mocked("/mocked")
	ws := e.ws(ctx, "a.example.com", "open")
	e.send(ws, 2)
	os.WriteFile(e.rules, []byte("mock: []\n"), 0o600)
	err := e.h.c.SetScope(ctx, rulesOf(t, "b.example.com"))
	if err == nil || !strings.Contains(err.Error(), "mock[0]: a.example.com is not in the new scope") {
		t.Fatalf("SetScope: %v, want it refused naming mock[0]", err)
	}
	if got := e.h.c.Scope().Hosts; !slices.Equal(got, []string{"a.example.com", "b.example.com"}) || e.h.c.ScopePending() != "" {
		t.Errorf("refused: status shows %v, pending %q", got, e.h.c.ScopePending())
	}
	e.send(ws, 2)
	if v := e.wsFlow("open"); v.WSMessages != 4 || v.State != "open" {
		t.Errorf("refused: the socket has %d messages, %s %q", v.WSMessages, v.State, v.Error)
	}
	mocked("/mocked") // on a new connection: still decrypted, the mock still loaded
	if dec := e.get("a.example.com", "/plain"); !dec {
		t.Error("refused: a no longer decrypted")
	}
}
