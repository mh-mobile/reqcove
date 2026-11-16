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

// client is an HTTP/1.1 client to name, keeping its connection; dials counts
// its connections.
func (e *liveEnv) client(name string, dials *atomic.Int32) *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dials.Add(1)
			return e.dial(ctx)
		},
		TLSClientConfig: &tls.Config{RootCAs: e.roots, ServerName: name},
		TLSNextProto:    map[string]func(string, *tls.Conn) http.RoundTripper{},
	}}
}

// do makes one request with c; it says whether mitmproxy decrypted it (its
// CA signed what the client saw), and the status.
func (e *liveEnv) do(c *http.Client, name, path string) (decrypted bool, status int) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", "https://"+name+":"+e.port+path, nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	r, err := c.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", name, path, err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	return strings.Contains(r.TLS.PeerCertificates[0].Issuer.String(), "mitmproxy"), r.StatusCode
}

// get makes one request to name on a new connection.
func (e *liveEnv) get(name, path string) (decrypted bool) {
	e.t.Helper()
	decrypted, _ = e.do(e.client(name, new(atomic.Int32)), name, path)
	return decrypted
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

// wsFlow is the socket tagged tag as the Store keeps it once done holds (the
// addon's lines arrive a moment after the server has the messages), or after
// wait (for what should not come, the time it is given to come).
func (e *liveEnv) wsFlow(tag string, done func(FlowView) bool, wait time.Duration) FlowView {
	e.t.Helper()
	for deadline := time.Now().Add(wait); ; time.Sleep(50 * time.Millisecond) {
		v, ok := e.h.findFlow("ws?"+tag, false)
		if ok && done(v) || time.Now().After(deadline) {
			return v
		}
	}
}

// wsCut: the socket's flow was ended by the gate; nothing more can come.
func wsCut(v FlowView) bool { return v.State == "error" }

func messages(n int) func(FlowView) bool { return func(v FlowView) bool { return v.WSMessages >= n } }

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
// Its open keep-alive connection stays decrypted, unrecorded; a new one passes
// through undecrypted. Across a stop (nothing recorded) and a start, an open
// socket's later messages are not recorded either; a new one's are.
func TestLiveScopeRemoveE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	e := newLiveEnv(t, ctx, []string{"a.example.com"}, nil)
	one := e.ws(ctx, "a.example.com", "one")
	e.send(one, 3)
	if v := e.wsFlow("one", messages(3), 10*time.Second); v.WSMessages != 3 {
		t.Fatalf("before: %d messages", v.WSMessages)
	}
	var dials atomic.Int32
	ka := e.client("a.example.com", &dials)
	if dec, _ := e.do(ka, "a.example.com", "/ka-before"); !dec {
		t.Fatal("a not decrypted before the removal")
	}
	e.recorded("/ka-before", true)
	e.scope(ctx, "b.example.com")
	e.send(one, 3)
	if v := e.wsFlow("one", wsCut, 10*time.Second); v.WSMessages != 3 || v.State != "error" || v.Error != ScopeCut {
		t.Errorf("removed: %d messages, %s %q", v.WSMessages, v.State, v.Error)
	}
	if dec, _ := e.do(ka, "a.example.com", "/ka-after"); !dec || dials.Load() != 1 {
		t.Errorf("the open connection after the removal: decrypted %v, connections %d", dec, dials.Load())
	}
	if _, rec := e.recorded("/ka-after", false); rec {
		t.Error("recorded on the open connection after the removal")
	}
	if e.get("a.example.com", "/new-after") {
		t.Error("a new connection to a decrypted after the removal")
	}
	if _, rec := e.recorded("/new-after", false); rec {
		t.Error("recorded on a new connection after the removal")
	}
	e.scope(ctx, "a.example.com", "b.example.com")
	e.send(one, 3)
	if v := e.wsFlow("one", messages(4), 2*time.Second); v.WSMessages != 3 {
		t.Errorf("a back: the socket resumed, %d messages", v.WSMessages)
	}
	two := e.ws(ctx, "a.example.com", "two")
	e.send(two, 3)
	e.wsFlow("two", messages(3), 10*time.Second)
	e.scope(ctx) // stop
	e.send(two, 3)
	e.scope(ctx, "a.example.com", "b.example.com") // start
	e.send(two, 3)
	if v := e.wsFlow("two", wsCut, 10*time.Second); v.WSMessages != 3 || v.Error != ScopeCut {
		t.Errorf("stop, start: %d messages (3 before the stop), %s %q", v.WSMessages, v.State, v.Error)
	}
	three := e.ws(ctx, "a.example.com", "three")
	e.send(three, 3)
	if v := e.wsFlow("three", messages(3), 10*time.Second); v.WSMessages != 3 || v.State != "open" {
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
		if _, status := e.do(e.client("a.example.com", new(atomic.Int32)), "a.example.com", path); status != 418 {
			t.Errorf("%s: status %d, want the mock's", path, status)
		}
		if v, _ := e.recorded(path, true); !v.Mocked {
			t.Errorf("%s: recorded as not mocked", path)
		}
	}
	mocked("/mocked?n=1")
	ws := e.ws(ctx, "a.example.com", "open")
	e.send(ws, 2)
	e.wsFlow("open", messages(2), 10*time.Second)
	os.WriteFile(e.rules, []byte("mock: []\n"), 0o600)
	err := e.h.c.SetScope(ctx, rulesOf(t, "b.example.com"))
	if err == nil || !strings.Contains(err.Error(), "mock[0]: a.example.com is not in the new scope") {
		t.Fatalf("SetScope: %v, want it refused naming mock[0]", err)
	}
	if got := e.h.c.Scope().Hosts; !slices.Equal(got, []string{"a.example.com", "b.example.com"}) || e.h.c.ScopePending() != "" {
		t.Errorf("refused: status shows %v, pending %q", got, e.h.c.ScopePending())
	}
	e.send(ws, 2)
	if v := e.wsFlow("open", messages(4), 10*time.Second); v.WSMessages != 4 || v.State != "open" {
		t.Errorf("refused: the socket has %d messages, %s %q", v.WSMessages, v.State, v.Error)
	}
	mocked("/mocked?n=2") // on a new connection: still decrypted, the mock still loaded
}

// TestCaptureStopE2E: reqcove capture stop and start. Stopped: an open
// WebSocket records nothing more and is closed with the error; a mocked URL
// reaches the server (the stand-in), on a new connection (not decrypted) and
// on one decrypted before the stop (not mocked, not recorded); the preset on
// is turned off and none can be turned on. Started: the old socket does not
// resume, a new one records, the mock answers again. Stopped again, a
// restarted mitmdump stays stopped (and its rules still load: they are
// checked against the base, not the empty scope recorded).
func TestCaptureStopE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	e := newLiveEnv(t, ctx, []string{"a.example.com"}, func(port string) string {
		return fmt.Sprintf("mock:\n  - match: {url: \"https://a.example.com:%[1]s/mocked\"}\n    status: 418\n  - match: {url: \"https://a.example.com:%[1]s/preset\"}\n    preset: teapot\n    status: 418\n", port)
	})
	status := func(c *http.Client, path string) (bool, int) {
		t.Helper()
		if c == nil {
			c = e.client("a.example.com", new(atomic.Int32))
		}
		return e.do(c, "a.example.com", path)
	}
	presetOn := func() bool {
		t.Helper()
		ps, err := e.h.c.Presets(ctx)
		if err != nil || len(ps) != 1 {
			t.Fatalf("presets: %v %v", ps, err)
		}
		return ps[0].Active
	}
	if _, st := status(nil, "/mocked?n=1"); st != 418 {
		t.Fatalf("before: the mock did not answer (%d)", st)
	}
	var dials atomic.Int32
	ka := e.client("a.example.com", &dials)
	if dec, _ := status(ka, "/ka-before"); !dec {
		t.Fatal("not decrypted before the stop")
	}
	e.recorded("/ka-before", true)
	one := e.ws(ctx, "a.example.com", "one")
	e.send(one, 3)
	e.wsFlow("one", messages(3), 10*time.Second)
	if _, err := e.h.c.Activate(ctx, "teapot", 60, 0); err != nil || !presetOn() {
		t.Fatalf("activate before the stop: %v", err)
	}

	if _, err := e.h.c.SetStopped(ctx, "capture stop", true); err != nil {
		t.Fatal(err)
	}
	if !e.h.c.Stopped() || e.h.c.ScopePending() != "" || !slices.Equal(e.h.c.Scope().Hosts, []string{"a.example.com"}) || e.h.stats()["recording"] != "stopped" {
		t.Errorf("stopped: %v, pending %q, base %v, stats %v", e.h.c.Stopped(), e.h.c.ScopePending(), e.h.c.Scope().Hosts, e.h.stats()["recording"])
	}
	e.send(one, 3)
	if v := e.wsFlow("one", wsCut, 10*time.Second); v.WSMessages != 3 || v.Error != ScopeCut {
		t.Errorf("stopped: the socket has %d messages, %s %q", v.WSMessages, v.State, v.Error)
	}
	if dec, st := status(nil, "/mocked?s=new"); dec || st != 200 {
		t.Errorf("stopped, a new connection: decrypted %v, status %d (want the server's 200, undecrypted)", dec, st)
	}
	if dec, st := status(ka, "/mocked?s=open"); !dec || st != 200 || dials.Load() != 1 {
		t.Errorf("stopped, the connection decrypted before: decrypted %v, status %d (want the server's 200, not the mock's), connections %d", dec, st, dials.Load())
	}
	if _, rec := e.recorded("/mocked?s=", false); rec {
		t.Error("recorded while stopped")
	}
	if presetOn() {
		t.Error("the preset is still on after the stop")
	}
	if _, err := e.h.c.Activate(ctx, "teapot", 60, 0); err == nil || !strings.Contains(err.Error(), "recording is stopped") {
		t.Errorf("activate while stopped: %v, want refused", err)
	}

	if base, err := e.h.c.SetStopped(ctx, "capture start", false); err != nil || !slices.Equal(base.Hosts, []string{"a.example.com"}) {
		t.Fatalf("start: %v %v", base.Hosts, err)
	}
	if e.h.c.Stopped() || e.h.stats()["recording"] != "on" {
		t.Error("still stopped after the start")
	}
	e.send(one, 3)
	if v := e.wsFlow("one", messages(4), 2*time.Second); v.WSMessages != 3 {
		t.Errorf("started: the old socket resumed, %d messages", v.WSMessages)
	}
	two := e.ws(ctx, "a.example.com", "two")
	e.send(two, 3)
	if v := e.wsFlow("two", messages(3), 10*time.Second); v.WSMessages != 3 || v.State != "open" {
		t.Errorf("started: a new socket has %d messages, %s", v.WSMessages, v.State)
	}
	if _, st := status(nil, "/mocked?n=2"); st != 418 {
		t.Errorf("started: the mock did not answer (%d)", st)
	}
	if v, _ := e.recorded("/mocked?n=2", true); !v.Mocked {
		t.Error("started: not recorded as mocked")
	}
	if presetOn() {
		t.Error("the preset came back on with the start")
	}

	// Stopped again, then mitmdump killed: the restarted one is stopped too.
	if _, err := e.h.c.SetStopped(ctx, "capture stop", true); err != nil {
		t.Fatal(err)
	}
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
	if dec, st := status(nil, "/mocked?s=restarted"); dec || st != 200 || !e.h.c.Stopped() {
		t.Errorf("restarted: decrypted %v, status %d, stopped %v (want still stopped)", dec, st, e.h.c.Stopped())
	}
	if _, rec := e.recorded("/mocked?s=restarted", false); rec {
		t.Error("recorded after the restart while stopped")
	}
}

// TestAllowAllE2E: reqcove capture allow-all with real mitmproxy. During it
// a host outside the base is decrypted and recorded, with no rule applied to
// it (a modify_headers rule naming no host applies to the base's alone);
// ended, a new connection to it is neither decrypted nor recorded, one open
// since stays decrypted but unrecorded, and the records made meanwhile stay.
func TestAllowAllE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	e := newLiveEnv(t, ctx, []string{"a.example.com"}, func(string) string { return "modify_headers:\n  - \"|~q|X-Injected|yes\"\n" })
	injected := func(v FlowView) bool {
		return slices.ContainsFunc(v.Rewrites, func(r string) bool { return strings.Contains(r, "X-Injected") })
	}
	if e.get("b.example.com", "/before") {
		t.Error("b decrypted before allow-all")
	}
	base, _ := rulesOf(t, "a.example.com").WithPass([]string{"c.example.com"}) // c: an app that pins (not among the hosts recorded)
	if err := e.h.c.SetScope(ctx, base); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.h.c.SetAllowAll(ctx, "capture allow-all --for 1h", time.Hour); err != nil {
		t.Fatal(err)
	}
	if e.get("c.example.com", "/passed") {
		t.Error("a --pass-hosts host decrypted during allow-all")
	}
	if e.h.c.AllowAllUntil().IsZero() || e.h.c.ScopePending() != "" || e.h.stats()["recording"] != RecordingAllowAll || !slices.Equal(e.h.c.Scope().Hosts, []string{"a.example.com"}) {
		t.Errorf("on: until %v, pending %q, stats %v, base %v", e.h.c.AllowAllUntil(), e.h.c.ScopePending(), e.h.stats()["recording"], e.h.c.Scope().Hosts)
	}
	if !e.get("b.example.com", "/during") {
		t.Error("b not decrypted during allow-all")
	}
	if v, ok := e.recorded("/during", true); !ok || injected(v) {
		t.Errorf("during: recorded %v, rewrites %v (want recorded, no rule)", ok, v.Rewrites)
	}
	if x, err := e.h.c.Explain(ctx, "GET", "https://b.example.com:"+e.port+"/x", ""); err != nil || !strings.Contains(x.Scope, "recorded while allow-all is on") || len(x.Rewrites) != 0 {
		t.Errorf("explain_rules during allow-all: %+v %v", x, err)
	}
	e.get("a.example.com", "/base")
	if v, ok := e.recorded("/base", true); !ok || !injected(v) {
		t.Errorf("the base during allow-all: recorded %v, rewrites %v (want the rule)", ok, v.Rewrites)
	}
	var dials atomic.Int32
	kb := e.client("b.example.com", &dials)
	if dec, _ := e.do(kb, "b.example.com", "/ka-during"); !dec {
		t.Error("kept-alive b not decrypted during allow-all")
	}
	e.recorded("/ka-during", true)

	if err := e.h.c.EndAllowAll(ctx, "capture allow-all --end"); err != nil {
		t.Fatal(err)
	}
	if !e.h.c.AllowAllUntil().IsZero() || e.h.stats()["recording"] != RecordingOn {
		t.Errorf("ended: until %v, stats %v", e.h.c.AllowAllUntil(), e.h.stats()["recording"])
	}
	if e.get("b.example.com", "/after") {
		t.Error("b decrypted on a new connection after the end")
	}
	if dec, _ := e.do(kb, "b.example.com", "/ka-after"); !dec || dials.Load() != 1 {
		t.Errorf("the connection open since: decrypted %v, connections %d (want still decrypted, one)", dec, dials.Load())
	}
	for _, p := range []string{"/after", "/ka-after"} {
		if _, rec := e.recorded(p, false); rec {
			t.Errorf("%s recorded after the end", p)
		}
	}
	if _, ok := e.recorded("/during", true); !ok || e.h.c.Store.OutsideScope(e.h.c.Scope()) != 2 {
		t.Errorf("allow-all's records: kept %v, outside the base %d (want 2)", ok, e.h.c.Store.OutsideScope(e.h.c.Scope()))
	}
}

// TestAllowAllKillE2E: mitmdump killed just before allow-all's end, so it is
// down when the end comes: the one started next has no allow-all (no
// extension), and the records made meanwhile stay.
func TestAllowAllKillE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	e := newLiveEnv(t, ctx, []string{"a.example.com"}, nil)
	until, _, err := e.h.c.SetAllowAll(ctx, "capture allow-all --for 8s", 8*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !e.get("b.example.com", "/during") {
		t.Fatal("b not decrypted during allow-all")
	}
	e.recorded("/during", true)
	b, err := os.ReadFile(filepath.Join(e.h.c.cfg.Dir, "mitmdump.pid"))
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		t.Fatalf("pid: %v", err)
	}
	time.Sleep(time.Until(until) - 500*time.Millisecond)
	syscall.Kill(-pid, syscall.SIGKILL)
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if s := e.h.stats(); s["state"] == "ready" && s["restarts"] == int64(1) && e.h.c.AllowAllUntil().IsZero() && e.h.c.ScopePending() == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no restart without allow-all: %v, until %v, pending %q", e.h.stats(), e.h.c.AllowAllUntil(), e.h.c.ScopePending())
		}
	}
	if e.get("b.example.com", "/after") {
		t.Error("b decrypted after the end: allow-all outlived its time in the restarted mitmdump")
	}
	if _, rec := e.recorded("/after", false); rec {
		t.Error("b recorded after the end")
	}
	if _, ok := e.recorded("/during", true); !ok {
		t.Error("allow-all's record gone")
	}
}
