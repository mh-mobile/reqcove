package capture

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMockPresets (REQCOVE_E2E=1): a preset answers only while turned on, for
// its time and its count; one preset on per match (method, URL, operation);
// presets on come before plain mocks; refusals say why; a reload turns them off.
func TestMockPresets(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, "origin %s", r.URL.Path)
	}))
	defer origin.Close()
	o := origin.Listener.Addr().String()
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.yaml")
	write := func(extra string) {
		os.WriteFile(rules, []byte(fmt.Sprintf(`mock:
  - match: {url: "http://%[1]s/profile"}
    preset: profile-503
    description: the profile API is down
    status: 503
    headers: {X-Mark: HDRMARK7}
    body: down
  - match: {url: "http://%[1]s/profile"}
    preset: profile-500
    status: 500
  - match: {url: "http://%[1]s/graphql", operation: Feed}
    preset: feed-500
    status: 500
  - match: {url: "http://%[1]s/graphql", operation: Login}
    preset: login-401
    status: 401
  - match: {url: "http://%[1]s/plain"}
    status: 418
  - match: {url: "http://%[1]s/order"}
    preset: order-503
    status: 503
    body: BODYMARK7
  - match: {url: "http://%[1]s/order*"}
    status: 418
%[2]s`, o, extra)), 0o600)
	}
	write("")
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.Rules, c.RulesReload = rules, true })
	if err != nil {
		t.Fatal(err)
	}
	hc := h.client("dev")
	get := func(path, body string) string {
		t.Helper()
		req, _ := http.NewRequest("GET", "http://"+o+path, nil)
		if body != "" {
			req, _ = http.NewRequest("POST", "http://"+o+path, strings.NewReader(body))
		}
		resp, err := hc.Do(req)
		if err != nil {
			return "error: " + err.Error()
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return fmt.Sprintf("%d %s", resp.StatusCode, b)
	}
	if got := get("/profile", ""); got != "200 origin /profile" {
		t.Errorf("a preset off answers: %q", got)
	}
	ps, err := h.c.Presets(ctx, "")
	if err != nil || len(ps) != 5 || ps[0].Name != "profile-503" || ps[0].Description != "the profile API is down" || ps[0].Active || *ps[0].Status != 503 {
		b, _ := json.Marshal(ps)
		t.Fatalf("presets: %s %v", b, err)
	}

	// Once: the next request, then the origin again.
	if a, err := h.c.Activate(ctx, "profile-503", "", 60, 1); err != nil || a.ExpiresAt < float64(time.Now().Unix()+50) {
		t.Fatalf("activate: %+v %v", a, err)
	}
	if got := get("/profile", ""); got != "503 down" {
		t.Errorf("once: %q", got)
	}
	if got := get("/profile?n=after-once", ""); got != "200 origin /profile" {
		t.Errorf("after once: %q", got)
	}
	if f := h.doneFlow("n=after-once", false); f.Preset != "" {
		t.Errorf("the origin's flow names a preset: %+v", f.Flow.Preset)
	}

	// One on per match: profile-500 turns profile-503 off.
	h.c.Activate(ctx, "profile-503", "", 60, 0)
	a, err := h.c.Activate(ctx, "profile-500", "", 60, 2)
	if err != nil || len(a.TurnedOff) != 1 || a.TurnedOff[0] != "profile-503" {
		t.Errorf("turned off: %+v %v", a, err)
	}
	if got := get("/profile", ""); !strings.HasPrefix(got, "500") {
		t.Errorf("profile-500: %q", got)
	}
	// Re-activating replaces the limits (a dropped call made again): 1, then 3.
	h.c.Activate(ctx, "profile-500", "", 60, 1)
	h.c.Activate(ctx, "profile-500", "", 60, 3)
	for i := range 3 {
		if got := get("/profile", ""); !strings.HasPrefix(got, "500") {
			t.Errorf("profile-500, %d of 3: %q", i+1, got)
		}
	}
	if got := get("/profile", ""); got != "200 origin /profile" {
		t.Errorf("profile-500 used up: %q", got)
	}

	// A preset on comes before a plain mock that matches too; off, the plain one answers.
	if got := get("/order", ""); !strings.HasPrefix(got, "418") {
		t.Errorf("preset off, plain mock: %q", got)
	}
	// Concurrent requests use the count exactly: 3 of 10 get the preset.
	h.c.Activate(ctx, "order-503", "", 60, 3)
	results := make(chan string, 10)
	for range 10 {
		go func() { results <- get("/order", "") }()
	}
	n503 := 0
	for range 10 {
		if strings.HasPrefix(<-results, "503") {
			n503++
		}
	}
	if n503 != 3 {
		t.Errorf("%d of 10 concurrent requests got the preset, want 3", n503)
	}

	// Operations on one URL each have their own; an operation that does not
	// match uses no count.
	h.c.Activate(ctx, "feed-500", "", 60, 1)
	h.c.Activate(ctx, "login-401", "", 60, 1)
	if got := get("/graphql", `{"operationName":"Other","query":"query Other { a }"}`); got != "200 origin /graphql" {
		t.Errorf("other operation: %q", got)
	}
	if got := get("/graphql", `{"operationName":"Feed","query":"query Feed { a }"}`); !strings.HasPrefix(got, "500") {
		t.Errorf("feed: %q", got)
	}
	if got := get("/graphql", `{"operationName":"Login","query":"mutation Login { a }"}`); !strings.HasPrefix(got, "401") {
		t.Errorf("login: %q", got)
	}
	// The Login row (events may come after the client has its answer, and
	// the newest /graphql row may still be Feed's for a moment).
	var login Summary
	for deadline := time.Now().Add(10 * time.Second); login.Preset == "" && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		for _, f := range listAll(h.c.Store, 1000) {
			if f.Operation == "Login" {
				login = f
			}
		}
	}
	if login.Preset != "login-401" || !login.Mocked {
		t.Errorf("Login row: preset %q, mocked %v", login.Preset, login.Mocked)
	}

	// Time: off after its seconds, also with a count left.
	h.c.Activate(ctx, "profile-503", "", 1, 5)
	time.Sleep(1200 * time.Millisecond)
	if got := get("/profile", ""); got != "200 origin /profile" {
		t.Errorf("expired: %q", got)
	}
	// Deactivate.
	h.c.Activate(ctx, "profile-503", "", 60, 0)
	if was, err := h.c.Deactivate(ctx, "profile-503", ""); !was || err != nil {
		t.Errorf("deactivate: %v %v", was, err)
	}
	if got := get("/profile", ""); got != "200 origin /profile" {
		t.Errorf("deactivated: %q", got)
	}
	if got := get("/plain", ""); !strings.HasPrefix(got, "418") {
		t.Errorf("a plain mock: %q", got)
	}

	// Refusals.
	for _, c := range []struct {
		name           string
		seconds, times int
		want           string
	}{
		{"nope", 60, 0, "no preset named 'nope'"},
		{"bad name!", 60, 0, "no preset by that name"},
		{"profile-503", 0, 0, "at most 5 minutes"},
		{"profile-503", 301, 0, "at most 5 minutes"},
		{"profile-503", 60, 21, "times must be from 1 to 20"},
	} {
		if _, err := h.c.Activate(ctx, c.name, "", c.seconds, c.times); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	// The addon checks the bounds too, and the secret.
	ask := func(req string) string {
		conn, err := net.Dial("unix", filepath.Join(h.c.cfg.Dir, ControlSock))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		fmt.Fprintln(conn, req)
		b, _ := io.ReadAll(conn)
		return string(b)
	}
	if got := ask(`{"op":"list"}`); !strings.Contains(got, `"refused"`) {
		t.Errorf("no secret: %s", got)
	}
	// The addon's own list carries no body or header value.
	if got := ask(fmt.Sprintf(`{"op":"list","secret":%q}`, h.c.SocksSecret)); !strings.Contains(got, "order-503") || strings.Contains(got, "BODYMARK7") || strings.Contains(got, "HDRMARK7") {
		t.Errorf("list: %s", got)
	}
	if got := ask(fmt.Sprintf(`{"op":"activate","name":"profile-503","seconds":301,"secret":%q}`, h.c.SocksSecret)); !strings.Contains(got, "seconds must be from 1 to 300") {
		t.Errorf("addon's bound: %s", got)
	}
	if fi, err := os.Stat(filepath.Join(h.c.cfg.Dir, ControlSock)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket: %v %v", fi, err)
	}

	// A changed file turns presets off, also one that does not load.
	h.c.Activate(ctx, "profile-503", "", 60, 0)
	write("  - match: {url: \"http://" + o + "/profile\"}\n    status: 200\n") // a plain mock with a preset's match: refused
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(fmt.Sprint(h.stats()["rules_error"]), "same match") {
		time.Sleep(200 * time.Millisecond)
	}
	if e := fmt.Sprint(h.stats()["rules_error"]); !strings.Contains(e, "a plain mock and a preset have the same match") {
		t.Errorf("rules_error: %s", e)
	}
	if got := get("/profile", ""); got != "200 origin /profile" {
		t.Errorf("after a reload that failed: %q", got)
	}
}

// TestMockFaults (REQCOVE_E2E=1): delay_ms holds one answer while another
// stream on the same HTTP/2 connection is answered at once; fault: close
// resets an HTTP/2 stream (the connection goes on) and closes an HTTP/1
// connection; the rows say a mock closed them.
func TestMockFaults(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin %s", r.URL.Path)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "origin.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	os.WriteFile(rules, []byte(fmt.Sprintf(`mock:
  - match: {url: "%[1]s/slow"}
    preset: slow
    delay_ms: 2000
    body: slow
  - match: {url: "%[1]s/close"}
    fault: close
  - match: {url: "%[1]s/close-later"}
    preset: close-later
    fault: close
    delay_ms: 300
`, srv.URL)), 0o600)
	up := startUpstream(t)
	defer up.ln.Close()
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.Upstream, c.UpstreamCA, c.Rules = up.ln.Addr().String(), caFile, rules })
	if err != nil {
		t.Fatal(err)
	}
	tr := h.client("dev").Transport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = true
	h2 := &http.Client{Transport: tr, Timeout: time.Minute}
	get := func(hc *http.Client, path string) (string, time.Duration, bool) {
		start := time.Now()
		var reused bool
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}))
		resp, err := hc.Do(req)
		if err != nil {
			return "error: " + err.Error(), time.Since(start), reused
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 && hc == h2 {
			t.Errorf("%s: HTTP/%d", path, resp.ProtoMajor)
		}
		return string(b), time.Since(start), reused
	}
	if got, _, _ := get(h2, "/warm"); got != "origin /warm" { // one connection, then two streams on it
		t.Fatalf("warm: %q", got)
	}
	if _, err := h.c.Activate(ctx, "slow", "", 60, 0); err != nil {
		t.Fatal(err)
	}
	slow := make(chan time.Duration)
	go func() { _, d, _ := get(h2, "/slow"); slow <- d }()
	time.Sleep(300 * time.Millisecond)
	if got, d, reused := get(h2, "/fast"); got != "origin /fast" || d > time.Second || !reused {
		t.Errorf("a second stream while one waits: %q in %v (same connection: %v)", got, d, reused)
	}
	if d := <-slow; d < 2*time.Second || d > 5*time.Second {
		t.Errorf("delay_ms 2000: %v", d)
	}
	// HTTP/2: the stream is reset, the connection goes on.
	if got, _, _ := get(h2, "/close"); !strings.HasPrefix(got, "error") {
		t.Errorf("close over HTTP/2: %q", got)
	}
	if got, _, reused := get(h2, "/after"); got != "origin /after" || !reused {
		t.Errorf("after a reset stream: %q (same connection: %v)", got, reused)
	}
	if f := h.doneFlow("/close", false); !strings.Contains(f.Error, "closed by a mock (fault: close)") {
		t.Errorf("HTTP/2 close row: error %q", f.Error)
	}
	// HTTP/1: the connection closes.
	h1 := &http.Client{Transport: h.client("dev").Transport, Timeout: time.Minute}
	if got, _, _ := get(h1, "/close"); !strings.HasPrefix(got, "error") {
		t.Errorf("close over HTTP/1: %q", got)
	}
	h.c.Activate(ctx, "close-later", "", 60, 1)
	if got, d, _ := get(h1, "/close-later"); !strings.HasPrefix(got, "error") || d < 300*time.Millisecond {
		t.Errorf("close after a delay: %q in %v", got, d)
	}
	f := h.doneFlow("/close-later", false)
	if f.Preset != "close-later" || !strings.Contains(f.Error, "closed by a mock (fault: close), preset close-later") {
		t.Errorf("row: preset %q, error %q", f.Preset, f.Error)
	}
}

// TestPresetClocks (REQCOVE_E2E=1, mitmproxy's Python): a preset is off once
// either clock passes its end: the monotonic clock stops while the computer
// sleeps, so a day asleep must not leave a "once" waiting.
func TestPresetClocks(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	dir := t.TempDir()
	for f, b := range map[string][]byte{"addon.py": addonPy, "mitm.py": mitmPy, "mitm.py.lock": mitmLock} {
		os.WriteFile(filepath.Join(dir, f), b, 0o600)
	}
	script := `import sys, time, types
sys.path.insert(0, sys.argv[1])
import addon
from pathlib import Path
m = addon.Mock()
m.add({"match": {"url": "https://a.example/x"}, "preset": "p", "status": 503}, Path(sys.argv[1]))
m.book.control({"op": "activate", "name": "p", "seconds": 300, "times": 1})
assert m.book.on("p")
real = time.time
addon.time = types.SimpleNamespace(time=lambda: real() + 86400, monotonic=time.monotonic)  # a day asleep
assert not m.book.on("p"), "still on after a day asleep"
addon.time = time
m.book.control({"op": "activate", "name": "p", "seconds": 300})
mono = time.monotonic
addon.time = types.SimpleNamespace(time=time.time, monotonic=lambda: mono() + 301)
assert not m.book.on("p"), "still on past its monotonic end"
print("ok")
`
	bin, args := PyCommand(Config{Uvx: "uvx", Python: "3.14", MitmSpec: "mitmproxy==12.3.1", Dir: dir}, "python")
	out, err := exec.Command(bin, append(args, "-c", script, dir)...).CombinedOutput()
	if err != nil || !strings.HasSuffix(strings.TrimSpace(string(out)), "ok") {
		t.Errorf("%v\n%s", err, out)
	}
}
