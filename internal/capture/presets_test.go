package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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
	ps, err := h.c.Presets(ctx)
	if err != nil || len(ps) != 4 || ps[0].Name != "profile-503" || ps[0].Description != "the profile API is down" || ps[0].Active || *ps[0].Status != 503 {
		b, _ := json.Marshal(ps)
		t.Fatalf("presets: %s %v", b, err)
	}
	if b, _ := json.Marshal(ps); strings.Contains(string(b), "down\"") && !strings.Contains(string(b), "is down") {
		t.Errorf("a body in the list: %s", b)
	}

	// Once: the next request, then the origin again.
	if a, err := h.c.Activate(ctx, "profile-503", 60, 1); err != nil || a.ExpiresAt < float64(time.Now().Unix()+50) {
		t.Fatalf("activate: %+v %v", a, err)
	}
	if got := get("/profile", ""); got != "503 down" {
		t.Errorf("once: %q", got)
	}
	if got := get("/profile", ""); got != "200 origin /profile" {
		t.Errorf("after once: %q", got)
	}
	if f := h.doneFlow("/profile", false); f.Preset != "" {
		t.Errorf("the origin's flow names a preset: %+v", f.Flow.Preset)
	}

	// One on per match: profile-500 turns profile-503 off.
	h.c.Activate(ctx, "profile-503", 60, 0)
	a, err := h.c.Activate(ctx, "profile-500", 60, 2)
	if err != nil || len(a.TurnedOff) != 1 || a.TurnedOff[0] != "profile-503" {
		t.Errorf("turned off: %+v %v", a, err)
	}
	if got := get("/profile", ""); !strings.HasPrefix(got, "500") {
		t.Errorf("profile-500: %q", got)
	}
	// Re-activating replaces the limits (a dropped call made again).
	h.c.Activate(ctx, "profile-500", 60, 1)
	if got := get("/profile", ""); !strings.HasPrefix(got, "500") {
		t.Errorf("profile-500 again: %q", got)
	}
	if got := get("/profile", ""); got != "200 origin /profile" {
		t.Errorf("profile-500 used up: %q", got)
	}

	// Operations on one URL each have their own; an operation that does not
	// match uses no count.
	h.c.Activate(ctx, "feed-500", 60, 1)
	h.c.Activate(ctx, "login-401", 60, 1)
	if got := get("/graphql", `{"operationName":"Other","query":"query Other { a }"}`); got != "200 origin /graphql" {
		t.Errorf("other operation: %q", got)
	}
	if got := get("/graphql", `{"operationName":"Feed","query":"query Feed { a }"}`); !strings.HasPrefix(got, "500") {
		t.Errorf("feed: %q", got)
	}
	if got := get("/graphql", `{"operationName":"Login","query":"mutation Login { a }"}`); !strings.HasPrefix(got, "401") {
		t.Errorf("login: %q", got)
	}
	if f := h.doneFlow("/graphql", false); f.Preset != "login-401" || !f.Mocked {
		t.Errorf("row: %+v", f.Flow.Preset)
	}

	// Time: off after its seconds, also with a count left.
	h.c.Activate(ctx, "profile-503", 1, 5)
	time.Sleep(1200 * time.Millisecond)
	if got := get("/profile", ""); got != "200 origin /profile" {
		t.Errorf("expired: %q", got)
	}
	// Deactivate.
	h.c.Activate(ctx, "profile-503", 60, 0)
	if was, err := h.c.Deactivate(ctx, "profile-503"); !was || err != nil {
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
		if _, err := h.c.Activate(ctx, c.name, c.seconds, c.times); err == nil || !strings.Contains(err.Error(), c.want) {
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
	if got := ask(fmt.Sprintf(`{"op":"activate","name":"profile-503","seconds":301,"secret":%q}`, h.c.SocksSecret)); !strings.Contains(got, "seconds must be from 1 to 300") {
		t.Errorf("addon's bound: %s", got)
	}
	if fi, err := os.Stat(filepath.Join(h.c.cfg.Dir, ControlSock)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket: %v %v", fi, err)
	}

	// A changed file turns presets off, also one that does not load.
	h.c.Activate(ctx, "profile-503", 60, 0)
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
