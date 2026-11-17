package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const leak = "SECRET-not-for-the-page"

// pageRun is a run's ctl.sock (no mitmproxy) with a status holding what the
// page must never show; it returns the state directory and ctl state.
func pageRun(t *testing.T, o *runOpts) (string, *ctlState) {
	t.Helper()
	dir, _ := os.MkdirTemp("/tmp", "rcvq-") // short socket paths
	t.Cleanup(func() { os.RemoveAll(dir) })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cap := &capture.Capture{Store: capture.NewStore(10, 1<<20)}
	st, err := serveCtl(ctx, dir, cap, o, nil, func() mcpserver.StatusOut {
		return mcpserver.StatusOut{Mode: "tailnet", Version: "v1.2.0", Executable: "/opt/reqcove", Service: "com.example", Manager: "brew services",
			ConfigFile: "/c/config", HostsFiles: []string{"/c/hosts"}, KeepAwake: "ac", Recording: "on", BaseAllowHosts: []string{"a.example.com"},
			NextSteps: []string{"approve the exit node"},
			Node: exitnode.Status{Node: "reqcove.ts.net", IPs: []string{"100.64.0.1"}, AuthURL: "https://login.example/" + leak, NodeKey: leak,
				Devices: map[string]string{"n1": "Taro's iPhone"}, Problems: []string{leak}, Health: []string{leak}},
			Capture: map[string]any{"upstream": "http://u:" + leak + "@proxy"}, ScopeChange: leak, ActivePresets: []mcpserver.PresetOut{{Name: leak}},
			OutOfScopeHosts:     []mcpserver.OutHost{{Host: leak}, {Host: "seen.example.com", Count: 3, Add: "reqcove capture add seen.example.com"}, {Host: "<img src=x>.example.com"}, {Host: "a b.example.com"}},
			OutOfScopeHostsKept: 4, DiscoverUntil: "2026-11-17T10:00:00Z", ConfigUnused: ""}
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir, st
}

// openUI is the console op: the page's base URL and a code.
func openUI(t *testing.T, state string) (string, string) {
	t.Helper()
	a, err := askRun(context.Background(), state, ctlRequest{Cmd: "console"})
	if err != nil || !a.OK || a.Port == 0 || len(a.Code) != 32 {
		t.Fatalf("ui: %v %+v", err, a)
	}
	// Printed above "opened in your browser" as above the link (--print).
	if strings.Contains(a.Message, "open the link") || !strings.Contains(a.Message, "works once, within 60 s") {
		t.Errorf("ui: %q", a.Message)
	}
	return "http://127.0.0.1:" + strconv.Itoa(a.Port), a.Code
}

// call asks the page; hdr's "Host" sets the Host.
func call(t *testing.T, base, method, path, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
	if method == "POST" {
		req.Header.Set("Origin", base)
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return r, string(b)
}

func trade(t *testing.T, base, code string) string {
	t.Helper()
	r, b := call(t, base, "POST", "/api/session", `{"code":"`+code+`"}`, nil)
	var d struct{ Token string }
	json.Unmarshal([]byte(b), &d)
	if r.StatusCode != 200 || len(d.Token) != 64 {
		t.Fatalf("trade: %d %s", r.StatusCode, b)
	}
	return d.Token
}

func pageStateOf(t *testing.T, base, token string) (int, pageState) {
	t.Helper()
	r, b := call(t, base, "GET", "/api/state", "", map[string]string{sessionHeader: token})
	var s pageState
	json.Unmarshal([]byte(b), &s)
	return r.StatusCode, s
}

func setClock(p *page, c *clock) {
	p.mu.Lock()
	p.now = c.now
	p.mu.Unlock()
}

// The listener is 127.0.0.1's alone, opened once; each console op a new code;
// neither the code nor a token is logged.
func TestPageListener(t *testing.T) {
	logged := logTo(t)
	state, st := pageRun(t, &runOpts{})
	base, code := openUI(t, state)
	base2, code2 := openUI(t, state)
	if base != base2 || code == code2 {
		t.Errorf("again: %s %s", base2, code2)
	}
	host, _, _ := net.SplitHostPort(st.page.host)
	if host != "127.0.0.1" || !strings.HasPrefix(base, "http://127.0.0.1:") {
		t.Errorf("listens on %s", st.page.host)
	}
	token := trade(t, base, code)
	if n, s := pageStateOf(t, base, token); n != 200 || s.Version != "v1.2.0" {
		t.Errorf("%d %+v", n, s)
	}
	for _, s := range []string{code, code2, token} {
		if strings.Contains(logged.String(), s) {
			t.Errorf("logged: %s", logged.String())
		}
	}
	if !strings.Contains(logged.String(), "reqcove console: the page listens on "+base+" (this computer only)") {
		t.Errorf("log: %s", logged.String())
	}
}

// Every check of every request.
func TestPageChecks(t *testing.T) {
	state, st := pageRun(t, &runOpts{})
	base, code := openUI(t, state)
	port := strings.TrimPrefix(base, "http://127.0.0.1")
	asked := st.reqs.ask(capture.HostRules{}, []string{"b.example.com"}).Requests[0]
	stillPending := func(why string) {
		t.Helper()
		if p := st.reqs.pending(); len(p) != 1 || p[0].ID != asked.ID {
			t.Errorf("%s: %+v", why, p)
		}
	}
	var all []*http.Response
	check := func(why string, r *http.Response, want int) {
		t.Helper()
		all = append(all, r)
		if r.StatusCode != want {
			t.Errorf("%s: %d, want %d", why, r.StatusCode, want)
		}
	}
	codeBody := `{"code":"` + code + `"}`

	// Before the code is traded: nothing here takes it.
	for _, h := range []string{"localhost" + port, "evil.example" + port, "127.0.0.1", "127.0.0.1:1", "[::1]" + port} {
		r, _ := call(t, base, "GET", "/", "", map[string]string{"Host": h})
		check("GET / Host "+h, r, http.StatusMisdirectedRequest)
		r, _ = call(t, base, "POST", "/api/session", codeBody, map[string]string{"Host": h})
		check("trade, Host "+h, r, http.StatusMisdirectedRequest)
	}
	for _, o := range []string{"http://evil.example", "http://localhost" + port, "null", ""} {
		r, _ := call(t, base, "POST", "/api/session", codeBody, map[string]string{"Origin": o})
		check("trade, Origin "+o, r, http.StatusForbidden)
	}
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", ""} {
		r, _ := call(t, base, "POST", "/api/session", codeBody, map[string]string{"Content-Type": ct})
		check("trade, Content-Type "+ct, r, http.StatusUnsupportedMediaType)
	}
	r, _ := call(t, base, "GET", "/api/session?code="+code, "", nil)
	check("GET trade", r, http.StatusMethodNotAllowed)
	r, _ = call(t, base, "POST", "/api/session", `{"code":"`+strings.Repeat("a", maxPageBody)+`"}`, nil)
	check("a big body", r, http.StatusBadRequest)
	token := trade(t, base, code) // still good

	r, b := call(t, base, "GET", "/", "", nil)
	check("GET /", r, 200)
	if !strings.Contains(b, `<script src="/app.js"`) || r.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("page: %s", b)
	}
	for _, f := range []string{"/app.js", "/app.css"} {
		r, _ := call(t, base, "GET", f, "", nil)
		check(f, r, 200)
	}
	r, _ = call(t, base, "GET", "/flows.json", "", nil)
	check("another path", r, 404)

	// The session: in its header, nowhere else.
	r, b = call(t, base, "GET", "/api/state", "", nil)
	check("no session", r, http.StatusUnauthorized)
	if !strings.Contains(b, "or run was stopped and started again") || strings.Contains(b, "run restarted") { // a restart keeps the sessions
		t.Errorf("no session: %s", b)
	}
	r, _ = call(t, base, "GET", "/api/state", "", map[string]string{sessionHeader: token[:63] + "x"})
	check("a wrong session", r, http.StatusUnauthorized)
	r, _ = call(t, base, "GET", "/api/state", "", map[string]string{sessionHeader: code})
	check("the code as a session", r, http.StatusUnauthorized)
	r, _ = call(t, base, "GET", "/api/state", "", map[string]string{"Cookie": sessionHeader + "=" + token + "; reqcove=" + token + "; reqcove-session=" + token})
	check("a cookie alone", r, http.StatusUnauthorized)
	r, _ = call(t, base, "GET", "/api/state", "", map[string]string{sessionHeader: token, "Host": "localhost" + port})
	check("a session, another Host", r, http.StatusMisdirectedRequest)
	r, b = call(t, base, "GET", "/api/state", "", map[string]string{sessionHeader: token})
	check("the session", r, 200)
	if strings.Contains(b, leak) || strings.Contains(b, token) || strings.Contains(b, code) {
		t.Errorf("shows what it must not: %s", b)
	}
	if !strings.Contains(b, `"started":"`+pageStarted+`"`) || pageStarted == "" { // the page sees a restart by it
		t.Errorf("started: %s", b)
	}

	// Changes: POST only, from this page, as JSON, with the session.
	approve := `{"id":"` + asked.ID + `","hosts":["b.example.com"]}`
	for _, c := range []struct {
		why, method, path, body string
		hdr                     map[string]string
		want                    int
	}{
		{"GET approve", "GET", "/api/approve?id=" + asked.ID + "&hosts=b.example.com", "", map[string]string{sessionHeader: token}, http.StatusMethodNotAllowed},
		{"GET deny", "GET", "/api/deny?id=" + asked.ID, "", map[string]string{sessionHeader: token}, http.StatusMethodNotAllowed},
		{"PUT approve", "PUT", "/api/approve", approve, map[string]string{sessionHeader: token, "Content-Type": "application/json"}, http.StatusMethodNotAllowed},
		{"OPTIONS approve", "OPTIONS", "/api/approve", "", map[string]string{"Origin": "http://evil.example", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": sessionHeader}, http.StatusMethodNotAllowed},
		{"approve, cross Origin", "POST", "/api/approve", approve, map[string]string{sessionHeader: token, "Origin": "http://evil.example"}, http.StatusForbidden},
		{"approve, no Origin", "POST", "/api/approve", approve, map[string]string{sessionHeader: token, "Origin": ""}, http.StatusForbidden},
		{"approve, a form", "POST", "/api/approve", approve, map[string]string{sessionHeader: token, "Content-Type": "text/plain"}, http.StatusUnsupportedMediaType},
		{"approve, no session", "POST", "/api/approve", approve, nil, http.StatusUnauthorized},
		{"approve, a cookie", "POST", "/api/approve", approve, map[string]string{"Cookie": sessionHeader + "=" + token}, http.StatusUnauthorized},
		{"deny, no session", "POST", "/api/deny", `{"id":"` + asked.ID + `"}`, nil, http.StatusUnauthorized},
		{"approve, Host", "POST", "/api/approve", approve, map[string]string{sessionHeader: token, "Host": "evil.example" + port}, http.StatusMisdirectedRequest},
	} {
		r, _ := call(t, base, c.method, c.path, c.body, c.hdr)
		check(c.why, r, c.want)
		stillPending(c.why)
	}
	for _, r := range all {
		h := r.Header
		if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") ||
			h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s %s: headers %v", r.Request.Method, r.Request.URL.Path, h)
		}
		for k := range h {
			if strings.HasPrefix(k, "Access-Control-") {
				t.Errorf("%s %s: %s", r.Request.Method, r.Request.URL.Path, k)
			}
		}
	}
}

// A code works once, for 60 s by either clock; used twice, it ends every
// session and says so. An unknown code ends nothing.
func TestPageCode(t *testing.T) {
	logged := logTo(t)
	state, st := pageRun(t, &runOpts{})
	base, _ := openUI(t, state)
	c := &clock{base: time.Now()}
	setClock(st.page, c)
	_, code1 := openUI(t, state)
	_, code2 := openUI(t, state)
	s1, s2 := trade(t, base, code1), trade(t, base, code2)

	r, b := call(t, base, "POST", "/api/session", `{"code":"`+strings.Repeat("0", 32)+`"}`, nil)
	if r.StatusCode != 403 || !strings.Contains(b, "not one this run gave") {
		t.Errorf("unknown: %d %s", r.StatusCode, b)
	}
	if n, _ := pageStateOf(t, base, s1); n != 200 {
		t.Errorf("an unknown code ended a session: %d", n)
	}
	r, b = call(t, base, "POST", "/api/session", `{"code":"`+code1+`"}`, nil)
	if r.StatusCode != 403 || !strings.Contains(b, "opened already: every page of reqcove console is closed now") || strings.Contains(b, "token") {
		t.Errorf("twice: %d %s", r.StatusCode, b)
	}
	for _, s := range []string{s1, s2} {
		if n, _ := pageStateOf(t, base, s); n != http.StatusUnauthorized {
			t.Errorf("a session after a code used twice: %d", n)
		}
	}
	if !strings.Contains(logged.String(), "a code was used twice: every session of the page ended") {
		t.Errorf("log: %s", logged.String())
	}

	for _, by := range []struct{ mono, wall time.Duration }{{time.Second, 0}, {0, time.Second}} {
		c := &clock{base: time.Now()}
		setClock(st.page, c)
		_, first := openUI(t, state)
		_, second := openUI(t, state)
		c.move(59*by.mono, 59*by.wall)
		trade(t, base, first) // at 59 s
		c.move(by.mono, by.wall)
		r, b := call(t, base, "POST", "/api/session", `{"code":"`+second+`"}`, nil)
		if r.StatusCode != 403 || !strings.Contains(b, "expired (it lasts 60 s)") {
			t.Errorf("%+v: %d %s", by, r.StatusCode, b)
		}
	}
}

// At most 4 sessions: a 5th ends the one used least recently; 12 h idle ends
// one, by either clock.
func TestPageSessions(t *testing.T) {
	state, st := pageRun(t, &runOpts{})
	base, _ := openUI(t, state)
	c := &clock{base: time.Now()}
	setClock(st.page, c)
	var s []string
	for range maxSessions {
		_, code := openUI(t, state)
		s = append(s, trade(t, base, code))
		c.move(time.Second, time.Second)
	}
	pageStateOf(t, base, s[0]) // s[1] is the least recently used now
	_, code := openUI(t, state)
	s = append(s, trade(t, base, code))
	for i, want := range []int{200, 401, 200, 200, 200} {
		if n, _ := pageStateOf(t, base, s[i]); n != want {
			t.Errorf("session %d: %d, want %d", i, n, want)
		}
	}
	c.move(pageIdle-time.Second, 0)
	if n, _ := pageStateOf(t, base, s[4]); n != 200 {
		t.Errorf("used just before 12 h: %d", n)
	}
	c.move(time.Second, 0)
	if n, _ := pageStateOf(t, base, s[0]); n != 401 {
		t.Errorf("12 h idle, by the monotonic clock: %d", n)
	}
	c = &clock{base: time.Now()} // the wall clock alone moves (the computer slept)
	setClock(st.page, c)
	_, code = openUI(t, state)
	last := trade(t, base, code)
	c.move(0, pageIdle-time.Second)
	if n, _ := pageStateOf(t, base, last); n != 200 {
		t.Errorf("used just before 12 h, by the wall clock: %d", n)
	}
	c.move(0, time.Second)
	if n, _ := pageStateOf(t, base, last); n != 401 {
		t.Errorf("12 h idle, by the wall clock: %d", n)
	}
}

// What the page shows, and Approve and Deny as reqcove capture approve and
// deny: the request's own hosts only, traced as the page's.
func TestPageApprove(t *testing.T) {
	logged := logTo(t)
	state, st := pageRun(t, &runOpts{})
	base, code := openUI(t, state)
	token := trade(t, base, code)
	a := st.reqs.ask(capture.HostRules{}, []string{"b.example.com", "c.example.com"}).Requests[0]
	d := st.reqs.ask(capture.HostRules{}, []string{"d.example.com"}).Requests[0]
	_, s := pageStateOf(t, base, token)
	if len(s.Requests) != 2 || s.Requests[0].ID != a.ID || strings.Join(s.Requests[0].Hosts, " ") != "b.example.com c.example.com" || s.Requests[0].Masked != "masked" || s.Requests[0].ExpiresAt != a.ExpiresAt {
		t.Errorf("requests: %+v", s.Requests)
	}
	if s.Executable != "/opt/reqcove" || s.KeepAwake != keepAwakeText("ac") || s.Node != "reqcove.ts.net" || strings.Join(s.Devices, "") != "Taro's iPhone" ||
		strings.Join(s.Hosts, "") != "a.example.com" || s.Recording != "on" || len(s.NextSteps) != 1 || s.ConfigFile != "/c/config" || s.Service != "com.example" {
		t.Errorf("state: %+v", s)
	}
	post := func(path, body string) (bool, string) {
		t.Helper()
		r, b := call(t, base, "POST", path, body, map[string]string{sessionHeader: token})
		var out struct {
			OK      bool
			Message string
		}
		if json.Unmarshal([]byte(b), &out) != nil || r.StatusCode != 200 || strings.Contains(b, token) {
			t.Fatalf("%s: %d %s", path, r.StatusCode, b)
		}
		return out.OK, out.Message
	}
	for _, hosts := range []string{`["b.example.com"]`, `["b.example.com","c.example.com","e.example.com"]`, `[]`} {
		if ok, msg := post("/api/approve", `{"id":"`+a.ID+`","hosts":`+hosts+`}`); ok || !strings.Contains(msg, "nothing changed") {
			t.Errorf("approve %s: %v %s", hosts, ok, msg)
		}
	}
	if p := st.reqs.pending(); len(p) != 2 {
		t.Errorf("a mismatch changed it: %+v", p)
	}
	post("/api/approve", `{"id":"`+a.ID+`","hosts":["c.example.com","b.example.com"]}`) // no mitmproxy here: it fails, approved
	waitLog(t, logged, "capture request "+a.ID+" (b.example.com c.example.com): approved in the console", 1)
	if got := st.reqs.list(a.ID).Requests[0]; got.ApprovedIn != "console" || got.State != "failed" {
		t.Errorf("approved: %+v", got)
	}
	if ok, msg := post("/api/deny", `{"id":"`+d.ID+`"}`); !ok || !strings.HasPrefix(msg, "denied: d.example.com") {
		t.Errorf("deny: %v %s", ok, msg)
	}
	waitLog(t, logged, "capture request "+d.ID+" (d.example.com): denied in the console", 1)
	if strings.Contains(logged.String(), token) || strings.Contains(logged.String(), code) {
		t.Errorf("logged: %s", logged.String())
	}
}

// In LAN mode the page opens (the state); what LAN mode refuses, it refuses.
func TestPageLAN(t *testing.T) {
	state, _ := pageRun(t, &runOpts{lanMode: true})
	base, code := openUI(t, state)
	token := trade(t, base, code)
	_, s := pageStateOf(t, base, token)
	for _, c := range [][3]string{
		{"POST", "/api/deny", `{"id":"0a1b2c3d"}`},
		{"POST", "/api/change", `{"cmd":"add","hosts":["b.example.com"],"rev":"` + s.Rev + `"}`},
		{"GET", "/api/save", ""},
	} {
		if _, b := call(t, base, c[0], c[1], c[2], map[string]string{sessionHeader: token}); !strings.Contains(b, "LAN mode") {
			t.Errorf("%s: %s", c[1], b)
		}
	}
}

// POST /api/change and GET /api/save: every check of v1.2's; the page's ops
// alone (never set, reload, restart, console nor the request ops), with the
// scope revision it read; nothing refused reaches run's change. A change on
// an older revision (another tab, the CLI) is refused; ctl.sock sets no
// revision nor the console's trace. The discovered names: hosts alone, as
// data. The warnings: run's, its flags' included.
func TestPageChange(t *testing.T) {
	state, st := pageRun(t, &runOpts{})
	base, code := openUI(t, state)
	port := strings.TrimPrefix(base, "http://127.0.0.1")
	token := trade(t, base, code)
	_, s := pageStateOf(t, base, token)
	if s.Rev == "" || s.Rev != st.revision() {
		t.Fatalf("rev %q, run's %q", s.Rev, st.revision())
	}
	gen, markers := st.gen.Load(), len(st.page.cap.Store.Markers(0))
	add := `{"cmd":"add","hosts":["b.example.com"],"rev":"` + s.Rev + `"}`
	auth := map[string]string{sessionHeader: token}
	with := func(kv ...string) map[string]string {
		m := map[string]string{sessionHeader: token}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	for _, c := range []struct {
		why, method, path, body string
		hdr                     map[string]string
		want                    int
	}{
		{"no session", "POST", "/api/change", add, nil, http.StatusUnauthorized},
		{"a wrong session", "POST", "/api/change", add, map[string]string{sessionHeader: token[:63] + "x"}, http.StatusUnauthorized},
		{"a cookie", "POST", "/api/change", add, map[string]string{"Cookie": sessionHeader + "=" + token}, http.StatusUnauthorized},
		{"cross Origin", "POST", "/api/change", add, with("Origin", "http://evil.example"), http.StatusForbidden},
		{"no Origin", "POST", "/api/change", add, with("Origin", ""), http.StatusForbidden},
		{"another Host", "POST", "/api/change", add, with("Host", "localhost"+port), http.StatusMisdirectedRequest},
		{"a form", "POST", "/api/change", add, with("Content-Type", "application/x-www-form-urlencoded"), http.StatusUnsupportedMediaType},
		{"text", "POST", "/api/change", add, with("Content-Type", "text/plain"), http.StatusUnsupportedMediaType},
		{"GET", "GET", "/api/change?cmd=add&hosts=b.example.com", "", auth, http.StatusMethodNotAllowed},
		{"OPTIONS", "OPTIONS", "/api/change", "", map[string]string{"Origin": "http://evil.example", "Access-Control-Request-Method": "POST"}, http.StatusMethodNotAllowed},
		{"not JSON", "POST", "/api/change", "cmd=add", auth, http.StatusBadRequest},
		{"another field", "POST", "/api/change", `{"cmd":"set","allow_hosts":["b.example.com"],"rev":"` + s.Rev + `"}`, auth, http.StatusBadRequest},
		{"an id", "POST", "/api/change", `{"cmd":"add","hosts":["b.example.com"],"id":"0a1b2c3d","rev":"` + s.Rev + `"}`, auth, http.StatusBadRequest},
		{"no rev", "POST", "/api/change", `{"cmd":"add","hosts":["b.example.com"]}`, auth, http.StatusBadRequest},
		{"a big body", "POST", "/api/change", `{"cmd":"add","hosts":["` + strings.Repeat("a", maxPageBody) + `"],"rev":"` + s.Rev + `"}`, auth, http.StatusBadRequest},
		{"save, no session", "GET", "/api/save", "", nil, http.StatusUnauthorized},
		{"save, another Host", "GET", "/api/save", "", with("Host", "evil.example"+port), http.StatusMisdirectedRequest},
		{"save, POST", "POST", "/api/save", "{}", auth, http.StatusMethodNotAllowed},
	} {
		r, b := call(t, base, c.method, c.path, c.body, c.hdr)
		if r.StatusCode != c.want {
			t.Errorf("%s: %d %s, want %d", c.why, r.StatusCode, b, c.want)
		}
		if h := r.Header; h.Get("Cache-Control") != "no-store" || !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") {
			t.Errorf("%s: headers %v", c.why, h)
		}
		for k := range r.Header {
			if strings.HasPrefix(k, "Access-Control-") {
				t.Errorf("%s: %s", c.why, k)
			}
		}
	}
	for _, cmd := range []string{"set", "reload", "restart", "console", "console-end", "request", "requests", "approve", "deny", "", "ADD"} {
		r, b := call(t, base, "POST", "/api/change", `{"cmd":"`+cmd+`","rev":"`+s.Rev+`"}`, auth)
		if r.StatusCode != http.StatusBadRequest || !strings.Contains(b, "capture set and reload are your terminal's") {
			t.Errorf("%q: %d %s", cmd, r.StatusCode, b)
		}
	}
	// A path, as --allow-hosts=@FILE takes it: refused by run, as capture add refuses it.
	for _, h := range []string{"@/etc/hosts", "@~/hosts"} {
		if _, b := call(t, base, "POST", "/api/change", `{"cmd":"add","hosts":["`+h+`"],"rev":"`+s.Rev+`"}`, auth); !strings.Contains(b, `"ok":false`) || !strings.Contains(b, "nothing changed") {
			t.Errorf("%s: %s", h, b)
		}
	}
	if g, m := st.gen.Load(), len(st.page.cap.Store.Markers(0)); g != gen || m != markers {
		t.Errorf("a refused request reached run: gen %d -> %d, markers %d -> %d", gen, g, markers, m)
	}

	// Another change made since (the CLI, another tab): refused; on the
	// revision read again, it goes on (no mitmproxy here: it fails there).
	if _, err := askRun(context.Background(), state, ctlRequest{Cmd: "add", Hosts: []string{"c.example.com"}}); err != nil {
		t.Fatal(err)
	}
	stale := "refused: the hosts changed since this page read them"
	if _, b := call(t, base, "POST", "/api/change", add, auth); !strings.Contains(b, stale) {
		t.Errorf("an older revision: %s", b)
	}
	_, s2 := pageStateOf(t, base, token)
	if s2.Rev == s.Rev {
		t.Errorf("the revision stayed %q", s.Rev)
	}
	if _, b := call(t, base, "POST", "/api/change", `{"cmd":"add","hosts":["b.example.com"],"rev":"`+s2.Rev+`"}`, auth); strings.Contains(b, stale) || !strings.Contains(b, `"message"`) {
		t.Errorf("the revision read again: %s", b)
	}
	// ctl.sock: a rev and from in its JSON are not read.
	conn, err := net.Dial("unix", filepath.Join(state, ctlSock))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, `{"cmd":"add","hosts":["d.example.com"],"rev":"x.0","from":"console"}`+"\n")
	b, _ := io.ReadAll(conn)
	conn.Close()
	if strings.Contains(string(b), stale) {
		t.Errorf("ctl.sock took a revision: %s", b)
	}

	// The discovered names: hosts alone, no command; as data.
	if want := []pageHost{{Host: "seen.example.com", Count: 3}}; !slices.Equal(s.Discovered, want) || s.DiscoveredKept != 4 || s.DiscoverUntil == "" {
		t.Errorf("discovered: %+v (%d), until %q", s.Discovered, s.DiscoveredKept, s.DiscoverUntil)
	}
	_, raw := call(t, base, "GET", "/api/state", "", auth)
	for _, no := range []string{"img", "a b.example", "reqcove capture add"} {
		if strings.Contains(raw, no) {
			t.Errorf("the state has %q: %s", no, raw)
		}
	}
	js, _ := pageFiles.ReadFile("ui/app.js")
	page, _ := pageFiles.ReadFile("ui/index.html")
	for _, m := range regexp.MustCompile(`\$\("([a-z-]+)"\)`).FindAllStringSubmatch(string(js), -1) { // a missing one stops the whole page
		if !strings.Contains(string(page), `id="`+m[1]+`"`) {
			t.Errorf("app.js uses #%s, not in index.html", m[1])
		}
	}
	for _, no := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"} {
		if strings.Contains(string(js), no) {
			t.Errorf("app.js puts in markup: %s", no)
		}
	}

	// The warnings: run's, its other flags' too (set at its start).
	defer func(n []string, o string) { allowAllNotes, openNote = n, o }(allowAllNotes, openNote)
	allowAllNotes, openNote = []string{"--web: mitmweb shows every one of them too, unmasked"}, webOpenNote
	_, s = pageStateOf(t, base, token)
	if w := s.Warnings; w.Stop != stopWarning || !strings.HasSuffix(w.Remove, webOpenNote) || !strings.HasSuffix(w.AllowAll, "; --web: mitmweb shows every one of them too, unmasked") || !strings.HasPrefix(w.AllowAll, "WARNING: every app's and site's traffic") {
		t.Errorf("warnings: %+v", w)
	}
}

// reqcove console: in a terminal only; opens the code file, never the link
// (the code would show in ps), and then prints neither the link nor its code
// (used twice, it would end every session, the one just opened too); the
// link printed when it could not open it or there is no file (a v1.2 run),
// and with --print, which opens nothing and removes the file; a v1.1 run
// says to restart it with v1.2.
func TestConsoleCmd(t *testing.T) {
	ctx := context.Background()
	code := strings.Repeat("ab", 16)
	file := "console-" + strings.Repeat("cd", 16) + ".html"
	dir, got := fakeCtlSock(t, func(req ctlRequest) ctlAnswer {
		return ctlAnswer{OK: true, Message: "the page", Port: 4242, Code: code, File: file}
	})
	var opened []string
	was := openBrowser
	openBrowser = func(_ context.Context, f string) error { opened = append(opened, f); return nil }
	defer func() { openBrowser, terminal = was, isTerminal }()
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if err := uiIn(ctx, r, w, dir, false); err == nil || !strings.Contains(err.Error(), "only in a terminal") || len(*got) != 0 {
		t.Errorf("off a terminal: %v %+v", err, *got)
	}
	if err := uiIn(ctx, r, w, dir, true); !errors.Is(err, errNotTerminal) || len(*got) != 0 {
		t.Errorf("--print off a terminal: %v %+v", err, *got)
	}
	terminal = func(*os.File) bool { return true }
	out, _ := os.Create(filepath.Join(t.TempDir(), "out"))
	defer out.Close()
	printed := func(printLink bool, state string) string {
		t.Helper()
		out.Truncate(0)
		out.Seek(0, 0)
		if err := uiIn(ctx, r, out, state, printLink); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(out.Name())
		return string(b)
	}
	link := "http://127.0.0.1:4242/#c=" + code
	if b := printed(false, dir); strings.Contains(b, "#c=") || strings.Contains(b, code) || !strings.Contains(b, "the page\nopened in your browser") || !strings.Contains(b, "reqcove console --print") || len(opened) != 1 || opened[0] != filepath.Join(dir, file) || (*got)[0].Cmd != "console" {
		t.Errorf("opened: %q %q %+v", b, opened, *got)
	}
	openBrowser = func(context.Context, string) error { return errors.New("no browser") }
	if b := printed(false, dir); !strings.Contains(b, "the page\n  "+link+"\n") || !strings.Contains(b, "not opened in a browser (no browser)") || strings.Contains(b, "opened in your browser") {
		t.Errorf("not opened: %q", b)
	}

	openBrowser = func(_ context.Context, f string) error { opened = append(opened, f); return nil }
	for _, f := range []string{"", "../console-" + strings.Repeat("cd", 16) + ".html", "/tmp/x.html", "console-x.html"} { // a v1.2 run, or not a code file's name
		noFile, _ := fakeCtlSock(t, func(ctlRequest) ctlAnswer {
			return ctlAnswer{OK: true, Message: "the page", Port: 4242, Code: code, File: f}
		})
		opened = nil
		if b := printed(false, noFile); len(opened) != 0 || !strings.Contains(b, link) || !strings.Contains(b, "open the link above yourself") {
			t.Errorf("file %q: %q %q", f, opened, b)
		}
		if b := printed(true, noFile); len(opened) != 0 || b != "the page\n  "+link+"\n" {
			t.Errorf("--print, file %q: %q %q", f, opened, b)
		}
	}

	// --print: the link, nothing opened, the code file removed.
	opened = nil
	os.WriteFile(filepath.Join(dir, file), []byte("x"), 0o600)
	if b := printed(true, dir); len(opened) != 0 || b != "the page\n  "+link+"\n" {
		t.Errorf("--print: %q %q", opened, b)
	}
	if _, err := os.Lstat(filepath.Join(dir, file)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("--print left the code file: %v", err)
	}

	old, _ := fakeCtlSock(t, func(ctlRequest) ctlAnswer { return ctlAnswer{Message: v11Answer} })
	if err := uiIn(ctx, r, out, old, false); !errors.Is(err, errOlderUI) || !strings.Contains(err.Error(), "restart it with v1.2") {
		t.Errorf("v1.1: %v", err)
	}
	for _, op := range []string{"console", "console-end"} {
		if err := captureCmd(ctx, []string{op, "--state", dir}); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("capture %s: %v", op, err)
		}
		if _, err := (ctlRequest{Cmd: op, Hosts: []string{"a.com"}}).normalized(); err == nil {
			t.Errorf("%s with hosts", op)
		}
	}
}

// The code file run writes: 0600, created, never one there already nor
// through a symlink; it sends the browser to the link, and goes after
// codeFileTTL. The code reaches the opener's arguments nowhere.
func TestCodeFile(t *testing.T) {
	logged := logTo(t)
	codeFileTTL = 300 * time.Millisecond
	defer func() { codeFileTTL = pageCodeTTL }()
	state, _ := pageRun(t, &runOpts{})
	a, err := askRun(context.Background(), state, ctlRequest{Cmd: "console"})
	if err != nil || !codeFileName.MatchString(a.File) || strings.Contains(a.File, a.Code) {
		t.Fatalf("%v %+v", err, a)
	}
	path := filepath.Join(state, a.File)
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", err, fi)
	}
	b, _ := os.ReadFile(path)
	link := "http://127.0.0.1:" + strconv.Itoa(a.Port) + "/#c=" + a.Code
	if !strings.Contains(string(b), `<meta http-equiv="refresh" content="0;url=`+link+`">`) || !strings.Contains(string(b), `<a href="`+link+`">`) {
		t.Errorf("%s", b)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the code file is still there")
		}
	}

	// The opener: the file's path, never the link; the code printed nowhere.
	codeFileTTL = pageCodeTTL // the file kept, to read the code from it
	var args []string
	was := openBrowser
	openBrowser = func(_ context.Context, f string) error { args = append(args, f); return nil }
	defer func() { openBrowser, terminal = was, isTerminal }()
	terminal = func(*os.File) bool { return true }
	out, _ := os.Create(filepath.Join(t.TempDir(), "out"))
	defer out.Close()
	if err := uiIn(context.Background(), out, out, state, false); err != nil || len(args) != 1 {
		t.Fatalf("%v %q", err, args)
	}
	b, _ = os.ReadFile(args[0])
	m := regexp.MustCompile(`#c=([0-9a-f]+)`).FindStringSubmatch(string(b))
	printed, _ := os.ReadFile(out.Name())
	if m == nil || strings.Contains(args[0], "#c=") || strings.Contains(args[0], "http") || strings.Contains(string(printed), "#c=") {
		t.Fatalf("opened %q (%s); printed %q", args[0], b, printed)
	}
	if strings.Contains(args[0], m[1]) || strings.Contains(string(printed), m[1]) || strings.Contains(logged.String(), m[1]) {
		t.Errorf("the code in %q, the terminal or the log", args[0])
	}

	// Never through a symlink, nor over a file there already.
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	os.WriteFile(outside, []byte("keep"), 0o600)
	for _, target := range []string{outside, filepath.Join(dir, "missing")} {
		p := filepath.Join(dir, "console-"+strings.Repeat("e", 32)+".html")
		os.Remove(p)
		os.Symlink(target, p)
		if err := writeCodeFile(p, link); err == nil {
			t.Errorf("through a symlink to %s", target)
		}
		if b, _ := os.ReadFile(outside); string(b) != "keep" {
			t.Errorf("wrote %s: %q", outside, b)
		}
		if _, err := os.Lstat(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("created the symlink's target")
		}
		if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("the symlink: %v %v", err, fi)
		}
	}
	if err := writeCodeFile(outside, link); err == nil {
		t.Error("over a file")
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Errorf("over a file: %q", b)
	}

	// The sweep: the code files alone.
	os.WriteFile(filepath.Join(dir, "console-"+strings.Repeat("1", 32)+".html"), nil, 0o600)
	if n := sweepCodeFiles(dir); n != 2 { // and the symlink
		t.Errorf("swept %d", n)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*")); len(m) != 1 || m[0] != outside {
		t.Errorf("left %v", m)
	}

	// Not written (the directory gone): the answer has the link, no file.
	_, st := pageRun(t, &runOpts{})
	st.dir = filepath.Join(dir, "gone")
	if a := answerCtl(context.Background(), nil, st, ctlRequest{Cmd: "console"}); !a.OK || a.Code == "" || a.File != "" {
		t.Errorf("%+v", a)
	}
	if !strings.Contains(logged.String(), "the file that opens the page not written") {
		t.Errorf("log: %s", logged.String())
	}
}

// reqcove console --end: every session and unused code ended, in LAN mode
// too; the page says so; the code files gone; a later code works.
func TestConsoleEnd(t *testing.T) {
	for _, lan := range []bool{false, true} {
		logged := logTo(t)
		state, _ := pageRun(t, &runOpts{lanMode: lan})
		end := func() ctlAnswer {
			t.Helper()
			a, err := askRun(context.Background(), state, ctlRequest{Cmd: "console-end"})
			if err != nil || !a.OK {
				t.Fatalf("lan %v: %v %+v", lan, err, a)
			}
			return a
		}
		if a := end(); !strings.Contains(a.Message, "nothing to end") {
			t.Errorf("no page: %+v", a)
		}
		base, code := openUI(t, state)
		s1 := trade(t, base, code)
		_, unused := openUI(t, state)
		_, unused2 := openUI(t, state)
		if a := end(); !strings.Contains(a.Message, "ended: 1 sessions of the page and 2 links") {
			t.Errorf("lan %v: %+v", lan, a)
		}
		if m, _ := filepath.Glob(filepath.Join(state, "console-*")); len(m) > 0 {
			t.Errorf("code files after --end: %v", m)
		}
		if r, b := call(t, base, "GET", "/api/state", "", map[string]string{sessionHeader: s1}); r.StatusCode != 401 || !strings.Contains(b, "reqcove console --end") {
			t.Errorf("a session after --end: %d %s", r.StatusCode, b)
		}
		for _, c := range []string{unused, unused2} {
			if r, b := call(t, base, "POST", "/api/session", `{"code":"`+c+`"}`, nil); r.StatusCode != 403 || !strings.Contains(b, "ended (reqcove console --end)") {
				t.Errorf("a code after --end: %d %s", r.StatusCode, b)
			}
		}
		_, fresh := openUI(t, state)
		s2 := trade(t, base, fresh)
		if n, _ := pageStateOf(t, base, s2); n != 200 {
			t.Errorf("a new session after --end: %d", n)
		}
		if r, b := call(t, base, "POST", "/api/session", `{"code":"`+code+`"}`, nil); r.StatusCode != 403 || !strings.Contains(b, "opened already") {
			t.Errorf("a used code after --end: %d %s", r.StatusCode, b)
		}
		if !strings.Contains(logged.String(), "reqcove console --end: 1 sessions and 2 unused links ended") {
			t.Errorf("log: %s", logged.String())
		}
		for _, c := range []string{code, unused, unused2, s1} {
			if strings.Contains(logged.String(), c) {
				t.Error("logged a code or token")
			}
		}
	}
}

// reqcove console --end: in a terminal only; a v1.2 run (its usage, or in LAN
// mode its refusal) says to restart it with v1.3.
func TestConsoleEndCmd(t *testing.T) {
	ctx := context.Background()
	dir, got := fakeCtlSock(t, func(req ctlRequest) ctlAnswer { return ctlAnswer{OK: true, Message: "ended: 0 sessions"} })
	defer func() { terminal = isTerminal }()
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if err := endIn(ctx, r, w, dir); !errors.Is(err, errNotTerminal) || len(*got) != 0 {
		t.Errorf("off a terminal: %v %+v", err, *got)
	}
	terminal = func(*os.File) bool { return true }
	out, _ := os.Create(filepath.Join(t.TempDir(), "out"))
	defer out.Close()
	if err := endIn(ctx, r, out, dir); err != nil || len(*got) != 1 || (*got)[0].Cmd != "console-end" {
		t.Errorf("%v %+v", err, *got)
	}
	if b, _ := os.ReadFile(out.Name()); string(b) != "ended: 0 sessions\n" {
		t.Errorf("%q", b)
	}
	// What a v1.2 run answers an op it does not know (as this one answers one).
	for _, lan := range []bool{false, true} {
		v12 := answerCtl(ctx, nil, newCtlState(&runOpts{lanMode: lan}), ctlRequest{Cmd: "console-unknown"})
		old, _ := fakeCtlSock(t, func(ctlRequest) ctlAnswer { return v12 })
		if err := endIn(ctx, r, out, old); !errors.Is(err, errOlderEnd) || !strings.Contains(err.Error(), "restart it with v1.3") {
			t.Errorf("lan %v: %v (%s)", lan, err, v12.Message)
		}
	}
	if err := endIn(ctx, r, out, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not running") && !strings.Contains(err.Error(), "v1.3") {
		t.Errorf("no run: %v", err)
	}
}

// The page's files: values in as text only, nothing from elsewhere.
func TestPageFiles(t *testing.T) {
	for _, f := range []string{"index.html", "app.js", "app.css"} {
		b, err := pageFiles.ReadFile("ui/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if m := regexp.MustCompile(`https?://|innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|<script>|<style|style=|\son[a-z]+=|reqcove ui\b`).Find(b); m != nil {
			t.Errorf("%s: %s", f, m)
		}
	}
}

// TestPageScopeE2E (REQCOVE_E2E=1, real mitmproxy): each change the page
// makes answers as reqcove capture's does (the times aside), traced as the
// console's; stop's, remove's and allow-all's warnings, shown before the
// page's confirm, are their answers' own words; a page on an older scope is
// refused. Save on a config without the hosts file's line: its diff first
// (the file created, the host pinned, the line added), nothing written until
// confirmed with that diff's token; then status (as reqcove status reads it)
// and the page list the new file at once, and a second Save writes it, as
// capture save does.
func TestPageScopeE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "rcvp-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	conf := filepath.Join(dir, "c")
	os.Mkdir(conf, 0o700)
	config, hostsFile := filepath.Join(conf, "config"), filepath.Join(conf, "hosts")
	if err := os.WriteFile(config, []byte("--allow-hosts=localhost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "s")
	o, err := parseRunFlags([]string{"--device", "x", "--config", config, "--state", state})
	if err != nil {
		t.Fatal(err)
	}
	c, err := capture.Start(ctx, capture.Config{Dir: o.state, Confdir: filepath.Join(dir, "m"),
		Uvx: "uvx", Python: defaultPython, MitmSpec: defaultMitmSpec,
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
		Log: os.Stderr, ReadyTimeout: 2 * time.Minute, AllowHosts: o.allow})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	logged := logTo(t)
	var node nodeState
	node.set(exitnode.Status{Backend: "Running"})
	st, err := serveCtl(ctx, state, c, o, nil, func() mcpserver.StatusOut { return withDiscovery(withFiles(liveStatus(node.get(), c), o), c) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := serveMCP(ctx, o, c, &node, st, "tok"); err != nil {
		t.Fatal(err)
	}
	base, code := openUI(t, state)
	token := trade(t, base, code)
	auth := map[string]string{sessionHeader: token}
	stateNow := func() pageState {
		t.Helper()
		n, s := pageStateOf(t, base, token)
		if n != 200 {
			t.Fatalf("state: %d", n)
		}
		return s
	}
	post := func(body map[string]any) (bool, string) {
		t.Helper()
		b, _ := json.Marshal(body)
		r, out := call(t, base, "POST", "/api/change", string(b), auth)
		var a struct {
			OK      bool
			Message string
		}
		if json.Unmarshal([]byte(out), &a) != nil || r.StatusCode != 200 {
			t.Fatalf("%s: %d %s", b, r.StatusCode, out)
		}
		return a.OK, a.Message
	}
	page := func(body map[string]any) (bool, string) {
		t.Helper()
		body["rev"] = stateNow().Rev
		return post(body)
	}
	sock := func(req ctlRequest) (bool, string) {
		t.Helper()
		a, err := askRun(ctx, state, req)
		if err != nil {
			t.Fatal(err)
		}
		return a.OK, a.Message
	}
	times := regexp.MustCompile(` \d\d:\d\d:\d\d \(in [0-9hms.]+\)`)
	warn := stateNow().Warnings
	one := []string{"127.0.0.1"}
	for _, tc := range []struct {
		body       map[string]any
		req, undo  ctlRequest
		warned     string
		traceStart string
	}{
		{map[string]any{"cmd": "add", "hosts": one}, ctlRequest{Cmd: "add", Hosts: one}, ctlRequest{Cmd: "remove", Hosts: one}, "", "capture add 127.0.0.1"},
		{map[string]any{"cmd": "add", "hosts": one, "pass": true}, ctlRequest{Cmd: "add", Hosts: one, Pass: true}, ctlRequest{Cmd: "remove", Hosts: one, Pass: true}, "", "capture add --pass 127.0.0.1"},
		{map[string]any{"cmd": "remove", "hosts": one, "pass": true}, ctlRequest{Cmd: "remove", Hosts: one, Pass: true}, ctlRequest{Cmd: "add", Hosts: one, Pass: true}, "", "capture remove --pass 127.0.0.1"},
		{map[string]any{"cmd": "remove", "hosts": one}, ctlRequest{Cmd: "remove", Hosts: one}, ctlRequest{Cmd: "add", Hosts: one}, warn.Remove, "capture remove 127.0.0.1"},
		{map[string]any{"cmd": "stop"}, ctlRequest{Cmd: "stop"}, ctlRequest{Cmd: "start"}, warn.Stop, "capture stop"},
		{map[string]any{"cmd": "start"}, ctlRequest{Cmd: "start"}, ctlRequest{Cmd: "stop"}, "", "capture start"},
		{map[string]any{"cmd": "allow-all", "for": "30m"}, ctlRequest{Cmd: "allow-all", For: "30m"}, ctlRequest{Cmd: "allow-all", End: true}, warn.AllowAll, "capture allow-all --for 30m"},
		{map[string]any{"cmd": "allow-all", "end": true}, ctlRequest{Cmd: "allow-all", End: true}, ctlRequest{Cmd: "allow-all", For: "30m"}, "", "capture allow-all --end"},
		{map[string]any{"cmd": "discover", "for": "1h"}, ctlRequest{Cmd: "discover", For: "1h"}, ctlRequest{Cmd: "discover", End: true}, "", "capture discover --for 1h"},
		{map[string]any{"cmd": "discover", "end": true}, ctlRequest{Cmd: "discover", End: true}, ctlRequest{Cmd: "discover", For: "1h"}, "", "capture discover --end"},
	} {
		pok, pmsg := page(tc.body)
		why := tc.traceStart + fromConsole
		waitLog(t, logged, why+": "+pmsg, 1)
		if s := liveStatus(node.get(), c); s.ScopeChange != why {
			t.Errorf("%s: status's change %q", why, s.ScopeChange)
		}
		if ms := c.Store.Markers(0); len(ms) == 0 || ms[len(ms)-1].Text != why || ms[len(ms)-1].Source != "cli" {
			t.Errorf("%s: markers %+v", why, ms)
		}
		sock(tc.undo)
		sok, smsg := sock(tc.req)
		if pok != sok || !pok || times.ReplaceAllString(pmsg, " T") != times.ReplaceAllString(smsg, " T") {
			t.Errorf("%s: the page's answer\n  %v %s\nctl.sock's\n  %v %s", tc.req, pok, pmsg, sok, smsg)
		}
		if tc.warned != "" && (!strings.Contains(pmsg, tc.warned) || !strings.Contains(smsg, tc.warned)) {
			t.Errorf("%s: the warning shown before is not the answer's:\n  %s\n  %s", tc.req, tc.warned, smsg)
		}
	}
	if strings.Contains(logged.String(), fromConsole+" (reqcove capture, from a terminal)") {
		t.Errorf("logged as a terminal's:\n%s", logged.String())
	}

	// The tailnet page: the same changes, traced with the device's name; their
	// answers without this computer's paths (allow-all's and discovery's name
	// their --end command, with --state).
	wasL, wasO, wasA, wasD := listenTailnet, ownDeviceAt, captureEndCmd, discoverEndCmd
	listenTailnet = func() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	ownDeviceAt = func(string) (exitnode.Device, bool) { return exitnode.Device{ID: "nIPHONE", Name: "iphone"}, true }
	captureEndCmd, discoverEndCmd = withState("reqcove capture allow-all --end", state), withState("reqcove capture discover --end", state)
	defer func() { listenTailnet, ownDeviceAt, captureEndCmd, discoverEndCmd = wasL, wasO, wasA, wasD }()
	tbase, tcode := openTailnetUI(t, state)
	tauth := map[string]string{sessionHeader: trade(t, tbase, tcode)}
	for _, tc := range []struct {
		body  map[string]any
		trace string
	}{
		{map[string]any{"cmd": "allow-all", "for": "30m"}, "capture allow-all --for 30m"},
		{map[string]any{"cmd": "allow-all", "end": true}, "capture allow-all --end"},
		{map[string]any{"cmd": "discover", "for": "1h"}, "capture discover --for 1h"},
		{map[string]any{"cmd": "discover", "end": true}, "capture discover --end"},
		{map[string]any{"cmd": "stop"}, "capture stop"},
		{map[string]any{"cmd": "start"}, "capture start"},
	} {
		_, sb := call(t, tbase, "GET", "/api/state", "", tauth)
		var ts pageState
		json.Unmarshal([]byte(sb), &ts)
		tc.body["rev"] = ts.Rev
		b, _ := json.Marshal(tc.body)
		r, out := call(t, tbase, "POST", "/api/change", string(b), tauth)
		var a struct {
			OK      bool
			Message string
		}
		if json.Unmarshal([]byte(out), &a) != nil || r.StatusCode != 200 || !a.OK || strings.Contains(out+sb, state) || strings.Contains(out+sb, dir) {
			t.Errorf("tailnet %s: %d %s\n%s", b, r.StatusCode, out, sb)
		}
		waitLog(t, logged, tc.trace+" (from the console on iphone, over the tailnet): ", 1)
	}

	// Another change since the page read the scope: refused, nothing changed.
	old := stateNow().Rev
	sock(ctlRequest{Cmd: "add", Hosts: []string{"127.0.0.3"}})
	if ok, msg := post(map[string]any{"cmd": "add", "hosts": []string{"127.0.0.4"}, "rev": old}); ok || !strings.HasPrefix(msg, "refused: the hosts changed since this page read them") || slices.Contains(c.Base().Hosts, "127.0.0.4") {
		t.Errorf("an older scope: %v %s; %q", ok, msg, c.Base().Hosts)
	}
	sock(ctlRequest{Cmd: "remove", Hosts: []string{"127.0.0.3"}})

	// Save: the diff first, then what it showed.
	page(map[string]any{"cmd": "add", "hosts": one})
	if s := stateNow(); !slices.Equal(s.Pinned, []string{"localhost"}) || len(s.Saved) != 0 || len(s.HostsFiles) != 0 {
		t.Errorf("before the save: pinned %q, saved %q, files %q", s.Pinned, s.Saved, s.HostsFiles)
	}
	diff := func() pageSave {
		t.Helper()
		_, b := call(t, base, "GET", "/api/save", "", auth)
		var d pageSave
		json.Unmarshal([]byte(b), &d)
		return d
	}
	d := diff()
	if len(d.Files) != 1 || d.Files[0].Path != hostsFile || !d.Files[0].Created || len(d.Files[0].Now) != 0 || !slices.Equal(d.Files[0].Write, one) ||
		!slices.Equal(d.Pinned, []string{"localhost"}) || d.Config != config || !slices.Equal(d.Add, []string{"--allow-hosts=@" + hostsFile}) || d.Confirm == "" || d.Message != "" {
		t.Fatalf("the diff: %+v", d)
	}
	unwritten := func(why string) {
		t.Helper()
		if b, _ := os.ReadFile(config); string(b) != "--allow-hosts=localhost\n" {
			t.Errorf("%s: config\n%s", why, b)
		}
		if _, err := os.Lstat(hostsFile); err == nil {
			t.Errorf("%s: %s made", why, hostsFile)
		}
	}
	unwritten("shown")
	if ok, msg := page(map[string]any{"cmd": "save"}); ok || !strings.HasPrefix(msg, "The config names no hosts file to save these to") {
		t.Errorf("no token: %v %s", ok, msg)
	}
	if ok, msg := page(map[string]any{"cmd": "save", "confirm": "0123"}); ok || !strings.Contains(msg, "changed since the change was shown") {
		t.Errorf("another token: %v %s", ok, msg)
	}
	unwritten("another token")
	if ok, msg := page(map[string]any{"cmd": "save", "confirm": d.Confirm}); !ok || !strings.HasPrefix(msg, "added to "+config+": --allow-hosts=@"+hostsFile+"; saved to "+hostsFile+": 127.0.0.1") {
		t.Fatalf("saved: %v %s", ok, msg)
	}
	if b, _ := os.ReadFile(config); string(b) != "--allow-hosts=localhost\n--allow-hosts=@"+hostsFile+"\n" {
		t.Errorf("config:\n%s", b)
	}
	waitLog(t, logged, "capture save"+fromConsole+": added to "+config, 1)
	// At once: the page and status (as reqcove status reads it) name the file.
	local, err := dialRun(ctx, state, "t")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	res, err := local.CallTool(ctx, &mcp.CallToolParams{Name: "status"})
	if err != nil {
		t.Fatal(err)
	}
	var status mcpserver.StatusOut
	b, _ := json.Marshal(res.StructuredContent)
	json.Unmarshal(b, &status)
	if s := stateNow(); !slices.Equal(status.HostsFiles, []string{hostsFile}) || !slices.Equal(s.HostsFiles, []string{hostsFile}) || !slices.Equal(s.Saved, one) {
		t.Errorf("after the first save: status %q, the page %q, saved %q", status.HostsFiles, s.HostsFiles, s.Saved)
	}

	// A second Save writes the file, nothing to add; as capture save's.
	page(map[string]any{"cmd": "add", "hosts": []string{"127.0.0.2"}})
	if s := stateNow(); !slices.Equal(s.Saved, one) || !slices.Contains(s.Hosts, "127.0.0.2") {
		t.Errorf("unsaved: %+v", s)
	}
	d = diff()
	if len(d.Files) != 1 || d.Files[0].Created || !slices.Equal(d.Files[0].Now, one) || !slices.Equal(d.Files[0].Write, []string{"127.0.0.1", "127.0.0.2"}) || len(d.Add) != 0 {
		t.Errorf("the second diff: %+v", d)
	}
	if ok, msg := page(map[string]any{"cmd": "save", "confirm": "0123"}); ok || !strings.Contains(msg, "changed since the change was shown") {
		t.Errorf("the second save, another token: %v %s", ok, msg)
	}
	if b, _ := os.ReadFile(hostsFile); strings.Contains(string(b), "127.0.0.2") {
		t.Errorf("written on another token:\n%s", b)
	}
	pok, pmsg := page(map[string]any{"cmd": "save", "confirm": d.Confirm})
	sok, smsg := sock(ctlRequest{Cmd: "save"})
	if !pok || !sok || pmsg != smsg || !strings.HasPrefix(pmsg, "saved to "+hostsFile+": 127.0.0.1, 127.0.0.2; not written, as given on the --config file") {
		t.Errorf("the second save: %s\nctl.sock's: %s", pmsg, smsg)
	}
}
