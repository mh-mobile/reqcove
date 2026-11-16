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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
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
	st, err := serveCtl(ctx, dir, cap, o, func() mcpserver.StatusOut {
		return mcpserver.StatusOut{Mode: "tailnet", Version: "v1.2.0", Executable: "/opt/reqcove", Service: "com.example", Manager: "brew services",
			ConfigFile: "/c/config", HostsFiles: []string{"/c/hosts"}, KeepAwake: "ac", Recording: "on", BaseAllowHosts: []string{"a.example.com"},
			NextSteps: []string{"approve the exit node"},
			Node: exitnode.Status{Node: "reqcove.ts.net", IPs: []string{"100.64.0.1"}, AuthURL: "https://login.example/" + leak, NodeKey: leak,
				Devices: map[string]string{"n1": "Taro's iPhone"}, Problems: []string{leak}, Health: []string{leak}},
			Capture: map[string]any{"upstream": "http://u:" + leak + "@proxy"}, ScopeChange: leak, ActivePresets: []mcpserver.PresetOut{{Name: leak}},
			OutOfScopeHosts: []mcpserver.OutHost{{Host: leak}}, ConfigUnused: ""}
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
	r, _ = call(t, base, "GET", "/api/state", "", nil)
	check("no session", r, http.StatusUnauthorized)
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
	_, b := call(t, base, "POST", "/api/deny", `{"id":"0a1b2c3d"}`, map[string]string{sessionHeader: token})
	if !strings.Contains(b, "LAN mode") {
		t.Errorf("%s", b)
	}
}

// reqcove console: in a terminal only; prints the link and opens the code
// file, never the link (the code would show in ps); with no file (a v1.2
// run), the link alone; a v1.1 run says to restart it with v1.2.
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
	if err := uiIn(ctx, r, w, dir); err == nil || !strings.Contains(err.Error(), "only in a terminal") || len(*got) != 0 {
		t.Errorf("off a terminal: %v %+v", err, *got)
	}
	terminal = func(*os.File) bool { return true }
	out, _ := os.Create(filepath.Join(t.TempDir(), "out"))
	defer out.Close()
	if err := uiIn(ctx, r, out, dir); err != nil {
		t.Fatal(err)
	}
	link := "http://127.0.0.1:4242/#c=" + code
	b, _ := os.ReadFile(out.Name())
	if !strings.Contains(string(b), "the page\n  "+link+"\n") || len(opened) != 1 || opened[0] != filepath.Join(dir, file) || (*got)[0].Cmd != "console" {
		t.Errorf("%q %q %+v", b, opened, *got)
	}
	openBrowser = func(context.Context, string) error { return errors.New("no browser") }
	out.Truncate(0)
	out.Seek(0, 0)
	if err := uiIn(ctx, r, out, dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out.Name()); !strings.Contains(string(b), link) || !strings.Contains(string(b), "not opened in a browser (no browser)") {
		t.Errorf("%q", b)
	}

	openBrowser = func(_ context.Context, f string) error { opened = append(opened, f); return nil }
	for _, f := range []string{"", "../console-" + strings.Repeat("cd", 16) + ".html", "/tmp/x.html", "console-x.html"} { // a v1.2 run, or not a code file's name
		noFile, _ := fakeCtlSock(t, func(ctlRequest) ctlAnswer {
			return ctlAnswer{OK: true, Message: "the page", Port: 4242, Code: code, File: f}
		})
		opened = nil
		out.Truncate(0)
		out.Seek(0, 0)
		if err := uiIn(ctx, r, out, noFile); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(out.Name()); len(opened) != 0 || !strings.Contains(string(b), link) || !strings.Contains(string(b), "open the link above yourself") {
			t.Errorf("file %q: %q %q", f, opened, b)
		}
	}

	old, _ := fakeCtlSock(t, func(ctlRequest) ctlAnswer { return ctlAnswer{Message: v11Answer} })
	if err := uiIn(ctx, r, out, old); !errors.Is(err, errOlderUI) || !strings.Contains(err.Error(), "restart it with v1.2") {
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

	// The opener: the file's path, never the link.
	var args []string
	was := openBrowser
	openBrowser = func(_ context.Context, f string) error { args = append(args, f); return nil }
	defer func() { openBrowser, terminal = was, isTerminal }()
	terminal = func(*os.File) bool { return true }
	out, _ := os.Create(filepath.Join(t.TempDir(), "out"))
	defer out.Close()
	if err := uiIn(context.Background(), out, out, state); err != nil || len(args) != 1 {
		t.Fatalf("%v %q", err, args)
	}
	if b, _ := os.ReadFile(out.Name()); strings.Contains(args[0], "#c=") || strings.Contains(args[0], "http") || !strings.Contains(string(b), "#c=") {
		t.Errorf("opened %q; printed %q", args[0], b)
	}
	for _, c := range regexp.MustCompile(`#c=([0-9a-f]+)`).FindAllStringSubmatch(string(b), -1) {
		if strings.Contains(args[0], c[1]) || strings.Contains(logged.String(), c[1]) {
			t.Errorf("the code in %q or the log", args[0])
		}
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
