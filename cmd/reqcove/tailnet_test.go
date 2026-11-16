package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

var (
	iphone = exitnode.Device{ID: "nIPHONE", Name: "iphone"}
	ipad   = exitnode.Device{ID: "nIPAD", Name: "ipad"}
)

// tailnetRun is a run's ctl.sock (no mitmproxy) whose status holds this
// computer's paths and discovery's names, with its tailnet page on 127.0.0.1
// (the stand-in for the node's tailnet address); who is the caller's
// own-device verdict, as exitnode.OwnDeviceAt gives it (nil: not one of the
// user's own devices: tagged, another user's, shared in).
func tailnetRun(t *testing.T, o *runOpts) (string, *ctlState, *atomic.Pointer[exitnode.Device]) {
	t.Helper()
	dir, _ := os.MkdirTemp("/tmp", "rcvt-") // short socket paths; not the default state
	t.Cleanup(func() { os.RemoveAll(dir) })
	home, _ := os.UserHomeDir()
	var who atomic.Pointer[exitnode.Device]
	who.Store(&iphone)
	wasL, wasO, wasEnd := listenTailnet, ownDeviceAt, captureEndCmd
	listenTailnet = func() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	ownDeviceAt = func(string) (exitnode.Device, bool) {
		d := who.Load()
		if d == nil {
			return exitnode.Device{}, false
		}
		return *d, true
	}
	captureEndCmd = withState("reqcove capture allow-all --end", dir)
	t.Cleanup(func() { listenTailnet, ownDeviceAt, captureEndCmd = wasL, wasO, wasEnd })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cap := &capture.Capture{Store: capture.NewStore(10, 1<<20)}
	st, err := serveCtl(ctx, dir, cap, o, nil, func() mcpserver.StatusOut {
		return mcpserver.StatusOut{Mode: "tailnet", Version: "v1.3.0", Executable: "/opt/homebrew/bin/reqcove", Service: "com.example", Manager: "launchd",
			ConfigFile: home + "/.config/reqcove/config", ConfigUnused: dir + "/config", HostsFiles: []string{dir + "/hosts"}, KeepAwake: "ac", Recording: "on",
			BaseAllowHosts: []string{"a.example.com"},
			NextSteps: []string{"approve the exit node", "to end it now, in your terminal: " + withState("reqcove capture discover --end", dir),
				"/Library/LaunchAgents/com.example.plist runs /opt/old/reqcove, which is gone", "see ~/Library/Logs/reqcove.log."},
			Node:            exitnode.Status{Node: "reqcove.ts.net", IPs: []string{"100.64.0.1"}, Devices: map[string]string{"n1": "iphone"}},
			OutOfScopeHosts: []mcpserver.OutHost{{Host: "seen.example.com", Count: 3, Add: "reqcove capture add seen.example.com"}}, OutOfScopeHostsKept: 7}
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir, st, &who
}

// openTailnetUI is the console op with --tailnet: the page's base URL and a code.
func openTailnetUI(t *testing.T, state string) (string, string) {
	t.Helper()
	a, err := askRun(context.Background(), state, ctlRequest{Cmd: "console", Tailnet: true})
	if err != nil || !a.OK || a.Addr == "" || a.Port != 0 || a.File != "" || len(a.Code) != 32 {
		t.Fatalf("console --tailnet: %v %+v", err, a)
	}
	return "http://" + a.Addr, a.Code
}

// Who calls, checked on every request from the connection: one of the
// user's own devices alone (others refused, at the files too); one that
// stops being so (retagged, removed) is refused on the connection it kept
// alive, which then closes.
func TestTailnetPageWho(t *testing.T) {
	logged := logTo(t)
	state, st, who := tailnetRun(t, &runOpts{})
	base, code := openTailnetUI(t, state)
	if st.page != nil || st.tailnet.Load() == nil {
		t.Fatal("the tailnet op opened this computer's page")
	}
	if m, _ := filepath.Glob(filepath.Join(state, "console-*")); len(m) > 0 {
		t.Errorf("a code file for the tailnet: %v", m)
	}
	who.Store(nil) // tagged, another user's, shared in: not own
	for _, c := range [][3]string{{"GET", "/", ""}, {"GET", "/app.js", ""}, {"POST", "/api/session", `{"code":"` + code + `"}`}} {
		if r, b := call(t, base, c[0], c[1], c[2], nil); r.StatusCode != 403 || !strings.Contains(b, "only your own devices") || !r.Close {
			t.Errorf("not own, %s: %d %s", c[1], r.StatusCode, b)
		}
	}
	who.Store(&iphone)
	token := trade(t, base, code) // the code was not used up by the refused trade
	if n, s := pageStateOf(t, base, token); n != 200 || !s.Tailnet {
		t.Errorf("own: %d %+v", n, s)
	}
	// One connection, kept alive: the verdict flips between two requests on it.
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 1}}
	get := func() (*http.Response, bool) {
		t.Helper()
		reused := false
		req, _ := http.NewRequest("GET", base+"/api/state", nil)
		req.Header.Set(sessionHeader, token)
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}))
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		return r, reused
	}
	if r, _ := get(); r.StatusCode != 200 {
		t.Fatalf("first: %d", r.StatusCode)
	}
	who.Store(nil) // retagged
	if r, reused := get(); !reused || r.StatusCode != 403 || !r.Close {
		t.Errorf("retagged on a kept-alive connection: reused %v, %d, close %v", reused, r.StatusCode, r.Close)
	}
	who.Store(&iphone)
	if r, reused := get(); reused || r.StatusCode != 200 {
		t.Errorf("after: reused %v, %d", reused, r.StatusCode)
	}
	if !strings.Contains(logged.String(), "reqcove console --tailnet: the page listens on "+base+", for your own devices") ||
		!strings.Contains(logged.String(), "reqcove console --tailnet: a session for iphone") || strings.Contains(logged.String(), code) || strings.Contains(logged.String(), token) {
		t.Errorf("log: %s", logged.String())
	}
}

// A session is the device's that traded the code: another device's use of
// it (its StableID) is refused, and ends it; this computer's page's tokens
// and codes are refused on the tailnet page, and its on this computer's.
func TestTailnetPageSessions(t *testing.T) {
	logTo(t)
	state, _, who := tailnetRun(t, &runOpts{})
	tbase, tcode := openTailnetUI(t, state)
	lbase, lcode := openUI(t, state)
	if tbase == lbase {
		t.Fatal("one listener")
	}
	_, lcode2 := openUI(t, state)
	_, tcode2 := openTailnetUI(t, state)
	if r, b := call(t, tbase, "POST", "/api/session", `{"code":"`+lcode2+`"}`, nil); r.StatusCode != 403 || !strings.Contains(b, "not one this run gave") {
		t.Errorf("a local code on the tailnet page: %d %s", r.StatusCode, b)
	}
	if r, b := call(t, lbase, "POST", "/api/session", `{"code":"`+tcode2+`"}`, nil); r.StatusCode != 403 || !strings.Contains(b, "not one this run gave") {
		t.Errorf("a tailnet code on the local page: %d %s", r.StatusCode, b)
	}
	tok := trade(t, tbase, tcode)
	ltok := trade(t, lbase, lcode)
	if n, _ := pageStateOf(t, tbase, ltok); n != 401 {
		t.Errorf("a local token on the tailnet page: %d", n)
	}
	if n, _ := pageStateOf(t, lbase, tok); n != 401 {
		t.Errorf("a tailnet token on the local page: %d", n)
	}
	who.Store(&ipad) // own too, but not the device that traded the code
	if r, b := call(t, tbase, "GET", "/api/state", "", map[string]string{sessionHeader: tok}); r.StatusCode != 401 || !strings.Contains(b, "used from another device") {
		t.Errorf("another device: %d %s", r.StatusCode, b)
	}
	who.Store(&iphone)
	if n, _ := pageStateOf(t, tbase, tok); n != 401 {
		t.Errorf("ended by the other device's use: %d", n)
	}
	if n, _ := pageStateOf(t, lbase, ltok); n != 200 {
		t.Errorf("the local session: %d", n)
	}
}

// The tailnet page's sessions: 1 h idle, 12 h in all (the wall clock as
// due has it for both), and
// counted for status by device; console --end ends them too.
func TestTailnetPageLimits(t *testing.T) {
	logTo(t)
	state, st, who := tailnetRun(t, &runOpts{})
	base, _ := openTailnetUI(t, state)
	c := &clock{base: time.Now()}
	setClock(st.tailnet.Load(), c)
	_, code := openTailnetUI(t, state)
	tok := trade(t, base, code)
	c.move(tailnetIdle-time.Second, 0)
	if n, _ := pageStateOf(t, base, tok); n != 200 {
		t.Errorf("used just before 1 h: %d", n)
	}
	c.move(tailnetIdle, 0)
	if n, _ := pageStateOf(t, base, tok); n != 401 {
		t.Errorf("1 h idle: %d", n)
	}
	_, code = openTailnetUI(t, state)
	tok = trade(t, base, code)
	for range 12 {
		c.move(time.Hour-time.Second, 0)
		pageStateOf(t, base, tok)
	}
	c.move(12*time.Second, 0)
	if n, _ := pageStateOf(t, base, tok); n != 401 {
		t.Errorf("12 h in all, used every hour: %d", n)
	}
	_, code = openTailnetUI(t, state)
	trade(t, base, code)
	_, code = openTailnetUI(t, state)
	trade(t, base, code)
	who.Store(&ipad)
	_, code = openTailnetUI(t, state)
	trade(t, base, code)
	lbase, lcode := openUI(t, state)
	ltok := trade(t, lbase, lcode)
	cs := st.consoleSessions()
	if cs == nil || cs.Local != 1 || len(cs.Tailnet) != 2 || cs.Tailnet["iphone"] != 2 || cs.Tailnet["ipad"] != 1 {
		t.Errorf("counted: %+v", cs)
	}
	if got := consoleText(cs); got != "1 sessions on this computer's page; on the tailnet page: ipad 1, iphone 2 (reqcove console --end ends them all)" {
		t.Errorf("status: %q", got)
	}
	a, err := askRun(context.Background(), state, ctlRequest{Cmd: "console-end"})
	if err != nil || !strings.Contains(a.Message, "ended: 4 sessions") {
		t.Errorf("--end: %v %+v", err, a)
	}
	if n, _ := pageStateOf(t, lbase, ltok); n != 401 {
		t.Errorf("local after --end: %d", n)
	}
	if cs := st.consoleSessions(); cs.Local != 0 || len(cs.Tailnet) != 0 {
		t.Errorf("after --end: %+v", cs)
	}
	if newCtlState(&runOpts{}).consoleSessions() != nil {
		t.Error("counted before a page")
	}
}

// Asked only as itself: the exact Host (its address and port: never a name
// nor another port) and, when a request carries an Origin, its own (--ui's
// page on :80 is another origin).
func TestTailnetPageOrigin(t *testing.T) {
	logTo(t)
	state, _, _ := tailnetRun(t, &runOpts{})
	base, code := openTailnetUI(t, state)
	tok := trade(t, base, code)
	host := strings.TrimPrefix(base, "http://")
	_, port, _ := net.SplitHostPort(host)
	other := strconv.Itoa(func() int { n, _ := strconv.Atoi(port); return n + 1 }())
	for _, h := range []string{"localhost:" + port, "reqcove.tail.ts.net:" + port, "reqcove:" + port, "127.0.0.1", "127.0.0.1:" + other} {
		if r, _ := call(t, base, "GET", "/api/state", "", map[string]string{"Host": h, sessionHeader: tok}); r.StatusCode != 421 {
			t.Errorf("Host %s: %d", h, r.StatusCode)
		}
	}
	for _, o := range []string{"http://127.0.0.1", "http://127.0.0.1:80", "http://localhost:" + port, "null"} {
		for _, m := range []string{"GET", "POST"} {
			body := ""
			if m == "POST" {
				body = `{"text":"x"}`
			}
			if r, b := call(t, base, m, "/api/marker", body, map[string]string{"Origin": o, sessionHeader: tok}); r.StatusCode != 403 || !strings.Contains(b, "from this page only") {
				t.Errorf("%s from %s: %d %s", m, o, r.StatusCode, b)
			}
		}
	}
	if r, b := call(t, base, "POST", "/api/marker", `{"text":"from the phone"}`, map[string]string{sessionHeader: tok}); r.StatusCode != 200 || !strings.Contains(b, `"ok":true`) {
		t.Errorf("its own origin: %d %s", r.StatusCode, b)
	}
}

// Only what ends with the run: every route of this computer's page that is
// not the tailnet page's is refused there, Save too, whatever the session.
// Its answers hold no path of this computer, and discovery's names as their
// count alone.
func TestTailnetPageServes(t *testing.T) {
	logTo(t)
	state, _, _ := tailnetRun(t, &runOpts{})
	base, code := openTailnetUI(t, state)
	tok := trade(t, base, code)
	lbase, lcode := openUI(t, state)
	ltok := trade(t, lbase, lcode)
	local := 0
	for _, rt := range pageRoutes() {
		if rt.tailnet {
			continue
		}
		local++
		m, path, _ := strings.Cut(rt.pattern, " ")
		body := ""
		if m == "POST" {
			body = `{}`
		}
		if r, b := call(t, base, m, path, body, map[string]string{sessionHeader: tok}); r.StatusCode != 403 || !strings.Contains(b, "only what ends with the run") {
			t.Errorf("%s on the tailnet page: %d %s", rt.pattern, r.StatusCode, b)
		}
		if r, b := call(t, lbase, m, path, body, map[string]string{sessionHeader: ltok}); strings.Contains(b, "only what ends with the run") {
			t.Errorf("%s on this computer's page: %d %s", rt.pattern, r.StatusCode, b)
		}
	}
	if local != 6 {
		t.Errorf("%d routes this computer's alone", local)
	}
	_, s := pageStateOf(t, base, tok)
	if r, b := call(t, base, "POST", "/api/change", `{"cmd":"save","confirm":"x","rev":"`+s.Rev+`"}`, map[string]string{sessionHeader: tok}); r.StatusCode != 403 || !strings.Contains(b, "nothing written") {
		t.Errorf("save: %d %s", r.StatusCode, b)
	}

	home, _ := os.UserHomeDir()
	var all strings.Builder
	for _, path := range []string{"/api/state", "/api/presets", "/api/ca"} {
		r, b := call(t, base, "GET", path, "", map[string]string{sessionHeader: tok})
		if r.StatusCode != 200 || !json.Valid([]byte(b)) {
			t.Errorf("%s: %d %s", path, r.StatusCode, b)
		}
		all.WriteString(b)
	}
	_, b := call(t, base, "POST", "/api/marker", `{"text":"x"}`, map[string]string{sessionHeader: tok})
	all.WriteString(b)
	for _, bad := range []string{state, home, "/opt/", "/Library", "~/", "seen.example.com", "config"} {
		if strings.Contains(all.String(), bad) {
			t.Errorf("%q in the tailnet page's answers: %s", bad, all.String())
		}
	}
	_, s = pageStateOf(t, base, tok)
	if !s.Tailnet || len(s.Discovered) != 0 || s.DiscoveredKept != 7 || s.Executable != "" || s.ConfigFile != "" || len(s.HostsFiles) != 0 || len(s.ServiceCmds) != 0 ||
		s.Service != "com.example" || s.KeepAwake == "" || len(s.NextSteps) != 4 || !strings.Contains(s.NextSteps[1], "reqcove capture discover --end --state "+pathHidden) ||
		s.FlowsURL != "" {
		t.Errorf("state: %+v", s)
	}
	// This computer's page still shows them.
	_, ls := pageStateOf(t, lbase, ltok)
	if len(ls.Discovered) != 1 || ls.Executable == "" || ls.Tailnet {
		t.Errorf("this computer's page: %+v", ls)
	}
}

// The words without this computer's paths; URLs and other words kept.
func TestWithoutPaths(t *testing.T) {
	dir := "/tmp/a state dir"
	for in, want := range map[string]string{
		withState("reqcove capture start", dir):             "reqcove capture start --state " + pathHidden,
		"see /Users/x/.reqcove/run.log.":                    "see " + pathHidden + ".",
		"(~/Library/LaunchAgents/x.plist)":                  "(" + pathHidden + ")",
		"open http://mitm.it in Safari, http://100.64.0.1/": "open http://mitm.it in Safari, http://100.64.0.1/",
		"30m/1h, allow/pass; 3 / 4":                         "30m/1h, allow/pass; 3 / 4",
		"--rules=/etc/x.yaml":                               "--rules=" + pathHidden,
	} {
		if got := withoutPaths(in, dir); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	v := withoutPaths(map[string]any{"a": []any{"/x/y", 1.0}}, "")
	if b, _ := json.Marshal(v); string(b) != `{"a":["`+pathHidden+`",1]}` {
		t.Errorf("%s", b)
	}
}

// Refused in LAN mode and where the node says no (tagged, not up): nothing
// opened; a change on the tailnet page is traced with the device's name.
func TestTailnetPageRefused(t *testing.T) {
	logged := logTo(t)
	state, st, _ := tailnetRun(t, &runOpts{lanMode: true})
	if a, err := askRun(context.Background(), state, ctlRequest{Cmd: "console", Tailnet: true}); err != nil || a.OK || !strings.Contains(a.Message, "LAN mode") || a.Code != "" || st.tailnet.Load() != nil {
		t.Errorf("LAN mode: %v %+v", err, a)
	}
	state, st, who := tailnetRun(t, &runOpts{})
	listenTailnet = func() (net.Listener, error) {
		return nil, errors.New("reqcove's node is tagged: a tagged node is no user's")
	}
	if a, err := askRun(context.Background(), state, ctlRequest{Cmd: "console", Tailnet: true}); err != nil || a.OK || !strings.Contains(a.Message, "tagged") || a.Code != "" || st.tailnet.Load() != nil {
		t.Errorf("tagged: %v %+v", err, a)
	}
	listenTailnet = func() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	if _, err := (ctlRequest{Cmd: "add", Hosts: []string{"a.com"}, Tailnet: true}).normalized(); err == nil {
		t.Error("tailnet with add")
	}
	base, code := openTailnetUI(t, state)
	tok := trade(t, base, code)
	d := st.reqs.ask(capture.HostRules{}, []string{"d.example.com"}).Requests[0]
	if r, b := call(t, base, "POST", "/api/deny", `{"id":"`+d.ID+`"}`, map[string]string{sessionHeader: tok}); r.StatusCode != 200 || !strings.Contains(b, "denied: d.example.com") {
		t.Errorf("deny: %d %s", r.StatusCode, b)
	}
	waitLog(t, logged, "capture request "+d.ID+" (d.example.com): denied in the console on iphone (tailnet)", 1)
	who.Store(&exitnode.Device{ID: "nNONAME"}) // a peer without a MagicDNS name: its StableID, never this computer's
	_, code = openTailnetUI(t, state)
	tok = trade(t, base, code)
	d = st.reqs.ask(capture.HostRules{}, []string{"e.example.com"}).Requests[0]
	call(t, base, "POST", "/api/deny", `{"id":"`+d.ID+`"}`, map[string]string{sessionHeader: tok})
	waitLog(t, logged, "capture request "+d.ID+" (e.example.com): denied in the console on nNONAME (tailnet)", 1)
	if cs := st.consoleSessions(); cs.Tailnet["nNONAME"] != 1 {
		t.Errorf("counted: %+v", cs)
	}
	if got := consoleFrom("iphone"); got != " (from the console on iphone, over the tailnet)" || consoleFrom("") != fromConsole {
		t.Errorf("trace: %q", got)
	}
}

// reqcove console --tailnet: in a terminal only; the link, with its code,
// as a QR code and as text in the terminal alone: no browser opened (the
// code never reaches an opener's arguments), no file. A run older than v1.3
// (no tailnet address in its answer) is said to be so.
func TestConsoleTailnetCmd(t *testing.T) {
	ctx := context.Background()
	code := strings.Repeat("ab", 16)
	dir, got := fakeCtlSock(t, func(req ctlRequest) ctlAnswer {
		return ctlAnswer{OK: true, Message: "the tailnet page", Code: code, Addr: "100.64.0.1:10002"}
	})
	was := openBrowser
	openBrowser = func(_ context.Context, f string) error { t.Errorf("opened %s", f); return nil }
	defer func() { openBrowser, terminal = was, isTerminal }()
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if err := tailnetIn(ctx, r, w, dir); !errors.Is(err, errNotTerminal) || len(*got) != 0 {
		t.Errorf("off a terminal: %v %+v", err, *got)
	}
	terminal = func(*os.File) bool { return true }
	out, _ := os.Create(filepath.Join(t.TempDir(), "out"))
	defer out.Close()
	if err := tailnetIn(ctx, r, out, dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out.Name())
	if link := "http://100.64.0.1:10002/#c=" + code; !strings.HasPrefix(string(b), "the tailnet page\n") || !strings.HasSuffix(string(b), "  "+link+"\n") ||
		!strings.Contains(string(b), "█") || len(*got) != 1 || !(*got)[0].Tailnet || (*got)[0].Cmd != "console" {
		t.Errorf("%q %+v", b, *got)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "console-*")); len(m) > 0 {
		t.Errorf("a file: %v", m)
	}
	for _, a := range []ctlAnswer{{OK: true, Message: "the page", Port: 4242, Code: code}, {OK: true, Code: code, Addr: "reqcove.ts.net:1"}, {Message: v11Answer}} {
		old, _ := fakeCtlSock(t, func(ctlRequest) ctlAnswer { return a })
		if err := tailnetIn(ctx, r, out, old); !errors.Is(err, errOlderTailnet) {
			t.Errorf("%+v: %v", a, err)
		}
	}
	refused, _ := fakeCtlSock(t, func(ctlRequest) ctlAnswer { return ctlAnswer{Message: "refused: in LAN mode"} })
	if err := tailnetIn(ctx, r, out, refused); err == nil || err.Error() != "refused: in LAN mode" {
		t.Errorf("refused: %v", err)
	}
	if err := consoleCmd(ctx, []string{"--tailnet", "--end", "--state", dir}); err == nil || !strings.Contains(err.Error(), "give it alone") {
		t.Errorf("--tailnet --end: %v", err)
	}
}

// The Remote Proxy's relay: the tailnet page opened, run hands the Remote
// Proxy the page's own handler (exitnode.RelayConsole), which then takes a
// proxy's absolute-form request with its checks unchanged: the caller from
// RemoteAddr (the proxy client's connection; a forwarded header naming an own
// device counts for nothing), the exact Host, the Origin, the session.
func TestTailnetPageRelayed(t *testing.T) {
	state, st, _ := tailnetRun(t, &runOpts{})
	var addr string
	var h http.Handler
	wasR, wasO := relayTailnet, ownDeviceAt
	relayTailnet = func(_ context.Context, a string, hh http.Handler) { addr, h = a, hh }
	ownDeviceAt = func(a string) (exitnode.Device, bool) { // by the address, as exitnode's
		host, _, _ := net.SplitHostPort(a)
		return iphone, host == "100.64.0.1"
	}
	t.Cleanup(func() { relayTailnet, ownDeviceAt = wasR, wasO })
	base, code := openTailnetUI(t, state)
	if p := st.tailnet.Load(); h != http.Handler(p) || "http://"+addr != base {
		t.Fatalf("relayed %q %T, the page %s", addr, h, base)
	}
	serve := func(method, url, from, body string, hdr http.Header) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, url, strings.NewReader(body)) // absolute-form, as a proxy gets it
		r.RemoteAddr = from
		maps.Copy(r.Header, hdr)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	post := http.Header{"Origin": {base}, "Content-Type": {"application/json"}}
	forwarded := http.Header{"X-Forwarded-For": {"100.64.0.1"}, "Forwarded": {"for=100.64.0.1"}, "X-Real-Ip": {"100.64.0.1"}}
	if w := serve("POST", base+"/api/session", "100.64.0.2:5000", `{"code":"`+code+`"}`, merge(post, forwarded)); w.Code != 403 {
		t.Errorf("not own, a forwarded header naming an own device: %d %s", w.Code, w.Body)
	}
	w := serve("POST", base+"/api/session", "100.64.0.1:5000", `{"code":"`+code+`"}`, post)
	var d struct{ Token string }
	json.Unmarshal(w.Body.Bytes(), &d)
	if w.Code != 200 || len(d.Token) != 64 {
		t.Fatalf("own, the trade: %d %s", w.Code, w.Body)
	}
	session := http.Header{sessionHeader: {d.Token}}
	if w := serve("GET", base+"/api/state", "100.64.0.1:5000", "", session); w.Code != 200 || !strings.Contains(w.Body.String(), `"tailnet":true`) {
		t.Errorf("own, the state: %d %s", w.Code, w.Body)
	}
	for _, c := range []struct {
		what, url, from string
		hdr             http.Header
		want            int
	}{
		{"not own, a forwarded header naming an own device", base + "/api/state", "100.64.0.2:5000", merge(session, forwarded), 403},
		{"by the node's name", strings.Replace(base, "127.0.0.1", "reqcove.tail.ts.net", 1) + "/api/state", "100.64.0.1:5000", session, 421},
		{"another Origin", base + "/api/state", "100.64.0.1:5000", merge(session, http.Header{"Origin": {"http://reqcove"}}), 403},
		{"no session", base + "/api/state", "100.64.0.1:5000", nil, 401},
		{"a route of this computer's page", base + "/api/settings", "100.64.0.1:5000", session, 403},
	} {
		if w := serve("GET", c.url, c.from, "", c.hdr); w.Code != c.want {
			t.Errorf("%s: %d %s", c.what, w.Code, w.Body)
		}
	}
}

func merge(hs ...http.Header) http.Header {
	out := http.Header{}
	for _, h := range hs {
		maps.Copy(out, h)
	}
	return out
}
