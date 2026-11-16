package main

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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/proxy"
)

// The arguments of reqcove capture: the hosts anywhere among the flags, and
// what is refused before run is asked ("*" above all).
func TestCaptureArgs(t *testing.T) {
	words, flags := wordsAndFlags([]string{"add", "--state", "/s", "API.b.com", "--allow-hosts", "x.com", "--pass"}, "allow-hosts", "pass-hosts")
	if strings.Join(words, " ") != "add API.b.com" || strings.Join(flags, " ") != "--state /s --allow-hosts x.com --pass" {
		t.Errorf("words %q, flags %q", words, flags)
	}
	req, err := ctlRequest{Cmd: "add", Hosts: []string{"API.b.com.", "c.com,*.d.com"}}.normalized()
	if err != nil || !slices.Equal(req.Hosts, []string{"api.b.com", "c.com", "*.d.com"}) || req.String() != "capture add api.b.com c.com *.d.com" {
		t.Errorf("%v %q %q", err, req.Hosts, req.String())
	}
	if req, _ := (ctlRequest{Cmd: "set", AllowHosts: []string{"a.com"}, PassHosts: []string{"a.com"}}).normalized(); req.String() != "capture set --allow-hosts a.com --pass-hosts a.com" {
		t.Errorf("set: %q", req.String())
	}
	if req, err := (ctlRequest{Cmd: "stop"}).normalized(); err != nil || req.String() != "capture stop" {
		t.Errorf("stop: %v %q", err, req.String())
	}
	for _, c := range []struct {
		req  ctlRequest
		want string
	}{
		{ctlRequest{Cmd: "add", Hosts: []string{"*"}}, `"*" is refused`},
		{ctlRequest{Cmd: "add", Hosts: []string{"a.com,*"}}, `"*" is refused`},
		{ctlRequest{Cmd: "set", AllowHosts: []string{"*"}}, `"*" is refused`},
		{ctlRequest{Cmd: "set", AllowHosts: []string{"a.com"}, PassHosts: []string{"*"}}, `"*" is refused`},
		{ctlRequest{Cmd: "add", Hosts: []string{"a b.com"}}, "bad host"},
		{ctlRequest{Cmd: "add", Hosts: []string{"$(id).com"}}, "bad host"},
		{ctlRequest{Cmd: "remove"}, "name the hosts"},
		{ctlRequest{Cmd: "add", Hosts: []string{"a.com"}, AllowHosts: []string{"b.com"}}, "go with capture set"},
		{ctlRequest{Cmd: "set"}, "needs --allow-hosts"},
		{ctlRequest{Cmd: "set", AllowHosts: []string{"a.com"}, Hosts: []string{"b.com"}}, "only"},
		{ctlRequest{Cmd: "stop", Hosts: []string{"a.com"}}, "takes no hosts"},
		{ctlRequest{Cmd: "start", Pass: true}, "takes no hosts"},
		{ctlRequest{Cmd: "allow-all"}, "takes --for D"},
		{ctlRequest{Cmd: "allow-all", For: "30m", End: true}, "takes --for D"},
		{ctlRequest{Cmd: "allow-all", For: "25h"}, "at most 24h"},
		{ctlRequest{Cmd: "allow-all", For: "0s"}, "at most 24h"},
		{ctlRequest{Cmd: "allow-all", For: "-5m"}, "at most 24h"},
		{ctlRequest{Cmd: "allow-all", For: "30"}, "a duration such as 30m"},
		{ctlRequest{Cmd: "allow-all", For: "1h", Hosts: []string{"a.com"}}, "takes no hosts"},
		{ctlRequest{Cmd: "stop", For: "1h"}, "go with capture allow-all"},
		{ctlRequest{Cmd: "add", Hosts: []string{"a.com"}, End: true}, "go with capture allow-all"},
		{ctlRequest{Cmd: "allow-al"}, "usage"},
		{ctlRequest{}, "usage"},
	} {
		if _, err := c.req.normalized(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.req, err, c.want)
		}
	}
	for _, c := range []struct {
		req  ctlRequest
		want string
	}{{ctlRequest{Cmd: "allow-all", For: "30m"}, "capture allow-all --for 30m"}, {ctlRequest{Cmd: "allow-all", For: "24h"}, "capture allow-all --for 24h"}, {ctlRequest{Cmd: "allow-all", End: true}, "capture allow-all --end"}} {
		if req, err := c.req.normalized(); err != nil || req.String() != c.want {
			t.Errorf("%+v: %v %q", c.req, err, req.String())
		}
	}
	// --for's value is not a host: past the arguments, only the terminal check is left.
	if err := captureCmd(context.Background(), []string{"allow-all", "--for", "30m", "--state", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "only in a terminal") {
		t.Errorf("allow-all --for 30m: %v", err)
	}
	// run checks again (any process of the user can reach ctl.sock), before the capture is touched.
	if a := answerCtl(context.Background(), nil, newCtlState(&runOpts{}), ctlRequest{Cmd: "add", Hosts: []string{"*"}}); a.OK || !strings.Contains(a.Message, `"*" is refused`) || !strings.Contains(a.Message, "nothing changed") {
		t.Errorf("run, *: %+v", a)
	}
}

func scopeOf(t *testing.T, allow, pass []string) capture.HostRules {
	t.Helper()
	r, err := capture.ParseAllowHosts(allow)
	if err == nil && len(pass) > 0 {
		r, err = r.WithPass(pass)
	}
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// newScope: what each command makes of the scope; a remove that a wildcard
// would undo is refused, naming the wildcard.
func TestNewScope(t *testing.T) {
	cur := scopeOf(t, []string{"a.com", "*.b.com", "c.com"}, []string{"c.com"})
	for _, c := range []struct {
		req               ctlRequest
		allow, pass       []string
		change, note, err string
	}{
		{req: ctlRequest{Cmd: "add", Hosts: []string{"d.com"}}, allow: []string{"a.com", "*.b.com", "c.com", "d.com"}, pass: []string{"c.com"}, change: "d.com added"},
		{req: ctlRequest{Cmd: "add", Hosts: []string{"api.b.com", "a.com"}}, change: "", note: "api.b.com is recorded already (through *.b.com)"},
		{req: ctlRequest{Cmd: "remove", Hosts: []string{"a.com"}}, allow: []string{"*.b.com", "c.com"}, pass: []string{"c.com"}, change: "a.com removed"},
		{req: ctlRequest{Cmd: "remove", Hosts: []string{"c.com"}}, allow: []string{"a.com", "*.b.com"}, change: "c.com removed, c.com no longer passed undecrypted"},
		{req: ctlRequest{Cmd: "remove", Hosts: []string{"api.b.com"}}, err: "api.b.com is recorded through *.b.com: remove *.b.com instead"},
		{req: ctlRequest{Cmd: "remove", Hosts: []string{"e.com"}}, change: "", note: "e.com was not recorded"},
		{req: ctlRequest{Cmd: "add", Pass: true, Hosts: []string{"x.b.com"}}, allow: []string{"a.com", "*.b.com", "c.com"}, pass: []string{"c.com", "x.b.com"}, change: "x.b.com passed undecrypted"},
		{req: ctlRequest{Cmd: "add", Pass: true, Hosts: []string{"z.com"}}, change: "z.com passed undecrypted", note: "z.com is not among the hosts recorded"},
		{req: ctlRequest{Cmd: "remove", Pass: true, Hosts: []string{"c.com"}}, allow: []string{"a.com", "*.b.com", "c.com"}, change: "c.com no longer passed undecrypted"},
		{req: ctlRequest{Cmd: "set", AllowHosts: []string{"a.com"}}, allow: []string{"a.com"}, change: "*.b.com, c.com removed, c.com no longer passed undecrypted"},
	} {
		next, notes, err := newScope(cur, c.req)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: %v, want %q", c.req, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.req, err)
			continue
		}
		if got := changes(cur, next); got != c.change {
			t.Errorf("%s: changes %q, want %q", c.req, got, c.change)
		}
		if c.allow != nil && (!slices.Equal(next.Hosts, c.allow) || !slices.Equal(next.PassHosts, c.pass)) {
			t.Errorf("%s: %q %q", c.req, next.Hosts, next.PassHosts)
		}
		if c.note != "" && !slices.ContainsFunc(notes, func(n string) bool { return strings.Contains(n, c.note) }) {
			t.Errorf("%s: notes %q, want %q", c.req, notes, c.note)
		}
	}
	// A host both named and under a wildcard stays recorded once removed: refused.
	if _, _, err := newScope(scopeOf(t, []string{"api.b.com", "*.b.com"}, nil), ctlRequest{Cmd: "remove", Hosts: []string{"api.b.com"}}); err == nil || !strings.Contains(err.Error(), "stays recorded through *.b.com") {
		t.Errorf("named and under a wildcard: %v", err)
	}
	// Under "*" (run --allow-hosts '*'): named through it.
	if _, _, err := newScope(scopeOf(t, []string{"*"}, nil), ctlRequest{Cmd: "remove", Hosts: []string{"a.com"}}); err == nil || !strings.Contains(err.Error(), "through *:") {
		t.Errorf("under *: %v", err)
	}
	// Passed hosts need hosts recorded.
	if _, _, err := newScope(scopeOf(t, []string{"c.com"}, []string{"*.c.com"}), ctlRequest{Cmd: "remove", Hosts: []string{"c.com"}}); err == nil || !strings.Contains(err.Error(), "need hosts recorded") {
		t.Errorf("pass hosts left alone: %v", err)
	}
}

// Off a terminal, nothing is asked of run; in LAN mode run refuses; a run
// without ctl.sock but with mcp.sock is an older one.
func TestCaptureRefusals(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "rcvc-") // short socket paths
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	asked := make(chan struct{}, 1)
	ln, err := net.Listen("unix", filepath.Join(dir, ctlSock))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			asked <- struct{}{}
			c.Close()
		}
	}()
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if err := captureIn(ctx, r, w, dir, ctlRequest{Cmd: "add", Hosts: []string{"a.com"}}); err == nil || !strings.Contains(err.Error(), "only in a terminal") {
		t.Errorf("off a terminal: %v", err)
	}
	select {
	case <-asked:
		t.Error("off a terminal: run was asked")
	case <-time.After(100 * time.Millisecond):
	}
	ln.Close()

	// LAN mode: refused by run, over the socket (as the CLI asks it).
	lanDir, _ := os.MkdirTemp("/tmp", "rcvc-")
	defer os.RemoveAll(lanDir)
	if err := serveCtl(ctx, lanDir, nil, &runOpts{lanMode: true}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(lanDir, ctlSock))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("ctl.sock: %v, mode %v", err, fi.Mode().Perm())
	}
	for _, req := range []ctlRequest{{Cmd: "add", Hosts: []string{"a.com"}}, {Cmd: "stop"}, {Cmd: "start"}, {Cmd: "save"}} {
		nothing := "nothing changed"
		if req.Cmd == "save" {
			nothing = "nothing written"
		}
		if err := sendCapture(ctx, io.Discard, lanDir, req); err == nil || !strings.Contains(err.Error(), "LAN mode") || !strings.Contains(err.Error(), nothing) {
			t.Errorf("LAN mode, %s: %v", req, err)
		}
	}

	// A v1.0 run: mcp.sock, no ctl.sock.
	old, _ := os.MkdirTemp("/tmp", "rcvc-")
	defer os.RemoveAll(old)
	if err := mcpserver.Serve(ctx, filepath.Join(old, "mcp.sock"), mcp.NewServer(&mcp.Implementation{Name: "reqcove", Version: "v1.0.0"}, nil)); err != nil {
		t.Fatal(err)
	}
	if err := sendCapture(ctx, io.Discard, old, ctlRequest{Cmd: "add", Hosts: []string{"a.com"}}); err == nil || !strings.Contains(err.Error(), "this run is v1.0.0: restart it with v1.1") {
		t.Errorf("older run: %v", err)
	}
	none, _ := os.MkdirTemp("/tmp", "rcvc-")
	defer os.RemoveAll(none)
	if err := sendCapture(ctx, io.Discard, none, ctlRequest{Cmd: "add", Hosts: []string{"a.com"}}); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Errorf("none running: %v", err)
	}
}

// A run that takes the connection and never answers (Ctrl-Z): the CLI gives up.
func TestCaptureNoAnswer(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "rcvc-")
	defer os.RemoveAll(dir)
	ln, err := net.Listen("unix", filepath.Join(dir, ctlSock))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	old := ctlWait
	ctlWait = 300 * time.Millisecond
	defer func() { ctlWait = old }()
	done := make(chan error, 1)
	go func() {
		done <- sendCapture(context.Background(), io.Discard, dir, ctlRequest{Cmd: "add", Hosts: []string{"a.com"}})
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "did not answer") {
			t.Errorf("%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waits for a run that does not answer")
	}
}

// next_steps: with nothing recorded, the command that adds hosts while run
// runs (with its --state); in LAN mode (none), the restart.
func TestCaptureStep(t *testing.T) {
	defer func() { mcpserver.CaptureAddCmd = "" }()
	stats := map[string]any{"state": "ready"}
	mcpserver.CaptureAddCmd = withState("reqcove capture add", "/tmp/my state")
	steps := nextSteps(exitnode.Status{Backend: "Running"}, stats, capture.HostRules{}, capture.CA{}, nil)
	if !slices.Contains(steps, "nothing is recorded: add your app's hosts, in your terminal: reqcove capture add --state '/tmp/my state' api.example.com") {
		t.Errorf("%q", steps)
	}
	// Stopped: the start, not the add (the hosts are kept for the start).
	mcpserver.CaptureStartCmd = withState("reqcove capture start", "/tmp/my state")
	defer func() { mcpserver.CaptureStartCmd = "reqcove capture start" }()
	steps = nextSteps(exitnode.Status{Backend: "Running"}, map[string]any{"state": "ready", "recording": "stopped"}, capture.HostRules{}, capture.CA{}, nil)
	if !slices.ContainsFunc(steps, func(s string) bool {
		return strings.HasPrefix(s, "recording is stopped: ") && strings.Contains(s, "the app reaches the real servers") && strings.HasSuffix(s, "reqcove capture start --state '/tmp/my state'")
	}) || slices.ContainsFunc(steps, func(s string) bool { return strings.HasPrefix(s, "nothing is recorded") }) {
		t.Errorf("stopped: %q", steps)
	}
	mcpserver.CaptureAddCmd = ""
	steps = nextSteps(exitnode.Status{Mode: "lan"}, stats, capture.HostRules{}, capture.CA{}, nil)
	if !slices.ContainsFunc(steps, func(s string) bool { return strings.Contains(s, "restart with --allow-hosts") }) {
		t.Errorf("LAN mode: %q", steps)
	}
}

// TestCaptureE2E (REQCOVE_E2E=1, real mitmproxy): reqcove capture over
// ctl.sock against a real capture. Started with nothing recorded, the step
// names capture add; after add, a new connection is recorded; after remove,
// one is not; each change leaves its log line, a cli marker and status's trace.
func TestCaptureE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "rcvc-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	state := filepath.Join(dir, "s")
	c, err := capture.Start(ctx, capture.Config{Dir: state, Confdir: filepath.Join(dir, "m"),
		Uvx: "uvx", Python: defaultPython, MitmSpec: defaultMitmSpec,
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
		Log: os.Stderr, ReadyTimeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	logged := logTo(t)
	mcpserver.CaptureAddCmd = withState("reqcove capture add", state)
	defer func() { mcpserver.CaptureAddCmd = "" }()
	if err := serveCtl(ctx, state, c, &runOpts{}); err != nil {
		t.Fatal(err)
	}
	node := exitnode.Status{Backend: "Running"}
	nothing := "nothing is recorded: add your app's hosts, in your terminal: " + withState("reqcove capture add", state) + " api.example.com"
	if steps := liveStatus(node, c).NextSteps; !slices.Contains(steps, nothing) {
		t.Errorf("at the start: %q", steps)
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	socks, _ := proxy.SOCKS5("tcp", c.SocksAddr, &proxy.Auth{User: "dev", Password: c.SocksSecret}, proxy.Direct)
	hc := &http.Client{Transport: &http.Transport{DialContext: socks.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}, Timeout: 30 * time.Second}
	get := func(path string) {
		t.Helper()
		r, err := hc.Get(origin.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	stat := func(k string) string { return fmt.Sprint(c.Store.Stats()[k]) }
	waitStat := func(k, want string) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); stat(k) != want; time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: %s, want %s", k, stat(k), want)
			}
		}
	}
	change := func(req ctlRequest) string {
		t.Helper()
		var out strings.Builder
		if err := sendCapture(ctx, &out, state, req); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	// paths are the flows' paths, oldest first: a request that was to be
	// recorded, sent before one that is, would be there first.
	paths := func() []string {
		var out []string
		flows, _ := c.Store.List(capture.Filter{Limit: 10})
		for _, f := range flows {
			out = append([]string{strings.TrimPrefix(f.URL, origin.URL)}, out...)
		}
		return out
	}
	get("/before")
	if out := change(ctlRequest{Cmd: "add", Hosts: []string{"127.0.0.1"}}); !strings.HasPrefix(out, "applied: 127.0.0.1 added; 0 records kept; not saved") || !strings.Contains(out, "new connections only: reopen the app") {
		t.Errorf("add: %q", out)
	}
	get("/added")
	waitStat("flows", "1")
	if got := paths(); !slices.Equal(got, []string{"/added"}) {
		t.Errorf("after add: %q", got)
	}
	s := liveStatus(node, c)
	if slices.Contains(s.NextSteps, nothing) || !slices.Equal(s.AllowHosts, []string{"127.0.0.1"}) || s.ScopeChange != "capture add 127.0.0.1" || s.ScopeChangedAt == "" || s.ScopePending != "" {
		t.Errorf("after add: steps %q, allow %q, change %q at %q, pending %q", s.NextSteps, s.AllowHosts, s.ScopeChange, s.ScopeChangedAt, s.ScopePending)
	}
	waitLog(t, logged, "capture add 127.0.0.1 (reqcove capture, from a terminal): applied: 127.0.0.1 added", 1)

	if out := change(ctlRequest{Cmd: "remove", Hosts: []string{"127.0.0.1"}}); !strings.HasPrefix(out, "applied: 127.0.0.1 removed; 1 records kept") || !strings.Contains(out, "open connections stay decrypted") {
		t.Errorf("remove: %q", out)
	}
	get("/removed")
	if s := liveStatus(node, c); s.ScopeChange != "capture remove 127.0.0.1" || !slices.Contains(s.NextSteps, nothing) {
		t.Errorf("after remove: change %q, steps %q", s.ScopeChange, s.NextSteps)
	}
	if out := change(ctlRequest{Cmd: "remove", Hosts: []string{"127.0.0.1"}}); out != "nothing changed; 127.0.0.1 was not recorded\n" {
		t.Errorf("remove again: %q", out)
	}
	change(ctlRequest{Cmd: "add", Hosts: []string{"127.0.0.1"}})
	get("/again")
	waitStat("flows", "2")
	if got := paths(); !slices.Equal(got, []string{"/added", "/again"}) {
		t.Errorf("after remove, then add again: %q", got)
	}
	var marks []string
	for _, m := range c.Store.Markers(0) {
		marks = append(marks, m.Source+": "+m.Text)
	}
	if !slices.Equal(marks, []string{"cli: capture add 127.0.0.1", "cli: capture remove 127.0.0.1", "cli: capture add 127.0.0.1"}) { // none for the change that changed nothing
		t.Errorf("markers: %q", marks)
	}
}

// TestCaptureStopE2E (REQCOVE_E2E=1, real mitmproxy): reqcove capture stop
// and start over ctl.sock. The stop's answer warns that the rules stop too
// and counts the records kept; status says recording stopped, allow_hosts []
// and the base, next_steps the start; a request is not recorded; an add while
// stopped changes the base only; the start says what it records, and records.
// Each change leaves its log line, a cli marker and status's trace.
func TestCaptureStopE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "rcvc-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	state := filepath.Join(dir, "s")
	allow, _ := capture.ParseAllowHosts([]string{"127.0.0.1"})
	c, err := capture.Start(ctx, capture.Config{Dir: state, Confdir: filepath.Join(dir, "m"),
		Uvx: "uvx", Python: defaultPython, MitmSpec: defaultMitmSpec,
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
		Log: os.Stderr, ReadyTimeout: 2 * time.Minute, AllowHosts: allow})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	logged := logTo(t)
	mcpserver.CaptureAddCmd = withState("reqcove capture add", state)
	mcpserver.CaptureStartCmd = withState("reqcove capture start", state)
	defer func() { mcpserver.CaptureAddCmd, mcpserver.CaptureStartCmd = "", "reqcove capture start" }()
	if err := serveCtl(ctx, state, c, &runOpts{}); err != nil {
		t.Fatal(err)
	}
	node := exitnode.Status{Backend: "Running"}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	socks, _ := proxy.SOCKS5("tcp", c.SocksAddr, &proxy.Auth{User: "dev", Password: c.SocksSecret}, proxy.Direct)
	hc := &http.Client{Transport: &http.Transport{DialContext: socks.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}, Timeout: 30 * time.Second}
	get := func(path string) {
		t.Helper()
		r, err := hc.Get(origin.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	paths := func() []string {
		var out []string
		flows, _ := c.Store.List(capture.Filter{Limit: 10})
		for _, f := range flows {
			out = append([]string{strings.TrimPrefix(f.URL, origin.URL)}, out...)
		}
		return out
	}
	waitPaths := func(want ...string) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !slices.Equal(paths(), want); time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("flows %q, want %q", paths(), want)
			}
		}
	}
	change := func(req ctlRequest) string {
		t.Helper()
		var out strings.Builder
		if err := sendCapture(ctx, &out, state, req); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	get("/before")
	waitPaths("/before")
	out := change(ctlRequest{Cmd: "stop"})
	for _, want := range []string{"applied: recording stopped; 1 records kept (still readable); WARNING: ", "mock, map_local, map_remote", "the app's requests go to the real servers", "not saved", "`reqcove capture start` records again"} {
		if !strings.Contains(out, want) {
			t.Errorf("stop: %q, want %q in it", out, want)
		}
	}
	waitLog(t, logged, "capture stop (reqcove capture, from a terminal): applied: recording stopped", 1)
	s := liveStatus(node, c)
	b, _ := json.Marshal(s)
	for _, want := range []string{`"allow_hosts":[]`, `"recording":"stopped"`, `"base_allow_hosts":["127.0.0.1"]`, `"scope_change":"capture stop"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("status while stopped: %s, want %s in it", b, want)
		}
	}
	start := "to record again, in your terminal: " + withState("reqcove capture start", state)
	if !slices.ContainsFunc(s.NextSteps, func(st string) bool { return strings.HasSuffix(st, start) }) || c.Store.Stats()["recording"] != "stopped" {
		t.Errorf("while stopped: steps %q, capture_stats recording %v", s.NextSteps, c.Store.Stats()["recording"])
	}
	get("/stopped")
	if out := change(ctlRequest{Cmd: "stop"}); !strings.HasPrefix(out, "nothing changed: recording is stopped already") {
		t.Errorf("stop again: %q", out)
	}
	if out := change(ctlRequest{Cmd: "add", Hosts: []string{"localhost"}}); !strings.HasPrefix(out, "applied: localhost added") || !strings.Contains(out, "recording is stopped: these are the hosts `reqcove capture start` records") || strings.Contains(out, "new connections only") {
		t.Errorf("add while stopped: %q", out)
	}
	if s := liveStatus(node, c); len(s.AllowHosts) != 0 || !slices.Equal(s.BaseAllowHosts, []string{"127.0.0.1", "localhost"}) {
		t.Errorf("add while stopped: allow %q, base %q", s.AllowHosts, s.BaseAllowHosts)
	}
	if out := change(ctlRequest{Cmd: "start"}); !strings.HasPrefix(out, "applied: recording started again: recording 127.0.0.1, localhost; 1 records kept") || !strings.Contains(out, "new connections only") {
		t.Errorf("start: %q", out)
	}
	if s := liveStatus(node, c); s.Recording != "on" || !slices.Equal(s.AllowHosts, []string{"127.0.0.1", "localhost"}) || s.ScopeChange != "capture start" {
		t.Errorf("started: recording %q, allow %q, change %q", s.Recording, s.AllowHosts, s.ScopeChange)
	}
	if out := change(ctlRequest{Cmd: "start"}); out != "nothing changed: recording is not stopped\n" {
		t.Errorf("start again: %q", out)
	}
	get("/started")
	waitPaths("/before", "/started")
	var marks []string
	for _, m := range c.Store.Markers(0) {
		marks = append(marks, m.Source+": "+m.Text)
	}
	if !slices.Equal(marks, []string{"cli: capture stop", "cli: capture add localhost", "cli: capture start"}) {
		t.Errorf("markers: %q", marks)
	}
}

// TestCaptureAllowAllE2E (REQCOVE_E2E=1, real mitmproxy): reqcove capture
// allow-all over ctl.sock. Its answer warns as --allow-hosts '*' does; status says
// allow-all, allow_hosts ["*"], the base, its end and time left, next_steps
// the --end; a host outside the base (localhost) is recorded; --end says how
// many of its records stay; status then counts them in records_outside_scope;
// a new request to it is not recorded. Each change leaves its trace.
func TestCaptureAllowAllE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "rcvc-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	state := filepath.Join(dir, "s")
	allow, _ := capture.ParseAllowHosts([]string{"127.0.0.1"})
	c, err := capture.Start(ctx, capture.Config{Dir: state, Confdir: filepath.Join(dir, "m"),
		Uvx: "uvx", Python: defaultPython, MitmSpec: defaultMitmSpec,
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
		Log: os.Stderr, ReadyTimeout: 2 * time.Minute, AllowHosts: allow})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	logged := logTo(t)
	captureEndCmd = withState("reqcove capture allow-all --end", state)
	allowAllNotes = []string{"--mcp-http: agents on your other devices (Grok Bot in xAI's cloud) read these records too"}
	defer func() { captureEndCmd, allowAllNotes = "reqcove capture allow-all --end", nil }()
	if err := serveCtl(ctx, state, c, &runOpts{}); err != nil {
		t.Fatal(err)
	}
	node := exitnode.Status{Backend: "Running"}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	socks, _ := proxy.SOCKS5("tcp", c.SocksAddr, &proxy.Auth{User: "dev", Password: c.SocksSecret}, proxy.Direct)
	hc := &http.Client{Transport: &http.Transport{DialContext: socks.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}, Timeout: 30 * time.Second}
	get := func(host, path string) {
		t.Helper()
		r, err := hc.Get("http://" + host + ":" + port + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	paths := func() []string {
		var out []string
		flows, _ := c.Store.List(capture.Filter{Limit: 10})
		for _, f := range flows {
			out = append([]string{strings.Replace(strings.TrimPrefix(f.URL, "http://"), ":"+port, "", 1)}, out...)
		}
		return out
	}
	waitPaths := func(want ...string) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !slices.Equal(paths(), want); time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("flows %q, want %q", paths(), want)
			}
		}
	}
	change := func(req ctlRequest) string {
		t.Helper()
		var out strings.Builder
		if err := sendCapture(ctx, &out, state, req); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	get("127.0.0.1", "/before")
	waitPaths("127.0.0.1/before")
	out := change(ctlRequest{Cmd: "allow-all", For: "30m"})
	for _, want := range []string{"applied: allow-all on: every host is recorded until ", "(in 30m0s)", "WARNING: every app's and site's traffic", "agents, and their model providers, can read it", "banks", "the records stay after it ends", "`reqcove capture allow-all --end` ends it sooner", "--mcp-http: agents on your other devices"} {
		if !strings.Contains(out, want) {
			t.Errorf("allow-all: %q, want %q in it", out, want)
		}
	}
	waitLog(t, logged, "capture allow-all --for 30m (reqcove capture, from a terminal): applied: allow-all on", 1)
	s := liveStatus(node, c)
	b, _ := json.Marshal(s)
	for _, want := range []string{`"allow_hosts":["*"]`, `"recording":"allow-all"`, `"base_allow_hosts":["127.0.0.1"]`, `"allow_all_until":"`, `"allow_all_left":"`, `"scope_change":"capture allow-all --for 30m"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("status during allow-all: %s, want %s in it", b, want)
		}
	}
	if !strings.HasSuffix(s.NextSteps[0], "to end it now, in your terminal: "+withState("reqcove capture allow-all --end", state)) || !strings.HasPrefix(s.NextSteps[0], "allow-all is on: every app's traffic is recorded") || c.Store.Stats()["recording"] != "allow-all" {
		t.Errorf("during allow-all: steps %q, capture_stats recording %v", s.NextSteps, c.Store.Stats()["recording"])
	}
	get("localhost", "/during")
	waitPaths("127.0.0.1/before", "localhost/during")
	if out := change(ctlRequest{Cmd: "allow-all", For: "1h"}); !strings.HasPrefix(out, "applied: allow-all was on until ") || !strings.Contains(out, "(in 1h0m0s)") {
		t.Errorf("allow-all again: %q", out)
	}
	if out := change(ctlRequest{Cmd: "add", Hosts: []string{"127.0.0.2"}}); !strings.Contains(out, "allow-all is on: every host is recorded until ") || strings.Contains(out, "new connections only") {
		t.Errorf("add during allow-all: %q", out)
	}

	out = change(ctlRequest{Cmd: "allow-all", End: true})
	if !strings.HasPrefix(out, "applied: allow-all ended: recording 127.0.0.1, 127.0.0.2; 2 records kept, 1 of them of hosts not recorded now") || !strings.Contains(out, "stay decrypted (unrecorded)") {
		t.Errorf("end: %q", out)
	}
	s = liveStatus(node, c)
	if s.Recording != "on" || !slices.Equal(s.AllowHosts, []string{"127.0.0.1", "127.0.0.2"}) || s.AllowAllUntil != "" || s.RecordsOutsideScope != 1 || s.ScopeChange != "capture allow-all --end" || slices.ContainsFunc(s.NextSteps, func(st string) bool { return strings.HasPrefix(st, "allow-all") }) {
		t.Errorf("ended: recording %q, allow %q, until %q, outside %d, change %q, steps %q", s.Recording, s.AllowHosts, s.AllowAllUntil, s.RecordsOutsideScope, s.ScopeChange, s.NextSteps)
	}
	get("localhost", "/after")
	get("127.0.0.1", "/again")
	waitPaths("127.0.0.1/before", "localhost/during", "127.0.0.1/again")
	if out := change(ctlRequest{Cmd: "allow-all", End: true}); out != "nothing changed: allow-all is not on\n" {
		t.Errorf("end again: %q", out)
	}
	var marks []string
	for _, m := range c.Store.Markers(0) {
		marks = append(marks, m.Source+": "+m.Text)
	}
	if !slices.Equal(marks, []string{"cli: capture allow-all --for 30m", "cli: capture allow-all --for 1h", "cli: capture add 127.0.0.2", "cli: capture allow-all --end"}) {
		t.Errorf("markers: %q", marks)
	}
}
