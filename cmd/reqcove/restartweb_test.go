package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

// restart --web: the answer says what mitmweb means and that it is for one
// start; run is asked with web; the exec carries envWeb, the binary's check
// sees --web (a bare run's config in place, then --web), and nothing is
// written to the config or the snapshot.
func TestRestartWebOnce(t *testing.T) {
	state := t.TempDir()
	start := "--device phone\n--state=" + state + "\n"
	st, config, _, _ := restartable(t, start)
	var snap string
	var web bool
	st.restart = func(s string, w bool) { snap, web = s, w }
	args := filepath.Join(t.TempDir(), "args")
	startBinary = filepath.Join(t.TempDir(), "reqcove")
	os.WriteFile(startBinary, []byte("#!/bin/sh\necho \"$@\" > "+args+"\n"), 0o755)
	startArgs = nil // a bare run: its config in o.args alone
	a := restartOp(t.Context(), st, 0, true)
	if !a.OK || !strings.Contains(a.Message, "+ --web (this start only; unmasked)") || !strings.Contains(a.Message, "earlier links stop working") || !strings.Contains(a.Message, "the next restart of any kind") {
		t.Fatalf("restart --web: %q", a.Message)
	}
	if got := strings.TrimSpace(read(t, args)); got != "run --check-config --config "+config+" --web" {
		t.Errorf("the binary checked %q", got)
	}
	a.after()
	if !web || read(t, config) != start || read(t, snap) != start {
		t.Errorf("asked web %v; config %q; snapshot %q", web, read(t, config), read(t, snap))
	}
	env := stubExec(t)
	execRestart(&restartExec{snapshot: snap, web: true})
	if !slices.Contains(*env, envWeb+"=1") {
		t.Errorf("exec'd without %s: %q", envWeb, *env)
	}
	// Asked without: none, even with envWeb in this process's environment.
	t.Setenv(envWeb, "1")
	execRestart(&restartExec{snapshot: snap})
	if slices.ContainsFunc(*env, func(kv string) bool { return strings.HasPrefix(kv, envWeb+"=") }) {
		t.Errorf("a restart without --web carried it: %q", *env)
	}
}

// The new start takes envWeb only with a restart's handover, and unsets it;
// a failed start's retry, and a later restart without --web, start without
// mitmweb.
func TestRestartWebNotCarried(t *testing.T) {
	logged := logTo(t)
	t.Setenv(envWeb, "1")
	if h := takeHandover(); h.web || os.Getenv(envWeb) != "" || !strings.Contains(logged.String(), "mitmweb stays off") {
		t.Errorf("a fresh start took %s: %+v", envWeb, h)
	}

	state := t.TempDir()
	_, _, args, restart := restartable(t, "--device phone\n--state="+state+"\n")
	snap := restart()
	t.Setenv(envWeb, "1")
	h := newProcess(t, snap, false)
	if !h.web || os.Getenv(envWeb) != "" {
		t.Fatalf("after restart --web: web %v, %s=%q", h.web, envWeb, os.Getenv(envWeb))
	}
	env := stubExec(t)
	h.failed(args, errors.New("boom"))
	if !slices.Contains(*env, envRetry+"=1") || slices.ContainsFunc(*env, func(kv string) bool { return strings.HasPrefix(kv, envWeb+"=") }) {
		t.Errorf("the retry: %q", *env)
	}
	if note := read(t, filepath.Join(state, restartNote)); !strings.Contains(note, "without mitmweb") {
		t.Errorf("note: %q", note)
	}

	// A start with mitmweb for this start, restarted plainly: it goes off.
	st, _, _, _ := restartable(t, "--device phone\n--state="+state+"\n")
	if err := webThisStart(st.o); err != nil || !st.o.web || !st.o.webOnce || slices.Contains(st.o.args, "--web") {
		t.Fatalf("webThisStart: %v %+v", err, st.o)
	}
	var web bool
	st.restart = func(_ string, w bool) { web = w }
	a := restartOp(t.Context(), st, 0, false)
	if !a.OK || !strings.Contains(a.Message, "mitmweb goes off") {
		t.Fatalf("plain restart: %q", a.Message)
	}
	a.after()
	if web {
		t.Error("a plain restart asked web")
	}
}

// --web on run's command line: kept as today; restart --web changes nothing
// (no envWeb, so no new password). The checks with --web come before
// anything stops: --proxy-port 8081 is refused, LAN mode is not.
func TestRestartWebChecks(t *testing.T) {
	state := t.TempDir()
	config, args := confFile(t, "--device phone\n--state="+state+"\n")
	o, err := parseRunFlags(append(slices.Clone(args), "--web"))
	if err != nil {
		t.Fatal(err)
	}
	st := newCtlState(o)
	var web bool
	st.restart = func(_ string, w bool) { web = w }
	startBinary, startBinaryErr, startArgs = os.Args[0], nil, o.args
	t.Cleanup(func() { startBinary, startArgs = "", nil })
	a := restartOp(t.Context(), st, 0, true)
	if !a.OK || !strings.Contains(a.Message, "mitmweb stays on (--web on run's command line)") || strings.Contains(a.Message, "+ --web") {
		t.Fatalf("on the command line: %q", a.Message)
	}
	a.after()
	if web {
		t.Error("asked web with --web on the command line")
	}

	snaps, _ := filepath.Glob(filepath.Join(state, "restart-*"))
	os.WriteFile(config, []byte("--device phone\n--state="+state+"\n--proxy-port=8081\n"), 0o600)
	st = newCtlState(&runOpts{args: args, config: config, state: state})
	st.restart = func(string, bool) { t.Error("restarted") }
	if a := restartOp(t.Context(), st, 0, true); a.OK || !strings.Contains(a.Message, "with --web") || !strings.Contains(a.Message, "port 8081") || !strings.HasSuffix(a.Message, "; nothing stopped") {
		t.Errorf("--proxy-port 8081: %q", a.Message)
	}
	if m, _ := filepath.Glob(filepath.Join(state, "restart-*")); len(m) != len(snaps) {
		t.Errorf("a snapshot written: %v", m)
	}
	if err := webThisStart(&runOpts{proxyPort: 8081}); err == nil {
		t.Error("the new start took --proxy-port 8081")
	}
	if o := (&runOpts{proxyPort: 8081, lanMode: true}); webThisStart(o) != nil || !o.webOnce {
		t.Errorf("LAN mode: %+v", o)
	}
	if o := (&runOpts{web: true}); webThisStart(o) != nil || o.webOnce {
		t.Errorf("on the command line: %+v", o)
	}
	if _, err := (ctlRequest{Cmd: "reload", Web: true}).normalized(); err == nil {
		t.Error("web with reload")
	}
	if got := restartOnly(&runOpts{web: true, webOnce: true}, &runOpts{}); slices.Contains(got, "--web") {
		t.Errorf("reload: %v", got)
	}
}

// mitmweb turned on by a restart gets a new password: the links seen before
// stop working; otherwise web-token is kept across starts.
func TestWebOnceNewToken(t *testing.T) {
	state := t.TempDir()
	old, _, err := keptToken(state, "web-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, kept, _, _ := runTokens(&runOpts{state: state, web: true}); kept != old {
		t.Errorf("--web: %q, want %q kept", kept, old)
	}
	_, made, _, err := runTokens(&runOpts{state: state, web: true, webOnce: true})
	if err != nil || made == old || made == "" || read(t, filepath.Join(state, "web-token")) != made {
		t.Errorf("this start: %q (was %q) %v", made, old, err)
	}
}

// status, the MCP status and the pages say mitmweb is on, and whether for
// this start: a boolean, never its link or password.
func TestMitmwebIndicator(t *testing.T) {
	o := &runOpts{web: true, webOnce: true}
	out := withFiles(mcpserver.StatusOut{}, o)
	if !out.Mitmweb || !out.MitmwebThisStart {
		t.Errorf("status: %+v", out)
	}
	b, _ := json.Marshal(out)
	if !strings.Contains(string(b), `"mitmweb":true,"mitmweb_this_start_only":true`) {
		t.Errorf("json: %s", b)
	}
	if out := withFiles(mcpserver.StatusOut{}, &runOpts{}); out.Mitmweb || out.MitmwebThisStart {
		t.Errorf("off: %+v", out)
	}
	if mitmwebText(true) != "on — unmasked; this start only" || mitmwebText(false) != "on — unmasked; from the command line" {
		t.Error(mitmwebText(true), mitmwebText(false))
	}
}

// The local page: Restart with mitmweb lists it (+ --web) with its own
// words, and asks run with web; the tailnet page has no such route (403),
// directly and through the relay.
func TestPageRestartWeb(t *testing.T) {
	base, token, st, _, _ := settingsRun(t, "--device=phone")
	hdr := map[string]string{sessionHeader: token}
	_, b := call(t, base, "GET", "/api/restart?web=1", "", hdr)
	var r pageRestart
	json.Unmarshal([]byte(b), &r)
	if r.Message != "" || !slices.Contains(r.Lines, "+ --web (this start only; unmasked)") || !strings.Contains(r.Web, "bodies included (up to 256 MB kept in memory)") || !strings.Contains(r.Web, "runs code on this computer") || !strings.Contains(r.Web, "`reqcove links` (under a service)") {
		t.Fatalf("restart with mitmweb: %s", b)
	}
	if _, b := call(t, base, "GET", "/api/restart", "", hdr); strings.Contains(b, `"web"`) || strings.Contains(b, "--web") {
		t.Errorf("plain restart: %s", b)
	}
	web := make(chan bool, 1)
	st.restart = func(_ string, w bool) { web <- w }
	if _, b := call(t, base, "POST", "/api/restart", `{"rev":"`+r.Rev+`","web":true}`, hdr); !strings.Contains(b, `"ok":true`) || !strings.Contains(b, "+ --web") {
		t.Fatalf("restart: %s", b)
	}
	if !<-web {
		t.Error("run asked without web")
	}

	state, tst, _ := tailnetRun(t, &runOpts{web: true, webOnce: true})
	tst.restart = func(string, bool) { t.Error("the tailnet page restarted run") }
	tbase, code := openTailnetUI(t, state)
	ttok := trade(t, tbase, code)
	if _, b := call(t, tbase, "GET", "/api/state", "", map[string]string{sessionHeader: ttok}); !strings.Contains(b, `"mitmweb":"on — unmasked; this start only"`) || strings.Contains(b, "token") || strings.Contains(b, "8081") {
		t.Errorf("the tailnet page's state: %s", b)
	}
	if res, b := call(t, tbase, "POST", "/api/restart", `{"rev":"x","web":true}`, map[string]string{sessionHeader: ttok}); res.StatusCode != 403 || !strings.Contains(b, "no restart") {
		t.Errorf("the tailnet page: %d %s", res.StatusCode, b)
	}
	if res, _ := call(t, tbase, "GET", "/api/restart?web=1", "", map[string]string{sessionHeader: ttok}); res.StatusCode != 403 {
		t.Errorf("the tailnet page's diff: %d", res.StatusCode)
	}
}
