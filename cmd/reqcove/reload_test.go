package main

import (
	"context"
	"errors"
	"flag"
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
	"golang.org/x/net/proxy"
)

// reload's parse of run's arguments changes nothing and never exits: a
// hosts file broken since the start is its error (run's own parse would
// exit), one emptied gives no hosts, nothing is logged, and an upstream proxy
// that went away is not dialled (it takes a restart anyway).
func TestReloadFlags(t *testing.T) {
	dir := t.TempDir()
	hostsFile, config := saveFiles(t, dir, "a.example.com\n", "--device x\n--mask-values=k=[a-z]{8,}\n")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	up := "http://" + ln.Addr().String()
	cmdHosts := filepath.Join(dir, "more-hosts")
	os.WriteFile(cmdHosts, []byte("c.example.com\n"), 0o644)
	args := []string{"--config", config, "--state", dir, "--allow-hosts", "@" + cmdHosts, "--upstream-proxy", up}
	o, err := parseRunFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(o.args, args) || !slices.Equal(o.maskValues, []string{"k=[a-z]{8,}"}) {
		t.Errorf("args %q, mask values %q", o.args, o.maskValues)
	}
	ln.Close()
	logged := logTo(t)
	n, err := reloadFlags(o.args)
	if err != nil || len(restartOnly(o, n)) > 0 {
		t.Fatalf("again: %v, %v", err, restartOnly(o, n))
	}
	os.WriteFile(cmdHosts, []byte("not a host!\n"), 0o644)
	for _, args := range [][]string{o.args, {"--device", "x", "--state", dir, "--allow-hosts", "@" + cmdHosts}} { // with a config, and without
		if _, err := reloadFlags(args); err == nil || !strings.Contains(err.Error(), "line 1 is not a host list") {
			t.Errorf("a broken hosts file: %v", err)
		}
	}
	os.WriteFile(cmdHosts, []byte("# none\n"), 0o644)
	if n, err := reloadFlags(o.args); err != nil || !slices.Equal(n.allow.Hosts, []string{"a.example.com"}) {
		t.Errorf("an emptied hosts file: %v, %v", n, err)
	}
	os.WriteFile(cmdHosts, []byte("c.example.com\n"), 0o644)
	os.WriteFile(config, []byte("--allow-hosts=@"+hostsFile+"\n--nope\n"), 0o600)
	if _, err := reloadFlags(o.args); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("a bad flag: %v", err)
	}
	if s := logged.String(); s != "" {
		t.Errorf("logged:\n%s", s)
	}
	os.WriteFile(hostsFile, []byte("b.example.com\n"), 0o644)
	os.WriteFile(config, []byte("--allow-hosts=@"+hostsFile+"\n--device y\n--mcp-http\n--mask-values=other\n"), 0o600)
	n, err = reloadFlags(o.args)
	if err != nil || !slices.Equal(n.allow.Hosts, []string{"b.example.com", "c.example.com"}) {
		t.Fatalf("%v %v", err, n)
	}
	if got := restartOnly(o, n); !slices.Equal(got, []string{"--device", "--mask-values", "--mcp-http"}) {
		t.Errorf("restart only: %q", got)
	}
}

// Every flag of run is reload's (the hosts), one that cannot change, or
// named as taking a restart.
func TestReloadSettings(t *testing.T) {
	var run *flag.FlagSet
	takeFlags = func(fs *flag.FlagSet) { run = fs }
	defer func() { takeFlags = nil }()
	parseRunFlags(nil)
	run.VisitAll(func(f *flag.Flag) {
		if slices.Contains([]string{"allow-hosts", "pass-hosts", "config", "lan"}, f.Name) {
			return
		}
		if !slices.ContainsFunc(restartSettings, func(s struct {
			name string
			of   func(*runOpts) string
		}) bool {
			return s.name == f.Name
		}) {
			t.Errorf("--%s: neither reloaded nor named as taking a restart", f.Name)
		}
	})
}

// A run started from flags alone has nothing to reload; in LAN mode reload
// is refused, as the other changes.
func TestReloadNothing(t *testing.T) {
	a := answerCtl(context.Background(), nil, newCtlState(&runOpts{args: []string{"--device", "x", "--allow-hosts", "a.com"}}), ctlRequest{Cmd: "reload"})
	if a.OK || !strings.HasPrefix(a.Message, "nothing to reload: this run was started from flags alone") || !strings.HasSuffix(a.Message, "nothing changed") {
		t.Errorf("%+v", a)
	}
	a = answerCtl(context.Background(), nil, newCtlState(&runOpts{lanMode: true, config: "/c"}), ctlRequest{Cmd: "reload"})
	if a.OK || !strings.Contains(a.Message, "LAN mode") {
		t.Errorf("LAN: %+v", a)
	}
	if got := undone(capture.HostRules{Hosts: []string{"a.com", "b.com"}}, capture.HostRules{Hosts: []string{"a.com", "c.com"}, PassHosts: []string{"a.com"}}, capture.HostRules{Hosts: []string{"a.com", "b.com", "d.com"}}); got != "c.com no longer recorded (added), b.com recorded again (removed), a.com no longer passed undecrypted (added)" {
		t.Errorf("undone: %q", got)
	}
}

// The command line's hosts file edited to "*" (a --config's is refused
// there) is refused by reload, as capture set refuses it (allow-all is the
// way, for a while); while mitmproxy restarts, a change is refused (it
// cannot be checked against the rules), saying to try again.
func TestReloadRefusesEverything(t *testing.T) {
	dir := t.TempDir()
	hostsFile := filepath.Join(dir, "hosts")
	os.WriteFile(hostsFile, []byte("a.example.com\n"), 0o644)
	o, err := parseRunFlags([]string{"--device", "x", "--state", filepath.Join(dir, "s"), "--allow-hosts", "@" + hostsFile})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(hostsFile, []byte("*\n"), 0o644)
	a := answerCtl(context.Background(), &capture.Capture{}, newCtlState(o), ctlRequest{Cmd: "reload"})
	if a.OK || !strings.HasPrefix(a.Message, `refused: the files give "*"`) || !strings.Contains(a.Message, "reqcove capture allow-all --for D") || !strings.HasSuffix(a.Message, "nothing changed") {
		t.Errorf("%+v", a)
	}
	os.WriteFile(hostsFile, []byte("b.example.com\n"), 0o644)
	a = answerCtl(context.Background(), &capture.Capture{}, newCtlState(o), ctlRequest{Cmd: "reload"}) // no mitmproxy to ask
	if a.OK || a.Message != "mitmproxy is restarting: try again in a moment; nothing changed" {
		t.Errorf("restarting: %+v", a)
	}
	a = answerCtl(context.Background(), &capture.Capture{}, newCtlState(o), ctlRequest{Cmd: "add", Hosts: []string{"c.example.com"}})
	if a.OK || a.Message != "mitmproxy is restarting: try again in a moment; nothing changed" {
		t.Errorf("add while restarting: %+v", a)
	}
}

// TestReloadE2E (REQCOVE_E2E=1, real mitmproxy): reqcove reload over
// ctl.sock. A host and a mock for it, added to the files together, apply
// together (the new rules are checked against the new hosts); a broken rules
// file changes nothing, its hosts file's edit included; the host and its
// mock taken out together apply; an unsaved capture add is said to be
// replaced; a preset on is off after; another setting changed is named.
func TestReloadE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "rcvr-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "server") }))
	defer origin.Close()
	hostsFile, config := saveFiles(t, dir, "localhost\n", "")
	rules := filepath.Join(dir, "rules.yaml")
	preset := fmt.Sprintf("mock:\n  - match: {url: \"http://localhost:%s/p\"}\n    body: preset\n    preset: p\n", origin.URL[strings.LastIndex(origin.URL, ":")+1:])
	os.WriteFile(rules, []byte(preset), 0o600)
	state := filepath.Join(dir, "s")
	o, err := parseRunFlags([]string{"--config", config, "--device", "x", "--state", state, "--rules", rules})
	if err != nil {
		t.Fatal(err)
	}
	c, err := capture.Start(ctx, capture.Config{Dir: state, Confdir: filepath.Join(dir, "m"),
		Uvx: "uvx", Python: defaultPython, MitmSpec: defaultMitmSpec,
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
		Log: os.Stderr, ReadyTimeout: 2 * time.Minute, AllowHosts: o.allow, Rules: o.rules})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	logged := logTo(t)
	if _, err := serveCtl(ctx, state, c, o, nil, nil); err != nil {
		t.Fatal(err)
	}
	socks, _ := proxy.SOCKS5("tcp", c.SocksAddr, &proxy.Auth{User: "dev", Password: c.SocksSecret}, proxy.Direct)
	hc := &http.Client{Transport: &http.Transport{DialContext: socks.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}, Timeout: 30 * time.Second}
	get := func(path string) string {
		t.Helper()
		r, err := hc.Get(origin.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return string(b)
	}
	reload := func() (string, error) {
		var out strings.Builder
		err := sendCapture(ctx, &out, state, ctlRequest{Cmd: "reload"})
		return out.String(), err
	}
	mock := fmt.Sprintf("  - match: {url: \"%s/mocked\"}\n    body: mocked\n", origin.URL)
	if out, err := reload(); err != nil || !strings.HasPrefix(out, "applied: the hosts as they were; rules from "+rules+": mock 1; presets are off") {
		t.Errorf("as started: %q %v", out, err)
	}
	if _, err := c.Activate(ctx, "p", 60, 0); err != nil {
		t.Fatal(err)
	}

	// The host and its mock, together.
	os.WriteFile(hostsFile, []byte("localhost\n127.0.0.1\n"), 0o644)
	os.WriteFile(rules, []byte(preset+mock), 0o600)
	out, err := reload()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"applied: 127.0.0.1 added", "rules from " + rules + ": mock 2", "presets are off", "new connections only"} {
		if !strings.Contains(out, want) {
			t.Errorf("reload: %q, want %q in it", out, want)
		}
	}
	if got := get("/mocked"); got != "mocked" {
		t.Errorf("the mock reloaded: %q", got)
	}
	if ps, _ := c.Presets(ctx); len(ps) != 1 || ps[0].Active {
		t.Errorf("presets after: %+v", ps)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "rules-loaded")); string(b) != preset+mock {
		t.Errorf("the private copy:\n%s", b)
	}
	waitLog(t, logged, "reload (reqcove reload, from a terminal): applied: 127.0.0.1 added", 1)

	// A broken rules file: nothing changes, the hosts file's edit neither.
	os.WriteFile(hostsFile, []byte("localhost\n"), 0o644)
	os.WriteFile(rules, []byte("mock: [{match: {url: \"http://127.0.0.1/x\"}, status: 700}]\n"), 0o600)
	if _, err := reload(); err == nil || !strings.Contains(err.Error(), "the --rules file does not load: mock[0]: status must be a number") || !strings.Contains(err.Error(), "nothing changed") {
		t.Errorf("broken rules: %v", err)
	}
	if b := c.Base(); !slices.Equal(b.Hosts, []string{"localhost", "127.0.0.1"}) {
		t.Errorf("hosts after a refusal: %q", b.Hosts)
	}
	if got := get("/mocked"); got != "mocked" {
		t.Errorf("rules after a refusal: %q", got)
	}

	// The host and its mock out together; an unsaved add replaced; another setting named.
	var add strings.Builder
	if err := sendCapture(ctx, &add, state, ctlRequest{Cmd: "add", Hosts: []string{"extra.example.com"}}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(rules, []byte(preset), 0o600)
	os.WriteFile(config, []byte("--allow-hosts=@"+hostsFile+"\n--mcp-http\n"), 0o600)
	out, err = reload()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"applied: 127.0.0.1, extra.example.com removed", "this replaces what reqcove capture changed and did not save: extra.example.com no longer recorded (added)", "rules from " + rules + ": mock 1", "\nother settings take effect at the next start of run: --mcp-http"} {
		if !strings.Contains(out, want) {
			t.Errorf("reload: %q, want %q in it", out, want)
		}
	}
	if b := c.Base(); !slices.Equal(b.Hosts, []string{"localhost"}) {
		t.Errorf("hosts: %q", b.Hosts)
	}
	if got := get("/mocked"); got != "server" {
		t.Errorf("after the mock is gone: %q", got)
	}
	if s := liveStatus(exitnode.Status{Backend: "Running"}, c); s.ScopeChange != "reload" {
		t.Errorf("status: %q", s.ScopeChange)
	}
}

// reload's parse (and the writer's check) runs no tailscale to name the
// devices a missing --device could be.
func TestReloadFlagsRunsNothing(t *testing.T) {
	called := false
	was := tailscaleStatus
	tailscaleStatus = func() ([]byte, error) { called = true; return nil, errors.New("none") }
	t.Cleanup(func() { tailscaleStatus = was })
	if _, err := reloadFlags([]string{"--state", t.TempDir()}); err == nil || !strings.Contains(err.Error(), "--device is required") || called {
		t.Errorf("%v, tailscale run: %v", err, called)
	}
}
