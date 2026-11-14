package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/proxy"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// syncBuf is a log destination tests read while run writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func logTo(t *testing.T) *syncBuf {
	t.Helper()
	b := &syncBuf{}
	w := log.Writer()
	log.SetOutput(io.MultiWriter(b, w))
	t.Cleanup(func() { log.SetOutput(w) })
	return b
}

func waitLog(t *testing.T, b *syncBuf, want string, n int) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); strings.Count(b.String(), want) < n; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%q not logged %d times:\n%s", want, n, b.String())
		}
	}
}

// TestRulesReloadPresetsE2E (REQCOVE_E2E=1, real mitmproxy): run's own rules
// log, with --rules-reload and a preset in the file. Saving the file froze the
// store for good (v0.7.0-v0.8.0): the log asked the store for the presets'
// targets while the store held its lock. Saved twice, flows are still
// recorded and the stats still answer.
func TestRulesReloadPresetsE2E(t *testing.T) {
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
	rules := filepath.Join(dir, "rules.yaml")
	write := func(n int) {
		t.Helper()
		b := fmt.Sprintf("map_remote:\n  - {rule: \"|~d api.example.com|https://api\\\\.example\\\\.com/|https://staging.example.com/\", preset: staging}\nmodify_headers:\n  - \"|~q|X-R|%d\"\n", n)
		if err := os.WriteFile(rules, []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(0)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, r.Header.Get("X-R")) }))
	defer origin.Close()
	allow, _ := capture.ParseAllowHosts([]string{"127.0.0.1"})
	c, err := capture.Start(ctx, capture.Config{Dir: filepath.Join(dir, "s"), Confdir: filepath.Join(dir, "m"),
		Uvx: "uvx", Python: defaultPython, MitmSpec: defaultMitmSpec, AllowHosts: allow, Rules: rules, RulesReload: true,
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
		Log: os.Stderr, ReadyTimeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	logged := logTo(t)
	logRules(&runOpts{rules: rules, rulesReload: true}, c, c.Store.Stats())
	socks, _ := proxy.SOCKS5("tcp", c.SocksAddr, &proxy.Auth{User: "dev", Password: c.SocksSecret}, proxy.Direct)
	hc := &http.Client{Transport: &http.Transport{DialContext: socks.(proxy.ContextDialer).DialContext}, Timeout: 30 * time.Second}
	for n := 1; n <= 2; n++ {
		write(n)
		waitLog(t, logged, "rules from "+rules+", again", n)
		waitLog(t, logged, "staging -> https://staging.example.com", n+1) // at start, and at each reload
		stats := make(chan map[string]any, 1)
		go func() { stats <- c.Store.Stats() }()
		select {
		case <-stats:
		case <-time.After(5 * time.Second):
			t.Fatalf("save %d: the store does not answer", n)
		}
		r, err := hc.Get(origin.URL + "/after")
		if err != nil {
			t.Fatalf("save %d: %v", n, err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if string(b) != fmt.Sprint(n) {
			t.Errorf("save %d: the origin got X-R %q", n, b)
		}
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if fmt.Sprint(c.Store.Stats()["flows"]) == "2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("flows recorded: %v", c.Store.Stats()["flows"])
		}
	}
}

// fakeMitmdump stands in for uv's mitmdump: its first run says hello and
// lives until killed; every later run exits at once, so the restarts fail.
const fakeMitmdump = `#!/usr/bin/env python3
import json, os, socket, sys, time
d = os.environ["FAKE_DIR"]
n = len(os.listdir(os.path.join(d, "runs"))) + 1
open(os.path.join(d, "runs", str(n)), "w").write(str(os.getpid()))
if n > 1:
    sys.exit(3)
path = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("reqcove_socket="))
s = socket.socket(socket.AF_UNIX); s.connect(path)
s.sendall((json.dumps({"v": 2, "ev": "hello", "mitmproxy": "fake"}) + "\n").encode())
time.sleep(600)
`

// When mitmproxy keeps failing and reqcove gives up on it, run returns an
// error (exits non-zero), not nil as for Ctrl-C: a service sees it failed.
func TestRunFailsWhenMitmproxyGivesUp(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "rcvf-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Mkdir(filepath.Join(dir, "runs"), 0o700)
	fake := filepath.Join(dir, "fakeuv") // not "uvx": that would run the uv beside it
	os.WriteFile(fake, []byte(fakeMitmdump), 0o700)
	t.Setenv("FAKE_DIR", dir)
	state := filepath.Join(dir, "s")
	if err := claimState(state); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(state, "mitmproxy"), 0o700)
	for _, f := range capture.CAFiles { // a CA there already: run does not ask the fake to make one
		os.WriteFile(filepath.Join(state, "mitmproxy", f), nil, 0o600)
	}
	restartDelay = time.Millisecond
	t.Cleanup(func() { restartDelay = 0 })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"--lan", "--lan-interface", loopback(t), "--proxy-port", fmt.Sprint(port),
			"--allow-hosts", "api.example.com", "--state", state, "--uvx", fake})
	}()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			c.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("run ended before it was up: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("run's LAN proxy never listened")
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "runs", "1"))
	pid, _ := strconv.Atoi(string(b))
	if pid == 0 {
		t.Fatalf("no pid for the first mitmdump: %q", b)
	}
	syscall.Kill(pid, syscall.SIGKILL)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "gave up after") {
			t.Errorf("run: %v, want mitmproxy's failure", err)
		}
	case <-ctx.Done():
		t.Fatal("run did not stop after mitmproxy gave up")
	}
}
