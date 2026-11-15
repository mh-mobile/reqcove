package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeMitmdump stands in for `uvx ... mitmdump`: it says hello (and leaves
// one flow open), then lives until killed. From run number dieFrom on, it
// exits at once instead. Each run writes runs/N: its pid and when it began.
// FAKE_RULES_ERROR: runs after the first say their rules do not load. FAKE_LATE: run 1 leaves a line that is read only
// after it died (a child outside its group writes it), as one still in the
// socket is.
const fakeMitmdump = `#!/usr/bin/env python3
import json, os, socket, sys, time
d = os.environ["FAKE_DIR"]
n = len(os.listdir(os.path.join(d, "runs"))) + 1
open(os.path.join(d, "runs", str(n)), "w").write("%d %f" % (os.getpid(), time.time()))
if n >= int(os.environ["FAKE_DIE_FROM"]):
    sys.exit(3)
if n < int(os.environ.get("FAKE_HELLO_FROM", "1")):
    time.sleep(600)
path = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("reqcove_socket="))
s = socket.socket(socket.AF_UNIX); s.connect(path)
hello = {"ev": "hello", "mitmproxy": "fake", "dropped_bodies": 2}
if n >= 2:
    hello["rules_error"] = os.environ.get("FAKE_RULES_ERROR", "")
late = os.environ.get("FAKE_LATE") and n == 1
for m in (hello,
          {"ev": "request", "id": "open%d" % n, "host": "h"}):
    m["v"] = 2
    if late:
        m["dropped_events"] = 1
    s.sendall((json.dumps(m) + "\n").encode())
parent = os.getpid()
if late and os.fork() == 0:
    os.setsid()
    while os.getppid() == parent:
        time.sleep(0.01)
    time.sleep(0.3)
    s.sendall((json.dumps({"v": 2, "ev": "request", "id": "late", "host": "h", "dropped_events": 1}) + "\n").encode())
    os._exit(0)
time.sleep(600)
`

func startFake(t *testing.T, dieFrom int, tweak ...func(*Config)) (*Capture, func(run int)) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rcvs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	os.Mkdir(filepath.Join(dir, "runs"), 0o700)
	fake := filepath.Join(dir, "uvx")
	os.WriteFile(fake, []byte(fakeMitmdump), 0o700)
	t.Setenv("FAKE_DIR", dir)
	t.Setenv("FAKE_DIE_FROM", strconv.Itoa(dieFrom))
	rules, _ := ParseAllowHosts([]string{"*"})
	cfg := Config{Dir: filepath.Join(dir, "s"), Uvx: fake, AllowHosts: rules,
		MaxFlows: 100, MaxBytes: 1 << 20, Log: os.Stderr, ReadyTimeout: 10 * time.Second,
		RestartDelay: 10 * time.Millisecond, Logf: t.Logf}
	for _, f := range tweak {
		f(&cfg)
	}
	c, err := Start(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	kill := func(run int) {
		b, err := os.ReadFile(filepath.Join(dir, "runs", strconv.Itoa(run)))
		pid, _ := strconv.Atoi(strings.Fields(string(b) + " ")[0])
		if err != nil || pid == 0 {
			t.Fatalf("run %d: no pid (%v)", run, err)
		}
		syscall.Kill(pid, syscall.SIGKILL)
	}
	return c, kill
}

func waitState(t *testing.T, c *Capture, state string, restarts int64) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		s := c.Store.Stats()
		if s["state"] == state && s["restarts"] == restarts {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("want state %s after %d restarts, got %v", state, restarts, s)
		}
	}
}

func TestRestartsMitmdump(t *testing.T) {
	c, kill := startFake(t, 1000)
	waitState(t, c, "ready", 0)
	if fi, err := os.Stat(filepath.Join(c.cfg.Dir, "ingest.sock")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("ingest socket mode %v, want 0600", fi.Mode().Perm())
	}
	kill(1)
	waitState(t, c, "ready", 1)
	if f, _ := c.Store.Get("open1", false); f.State != "error" || !strings.Contains(f.Error, "mitmdump exited") {
		t.Errorf("flow left open by the dead mitmdump: %+v", f.Flow)
	}
	if got := c.Store.Stats()["addon_dropped_bodies"]; got != int64(4) {
		t.Errorf("addon_dropped_bodies = %v, want 2 from each run", got)
	}
	select {
	case <-c.Done():
		t.Fatalf("gave up after one restart: %v", c.Err())
	default:
	}
	c.Stop()
	if c.Err() != nil {
		t.Errorf("Err after Stop = %v", c.Err())
	}
	for _, f := range []string{"socks-secret", "addon.py", "mitmdump.pid", "ingest.sock", rulesCopy} {
		if _, err := os.Stat(filepath.Join(c.cfg.Dir, f)); err == nil {
			t.Errorf("%s left in the state directory after Stop", f)
		}
	}
}

// TestLateLinesOfDeadMitmdump: the lines a dead mitmdump left in its socket
// are read before its flows are closed: a request among them is closed too,
// and the counters they carry are counted once.
func TestLateLinesOfDeadMitmdump(t *testing.T) {
	t.Setenv("FAKE_LATE", "1")
	c, kill := startFake(t, 1000)
	defer c.Stop()
	kill(1)
	waitState(t, c, "ready", 1)
	var f FlowView
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var err error
		if f, err = c.Store.Get("late", false); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the late line never landed")
		}
	}
	time.Sleep(100 * time.Millisecond) // a close that would come after it
	if f, _ = c.Store.Get("late", false); f.State != "error" || !strings.Contains(f.Error, "mitmdump exited") {
		t.Errorf("a request read after its mitmdump died: %+v", f.Flow)
	}
	if got := c.Store.Stats()["addon_dropped_events"]; got != int64(1) {
		t.Errorf("addon_dropped_events = %v, want the dead run's 1 once", got)
	}
}

// TestRetriesMitmdump: a mitmdump that keeps exiting is started again past
// the 5 attempts v1.0 gave up after, each wait longer than the one before,
// and the capture does not end; capture_stats says why, how many attempts
// and when the next is.
func TestRetriesMitmdump(t *testing.T) {
	c, kill := startFake(t, 2) // the first run works, every restart dies
	defer c.Stop()
	runs := filepath.Join(os.Getenv("FAKE_DIR"), "runs")
	kill(1)
	const want = 9 // 8 attempts after the first run
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if ents, _ := os.ReadDir(runs); len(ents) >= want {
			break
		}
		select {
		case <-c.Done():
			t.Fatalf("gave up: %v", c.Err())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %v", c.Store.Stats())
		}
	}
	var began []float64
	for n := 2; n <= want; n++ {
		b, _ := os.ReadFile(filepath.Join(runs, strconv.Itoa(n)))
		f := strings.Fields(string(b))
		at, err := strconv.ParseFloat(f[len(f)-1], 64)
		if err != nil {
			t.Fatalf("run %d: %q", n, b)
		}
		began = append(began, at)
	}
	// From run k to k+1 (k >= 2), the wait before the k-th retry, 10 ms
	// doubled k-1 times (up to 1280 ms): a start's own time only adds to it.
	for i := 0; i < len(began)-1; i++ {
		if gap, wait := began[i+1]-began[i], (10 * time.Millisecond << (i + 1)).Seconds(); gap < wait {
			t.Errorf("run %d to %d: %.3fs, want at least %.3fs", i+2, i+3, gap, wait)
		}
	}
	s := c.Store.Stats()
	if s["state"] != "restarting" || s["retries"].(int64) < want-2 || s["next_attempt"] == nil || !strings.Contains(s["last_failure"].(string), "exited") {
		t.Errorf("stats while retrying: state %v, retries %v, next_attempt %v, last_failure %v", s["state"], s["retries"], s["next_attempt"], s["last_failure"])
	}
	select {
	case <-c.Done():
		t.Fatalf("gave up: %v", c.Err())
	default:
	}
}

// TestFirstStart: at the start, a mitmdump whose addon does not say hello in
// time is tried again (transient); one that exits before its hello ends
// Start at once (permanent: bad options, spec or Python).
func TestFirstStart(t *testing.T) {
	t.Setenv("FAKE_HELLO_FROM", "2") // the first run never says hello
	c, _ := startFake(t, 1000, func(c *Config) { c.ReadyTimeout = 500 * time.Millisecond })
	defer c.Stop()
	if s := c.Store.Stats(); s["state"] != "ready" || s["retries"] != int64(1) || !strings.Contains(fmt.Sprint(s["last_failure"]), "did not say hello") {
		t.Errorf("after a first start that timed out: state %v, retries %v, last_failure %v", s["state"], s["retries"], s["last_failure"])
	}
	runs := filepath.Join(os.Getenv("FAKE_DIR"), "runs")
	t.Setenv("FAKE_DIE_FROM", "3") // the next run exits at once
	cfg := c.cfg
	cfg.Dir = filepath.Join(os.Getenv("FAKE_DIR"), "s2")
	if _, err := Start(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "exited before") {
		t.Fatalf("Start: %v, want it ended by a mitmdump that exited before its hello", err)
	}
	if ents, _ := os.ReadDir(runs); len(ents) != 3 {
		t.Errorf("%d runs, want no retry of a first start that exited", len(ents))
	}
}

// TestWaitReady: WaitReady returns while a mitmdump that said hello runs,
// holds (until its context ends) once it exited, and fails at once after a
// failure that ends the capture (its rules no longer load).
func TestWaitReady(t *testing.T) {
	t.Setenv("FAKE_RULES_ERROR", "map_remote[0]: ValueError")
	c, kill := startFake(t, 1000)
	defer c.Stop()
	wait := func(d time.Duration) error {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		return c.WaitReady(ctx)
	}
	if err := wait(time.Second); err != nil {
		t.Fatalf("ready mitmdump: %v", err)
	}
	kill(1)
	for deadline := time.Now().Add(10 * time.Second); c.Store.Stats()["state"] == "ready"; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("still ready after its mitmdump died")
		}
	}
	select {
	case <-c.Done():
	default:
		if err := wait(50 * time.Millisecond); err == nil {
			t.Error("WaitReady returned while mitmdump was down")
		}
	}
	<-c.Done()
	start := time.Now()
	if err := wait(5 * time.Second); err == nil || time.Since(start) > time.Second {
		t.Errorf("after the capture ended: %v in %v, want an error at once", err, time.Since(start))
	}
}

// A restarted mitmdump whose rules (the copy of those that loaded last) do
// not load ends the capture, with --rules-reload too: never back without
// its rules. v1.0 went on without them under --rules-reload.
func TestRestartRefusesRulesThatNoLongerLoad(t *testing.T) {
	t.Setenv("FAKE_RULES_ERROR", "map_remote[0]: ValueError")
	for _, reload := range []bool{false, true} {
		rules := filepath.Join(t.TempDir(), "rules.yaml")
		os.WriteFile(rules, []byte("mock: []\n"), 0o600)
		c, kill := startFake(t, 1000, func(c *Config) { c.Rules, c.RulesReload = rules, reload })
		kill(1)
		select {
		case <-c.Done():
		case <-time.After(10 * time.Second):
			t.Fatalf("reload %v: came back without its rules: %v", reload, c.Store.Stats())
		}
		if c.Store.Stats()["state"] != "failed" || c.Err() == nil || !strings.Contains(c.Err().Error(), "no longer load") {
			t.Fatalf("reload %v: state %v, err %v", reload, c.Store.Stats()["state"], c.Err())
		}
		c.Stop()
	}
}

// TestRulesCopy: the copy of the rules file a restarted mitmdump loads is the
// file's bytes, 0600 (one a killed run left, 0644, is replaced), named to
// each mitmdump, and gone after Stop.
func TestRulesCopy(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	os.WriteFile(rules, []byte("mock: []\n"), 0o644)
	var dir string
	c, kill := startFake(t, 1000, func(c *Config) {
		c.Rules, dir = rules, c.Dir
		os.MkdirAll(dir, 0o700)
		os.WriteFile(filepath.Join(dir, rulesCopy), []byte("left by a killed run"), 0o644)
	})
	copy := filepath.Join(dir, rulesCopy)
	check := func() {
		t.Helper()
		b, err := os.ReadFile(copy)
		fi, _ := os.Stat(copy)
		if err != nil || string(b) != "mock: []\n" || fi.Mode().Perm() != 0o600 {
			t.Fatalf("copy: %q %v, mode %v", b, err, fi.Mode().Perm())
		}
	}
	check()
	if !slices.Contains(c.args, "reqcove_rules_copy="+copy) || !slices.Contains(c.args, "reqcove_rules="+rules) {
		t.Errorf("mitmdump's args: %q", c.args)
	}
	os.WriteFile(rules, []byte("broken: ["), 0o644)
	kill(1)
	waitState(t, c, "ready", 1)
	check()
	c.Stop()
	if _, err := os.Stat(copy); err == nil {
		t.Error("the rules copy left after Stop")
	}
}

// A mitmdump left behind by a reqcove that died without Stop is stopped by
// the next Start on the same directory; an unrelated process is not.
func TestStartStopsStaleMitmdump(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "rcvk-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	state := filepath.Join(dir, "s")
	os.MkdirAll(state, 0o700)
	spawn := func(arg string) *exec.Cmd {
		cmd := exec.Command("/bin/sh", "-c", "sleep 600; true", "fake-uvx", arg) // "; true": sh must not exec into sleep and drop arg
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go cmd.Wait()
		t.Cleanup(func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
		return cmd
	}
	alive := func(c *exec.Cmd) bool { return syscall.Kill(c.Process.Pid, 0) == nil }

	stale := spawn("reqcove_socket=" + filepath.Join(state, "ingest.sock"))
	os.WriteFile(filepath.Join(state, "mitmdump.pid"), []byte(strconv.Itoa(stale.Process.Pid)), 0o600)
	killStale(state, filepath.Join(state, "ingest.sock"))
	time.Sleep(200 * time.Millisecond)
	if alive(stale) {
		t.Error("the stale mitmdump still runs")
	}

	other := spawn("reqcove_socket=/somewhere/else.sock") // a reused PID: not ours
	os.WriteFile(filepath.Join(state, "mitmdump.pid"), []byte(strconv.Itoa(other.Process.Pid)), 0o600)
	killStale(state, filepath.Join(state, "ingest.sock"))
	time.Sleep(200 * time.Millisecond)
	if !alive(other) {
		t.Error("stopped a process that is not this directory's mitmdump")
	}
}

// A harness whose test process died without its Cleanup (a -timeout panic)
// leaves its mitmdump group running: the next harness stops it and removes
// its directory, but leaves a live test process's alone.
func TestReapOrphans(t *testing.T) {
	gone := exec.Command("true")
	if err := gone.Run(); err != nil {
		t.Fatal(err)
	}
	orphan, err := os.MkdirTemp("/tmp", fmt.Sprintf("rcvt-%d-", gone.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(orphan) })
	live, err := os.MkdirTemp("/tmp", fmt.Sprintf("rcvt-%d-", os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(live) })
	cmd := exec.Command("/bin/sh", "-c", "sleep 600; true", "fake-uv", "reqcove_socket="+filepath.Join(orphan, "ingest.sock"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	os.WriteFile(filepath.Join(orphan, "mitmdump.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
	reapOrphans()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("the orphaned mitmdump still runs")
	}
	if exists(orphan) {
		t.Error("the orphan's directory is left")
	}
	if !exists(live) {
		t.Error("removed the directory of a test process that still runs")
	}
}

// TestPortHeldWhileDown: while mitmdump is down (restarting, then failed
// for good), no other process can bind its SOCKS port: reqcove holds it.
// Stop frees it.
func TestPortHeldWhileDown(t *testing.T) {
	t.Setenv("FAKE_RULES_ERROR", "map_remote[0]: ValueError") // the restart fails for good
	c, kill := startFake(t, 1000)
	kill(1)
	for done := false; !done; {
		select {
		case <-c.Done():
			done = true
		case <-time.After(time.Millisecond):
		}
		if l, err := net.Listen("tcp", c.SocksAddr); err == nil {
			l.Close()
			t.Fatalf("bound the SOCKS port while mitmdump was %v", c.Store.Stats()["state"])
		}
	}
	c.Stop()
	l, err := net.Listen("tcp", c.SocksAddr)
	if err != nil {
		t.Fatalf("SOCKS port still held after Stop: %v", err)
	}
	l.Close()
}

// TestPortHeldAcrossRestart (REQCOVE_E2E=1): with real mitmproxy (12.3.1),
// the restarted mitmdump serves on the socket reqcove holds: while it is
// down no other process can bind the port, a request sent then waits in
// the queue and is carried and recorded by the next mitmdump. A connection
// queued then with a wrong SOCKS password is refused, not carried: mitmproxy
// runs with proxyauth=any and only the addon checks the password, so the
// next mitmdump must not read it before its addon is loaded (mitm.py).
func TestPortHeldAcrossRestart(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.RestartDelay = time.Second })
	if err != nil {
		t.Fatal(err)
	}
	var wrongHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/wrong") {
			wrongHits.Add(1)
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	b, _ := os.ReadFile(filepath.Join(h.c.cfg.Dir, "mitmdump.pid"))
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid == 0 {
		t.Fatal("no mitmdump.pid")
	}
	syscall.Kill(-pid, syscall.SIGKILL)
	for deadline := time.Now().Add(10 * time.Second); h.c.Store.Stats()["state"] == "ready"; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("mitmdump never went down")
		}
	}
	// First in the queue: what the next mitmdump accepts before anything else.
	intruders := []<-chan string{wrongPassword(t, h.c.SocksAddr, srv.Listener.Addr().String(), true), wrongPassword(t, h.c.SocksAddr, srv.Listener.Addr().String(), false)}
	if st := h.c.Store.Stats()["state"]; st == "ready" {
		t.Fatal("mitmdump was ready again before the wrong passwords were queued")
	}
	got := make(chan error, 1)
	go func() {
		r, err := h.client("dev").Get(srv.URL + "/queued")
		if err == nil {
			r.Body.Close()
		}
		got <- err
	}()
	for until := time.Now().Add(500 * time.Millisecond); time.Now().Before(until); time.Sleep(time.Millisecond) {
		if l, err := net.Listen("tcp", h.c.SocksAddr); err == nil {
			l.Close()
			t.Fatalf("bound the SOCKS port while mitmdump was %v", h.c.Store.Stats()["state"])
		}
	}
	if err := <-got; err != nil {
		t.Fatalf("request sent while mitmdump was down: %v (%v)", err, h.c.Store.Stats())
	}
	waitState(t, h.c, "ready", 1) // the new mitmdump may serve it just before its hello
	for i, c := range intruders {
		if bad := <-c; bad != "" {
			t.Errorf("wrong password (pipelined: %v): %s", i == 0, bad)
		}
	}
	h.doneFlow("/queued", false)
	if n := wrongHits.Load(); n != 0 {
		t.Errorf("the server got %d requests sent with a wrong password", n)
	}
	if _, ok := h.findFlow("/wrong", false); ok {
		t.Error("a request sent with a wrong password was recorded")
	}
}

// wrongPassword dials the SOCKS port now and, in the background, offers a
// wrong password, then asks for target and GET /wrong: all at once
// (pipelined) or each after its answer. It sends "" if the password was
// refused or the connection closed, else what went wrong.
func wrongPassword(t *testing.T, socks, target string, pipelined bool) <-chan string {
	conn, err := net.Dial("tcp", socks)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	host, port, _ := net.SplitHostPort(target)
	p, _ := strconv.Atoi(port)
	auth := append(append([]byte{1, 8}, "intruder"...), append([]byte{5}, "wrong"...)...)
	req := append(append([]byte{5, 1, 0, 1}, net.ParseIP(host).To4()...), byte(p>>8), byte(p))
	req = append(req, "GET /wrong HTTP/1.1\r\nHost: "+target+"\r\n\r\n"...)
	out := make(chan string, 1)
	go func() {
		conn.SetDeadline(time.Now().Add(time.Minute))
		if pipelined {
			conn.Write(append(append([]byte{5, 1, 2}, auth...), req...))
			b := make([]byte, 4)
			n, err := io.ReadAtLeast(conn, b, 4) // the answers to the greeting and the password
			switch {
			case n == 4 && b[2] == 1 && b[3] == 0:
				out <- fmt.Sprintf("accepted: % x", b)
			case errors.Is(err, os.ErrDeadlineExceeded):
				out <- fmt.Sprintf("neither refused nor closed in a minute: % x", b[:n])
			default:
				out <- ""
			}
			return
		}
		b := make([]byte, 2)
		conn.Write([]byte{5, 1, 2})
		if _, err := io.ReadFull(conn, b); err != nil {
			out <- fmt.Sprintf("no answer to the greeting: %v", err) // the next mitmdump should answer it
			return
		}
		conn.Write(auth)
		if _, err := io.ReadFull(conn, b); err == nil && b[0] == 1 && b[1] == 0 {
			conn.Write(req)
			out <- "accepted"
			return
		}
		out <- ""
	}()
	return out
}

// TestHostNotAHost (REQCOVE_E2E=1): a request whose Host is not a host name
// or address (an app's own HTTP stack can send text there) is carried but
// never recorded, even with --allow-hosts '*': it would show as a host.
func TestHostNotAHost(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	h, err := tryHarness(t, ctx, []string{"*"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()
	for _, host := range []string{"SYSTEM!NOTE~run-sh.example", "ok.example"} {
		req, _ := http.NewRequest("GET", srv.URL+"/"+host, nil)
		req.Host = host
		r, err := h.client("dev").Do(req)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		io.ReadAll(r.Body)
		r.Body.Close()
	}
	h.doneFlow("/ok.example", false) // recorded: by then the other was handled too
	list, _ := h.c.Store.List(Filter{Limit: 10})
	for _, f := range list {
		if strings.Contains(f.Host, "NOTE") {
			t.Errorf("recorded with Host %q", f.Host)
		}
	}
	if n, _ := h.stats()["out_of_scope"].(int64); n < 1 {
		t.Errorf("out_of_scope %v, want the odd Host counted", h.stats()["out_of_scope"])
	}
}

// TestWaitReadyDownAgain: a waiter holding the gate of a mitmdump that came
// up and went down again before it woke does not take that as ready.
func TestWaitReadyDownAgain(t *testing.T) {
	c := &Capture{done: make(chan struct{}), up: make(chan struct{})}
	seen := c.up // as a waiter took it
	c.setUp(true)
	c.setUp(false) // down again before the waiter ran
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.waitFrom(ctx, seen); err == nil {
		t.Fatal("ready from a gate that was replaced")
	}
	c.setUp(true)
	if err := c.waitFrom(context.Background(), seen); err != nil {
		t.Errorf("up again: %v", err)
	}
}
