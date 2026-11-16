package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"golang.org/x/sys/unix"
)

// restartable is the ctl state of a run started from a --config file of text
// (its --state made, as run makes it), with what its restart op would exec
// recorded: the snapshot's path, once asked.
func restartable(t *testing.T, text string) (st *ctlState, config string, args []string, snap func() string) {
	t.Helper()
	config, args = confFile(t, text)
	o, err := parseRunFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	if err := claimState(o.state); err != nil {
		t.Fatal(err)
	}
	st = newCtlState(o)
	var asked string
	st.restart = func(s string) { asked = s }
	startBinary, startBinaryErr, startArgs = os.Args[0], nil, args
	t.Cleanup(func() { startBinary, startArgs = "", nil })
	return st, config, args, func() string {
		t.Helper()
		a := restartOp(t.Context(), st, 0)
		if !a.OK || a.after == nil {
			t.Fatalf("restart refused: %q", a.Message)
		}
		a.after()
		return asked
	}
}

// stubExec records what a restart would exec in place of execing it.
func stubExec(t *testing.T) *[]string {
	t.Helper()
	var env []string
	sysExec = func(_ string, _, e []string) error { env = e; return errors.New("not in a test") }
	t.Cleanup(func() { sysExec = syscall.Exec })
	return &env
}

// newProcess is the process a restart execs, as far as the handover goes:
// the snapshot's path (and the retry's mark) in its environment.
func newProcess(t *testing.T, snap string, retry bool) *handover {
	t.Helper()
	t.Setenv(envSnapshot, snap)
	if retry {
		t.Setenv(envRetry, "1")
	}
	return takeHandover()
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Started through a link, the path recorded is the link: Homebrew's opt
// path survives brew upgrade and cleanup, the Cellar path it points to does not.
func TestBinaryPathKeepsLink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "Cellar-reqcove")
	os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755)
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0o755)
	link := filepath.Join(bin, "reqcove-linked")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if got, err := binaryPath(link); err != nil || got != link {
		t.Errorf("absolute: %q %v", got, err)
	}
	t.Setenv("PATH", bin)
	if got, err := binaryPath("reqcove-linked"); err != nil || got != link {
		t.Errorf("through PATH: %q %v", got, err)
	}
	if _, err := binaryPath("reqcove-none"); err == nil {
		t.Error("not on PATH: no error")
	}
}

// Two page writes, or a page write then an edit on disk, then a failed
// start: the config the run started from comes back, not config.prev (the
// file before the last write); the failed one is kept aside, and the start
// once more is the retry, with the snapshot still there for it.
func TestRestartRestoresStartConfig(t *testing.T) {
	for _, onDisk := range []bool{false, true} {
		state := t.TempDir()
		start := "--device phone\n--allow-hosts=a.example\n--state=" + state + "\n"
		st, config, args, restart := restartable(t, start)
		plan, err := planConfig(config, args, nil, configEdit{Flag: "keep-awake", Values: []string{"ac"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := plan.commit(); err != nil {
			t.Fatal(err)
		}
		if onDisk {
			os.WriteFile(config, []byte(read(t, config)+"--uvx=/nonexistent/uvx\n"), 0o600)
		} else if plan, err = planConfig(config, args, nil, configEdit{Flag: "verbose", Values: []string{"true"}}); err != nil {
			t.Fatal(err)
		} else if err := plan.commit(); err != nil {
			t.Fatal(err)
		}
		failing := read(t, config)
		// Two writes: config.prev is the file after the first, not the start
		// config. A write then an edit: the file on disk is not either.
		if !onDisk && read(t, config+".prev") == start {
			t.Fatal("config.prev is the start config: the test shows nothing")
		}
		snap := restart()
		if fi, err := os.Lstat(snap); err != nil || fi.Mode().Perm() != 0o600 || filepath.Dir(snap) != state || read(t, snap) != start {
			t.Fatalf("snapshot %s: %v %v", snap, fi, err)
		}

		env := stubExec(t)
		h := newProcess(t, snap, false)
		if err := h.failed(args, errors.New("boom")); err == nil || !strings.Contains(err.Error(), "did not start again") {
			t.Errorf("failed: %v", err)
		}
		if got := read(t, config); got != start {
			t.Errorf("on disk %v: config after the failed start:\n%s", onDisk, got)
		}
		if got := read(t, config+".failed"); got != failing {
			t.Errorf("config.failed:\n%s", got)
		}
		if fi, _ := os.Stat(config); fi.Mode().Perm() != 0o600 {
			t.Errorf("config mode %v", fi.Mode())
		}
		if !slices.Contains(*env, envRetry+"=1") || !slices.Contains(*env, envSnapshot+"="+snap) || !exists(snap) {
			t.Errorf("the retry: env %q, snapshot there %v", *env, exists(snap))
		}
		if note := read(t, filepath.Join(state, restartNote)); !strings.Contains(note, "failed (boom)") || !strings.Contains(note, config+" is back") || !strings.Contains(note, config+".failed") {
			t.Errorf("note: %q", note)
		}
		_ = st
	}
}

// The retry fails too: no exec, the snapshot removed, the note says run
// stays down.
func TestRetryOnce(t *testing.T) {
	state := t.TempDir()
	_, config, args, restart := restartable(t, "--device phone\n--state="+state+"\n")
	snap := restart()
	env := stubExec(t)
	*env = []string{"none"}
	writePrivate(filepath.Join(state, restartNote), []byte("the start after a restart failed (boom); run starts once more with it.\n"))
	h := newProcess(t, snap, true)
	if err := h.failed(args, errors.New("again")); err == nil || err.Error() != "again" {
		t.Errorf("failed: %v", err)
	}
	if !slices.Equal(*env, []string{"none"}) || exists(snap) {
		t.Errorf("exec'd %q; snapshot there %v", *env, exists(snap))
	}
	if note := read(t, filepath.Join(state, restartNote)); !strings.Contains(note, "once more with it. That start failed too (again): run stays down.") {
		t.Errorf("note: %q", note)
	}
	_ = config
}

// A leftover snapshot (a crash), then a restart and a failed start: the
// restart's snapshot comes back, not the leftover; any start removes the
// leftover, never the snapshot handed over.
func TestRestartLeftoverSnapshot(t *testing.T) {
	state := t.TempDir()
	start := "--device phone\n--state=" + state + "\n"
	_, config, args, restart := restartable(t, start)
	leftover, err := writeSnapshot(state, []byte("--device old\n"))
	if err != nil {
		t.Fatal(err)
	}
	snap := restart()
	os.WriteFile(config, []byte(start+"--verbose\n"), 0o600)
	stubExec(t)
	h := newProcess(t, snap, false)
	if n := sweepSnapshots(state, h.snapPath); n != 1 || exists(leftover) || !exists(snap) {
		t.Errorf("swept %d: leftover there %v, snapshot there %v", n, exists(leftover), exists(snap))
	}
	h.failed(args, errors.New("boom"))
	if got := read(t, config); got != start {
		t.Errorf("config:\n%s", got)
	}
}

// The sweep at run's start keeps the snapshot handed over until the retry is
// decided: run fails (its mitmproxy cannot start), the leftover is gone, the
// snapshot is not.
func TestRunSweepKeepsHandedOver(t *testing.T) {
	state := t.TempDir()
	claimState(state)
	snap, _ := writeSnapshot(state, []byte("--device phone\n"))
	leftover, _ := writeSnapshot(state, []byte("--device old\n"))
	lock, err := lockFile(state)
	if err != nil {
		t.Fatal(err)
	}
	carried = &handover{restarted: true, snapPath: snap, lock: lock}
	defer func() { carried = nil }()
	err = run(context.Background(), []string{"--device", "phone", "--state", state, "--uvx", "/usr/bin/false", "--keep-awake", "never"})
	if err == nil {
		t.Fatal("run started")
	}
	if !exists(snap) || exists(leftover) {
		t.Errorf("snapshot there %v, leftover there %v (%v)", exists(snap), exists(leftover), err)
	}
	if !carried.adopted {
		t.Error("the lock carried in not taken on")
	}
	if _, err := lockFile(state); err == nil { // the retry's: run let it go
		t.Error("the lock carried in let go")
	}
	carried.drop()
	if exists(snap) {
		t.Error("dropped: the snapshot still there")
	}
}

// An edit that changes --state, then a failed start: the snapshot, in the
// old state directory, is read from the path handed over; the retry puts the
// old config back and carries the old state's lock on.
func TestRestartStateEdited(t *testing.T) {
	stateA, stateB := t.TempDir(), t.TempDir()
	start := "--device phone\n--state=" + stateA + "\n"
	st, config, args, restart := restartable(t, start)
	os.WriteFile(config, []byte("--device phone\n--state="+stateB+"\n"), 0o600)
	a := restartOp(t.Context(), st, 0)
	if !strings.Contains(a.Message, "the config names another --state now: "+stateB) {
		t.Errorf("answer: %q", a.Message)
	}
	snap := restart()
	lock, err := lockFile(stateA)
	if err != nil {
		t.Fatal(err)
	}
	env := stubExec(t)
	h := newProcess(t, snap, false)
	h.lock = lock // carried in
	carried = h
	defer func() { carried = nil }()
	own, err := stateLock(stateB)
	if err != nil || h.adopted {
		t.Fatalf("B's lock: %v, adopted %v", err, h.adopted)
	}
	own.Close()
	if n := sweepSnapshots(stateB, h.snapPath); n != 0 || !exists(snap) {
		t.Errorf("B's sweep: %d, snapshot there %v", n, exists(snap))
	}
	h.failed(args, errors.New("boom"))
	if got := read(t, config); got != start {
		t.Errorf("config:\n%s", got)
	}
	fd := strconv.Itoa(int(lock.Fd()))
	if !slices.Contains(*env, envLock+"="+fd) {
		t.Errorf("the retry carries no lock: %q", *env)
	}
	if _, err := lockFile(stateA); err == nil {
		t.Error("A's lock let go before the retry")
	}
}

// A path handed over that is a link, another user's file, not 0600, not
// named as a snapshot, outside a state directory or missing is neither read
// nor removed, and there is no retry.
func TestSnapshotUntrusted(t *testing.T) {
	var state string
	good := func() string {
		p, err := writeSnapshot(state, []byte("--device phone\n"))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	plain := t.TempDir() // no marker
	for _, c := range []struct {
		name string
		make func() string
		why  string
	}{
		{"link", func() string {
			target := good()
			p := filepath.Join(state, "restart-"+secret(16)+".config")
			os.Symlink(target, p)
			return p
		}, "not a plain file"},
		{"other user's", func() string {
			p := good()
			me := uid()
			uid = func() int { return me + 1 }
			return p
		}, "not this user's"},
		{"0640", func() string { p := good(); os.Chmod(p, 0o640); return p }, "not mode 0600"},
		{"wrong name", func() string {
			p := filepath.Join(state, "restart-x.config")
			os.WriteFile(p, []byte("--device phone\n"), 0o600)
			return p
		}, "not a snapshot's name"},
		{"outside a state directory", func() string {
			p := filepath.Join(plain, "restart-"+secret(16)+".config")
			os.WriteFile(p, []byte("--device phone\n"), 0o600)
			return p
		}, "not in a reqcove state directory"},
		{"relative", func() string { return "restart-" + secret(16) + ".config" }, "not a snapshot's name"},
		{"missing", func() string { return filepath.Join(state, "restart-"+secret(16)+".config") }, "missing"},
	} {
		t.Run(c.name, func(t *testing.T) {
			state = t.TempDir()
			claimState(state)
			t.Cleanup(func() { uid = os.Getuid })
			p := c.make()
			before, _ := os.Lstat(p)
			logged := logTo(t)
			env := stubExec(t)
			*env = []string{"none"}
			h := newProcess(t, p, false)
			if h.snapPath != "" || h.snap != nil || !strings.Contains(logged.String(), c.why) || !strings.Contains(logged.String(), "neither read nor removed") {
				t.Errorf("taken: %q %q; log %q", h.snapPath, h.snap, logged.String())
			}
			_, args := confFile(t, "--device phone\n")
			if err := h.failed(args, errors.New("boom")); err == nil || !slices.Equal(*env, []string{"none"}) {
				t.Errorf("retried: %q", *env)
			}
			if after, _ := os.Lstat(p); before != nil && (after == nil || !os.SameFile(before, after)) {
				t.Error("removed")
			}
			if c.name != "link" && before != nil && sweepSnapshots(filepath.Dir(p), "") != 0 {
				t.Error("swept")
			}
		})
	}
}

// The handover variables are unset and the fds made close-on-exec at once:
// a child gets neither. Without the page's port, no session comes across; a
// fresh start has none.
func TestHandoverTaken(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f, _ := ln.(*net.TCPListener).File()
	ln.Close()
	lf, _ := os.CreateTemp(t.TempDir(), "lock")
	var fds []int
	for _, o := range []*os.File{f, lf} {
		fd, err := syscall.Dup(int(o.Fd())) // the handover's own: no other File closes it
		if err != nil {
			t.Fatal(err)
		}
		o.Close()
		unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0) // as an exec hands them over
		fds = append(fds, fd)
	}
	hash := strings.Repeat("ab", 32)
	t.Setenv(envListener, strconv.Itoa(fds[0]))
	t.Setenv(envLock, strconv.Itoa(fds[1]))
	t.Setenv(envSessions, "local:"+hash+":30,tailnet:"+hash+":1,local:zz:1")
	logged := logTo(t)
	h := takeHandover()
	defer h.pageLn.Close()
	for _, k := range handoverVars {
		if _, ok := os.LookupEnv(k); ok {
			t.Errorf("%s still set", k)
		}
	}
	for _, fd := range fds {
		if fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil || fl&unix.FD_CLOEXEC == 0 {
			t.Errorf("fd %d not close-on-exec: %v", fd, err)
		}
	}
	if h.pageLn == nil || h.lock == nil || len(h.sessions) != 1 || h.sessions[0].idle != 30*time.Second || fmt.Sprintf("%x", h.sessions[0].hash) != hash {
		t.Fatalf("taken: %+v", h)
	}
	out, err := exec.Command("sh", "-c", "env").Output()
	if err != nil || strings.Contains(string(out), "REQCOVE_RESTART") {
		t.Errorf("a child's environment: %v\n%s", err, out)
	}
	if strings.Contains(logged.String(), hash) {
		t.Errorf("a hash logged: %s", logged.String())
	}

	// The page's port not carried (an fd not open): the sessions end.
	t.Setenv(envListener, "999")
	t.Setenv(envSessions, "local:"+hash+":30")
	if h := takeHandover(); h.pageLn != nil || h.sessions != nil || !strings.Contains(logged.String(), "its sessions end") {
		t.Errorf("without the port: %+v", h)
	}
	// A fresh start: nothing carried, no page until reqcove console.
	if h := takeHandover(); h.restarted || h.sessions != nil {
		t.Errorf("fresh: %+v", h)
	}
	if st, err := serveCtl(t.Context(), shortDir(t), nil, &runOpts{}, nil, nil); err != nil || st.page != nil {
		t.Errorf("fresh start's page: %v %v", err, st)
	}
}

func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rcrs-") // macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// The page carried in serves at once, its sessions working, idle as they were.
func TestCarriedPage(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	f, _ := ln.(*net.TCPListener).File()
	pl, _ := net.FileListener(f)
	ln.Close()
	token := secret(32)
	h := &handover{page: f, pageLn: pl, sessions: []carriedSession{{hash: sha(token), idle: time.Minute}, {hash: sha("old"), idle: pageIdle}}}
	carried = h
	defer func() { carried = nil }()
	logged := logTo(t)
	st, err := serveCtl(t.Context(), shortDir(t), nil, &runOpts{}, nil, nil)
	if err != nil || st.page == nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		token string
		code  int
	}{{token, http.StatusOK}, {"old", http.StatusUnauthorized}, {"", http.StatusUnauthorized}} {
		req, _ := http.NewRequest("GET", "http://"+st.page.host+"/api/state", nil)
		req.Header.Set(sessionHeader, c.token)
		res, err := http.DefaultClient.Do(req)
		if err != nil || res.StatusCode != c.code {
			t.Errorf("%q: %v %v", c.token, err, res)
		} else {
			res.Body.Close()
		}
	}
	if s := st.page.carry(); len(s) != 1 || s[0].hash != sha(token) {
		t.Errorf("carried on: %+v", s)
	}
	if l := logged.String(); !strings.Contains(l, "carried across the restart") || strings.Contains(l, token) || strings.Contains(l, fmt.Sprintf("%x", sha(token))) {
		t.Errorf("log: %s", l)
	}
}

// Refused, nothing stopped and no snapshot written: the binary gone, or the
// config on disk the next start would refuse. Allowed in LAN mode.
func TestRestartRefused(t *testing.T) {
	state := t.TempDir()
	st, config, _, _ := restartable(t, "--device phone\n--state="+state+"\n")
	snaps := func() int { m, _ := filepath.Glob(filepath.Join(state, "restart-*")); return len(m) }
	startBinary = filepath.Join(t.TempDir(), "gone")
	if a := restartOp(t.Context(), st, 0); a.OK || a.after != nil || !strings.Contains(a.Message, "is not there to start again") || !strings.HasSuffix(a.Message, "; nothing stopped") {
		t.Errorf("binary gone: %q", a.Message)
	}
	startBinary = os.Args[0]
	os.WriteFile(config, []byte("--device phone\n--state="+state+"\n--web\n"), 0o600)
	if a := restartOp(t.Context(), st, 0); a.OK || !strings.Contains(a.Message, "the next start would refuse the settings") || !strings.Contains(a.Message, "--web only on the command line") {
		t.Errorf("config refused: %q", a.Message)
	}
	if snaps() != 0 {
		t.Error("a snapshot written")
	}
	st.o.lanMode = true
	os.WriteFile(config, []byte("--device phone\n--state="+state+"\n"), 0o600)
	if a := answerCtl(t.Context(), nil, st, ctlRequest{Cmd: "restart"}); !a.OK || !strings.Contains(a.Message, "restarting: ") {
		t.Errorf("LAN mode: %q", a.Message)
	}
	if a := answerCtl(t.Context(), nil, st, ctlRequest{Cmd: "restart", Hosts: []string{"a.com"}}); a.OK {
		t.Errorf("with hosts: %q", a.Message)
	}
}

// capture save's first save adds the @FILE line to the config and to the
// start config's snapshot: a failed start after a restart keeps the line,
// and the next save writes the hosts file rather than creating it again.
func TestSaveLineJoinsSnapshot(t *testing.T) {
	state := t.TempDir()
	start := "--device x\n--allow-hosts=inline.a.com\n--state=" + state // no newline at the end
	st, config, args, restart := restartable(t, start)
	base, _ := capture.ParseAllowHosts([]string{"inline.a.com,new.b.com"})
	a, _ := saveScope(base, st, "")
	if a, _ := saveScope(base, st, a.Confirm); !a.OK {
		t.Fatalf("save: %q", a.Message)
	}
	hosts := filepath.Join(filepath.Dir(config), "hosts")
	want := start + "\n--allow-hosts=@" + hosts + "\n"
	if got := read(t, config); got != want {
		t.Fatalf("config:\n%s", got)
	}
	snap := restart()
	os.WriteFile(config, []byte("--device x\n--state="+state+"\n--verbose\n"), 0o600)
	stubExec(t)
	newProcess(t, snap, false).failed(args, errors.New("boom"))
	if got := read(t, config); got != want {
		t.Fatalf("config put back:\n%s", got)
	}
	o, err := reloadFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	more, _ := capture.ParseAllowHosts([]string{"inline.a.com,new.b.com,third.c.com"})
	if a, saved := saveScope(more, newCtlState(o), ""); !a.OK || !saved || a.Confirm != "" || !strings.HasPrefix(a.Message, "saved to "+hosts+": new.b.com, third.c.com") {
		t.Errorf("the save after: %+v", a)
	}
}

// The exec itself, through the test binary run twice: the lock and the
// page's listener come across (the port answers, a second run finds the
// state in use, the session is there), the variables are unset and no child
// of the new process holds either fd; nothing logged holds the hash.
func TestRestartExec(t *testing.T) {
	dir := shortDir(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestRestartExecHelper$")
	cmd.Env = append(os.Environ(), "REQCOVE_TEST_STAGE=1", "REQCOVE_TEST_DIR="+dir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	resultFile := filepath.Join(dir, "result")
	for deadline := time.Now().Add(30 * time.Second); !exists(resultFile); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no result:\n%s", stderr.String())
		}
	}
	time.Sleep(50 * time.Millisecond) // written whole
	var res struct {
		Pid      int
		Port     int
		Vars     []string
		Sessions []string
		Child    string
	}
	if err := json.Unmarshal([]byte(read(t, resultFile)), &res); err != nil {
		t.Fatal(err)
	}
	if res.Pid != cmd.Process.Pid || len(res.Vars) > 0 || !slices.Equal(res.Sessions, []string{helperHash}) || res.Child != "clean" {
		t.Errorf("after the exec: %+v", res)
	}
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", res.Port))
	if err != nil {
		t.Fatalf("the port: %v", err)
	}
	if b, _ := io.ReadAll(c); string(b) != "ok" {
		t.Errorf("the port answered %q", b)
	}
	c.Close()
	if _, err := lockFile(filepath.Join(dir, "state")); err == nil || !strings.Contains(err.Error(), "another reqcove is using") {
		t.Errorf("a second run: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "done"), nil, 0o600)
	if err := cmd.Wait(); err != nil {
		t.Errorf("helper: %v\n%s", err, stderr.String())
	}
	if strings.Contains(stderr.String(), helperHash) {
		t.Errorf("the hash logged:\n%s", stderr.String())
	}
}

const helperHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestRestartExecHelper is TestRestartExec's process: stage 1 holds the lock
// and the port and execs itself (stage 2), which takes the handover.
func TestRestartExecHelper(t *testing.T) {
	dir := os.Getenv("REQCOVE_TEST_DIR")
	state := filepath.Join(dir, "state")
	switch os.Getenv("REQCOVE_TEST_STAGE") {
	case "":
		t.Skip("TestRestartExec's")
	case "1":
		if err := claimState(state); err != nil {
			t.Fatal(err)
		}
		lock, err := lockFile(state)
		if err != nil {
			t.Fatal(err)
		}
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		f, _ := ln.(*net.TCPListener).File()
		ln.Close()
		h, _ := hexHash(helperHash)
		os.Setenv("REQCOVE_TEST_STAGE", "2")
		os.RemoveAll(testHome) // TestMain's, which the exec skips
		startBinary = os.Args[0]
		t.Fatal(execRestart(&restartExec{lock: lock, page: f, sessions: []carriedSession{{hash: h, idle: time.Second}}}))
	case "2":
		h := takeHandover()
		var res struct {
			Pid      int
			Port     int
			Vars     []string
			Sessions []string
			Child    string
		}
		res.Pid = os.Getpid()
		for _, k := range handoverVars {
			if _, ok := os.LookupEnv(k); ok {
				res.Vars = append(res.Vars, k)
			}
		}
		for _, s := range h.sessions {
			res.Sessions = append(res.Sessions, fmt.Sprintf("%x", s.hash))
		}
		if a, ok := addrOf(h.pageLn); ok {
			res.Port = a.Port
		}
		carried = h
		if _, err := stateLock(state); err != nil || !h.adopted {
			t.Fatalf("the lock not taken on: %v", err)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestRestartExecHelper$")
		child.Env = append(os.Environ(), "REQCOVE_TEST_STAGE=child", fmt.Sprintf("REQCOVE_TEST_PORT=%d", res.Port))
		out, err := child.Output()
		res.Child, _, _ = strings.Cut(string(out), "\n") // then the test binary's PASS
		if err != nil {
			res.Child += " " + err.Error()
		}
		b, _ := json.Marshal(res)
		os.WriteFile(filepath.Join(dir, "result"), b, 0o600)
		if h.pageLn != nil {
			if c, err := h.pageLn.Accept(); err == nil {
				c.Write([]byte("ok"))
				c.Close()
			}
		}
		for !exists(filepath.Join(dir, "done")) {
			time.Sleep(20 * time.Millisecond)
		}
	case "child":
		lockInfo, _ := os.Stat(filepath.Join(state, "lock"))
		var leaks []string
		for fd := 3; fd < 256; fd++ {
			var st syscall.Stat_t
			if syscall.Fstat(fd, &st) != nil {
				continue
			}
			switch uint32(st.Mode) & syscall.S_IFMT {
			case syscall.S_IFSOCK:
				if sa, err := syscall.Getsockname(fd); err == nil {
					if in, ok := sa.(*syscall.SockaddrInet4); ok && strconv.Itoa(in.Port) == os.Getenv("REQCOVE_TEST_PORT") {
						leaks = append(leaks, "the page's port")
					}
				}
			case syscall.S_IFREG:
				if fi, err := os.NewFile(uintptr(fd), "").Stat(); err == nil && lockInfo != nil && os.SameFile(fi, lockInfo) {
					leaks = append(leaks, "the lock")
				}
			}
		}
		for _, k := range handoverVars {
			if _, ok := os.LookupEnv(k); ok {
				leaks = append(leaks, k)
			}
		}
		if len(leaks) == 0 {
			fmt.Println("clean")
		} else {
			fmt.Println(strings.Join(leaks, ", "))
		}
	}
}

func hexHash(s string) ([32]byte, error) {
	b, err := hex.DecodeString(s)
	return [32]byte(b), err
}

func sha(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// TestRestartE2E (REQCOVE_E2E=1, real mitmproxy): a real run, in LAN mode
// on the loopback (no tailnet node: tsnet needs a tailnet), started through
// a link, restarted with reqcove restart's op, then restarted after an edit
// on disk that its start refuses late (its LAN proxy's port taken, after
// mitmproxy, caffeinate and the system proxy are up), then stopped. Each restart
// keeps the pid, the page's port and session; a second run never takes the
// state meanwhile; mitmdump and caffeinate are stopped and reaped before the
// exec (one caffeinate after); on macOS, with --local-proxy and a fake
// networksetup first on PATH, the system proxy is put back at each stop. The
// failed start puts back the config run had started from and starts once
// more; status says so.
func TestRestartE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	lo := loopback(t)
	dir := shortDir(t)
	bin := filepath.Join(dir, "reqcove")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	os.Mkdir(filepath.Join(dir, "bin"), 0o700)
	link := filepath.Join(dir, "bin", "reqcove")
	os.Symlink(bin, link)
	port := quietPort(t)
	state := filepath.Join(dir, "s")
	config := filepath.Join(dir, "config")
	start := fmt.Sprintf("--allow-hosts=example.com\n--state=%s\n--proxy-port=%d\n--keep-awake=always\n", state, port)
	os.WriteFile(config, []byte(start), 0o600)
	args := []string{"run", "--config", config, "--lan", "--lan-interface", lo}
	env := os.Environ()
	nsLog := filepath.Join(dir, "networksetup.log")
	proxyCheck := false
	if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localProxyPort)); err == nil && runtime.GOOS == "darwin" {
		l.Close()
		fake := filepath.Join(dir, "fake")
		os.Mkdir(fake, 0o700)
		os.WriteFile(filepath.Join(fake, "networksetup"), []byte(`#!/bin/sh
echo "$@" >> "$FAKE_NS_LOG"
case "$1" in
-listallnetworkservices) printf 'An asterisk (*) denotes that a network service is disabled.\nFakeNet\n' ;;
-getwebproxy|-getsecurewebproxy) printf 'Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n' ;;
-getproxybypassdomains) echo "There aren't any bypass domains set on FakeNet." ;;
esac
`), 0o700)
		path := fake + string(os.PathListSeparator) + os.Getenv("PATH")
		if first := strings.Split(path, string(os.PathListSeparator))[0]; first != fake {
			t.Fatal("the fake networksetup is not first on PATH")
		}
		env = append(env, "PATH="+path, "FAKE_NS_LOG="+nsLog)
		args = append(args, "--local-proxy")
		proxyCheck = true
	} else {
		t.Log("not checked: the system proxy (not macOS, or 127.0.0.1:8082 taken)")
	}
	logFile, _ := os.Create(filepath.Join(dir, "run.log"))
	cmd := exec.Command(link, args...)
	cmd.Env, cmd.Stdout, cmd.Stderr = env, logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	logged := func() string { return read(t, logFile.Name()) }
	mitmLog := func() string {
		b, _ := os.ReadFile(filepath.Join(state, "mitmproxy.log"))
		return "mitmproxy.log:\n" + string(b)
	}
	waitReady := func(n int, check func()) {
		t.Helper()
		for deadline := time.Now().Add(3 * time.Minute); strings.Count(logged(), "reqcove is ready") < n; time.Sleep(50 * time.Millisecond) {
			select {
			case err := <-exited:
				t.Fatalf("run ended: %v\n%s\n%s", err, logged(), mitmLog())
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("not ready %d times:\n%s\n%s", n, logged(), mitmLog())
			}
			if check != nil {
				check()
			}
		}
	}
	held := func() { // a second run, meanwhile, finds the state in use
		if f, err := lockFile(state); err == nil {
			f.Close()
			t.Fatalf("the state was free during the restart:\n%s", logged())
		}
	}
	pidOf := func() int {
		n, _ := strconv.Atoi(strings.TrimSpace(read(t, filepath.Join(state, "mitmdump.pid"))))
		return n
	}
	gone := func(pid int) bool { return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) }
	caffeinates := func() []string {
		if runtime.GOOS != "darwin" {
			return nil
		}
		out, _ := exec.Command("pgrep", "-f", fmt.Sprintf("caffeinate -i -w %d$", cmd.Process.Pid)).Output()
		return strings.Fields(string(out))
	}
	mitmdumps := func() int { // the failing start's, too, whose pid file is gone
		out, _ := exec.Command("pgrep", "-f", "mitmdump.*"+state).Output()
		return len(strings.Fields(string(out)))
	}
	ctx := t.Context()
	waitReady(1, nil)
	mitmdumps0 := mitmdumps()
	if mitmdumps0 == 0 {
		t.Fatalf("no mitmdump of %s found by its arguments", state)
	}
	a, err := askRun(ctx, state, ctlRequest{Cmd: "console"})
	if err != nil || !a.OK {
		t.Fatalf("console: %v %+v", err, a)
	}
	pageURL := fmt.Sprintf("http://127.0.0.1:%d", a.Port)
	req, _ := http.NewRequest("POST", pageURL+"/api/session", strings.NewReader(`{"code":"`+a.Code+`"}`))
	req.Header.Set("Origin", pageURL)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var session struct{ Token string }
	json.NewDecoder(res.Body).Decode(&session)
	res.Body.Close()
	pageWorks := func(when string) {
		t.Helper()
		req, _ := http.NewRequest("GET", pageURL+"/api/state", nil)
		req.Header.Set(sessionHeader, session.Token)
		res, err := http.DefaultClient.Do(req)
		if err != nil || res.StatusCode != http.StatusOK {
			t.Errorf("%s: the page: %v %v", when, err, res)
			return
		}
		res.Body.Close()
	}
	pageWorks("before")
	mitm, caff := pidOf(), caffeinates()
	if runtime.GOOS == "darwin" && len(caff) != 1 {
		t.Fatalf("caffeinate: %q", caff)
	}

	a, err = askRun(ctx, state, ctlRequest{Cmd: "restart"})
	if err != nil || !a.OK || !strings.Contains(a.Message, link+" starts again") || !strings.Contains(a.Message, "keeps its port and sessions") {
		t.Fatalf("restart: %v %+v", err, a)
	}
	waitReady(2, held)
	pageWorks("after the restart")
	if !gone(mitm) || pidOf() == mitm {
		t.Errorf("the first mitmdump (%d) not stopped", mitm)
	}
	if now := caffeinates(); runtime.GOOS == "darwin" && (len(now) != 1 || slices.Equal(now, caff)) {
		t.Errorf("caffeinate: before %q, after %q", caff, now)
	}

	// A start that fails late: mitmproxy, caffeinate and the system proxy up,
	// then the LAN proxy's port taken (the checks do not bind it).
	taken, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	failing := strings.Replace(start, fmt.Sprintf("--proxy-port=%d", port), fmt.Sprintf("--proxy-port=%d", taken.Addr().(*net.TCPAddr).Port), 1)
	os.WriteFile(config, []byte(failing), 0o600)
	mitm = pidOf()
	if a, err := askRun(ctx, state, ctlRequest{Cmd: "restart"}); err != nil || !a.OK {
		t.Fatalf("second restart: %v %+v", err, a)
	}
	waitReady(3, held)
	pageWorks("after the retry")
	if l := logged(); !strings.Contains(l, "restart: the start after a restart failed (LAN proxy on 127.0.0.1:") || !strings.Contains(l, config+" is back as run had started from it") {
		t.Errorf("log:\n%s", l)
	}
	if read(t, config) != start || read(t, config+".failed") != failing || !gone(mitm) {
		t.Errorf("config:\n%s\nfailed:\n%s", read(t, config), read(t, config+".failed"))
	}
	out, _ := exec.Command(bin, "status", "--state", state).Output()
	if !strings.Contains(string(out), "restart: the start after a restart failed") {
		t.Errorf("status:\n%s", out)
	}
	if n := mitmdumps(); n != mitmdumps0 {
		t.Errorf("after the retry: %d mitmdumps of this state, %d at first", n, mitmdumps0)
	}
	if now := caffeinates(); runtime.GOOS == "darwin" && len(now) != 1 {
		t.Errorf("after the retry: caffeinate %q", now)
	}
	if m, _ := filepath.Glob(filepath.Join(state, "restart-*.config")); len(m) > 0 {
		t.Errorf("snapshots left: %q", m)
	}

	mitm = pidOf()
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(time.Minute):
		t.Fatal("run did not stop")
	}
	if !gone(mitm) || len(caffeinates()) > 0 || mitmdumps() > 0 {
		t.Errorf("after the stop: mitmdump gone %v, caffeinate %q", gone(mitm), caffeinates())
	}
	if proxyCheck {
		var seq strings.Builder
		for l := range strings.SplitSeq(read(t, nsLog), "\n") {
			switch {
			case strings.HasPrefix(l, "-setwebproxy FakeNet 127.0.0.1"):
				seq.WriteString("P")
			case l == "-setwebproxystate FakeNet off":
				seq.WriteString("B")
			}
		}
		if seq.String() != "PBPBPBPB" { // started; restarted; restarted, its start failing after the proxy, retried; stopped
			t.Errorf("the system proxy pointed (P) and put back (B): %s", seq.String())
		}
	}
}

// reqcove restart: in a terminal only; a run older than v1.3 (its usage, or
// in LAN mode its refusal) says to stop it and start it again.
func TestRestartCmd(t *testing.T) {
	ctx := context.Background()
	dir, got := fakeCtlSock(t, func(req ctlRequest) ctlAnswer { return ctlAnswer{OK: true, Message: "restarting: run stops"} })
	defer func() { terminal = isTerminal }()
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if err := restartIn(ctx, r, w, dir); !errors.Is(err, errRestartNotTerminal) || len(*got) != 0 {
		t.Errorf("off a terminal: %v %+v", err, *got)
	}
	terminal = func(*os.File) bool { return true }
	out, _ := os.Create(filepath.Join(t.TempDir(), "out"))
	defer out.Close()
	if err := restartIn(ctx, r, out, dir); err != nil || len(*got) != 1 || (*got)[0].Cmd != "restart" {
		t.Errorf("%v %+v", err, *got)
	}
	if b, _ := os.ReadFile(out.Name()); string(b) != "restarting: run stops\n" {
		t.Errorf("%q", b)
	}
	for _, lan := range []bool{false, true} {
		v12 := answerCtl(ctx, nil, newCtlState(&runOpts{lanMode: lan}), ctlRequest{Cmd: "restart-unknown"})
		old, _ := fakeCtlSock(t, func(ctlRequest) ctlAnswer { return v12 })
		if err := restartIn(ctx, r, out, old); !errors.Is(err, errOlderRestart) {
			t.Errorf("lan %v: %v (%s)", lan, err, v12.Message)
		}
	}
	if err := restartIn(ctx, r, out, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Errorf("no run: %v", err)
	}
}

// quietPort is a free TCP port on 127.0.0.1 outside the systems' ephemeral
// ranges (Linux from 32768, macOS from 49152), where outgoing connections take
// their source ports: one picked with :0 and closed could be taken by another
// test's connection before run binds it (seen on CI: "address already in use").
func quietPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 200; i++ {
		port := 20000 + rand.IntN(10000)
		if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			ln.Close()
			return port
		}
	}
	t.Fatal("no free port in 20000-29999")
	return 0
}

// The retry carries the page's sessions as they are when the start failed:
// none after reqcove console --end while it served (never the list handed
// over), the same ones when nothing changed, none when it never served.
func TestRetryCarriesSessionsNow(t *testing.T) {
	for _, c := range []struct {
		name         string
		serve, end   bool
		wantSessions int
	}{{"ended", true, true, 0}, {"kept", true, false, 2}, {"never served", false, false, 0}} {
		state := t.TempDir()
		_, _, args, restart := restartable(t, "--device phone\n--state="+state+"\n")
		snap := restart()
		env := stubExec(t)
		h := newProcess(t, snap, false)
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		f, _ := ln.(*net.TCPListener).File()
		h.page, h.pageLn = f, ln
		h.sessions = []carriedSession{{hash: sha("a"), idle: time.Second}, {hash: sha("b"), idle: time.Second}}
		if c.serve {
			carried = h
			st, err := serveCtl(t.Context(), shortDir(t), nil, &runOpts{}, nil, nil)
			carried = nil
			if err != nil {
				t.Fatal(err)
			}
			if c.end {
				endPage(st)
			}
		}
		h.failed(args, errors.New("boom"))
		var got []string
		for _, kv := range *env {
			if v, ok := strings.CutPrefix(kv, envSessions+"="); ok {
				got = strings.Split(v, ",")
			}
		}
		if len(got) != c.wantSessions {
			t.Errorf("%s: the retry carries %q", c.name, got)
		}
		ln.Close()
		f.Close()
	}
}

// oneConn is a listener that hands out conns, then waits until closed.
type oneConn struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *oneConn) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *oneConn) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *oneConn) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }

// A request already queued on the carried port when the page starts
// serving (the page's poll during the restart) finds its session there:
// the sessions are in place, under the page's lock, before it serves.
func TestCarriedPageSessionsBeforeServing(t *testing.T) {
	token := secret(32)
	srvEnd, cliEnd := net.Pipe()
	ln := &oneConn{conns: make(chan net.Conn, 1), done: make(chan struct{})}
	ln.conns <- srvEnd
	code := make(chan int, 1)
	go func() {
		fmt.Fprintf(cliEnd, "GET /api/state HTTP/1.1\r\nHost: 127.0.0.1:1\r\n%s: %s\r\nConnection: close\r\n\r\n", sessionHeader, token)
		res, err := http.ReadResponse(bufio.NewReader(cliEnd), nil)
		if err != nil {
			code <- 0
			return
		}
		code <- res.StatusCode
	}()
	carried = &handover{pageLn: ln, sessions: []carriedSession{{hash: sha(token), idle: time.Second}}}
	defer func() { carried = nil }()
	if _, err := serveCtl(t.Context(), shortDir(t), nil, &runOpts{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if c := <-code; c != http.StatusOK {
		t.Errorf("the queued poll: %d", c)
	}
}

// run's restart is in place before ctl.sock serves: a restart asked at once
// is never refused as one this run cannot make.
func TestCtlRestartBeforeServing(t *testing.T) {
	state := shortDir(t)
	if _, err := serveCtl(t.Context(), state, nil, &runOpts{}, func(string) {}, nil); err != nil {
		t.Fatal(err)
	}
	a, err := askRun(t.Context(), state, ctlRequest{Cmd: "restart"})
	if err != nil || strings.Contains(a.Message, "cannot restart itself") {
		t.Errorf("%v %q", err, a.Message)
	}
}

// stubRun stands in for run in runRestartable.
func stubRun(t *testing.T, f func(ctx context.Context) error) {
	t.Helper()
	runStart = func(ctx context.Context, _ []string) error { return f(ctx) }
	t.Cleanup(func() { runStart = run })
}

// A stop (Ctrl-C, a service's SIGTERM) is never undone by a restart: asked
// while run stops for one, no exec and the new snapshot removed; ending the
// start after one, no failed start (no config put back, no exec), the
// snapshot removed.
func TestRestartStopSignal(t *testing.T) {
	state := t.TempDir()
	start := "--device phone\n--state=" + state + "\n"
	_, config, args, restart := restartable(t, start)
	env := stubExec(t)
	*env = []string{"none"}
	stopped, stop := context.WithCancel(t.Context())
	stop()

	snap := restart()
	stubRun(t, func(context.Context) error { return &restartExec{snapshot: snap} })
	if err := runRestartable(stopped, args); err != nil || !slices.Equal(*env, []string{"none"}) || exists(snap) {
		t.Errorf("stopped while restarting: %v, exec'd %v, snapshot there %v", err, !slices.Equal(*env, []string{"none"}), exists(snap))
	}

	snap = restart()
	os.WriteFile(config, []byte(start+"--verbose\n"), 0o600)
	t.Setenv(envSnapshot, snap)
	stubRun(t, func(ctx context.Context) error { return fmt.Errorf("mitmproxy: %w", ctx.Err()) })
	if err := runRestartable(stopped, args); err == nil || !slices.Equal(*env, []string{"none"}) || exists(snap) || exists(config+".failed") || read(t, config) == start {
		t.Errorf("stopped while starting: %v, exec'd %v, snapshot there %v, config put back %v", err, !slices.Equal(*env, []string{"none"}), exists(snap), read(t, config) == start)
	}
}

// A start after a restart that has served restartGrace counts as good, ready
// or not (a node waiting for a login): a failure later neither puts the
// config back nor execs; the snapshot is gone.
func TestRestartGrace(t *testing.T) {
	state := t.TempDir()
	start := "--device phone\n--state=" + state + "\n"
	_, config, args, restart := restartable(t, start)
	env := stubExec(t)
	*env = []string{"none"}
	restartGrace = 20 * time.Millisecond
	t.Cleanup(func() { restartGrace = 2 * time.Minute })
	snap := restart()
	os.WriteFile(config, []byte(start+"--verbose\n"), 0o600)
	t.Setenv(envSnapshot, snap)
	stubRun(t, func(context.Context) error {
		carried.serving()
		for exists(snap) {
			time.Sleep(5 * time.Millisecond)
		}
		return errors.New("hours later")
	})
	done := make(chan error, 1)
	go func() { done <- runRestartable(t.Context(), args) }()
	select {
	case err := <-done:
		if err == nil || !slices.Equal(*env, []string{"none"}) || read(t, config) == start {
			t.Errorf("%v, exec'd %v, config put back %v", err, !slices.Equal(*env, []string{"none"}), read(t, config) == start)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the snapshot stays: the start never counted as good")
	}
}
