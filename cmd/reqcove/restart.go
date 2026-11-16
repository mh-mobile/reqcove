package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// `reqcove restart` (since v1.3; the console's local page asks the same op):
// run checks the config on disk and its command line as the next start would
// take them (checkFlags, nothing changed), that the binary it was started
// from is still there, and that this binary takes them too (its hidden
// `run --check-config` mode: a newer binary may check more; one without it,
// older than v1.3, is refused); then it stops as at Ctrl-C (the system proxy
// put back, mitmproxy, the node and caffeinate stopped: run returns, its
// defers run) and execs that binary again, with the same arguments and pid,
// so launchd, systemd and brew services see the same process. Across the
// exec go, in fds with close-on-exec cleared, the state's lock (no other run
// takes the state, or sweeps the snapshot, meanwhile) and the console page's
// listener (its port never let go), and in the environment their numbers, the
// page's sessions by hash (never a token) and the path of the start config's
// snapshot: the bytes run read from --config at its start, written at the
// restart to a private file in the state directory. A start after a restart
// that fails puts that config back (the failed one kept aside) and execs once
// more; that one failing too, run stays down. The new process unsets every
// handover variable and makes the fds close-on-exec again before anything
// else, so no child (mitmdump, caffeinate) gets them.

const (
	envSnapshot = "REQCOVE_RESTART_SNAPSHOT" // the start config's snapshot's path
	envListener = "REQCOVE_RESTART_LISTENER" // the page's listening socket's fd
	envLock     = "REQCOVE_RESTART_LOCK"     // the state lock's fd
	envSessions = "REQCOVE_RESTART_SESSIONS" // the page's sessions: local:HASH:IDLE_SECONDS,...
	envRetry    = "REQCOVE_RESTART_RETRY"    // 1: this start is the retry, never retried again
)

var handoverVars = []string{envSnapshot, envListener, envLock, envSessions, envRetry}

// snapshotName is a snapshot's name in the state directory; restartNote the
// file that says what came of a failed start after a restart (status shows it).
var snapshotName = regexp.MustCompile(`^restart-[0-9a-f]{32}\.config$`)

const restartNote = "restart-note"

// startBinary is what a restart execs, recorded at run's start (binaryPath);
// startBinaryErr why it is not known; startArgs run's arguments as given (the
// exec's, and the check's).
var (
	startBinary    string
	startBinaryErr error
	startArgs      []string
)

// checkConfigArg, first after run, makes run a check of its flags alone:
// the config and the command line after it, read as a start would read them
// (checkFlags: no lock, no file written, nothing started, nothing logged);
// exit 0, or 1 with the reason. Hidden: not one of run's flags,
// for a restart to ask the binary it would exec (binaryCheck).
const checkConfigArg = "--check-config"

// checkPrefix starts the check mode's reason, for binaryCheck to find.
const checkPrefix = "check-config: "

// checkConfigMode is run --check-config ARGS: a bare run's file when ARGS is
// empty, as run reads it.
func checkConfigMode(args []string) error {
	if len(args) == 0 {
		if p, _ := bareConfig(); p != "" {
			args = []string{"--config", p}
		}
	}
	if _, err := checkFlags(args, nil, nil); err != nil {
		return errors.New(checkPrefix + err.Error())
	}
	return nil
}

// checkTimeout is how long binaryCheck waits (under ctlWait: the answer
// goes out first).
var checkTimeout = 8 * time.Second

// binaryCheck runs startBinary's check mode with run's arguments. old: the
// binary has no such mode (older than v1.3): a restart refuses it, as it
// could not take on the state's lock carried across, nor retry.
func binaryCheck(ctx context.Context) (old bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, startBinary, append([]string{"run", checkConfigArg}, startArgs...)...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if err == nil {
		return false, nil
	}
	s := string(out)
	if strings.Contains(s, "flag provided but not defined: -check-config") {
		return true, nil
	}
	if i := strings.LastIndex(s, checkPrefix); i >= 0 {
		why, _, _ := strings.Cut(s[i+len(checkPrefix):], "\n")
		return false, errors.New(why)
	}
	if ctx.Err() != nil {
		return false, fmt.Errorf("it did not answer within %v", checkTimeout)
	}
	last := strings.TrimSpace(s)
	if i := strings.LastIndexByte(last, '\n'); i >= 0 {
		last = last[i+1:]
	}
	if len(last) > 300 {
		last = last[:300]
	}
	return false, fmt.Errorf("%v: %s", err, last)
}

// binaryPath is argv0 when absolute (launchd, systemd and brew services start
// run so), else the one PATH lookup, made absolute; never os.Executable (on
// Linux /proc/self/exe, already resolved to the Cellar path) nor a resolved
// link: Homebrew's opt path survives brew upgrade and brew cleanup.
func binaryPath(argv0 string) (string, error) {
	if filepath.IsAbs(argv0) {
		return argv0, nil
	}
	p, err := exec.LookPath(argv0)
	if err != nil {
		return "", err
	}
	return filepath.Abs(p) // lexical: no link resolved
}

// handover is what a restart carried into this process (none: a fresh start).
type handover struct {
	restarted bool     // a start after a restart (any handover variable set)
	retry     bool     // the retry of a failed one
	lock      *os.File // the state lock carried in
	adopted   bool     // lock is this run's state's: run's own lock
	page      *os.File // the page's socket carried in, kept for the next restart
	pageLn    net.Listener
	sessions  []carriedSession
	served    *page  // the page carried in, once served (carriedPage)
	snapPath  string // the snapshot, checked and read; "" for none
	snap      []byte
	why       string      // why there is no snapshot to retry with
	started   atomic.Bool // a good start, or the retry decided: once
	dropOnce  sync.Once
	grace     *time.Timer // serving's
}

type carriedSession struct {
	hash [32]byte
	idle time.Duration
}

// carried is this process's handover while run runs (nil: none, as in tests).
var carried *handover

// takeHandover reads the handover variables, unsets them, makes the fds they
// name close-on-exec, and reads the snapshot once its path checks out.
func takeHandover() *handover {
	v := map[string]string{}
	for _, k := range handoverVars {
		if s, ok := os.LookupEnv(k); ok {
			v[k] = s
		}
		os.Unsetenv(k)
	}
	h := &handover{restarted: v[envSnapshot] != "" || v[envListener] != "" || v[envLock] != "", retry: v[envRetry] == "1"}
	h.lock = carriedFD(v[envLock], "the state lock", syscall.S_IFREG)
	if f := carriedFD(v[envListener], "the page's port", syscall.S_IFSOCK); f != nil {
		ln, err := net.FileListener(f)
		if a, ok := addrOf(ln); err == nil && ok && a.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			h.page, h.pageLn = f, ln
		} else {
			if ln != nil {
				ln.Close()
			}
			f.Close()
			log.Print("restart: the page's port carried in is not one of 127.0.0.1: closed")
		}
	}
	switch {
	case h.pageLn != nil:
		h.sessions = parseSessions(v[envSessions])
	case v[envSessions] != "":
		log.Print("restart: the page's port did not come across: its sessions end (reqcove console opens a new page)")
	}
	if p := v[envSnapshot]; p != "" {
		b, err := readSnapshot(p)
		if err != nil {
			h.why = "the start config's snapshot " + p + " is not used (" + err.Error() + "): neither read nor removed"
			log.Print("restart: " + h.why)
		} else {
			h.snapPath, h.snap = p, b
		}
	} else if h.restarted {
		h.why = "no snapshot of the config run had started from (started from flags alone?)"
	}
	return h
}

func addrOf(ln net.Listener) (*net.TCPAddr, bool) {
	if ln == nil {
		return nil, false
	}
	a, ok := ln.Addr().(*net.TCPAddr)
	return a, ok
}

// carriedFD is fd v (decimal, 3 or more) as a file, made close-on-exec at once,
// when it is open and of kind (S_IFREG, S_IFSOCK); nil otherwise.
func carriedFD(v, what string, kind uint32) *os.File {
	if v == "" {
		return nil
	}
	fd, err := strconv.Atoi(v)
	if err != nil || fd < 3 {
		log.Printf("restart: %s: not a carried fd", what)
		return nil
	}
	syscall.CloseOnExec(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || uint32(st.Mode)&syscall.S_IFMT != kind {
		log.Printf("restart: %s did not come across", what)
		return nil
	}
	return os.NewFile(uintptr(fd), what)
}

// parseSessions reads envSessions: the local page's sessions alone, at most
// maxSessions; anything else is dropped.
func parseSessions(v string) []carriedSession {
	var out []carriedSession
	for s := range strings.SplitSeq(v, ",") {
		kind, rest, _ := strings.Cut(s, ":")
		hx, idle, _ := strings.Cut(rest, ":")
		b, err := hex.DecodeString(hx)
		secs, err2 := strconv.Atoi(idle)
		if kind != "local" || err != nil || len(b) != 32 || err2 != nil || secs < 0 || len(out) >= maxSessions {
			continue
		}
		out = append(out, carriedSession{hash: [32]byte(b), idle: time.Duration(secs) * time.Second})
	}
	return out
}

// uid is this user's (a seam: the tests' other user).
var uid = os.Getuid

// privateFile: fi is a plain file (no link) of this user's, mode 0600.
func privateFile(fi fs.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return errors.New("not a plain file")
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid() {
		return errors.New("not this user's")
	}
	if fi.Mode().Perm() != 0o600 {
		return errors.New("not mode 0600")
	}
	return nil
}

// snapshotCheck is why path is not a snapshot to trust: an absolute path
// named as one, directly in a reqcove state directory (its marker), a
// private file (privateFile).
func snapshotCheck(path string) (fs.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !snapshotName.MatchString(filepath.Base(path)) {
		return nil, errors.New("not a snapshot's name")
	}
	if fi, err := os.Lstat(filepath.Join(filepath.Dir(path), stateMarker)); err != nil || !fi.Mode().IsRegular() {
		return nil, errors.New("not in a reqcove state directory")
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("missing: another run swept its state directory?")
	}
	if err != nil {
		return nil, err
	}
	return fi, privateFile(fi)
}

// readSnapshot reads the snapshot at path once snapshotCheck passes, through
// no link and the file checked.
func readSnapshot(path string) ([]byte, error) {
	fi, err := snapshotCheck(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if now, err := f.Stat(); err != nil || !os.SameFile(fi, now) {
		return nil, errors.New("changed while read")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err == nil && len(b) > 1<<20 {
		err = errors.New("over 1 MiB")
	}
	return b, err
}

// writeSnapshot writes b to a new snapshot in dir: a random name, created
// exclusively through no link, 0600. Its path.
func writeSnapshot(dir string, b []byte) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "restart-"+secret(16)+".config")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.Write(b)
	if err = errors.Join(err, f.Close()); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// sweepSnapshots removes the snapshots in dir that a crash or a power loss
// left, after the same checks, but never keep (the one handed over); how many.
func sweepSnapshots(dir, keep string) int {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return 0
	}
	n := 0
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		if p == keep {
			continue
		}
		if _, err := snapshotCheck(p); err == nil && os.Remove(p) == nil {
			n++
		}
	}
	return n
}

// withLines is a config's text with lines added at its end, as the config
// writer adds them (the start config's snapshot follows capture save's @FILE line).
func withLines(text []byte, lines []string) []byte {
	out := slices.Clone(text)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	for _, l := range lines {
		out = append(out, l+"\n"...)
	}
	return out
}

// restoreConfig puts snap back as config: the file there now kept aside as
// config.failed, the new one written private (0600) beside it and renamed in
// place; never through a link.
func restoreConfig(config string, snap []byte) (aside string, err error) {
	fi, err := os.Lstat(config)
	switch {
	case err == nil && fi.Mode()&fs.ModeSymlink != 0:
		return "", fmt.Errorf("%s is a link: reqcove writes a plain file only", config)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(config), ".config.tmp*") // 0600
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // nothing once renamed
	_, err = tmp.Write(snap)
	if err == nil {
		err = tmp.Sync()
	}
	if err = errors.Join(err, tmp.Close()); err != nil {
		return "", err
	}
	if fi != nil {
		aside = config + ".failed"
		if err := os.Rename(config, aside); err != nil {
			return "", err
		}
	}
	if err := os.Rename(tmp.Name(), config); err != nil {
		if aside != "" {
			os.Rename(aside, config)
		}
		return "", err
	}
	return aside, nil
}

// configOf is the --config file run's arguments read (a bare run's file), absolute; "" for none.
func configOf(args []string) string {
	if len(args) == 0 {
		p, _ := bareConfig()
		return absPath(p)
	}
	if p, ok, _ := configFile(args); ok {
		return absPath(p)
	}
	return ""
}

// stateLock is run's lock of dir: the one a restart carried in when it is
// dir's (claimed again, as openState does), else a new one.
func stateLock(dir string) (*os.File, error) {
	if h := carried; h != nil && h.lock != nil {
		if err := claimState(dir); err != nil {
			return nil, err
		}
		held, err := h.lock.Stat()
		now, nowErr := os.Stat(filepath.Join(dir, "lock"))
		if err == nil && nowErr == nil && os.SameFile(held, now) && syscall.Flock(int(h.lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
			h.adopted = true
			return h.lock, nil
		}
	}
	return openStateFile(dir)
}

// ready is run's good start after a restart: the snapshot removed (no retry
// needed now), another state's lock let go.
func (h *handover) ready() {
	if h != nil && !h.started.Swap(true) {
		h.drop()
	}
}

// restartGrace is how long after ctl.sock and mcp.sock serve a start after a
// restart counts as good, ready or not (a node waiting for a login, a new
// --state): a failure later is no failed start, and keeps no snapshot or lock.
var restartGrace = 2 * time.Minute

// serving is run's ctl.sock and mcp.sock serving: ready once restartGrace
// has passed (runRestartable stops the timer when run returns).
func (h *handover) serving() {
	if h == nil || !h.restarted {
		return
	}
	h.grace = time.AfterFunc(restartGrace, func() {
		if !h.started.Swap(true) {
			log.Printf("restart: run has served for %v: the start counts as good (no retry now)", restartGrace)
			h.drop()
		}
	})
}

// drop removes the snapshot (checked again) and lets another state's lock go:
// once the retry is decided.
func (h *handover) drop() {
	h.dropOnce.Do(func() {
		if h.snapPath != "" {
			if _, err := snapshotCheck(h.snapPath); err == nil {
				os.Remove(h.snapPath)
			}
		}
		if h.lock != nil && !h.adopted {
			h.lock.Close()
		}
	})
}

// restartExec is run's answer when a restart was asked: what to carry
// across the exec. An error, so that run returns it after its defers.
type restartExec struct {
	lock, page *os.File
	sessions   []carriedSession
	snapshot   string
	retry      bool
}

func (*restartExec) Error() string { return "restart" }

// runStart is run (a seam: tests stand in for it).
var runStart = run

// runRestartable is `reqcove run`: run, and the exec when it returns for a
// restart; after a restart, the retry of a failed start. A stop (ctx: Ctrl-C,
// or a service's SIGTERM) is never undone: asked during a restart, no exec;
// ending a start after one, it is no failed start.
func runRestartable(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == checkConfigArg {
		return checkConfigMode(args[1:])
	}
	startBinary, startBinaryErr = binaryPath(os.Args[0])
	startArgs = args
	h := takeHandover()
	carried = h
	defer func() { carried = nil }()
	err := runStart(ctx, args)
	if h.grace != nil {
		h.grace.Stop()
	}
	var r *restartExec
	if errors.As(err, &r) {
		if ctx.Err() == nil {
			return execRestart(r)
		}
		log.Print("restart: run was told to stop while it restarted: it stays stopped")
		if _, err := snapshotCheck(r.snapshot); err == nil {
			os.Remove(r.snapshot)
		}
		h.drop()
		return nil
	}
	if !h.restarted || !h.started.CompareAndSwap(false, true) { // a good start: what ready decided stands
		return err
	}
	if err == nil || ctx.Err() != nil { // stopped before it was up: it stays down
		h.drop()
		return err
	}
	return h.failed(args, err)
}

// failed follows a start after a restart that failed: the config run had
// started from put back and one more exec, unless this was that one.
func (h *handover) failed(args []string, err error) error {
	note := func(msg string) {
		log.Print("restart: " + msg)
		if h.snapPath != "" {
			writePrivate(filepath.Join(filepath.Dir(h.snapPath), restartNote), []byte(msg+"\n"))
		}
	}
	if h.retry {
		was := ""
		if h.snapPath != "" {
			b, _ := os.ReadFile(filepath.Join(filepath.Dir(h.snapPath), restartNote))
			was = strings.TrimSpace(string(b)) + " "
		}
		note(was + "That start failed too (" + err.Error() + "): run stays down.")
		h.drop()
		return err
	}
	config := configOf(args)
	switch {
	case h.snapPath == "":
		log.Printf("restart: the start after a restart failed; no retry: %s", h.why)
		h.drop()
		return err
	case config == "":
		note("the start after a restart failed (" + err.Error() + "); no retry: no --config file in run's arguments to put back.")
		h.drop()
		return err
	}
	aside, rerr := restoreConfig(config, h.snap)
	if rerr != nil {
		note("the start after a restart failed (" + err.Error() + "); no retry: the config run had started from could not be put back in " + config + " (" + rerr.Error() + ").")
		h.drop()
		return err
	}
	kept := ""
	if aside != "" {
		kept = " (the one that failed kept as " + aside + ")"
	}
	note("the start after a restart failed (" + err.Error() + "); " + config + " is back as run had started from it" + kept + ", and run starts once more with it.")
	// The page's sessions as they are now: --end, or a session traded, while
	// it served; none if it never served.
	var sessions []carriedSession
	if h.served != nil {
		sessions = h.served.carry()
	}
	return execRestart(&restartExec{lock: h.lock, page: h.page, sessions: sessions, snapshot: h.snapPath, retry: true})
}

// sysExec is syscall.Exec (a seam: tests record what would be exec'd).
var sysExec = syscall.Exec

// execRestart execs startBinary with run's arguments and r carried; it
// returns only when the exec failed.
func execRestart(r *restartExec) error {
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		k, _, _ := strings.Cut(kv, "=")
		return slices.Contains(handoverVars, k)
	})
	var fds []int
	add := func(k string, f *os.File) {
		if f == nil {
			return
		}
		c, err := f.SyscallConn()
		if err != nil {
			return
		}
		c.Control(func(fd uintptr) { fds = append(fds, int(fd)); env = append(env, k+"="+strconv.Itoa(int(fd))) })
	}
	add(envLock, r.lock)
	add(envListener, r.page)
	if r.page != nil && len(r.sessions) > 0 {
		var ss []string
		for _, s := range r.sessions {
			ss = append(ss, fmt.Sprintf("local:%x:%d", s.hash, int(s.idle.Seconds())))
		}
		env = append(env, envSessions+"="+strings.Join(ss, ","))
	}
	if r.snapshot != "" {
		env = append(env, envSnapshot+"="+r.snapshot)
	}
	if r.retry {
		env = append(env, envRetry+"=1")
	}
	if startBinary == "" {
		return fmt.Errorf("restart: run is stopped, and not started again: the path it was started from is not known (%v)", startBinaryErr)
	}
	// No fork between clearing close-on-exec and the exec: a child started
	// meanwhile would get the fds.
	syscall.ForkLock.Lock()
	for _, fd := range fds {
		unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0)
	}
	err := sysExec(startBinary, os.Args, env)
	for _, fd := range fds {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.Unlock()
	return fmt.Errorf("restart: run is stopped, and %s did not start again: %v", startBinary, err)
}

// restartOp is the restart op (st.mu held): refused, with nothing stopped,
// unless the binary run started from is there and the config on disk and
// run's command line would start, as this run checks them and as that binary
// does (binaryCheck); else the start config's snapshot written, and the
// restart starts once the answer is sent (ctlAnswer.after).
func restartOp(ctx context.Context, st *ctlState, records any) ctlAnswer {
	refuse := func(why string) ctlAnswer { return ctlAnswer{Message: "refused: " + why + "; nothing stopped"} }
	if st.restart == nil {
		return refuse("this run cannot restart itself")
	}
	if startBinary == "" {
		return refuse(fmt.Sprintf("the path run was started from is not known (%v): stop it and start it again yourself", startBinaryErr))
	}
	if fi, err := os.Stat(startBinary); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return refuse(startBinary + ", which run was started from, is not there to start again (removed by an upgrade?): stop run and start it again yourself")
	}
	n, err := checkFlags(st.o.args, nil, nil)
	if err != nil {
		return refuse("the next start would refuse the settings (the --config file on disk and run's command line): " + err.Error())
	}
	old, err := binaryCheck(ctx)
	if err != nil {
		return refuse(startBinary + ", which a restart starts, refuses the settings (the --config file on disk and run's command line): " + err.Error())
	}
	if old { // its run would not take on the lock carried across: it would stay down
		return refuse(startBinary + ", which a restart starts, is older than v1.3 (it cannot take over the running state): stop run and start it again yourself")
	}
	snap := ""
	if st.o.config != "" {
		if snap, err = writeSnapshot(st.o.state, st.startConfig); err != nil {
			return refuse("the copy of the config run started from, kept until the next start is up, could not be written: " + err.Error())
		}
	}
	os.Remove(filepath.Join(st.o.state, restartNote))
	msg := fmt.Sprintf("restarting: run stops (the system proxy put back, mitmproxy and the node stopped) and %s starts again with the config on disk and the same command line; %s", startBinary, restartEmpties(records))
	if absPath(n.state) != absPath(st.o.state) {
		msg += "; the config names another --state now: " + n.state
	}
	if st.page != nil {
		msg += "; the console's page keeps its port and sessions"
	}
	msg += ". If the new start fails, run puts back the config it had started from and starts once more; " + withState("reqcove status", n.state) + " says how it went"
	log.Print("restart: asked; " + strings.TrimPrefix(msg, "restarting: "))
	return ctlAnswer{OK: true, Message: msg, after: func() { st.restart(snap) }}
}

// restartEmpties is what a restart loses, for its answer and the page's confirm.
func restartEmpties(records any) string {
	return fmt.Sprintf("the records (%v now) start empty, and devices lose the internet until it is up", records)
}

// restartCommand is `reqcove restart`, in a terminal only.
func restartCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("restart", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return restartIn(ctx, os.Stdin, os.Stdout, *state)
}

var errRestartNotTerminal = errors.New("reqcove restart runs only in a terminal: it empties the records and stops the devices' traffic for a moment, which is the user's choice (an agent never runs it). Run it in your own terminal")

func restartIn(ctx context.Context, in, out *os.File, state string) error {
	if !terminal(in) || !terminal(out) {
		return errRestartNotTerminal
	}
	return sendCapture(ctx, out, state, ctlRequest{Cmd: "restart"})
}
