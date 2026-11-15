// Package capture runs mitmproxy (mitmdump, SOCKS5 mode) as a child process
// with an embedded addon, and keeps the flows the addon sends in a Store.
package capture

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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
)

//go:embed addon.py
var addonPy []byte

// mitm.py and its lock run mitmproxy from exactly the files the lock names,
// hashes checked (uv run --locked; uvx checks none).
//
//go:embed mitm.py
var mitmPy []byte

//go:embed mitm.py.lock
var mitmLock []byte

// scriptFiles are what Start writes into the state directory for mitmproxy.
var scriptFiles = map[string][]byte{"addon.py": addonPy, "mitm.py": mitmPy, "mitm.py.lock": mitmLock, "mitm-overrides.txt": []byte(lockOverrides)}

// mitm.py's exclude-newer and override-dependencies (TestLockMeta keeps them
// in step), for the locked mitmproxy through uvx (a --uvx wrapper): the
// lock's tornado, not the older one mitmproxy 12.3.1 caps it at; the other
// packages from before UVExcludeNewer, as for another spec; no hashes.
const (
	lockExcludeNewer = "2026-11-14T00:00:00Z"
	lockOverrides    = "tornado>=6.6.1\n"
)

// LockedMitmSpec is the mitmproxy that mitm.py.lock pins. With another
// --mitmproxy-spec, mitmproxy comes through uvx, its files unchecked.
const LockedMitmSpec = "mitmproxy==12.3.1"

// PyCommand is how to run tool (mitmdump, mitmweb, or python) for cfg: from
// the lock with the uv beside uvx, or with uvx --from for another spec, or for
// a --uvx not named uvx (a wrapper, whose uv is not known).
func PyCommand(cfg Config, tool string) (string, []string) {
	if cfg.MitmSpec == LockedMitmSpec && filepath.Base(cfg.Uvx) == "uvx" {
		uv := filepath.Join(filepath.Dir(cfg.Uvx), "uv") // "uv" itself when uvx is on PATH
		return uv, []string{"run", "--locked", "--no-project", "--python", cfg.Python, "--script", filepath.Join(cfg.Dir, "mitm.py"), tool}
	}
	args := []string{"--python", cfg.Python, "--exclude-newer", UVExcludeNewer}
	if cfg.MitmSpec == LockedMitmSpec { // a wrapper: the lock's tornado
		args = append(args, "--exclude-newer-package", "tornado="+lockExcludeNewer, "--overrides", filepath.Join(cfg.Dir, "mitm-overrides.txt"))
	}
	args = append(args, "--from", cfg.MitmSpec, tool)
	if tool != "python" { // mitmdump and mitmweb through the launcher too, for the SOCKS socket (mitm.py)
		args = append(args[:len(args)-1], "python", filepath.Join(cfg.Dir, "mitm.py"), tool)
	}
	return cfg.Uvx, args
}

// Apple's services fail on HTTPS interception
// (https://support.apple.com/en-us/101555), so these pass through undecrypted.
// The same list as docs/apple-ignore-hosts.txt.
//
//go:embed apple-ignore-hosts.txt
var appleIgnoreHosts string

// AppleIgnored says host is on the Apple list mitmproxy passes through itself:
// a --pass-hosts host there is never recorded.
func AppleIgnored(host string) bool {
	for _, re := range strings.Split(strings.TrimSpace(appleIgnoreHosts), "\n") {
		if m, _ := regexp.MatchString(re, host+":443"); m {
			return true
		}
	}
	return false
}

// UVExcludeNewer: uv resolves mitmproxy's dependencies only from releases
// before this, the versions tested with it, so a release made later (a
// compromised one included) never runs with the CA key. Move it with MitmSpec.
const UVExcludeNewer = "2026-11-08T00:00:00Z"

type Config struct {
	Dir          string // private directory (0700) for the addon and its socket; keep the path short (macOS caps socket paths at 104 bytes)
	Confdir      string // mitmproxy confdir: the CA lives here
	Uvx          string // path to uvx
	Python       string // Python for uvx (zstd decoding needs 3.14)
	MitmSpec     string // uvx --from spec, e.g. "mitmproxy==12.3.1"
	BodyHead     int    // decoded bytes of each body kept
	MaxFlows     int
	MaxBytes     int
	Log          io.Writer // mitmdump's stdout and stderr; errors only (termlog_verbosity=error)
	ReadyTimeout time.Duration
	AllowHosts   HostRules                     // hosts decrypted and recorded; the zero value records nothing
	NoRedact     bool                          // keep secrets in the records (--no-redact)
	CAName       string                        // name of a CA made for this confdir (mitmproxy's own is just "mitmproxy"); empty: mitmproxy's default
	WebPort      int                           // run mitmweb on 127.0.0.1:WebPort instead of mitmdump (--web); 0: mitmdump
	WebPassword  string                        // with WebPort: mitmweb's password (run keeps it in the state directory)
	Rules        string                        // --rules file (absolute); the addon loads it on every (re)start
	RulesReload  bool                          // --rules-reload: the addon also takes the file again whenever it changes
	Upstream     string                        // host:port of an HTTP proxy decrypted requests go on to (--upstream-proxy); empty: none
	UpstreamCA   string                        // PEM file of the upstream's CA, the only CA trusted then (--upstream-ca); empty: the public CAs
	RestartDelay time.Duration                 // first wait before restarting mitmdump, doubled each time up to maxRestartDelay; 0 means 1s
	Logf         func(format string, a ...any) // restarts are reported here; nil is quiet
	webMaxFlows  int                           // tests: fewer flows kept in mitmweb than its default
	trustCA      string                        // tests: the one CA mitmproxy trusts upstream, as with --upstream-ca, without an upstream proxy
}

// WebKeep is the largest body (on the wire) given to mitmweb whole (--web).
const WebKeep = 2 << 20

// mitmdump is restarted when it exits, after RestartDelay doubled for each
// failure in a row, at most maxRestartDelay, with no limit on the attempts; a
// run that stayed up for stableAfter resets the count.
const (
	maxRestartDelay = 5 * time.Minute
	stableAfter     = time.Minute
	// drainWait bounds how long an exited mitmdump's lines, still in its
	// socket, are waited for before its open flows are closed.
	drainWait = 2 * time.Second
)

type Capture struct {
	Store       *Store
	SocksAddr   string // 127.0.0.1:port of mitmdump's SOCKS5 listener; reqcove holds it for the whole run (socks)
	SocksSecret string // the SOCKS5 password; any user name (reqcove sends the device's StableID)
	WebURL      string // with WebPort: mitmweb's address, with its password as the token
	CA          CA     // the CA iPhones must trust

	cfg    Config
	bin    string   // uv, or uvx
	args   []string // mitmdump's, but the scope's (mitmArgs adds them)
	ln     net.Listener
	socks  *os.File // the SOCKS5 listener, bound by Start and handed to each mitmdump as fd 3: its port is never free while mitmdump restarts
	cancel context.CancelFunc
	done   chan struct{}
	upMu   sync.Mutex
	up     chan struct{} // closed while a mitmdump that said hello runs; replaced when it exits
	// wasUp: a mitmdump of this run said hello, so its options work: a later
	// one that cannot start or exits before its hello is retried, not given up on.
	wasUp   bool
	err     error
	readers atomic.Int64 // ingest connections still being read

	// The scope (SetScope). scopeMu orders the changes and spawn's use of
	// them: want is the base scope asked for last, the one a new mitmdump
	// starts with, and at most one overlay over it: stopped (SetStopped:
	// nothing recorded, no rule applies) or allow-all until allUntil
	// (SetAllowAll: every host recorded; zero when off); storeGen the newest
	// generation the Store has; instance names the mitmdump spawned last,
	// whose answers alone count, proc is it, and instAll says whether it was
	// started with allow-all on.
	scopeMu   sync.Mutex
	want      HostRules
	stopped   bool
	allUntil  time.Time // with its monotonic reading: see expire
	wantGen   int64
	storeGen  int64
	instance  string
	proc      *proc
	instAll   bool
	instDisc  bool       // and whether with discovery on
	loggedGen int64      // the generation whose retry failure was logged last
	ackMu     sync.Mutex // acked alone, for status: never held across a call to mitmdump
	acked     HostRules  // what mitmdump acknowledged last
	ackStop   bool       // and whether stopped
	ackAll    time.Time  // and allow-all's end (zero: off)
	pending   string     // ScopePending
	changeAt  time.Time  // LastChange
	change    string
	// reloadRules, set by Reload for its one scope op: the rules file the
	// addon loads and puts in force with the scope; loaded, what it answered.
	reloadRules string
	loaded      map[string]int
	discUntil   time.Time // discovery's end (SetDiscover), with its monotonic reading; zero when off
	discAck     bool      // under ackMu: the mitmdump spawned last has discovery on (DiscoverUntil)
}

// proc is one mitmdump process.
type proc struct {
	cmd   *exec.Cmd
	done  chan struct{}
	err   error
	ready time.Time
}

// stop ends mitmdump (and uvx above it): SIGTERM to the group, SIGKILL after 5s.
func (p *proc) stop() {
	syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
	}
}

// rulesCopy is the private copy (0600, in Dir) of the --rules file as it last
// loaded: written at Start, replaced by the addon when --rules-reload takes the
// file again (and by Reload), and what a restarted mitmdump loads, never the
// file on disk, which may be broken by then. rulesCopy+".new" is the addon's
// while it checks; reloadCopy, Reload's.
const (
	rulesCopy  = "rules-loaded"
	reloadCopy = "rules-reload"
)

// permanent marks a failure that trying again cannot mend: Start returns it,
// supervise ends with it.
type permanent struct{ error }

func (p permanent) Unwrap() error { return p.error }

func isPermanent(err error) bool { return errors.As(err, new(permanent)) }

// restartWait is the wait before the n-th attempt in a row (n >= 1).
func restartWait(base time.Duration, n int) time.Duration {
	return min(base<<min(n-1, 20), maxRestartDelay) // the shift bounded: an unbounded one overflows to a negative wait
}

// Start launches mitmdump, returns once its addon has said hello, and keeps
// restarting it when it exits. At the start, an addon that does not say hello
// within ReadyTimeout is tried again (a slow machine, or uv still downloading);
// other failures are returned (see spawn).
func Start(ctx context.Context, cfg Config) (*Capture, error) {
	if cfg.RestartDelay == 0 {
		cfg.RestartDelay = time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	sock := filepath.Join(cfg.Dir, "ingest.sock")
	killStale(cfg.Dir, sock)
	os.Remove(sock) // callers hold the state directory lock, so a socket here is stale
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	os.Chmod(sock, 0o600) // the directory is 0700 already; this keeps the socket private on its own too
	var socks *os.File
	fail := func(err error) (*Capture, error) {
		ln.Close()
		if socks != nil {
			socks.Close()
		}
		os.Remove(sock)
		os.Remove(filepath.Join(cfg.Dir, "socks-secret"))
		for f := range scriptFiles {
			os.Remove(filepath.Join(cfg.Dir, f))
		}
		removeRulesCopy(cfg.Dir)
		return nil, err
	}
	addon := filepath.Join(cfg.Dir, "addon.py")
	for f, b := range scriptFiles {
		if err := os.WriteFile(filepath.Join(cfg.Dir, f), b, 0o600); err != nil {
			return fail(err)
		}
	}
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fail(err)
	}
	port := socksLn.Addr().(*net.TCPAddr).Port
	socks, err = socksLn.(*net.TCPListener).File() // a dup: the socket outlives socksLn
	socksLn.Close()
	if err != nil {
		return fail(err)
	}
	// A new SOCKS5 password each run, in a file (not argv, which ps shows).
	secret := rand.Text()
	secretFile := filepath.Join(cfg.Dir, "socks-secret")
	if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
		return fail(err)
	}
	removeRulesCopy(cfg.Dir) // a killed run's
	if cfg.Rules != "" {
		b, err := os.ReadFile(cfg.Rules)
		if err != nil {
			return fail(fmt.Errorf("--rules: %w", err))
		}
		if err := os.WriteFile(filepath.Join(cfg.Dir, rulesCopy), b, 0o600); err != nil {
			return fail(err)
		}
	}
	if cfg.CAName != "" {
		if err := ensureCA(ctx, cfg); err != nil {
			return fail(fmt.Errorf("making the CA: %w", err))
		}
	}
	// mitmweb's password goes in confdir/config.yaml (0600), which mitmproxy
	// reads at start; never in argv. mitmdump gets no config file.
	webConfig := filepath.Join(cfg.Confdir, "config.yaml")
	if cfg.Confdir != "" {
		os.Remove(webConfig) // a password left by a --web run that did not stop cleanly
		// mitmproxy also reads config.yml, which reqcove never writes: options
		// in it (proxyauth, scripts) must not come from anyone else.
		os.Remove(filepath.Join(cfg.Confdir, "config.yml"))
	}
	var webURL string
	if cfg.WebPort != 0 {
		if cfg.Confdir == "" {
			return fail(errors.New("--web needs a confdir"))
		}
		pw := cfg.WebPassword
		if pw == "" {
			return fail(errors.New("--web needs a password"))
		}
		if err := os.MkdirAll(cfg.Confdir, 0o700); err != nil {
			return fail(err)
		}
		if err := os.WriteFile(webConfig, []byte("web_password: "+pw+"\n"), 0o600); err != nil {
			return fail(err)
		}
		webURL = fmt.Sprintf("http://127.0.0.1:%d/?token=%s", cfg.WebPort, pw)
	}
	c := &Capture{Store: NewStore(cfg.MaxFlows, cfg.MaxBytes), SocksAddr: fmt.Sprintf("127.0.0.1:%d", port), SocksSecret: secret, WebURL: webURL,
		cfg: cfg, ln: ln, socks: socks, done: make(chan struct{}), up: make(chan struct{}),
		want: cfg.AllowHosts, acked: cfg.AllowHosts}
	c.Store.SetScope(cfg.AllowHosts, !cfg.NoRedact)
	go c.accept()

	tool := "mitmdump"
	if cfg.WebPort != 0 {
		tool = "mitmweb"
	}
	c.bin, c.args = PyCommand(cfg, tool)
	c.args = append(c.args,
		"--mode", "socks5", "--listen-host", "127.0.0.1", "--listen-port", fmt.Sprint(port),
		"--set", "confdir="+cfg.Confdir,
		"--set", "proxyauth=any",
		// Bodies stream through the addon's callables; store_streamed_bodies
		// would buffer them in mitmproxy anyway. -q equivalent: errors only.
		"--set", "flow_detail=0", "--set", "termlog_verbosity=error",
		"--set", fmt.Sprintf("reqcove_body_head=%d", cfg.BodyHead),
		"-s", addon, "--set", "reqcove_socket="+sock, "--set", "reqcove_control="+filepath.Join(cfg.Dir, ControlSock),
		"--set", "reqcove_secret_file="+secretFile)
	if cfg.Rules != "" {
		c.args = append(c.args, "--set", "reqcove_rules="+cfg.Rules, "--set", "reqcove_rules_copy="+filepath.Join(cfg.Dir, rulesCopy))
		if cfg.RulesReload {
			c.args = append(c.args, "--set", "reqcove_rules_reload=true")
		}
	}
	if cfg.Upstream != "" {
		// lazy: otherwise mitmproxy connects to the server itself first, around the upstream.
		c.args = append(c.args, "--set", "reqcove_upstream="+cfg.Upstream, "--set", "connection_strategy=lazy")
		if cfg.UpstreamCA != "" {
			c.args = append(c.args, "--set", "ssl_verify_upstream_trusted_ca="+cfg.UpstreamCA)
		}
	}
	if cfg.trustCA != "" {
		c.args = append(c.args, "--set", "ssl_verify_upstream_trusted_ca="+cfg.trustCA)
	}
	if cfg.WebPort != 0 {
		c.args = append(c.args, "--set", "web_host=127.0.0.1", "--set", fmt.Sprintf("web_port=%d", cfg.WebPort), "--set", "web_open_browser=false")
		// mitmweb keeps no streamed body: the addon gives it each one up to
		// WebKeep, and drops its oldest flows past its own bounds.
		c.args = append(c.args, "--set", fmt.Sprintf("reqcove_web_keep=%d", WebKeep))
		if cfg.webMaxFlows > 0 {
			c.args = append(c.args, "--set", fmt.Sprintf("reqcove_web_max_flows=%d", cfg.webMaxFlows))
		}
	}
	for _, re := range strings.Split(strings.TrimSpace(appleIgnoreHosts), "\n") {
		c.args = append(c.args, "--ignore-hosts", re)
	}

	p, err := c.spawn(ctx)
	fails := 0
	for ; err != nil; p, err = c.spawn(ctx) {
		if fails++; isPermanent(err) || ctx.Err() != nil || !c.retryWait(ctx, err, fails) {
			return fail(err)
		}
	}
	c.CA, _ = ReadCA(cfg.Confdir) // mitmproxy has made it by now if it was missing
	ctx, c.cancel = context.WithCancel(ctx)
	go c.supervise(ctx, p, fails)
	go c.expireLoop(ctx)
	return c, nil
}

func removeRulesCopy(dir string) {
	os.Remove(filepath.Join(dir, rulesCopy))
	os.Remove(filepath.Join(dir, rulesCopy+".new"))
	os.Remove(filepath.Join(dir, reloadCopy))
}

// retryWait notes err, the n-th failure in a row, and waits before the next
// attempt; false if ctx ended first.
func (c *Capture) retryWait(ctx context.Context, err error, n int) bool {
	delay := restartWait(c.cfg.RestartDelay, n)
	c.Store.retrying(err.Error(), n, time.Now().Add(delay))
	c.cfg.Logf("%v; starting it again in %v (retry %d)", err, delay, n)
	select {
	case <-ctx.Done():
		return false
	case <-time.After(delay):
		return true
	}
}

// spawn starts one mitmdump and waits for its addon's hello. Its failures are
// permanent (retrying cannot mend them) when the rules do not load, and, until
// a mitmdump of this run has said hello, when it cannot be launched or exits
// before its hello (bad options, spec or Python). The others are transient:
// no hello within ReadyTimeout, and once one has come up, any other.
func (c *Capture) spawn(ctx context.Context) (*proc, error) {
	before := c.Store.helloCount()
	c.scopeMu.Lock()
	c.instance, c.instAll, c.instDisc = rand.Text(), c.allOn(), !c.discUntil.IsZero()
	c.setDiscAck(false) // until its hello
	args := c.mitmArgs()
	c.scopeMu.Unlock()
	p := &proc{cmd: exec.Command(c.bin, args...), done: make(chan struct{})}
	p.cmd.Stdout, p.cmd.Stderr = c.cfg.Log, c.cfg.Log
	p.cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1", "REQCOVE_SOCKS_FD=3") // PYTHONUNBUFFERED: mitmproxy.log as it happens, not when Python's buffer fills
	p.cmd.ExtraFiles = []*os.File{c.socks}                                       // fd 3: the addon serves SOCKS5 on it
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := p.cmd.Start(); err != nil {
		if !c.wasUp {
			err = permanent{err}
		}
		return nil, err
	}
	c.scopeMu.Lock()
	c.proc = p // for endAllLocked to restart
	c.scopeMu.Unlock()
	// If reqcove dies without Stop (SIGKILL, a crash), mitmdump outlives it
	// in its own process group; the next Start stops it (killStale).
	os.WriteFile(filepath.Join(c.cfg.Dir, "mitmdump.pid"), []byte(strconv.Itoa(p.cmd.Process.Pid)), 0o600)
	go func() {
		p.err = p.cmd.Wait()
		close(p.done)
	}()
	deadline := time.After(c.cfg.ReadyTimeout)
	for c.Store.helloCount() == before {
		select {
		case <-ctx.Done():
			p.stop()
			return nil, ctx.Err()
		case <-p.done:
			err := fmt.Errorf("mitmdump exited before its addon said hello: %v", p.err)
			if !c.wasUp {
				err = permanent{err}
			}
			return nil, err
		case <-deadline:
			p.stop()
			return nil, fmt.Errorf("mitmdump's addon did not say hello within %v", c.cfg.ReadyTimeout)
		case <-time.After(100 * time.Millisecond):
		}
	}
	// Never without its rules: a mock or map_remote lost would send test
	// requests to the real servers. A restarted one loads rulesCopy, the
	// rules that loaded last; those failing now (a file they name is gone)
	// end the run too.
	if e := c.Store.helloRulesError(); e != "" {
		p.stop()
		if c.wasUp {
			return nil, permanent{fmt.Errorf("--rules: the rules that loaded last no longer load (%s)", e)}
		}
		return nil, permanent{fmt.Errorf("--rules: %s", e)}
	}
	c.syncScope(ctx)
	p.ready = time.Now()
	c.wasUp = true
	c.Store.setState("ready", "")
	c.setUp(true)
	return p, nil
}

// mitmArgs is mitmdump's arguments with the scope asked for last and its
// generation, so a restarted mitmdump keeps a change, a stop or allow-all too
// (allow-all until it ends; never in c.args) (and the Store's gate takes
// what it admits). The addon gets the base (its rules are checked against
// it), mitmproxy the effective allow_hosts. Called with scopeMu held.
func (c *Capture) mitmArgs() []string {
	hosts, _ := json.Marshal(addonHosts(c.want))
	args := append(slices.Clone(c.args), "--set", "reqcove_allow_hosts="+string(hosts),
		"--set", fmt.Sprintf("reqcove_scope_gen=%d", c.wantGen), "--set", "reqcove_instance="+c.instance)
	if c.stopped {
		args = append(args, "--set", "reqcove_stopped=true")
	}
	if c.allOn() {
		args = append(args, "--set", "reqcove_allow_all=true")
	}
	if !c.discUntil.IsZero() {
		args = append(args, "--set", "reqcove_discover=true")
	}
	for _, re := range mitmAllow(effective(c.want, c.stopped, c.allOn())) {
		args = append(args, "--allow-hosts", re) // per connection: others pass through undecrypted
	}
	return args
}

// allOn: allow-all is asked for. Called with scopeMu held.
func (c *Capture) allOn() bool { return !c.allUntil.IsZero() }

// mitmAllow is mitmproxy's allow_hosts for the effective scope r: while
// stopped mitm.it alone, never empty, which decrypts everything (Apple's
// still ignored); "*" (r.All, allow-all too) the empty list.
func mitmAllow(r HostRules) []string {
	if allow := r.mitmAllowHosts(); allow != nil {
		return allow
	}
	return []string{}
}

// effective is the scope recorded: none while stopped; with allow-all every
// host, the base's --pass-hosts still passed undecrypted; else the base.
func effective(base HostRules, stopped, all bool) HostRules {
	switch {
	case stopped:
		return HostRules{}
	case all && !base.All:
		r, _ := HostRules{All: true, Hosts: []string{"*"}}.WithPass(base.PassHosts) // parsed before: no error
		return r
	}
	return base
}

// What status's recording and capture_stats' say.
const (
	RecordingOn       = "on"
	RecordingStopped  = "stopped"
	RecordingAllowAll = "allow-all"
)

func recording(stopped, all bool) string {
	switch {
	case stopped:
		return RecordingStopped
	case all:
		return RecordingAllowAll
	}
	return RecordingOn
}

// addonHosts is the addon's reqcove_allow_hosts: the hosts it records.
func addonHosts(r HostRules) map[string]any {
	return map[string]any{"all": r.All, "patterns": r.Patterns, "pass": r.Pass}
}

// syncScope, after a mitmdump's hello: one started with the scope asked for
// last has acknowledged it; one started before that change is told it again
// (a failure leaves it pending, as SetScope's), and discovery likewise.
func (c *Capture) syncScope(ctx context.Context) {
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	inst, gen := c.Store.helloScope()
	switch {
	case inst != c.instance: // a stand-in for mitmdump, in tests: none to compare
		return
	case gen == c.wantGen:
		c.appliedLocked()
	default:
		c.retryScopeLocked(ctx)
	}
	on := !c.discUntil.IsZero()
	if on == c.instDisc { // as it was started
		c.setDiscAck(on)
		return
	}
	err := c.discoverOp(ctx, on) // changed while it started
	c.setDiscAck(on && err == nil)
	if err != nil {
		c.cfg.Logf("host discovery (on: %v) is not applied yet: %v", on, err)
	}
}

// retryScopeLocked tells the mitmdump spawned last the scope asked for last
// again; one started with allow-all, ended since, that does not take it is
// killed: never left on.
func (c *Capture) retryScopeLocked(ctx context.Context) {
	if err := c.applyLocked(ctx); err != nil {
		if c.loggedGen != c.wantGen { // once a generation: retryPending tries every few seconds
			c.loggedGen = c.wantGen
			c.cfg.Logf("the scope asked for (generation %d) is not applied yet: %v", c.wantGen, err)
		}
		if c.instAll && !c.allOn() {
			c.killLocked()
		}
	}
}

// retryPending, every few seconds (expireLoop): what is pending (the scope,
// discovery on) is told the mitmdump spawned last again, so a change whose
// answer was lost does not wait for its next hello.
func (c *Capture) retryPending(ctx context.Context) {
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	if c.ScopePending() != "" {
		c.retryScopeLocked(ctx)
	}
	if !c.discUntil.IsZero() && !c.discAcked() {
		c.setDiscAck(c.discoverOp(ctx, true) == nil)
	}
}

// What ScopePending says of a scope asked for and not acknowledged yet.
const (
	PendingNarrowed = "narrowed in reqcove's records, mitmproxy not told yet"
	PendingAsked    = "asked, not acknowledged by mitmproxy yet"
)

// Scope is the base scope mitmproxy has acknowledged (what is recorded
// unless Stopped): what status shows.
func (c *Capture) Scope() HostRules {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	return c.acked
}

// Stopped says whether mitmproxy has acknowledged a stop (SetStopped) that
// no start has ended.
func (c *Capture) Stopped() bool {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	return c.ackStop
}

// AllowAllUntil is when the allow-all mitmproxy has acknowledged ends; zero
// when off.
func (c *Capture) AllowAllUntil() time.Time {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	return c.ackAll
}

// Recorded is the scope mitmproxy has acknowledged with its overlay: none
// while stopped, every host (but --pass-hosts) during allow-all, else Scope.
func (c *Capture) Recorded() HostRules {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	return effective(c.acked, c.ackStop, !c.ackAll.IsZero())
}

// ScopePending is "" when the scope asked for last is the one acknowledged
// (Scope), else PendingNarrowed or PendingAsked.
func (c *Capture) ScopePending() string {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	return c.pending
}

// SetScope changes the hosts recorded (and decrypted, on new connections:
// open ones keep how they were carried) without restarting mitmdump. The
// addon first checks the rules in force against r: a mock or resolve naming
// a host r leaves out refuses it, and nothing changes. Then a change that
// takes anything out applies to the Store first (an event of a host left out
// is no longer recorded, even if mitmdump is not told), then to mitmdump; one
// that only adds applies to mitmdump first, and to the Store once it
// acknowledged. An error after the check leaves the change pending
// (ScopePending; the error wraps ErrPending): a mitmdump started later gets
// it, and one that says hello again is told it again. Any other error: nothing
// changed.
func (c *Capture) SetScope(ctx context.Context, r HostRules) error {
	return c.ChangeScope(ctx, "", func(HostRules, string) (HostRules, error) { return r, nil })
}

// ErrPending: a change was taken, but mitmdump has not acknowledged it yet.
var ErrPending = errors.New("the change is pending")

// ChangeScope is SetScope of what f makes of the base scope asked for last
// (a pending one included), under the lock every change takes, so two never
// undo each other. f is also told the overlay (Recording*): while stopped or
// allow-all, the base changes, what is recorded once the overlay ends. An
// error of f is returned as it is, and nothing changes. why, when not "", is
// kept with the time once the change is taken (applied or pending):
// LastChange.
func (c *Capture) ChangeScope(ctx context.Context, why string, f func(base HostRules, recording string) (HostRules, error)) error {
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	r, err := f(c.want, recording(c.stopped, c.allOn()))
	if err != nil {
		return err
	}
	var ack scopeAck
	if err := c.control(ctx, scopeOp(r, c.wantGen+1, true, c.stopped, c.allOn()), &ack); err != nil {
		return notChecked(err) // or refused: the rules' conflicts
	}
	return c.changeLocked(ctx, why, r, c.stopped, c.allUntil)
}

// notChecked is a check's error: one mitmproxy did not answer (restarting)
// says to try again, as nothing is taken meanwhile (a change cannot be
// checked against the rules then).
func notChecked(err error) error {
	switch {
	case errors.Is(err, ErrNoControl):
		return errors.New("mitmproxy is restarting: try again in a moment; nothing changed")
	case errors.Is(err, ErrUncertain):
		return errors.New("mitmproxy did not answer in time (restarting?): try again in a moment; nothing changed")
	}
	return err
}

// Reload is reqcove reload: base r and, when rules is not nil, the --rules
// file's new bytes, both or neither. The addon checks the new rules against r
// (never the rules in force: a host and the mock naming it go out together),
// then gets both in one scope op, so no request meets one without the other.
// The private copy (rulesCopy) holds the new rules before that op: a mitmdump
// restarted meanwhile starts with them and r (mitmArgs), never one without
// the other; a refusal puts the old copy back. New rules turn every preset
// off. loaded is the rules by kind, as the addon loaded them (nil without
// rules). Errors are ChangeScope's: ErrPending, the change taken; else
// nothing changed. The addon's event loop serializes this op with
// --rules-reload's look at the file.
func (c *Capture) Reload(ctx context.Context, why string, r HostRules, rules []byte) (loaded map[string]int, err error) {
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	op := scopeOp(r, c.wantGen+1, true, c.stopped, c.allOn())
	copyPath, staged := filepath.Join(c.cfg.Dir, rulesCopy), filepath.Join(c.cfg.Dir, reloadCopy)
	if rules != nil {
		if c.cfg.Rules == "" {
			return nil, errors.New("this run has no --rules file")
		}
		defer os.Remove(staged)
		if err := os.WriteFile(staged, rules, 0o600); err != nil {
			return nil, err
		}
		op["rules_file"] = staged
	}
	var ack scopeAck
	if err := c.control(ctx, op, &ack); err != nil {
		return nil, notChecked(err) // or refused: why the rules do not load, or name hosts r leaves out
	}
	var old []byte
	if rules != nil {
		if old, err = os.ReadFile(copyPath); err != nil {
			return nil, err
		}
		if err := os.Rename(staged, copyPath); err != nil {
			return nil, err
		}
		c.reloadRules, c.loaded = copyPath, nil
	}
	err = c.changeLocked(ctx, why, r, c.stopped, c.allUntil)
	if errors.Is(err, ErrPending) && rules != nil {
		// mitmdump may not have the new rules, and retryPending would tell it
		// the hosts alone: never one without the other. The next one starts
		// with both (mitmArgs, rulesCopy).
		c.cfg.Logf("reqcove reload: mitmproxy did not acknowledge the new hosts and rules (%v): restarting it with both", err)
		c.killLocked()
	}
	c.reloadRules = ""
	if errors.As(err, new(*refusal)) && rules != nil { // the scope went back (changeLocked): the rules too
		if werr := os.WriteFile(copyPath, old, 0o600); werr != nil {
			c.cfg.Logf("the rules that loaded last could not be put back in %s: %v", copyPath, werr)
		}
	}
	if rules == nil {
		return nil, err
	}
	return c.loaded, err
}

// ErrUnchanged: SetStopped found capture stopped (or started) already;
// SetAllowAll, every host recorded already ("*"); EndAllowAll, allow-all off.
var ErrUnchanged = errors.New("unchanged")

// ErrStopped: SetAllowAll while stopped (the overlays exclude each other).
var ErrStopped = errors.New("recording is stopped")

// MaxAllowAll bounds SetAllowAll's d.
const MaxAllowAll = 24 * time.Hour

// SetAllowAll records every host (but the base's --pass-hosts, and Apple's,
// which mitmproxy ignores) for d, at most MaxAllowAll, from now: until, by
// this process's monotonic clock or the wall clock, whichever comes first
// (expire). The base does not change, and the rules are checked and applied
// against it alone. On already, its end moves to now+d (was: the end before).
// mitmproxy first, then the Store (a widening): ErrPending while mitmproxy has
// not acknowledged it. Never kept past a restart of run (it is in no file),
// nor past its end in a restarted mitmdump (mitmArgs).
func (c *Capture) SetAllowAll(ctx context.Context, why string, d time.Duration) (until, was time.Time, err error) {
	if d <= 0 || d > MaxAllowAll {
		return time.Time{}, time.Time{}, fmt.Errorf("allow-all lasts more than 0 and at most %v, not %v", MaxAllowAll, d)
	}
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	switch {
	case c.stopped:
		return time.Time{}, time.Time{}, ErrStopped
	case c.want.All:
		return time.Time{}, time.Time{}, ErrUnchanged
	}
	until, was = time.Now().Add(d), c.allUntil
	if c.allOn() { // the same scope: its end alone moves
		c.allUntil = until
		c.ackMu.Lock()
		if !c.ackAll.IsZero() {
			c.ackAll = until
		}
		c.changeAt, c.change = time.Now(), why
		c.ackMu.Unlock()
		return until, was, nil
	}
	return until, was, c.changeLocked(ctx, why, c.want, false, until)
}

// EndAllowAll ends allow-all now, as its time running out does (expire):
// ErrUnchanged when off; ErrPending when mitmproxy was not told (it is then
// restarted without it).
func (c *Capture) EndAllowAll(ctx context.Context, why string) error {
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	if !c.allOn() {
		return ErrUnchanged
	}
	return c.endAllLocked(ctx, why)
}

// endAllLocked ends allow-all, failing closed: the Store first (nothing
// outside the base is recorded from now), then mitmproxy; one that does not
// acknowledge it (silent, restarting, refusing) is killed, and the one
// supervise starts next has no allow-all (mitmArgs). The records made
// meanwhile stay. Never checked against the rules: the base is unchanged.
func (c *Capture) endAllLocked(ctx context.Context, why string) error {
	c.allUntil = time.Time{}
	c.wantGen++
	c.toStoreLocked()
	c.setPending(PendingNarrowed)
	c.ackMu.Lock()
	c.changeAt, c.change = time.Now(), why
	c.ackMu.Unlock()
	if err := c.applyLocked(ctx); err != nil {
		c.cfg.Logf("allow-all ended in reqcove's records, mitmproxy not told (%v): restarting it without allow-all", err)
		c.killLocked()
		return fmt.Errorf("mitmproxy restarted without allow-all: %w", ErrPending)
	}
	return nil
}

// killLocked kills the mitmdump spawned last, if it still runs: supervise
// starts the next one with the scope asked for now.
func (c *Capture) killLocked() {
	if p := c.proc; p != nil {
		select {
		case <-p.done:
		default:
			syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		}
	}
}

// expire ends allow-all once mono (with a monotonic reading) or wall (the
// wall clock) reaches its end, whichever first: the monotonic clock stops
// while the computer sleeps (macOS, Linux), so by it the end would come that
// much late; the wall clock can be set back.
func (c *Capture) expire(ctx context.Context, mono, wall time.Time) {
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	if !c.discUntil.IsZero() && due(c.discUntil, mono, wall) { // discovery likewise
		c.cfg.Logf("host discovery ended: its time is up (%s); the names seen stay until run restarts", c.discUntil.Round(0).Format(time.RFC3339))
		c.endDiscoverLocked(ctx, "host discovery ended: its time is up")
	}
	if !c.allOn() || !due(c.allUntil, mono, wall) {
		return
	}
	c.cfg.Logf("allow-all ended: its time is up (%s); the records made meanwhile stay", c.allUntil.Round(0).Format(time.RFC3339))
	c.endAllLocked(ctx, "allow-all ended: its time is up")
}

// expireLoop calls expire every second, and retryPending every retryEvery
// seconds, until ctx ends.
func (c *Capture) expireLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for n := 1; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			c.expire(ctx, now, now)
			if n%retryEvery == 0 {
				c.retryPending(ctx)
			}
		}
	}
}

const retryEvery = 3

// SetStopped stops recording (stop) or starts it again with the base scope:
// a stop records nothing new (the Store first, then mitmproxy decrypts mitm.it
// alone) and no rule applies, presets turned off; a start is a new generation,
// so no event of a flow open before it is recorded again. Nothing is checked
// first (the base does not change): a stop is taken even while mitmproxy
// restarts (pending; ErrPending), and a mitmdump started later stays stopped.
// base is the base scope, the one a start records.
func (c *Capture) SetStopped(ctx context.Context, why string, stop bool) (base HostRules, err error) {
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	if c.stopped == stop {
		return c.want, ErrUnchanged
	}
	return c.want, c.changeLocked(ctx, why, c.want, stop, time.Time{}) // a stop ends allow-all
}

// changeLocked takes base r, stopped stop and allow-all until as the scope
// asked for, a new generation: to the Store first if the scope recorded
// narrows, then to mitmdump.
func (c *Capture) changeLocked(ctx context.Context, why string, r HostRules, stop bool, until time.Time) error {
	gen := c.wantGen + 1
	old, oldStop, oldUntil := c.want, c.stopped, c.allUntil
	c.want, c.stopped, c.allUntil, c.wantGen = r, stop, until, gen
	if narrows(effective(old, oldStop, !oldUntil.IsZero()), effective(r, stop, !until.IsZero())) {
		c.toStoreLocked()
		c.setPending(PendingNarrowed)
	} else {
		c.setPending(PendingAsked)
	}
	err := c.applyLocked(ctx)
	// An allow-all this change ended (a stop) whose end mitmdump was not told
	// would go on there, with no end left here to expire: killed, as
	// endAllLocked does; the next one starts without it.
	defer func() {
		if !oldUntil.IsZero() && !c.allOn() && c.ScopePending() != "" {
			c.cfg.Logf("allow-all ended in reqcove's records, mitmproxy not told: restarting it without allow-all")
			c.killLocked()
		}
	}()
	var refused *refusal
	if errors.As(err, &refused) { // the rules changed since the check (--rules-reload): back to the scope before
		c.want, c.stopped, c.wantGen = old, oldStop, gen+1
		if !until.IsZero() { // never back into an allow-all this change ended
			c.allUntil = oldUntil
		}
		c.toStoreLocked() // with a newer generation than r's, so the Store and mitmdump agree again
		if err := c.applyLocked(ctx); err != nil {
			c.cfg.Logf("the scope before (generation %d) is not applied yet: %v", c.wantGen, err)
		}
		return err
	}
	if why != "" {
		c.ackMu.Lock()
		c.changeAt, c.change = time.Now(), why
		c.ackMu.Unlock()
	}
	return err
}

// Base is the base scope asked for last, a pending one included (Scope is
// the one acknowledged): what a start records, and what capture save writes.
func (c *Capture) Base() HostRules {
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	return c.want
}

// NoteChange keeps why as the last change (LastChange), for one that changes
// no scope: capture save.
func (c *Capture) NoteChange(why string) {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	c.changeAt, c.change = time.Now(), why
}

// LastChange is when ChangeScope last took a change with a why (or
// NoteChange), and the why; the zero time before any.
func (c *Capture) LastChange() (time.Time, string) {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	return c.changeAt, c.change
}

// refusal is the addon's answer refusing a scope.
type refusal struct{ error }

// scopeAck is the addon's answer to a scope op.
type scopeAck struct {
	OK       bool           `json:"ok"`
	Gen      int64          `json:"gen"`
	Instance string         `json:"instance"`
	Loaded   map[string]int `json:"rules_loaded"` // the rules Reload put in force, by kind
}

// scopeOp is the addon's scope op for base r: the rules are checked against
// the base, mitmproxy's allow_hosts is the effective scope's.
func scopeOp(r HostRules, gen int64, check, stopped, all bool) map[string]any {
	return map[string]any{"op": "scope", "gen": gen, "allow_hosts": mitmAllow(effective(r, stopped, all)), "rules": addonHosts(r), "check": check, "stopped": stopped, "allow_all": all}
}

// applyLocked tells the mitmdump spawned last the scope asked for last; on
// its acknowledgment (its instance, the generation) the scope is applied.
func (c *Capture) applyLocked(ctx context.Context) error {
	var ack scopeAck
	op := scopeOp(c.want, c.wantGen, false, c.stopped, c.allOn())
	if c.reloadRules != "" { // Reload's op alone: never again (a revert, a later hello's)
		op["rules_file"], c.reloadRules = c.reloadRules, ""
	}
	err := c.control(ctx, op, &ack)
	switch {
	case errors.Is(err, ErrNoControl), errors.Is(err, ErrUncertain):
		return fmt.Errorf("mitmproxy did not answer (restarting?): %w", ErrPending)
	case err != nil:
		return &refusal{err}
	case !ack.OK || ack.Instance != c.instance || ack.Gen != c.wantGen:
		return fmt.Errorf("mitmproxy answered for another generation or process: %w", ErrPending)
	}
	c.loaded = ack.Loaded
	c.appliedLocked()
	return nil
}

// appliedLocked: mitmdump has the scope asked for last.
func (c *Capture) appliedLocked() {
	c.toStoreLocked()
	c.ackMu.Lock()
	c.acked, c.ackStop, c.ackAll, c.pending = c.want, c.stopped, c.allUntil, ""
	c.ackMu.Unlock()
}

func (c *Capture) toStoreLocked() {
	if c.storeGen < c.wantGen {
		c.Store.setScopeGen(c.wantGen, effective(c.want, c.stopped, c.allOn()), recording(c.stopped, c.allOn()))
		c.storeGen = c.wantGen
	}
}

func (c *Capture) setPending(p string) {
	c.ackMu.Lock()
	c.pending = p
	c.ackMu.Unlock()
}

// narrows says whether r leaves out anything old recorded, judged by the
// specs: a host or pattern of old missing from r, "*" given up, or a
// --pass-hosts host added. A change it calls narrowing may also add hosts:
// the Store then has them before mitmdump, which admits none of them meanwhile.
func narrows(old, r HostRules) bool {
	for _, p := range r.PassHosts {
		if !slices.Contains(old.PassHosts, p) {
			return true
		}
	}
	if r.All {
		return false
	}
	if old.All {
		return true
	}
	for _, h := range old.Hosts {
		if !slices.Contains(r.Hosts, h) {
			return true
		}
	}
	return false
}

// supervise restarts mitmdump until ctx ends or a failure is permanent;
// fails: the failures in a row before p came up.
// While it is down the exit node cannot reach mitmdump, so the iPhone's
// connections fail; they never go out undecrypted and unrecorded instead.
func (c *Capture) supervise(ctx context.Context, p *proc, fails int) {
	defer close(c.done)
	for {
		var stable <-chan time.Time
		if fails > 0 {
			stable = time.After(time.Until(p.ready.Add(stableAfter)))
		}
		select {
		case <-ctx.Done():
			c.setUp(false)
			p.stop()
			return
		case <-stable:
			fails = 0
			c.Store.retrying("", 0, time.Time{})
			continue
		case <-p.done:
		}
		// First: from now connections wait in the listener's queue for the next one.
		c.setUp(false)
		syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL) // whatever is left of its group would still accept on the port
		// Its lines still in the socket come first: one read after
		// mitmdumpExited would open a flow nothing closes, and count its
		// counters twice. Its connections end at their EOF, now it is gone.
		for deadline := time.Now().Add(drainWait); c.readers.Load() > 0 && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		err := fmt.Errorf("mitmdump exited: %v", p.err)
		c.Store.mitmdumpExited(err.Error())
		if time.Since(p.ready) >= stableAfter {
			fails = 0
		}
		for p = nil; p == nil; {
			c.Store.setState("restarting", err.Error())
			if fails++; !c.retryWait(ctx, err, fails) {
				return
			}
			if p, err = c.spawn(ctx); err != nil && ctx.Err() != nil {
				return
			}
			if isPermanent(err) {
				c.err = err
				c.Store.setState("failed", err.Error())
				return
			}
		}
		c.cfg.Logf("mitmdump is back")
	}
}

// WaitReady returns once mitmdump is ready (its addon said hello), so that
// dials made while it is down wait for it here rather than in the SOCKS
// listener's queue. The port itself is never free: reqcove holds it (socks).
func (c *Capture) WaitReady(ctx context.Context) error {
	c.upMu.Lock()
	up := c.up
	c.upMu.Unlock()
	return c.waitFrom(ctx, up)
}

// waitFrom is WaitReady from the gate seen as up. Woken, it checks the gate
// is still that one: a mitmdump that went down again meanwhile replaced it.
func (c *Capture) waitFrom(ctx context.Context, up chan struct{}) error {
	for {
		select {
		case <-c.done:
			return errors.New("mitmdump is not running")
		default:
		}
		select {
		case <-up:
			c.upMu.Lock()
			now := c.up
			c.upMu.Unlock()
			if now == up {
				return nil
			}
			up = now // down again since: wait for the next one
		case <-c.done:
			return errors.New("mitmdump is not running")
		case <-ctx.Done():
			return fmt.Errorf("mitmdump is not ready: %w", ctx.Err())
		}
	}
}

func (c *Capture) setUp(up bool) {
	c.upMu.Lock()
	defer c.upMu.Unlock()
	select {
	case <-c.up:
		if !up {
			c.up = make(chan struct{})
		}
	default:
		if up {
			close(c.up)
		}
	}
}

// Done is closed when mitmdump is stopped or failed for good (a permanent failure); Err then says why (nil after Stop).
func (c *Capture) Done() <-chan struct{} { return c.done }
func (c *Capture) Err() error            { return c.err }

// Stop ends mitmdump and closes the socket.
func (c *Capture) Stop() {
	c.cancel()
	<-c.done
	c.ln.Close()
	c.socks.Close()
	os.Remove(c.ln.Addr().String())
	os.Remove(filepath.Join(c.cfg.Dir, "mitmdump.pid"))
	os.Remove(filepath.Join(c.cfg.Dir, "socks-secret")) // a run's secret ends with the run
	os.Remove(filepath.Join(c.cfg.Dir, ControlSock))
	for f := range scriptFiles {
		os.Remove(filepath.Join(c.cfg.Dir, f))
	}
	removeRulesCopy(c.cfg.Dir) // the rules (tokens in modify_headers, say) end with the run
	if c.WebURL != "" {
		os.Remove(filepath.Join(c.cfg.Confdir, "config.yaml"))
	}
}

func (c *Capture) accept() {
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			return
		}
		c.readers.Add(1)
		go func() {
			defer c.readers.Add(-1)
			defer conn.Close()
			r := bufio.NewReaderSize(conn, 1<<16)
			for {
				line, err := readLine(r, maxIngestLine)
				switch {
				case errors.Is(err, errLongLine):
					c.Store.badLine() // never held whole: the addon's bounds keep real lines far below
				case len(line) > 0:
					c.Store.Apply(line)
				}
				if err != nil && !errors.Is(err, errLongLine) {
					return
				}
			}
		}()
	}
}

// maxIngestLine bounds one line from the addon: a body head (64 KiB, in
// base64) and headers (256 KiB, JSON-escaped) fit many times over.
const maxIngestLine = 8 << 20

var errLongLine = errors.New("ingest line too long")

// readLine reads up to a newline, at most max bytes: a longer line is read
// to its end and dropped (errLongLine), not held.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > max {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			return nil, errLongLine // counted even when the stream ends there; the next read says EOF
		}
		line = append(line, part...)
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, err
		}
	}
}

// killStale stops a mitmdump (with uvx above it) left by a reqcove that died
// without stopping it, as recorded in dir/mitmdump.pid. Only a process whose
// arguments name this directory's socket is stopped: the PID may have been reused.
func killStale(dir, sock string) {
	b, err := os.ReadFile(filepath.Join(dir, "mitmdump.pid"))
	if err != nil {
		return
	}
	os.Remove(filepath.Join(dir, "mitmdump.pid"))
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return
	}
	args, err := exec.Command("ps", "-o", "args=", "-p", strconv.Itoa(pid)).Output()
	if err != nil || !strings.Contains(string(args), "reqcove_socket="+sock) {
		return
	}
	syscall.Kill(-pid, syscall.SIGTERM)
	for range 50 {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	syscall.Kill(-pid, syscall.SIGKILL)
}

// CA describes the mitmproxy CA, so the profile on the iPhone can be matched.
type CA struct {
	Name     string
	SHA256   string // fingerprint, uppercase hex as security -Z takes it (iOS shows it lowercase, in spaced pairs)
	NotAfter time.Time
}

func ReadCA(confdir string) (CA, error) {
	b, err := os.ReadFile(filepath.Join(confdir, "mitmproxy-ca-cert.pem"))
	if err != nil {
		return CA{}, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return CA{}, errors.New("no PEM in mitmproxy-ca-cert.pem")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return CA{}, err
	}
	sum := sha256.Sum256(cert.Raw)
	return CA{Name: cert.Subject.CommonName, SHA256: strings.ToUpper(hex.EncodeToString(sum[:])), NotAfter: cert.NotAfter}, nil
}

// ensureCA makes the CA with mitmproxy's own CertStore.create_store, which
// takes a name (mitmproxy always passes "mitmproxy"), so iPhones holding CAs
// from several machines can tell them apart. An existing CA (its key) is never
// touched: certificate files missing beside it are written again from
// mitmproxy-ca.pem, which holds the certificate too, as create_store writes
// them. create_store is internal mitmproxy API: TestCANamed catches a change.
func ensureCA(ctx context.Context, cfg Config) error {
	py := `import sys; from pathlib import Path; from mitmproxy.certs import CertStore; CertStore.create_store(Path(sys.argv[1]), "mitmproxy", 2048, organization="Reqcove", cn=sys.argv[2])`
	if HasCA(cfg.Confdir) {
		whole := true
		for _, name := range CAFiles {
			if _, err := os.Stat(filepath.Join(cfg.Confdir, name)); err != nil {
				whole = false
			}
		}
		if whole {
			return nil
		}
		py = certsFromKey
	}
	if err := os.MkdirAll(cfg.Confdir, 0o700); err != nil {
		return err
	}
	bin, args := PyCommand(cfg, "python")
	cmd := exec.CommandContext(ctx, bin, append(args, "-c", py, cfg.Confdir, cfg.CAName)...)
	cmd.Stdout, cmd.Stderr = cfg.Log, cfg.Log
	return cmd.Run()
}

// certsFromKey writes the certificate files missing beside mitmproxy-ca.pem
// from the certificate in it, as create_store writes them.
const certsFromKey = `import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
p = Path(sys.argv[1])
ca = x509.load_pem_x509_certificates((p / "mitmproxy-ca.pem").read_bytes())[0]
pem = ca.public_bytes(serialization.Encoding.PEM)
for name, b in (("mitmproxy-ca-cert.pem", pem), ("mitmproxy-ca-cert.cer", pem),
                ("mitmproxy-ca-cert.p12", pkcs12.serialize_key_and_certificates(name=b"mitmproxy", key=None, cert=ca, cas=None, encryption_algorithm=serialization.NoEncryption()))):
    if not (p / name).exists():
        (p / name).write_bytes(b)
`

// HasCA says confdir holds a CA: its key, mitmproxy-ca.pem (with the
// certificate in it). Whatever else is missing, a CA there is never replaced.
func HasCA(confdir string) bool {
	_, err := os.Stat(filepath.Join(confdir, "mitmproxy-ca.pem"))
	return err == nil
}

// CAFiles are what mitmproxy and mitm.it use of a CA, the key last, so a copy
// cut short never looks like a CA (HasCA).
// Not copied: mitmproxy-ca.p12 (the key again, without a passphrase, which
// mitmproxy does not read), the dhparam (made when missing) and config.yaml
// (mitmweb's password).
var CAFiles = []string{"mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.p12", "mitmproxy-ca.pem"}

// CopyCA copies the CA of confdir src into dst, so one profile on the iPhone
// serves both nodes. It does nothing when src has no CA or dst has one, and
// copies nothing when src lacks one of CAFiles; a copy that fails is removed.
func CopyCA(src, dst string) (bool, error) {
	if !HasCA(src) || HasCA(dst) {
		return false, nil
	}
	for _, name := range CAFiles {
		if _, err := os.Stat(filepath.Join(src, name)); err != nil {
			return false, fmt.Errorf("%s has a CA but no %s (its node writes it again at its next start)", src, name)
		}
	}
	// Temporary files of a copy cut short (one may hold the key): NAME.DIGITS,
	// as os.CreateTemp names them; nothing else, a .bak say, goes.
	ents, _ := os.ReadDir(dst)
	for _, e := range ents {
		name, suffix, _ := strings.Cut(e.Name(), ".tmp")
		if slices.Contains(CAFiles, name) && suffix != "" && strings.Trim(suffix, "0123456789") == "" {
			os.Remove(filepath.Join(dst, e.Name()))
		}
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return false, err
	}
	var done []string
	for _, name := range CAFiles {
		if err := copyFile(filepath.Join(src, name), filepath.Join(dst, name)); err != nil {
			removeAll(done)
			return false, err
		}
		done = append(done, filepath.Join(dst, name))
	}
	return true, nil
}

// copyFile copies src to dst, 0600, through a temporary file: dst is whole or absent.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp*") // 0600, NAME.tmpDIGITS
	if err != nil {
		return err
	}
	_, err = io.Copy(tmp, in)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), dst)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

func removeAll(paths []string) {
	for _, p := range paths {
		os.Remove(p)
	}
}
