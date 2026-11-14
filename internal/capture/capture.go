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

// UVExcludeNewer: for another --mitmproxy-spec, uv resolves mitmproxy's
// dependencies only from releases before this, so a release made later (a
// compromised one included) never runs with the CA key.
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
	RestartDelay time.Duration                 // first wait before restarting mitmdump, doubled each time; 0 means 1s
	Logf         func(format string, a ...any) // restarts are reported here; nil is quiet
	webMaxFlows  int                           // tests: fewer flows kept in mitmweb than its default
}

// WebKeep is the largest body (on the wire) given to mitmweb whole (--web).
const WebKeep = 2 << 20

// mitmdump is restarted when it exits, up to maxRestarts times in a row; a
// run that stayed up for stableAfter resets the count.
const (
	maxRestarts = 5
	stableAfter = time.Minute
)

type Capture struct {
	Store       *Store
	SocksAddr   string // 127.0.0.1:port of mitmdump's SOCKS5 listener; reqcove holds it for the whole run (socks)
	SocksSecret string // the SOCKS5 password; any user name (reqcove sends the device's StableID)
	WebURL      string // with WebPort: mitmweb's address, with its password as the token
	CA          CA     // the CA iPhones must trust

	cfg    Config
	bin    string // uv, or uvx
	args   []string
	ln     net.Listener
	socks  *os.File // the SOCKS5 listener, bound by Start and handed to each mitmdump as fd 3: its port is never free while mitmdump restarts
	cancel context.CancelFunc
	done   chan struct{}
	upMu   sync.Mutex
	up     chan struct{} // closed while a mitmdump that said hello runs; replaced when it exits
	// restarted: spawn runs again after mitmdump exited (supervise), not at start.
	restarted bool
	err       error
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

// Start launches mitmdump, returns once its addon has said hello, and keeps
// restarting it when it exits.
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
	allowJSON, _ := json.Marshal(map[string]any{"all": cfg.AllowHosts.All, "patterns": cfg.AllowHosts.Patterns, "pass": cfg.AllowHosts.Pass})
	c := &Capture{Store: NewStore(cfg.MaxFlows, cfg.MaxBytes), SocksAddr: fmt.Sprintf("127.0.0.1:%d", port), SocksSecret: secret, WebURL: webURL,
		cfg: cfg, ln: ln, socks: socks, done: make(chan struct{}), up: make(chan struct{})}
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
		"--set", "reqcove_secret_file="+secretFile,
		"--set", "reqcove_allow_hosts="+string(allowJSON))
	if cfg.Rules != "" {
		c.args = append(c.args, "--set", "reqcove_rules="+cfg.Rules)
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
	if cfg.WebPort != 0 {
		c.args = append(c.args, "--set", "web_host=127.0.0.1", "--set", fmt.Sprintf("web_port=%d", cfg.WebPort), "--set", "web_open_browser=false")
		// mitmweb keeps no streamed body: the addon gives it each one up to
		// WebKeep, and drops its oldest flows past its own bounds.
		c.args = append(c.args, "--set", fmt.Sprintf("reqcove_web_keep=%d", WebKeep))
		if cfg.webMaxFlows > 0 {
			c.args = append(c.args, "--set", fmt.Sprintf("reqcove_web_max_flows=%d", cfg.webMaxFlows))
		}
	}
	for _, re := range cfg.AllowHosts.mitmAllowHosts() {
		c.args = append(c.args, "--allow-hosts", re) // per connection: others pass through undecrypted
	}
	for _, re := range strings.Split(strings.TrimSpace(appleIgnoreHosts), "\n") {
		c.args = append(c.args, "--ignore-hosts", re)
	}

	p, err := c.spawn(ctx)
	if err != nil {
		return fail(err)
	}
	c.CA, _ = ReadCA(cfg.Confdir) // mitmproxy has made it by now if it was missing
	ctx, c.cancel = context.WithCancel(ctx)
	go c.supervise(ctx, p)
	return c, nil
}

// spawn starts one mitmdump and waits for its addon's hello.
func (c *Capture) spawn(ctx context.Context) (*proc, error) {
	before := c.Store.helloCount()
	p := &proc{cmd: exec.Command(c.bin, c.args...), done: make(chan struct{})}
	p.cmd.Stdout, p.cmd.Stderr = c.cfg.Log, c.cfg.Log
	p.cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1", "REQCOVE_SOCKS_FD=3") // PYTHONUNBUFFERED: mitmproxy.log as it happens, not when Python's buffer fills
	p.cmd.ExtraFiles = []*os.File{c.socks}                                       // fd 3: the addon serves SOCKS5 on it
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := p.cmd.Start(); err != nil {
		return nil, err
	}
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
			return nil, fmt.Errorf("mitmdump exited before its addon said hello: %v", p.err)
		case <-deadline:
			p.stop()
			return nil, errors.New("mitmdump's addon never said hello")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if e, _ := c.Store.Stats()["rules_error"].(string); e != "" {
		if !rulesKeepGoing(c.restarted, c.cfg.RulesReload) {
			p.stop()
			return nil, fmt.Errorf("--rules: %s", e)
		}
		c.cfg.Logf("WARN: mitmdump restarted while the --rules file does not load (%s): no rules apply until it is fixed", e)
	}
	p.ready = time.Now()
	c.Store.setState("ready", "")
	c.setUp(true)
	return p, nil
}

// rulesKeepGoing: a rules file that does not load stops a start, but not a
// restart under --rules-reload, where the user was told it can be fixed
// while running: stopping then would cut every device off. The restarted
// mitmdump has no rules until the file loads again.
func rulesKeepGoing(restarted, reload bool) bool { return restarted && reload }

// supervise restarts mitmdump until ctx ends or it fails maxRestarts times in a row.
// While it is down the exit node cannot reach mitmdump, so the iPhone's
// connections fail; they never go out undecrypted and unrecorded instead.
func (c *Capture) supervise(ctx context.Context, p *proc) {
	defer close(c.done)
	fails := 0
	for {
		select {
		case <-ctx.Done():
			c.setUp(false)
			p.stop()
			return
		case <-p.done:
		}
		// First: from now connections wait in the listener's queue for the next one.
		c.setUp(false)
		syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL) // whatever is left of its group would still accept on the port
		err := fmt.Errorf("mitmdump exited: %v", p.err)
		c.Store.mitmdumpExited(err.Error())
		if time.Since(p.ready) >= stableAfter {
			fails = 0
		}
		for p = nil; p == nil; {
			if fails++; fails > maxRestarts {
				c.err = fmt.Errorf("%w; gave up after %d restarts in a row", err, maxRestarts)
				c.Store.setState("failed", c.err.Error())
				return
			}
			delay := c.cfg.RestartDelay << (fails - 1)
			c.Store.setState("restarting", err.Error())
			c.cfg.Logf("%v; restarting it in %v (%d/%d)", err, delay, fails, maxRestarts)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
			c.restarted = true
			if p, err = c.spawn(ctx); err != nil && ctx.Err() != nil {
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

// Done is closed when mitmdump is stopped or has failed too often; Err then says why (nil after Stop).
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
		go func() {
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
