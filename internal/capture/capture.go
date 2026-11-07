// Package capture runs mitmproxy (mitmdump, SOCKS5 mode) as a child process
// with an embedded addon, and keeps the flows the addon sends in a Store.
package capture

import (
	"bufio"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

//go:embed addon.py
var addonPy []byte

// Apple's services fail on HTTPS interception
// (https://support.apple.com/en-us/101555), so these pass through undecrypted.
// The same list as docs/apple-ignore-hosts.txt.
//
//go:embed apple-ignore-hosts.txt
var appleIgnoreHosts string

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
	RestartDelay time.Duration                 // first wait before restarting mitmdump, doubled each time; 0 means 1s
	Logf         func(format string, a ...any) // restarts are reported here; nil is quiet
}

// mitmdump is restarted when it exits, up to maxRestarts times in a row; a
// run that stayed up for stableAfter resets the count.
const (
	maxRestarts = 5
	stableAfter = time.Minute
)

type Capture struct {
	Store       *Store
	SocksAddr   string // 127.0.0.1:port of mitmdump's SOCKS5 listener; the same across restarts
	SocksSecret string // the SOCKS5 password; any user name (reqcove sends the device's StableID)

	cfg    Config
	args   []string
	ln     net.Listener
	cancel context.CancelFunc
	done   chan struct{}
	err    error
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
	os.Remove(sock) // callers hold the state directory lock, so a socket here is stale
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Capture, error) {
		ln.Close()
		os.Remove(sock)
		return nil, err
	}
	addon := filepath.Join(cfg.Dir, "addon.py")
	if err := os.WriteFile(addon, addonPy, 0o600); err != nil {
		return fail(err)
	}
	port, err := freePort()
	if err != nil {
		return fail(err)
	}
	// A new SOCKS5 password each run, in a file (not argv, which ps shows).
	secret := rand.Text()
	secretFile := filepath.Join(cfg.Dir, "socks-secret")
	if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
		return fail(err)
	}
	allowJSON, _ := json.Marshal(map[string]any{"all": cfg.AllowHosts.All, "patterns": cfg.AllowHosts.Patterns})
	c := &Capture{Store: NewStore(cfg.MaxFlows, cfg.MaxBytes), SocksAddr: fmt.Sprintf("127.0.0.1:%d", port), SocksSecret: secret,
		cfg: cfg, ln: ln, done: make(chan struct{})}
	c.Store.SetScope(cfg.AllowHosts, !cfg.NoRedact)
	go c.accept()

	c.args = []string{"--python", cfg.Python, "--from", cfg.MitmSpec, "mitmdump",
		"--mode", "socks5", "--listen-host", "127.0.0.1", "--listen-port", fmt.Sprint(port),
		"--set", "confdir=" + cfg.Confdir,
		"--set", "proxyauth=any",
		// Bodies stream through the addon's callables; store_streamed_bodies
		// would buffer them in mitmproxy anyway. -q equivalent: errors only.
		"--set", "flow_detail=0", "--set", "termlog_verbosity=error",
		"--set", fmt.Sprintf("reqcove_body_head=%d", cfg.BodyHead),
		"-s", addon, "--set", "reqcove_socket=" + sock,
		"--set", "reqcove_secret_file=" + secretFile,
		"--set", "reqcove_allow_hosts=" + string(allowJSON)}
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
	ctx, c.cancel = context.WithCancel(ctx)
	go c.supervise(ctx, p)
	return c, nil
}

// spawn starts one mitmdump and waits for its addon's hello.
func (c *Capture) spawn(ctx context.Context) (*proc, error) {
	before := c.Store.helloCount()
	p := &proc{cmd: exec.Command(c.cfg.Uvx, c.args...), done: make(chan struct{})}
	p.cmd.Stdout, p.cmd.Stderr = c.cfg.Log, c.cfg.Log
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := p.cmd.Start(); err != nil {
		return nil, err
	}
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
	p.ready = time.Now()
	c.Store.setState("ready", "")
	return p, nil
}

// supervise restarts mitmdump until ctx ends or it fails maxRestarts times in a row.
// While it is down the exit node cannot reach mitmdump, so the iPhone's
// connections fail; they never go out undecrypted and unrecorded instead.
func (c *Capture) supervise(ctx context.Context, p *proc) {
	defer close(c.done)
	fails := 0
	for {
		select {
		case <-ctx.Done():
			p.stop()
			return
		case <-p.done:
		}
		syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL) // whatever is left of its group would hold the port
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
			if p, err = c.spawn(ctx); err != nil && ctx.Err() != nil {
				return
			}
		}
		c.cfg.Logf("mitmdump is back")
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
	os.Remove(c.ln.Addr().String())
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
				line, err := r.ReadBytes('\n') // no line limit: body heads are inline
				if len(line) > 0 {
					c.Store.Apply(line)
				}
				if err != nil {
					return
				}
			}
		}()
	}
}

// freePort asks the kernel for an unused port.
// ponytail: the port is free when asked, not guaranteed when mitmdump binds; retry if that ever races.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
