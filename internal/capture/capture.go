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
	AllowHosts   HostRules // hosts decrypted and recorded; the zero value records nothing
	NoRedact     bool      // keep secrets in the records (--no-redact)
}

type Capture struct {
	Store       *Store
	SocksAddr   string // 127.0.0.1:port of mitmdump's SOCKS5 listener
	SocksSecret string // the SOCKS5 password; any user name (reqcove sends the device's StableID)

	cmd  *exec.Cmd
	ln   net.Listener
	done chan struct{}
	err  error
}

// Start launches mitmdump and returns once its addon has said hello.
func Start(ctx context.Context, cfg Config) (*Capture, error) {
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	sock := filepath.Join(cfg.Dir, "ingest.sock")
	os.Remove(sock) // callers hold the state directory lock, so a socket here is stale
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	addon := filepath.Join(cfg.Dir, "addon.py")
	if err := os.WriteFile(addon, addonPy, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	port, err := freePort()
	if err != nil {
		ln.Close()
		return nil, err
	}
	// A new SOCKS5 password each run, in a file (not argv, which ps shows).
	secret := rand.Text()
	secretFile := filepath.Join(cfg.Dir, "socks-secret")
	if err := os.WriteFile(secretFile, []byte(secret), 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	allowJSON, _ := json.Marshal(map[string]any{"all": cfg.AllowHosts.All, "patterns": cfg.AllowHosts.Patterns})
	c := &Capture{Store: NewStore(cfg.MaxFlows, cfg.MaxBytes), SocksAddr: fmt.Sprintf("127.0.0.1:%d", port), SocksSecret: secret, ln: ln, done: make(chan struct{})}
	c.Store.SetScope(cfg.AllowHosts, !cfg.NoRedact)
	go c.accept()

	args := []string{"--python", cfg.Python, "--from", cfg.MitmSpec, "mitmdump",
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
		args = append(args, "--allow-hosts", re) // per connection: others pass through undecrypted
	}
	for _, re := range strings.Split(strings.TrimSpace(appleIgnoreHosts), "\n") {
		args = append(args, "--ignore-hosts", re)
	}
	c.cmd = exec.Command(cfg.Uvx, args...)
	c.cmd.Stdout, c.cmd.Stderr = cfg.Log, cfg.Log
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := c.cmd.Start(); err != nil {
		ln.Close()
		return nil, err
	}
	go func() {
		c.err = c.cmd.Wait()
		close(c.done)
	}()

	deadline := time.After(cfg.ReadyTimeout)
	for c.Store.Stats()["mitmproxy"] == "" {
		select {
		case <-ctx.Done():
			c.Stop()
			return nil, ctx.Err()
		case <-c.done:
			c.Stop()
			return nil, fmt.Errorf("mitmdump exited before its addon said hello: %v", c.err)
		case <-deadline:
			c.Stop()
			return nil, errors.New("mitmdump's addon never said hello")
		case <-time.After(100 * time.Millisecond):
		}
	}
	return c, nil
}

// Done is closed when mitmdump exits; Err then says why.
func (c *Capture) Done() <-chan struct{} { return c.done }
func (c *Capture) Err() error            { return c.err }

// Stop ends mitmdump (and uvx above it) and closes the socket.
func (c *Capture) Stop() {
	if c.cmd != nil && c.cmd.Process != nil {
		syscall.Kill(-c.cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-c.done:
		case <-time.After(5 * time.Second):
			syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
			<-c.done
		}
	}
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
