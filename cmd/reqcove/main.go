// Command reqcove lets an AI agent read the HTTP(S) traffic of iPhones in
// your tailnet: the iPhone picks reqcove as its exit node, mitmproxy decrypts
// the traffic, and `reqcove mcp` serves it to the agent.
//
//	reqcove run --device NAME [--device NAME ...]   until Ctrl-C
//	reqcove mcp                                     what the agent launches
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
	"github.com/skip2/go-qrcode"
)

// version is set at release builds: -ldflags "-X main.version=v0.1.0".
var version = "dev"

const usage = `Reqcove hands an iPhone's HTTP(S) traffic to AI agents over MCP.

Usage:
  reqcove run --device NAME --allow-hosts HOSTS [flags]
                     carry the device's traffic as a Tailscale exit node and record
                     the allowed hosts; prints what is left to set up
  reqcove status     what reqcove is doing, and the next steps
  reqcove mcp        the MCP server for an agent: claude mcp add reqcove -- reqcove mcp
  reqcove cleanup    how to undo everything (--delete-state removes ~/.reqcove)
  reqcove version

"reqcove run -h" lists run's flags. More: https://github.com/mh-mobile/reqcove
`

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	mcpserver.Version = version
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(capture.GoMemoryLimit)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "run":
		err = run(ctx, os.Args[2:])
	case "mcp":
		err = runMCP(ctx, os.Args[2:])
	case "status":
		err = status(ctx, os.Args[2:])
	case "cleanup":
		err = cleanup(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Println("reqcove", version)
		return
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

func defaultState() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".reqcove")
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var devices []string
	fs.Func("device", "device whose traffic is carried: machine name, device name (your own devices), tailnet IP or StableID (repeatable)", func(v string) error {
		devices = append(devices, v)
		return nil
	})
	var allowSpecs []string
	fs.Func("allow-hosts", `hosts decrypted and recorded, comma-separated (repeatable): "api.example.com", "*.example.com", or "*" for everything. Without it, nothing is recorded.`, func(v string) error {
		allowSpecs = append(allowSpecs, v)
		return nil
	})
	rules := fs.String("rules", "", "YAML file of map_remote, map_local and modify_headers rules (mitmproxy's syntax), and resolve and keep_host_header (reqcove's), applied to --allow-hosts hosts only")
	web := fs.Bool("web", false, "run mitmweb instead of mitmdump, its UI on http://127.0.0.1:8081 (no masking, can edit and replay)")
	noRedact := fs.Bool("no-redact", false, "keep Authorization, cookies and secret query values in the records")
	state := fs.String("state", defaultState(), "state directory")
	hostname := fs.String("hostname", "reqcove", "tailnet node name")
	dnsFlag := fs.String("dns", "1.1.1.1:53", `exit node DNS upstreams, comma-separated; "system" for the first nameserver in /etc/resolv.conf`)
	mitmSpec := fs.String("mitmproxy-spec", "mitmproxy==12.3.1", "uvx --from spec for mitmproxy")
	python := fs.String("python", "3.14", "Python for uvx")
	uvx := fs.String("uvx", "uvx", "path to uvx")
	proxyPort := fs.Int("proxy-port", 8080, "Remote Proxy port on the tailnet, for the iPhone's Wi-Fi proxy setting; 0 turns it off")
	upstreamProxy := fs.String("upstream-proxy", "", "send decrypted requests on through this HTTP proxy (Burp Suite, ZAP, …): http://HOST:PORT")
	upstreamCA := fs.String("upstream-ca", "", "the upstream proxy's CA (PEM or DER, as Burp exports it): trusted instead of the public CAs; for a proxy that decrypts")
	verbose := fs.Bool("verbose", false, "log tsnet's backend and every flow decision")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if len(devices) == 0 {
		msg := "--device is required: the iPhone to carry, by its machine name (see `tailscale status`)"
		if names := iosDevices(); len(names) > 0 {
			msg += "; yours on this tailnet: " + strings.Join(names, ", ")
		}
		return errors.New(msg)
	}
	dns, err := parseDNS(*dnsFlag)
	if err != nil {
		return err
	}
	allow, err := capture.ParseAllowHosts(hostsOnly(allowSpecs))
	if err != nil {
		return err
	}
	switch {
	case allow.All:
		log.Print("WARN: --allow-hosts '*': every decrypted request is recorded, including other apps' and sites'. Agents, and their model providers, can read them.")
	case len(allow.Patterns) == 0:
		log.Print("no --allow-hosts: traffic is carried but nothing is decrypted or recorded. Add --allow-hosts api.example.com for your app.")
	}
	if *rules != "" {
		if !allow.All && len(allow.Patterns) == 0 {
			return fmt.Errorf("--rules needs --allow-hosts: rules apply only to the hosts reqcove decrypts")
		}
		if *rules, err = filepath.Abs(*rules); err != nil {
			return err
		}
		if _, err := os.Stat(*rules); err != nil {
			return fmt.Errorf("--rules: %w", err)
		}
	}
	if *noRedact {
		log.Print("WARN: --no-redact: Authorization, cookies and secret query values are kept in the records")
	}
	if *upstreamProxy != "" && !allow.All && len(allow.Patterns) == 0 {
		return fmt.Errorf("--upstream-proxy needs --allow-hosts: only decrypted requests go on to it")
	}
	upstream, err := parseUpstream(*upstreamProxy, *upstreamCA)
	if err != nil {
		return err
	}

	if _, err := exec.LookPath(*uvx); err != nil {
		return fmt.Errorf("uv not found (%s): install it first, https://docs.astral.sh/uv/ ; reqcove fetches mitmproxy and Python with it", *uvx)
	}
	unlock, err := openState(*state)
	if err != nil {
		return err
	}
	defer unlock()
	keepAwake(ctx)
	var upstreamCAFile string
	if *upstreamCA != "" {
		if upstreamCAFile, err = writeUpstreamCA(*upstreamCA, *state); err != nil {
			return err
		}
	} else if upstream != "" {
		b, err := fetchBurpCA(upstream)
		if err == nil {
			upstreamCAFile, err = saveUpstreamCA(b, "http://burp/cert", *state)
		}
		if err == nil {
			log.Printf("using Burp's CA from http://burp/cert (--upstream-ca to choose one)")
		} else {
			log.Printf("no Burp CA from http://burp/cert (%v): the public CAs are trusted through the proxy", err)
		}
	}

	mitmLog, err := os.OpenFile(filepath.Join(*state, "mitmproxy.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer mitmLog.Close()
	log.Printf("starting mitmproxy (%s) through uvx; the first run downloads it", *mitmSpec)
	cap, err := capture.Start(ctx, capture.Config{
		Dir: *state, Confdir: filepath.Join(*state, "mitmproxy"),
		Uvx: *uvx, Python: *python, MitmSpec: *mitmSpec,
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
		Log: mitmLog, ReadyTimeout: 2 * time.Minute,
		AllowHosts: allow, NoRedact: *noRedact, Rules: *rules, WebPort: webPort(*web),
		Upstream: upstream, UpstreamCA: upstreamCAFile,
		CAName: caName(),
		Logf:   func(f string, a ...any) { log.Printf(f+" (log: %s)", append(a, mitmLog.Name())...) },
	})
	if err != nil {
		return fmt.Errorf("mitmproxy: %w (log: %s)", err, mitmLog.Name())
	}
	defer cap.Stop()
	s := cap.Store.Stats()
	log.Printf("mitmproxy %v ready (Python %v, brotli %v)", s["mitmproxy"], s["python"], s["brotli"])
	if ca := cap.CA; ca.Name != "" {
		log.Printf("CA %q, SHA-256 %s, until %s: iPhones get it from http://mitm.it (the same CA as long as %s is kept)", ca.Name, ca.SHA256, ca.NotAfter.Format("2006-01-02"), filepath.Join(*state, "mitmproxy"))
		printQR(os.Stderr, "http://mitm.it", "to get the CA, scan this with the iPhone's camera while it uses the exit node (Safari opens http://mitm.it)")
	}
	if upstream != "" {
		trust := "the public CAs"
		if upstreamCAFile != "" {
			trust = "its CA only"
		}
		log.Printf("decrypted requests go on to the upstream proxy %s, which sees them unmasked; HTTPS through it is checked against %s", upstream, trust)
		if upstreamCAFile == "" {
			log.Print("if the proxy decrypts (ZAP and Charles do), pass its CA with --upstream-ca, or HTTPS through it fails with 'unable to get local issuer certificate'")
		}
	}
	if *rules != "" {
		log.Printf("rules from %s: %v", *rules, s["rules"])
		if r, _ := s["resolve"].([]string); len(r) > 0 {
			log.Printf("resolve: %s (Host and SNI as the app sent them; TLS checked against the name)", strings.Join(r, ", "))
		}
	}
	if *web {
		log.Printf("mitmweb on %s", cap.WebURL)
		log.Print("WARN: --web: mitmweb shows traffic unmasked (cookies, tokens), and from its page flows can be edited, replayed and options changed. It keeps every flow until reqcove stops, so memory is not bounded.")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-cap.Done()
		if ctx.Err() == nil {
			log.Printf("%v (log: %s)", cap.Err(), mitmLog.Name())
			cancel()
		}
	}()
	mcpSock := filepath.Join(*state, "mcp.sock")
	var node nodeState
	if err := mcpserver.Serve(ctx, mcpSock, mcpserver.New(cap.Store, func() mcpserver.StatusOut {
		return statusOut(node.get(), cap.Store.Stats(), allow, cap.CA, cap.Store.Devices())
	})); err != nil {
		return fmt.Errorf("MCP socket: %w (a shorter --state path helps if it is too long)", err)
	}
	log.Printf("MCP on %s; agents connect with `reqcove mcp` (Claude Code: claude mcp add reqcove -- reqcove mcp)", mcpSock)

	err = exitnode.Run(ctx, exitnode.Config{
		Dir: filepath.Join(*state, "tsnet"), Hostname: *hostname, DNS: dns,
		Devices: devices, SocksAddr: cap.SocksAddr, SocksSecret: cap.SocksSecret, ProxyPort: *proxyPort, Verbose: *verbose,
		OnDevices: cap.Store.SetDeviceNames, OnStatus: node.set,
	})
	fmt.Fprintln(os.Stderr, "\nreqcove is stopping. On the iPhone, turn off the exit node, or set the Wi-Fi proxy back to Off: without reqcove it cannot reach the internet.")
	if ctx.Err() != nil {
		return nil // Ctrl-C, or mitmproxy failed (already logged)
	}
	return err
}

// caName names a new CA after this machine and the day, so an iPhone holding
// CAs from several machines can tell their profiles apart.
func caName() string {
	host, _ := os.Hostname()
	host = strings.TrimSuffix(host, ".local")
	return fmt.Sprintf("Reqcove CA (%s, %s)", host, time.Now().Format("2006-01-02"))
}

func webPort(on bool) int {
	if on {
		return 8081
	}
	return 0
}

func parseDNS(v string) ([]netip.AddrPort, error) {
	if v == "system" {
		return nil, nil
	}
	var out []netip.AddrPort
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		ap, err := netip.ParseAddrPort(s)
		if ip, ipErr := netip.ParseAddr(s); err != nil && ipErr == nil {
			ap, err = netip.AddrPortFrom(ip, 53), nil // no port: DNS's
		}
		if err != nil {
			return nil, fmt.Errorf("--dns %q: want an IP address, optionally with :PORT", s)
		}
		out = append(out, ap)
	}
	return out, nil
}

// parseFlags parses args and refuses leftovers: flag stops at the first one,
// so `--device Taro's iPhone --allow-hosts x` would drop the --allow-hosts.
func parseFlags(fs *flag.FlagSet, args []string) error {
	fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q (quote values with spaces, such as --device \"Taro's iPhone\")", fs.Arg(0))
	}
	return nil
}

// openState makes the state directory (0700) and locks it. It refuses a
// directory that holds other files and was never reqcove's (no lock file), so
// that neither its chmod nor `cleanup --delete-state` reaches someone else's files.
func openState(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	ents = slices.DeleteFunc(ents, func(e os.DirEntry) bool { return e.Name() == ".DS_Store" }) // Finder leaves it in folders it opened
	if len(ents) > 0 && !isState(dir) {
		return nil, fmt.Errorf("%s holds other files and is not a reqcove state directory; pick an empty or new --state", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	// The marker is what makes a directory reqcove's (for this check and for
	// cleanup), not a file with a name as common as "lock".
	if err := os.WriteFile(filepath.Join(dir, stateMarker), []byte("reqcove state directory\n"), 0o600); err != nil {
		return nil, err
	}
	return lockState(dir)
}

const stateMarker = ".reqcove-state"

// lockState makes sure only one reqcove uses the state directory: two tsnet
// processes with the same node key would fight.
func lockState(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another reqcove is using %s", dir)
	}
	return func() { f.Close() }, nil
}

func runMCP(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	sock := filepath.Join(*state, "mcp.sock")
	if err := mcpserver.Relay(ctx, sock, os.Stdin, os.Stdout); err != nil {
		return fmt.Errorf("is `reqcove run` running? %w", err)
	}
	return nil
}

// printQR draws url as a QR code, with what it is for, when w is a terminal:
// typing http://mitm.it by hand is easy to get wrong (Safari tries https).
func printQR(w *os.File, url, what string) {
	if fi, err := w.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return // a log file or pipe: the URL in the line above is enough
	}
	q, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "%s:\n%s", what, q.ToSmallString(false))
}

// parseUpstream checks --upstream-proxy (http://HOST:PORT, answering now) and
// returns HOST:PORT for mitmproxy.
func parseUpstream(raw, ca string) (string, error) {
	if raw == "" {
		if ca != "" {
			return "", errors.New("--upstream-ca needs --upstream-proxy")
		}
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" || u.Port() == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("--upstream-proxy %q: want http://HOST:PORT", raw)
	}
	c, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("--upstream-proxy %s does not answer (start it first): %w", u.Host, err)
	}
	c.Close()
	return u.Host, nil
}

// writeUpstreamCA reads the upstream's CA certificate, PEM or DER, and writes
// it as PEM into the state directory for mitmproxy (which cannot read DER).
func writeUpstreamCA(path, state string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("--upstream-ca: %w", err)
	}
	return saveUpstreamCA(b, path, state)
}

// fetchBurpCA gets Burp's CA the way its docs say, http://burp/cert through
// the proxy, when the proxy is on this computer: over a network, plain HTTP
// could hand back someone else's CA. Other proxies answer with an error.
func fetchBurpCA(upstream string) ([]byte, error) {
	host, _, _ := net.SplitHostPort(upstream)
	if ip, err := netip.ParseAddr(host); (err != nil || !ip.IsLoopback()) && host != "localhost" {
		return nil, errors.New("not on this computer")
	}
	c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: upstream})}}
	resp, err := c.Get("http://burp/cert")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http://burp/cert: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	// Burp's own CA only: a proxy that is not Burp may fetch "http://burp/cert"
	// from wherever the name leads, and that must not become the CA trusted.
	if c, err := x509.ParseCertificate(b); err != nil || c.Subject.CommonName != "PortSwigger CA" {
		return nil, errors.New("not Burp's CA (PortSwigger CA)")
	}
	return b, nil
}

// saveUpstreamCA checks a CA certificate (PEM or DER) from src and writes it as
// PEM into the state directory for mitmproxy.
func saveUpstreamCA(b []byte, path, state string) (string, error) {
	// PEM: the first certificate (a file may hold a key first); else DER.
	for rest := b; ; {
		var p *pem.Block
		if p, rest = pem.Decode(rest); p == nil {
			break
		}
		if p.Type == "CERTIFICATE" {
			b = p.Bytes
			break
		}
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return "", fmt.Errorf("--upstream-ca %s: not a certificate (PEM or DER): %w", path, err)
	}
	if !cert.IsCA {
		return "", fmt.Errorf("--upstream-ca %s: %q is not a CA certificate", path, cert.Subject.CommonName)
	}
	out := filepath.Join(state, "upstream-ca.pem")
	if err := os.WriteFile(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		return "", err
	}
	return out, nil
}

// tailscaleStatus is `tailscale status --json` from the Tailscale CLI, if any
// (on macOS the app's binary works as one).
var tailscaleStatus = func() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	bins := []string{"/Applications/Tailscale.app/Contents/MacOS/Tailscale"}
	if bin, err := exec.LookPath("tailscale"); err == nil {
		bins = append([]string{bin}, bins...) // one that cannot reach tailscaled gives way to the app's
	}
	var err error
	for _, bin := range bins {
		var out []byte
		if out, err = exec.CommandContext(ctx, bin, "status", "--json").Output(); err == nil {
			return out, nil
		}
	}
	return nil, err
}

// iosDevices names this user's iPhones and iPads on the tailnet, online ones
// first, for a missing --device: nothing if the CLI is not there.
func iosDevices() []string {
	out, err := tailscaleStatus()
	if err != nil {
		return nil
	}
	var st struct {
		Self struct{ UserID int64 }
		Peer map[string]struct {
			DNSName, OS string
			UserID      int64
			Online      bool
		}
	}
	if json.Unmarshal(out, &st) != nil {
		return nil
	}
	var online, offline []string
	for _, p := range st.Peer {
		name, _, _ := strings.Cut(p.DNSName, ".")
		if p.OS != "iOS" || p.UserID != st.Self.UserID || name == "" {
			continue
		}
		if p.Online {
			online = append(online, name+" (online)")
		} else {
			offline = append(offline, name)
		}
	}
	slices.Sort(online)
	slices.Sort(offline)
	return append(online, offline...)
}

// hostsOnly takes the hosts out of --allow-hosts values pasted as URLs or with
// a port, saying so: only hosts are matched, not schemes, paths or ports.
func hostsOnly(specs []string) []string {
	var out []string
	for _, spec := range specs {
		var hosts []string
		for _, h := range strings.Split(spec, ",") {
			h = strings.TrimSpace(h)
			host := h
			if u, err := url.Parse(h); err == nil && strings.Contains(h, "://") && u.Hostname() != "" {
				host = u.Hostname()
			} else if hh, port, err := net.SplitHostPort(h); err == nil && port != "" {
				host = hh
			}
			if host != h {
				log.Printf("--allow-hosts: %q taken as %q (hosts are matched, not paths or ports)", h, host)
			}
			hosts = append(hosts, host)
		}
		out = append(out, strings.Join(hosts, ","))
	}
	return out
}
