// Command reqcove lets an AI agent read the HTTP(S) traffic of iPhones in
// your tailnet: the iPhone picks reqcove as its exit node, mitmproxy decrypts
// the traffic, and `reqcove mcp` serves it to the agent.
//
//	reqcove run --device NAME [--device NAME ...]   until Ctrl-C
//	reqcove mcp                                     what the agent launches
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

// version is set at release builds: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: reqcove run --device NAME [...] | reqcove status | reqcove cleanup | reqcove mcp | reqcove version")
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
	fs.Func("device", "device whose traffic is carried: machine name, device name, tailnet IP or StableID (repeatable)", func(v string) error {
		devices = append(devices, v)
		return nil
	})
	var allowSpecs []string
	fs.Func("allow-hosts", `hosts decrypted and recorded, comma-separated (repeatable): "api.example.com", "*.example.com", or "*" for everything. Without it, nothing is recorded.`, func(v string) error {
		allowSpecs = append(allowSpecs, v)
		return nil
	})
	rules := fs.String("rules", "", "YAML file of map_remote, map_local and modify_headers rules (mitmproxy's syntax), applied to --allow-hosts hosts only")
	web := fs.Bool("web", false, "run mitmweb instead of mitmdump, its UI on http://127.0.0.1:8081 (no masking, can edit and replay)")
	noRedact := fs.Bool("no-redact", false, "keep Authorization, cookies and secret query values in the records")
	state := fs.String("state", defaultState(), "state directory")
	hostname := fs.String("hostname", "reqcove", "tailnet node name")
	dnsFlag := fs.String("dns", "1.1.1.1:53", `exit node DNS upstreams, comma-separated; "system" for the first nameserver in /etc/resolv.conf`)
	mitmSpec := fs.String("mitmproxy-spec", "mitmproxy==12.3.1", "uvx --from spec for mitmproxy")
	python := fs.String("python", "3.14", "Python for uvx")
	uvx := fs.String("uvx", "uvx", "path to uvx")
	proxyPort := fs.Int("proxy-port", 8080, "Remote Proxy port on the tailnet, for the iPhone's Wi-Fi proxy setting; 0 turns it off")
	verbose := fs.Bool("verbose", false, "log tsnet's backend and every flow decision")
	fs.Parse(args)
	if len(devices) == 0 {
		return fmt.Errorf("--device is required (see `tailscale status` for names)")
	}
	dns, err := parseDNS(*dnsFlag)
	if err != nil {
		return err
	}
	allow, err := capture.ParseAllowHosts(allowSpecs)
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

	if _, err := exec.LookPath(*uvx); err != nil {
		return fmt.Errorf("uv not found (%s): install it first, https://docs.astral.sh/uv/ ; reqcove fetches mitmproxy and Python with it", *uvx)
	}
	if err := os.MkdirAll(*state, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(*state, 0o700); err != nil {
		return err
	}
	unlock, err := lockState(*state)
	if err != nil {
		return err
	}
	defer unlock()
	keepAwake(ctx)

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
	}
	if *rules != "" {
		log.Printf("rules from %s: %v", *rules, s["rules"])
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
	go mcpserver.Serve(ctx, mcpSock, mcpserver.New(cap.Store, func() mcpserver.StatusOut {
		stats := cap.Store.Stats()
		n := node.get()
		return mcpserver.StatusOut{Node: n, Capture: stats, NextSteps: nextSteps(n, stats, allow, cap.CA, cap.Store.Devices())}
	}))
	log.Printf("MCP on %s; agents connect with `reqcove mcp`", mcpSock)

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
		ap, err := netip.ParseAddrPort(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("--dns: %w", err)
		}
		out = append(out, ap)
	}
	return out, nil
}

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
	fs.Parse(args)
	sock := filepath.Join(*state, "mcp.sock")
	if err := mcpserver.Relay(ctx, sock, os.Stdin, os.Stdout); err != nil {
		return fmt.Errorf("is `reqcove run` running? %w", err)
	}
	return nil
}
