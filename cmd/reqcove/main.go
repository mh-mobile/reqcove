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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: reqcove run --device NAME [...] | reqcove mcp")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "run":
		err = run(ctx, os.Args[2:])
	case "mcp":
		err = mcp(ctx, os.Args[2:])
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
	if *noRedact {
		log.Print("WARN: --no-redact: Authorization, cookies and secret query values are kept in the records")
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
		BodyHead: 64 << 10, MaxFlows: 10000, MaxBytes: 256 << 20,
		Log: mitmLog, ReadyTimeout: 2 * time.Minute,
		AllowHosts: allow, NoRedact: *noRedact,
		Logf: func(f string, a ...any) { log.Printf(f+" (log: %s)", append(a, mitmLog.Name())...) },
	})
	if err != nil {
		return fmt.Errorf("mitmproxy: %w (log: %s)", err, mitmLog.Name())
	}
	defer cap.Stop()
	s := cap.Store.Stats()
	log.Printf("mitmproxy %v ready (Python %v, brotli %v)", s["mitmproxy"], s["python"], s["brotli"])

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
	go mcpserver.Serve(ctx, mcpSock, mcpserver.New(cap.Store))
	log.Printf("MCP on %s; agents connect with `reqcove mcp`", mcpSock)

	err = exitnode.Run(ctx, exitnode.Config{
		Dir: filepath.Join(*state, "tsnet"), Hostname: *hostname, DNS: dns,
		Devices: devices, SocksAddr: cap.SocksAddr, SocksSecret: cap.SocksSecret, ProxyPort: *proxyPort, Verbose: *verbose,
		OnDevices: cap.Store.SetDeviceNames,
	})
	fmt.Fprintln(os.Stderr, "\nreqcove is stopping. On the iPhone, turn off the exit node, or set the Wi-Fi proxy back to Off: without reqcove it cannot reach the internet.")
	if ctx.Err() != nil {
		return nil // Ctrl-C, or mitmproxy failed (already logged)
	}
	return err
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

func mcp(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	fs.Parse(args)
	sock := filepath.Join(*state, "mcp.sock")
	if err := mcpserver.Relay(ctx, sock, os.Stdin, os.Stdout); err != nil {
		return fmt.Errorf("is `reqcove run` running? %w", err)
	}
	return nil
}
