package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
)

// runOpts are run's flags, checked: what parseRunFlags leaves for run.
type runOpts struct {
	devices                             []string
	allow                               capture.HostRules
	rules                               string
	rulesReload, web, noRedact          bool
	state, hostname                     string
	dns                                 []netip.AddrPort
	mitmSpec, python, uvx               string
	proxyPort                           int
	mcpHTTP, ui, verbose, lanMode       bool
	upstreamProxy, upstreamCA, upstream string
	lanIface                            string
	localProxy                          bool
}

// parseRunFlags defines run's flags, reads --config and the command line, and
// refuses what does not go together, warning of what is risky; it also sets
// the mask policy and loads --proto.
func parseRunFlags(args []string) (*runOpts, error) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var devices []string
	fs.Func("device", "device whose traffic is carried: machine name, device name (your own devices), tailnet IP or StableID (repeatable)", func(v string) error {
		devices = append(devices, v)
		return nil
	})
	var allowSpecs, passSpecs []string
	fs.Func("allow-hosts", `hosts decrypted and recorded, comma-separated (repeatable): "api.example.com", "*.example.com", or "*" for everything; @FILE reads them from a file, one a line. Without it, nothing is recorded.`, func(v string) error {
		v, err := hostList(v)
		allowSpecs = append(allowSpecs, v)
		return err
	})
	fs.Func("pass-hosts", `allowed hosts carried undecrypted, as --allow-hosts' (not "*"; @FILE too): for apps that refuse Reqcove's certificate there (certificate pinning). Only their connections are recorded (host, times, bytes): no URL, headers or bodies`, func(v string) error {
		v, err := hostList(v)
		passSpecs = append(passSpecs, v)
		return err
	})
	rulesReload := fs.Bool("rules-reload", false, "take the --rules file again whenever it changes, while running (whatever can write the file can then change where the devices' requests go)")
	rules := fs.String("rules", "", "YAML file of map_remote, map_local and modify_headers rules (mitmproxy's syntax), and mock, resolve and keep_host_header (reqcove's), applied to --allow-hosts hosts only")
	web := fs.Bool("web", false, "run mitmweb instead of mitmdump: on http://127.0.0.1:8081 (8091-8099 while another run has it), and on the node's port 8081 for your own devices on the tailnet (no masking, can edit and replay; a link with a token is printed)")
	noRedact := fs.Bool("no-redact", false, "keep secrets unmasked in the records (headers, URLs, bodies, error text)")
	protoFile := fs.String("proto", "", "a compiled protobuf schema (protoc --descriptor_set_out=FILE --include_imports): messages of its gRPC, Connect and Twirp methods are read with their field names and masked by name; without it, protobuf shows its structure only")
	var maskNameSpecs, maskValueSpecs []string
	fs.Func("mask-names", "names to mask as secret too, as the built-in ones are (headers, URL and form parameters, JSON fields, GraphQL arguments), comma-separated, or @FILE (one a line)", func(v string) error {
		maskNameSpecs = append(maskNameSpecs, v)
		return nil
	})
	// Checked after parsing, by number: the flag package would print a value it refused, and a pattern may be a secret.
	fs.Func("mask-values", "a pattern (RE2) whose matches are masked wherever they appear, such as 'key=[A-Za-z0-9]{16,}'; repeat it, or @FILE (one a line): a file keeps a literal secret out of ps (write one as \\Q…\\E, so + / . in it match themselves)", func(v string) error {
		maskValueSpecs = append(maskValueSpecs, v)
		return nil
	})
	state := fs.String("state", defaultState(), "state directory")
	fs.String("hostname", "reqcove", "tailnet node name, kept in the state for the next runs (with a new --state named reqcove-NAME, that name)")
	dnsFlag := fs.String("dns", "1.1.1.1:53", `exit node DNS upstreams, comma-separated; "system" for the first nameserver in /etc/resolv.conf`)
	mitmSpec := fs.String("mitmproxy-spec", defaultMitmSpec, "uvx --from spec for mitmproxy")
	python := fs.String("python", defaultPython, "Python for uvx")
	uvx := fs.String("uvx", "uvx", "path to uvx (uv beside it runs the default mitmproxy from its lock, hashes checked)")
	proxyPort := fs.Int("proxy-port", 8080, "the proxy port for the iPhone's Wi-Fi proxy setting: the Remote Proxy's on the tailnet, or with --lan the LAN proxy's; 0 turns the Remote Proxy off")
	mcpHTTP := fs.Bool("mcp-http", false, fmt.Sprintf("serve the MCP tools on the node's port %d (http://NODE:%d/mcp) for agents on your own devices on the tailnet, such as Grok Bot, with the token reqcove links prints", exitnode.MCPPort, exitnode.MCPPort))
	uiFlag := fs.Bool("ui", false, "serve a read-only page of the flows on the node's port 80: your own devices on the tailnet see every device's, a --device device of another user its own (a link with a token is printed)")
	upstreamProxy := fs.String("upstream-proxy", "", "send decrypted requests on through this HTTP proxy (Burp Suite, ZAP, …): http://HOST:PORT")
	upstreamCA := fs.String("upstream-ca", "", "the upstream proxy's CA (PEM or DER, as Burp exports it): trusted instead of the public CAs; for a proxy that decrypts")
	verbose := fs.Bool("verbose", false, "log tsnet's backend and every flow decision")
	lanMode := fs.Bool("lan", false, "LAN mode, without Tailscale: an HTTP proxy on this computer's LAN address (--proxy-port), for clients on that network you allow (reqcove lan allow ADDR, or run's prompt); ports 80 and 443 only")
	lanIface := fs.String("lan-interface", "", "with --lan, the interface to listen on (default: the default route's, such as en0)")
	localProxy := fs.Bool("local-proxy", false, fmt.Sprintf("an HTTP proxy on 127.0.0.1:%d for this computer's own apps, such as the iOS Simulator, recorded as the device \"local\"; on macOS the system's web proxies point at it while run runs", localProxyPort))
	fs.String("config", "", "a `FILE` of these flags, one a line (for a service), read before the command line's; --no-redact, --web, --rules-reload, --lan and --allow-hosts '*' are refused there. The file must be yours, readable by you only (chmod 600)")
	if takeFlags == nil { // the docs test reads no file
		if path, ok, err := configFile(args); err != nil {
			return nil, err
		} else if ok {
			if err := parseConfig(fs, path, &allowSpecs); err != nil {
				return nil, err
			}
		}
	}
	if err := parseFlags(fs, args); err != nil {
		return nil, err
	}
	if *proxyPort < 0 || *proxyPort > 65535 { // LAN mode took 65616 as 80 (16 bits)
		return nil, fmt.Errorf("--proxy-port %d: a port is 1 to 65535 (0 turns the Remote Proxy off)", *proxyPort)
	}
	if err := lanFlags(fs, *lanMode, *proxyPort); err != nil {
		return nil, err
	}
	hostname := nodeName(fs, *state)
	if len(devices) == 0 && !*localProxy && !*lanMode {
		msg := "--device is required: the iPhone to carry, by its machine name (see `tailscale status`)"
		if names := iosDevices(); len(names) > 0 {
			msg += "; yours on this tailnet: " + strings.Join(names, ", ")
		}
		return nil, errors.New(msg)
	}
	dns, err := parseDNS(*dnsFlag)
	if err != nil {
		return nil, err
	}
	allow, err := capture.ParseAllowHosts(hostsOnly("--allow-hosts", allowSpecs))
	if err != nil {
		return nil, err
	}
	if len(passSpecs) > 0 {
		if !allow.All && len(allow.Patterns) == 0 {
			return nil, errors.New("--pass-hosts needs --allow-hosts: hosts outside it pass undecrypted already, and nothing about them is recorded")
		}
		if allow, err = allow.WithPass(hostsOnly("--pass-hosts", passSpecs)); err != nil {
			return nil, err
		}
		for _, h := range allow.PassHosts {
			name := strings.TrimPrefix(h, "*.")
			this, _ := capture.ParseAllowHosts([]string{h})
			// Allowed by --allow-hosts, or covering one of its hosts (*.example.com
			// over api.example.com).
			covered := allow.Allowed(name) || slices.ContainsFunc(allow.Hosts, func(a string) bool { return this.Allowed(strings.TrimPrefix(a, "*.")) })
			switch {
			case capture.AppleIgnored(name):
				log.Printf("WARN: --pass-hosts %s: one of Apple's, which mitmproxy passes undecrypted itself: nothing about it is recorded", h)
			case !covered:
				log.Printf("WARN: --pass-hosts %s: not in --allow-hosts, so it passes undecrypted already, and nothing about it is recorded", h)
			}
		}
		for _, a := range allow.Hosts {
			if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() {
				log.Printf("WARN: --allow-hosts %s: connections to that address are decrypted whatever name they carry; --pass-hosts does not apply to them", a)
			}
		}
		log.Printf("--pass-hosts: %s carried undecrypted; their connections (host, times, bytes) are recorded, nothing inside them", strings.Join(allow.PassHosts, ", "))
	}
	switch {
	case allow.All:
		log.Print("WARN: --allow-hosts '*': every decrypted request is recorded, including other apps' and sites'. Agents, and their model providers, can read them.")
	case len(allow.Patterns) == 0:
		log.Print("no --allow-hosts: traffic is carried but nothing is decrypted or recorded. Add --allow-hosts api.example.com for your app.")
	}
	if *rules != "" {
		if !allow.All && len(allow.Patterns) == 0 {
			return nil, fmt.Errorf("--rules needs --allow-hosts: rules apply only to the hosts reqcove decrypts")
		}
		if *rules, err = filepath.Abs(*rules); err != nil {
			return nil, err
		}
		if _, err := os.Stat(*rules); err != nil {
			return nil, fmt.Errorf("--rules: %w", err)
		}
	} else if *rulesReload {
		return nil, errors.New("--rules-reload needs --rules FILE")
	}
	if *noRedact {
		log.Print("WARN: --no-redact: secrets are kept unmasked in the records (headers, URLs, bodies, error text)")
	}
	if *mitmSpec == capture.LockedMitmSpec && pythonBelow(*python, 3, 14) {
		return nil, fmt.Errorf("--python %s: the locked mitmproxy needs Python 3.14 or later; with an older one, give --mitmproxy-spec too (fetched through uvx, no lock)", *python)
	}
	maskNames, maskValues, err := maskPolicy(maskNameSpecs, maskValueSpecs)
	if err != nil {
		return nil, err
	}
	if *noRedact && len(maskNames)+len(maskValues) > 0 {
		log.Print("WARN: --mask-names and --mask-values do nothing with --no-redact")
	} else if err := capture.SetMaskPolicy(maskNames, maskValues); err != nil {
		return nil, err
	}
	if *protoFile != "" {
		if *noRedact {
			log.Print("WARN: --proto does nothing with --no-redact: protobuf bodies are kept as they came")
		}
		n, err := capture.LoadProtoSchema(*protoFile)
		if err != nil {
			return nil, fmt.Errorf("--proto %s: %w", *protoFile, err)
		}
		log.Printf("--proto: %d message types from %s", n, *protoFile)
	}
	if *uiFlag && *proxyPort == 80 {
		return nil, errors.New("--ui uses the node's port 80: give --proxy-port another")
	}
	if *web && *proxyPort == exitnode.WebPort && !*lanMode { // LAN mode serves no node port
		return nil, fmt.Errorf("--web uses the node's port %d too, for your own devices: give --proxy-port another", exitnode.WebPort)
	}
	if *mcpHTTP && *proxyPort == exitnode.MCPPort {
		return nil, fmt.Errorf("--mcp-http uses the node's port %d: give --proxy-port another", exitnode.MCPPort)
	}
	if *mcpHTTP && *noRedact {
		log.Print("WARN: --mcp-http with --no-redact: agents on your other devices (Grok Bot in xAI's cloud) read the records unmasked")
	}
	if *upstreamProxy != "" && !allow.All && len(allow.Patterns) == 0 {
		return nil, fmt.Errorf("--upstream-proxy needs --allow-hosts: only decrypted requests go on to it")
	}
	upstream, err := parseUpstream(*upstreamProxy, *upstreamCA)
	if err != nil {
		return nil, err
	}
	if len(allow.PassHosts) > 0 && (*rules != "" || upstream != "") {
		log.Print("WARN: --pass-hosts with --rules or --upstream-proxy: the hosts passed through skip both and reach their own servers directly (a host --rules sends to staging reaches production); only their requests mitmproxy decrypts anyway (plain HTTP, or on an allowed host's connection) still go through --upstream-proxy")
	}
	if upstream != "" && allow.All {
		// Burp looks HTTPS names up again on this computer; a site can answer that
		// lookup with 127.0.0.1 or a LAN address (DNS rebinding).
		log.Print("WARN: --upstream-proxy with --allow-hosts '*': the proxy connects to HTTPS hosts by name, looked up again on this computer, so a site the iPhone visits can point it at this computer or the LAN. Keep --allow-hosts to the hosts you test.")
	}
	return &runOpts{
		devices: devices, allow: allow, rules: *rules, rulesReload: *rulesReload, web: *web, noRedact: *noRedact,
		state: *state, hostname: hostname, dns: dns, mitmSpec: *mitmSpec, python: *python, uvx: *uvx,
		proxyPort: *proxyPort, mcpHTTP: *mcpHTTP, ui: *uiFlag, verbose: *verbose, lanMode: *lanMode,
		upstreamProxy: *upstreamProxy, upstreamCA: *upstreamCA, upstream: upstream,
		lanIface: *lanIface, localProxy: *localProxy,
	}, nil
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
