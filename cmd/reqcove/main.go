// Command reqcove lets an AI agent read the HTTP(S) traffic of iPhones in
// your tailnet: the iPhone picks reqcove as its exit node, mitmproxy decrypts
// the traffic, and `reqcove mcp` serves it to the agent.
//
//	reqcove run --device NAME [--device NAME ...]   until Ctrl-C
//	reqcove mcp                                     what the agent launches
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
	"github.com/mh-mobile/reqcove/internal/webui"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// version is set at release builds: -ldflags "-X main.version=v0.1.0".
var version = "dev"

// buildVersion names a build from source by its commit (dev-77e6706, -dirty
// with changes not committed), so `reqcove mcp` and a `run` of other builds
// tell each other apart; a release keeps the version it was given.
func buildVersion(v string, info *debug.BuildInfo) string {
	if v != "dev" {
		return v
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch {
		case s.Key == "vcs.revision" && len(s.Value) >= 7:
			rev = s.Value[:7]
		case s.Key == "vcs.modified" && s.Value == "true":
			dirty = "-dirty"
		}
	}
	if rev == "" {
		return v
	}
	return v + "-" + rev + dirty
}

const usage = `Reqcove hands an iPhone's HTTP(S) traffic to AI agents over MCP.

Usage:
  reqcove run --device NAME --allow-hosts HOSTS [flags]
                     (--local-proxy instead of, or with, --device: the iOS Simulator)
                     carry the device's traffic as a Tailscale exit node and record
                     the allowed hosts; prints what is left to set up
  reqcove status     what reqcove is doing, and the next steps
  reqcove links      the login URL and the --ui, --web, --mcp-http links, in your
                     terminal only (never for an agent)
  reqcove mcp        the MCP server for an agent: claude mcp add reqcove -- reqcove mcp
  reqcove har > flows.har
                     the recorded flows as a HAR file, masked (-h for filters)
  reqcove cleanup    how to undo everything (--delete-state removes ~/.reqcove)
  reqcove init       add the agent skill (how to use reqcove's tools) to the agents in ~
  reqcove version

"reqcove run -h" lists run's flags. More: https://github.com/mh-mobile/reqcove
`

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		version = buildVersion(version, info)
	}
	mcpserver.Version = version
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(capture.GoMemoryLimit)
	}
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) { // under nohup it stays ignored
		sigs = append(sigs, syscall.SIGHUP) // the terminal closed: --local-proxy must still put the system proxy back
	}
	ctx, stop := signal.NotifyContext(context.Background(), sigs...)
	defer stop()
	var err error
	if c, ok := commands[os.Args[1]]; ok {
		err = c(ctx, os.Args[2:])
	} else {
		err = other(os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

// commands are reqcove's commands with flags; the docs test parses what the
// docs write with each one's own flags.
var commands = map[string]func(context.Context, []string) error{
	"run":     run,
	"mcp":     func(ctx context.Context, args []string) error { return runMCP(ctx, args, &mcp.StdioTransport{}) },
	"status":  status,
	"har":     har,
	"cleanup": func(_ context.Context, args []string) error { return cleanup(args) },
	"init":    func(_ context.Context, args []string) error { return initSkill(args) },
	"links":   links,
}

// noFlags are the commands that take nothing.
var noFlags = []string{"version", "--version", "-version", "help", "-h", "-help", "--help"}

func other(name string) error {
	switch name {
	case "version", "--version", "-version":
		fmt.Println("reqcove", version)
		return nil
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q", name)
}

// The mitmproxy and Python run uses, unless told otherwise; the Dockerfile
// fetches the same (TestDockerfileInStep).
const (
	defaultMitmSpec = capture.LockedMitmSpec
	defaultPython   = "3.14"
)

func defaultState() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".reqcove")
}

func run(ctx context.Context, args []string) error {
	logOut := log.Writer()
	red := &exitnode.Redactor{W: logOut} // tokens and login URLs never in a log line
	log.SetOutput(red)
	defer log.SetOutput(logOut)
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
	proxyPort := fs.Int("proxy-port", 8080, "Remote Proxy port on the tailnet, for the iPhone's Wi-Fi proxy setting; 0 turns it off")
	mcpHTTP := fs.Bool("mcp-http", false, fmt.Sprintf("serve the MCP tools on the node's port %d (http://NODE:%d/mcp) for agents on your own devices on the tailnet, such as Grok Bot, with the token run prints", exitnode.MCPPort, exitnode.MCPPort))
	uiFlag := fs.Bool("ui", false, "serve a read-only page of the flows on the node's port 80: your own devices on the tailnet see every device's, a --device device of another user its own (a link with a token is printed)")
	upstreamProxy := fs.String("upstream-proxy", "", "send decrypted requests on through this HTTP proxy (Burp Suite, ZAP, …): http://HOST:PORT")
	upstreamCA := fs.String("upstream-ca", "", "the upstream proxy's CA (PEM or DER, as Burp exports it): trusted instead of the public CAs; for a proxy that decrypts")
	verbose := fs.Bool("verbose", false, "log tsnet's backend and every flow decision")
	localProxy := fs.Bool("local-proxy", false, fmt.Sprintf("an HTTP proxy on 127.0.0.1:%d for this computer's own apps, such as the iOS Simulator, recorded as the device \"local\"; on macOS the system's web proxies point at it while run runs", localProxyPort))
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	hostname := nodeName(fs, *state)
	if len(devices) == 0 && !*localProxy {
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
	allow, err := capture.ParseAllowHosts(hostsOnly("--allow-hosts", allowSpecs))
	if err != nil {
		return err
	}
	if len(passSpecs) > 0 {
		if !allow.All && len(allow.Patterns) == 0 {
			return errors.New("--pass-hosts needs --allow-hosts: hosts outside it pass undecrypted already, and nothing about them is recorded")
		}
		if allow, err = allow.WithPass(hostsOnly("--pass-hosts", passSpecs)); err != nil {
			return err
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
			return fmt.Errorf("--rules needs --allow-hosts: rules apply only to the hosts reqcove decrypts")
		}
		if *rules, err = filepath.Abs(*rules); err != nil {
			return err
		}
		if _, err := os.Stat(*rules); err != nil {
			return fmt.Errorf("--rules: %w", err)
		}
	} else if *rulesReload {
		return errors.New("--rules-reload needs --rules FILE")
	}
	if *noRedact {
		log.Print("WARN: --no-redact: secrets are kept unmasked in the records (headers, URLs, bodies, error text)")
	}
	if *mitmSpec == capture.LockedMitmSpec && pythonBelow(*python, 3, 14) {
		return fmt.Errorf("--python %s: the locked mitmproxy needs Python 3.14 or later; with an older one, give --mitmproxy-spec too (fetched through uvx, no lock)", *python)
	}
	maskNames, maskValues, err := maskPolicy(maskNameSpecs, maskValueSpecs)
	if err != nil {
		return err
	}
	if *noRedact && len(maskNames)+len(maskValues) > 0 {
		log.Print("WARN: --mask-names and --mask-values do nothing with --no-redact")
	} else if err := capture.SetMaskPolicy(maskNames, maskValues); err != nil {
		return err
	}
	if *protoFile != "" {
		if *noRedact {
			log.Print("WARN: --proto does nothing with --no-redact: protobuf bodies are kept as they came")
		}
		n, err := capture.LoadProtoSchema(*protoFile)
		if err != nil {
			return fmt.Errorf("--proto %s: %w", *protoFile, err)
		}
		log.Printf("--proto: %d message types from %s", n, *protoFile)
	}
	if *uiFlag && *proxyPort == 80 {
		return errors.New("--ui uses the node's port 80: give --proxy-port another")
	}
	if *web && *proxyPort == exitnode.WebPort {
		return fmt.Errorf("--web uses the node's port %d too, for your own devices: give --proxy-port another", exitnode.WebPort)
	}
	if *mcpHTTP && *proxyPort == exitnode.MCPPort {
		return fmt.Errorf("--mcp-http uses the node's port %d: give --proxy-port another", exitnode.MCPPort)
	}
	if *mcpHTTP && *noRedact {
		log.Print("WARN: --mcp-http with --no-redact: agents on your other devices (Grok Bot in xAI's cloud) read the records unmasked")
	}
	if *upstreamProxy != "" && !allow.All && len(allow.Patterns) == 0 {
		return fmt.Errorf("--upstream-proxy needs --allow-hosts: only decrypted requests go on to it")
	}
	upstream, err := parseUpstream(*upstreamProxy, *upstreamCA)
	if err != nil {
		return err
	}
	if len(allow.PassHosts) > 0 && (*rules != "" || upstream != "") {
		log.Print("WARN: --pass-hosts with --rules or --upstream-proxy: the hosts passed through skip both and reach their own servers directly (a host --rules sends to staging reaches production); only their requests mitmproxy decrypts anyway (plain HTTP, or on an allowed host's connection) still go through --upstream-proxy")
	}
	if upstream != "" && allow.All {
		// Burp looks HTTPS names up again on this computer; a site can answer that
		// lookup with 127.0.0.1 or a LAN address (DNS rebinding).
		log.Print("WARN: --upstream-proxy with --allow-hosts '*': the proxy connects to HTTPS hosts by name, looked up again on this computer, so a site the iPhone visits can point it at this computer or the LAN. Keep --allow-hosts to the hosts you test.")
	}

	// First, before anything is changed: one --local-proxy per computer.
	var localLn net.Listener
	if *localProxy {
		if localLn, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localProxyPort)); err != nil {
			return fmt.Errorf("--local-proxy: 127.0.0.1:%d is taken (%v); --local-proxy is one per computer: is another reqcove run using it?", localProxyPort, err)
		}
		defer localLn.Close()
	}
	if _, err := exec.LookPath(*uvx); err != nil {
		return fmt.Errorf("uv not found (%s): install it first, https://docs.astral.sh/uv/ ; reqcove fetches mitmproxy and Python with it", *uvx)
	}
	unlock, err := openState(*state)
	if err != nil {
		return err
	}
	defer unlock()
	onTerminal := isTerminal(os.Stderr)
	linksCmd := withState("reqcove links", *state)
	for _, name := range []string{loginURLFile, linksFile} { // a crashed run's, and this one's at the end
		p := filepath.Join(*state, name)
		os.Remove(p)
		defer os.Remove(p)
	}
	if err := keepNodeName(*state, hostname); err != nil {
		return err
	}
	if confdir := filepath.Join(*state, "mitmproxy"); !isDefaultState(*state) && !capture.HasCA(confdir) {
		// One CA for every node here, so the iPhone's one profile serves them all.
		from := filepath.Join(defaultState(), "mitmproxy")
		abs, _ := filepath.Abs(confdir)
		switch copied, err := capture.CopyCA(from, confdir); {
		case err != nil:
			return fmt.Errorf("the CA of %s, to share it with this node: %w (if the default node is starting for the first time, start this one once it is up; else copy that mitmproxy folder whole from where it came)", defaultState(), err)
		case copied:
			log.Printf("using the CA of %s, copied into %s: the iPhone's profile for it serves this node too", defaultState(), abs)
			if err := noteCACopy(abs); err != nil {
				log.Printf("WARN: %s does not list this copy (%v): its cleanup will not name it", defaultState(), err)
			}
		default:
			log.Printf("%s has no CA yet: this node makes one of its own, and the iPhone needs its profile too (to share one: stop this node, start the default one and wait until it prints its CA, then start this one with a new --state)", defaultState())
		}
	}
	if !isDefaultState(*state) {
		log.Printf("this node's commands take --state too: %s", withState("reqcove status", *state))
		if hostname == "reqcove" {
			log.Print("the node is named reqcove, as the default state's is: give --hostname, or name --state reqcove-NAME, to tell them apart")
		}
	}
	// A run that died with the system proxy pointed at it: put it back first.
	if err := restoreSystemProxy(*state); err != nil {
		log.Printf("WARN: the system's web proxies, pointed at reqcove by a run that did not stop cleanly, could not be put back: %v. System Settings, Network, Details, Proxies", err)
	}
	keepAwake(ctx)
	var upstreamCAFile string
	if *upstreamCA != "" {
		if upstreamCAFile, err = writeUpstreamCA(*upstreamCA, *state); err != nil {
			return err
		}
	} else if upstream != "" {
		b, err := fetchBurpCA(upstream)
		if err == nil {
			upstreamCAFile, err = saveUpstreamCA(b, "Burp's /cert", *state)
		}
		if err == nil {
			log.Printf("using Burp's CA from %s/cert (--upstream-ca to choose one)", *upstreamProxy)
		} else {
			log.Printf("no Burp CA at %s/cert (%v): the public CAs are trusted through the proxy", *upstreamProxy, err)
		}
	}

	mitmLog, err := os.OpenFile(filepath.Join(*state, "mitmproxy.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer mitmLog.Close()
	webLocal := 0
	if *web {
		if webLocal, err = pickWebPort(); err != nil {
			return err
		}
	}
	log.Printf("starting mitmproxy (%s) through uvx; the first run downloads it", *mitmSpec)
	// The page's and mitmweb's tokens, kept across starts (tokens.go).
	var uiToken, webToken, mcpToken string
	for _, t := range []struct {
		on   bool
		name string
		to   *string
	}{{*uiFlag, "ui-token", &uiToken}, {*web, "web-token", &webToken}, {*mcpHTTP, "mcp-token", &mcpToken}} {
		if !t.on {
			continue
		}
		var made bool
		if *t.to, made, err = keptToken(*state, t.name); err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		} else if made {
			log.Printf("a new token in %s", filepath.Join(*state, t.name))
		}
	}
	red.Add(uiToken, webToken, mcpToken)
	cap, err := capture.Start(ctx, capture.Config{
		Dir: *state, Confdir: filepath.Join(*state, "mitmproxy"),
		Uvx: *uvx, Python: *python, MitmSpec: *mitmSpec,
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
		Log: mitmLog, ReadyTimeout: 2 * time.Minute,
		AllowHosts: allow, NoRedact: *noRedact, Rules: *rules, RulesReload: *rulesReload, WebPort: webLocal, WebPassword: webToken,
		Upstream: upstream, UpstreamCA: upstreamCAFile,
		CAName: caName(),
		Logf:   func(f string, a ...any) { log.Printf(f+" (log: %s)", append(a, mitmLog.Name())...) },
	})
	if err != nil {
		return fmt.Errorf("mitmproxy: %w (log: %s)", err, mitmLog.Name())
	}
	defer cap.Stop()
	red.Add(cap.SocksSecret)
	s := cap.Store.Stats()
	log.Printf("mitmproxy %v ready (Python %v, brotli %v)", s["mitmproxy"], s["python"], s["brotli"])
	if ca := cap.CA; ca.Name != "" {
		log.Printf("CA %q, SHA-256 %s, until %s: iPhones get it from http://mitm.it (the same CA as long as %s is kept; its QR code comes with the others once the node is up)", ca.Name, ca.SHA256, ca.NotAfter.Format("2006-01-02"), filepath.Join(*state, "mitmproxy"))
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
		if *rulesReload {
			log.Printf("--rules-reload: %s is taken again whenever it changes", *rules)
			cap.Store.SetRulesLog(func(r map[string]int, resolve []string, problem string) {
				if problem != "" {
					log.Printf("--rules: %s does not load (%s); the rules before it still apply", *rules, problem)
					return
				}
				log.Printf("rules from %s, again: %v", *rules, r)
				if len(resolve) > 0 {
					log.Printf("resolve: %s", strings.Join(resolve, ", "))
				}
			})
		}
		if r, _ := s["resolve"].([]string); len(r) > 0 {
			log.Printf("resolve: %s (Host and SNI as the app sent them; TLS checked against the name)", strings.Join(r, ", "))
		}
	}
	if *web {
		log.Printf("mitmweb on http://127.0.0.1:%d/ (its link: `%s`)", webLocal, linksCmd)
		if webLocal != exitnode.WebPort {
			log.Printf("(%d is taken here, by another run maybe; on the node it is still %d)", exitnode.WebPort, exitnode.WebPort)
		}
		log.Print("WARN: --web: mitmweb shows traffic unmasked (cookies, tokens), and from its page flows can be edited, replayed and options changed. It keeps the newest 10,000 flows, with bodies up to 2 MB each and 256 MB in all")
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
	tools := mcpserver.New(cap.Store, func() mcpserver.StatusOut {
		return statusOut(node.get(), cap.Store.Stats(), allow, cap.CA, cap.Store.Devices())
	})
	var mcpHandler http.Handler
	if *mcpHTTP {
		mcpHandler = mcpserver.HTTP(tools, mcpToken, exitnode.Caller)
	}
	if err := mcpserver.Serve(ctx, mcpSock, tools); err != nil {
		return fmt.Errorf("MCP socket: %w (a shorter --state path helps if it is too long)", err)
	}
	hint := mcpHint(*state, hostname)
	log.Printf("MCP on %s; agents connect with `reqcove mcp` (Claude Code: %s; Codex: %s)", mcpSock, hint, strings.Replace(hint, "claude mcp add", "codex mcp add", 1))
	if n := staleSkillNote(); n != "" {
		log.Print(n)
	}

	webAddr := ""
	if cap.WebURL != "" {
		webAddr = fmt.Sprintf("127.0.0.1:%d", webLocal)
	}
	var pageFn func(w http.ResponseWriter, r *http.Request, deviceID string, all bool)
	var page *webui.UI
	if *uiFlag {
		page = webui.New(cap.Store, uiToken, func(id string, all bool) []string {
			if all { // one of the user's own devices: the steps as `reqcove status` gives them
				return withoutMacStep(statusOut(node.get(), cap.Store.Stats(), allow, cap.CA, cap.Store.Devices()).NextSteps)
			}
			return pageSteps(node.get(), cap.Store.Stats(), allow, cap.CA, cap.Store.Devices(), id)
		})
		if hostname != "reqcove" {
			page.Node = hostname
		}
		pageFn = page.Serve
	}
	var shown bool
	var gate readyGate
	var loginURL string
	onStatus := func(s exitnode.Status) {
		node.set(s)
		switch {
		case s.Backend == "NeedsLogin" && s.AuthURL != "" && s.AuthURL != loginURL:
			loginURL = s.AuthURL
			red.Add(loginURL)
			if err := writePrivate(filepath.Join(*state, loginURLFile), []byte(loginURL+"\n")); err != nil {
				log.Printf("WARN: %s: %v", loginURLFile, err)
			}
			if onTerminal { // for the user's eyes: never in a log line
				fmt.Fprintf(os.Stderr, "login URL: %s\n  (whoever opens it first puts this node in their tailnet; `%s` prints it again)\n", loginURL, linksCmd)
			}
		case loginURL != "" && s.Backend != "NeedsLogin":
			loginURL = ""
			os.Remove(filepath.Join(*state, loginURLFile))
		}
		ip := firstIPv4(s.IPs)
		if shown || ip == "" || !gate.ready(s) {
			return
		}
		shown = true
		// One block when ready, so what to do is not lost among the lines above.
		// Tokens stay in this terminal, as the login URL does: never in the MCP tools.
		var uiLink, webLink string
		if page != nil {
			uiLink = "http://" + ip + "/?k=" + uiToken
		}
		if webAddr != "" {
			webLink = nodeWebLink(cap.WebURL, webAddr, ip)
		}
		var mcpURL string
		if mcpHandler != nil {
			host := strings.TrimSuffix(s.Node, ".") // the MagicDNS name, as Grok Bot asks for
			if host == "" {
				host = ip
			}
			mcpURL = fmt.Sprintf("http://%s:%d/mcp", host, exitnode.MCPPort)
		}
		if err := writePrivate(filepath.Join(*state, linksFile), formatLinks([]linkLine{{"ui", uiLink}, {"web", webLink}, {"mcp", mcpURL}, {"mcp-token", mcpToken}})); err != nil {
			log.Printf("WARN: %s: %v", linksFile, err)
		}
		shownUI, shownWeb, shownToken := uiLink, webLink, mcpToken
		if !onTerminal { // a service, docker logs: the links stay in the file
			hint := "(`" + linksCmd + "` prints it)"
			for _, v := range []*string{&shownUI, &shownWeb, &shownToken} {
				if *v != "" {
					*v = hint
				}
			}
		}
		fmt.Fprint(os.Stderr, readyBlock(s.Devices, shownUI, shownWeb, mcpURL, shownToken, *state, statusOut(s, cap.Store.Stats(), allow, cap.CA, cap.Store.Devices()).NextSteps, onTerminal))
		var codes []qrItem
		if uiLink != "" {
			codes = append(codes, qrItem{uiLink, "--ui (the flows)"})
		}
		if webLink != "" {
			codes = append(codes, qrItem{webLink, "--web (mitmweb, unmasked)"})
		}
		if len(devices) > 0 {
			codes = append(codes, qrItem{"http://mitm.it", "CA (with the exit node on)"})
		}
		printQRs(os.Stderr, codes...)
	}
	localAddr := ""
	if localLn != nil {
		localAddr = fmt.Sprintf("127.0.0.1:%d", localProxyPort)
		caPEM := filepath.Join(*state, "mitmproxy", "mitmproxy-ca-cert.pem")
		trusted := macTrusts(caPEM)
		switch {
		case allow.All && trusted:
			log.Print("WARN: --local-proxy with --allow-hosts '*', and this computer trusts Reqcove's CA: every HTTPS site its apps open (but Apple's) is decrypted and recorded")
		case allow.All:
			log.Print("WARN: --local-proxy with --allow-hosts '*': every HTTPS site this computer's apps open is decrypted, and fails in those that do not trust Reqcove's CA (Safari here, say)")
		}
		if runtime.GOOS == "darwin" {
			if trusted {
				log.Printf("this Mac trusts Reqcove's CA: its own browsers' requests to the allowed hosts are decrypted and recorded too, as \"local\" (to stop: %s)", macUntrustCommand(cap.CA.SHA256))
			}
			localCA = caPEM // nextSteps says how to trust it, while this Mac does not
			log.Printf("local proxy on %s, recorded as the device \"local\"", localAddr)
			if sims, err := trustInSimulators(caPEM); err != nil {
				log.Printf("WARN: the CA into the iOS Simulator: %v", err)
			} else if len(sims) > 0 {
				log.Printf("CA added to the booted iOS Simulators: %s (one booted later: xcrun simctl keychain booted add-root-cert %s)", strings.Join(sims, ", "), shellWord(caPEM))
			} else {
				log.Printf("no iOS Simulator booted: once one is, xcrun simctl keychain booted add-root-cert %s", shellWord(caPEM))
			}
		} else {
			log.Printf("local proxy on %s: point apps at it (HTTPS_PROXY=http://%s HTTP_PROXY=http://%s NO_PROXY=localhost,127.0.0.1) and have them trust the CA %s (docs/guide.md, The iOS Simulator, has the commands); recorded as the device \"local\"", localAddr, localAddr, localAddr, caPEM)
		}
	}
	err = withSystemProxy(*state, *localProxy, func() error {
		return exitnode.Run(ctx, exitnode.Config{
			Dir: filepath.Join(*state, "tsnet"), Hostname: hostname, DNS: dns,
			Devices: devices, SocksAddr: cap.SocksAddr, SocksSecret: cap.SocksSecret, SocksReady: cap.WaitReady, ProxyPort: *proxyPort, Verbose: *verbose,
			UI:         pageFn,
			Web:        webAddr,
			MCP:        mcpHandler,
			LocalProxy: localLn,
			StatusCmd:  withState("reqcove status", *state),
			LinksCmd:   linksCmd,
			OnDevices:  cap.Store.SetDeviceNames, OnStatus: onStatus,
		})
	})
	if len(devices) > 0 {
		fmt.Fprintln(os.Stderr, "\nreqcove is stopping. On the iPhone, turn off the exit node, or set the Wi-Fi proxy back to Off: without reqcove it cannot reach the internet.")
	}
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
	if takeFlags != nil { // the docs test: the command's flags, not run
		takeFlags(fs)
		return errFlagsTaken
	}
	fs.Usage = func() { usageOf(fs) }
	if err := fs.Parse(args); err != nil { // ExitOnError exits first; a test's ContinueOnError returns
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q (quote values with spaces, such as --device \"Taro's iPhone\")", fs.Arg(0))
	}
	// --state=~/x, or a quoted ~: the shell left the ~, which would name ./~/x
	// (for run, a place to copy the CA's key into; for cleanup, one already gone).
	if f := fs.Lookup("state"); f != nil && strings.HasPrefix(f.Value.String(), "~") {
		given := false
		fs.Visit(func(v *flag.Flag) { given = given || v.Name == "state" })
		if !given {
			return fmt.Errorf("HOME is %s, starting with ~: set it to the full path of your home directory", os.Getenv("HOME"))
		}
		return fmt.Errorf("--state %s: the shell did not expand the ~ (it does not after =, nor in quotes): write --state ~/… with a space, or the full path", f.Value.String())
	}
	return nil
}

// takeFlags, set by the docs test, is handed each command's FlagSet in place
// of parsing it. Every command calls parseFlags before doing anything else.
var (
	takeFlags     func(*flag.FlagSet)
	errFlagsTaken = errors.New("flags taken")
)

// usageOf prints a command's flags with two dashes, as the README and run's
// own messages write them (Go's flag package prints one; it takes either).
func usageOf(fs *flag.FlagSet) {
	var b strings.Builder
	fs.SetOutput(&b)
	fs.PrintDefaults()
	fs.SetOutput(os.Stderr)
	fmt.Fprintf(os.Stderr, "Usage: reqcove %s [flags]\n", fs.Name())
	for _, line := range strings.SplitAfter(b.String(), "\n") {
		if strings.HasPrefix(line, "  -") {
			line = "  --" + line[3:]
		}
		fmt.Fprint(os.Stderr, line)
	}
}

func runMCP(ctx context.Context, args []string, agent mcp.Transport) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	// The agent's connection stays up while run restarts or is not running.
	err := mcpserver.Proxy(ctx, filepath.Join(*state, "mcp.sock"), notRunningMsg(*state), agent)
	if ctx.Err() != nil {
		return nil // a signal: not an error
	}
	return err
}

// notRunningMsg is what the agent's tools answer while run is not running.
func notRunningMsg(state string) string {
	return fmt.Sprintf("reqcove is not running (%s). Do not start it yourself: the user starts `%s` in a terminal and leaves it running (if it is restarting, wait a few seconds). Then call again; the records start empty after a restart.", state, withState("reqcove run …", state))
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
