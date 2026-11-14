package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
	"github.com/mh-mobile/reqcove/internal/webui"
)

func run(ctx context.Context, args []string) error {
	// Tokens and login URLs never in a log line: kept after run returns, so
	// main's log.Fatal goes through it too.
	red := &exitnode.Redactor{W: log.Writer()}
	log.SetOutput(red)
	o, err := parseRunFlags(args)
	if err != nil {
		return err
	}

	var lanCfg *exitnode.LAN
	if o.lanMode {
		if lanCfg, err = lanConfig(ctx, o.lanIface, o.state, o.allow); err != nil {
			return err
		}
	}

	// First, before anything is changed: one --local-proxy per computer.
	var localLn net.Listener
	if o.localProxy {
		if localLn, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localProxyPort)); err != nil {
			return fmt.Errorf("--local-proxy: 127.0.0.1:%d is taken (%v); --local-proxy is one per computer: is another reqcove run using it?", localProxyPort, err)
		}
		defer localLn.Close()
	}
	if _, err := exec.LookPath(o.uvx); err != nil {
		return fmt.Errorf("uv not found (%s): install it first, https://docs.astral.sh/uv/ ; reqcove fetches mitmproxy and Python with it", o.uvx)
	}
	unlock, err := openState(o.state)
	if err != nil {
		return err
	}
	defer unlock()
	linksCmd := withState("reqcove links", o.state)
	user := newUserLinks(os.Stderr, red, o.state, linksCmd)
	user.lan = o.lanMode
	defer func() { stepLinksCmd = "reqcove links" }()
	for _, name := range []string{loginURLFile, linksFile} { // a crashed run's, and this one's at the end
		p := filepath.Join(o.state, name)
		os.Remove(p)
		defer os.Remove(p)
	}
	if err := keepNodeName(o.state, o.hostname); err != nil {
		return err
	}
	if err := shareCA(o.state); err != nil {
		return err
	}
	for _, n := range stateNotes(o.state, o.hostname, o.lanMode) {
		log.Print(n)
	}
	// A run that died with the system proxy pointed at it: put it back first.
	if err := restoreSystemProxy(o.state); err != nil {
		log.Printf("WARN: the system's web proxies, pointed at reqcove by a run that did not stop cleanly, could not be put back: %v. System Settings, Network, Details, Proxies", err)
	}
	keepAwake(ctx)
	upstreamCAFile, err := upstreamCA(o)
	if err != nil {
		return err
	}

	mitmLog, err := os.OpenFile(filepath.Join(o.state, "mitmproxy.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer mitmLog.Close()
	webLocal := 0
	if o.web {
		if webLocal, err = pickWebPort(); err != nil {
			return err
		}
	}
	log.Printf("starting mitmproxy (%s) through uvx; the first run downloads it", o.mitmSpec)
	uiToken, webToken, mcpToken, err := runTokens(o)
	if err != nil {
		return err
	}
	red.Add(uiToken, webToken, mcpToken)
	cap, err := capture.Start(ctx, capture.Config{
		Dir: o.state, Confdir: filepath.Join(o.state, "mitmproxy"),
		Uvx: o.uvx, Python: o.python, MitmSpec: o.mitmSpec,
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
		Log: mitmLog, ReadyTimeout: 2 * time.Minute,
		AllowHosts: o.allow, NoRedact: o.noRedact, Rules: o.rules, RulesReload: o.rulesReload, WebPort: webLocal, WebPassword: webToken,
		Upstream: o.upstream, UpstreamCA: upstreamCAFile,
		CAName: caName(),
		Logf:   func(f string, a ...any) { log.Printf(f+" (log: %s)", append(a, mitmLog.Name())...) },
	})
	if err != nil {
		return fmt.Errorf("mitmproxy: %w (log: %s)", err, mitmLog.Name())
	}
	defer cap.Stop()
	red.Add(cap.SocksSecret)
	logCapture(o, cap, upstreamCAFile)
	if o.web {
		user.web(cap.WebURL)
		if webLocal != exitnode.WebPort && !o.lanMode {
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
	var node nodeState
	if o.lanMode {
		node.set(exitnode.Status{Mode: "lan"}) // before the first status: not a tailnet node starting
	}
	mcpHandler, err := serveMCP(ctx, o, cap, &node, mcpToken)
	if err != nil {
		return err
	}

	webAddr := ""
	if cap.WebURL != "" {
		webAddr = fmt.Sprintf("127.0.0.1:%d", webLocal)
	}
	var pageFn func(w http.ResponseWriter, r *http.Request, deviceID string, all bool)
	var page *webui.UI
	if o.ui {
		page = uiPage(o, cap, &node, uiToken)
		pageFn = page.Serve
	}
	onStatus := readyOnStatus(o, cap, &node, user, lanCfg, page, mcpHandler, uiToken, mcpToken, webAddr)
	if localLn != nil {
		logLocalProxy(o.state, o.allow, cap.CA.SHA256)
	}
	err = withSystemProxy(o.state, o.localProxy, func() error {
		return exitnode.Run(ctx, exitnode.Config{
			Dir: filepath.Join(o.state, "tsnet"), Hostname: o.hostname, DNS: o.dns,
			Devices: o.devices, SocksAddr: cap.SocksAddr, SocksSecret: cap.SocksSecret, SocksReady: cap.WaitReady, ProxyPort: o.proxyPort, Verbose: o.verbose,
			UI:         pageFn,
			Web:        webAddr,
			MCP:        mcpHandler,
			LocalProxy: localLn,
			LAN:        lanCfg,
			StatusCmd:  withState("reqcove status", o.state),
			LinksCmd:   linksCmd,
			OnDevices:  cap.Store.SetDeviceNames, OnStatus: onStatus,
		})
	})
	if len(o.devices) > 0 || o.lanMode {
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

// shareCA copies the default state's CA into a new --state's.
func shareCA(state string) error {
	if confdir := filepath.Join(state, "mitmproxy"); !isDefaultState(state) && !capture.HasCA(confdir) {
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
	return nil
}

// upstreamCA is the file of the CA mitmproxy trusts through --upstream-proxy:
// --upstream-ca's, else Burp's if the proxy serves one, else none.
func upstreamCA(o *runOpts) (string, error) {
	var upstreamCAFile string
	var err error
	if o.upstreamCA != "" {
		if upstreamCAFile, err = writeUpstreamCA(o.upstreamCA, o.state); err != nil {
			return "", err
		}
	} else if o.upstream != "" {
		b, err := fetchBurpCA(o.upstream)
		if err == nil {
			upstreamCAFile, err = saveUpstreamCA(b, "Burp's /cert", o.state)
		}
		if err == nil {
			log.Printf("using Burp's CA from %s/cert (--upstream-ca to choose one)", o.upstreamProxy)
		} else {
			log.Printf("no Burp CA at %s/cert (%v): the public CAs are trusted through the proxy", o.upstreamProxy, err)
		}
	}
	return upstreamCAFile, nil
}

// runTokens are the page's, mitmweb's and --mcp-http's tokens, kept across
// starts (tokens.go); "" for those not on.
func runTokens(o *runOpts) (uiToken, webToken, mcpToken string, err error) {
	for _, t := range []struct {
		on   bool
		name string
		to   *string
	}{{o.ui, "ui-token", &uiToken}, {o.web, "web-token", &webToken}, {o.mcpHTTP, "mcp-token", &mcpToken}} {
		if !t.on {
			continue
		}
		var made bool
		if *t.to, made, err = keptToken(o.state, t.name); err != nil {
			return "", "", "", fmt.Errorf("%s: %w", t.name, err)
		} else if made {
			log.Printf("a new token in %s", filepath.Join(o.state, t.name))
		}
	}
	return uiToken, webToken, mcpToken, nil
}

// logCapture logs what mitmproxy started with: its version, the CA, the
// upstream proxy and the rules.
func logCapture(o *runOpts, cap *capture.Capture, upstreamCAFile string) {
	s := cap.Store.Stats()
	log.Printf("mitmproxy %v ready (Python %v, brotli %v)", s["mitmproxy"], s["python"], s["brotli"])
	if ca := cap.CA; ca.Name != "" {
		log.Printf("CA %q, SHA-256 %s, until %s: iPhones get it from http://mitm.it (the same CA as long as %s is kept; its QR code comes with the others once the node is up)", ca.Name, ca.SHA256, ca.NotAfter.Format("2006-01-02"), filepath.Join(o.state, "mitmproxy"))
	}
	if o.upstream != "" {
		trust := "the public CAs"
		if upstreamCAFile != "" {
			trust = "its CA only"
		}
		log.Printf("decrypted requests go on to the upstream proxy %s, which sees them unmasked; HTTPS through it is checked against %s", o.upstream, trust)
		if upstreamCAFile == "" {
			log.Print("if the proxy decrypts (ZAP and Charles do), pass its CA with --upstream-ca, or HTTPS through it fails with 'unable to get local issuer certificate'")
		}
	}
	if o.rules != "" {
		logRules(o, cap, s)
	}
}

// logRules logs the --rules file's rules and presets, and with --rules-reload
// each time it is taken again.
func logRules(o *runOpts, cap *capture.Capture, s map[string]any) {
	log.Printf("rules from %s: %v", o.rules, s["rules"])
	logPresets := func(names []string, targets map[string]string) {
		if len(names) > 0 {
			log.Printf("presets (off until an agent turns one on, for at most 5 minutes; -> where one sends requests while on): %s", strings.Join(presetNames(names, targets), ", "))
		}
	}
	logPresets(statsPresets(s), cap.Store.PresetTargets())
	if o.rulesReload {
		log.Printf("--rules-reload: %s is taken again whenever it changes", o.rules)
		cap.Store.SetRulesLog(func(r map[string]int, resolve, presets []string, targets map[string]string, problem string) {
			if problem != "" {
				log.Printf("--rules: %s does not load (%s); the rules before it still apply%s", o.rules, problem, presetsOff(presets))
				return
			}
			log.Printf("rules from %s, again: %v%s", o.rules, r, presetsOff(presets))
			logPresets(presets, targets)
			if len(resolve) > 0 {
				log.Printf("resolve: %s", strings.Join(resolve, ", "))
			}
		})
	}
	if r, _ := s["resolve"].([]string); len(r) > 0 {
		log.Printf("resolve: %s (Host and SNI as the app sent them; TLS checked against the name)", strings.Join(r, ", "))
	}
}

// serveMCP serves the MCP tools on the state's socket until ctx ends, and
// returns --mcp-http's handler (nil without it).
func serveMCP(ctx context.Context, o *runOpts, cap *capture.Capture, node *nodeState, mcpToken string) (http.Handler, error) {
	mcpSock := filepath.Join(o.state, "mcp.sock")
	remoteStatus := func() mcpserver.StatusOut {
		return statusOut(node.get(), cap.Store.Stats(), o.allow, cap.CA, cap.Store.Devices())
	}
	tools, remote := mcpserver.Servers(cap.Store, func() mcpserver.StatusOut {
		out := remoteStatus()
		if len(statsPresets(out.Capture)) > 0 {
			ctx, cancel := context.WithTimeout(ctx, time.Second) // status comes first: never long
			defer cancel()
			out.SetActivePresets(cap.Presets(ctx))
		}
		return out
	}, remoteStatus, cap)
	var mcpHandler http.Handler
	if o.mcpHTTP { // its own server: read-only, never the preset tools
		mcpHandler = mcpserver.HTTP(remote, mcpToken, exitnode.Caller)
	}
	if err := mcpserver.Serve(ctx, mcpSock, tools); err != nil {
		return nil, fmt.Errorf("MCP socket: %w (a shorter --state path helps if it is too long)", err)
	}
	hint := mcpHint(o.state, o.hostname)
	log.Printf("MCP on %s; agents connect with `reqcove mcp` (Claude Code: %s; Codex: %s%s)", mcpSock, hint, strings.Replace(hint, "claude mcp add", "codex mcp add", 1), containerEngineNote())
	if n := staleSkillNote(); n != "" {
		log.Print(n)
	}
	return mcpHandler, nil
}

// uiPage is --ui's page of the flows.
func uiPage(o *runOpts, cap *capture.Capture, node *nodeState, uiToken string) *webui.UI {
	page := webui.New(cap.Store, uiToken, func(id string, all bool) []string {
		if all { // one of the user's own devices: the steps as `reqcove status` gives them
			return withoutMacStep(statusOut(node.get(), cap.Store.Stats(), o.allow, cap.CA, cap.Store.Devices()).NextSteps)
		}
		return pageSteps(node.get(), cap.Store.Stats(), o.allow, cap.CA, cap.Store.Devices(), id)
	})
	if o.hostname != "reqcove" {
		page.Node = o.hostname
	}
	return page
}
