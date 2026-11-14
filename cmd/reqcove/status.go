package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/net/publicsuffix"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// nodeState keeps the node's latest status for the status tool.
type nodeState struct {
	mu sync.Mutex
	s  exitnode.Status
}

func (n *nodeState) set(s exitnode.Status) { n.mu.Lock(); n.s = s; n.mu.Unlock() }
func (n *nodeState) get() exitnode.Status  { n.mu.Lock(); defer n.mu.Unlock(); return n.s }

// statusOut is what the status tool returns. The login URL is left out: it
// would reach the agent and its model provider, and whoever opens it first
// puts this node in their own tailnet. The steps point at run's terminal instead.
func statusOut(n exitnode.Status, stats map[string]any, allow capture.HostRules, ca capture.CA, devices []capture.DeviceInfo) mcpserver.StatusOut {
	n.AuthURL = ""
	service := ""
	// launchd's label under brew services: sh.brew.NAME (Homebrew 2026, tried),
	// homebrew.mxcl.NAME before, or reqcove service install's; not a terminal
	// another brew service started. Under systemd, the unit says (service.go).
	if v := os.Getenv("XPC_SERVICE_NAME"); slices.Contains(brewLabels, v) || v == serviceLabel {
		service = v
	} else if os.Getenv("REQCOVE_SERVICE") == serviceUnit {
		service = serviceUnit
	}
	hosts := allow.Hosts
	if hosts == nil {
		hosts = []string{} // [], not null: nothing is recorded
	}
	out := mcpserver.StatusOut{Mode: cmp.Or(n.Mode, "tailnet"), Node: n, Capture: stats, NextSteps: nextSteps(n, stats, allow, ca, devices), AllowHosts: hosts, PassHosts: allow.PassHosts, Service: service}
	if n.LAN != nil {
		out.LAN = n.LAN
	}
	return out
}

// pageSteps are the next steps the --ui page shows the device id: built from it
// alone, so no other device's name or problem gets into them.
func pageSteps(n exitnode.Status, stats map[string]any, allow capture.HostRules, ca capture.CA, devices []capture.DeviceInfo, id string) []string {
	n.Problems = nil
	var mine []capture.DeviceInfo
	for _, d := range devices {
		if d.ID == id {
			mine = append(mine, d)
		}
	}
	return statusOut(n, stats, allow, ca, mine).NextSteps
}

// localCA, set by run with --local-proxy on macOS, is the CA's file: while
// this Mac does not trust it, nextSteps says how. The answer is kept a few
// seconds: the page asks every second, too often to run security each time.
var localCA string

var macTrust struct {
	sync.Mutex
	at      time.Time
	trusted bool
}

// macTrustTTL is how long a check of this Mac's trust is kept (tests set 0).
var macTrustTTL = 10 * time.Second

// withoutMacStep drops the step about this Mac trusting the CA: the page is
// read on a phone, where nothing can be done about it (the terminal and
// `reqcove status` keep it).
func withoutMacStep(steps []string) []string {
	if ls := localStep(); ls != "" {
		steps = slices.DeleteFunc(steps, func(s string) bool { return s == ls })
	}
	return steps
}

func localStep() string {
	if localCA == "" {
		return ""
	}
	macTrust.Lock()
	defer macTrust.Unlock()
	if time.Since(macTrust.at) >= macTrustTTL {
		macTrust.trusted, macTrust.at = macTrusts(localCA), time.Now()
	}
	if macTrust.trusted {
		return ""
	}
	return "this Mac's browsers warn on the allowed hosts. To record them too, trust Reqcove's CA once (TLS only; macOS asks for your password):\n" + macTrustCommand(localCA)
}

// stepLinksCmd is the `reqcove links` the steps name: run sets it to its own
// node's (with --state).
var stepLinksCmd = "reqcove links"

// nextSteps lists what the user must still do, most urgent first.
func nextSteps(node exitnode.Status, stats map[string]any, allow capture.HostRules, ca capture.CA, devices []capture.DeviceInfo) []string {
	var steps []string
	if node.Backend == "" && node.Mode != "lan" {
		steps = append(steps, "the tailnet node is starting")
	}
	steps = append(steps, lanSteps(node, devices)...)
	if s := exitnode.FirstStepWith(node, stepLinksCmd); s != "" {
		steps = append(steps, s)
	}
	if node.Backend == "Running" {
		for _, p := range node.Problems {
			steps = append(steps, "device "+p+" (see `tailscale status` for names)")
		}
	}
	if st, _ := stats["state"].(string); st != "ready" {
		steps = append(steps, fmt.Sprintf("mitmproxy is %s: %v (see mitmproxy.log in the state directory)", st, stats["state_detail"]))
	}
	if e, _ := stats["rules_error"].(string); e != "" {
		steps = append(steps, "the --rules file does not load ("+e+"): the rules before it still apply until it is fixed (--rules-reload), or none, if mitmproxy restarted meanwhile")
	}
	if !allow.All && len(allow.Patterns) == 0 {
		steps = append(steps, "nothing is recorded: restart with --allow-hosts api.example.com (your app's hosts)")
	}
	if slices.ContainsFunc(devices, func(d capture.DeviceInfo) bool { return d.ID == exitnode.Local.ID }) {
		if s := localStep(); s != "" {
			steps = append(steps, s)
		}
	}
	for _, d := range devices {
		if d.ID == exitnode.Local.ID {
			if d.TLSFailures > 0 && d.Flows == 0 {
				steps = append(steps, fmt.Sprintf("the local proxy's apps refuse every certificate so far: trust the CA %q (iOS Simulator: xcrun simctl keychain booted add-root-cert; this Mac: security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db; with mitmproxy/mitmproxy-ca-cert.pem in the state directory), unless the app pins its certificates", ca.Name))
			}
			continue // not a phone: no exit node to turn on
		}
		if d.Carried && d.TLSFailures == 0 && d.Flows == 0 && d.Passthroughs == 0 && node.ExitApproved {
			// The PeerAPI port stays the same across restarts (derived from the IP), but a device
			// that tried DNS while reqcove was down can stay DNS-dead (tailscale/tailscale#20870).
			steps = append(steps, fmt.Sprintf("no traffic from %s yet: turn on its exit node (%s). If it is on and sites do not load, turn the exit node off and on again: its DNS can stay stuck after reqcove was down", d.Name, node.Node))
		}
		if d.Carried && d.TLSFailures > 0 && d.Flows == 0 {
			if android(node, d.ID) {
				steps = append(steps, fmt.Sprintf("%s refuses every certificate so far. It runs Android, whose apps trust only the system's CAs, not one you install: open a site in Chrome to check the CA %q (if Chrome warns, install it from http://mitm.it, typing http://, as a CA certificate in Settings). For your own app, a debug build that trusts user CAs (network_security_config)", d.Name, ca.Name))
			} else {
				steps = append(steps, fmt.Sprintf("%s refuses every certificate so far: install and trust the CA %q on it (open http://mitm.it, typing http://), unless the app pins its certificates", d.Name, ca.Name))
			}
		}
	}
	// Hosts a device refuses while it accepts the CA elsewhere, for these
	// devices only (the --ui page of another user's device lists its own).
	refused, _ := stats["refused_hosts"].([]capture.RefusedHost)
	for _, d := range devices {
		var mine []capture.RefusedHost
		for _, r := range refused {
			if r.Device == d.ID {
				mine = append(mine, r)
			}
		}
		if len(mine) == 0 {
			continue
		}
		hosts, counts := passSuggestion(mine, allow.PassHosts)
		// The hosts passed already stay (the command replaces the flag), but
		// for those a *.domain now covers.
		var all []string
		for _, p := range allow.PassHosts {
			if !slices.ContainsFunc(hosts, func(h string) bool { return h != p && strings.HasPrefix(h, "*.") && strings.HasSuffix(p, h[1:]) }) {
				all = append(all, p)
			}
		}
		all = append(all, hosts...)
		if android(node, d.ID) {
			steps = append(steps, fmt.Sprintf("%s refused Reqcove's certificate again and again for %s. It runs Android: its apps trust only the system's CAs, so all but Chrome and apps built to trust user CAs (network_security_config) refuse it. Keep --allow-hosts to the hosts you test (the others pass undecrypted, and their apps work), or start run again with --pass-hosts %s (carried undecrypted: only their connections are recorded, no URL, headers or bodies)", cmp.Or(d.Name, d.ID), strings.Join(counts, ", "), shellWord(strings.Join(all, ","))))
			continue
		}
		steps = append(steps, fmt.Sprintf("%s refused Reqcove's certificate again and again for %s, while it accepts it for other hosts: certificate pinning, or an app with its own list of CAs. To let those apps work, start run again with --pass-hosts %s (carried undecrypted: only their connections are recorded, no URL, headers or bodies)", cmp.Or(d.Name, d.ID), strings.Join(counts, ", "), shellWord(strings.Join(all, ","))))
	}
	return steps
}

// android: Tailscale says the device runs Android, whose apps trust only the
// system's CAs (Android 7 and later, unless the app opts in).
func android(node exitnode.Status, id string) bool {
	return strings.EqualFold(node.DeviceOS[id], "android")
}

// status prints where a running reqcove stands, or, when none runs, what
// the files say.
func status(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	asJSON := fs.Bool("json", false, "print the status tool's JSON")
	uvx := fs.String("uvx", "uvx", "path to uvx")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if n := staleSkillNote(); n != "" {
		fmt.Fprintln(os.Stderr, "note: "+n) // stderr: --json stays clean
	}

	session, err := dialRun(ctx, *state, "reqcove-status")
	switch {
	case errors.Is(err, errNotRunning):
		return offlineStatus(*state, *uvx)
	case errors.Is(err, errStarting):
		fmt.Println(err)
		return nil
	case err != nil:
		return err
	}
	defer session.Close()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "status"})
	if err != nil {
		return fmt.Errorf("the running reqcove did not answer status (%v); an older build? restart `%s` with this one", err, withState("reqcove run", *state))
	}
	b, _ := json.Marshal(res.StructuredContent)
	if *asJSON {
		fmt.Println(string(b))
		return nil
	}
	var out struct {
		Mode      string                `json:"mode"`
		LAN       *exitnode.LANStatus   `json:"lan"`
		Node      exitnode.Status       `json:"node"`
		NextSteps []string              `json:"next_steps"`
		Capture   map[string]any        `json:"capture"`
		Active    []mcpserver.PresetOut `json:"active_presets"` // every kind (kind says which)
		ActiveErr string                `json:"active_presets_error"`
		// v0.6 and v0.7's names (a run not yet restarted): read when the new
		// ones are absent, never written (removed in v1.0).
		OldActive    []mcpserver.PresetOut `json:"active_mock_presets"`
		OldActiveErr string                `json:"active_mock_presets_error"`
		Service      string                `json:"service"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return err
	}
	if out.Active == nil && out.ActiveErr == "" {
		out.Active, out.ActiveErr = out.OldActive, out.OldActiveErr
	}
	n := out.Node
	fmt.Printf("reqcove is running (%s)\n", *state)
	if out.Service != "" {
		fmt.Printf("  service:     %s (%s)\n", out.Service, serviceHint(out.Service, *state))
	}
	if out.Mode == "lan" {
		printLANStatus(os.Stdout, out.LAN)
	} else {
		fmt.Printf("  node:        %s %s %s\n", orDash(n.Node), strings.Join(n.IPs, " "), n.Backend)
		fmt.Printf("  exit node:   approved=%v", n.ExitApproved)
		if n.LockEnabled {
			fmt.Printf("  tailnet lock: signed=%v", n.LockSigned)
		}
		fmt.Println()
	}
	var names []string
	for _, name := range n.Devices {
		names = append(names, name)
	}
	fmt.Printf("  devices:     %s\n", orDash(strings.Join(names, ", ")))
	c := out.Capture
	fmt.Printf("  mitmproxy:   %v %v, %v flows, %v TLS failures\n", c["mitmproxy"], c["state"], c["flows"], c["tls_failures"])
	presets, ok := c["presets"]
	if !ok {
		presets = c["mock_presets"] // v0.6 and v0.7's name
	}
	if names, _ := presets.([]any); len(names) > 0 {
		var on []string
		for _, p := range out.Active {
			s := p.Name
			if t := cmp.Or(p.Target, p.Address); t != "" {
				s += " -> " + t
			}
			s += " until " + p.ExpiresAt
			if p.Remaining != nil {
				s += fmt.Sprintf(", %d requests left", *p.Remaining)
			}
			on = append(on, s)
		}
		shown := orDash(strings.Join(on, "; "))
		if out.ActiveErr != "" {
			shown = "unknown (" + out.ActiveErr + ")"
		}
		fmt.Printf("  presets:     %d (%s); on: %s\n", len(names), joinAny(names), shown)
	}
	printCA(os.Stdout, *state, out.Mode == "lan")
	if len(out.NextSteps) == 0 {
		if out.Mode == "lan" {
			fmt.Println("ready: set the device's Wi-Fi proxy to the LAN proxy above and use it")
		} else {
			fmt.Println("ready: turn on the exit node on the device (or set its Wi-Fi proxy) and use it")
		}
		return nil
	}
	fmt.Println("next:")
	for _, s := range out.NextSteps {
		fmt.Println("  - " + strings.ReplaceAll(s, "\n", "\n    ")) // a command on a line of its own
	}
	return nil
}

func joinAny(v []any) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprint(x)
	}
	return strings.Join(s, ", ")
}

func offlineStatus(state, uvx string) error {
	fmt.Printf("reqcove is not running (%s)\n", state)
	if _, err := exec.LookPath(uvx); err != nil {
		fmt.Println("  uv:    not found. Install it first: https://docs.astral.sh/uv/ (reqcove fetches mitmproxy and Python with it)")
	} else {
		fmt.Println("  uv:    found")
	}
	switch b, err := os.ReadFile(filepath.Join(state, "tsnet", "tailscaled.state")); {
	case err != nil:
		fmt.Printf("  node:  never started here; `%s` will ask you to log in\n", withState("reqcove run", state))
	case !loggedIn(b):
		fmt.Printf("  node:  not logged in yet; `%s` will ask you to log in\n", withState("reqcove run", state))
	default:
		fmt.Println("  node:  has logged in before (state kept)")
	}
	printCA(os.Stdout, state, false)
	fmt.Println("start it with: " + withState("reqcove run --device NAME --allow-hosts api.example.com", state))
	return nil
}

// loggedIn reports whether tsnet's state file (a JSON object of base64 values)
// holds a login profile: tsnet writes its machine key at the first start, the
// profiles only once a login gave the node an ID; a logout empties them.
func loggedIn(tailscaledState []byte) bool {
	var keys map[string][]byte
	var profiles map[string]json.RawMessage
	return json.Unmarshal(tailscaledState, &keys) == nil && json.Unmarshal(keys["_profiles"], &profiles) == nil && len(profiles) > 0
}

// printCA says which CA the devices must trust, and how to add and remove it on an iPhone.
// In LAN mode (lan) the iPhone gets it through the Wi-Fi proxy, over plain HTTP.
func printCA(w io.Writer, state string, lan bool) {
	confdir := filepath.Join(state, "mitmproxy")
	ca, err := capture.ReadCA(confdir)
	if err != nil {
		if isDefaultState(state) {
			fmt.Fprintln(w, "  CA:          none yet; the first `reqcove run` makes it")
		} else {
			fmt.Fprintf(w, "  CA:          none yet; the first `%s` copies %s's, or makes one if it has none\n", withState("reqcove run", state), defaultState())
		}
		return
	}
	fmt.Fprintf(w, "  CA:          %q, SHA-256 %s, until %s\n", ca.Name, ca.SHA256, ca.NotAfter.Format("2006-01-02"))
	with := "with the exit node on"
	if lan {
		with = "with the Wi-Fi proxy set to the LAN proxy"
	}
	fmt.Fprintf(w, "    add on an iPhone:    %s, open http://mitm.it in Safari (type http:// yourself), get the iOS profile,\n", with)
	fmt.Fprintln(w, "                         install it (Settings, Profile Downloaded), then trust it (General, About, Certificate Trust Settings)")
	if lan {
		fmt.Fprintf(w, "                         %s\n", lanCAAdvice(caPEM(state), ca.SHA256))
	}
	fmt.Fprintf(w, "    remove from iPhone:  Settings, General, VPN & Device Management, %q, Remove Profile\n", ca.Name)
	if macTrusts(filepath.Join(confdir, "mitmproxy-ca-cert.pem")) {
		fmt.Fprintf(w, "    this Mac trusts it (--local-proxy); to stop: %s\n", macUntrustCommand(ca.SHA256))
	}
}

// cleanup lists how to undo reqcove, and with --delete-state removes the state directory.
func cleanup(args []string) error {
	fs := flag.NewFlagSet("cleanup", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	fs.String("hostname", "reqcove", "tailnet node name (by default the one run kept in the state)")
	del := fs.Bool("delete-state", false, "delete the state directory (node key, CA and its private key, logs)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	hostname := nodeName(fs, *state)
	ca, caErr := capture.ReadCA(filepath.Join(*state, "mitmproxy"))
	fmt.Println("To undo reqcove:")
	fmt.Printf("  1. On each iPhone: Tailscale app, Exit Node, None (or set the Wi-Fi proxy back to Off).\n")
	if caErr == nil {
		fmt.Printf("  2. On each iPhone: Settings, General, VPN & Device Management, %q, Remove Profile.\n", ca.Name)
		if def, err := capture.ReadCA(filepath.Join(defaultState(), "mitmproxy")); err == nil && def.SHA256 == ca.SHA256 && !isDefaultState(*state) {
			fmt.Printf("     It is the CA of %s too (copied): without the profile, that node no longer decrypts either. Keep it to go on using that one.\n", defaultState())
		}
	} else {
		fmt.Println("  2. On each iPhone: remove the reqcove CA profile, if you installed one.")
	}
	fmt.Printf("  3. Tailscale admin console, Machines: remove %q.\n", hostname)
	fmt.Printf("  4. This computer: delete %s (`%s`).\n", *state, withState("reqcove cleanup --delete-state", *state))
	if caErr == nil && isDefaultState(*state) {
		for _, d := range caCopiesOf(ca.SHA256) {
			fmt.Printf("     %s holds a copy of this CA and its key (another node's): `%s`.\n", d, withState("reqcove cleanup --delete-state", d))
		}
	}
	if _, err := os.Stat(savedProxyFile(*state)); err == nil { // --local-proxy left them pointed at reqcove
		if unlock, err := lockState(*state); err != nil {
			fmt.Println("  The system's web proxies point at the reqcove that is running; they go back when it stops.")
		} else {
			if err := restoreSystemProxy(*state); err != nil {
				fmt.Printf("  The system's web proxies still point at reqcove and could not be put back (%v): System Settings, Network, Details, Proxies.\n", err)
			} else {
				fmt.Println("  The system's web proxies, left pointed at reqcove by a run that died, are back as they were.")
			}
			unlock()
		}
	}
	if runtime.GOOS == "darwin" {
		fmt.Println("  5. iOS Simulator, if you used --local-proxy: xcrun simctl keychain booted reset (removes every certificate added to it).")
		if caErr == nil && macTrusts(filepath.Join(*state, "mitmproxy", "mitmproxy-ca-cert.pem")) {
			fmt.Printf("  6. This Mac trusts the CA: %s\n", macUntrustCommand(ca.SHA256))
		}
	}
	if !*del {
		return nil
	}
	if _, err := os.Stat(savedProxyFile(*state)); err == nil {
		return fmt.Errorf("not deleting %s: it holds the system's web proxy settings to put back (%s)", *state, savedProxyFile(*state))
	}
	// The directory itself, not a symlink to it: RemoveAll would take only the link and leave the CA's key.
	dir, err := filepath.EvalSymlinks(*state)
	if os.IsNotExist(err) {
		fmt.Printf("%s is already gone\n", *state)
		return nil
	} else if err != nil {
		return err
	}
	if !isState(dir) {
		return fmt.Errorf("%s does not look like reqcove's state (no %s marker, nor lock and tsnet/tailscaled.state); not deleting it", dir, stateMarker)
	}
	unlock, err := lockState(dir) // refuses while `reqcove run` holds it
	if err != nil {
		return fmt.Errorf("%w: stop `%s` first", err, withState("reqcove run", *state))
	}
	defer unlock() // held until it is gone, so no run starts in between
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	os.Remove(filepath.Clean(*state)) // the symlink, if *state was one
	fmt.Printf("deleted %s\n", dir)
	return nil
}

// isState reports whether dir is a state directory `reqcove run` used: its
// marker, or (from before the marker) its lock with the node's state file.
func isState(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, stateMarker)); err == nil {
		return true
	}
	// Made before the marker existed: reqcove's lock and the node's own state file.
	_, lockErr := os.Stat(filepath.Join(dir, "lock"))
	_, nodeErr := os.Stat(filepath.Join(dir, "tsnet", "tailscaled.state"))
	return lockErr == nil && nodeErr == nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// passSuggestion groups refused hosts by their registered domain (the public
// suffix list: paypay.ne.jp, not ne.jp): two or more under one, or one under a
// domain a pass host has already, become *.domain. Addresses stay as they are.
func passSuggestion(refused []capture.RefusedHost, passed []string) (hosts, counts []string) {
	domainOf := func(h string) string {
		if _, err := netip.ParseAddr(h); err == nil {
			return h
		}
		if d, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimPrefix(h, "*.")); err == nil {
			return d
		}
		return h
	}
	passedDomains := map[string]bool{}
	for _, p := range passed {
		passedDomains[domainOf(p)] = true
	}
	type group struct {
		hosts    []string
		counts   []int
		n        int
		siblings bool // another host of the domain is recorded: no *.domain
	}
	groups := map[string]*group{}
	var order []string
	for _, r := range refused {
		key := domainOf(r.Host)
		if groups[key] == nil {
			groups[key] = &group{}
			order = append(order, key)
		}
		groups[key].hosts = append(groups[key].hosts, r.Host)
		groups[key].counts = append(groups[key].counts, r.Refusals)
		groups[key].n += r.Refusals
		groups[key].siblings = groups[key].siblings || r.SiblingsRecorded
	}
	for _, key := range order {
		g := groups[key]
		if g.siblings || len(g.hosts) == 1 && (!passedDomains[key] || key == g.hosts[0]) {
			for i, h := range g.hosts {
				hosts = append(hosts, h)
				counts = append(counts, fmt.Sprintf("%s (%d)", h, g.counts[i]))
			}
			continue
		}
		hosts = append(hosts, "*."+key)
		counts = append(counts, fmt.Sprintf("%d hosts of %s (%d)", len(g.hosts), key, g.n))
	}
	return hosts, counts
}

// serviceHint says how to stop the service that started run, and where its log is.
func serviceHint(label, state string) string {
	switch label {
	case serviceLabel:
		return "reqcove service uninstall stops and removes it; launchctl bootout gui/$(id -u)/" + serviceLabel + " stops it until the next login; the log: " + filepath.Join(state, serviceLog)
	case serviceUnit:
		return "reqcove service uninstall stops and removes it; systemctl --user stop reqcove stops it until it starts again at login; the log: journalctl --user -u reqcove"
	}
	return "brew services stop reqcove; the log: $(brew --prefix)/var/log/reqcove.log"
}
