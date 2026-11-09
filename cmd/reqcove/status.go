package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
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
	return mcpserver.StatusOut{Node: n, Capture: stats, NextSteps: nextSteps(n, stats, allow, ca, devices)}
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

// nextSteps lists what the user must still do, most urgent first.
func nextSteps(node exitnode.Status, stats map[string]any, allow capture.HostRules, ca capture.CA, devices []capture.DeviceInfo) []string {
	var steps []string
	if node.Backend == "" {
		steps = append(steps, "the tailnet node is starting")
	}
	if s := exitnode.FirstStep(node); s != "" {
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
		steps = append(steps, "the --rules file does not load ("+e+"): the rules before it still apply until it is fixed (--rules-reload)")
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
		if d.Carried && d.TLSFailures == 0 && d.Flows == 0 && node.ExitApproved {
			// The PeerAPI port stays the same across restarts (derived from the IP), but a device
			// that tried DNS while reqcove was down can stay DNS-dead (tailscale/tailscale#20870).
			steps = append(steps, fmt.Sprintf("no traffic from %s yet: turn on its exit node (%s). If it is on and sites do not load, turn the exit node off and on again: its DNS can stay stuck after reqcove was down", d.Name, node.Node))
		}
		if d.Carried && d.TLSFailures > 0 && d.Flows == 0 {
			steps = append(steps, fmt.Sprintf("%s refuses every certificate so far: install and trust the CA %q on it (open http://mitm.it, typing http://), unless the app pins its certificates", d.Name, ca.Name))
		}
	}
	return steps
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

	conn, err := net.Dial("unix", filepath.Join(*state, "mcp.sock"))
	if err != nil {
		return offlineStatus(*state, *uvx)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "reqcove-status", Version: "dev"}, nil)
	session, err := client.Connect(ctx, &mcp.IOTransport{Reader: conn, Writer: conn}, nil)
	if err != nil {
		return err
	}
	defer session.Close()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "status"})
	if err != nil {
		return fmt.Errorf("the running reqcove did not answer status (%v); an older build? restart `reqcove run` with this one", err)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if *asJSON {
		fmt.Println(string(b))
		return nil
	}
	var out struct {
		Node      exitnode.Status `json:"node"`
		NextSteps []string        `json:"next_steps"`
		Capture   map[string]any  `json:"capture"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return err
	}
	n := out.Node
	fmt.Printf("reqcove is running (%s)\n", *state)
	fmt.Printf("  node:        %s %s %s\n", orDash(n.Node), strings.Join(n.IPs, " "), n.Backend)
	fmt.Printf("  exit node:   approved=%v", n.ExitApproved)
	if n.LockEnabled {
		fmt.Printf("  tailnet lock: signed=%v", n.LockSigned)
	}
	fmt.Println()
	var names []string
	for _, name := range n.Devices {
		names = append(names, name)
	}
	fmt.Printf("  devices:     %s\n", orDash(strings.Join(names, ", ")))
	c := out.Capture
	fmt.Printf("  mitmproxy:   %v %v, %v flows, %v TLS failures\n", c["mitmproxy"], c["state"], c["flows"], c["tls_failures"])
	printCA(filepath.Join(*state, "mitmproxy"))
	if len(out.NextSteps) == 0 {
		fmt.Println("ready: turn on the exit node on the device (or set its Wi-Fi proxy) and use it")
		return nil
	}
	fmt.Println("next:")
	for _, s := range out.NextSteps {
		fmt.Println("  - " + strings.ReplaceAll(s, "\n", "\n    ")) // a command on a line of its own
	}
	return nil
}

func offlineStatus(state, uvx string) error {
	fmt.Printf("reqcove is not running (%s)\n", state)
	if _, err := exec.LookPath(uvx); err != nil {
		fmt.Println("  uv:    not found. Install it first: https://docs.astral.sh/uv/ (reqcove fetches mitmproxy and Python with it)")
	} else {
		fmt.Println("  uv:    found")
	}
	if _, err := os.Stat(filepath.Join(state, "tsnet", "tailscaled.state")); err != nil {
		fmt.Println("  node:  never started here; `reqcove run` will ask you to log in")
	} else {
		fmt.Println("  node:  has logged in before (state kept)")
	}
	printCA(filepath.Join(state, "mitmproxy"))
	fmt.Println("start it with: reqcove run --device NAME --allow-hosts api.example.com")
	return nil
}

// printCA says which CA the devices must trust, and how to add and remove it on an iPhone.
func printCA(confdir string) {
	ca, err := capture.ReadCA(confdir)
	if err != nil {
		fmt.Println("  CA:          none yet; the first `reqcove run` makes it")
		return
	}
	fmt.Printf("  CA:          %q, SHA-256 %s, until %s\n", ca.Name, ca.SHA256, ca.NotAfter.Format("2006-01-02"))
	fmt.Println("    add on an iPhone:    with the exit node on, open http://mitm.it in Safari (type http:// yourself), get the iOS profile,")
	fmt.Println("                         install it (Settings, Profile Downloaded), then trust it (General, About, Certificate Trust Settings)")
	fmt.Printf("    remove from iPhone:  Settings, General, VPN & Device Management, %q, Remove Profile\n", ca.Name)
	if macTrusts(filepath.Join(confdir, "mitmproxy-ca-cert.pem")) {
		fmt.Printf("    this Mac trusts it (--local-proxy); to stop: %s\n", macUntrustCommand(ca.SHA256))
	}
}

// cleanup lists how to undo reqcove, and with --delete-state removes the state directory.
func cleanup(args []string) error {
	fs := flag.NewFlagSet("cleanup", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	fs.String("hostname", "reqcove", "tailnet node name (with a --state named reqcove-NAME, that name)")
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
	del4 := "reqcove cleanup --delete-state"
	if !isDefaultState(*state) {
		del4 += " --state " + shellWord(*state)
	}
	fmt.Printf("  4. This computer: delete %s (`%s`).\n", *state, del4)
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
		return fmt.Errorf("%w: stop `reqcove run` first", err)
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
