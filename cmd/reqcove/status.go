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
	"strings"
	"sync"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// nodeState keeps the node's latest status for the status tool.
type nodeState struct {
	mu sync.Mutex
	s  exitnode.Status
}

func (n *nodeState) set(s exitnode.Status) { n.mu.Lock(); n.s = s; n.mu.Unlock() }
func (n *nodeState) get() exitnode.Status  { n.mu.Lock(); defer n.mu.Unlock(); return n.s }

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
	if !allow.All && len(allow.Patterns) == 0 {
		steps = append(steps, "nothing is recorded: restart with --allow-hosts api.example.com (your app's hosts)")
	}
	for _, d := range devices {
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
	fs.Parse(args)

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
		fmt.Println("  - " + s)
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
}

// cleanup lists how to undo reqcove, and with --delete-state removes the state directory.
func cleanup(args []string) error {
	fs := flag.NewFlagSet("cleanup", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	hostname := fs.String("hostname", "reqcove", "tailnet node name")
	del := fs.Bool("delete-state", false, "delete the state directory (node key, CA and its private key, logs)")
	fs.Parse(args)
	ca, caErr := capture.ReadCA(filepath.Join(*state, "mitmproxy"))
	fmt.Println("To undo reqcove:")
	fmt.Printf("  1. On each iPhone: Tailscale app, Exit Node, None (or set the Wi-Fi proxy back to Off).\n")
	if caErr == nil {
		fmt.Printf("  2. On each iPhone: Settings, General, VPN & Device Management, %q, Remove Profile.\n", ca.Name)
	} else {
		fmt.Println("  2. On each iPhone: remove the reqcove CA profile, if you installed one.")
	}
	fmt.Printf("  3. Tailscale admin console, Machines: remove %q.\n", *hostname)
	fmt.Printf("  4. This computer: delete %s (`reqcove cleanup --delete-state`).\n", *state)
	if !*del {
		return nil
	}
	if _, err := os.Stat(*state); err != nil {
		fmt.Printf("%s is already gone\n", *state)
		return nil
	}
	unlock, err := lockState(*state) // refuses while `reqcove run` holds it
	if err != nil {
		return fmt.Errorf("%w: stop `reqcove run` first", err)
	}
	unlock()
	if err := os.RemoveAll(*state); err != nil {
		return err
	}
	fmt.Printf("deleted %s\n", *state)
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
