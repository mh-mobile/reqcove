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
		return err
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
	if ca, err := capture.ReadCA(filepath.Join(state, "mitmproxy")); err != nil {
		fmt.Println("  CA:    none yet; the first `reqcove run` makes it")
	} else {
		fmt.Printf("  CA:    %q, SHA-256 %s, until %s\n", ca.Name, ca.SHA256, ca.NotAfter.Format("2006-01-02"))
	}
	fmt.Println("start it with: reqcove run --device NAME --allow-hosts api.example.com")
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
