package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

func TestNextSteps(t *testing.T) {
	ready := map[string]any{"state": "ready"}
	allow, _ := capture.ParseAllowHosts([]string{"api.example.com"})
	ok := exitnode.Status{Backend: "Running", Node: "reqcove.ts.net", ExitApproved: true, Devices: map[string]string{"n1": "phone"}}
	ca := capture.CA{Name: "Reqcove CA (mac, 2026-11-07)"}
	for _, c := range []struct {
		name    string
		node    exitnode.Status
		stats   map[string]any
		allow   capture.HostRules
		devices []capture.DeviceInfo
		want    []string // substrings, in order; none: no steps
	}{
		{"all set", ok, ready, allow, nil, nil},
		{"login", exitnode.Status{Backend: "NeedsLogin", AuthURL: "https://login.example/a/1"}, ready, allow, nil, []string{"log in: open https://login.example/a/1"}},
		{"lock", exitnode.Status{Backend: "Running", LockEnabled: true, NodeKey: "nodekey:ab"}, ready, allow, nil, []string{"tailscale lock sign nodekey:ab"}},
		{"approve", exitnode.Status{Backend: "Running", Node: "reqcove.ts.net"}, ready, allow, nil, []string{"approve the exit node", "reqcove.ts.net"}},
		{"device missing", exitnode.Status{Backend: "Running", ExitApproved: true, Problems: []string{`"phone": no such device`}}, ready, allow, nil, []string{`device "phone": no such device`}},
		{"mitmproxy down", ok, map[string]any{"state": "restarting", "state_detail": "exit 1"}, allow, nil, []string{"mitmproxy is restarting: exit 1"}},
		{"no allow-hosts", ok, ready, capture.HostRules{}, nil, []string{"--allow-hosts"}},
		{"CA not trusted", ok, ready, allow, []capture.DeviceInfo{{Name: "phone", Carried: true, TLSFailures: 3}}, []string{"phone refuses", "Reqcove CA (mac, 2026-11-07)", "http://mitm.it"}},
		{"CA fine", ok, ready, allow, []capture.DeviceInfo{{Name: "phone", Carried: true, TLSFailures: 3, Flows: 10}}, nil},
		{"silent device", ok, ready, allow, []capture.DeviceInfo{{Name: "phone", Carried: true}}, []string{"no traffic from phone yet", "reqcove.ts.net", "off and on again"}},
		{"busy device", ok, ready, allow, []capture.DeviceInfo{{Name: "phone", Carried: true, Flows: 1}}, nil},
	} {
		got := strings.Join(nextSteps(c.node, c.stats, c.allow, ca, c.devices), "\n")
		if len(c.want) == 0 && got != "" {
			t.Errorf("%s: want no steps, got %q", c.name, got)
		}
		rest := got
		for _, w := range c.want {
			i := strings.Index(rest, w)
			if i < 0 {
				t.Errorf("%s: %q not in %q", c.name, w, got)
				break
			}
			rest = rest[i+len(w):]
		}
	}
}

// TestStatusCommand: `reqcove status` asks a running reqcove over its socket
// and prints the next steps.
func TestStatusCommand(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "rcvs-") // short socket path
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := capture.NewStore(10, 1<<20)
	go mcpserver.Serve(ctx, filepath.Join(dir, "mcp.sock"), mcpserver.New(st, func() mcpserver.StatusOut {
		return mcpserver.StatusOut{Node: exitnode.Status{Backend: "Running", Node: "reqcove.ts.net", IPs: []string{"100.1.2.3"}},
			Capture: st.Stats(), NextSteps: []string{"approve the exit node: admin console"}}
	}))
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(filepath.Join(dir, "mcp.sock")); err == nil || time.Now().After(deadline) {
			break
		}
	}
	out := captureStdout(t, func() error { return status(ctx, []string{"--state", dir}) })
	for _, w := range []string{"reqcove is running", "reqcove.ts.net 100.1.2.3 Running", "next:", "- approve the exit node"} {
		if !strings.Contains(out, w) {
			t.Errorf("%q not in:\n%s", w, out)
		}
	}
	cancel()
	time.Sleep(100 * time.Millisecond)
	if out := captureStdout(t, func() error { return status(context.Background(), []string{"--state", dir}) }); !strings.Contains(out, "reqcove is not running") {
		t.Errorf("after stop:\n%s", out)
	}
}

func captureStdout(t *testing.T, f func() error) string {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	err := f()
	w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCleanup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	os.MkdirAll(filepath.Join(dir, "tsnet"), 0o700)
	out := captureStdout(t, func() error { return cleanup([]string{"--state", dir}) })
	if !strings.Contains(out, "Exit Node, None") || !strings.Contains(out, `remove "reqcove"`) {
		t.Errorf("steps:\n%s", out)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("deleted without --delete-state")
	}
	// While a run holds the lock, the state stays.
	unlock, err := lockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup([]string{"--state", dir, "--delete-state"}); err == nil {
		t.Error("deleted the state of a running reqcove")
	}
	unlock()
	captureStdout(t, func() error { return cleanup([]string{"--state", dir, "--delete-state"}) })
	if _, err := os.Stat(dir); err == nil {
		t.Error("state still there after --delete-state")
	}
}
