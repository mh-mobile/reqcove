package main

import (
	"context"
	"encoding/json"
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
	if err := mcpserver.Serve(ctx, filepath.Join(dir, "mcp.sock"), mcpserver.New(st, func() mcpserver.StatusOut {
		return mcpserver.StatusOut{Node: exitnode.Status{Backend: "Running", Node: "reqcove.ts.net", IPs: []string{"100.1.2.3"}},
			Capture: st.Stats(), NextSteps: []string{"approve the exit node: admin console"}}
	})); err != nil {
		t.Fatal(err)
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

	// A --state that is not reqcove's (a typo, a project) is never deleted.
	foreign := filepath.Join(t.TempDir(), "project")
	os.MkdirAll(filepath.Join(foreign, "src"), 0o755)
	os.WriteFile(filepath.Join(foreign, "src", "main.go"), []byte("package main"), 0o644)
	if err := cleanup([]string{"--state", foreign, "--delete-state"}); err == nil {
		t.Error("--delete-state on a directory that is not reqcove's: no error")
	}
	if _, err := os.Stat(filepath.Join(foreign, "src", "main.go")); err != nil {
		t.Errorf("deleted a directory that is not reqcove's: %v", err)
	}

	// A symlinked state: the directory and its CA key go, not just the link.
	real := filepath.Join(t.TempDir(), "real")
	os.MkdirAll(filepath.Join(real, "mitmproxy"), 0o700)
	os.WriteFile(filepath.Join(real, "lock"), nil, 0o600)
	os.WriteFile(filepath.Join(real, "mitmproxy", "mitmproxy-ca.pem"), []byte("KEY"), 0o600)
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(real, link)
	captureStdout(t, func() error { return cleanup([]string{"--state", link, "--delete-state"}) })
	if _, err := os.Stat(filepath.Join(real, "mitmproxy", "mitmproxy-ca.pem")); err == nil {
		t.Error("the CA key is still there after --delete-state through a symlink")
	}
	if _, err := os.Lstat(link); err == nil {
		t.Error("the symlink is still there")
	}
}

// `run` never takes over a directory holding someone else's files (it would
// chmod it, and cleanup would later delete it); an empty or earlier state is fine.
func TestOpenState(t *testing.T) {
	foreign := t.TempDir()
	os.WriteFile(filepath.Join(foreign, "notes.txt"), nil, 0o644)
	os.Chmod(foreign, 0o755)
	if unlock, err := openState(foreign); err == nil {
		unlock()
		t.Error("openState took a directory with other files")
	}
	if fi, _ := os.Stat(foreign); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode changed to %v", fi.Mode().Perm())
	}
	// A folder made by hand and opened in Finder holds only .DS_Store: still empty.
	finder := t.TempDir()
	os.WriteFile(filepath.Join(finder, ".DS_Store"), nil, 0o644)
	if unlock, err := openState(finder); err != nil {
		t.Errorf("openState refused a folder with only .DS_Store: %v", err)
	} else {
		unlock()
	}
	fresh := filepath.Join(t.TempDir(), "state")
	unlock, err := openState(fresh)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	os.MkdirAll(filepath.Join(fresh, "tsnet"), 0o700)
	if unlock, err := openState(fresh); err != nil {
		t.Errorf("openState on its own earlier state: %v", err)
	} else {
		unlock()
	}
	if fi, _ := os.Stat(fresh); fi.Mode().Perm() != 0o700 {
		t.Errorf("state mode %v, want 0700", fi.Mode().Perm())
	}
}

// Flags after a stray argument would be dropped silently, so a stray argument is an error.
func TestStrayArgument(t *testing.T) {
	// --state and --uvx first: should the check go missing, run stops at uvx, far from ~/.reqcove.
	err := run(context.Background(), []string{"--state", t.TempDir(), "--uvx", "/nonexistent/uvx", "--device", "Taro's", "iPhone", "--allow-hosts", "api.example.com"})
	if err == nil || !strings.Contains(err.Error(), `"iPhone"`) {
		t.Errorf("run with a stray argument: %v", err)
	}
	if err := cleanup([]string{"--state", t.TempDir(), "extra"}); err == nil {
		t.Error("cleanup with a stray argument: no error")
	}
}

// The login URL never reaches the status tool, and so never the agent.
func TestStatusOutHidesLoginURL(t *testing.T) {
	allow, _ := capture.ParseAllowHosts([]string{"api.example.com"})
	out := statusOut(exitnode.Status{Backend: "NeedsLogin", AuthURL: "https://login.tailscale.com/a/S3CRET"}, map[string]any{"state": "ready"}, allow, capture.CA{}, nil)
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "S3CRET") || strings.Contains(string(b), "login.tailscale.com") {
		t.Errorf("login URL in the status tool: %s", b)
	}
	if !strings.Contains(strings.Join(out.NextSteps, "\n"), "prints in its terminal") {
		t.Errorf("steps do not say where to log in: %v", out.NextSteps)
	}
}
