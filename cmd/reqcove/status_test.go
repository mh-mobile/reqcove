package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
	"tailscale.com/health/healthmsg"
)

// The page's steps are the viewing device's: names that overlap (iphone,
// iphone-1) keep its own, and another device's problem or step is not there.
func TestPageSteps(t *testing.T) {
	ok := exitnode.Status{Backend: "Running", Node: "reqcove.ts.net", ExitApproved: true, Problems: []string{`"ipad": no such device`}}
	allow, _ := capture.ParseAllowHosts([]string{"api.example.com"})
	devices := []capture.DeviceInfo{{ID: "a", Name: "iphone", Carried: true}, {ID: "b", Name: "iphone-1", Carried: true, TLSFailures: 2}}
	got := strings.Join(pageSteps(ok, map[string]any{"state": "ready"}, allow, capture.CA{}, devices, "a"), "\n")
	if !strings.Contains(got, "no traffic from iphone yet") || strings.Contains(got, "iphone-1") || strings.Contains(got, "ipad") {
		t.Errorf("a's steps: %q", got)
	}
	got = strings.Join(pageSteps(ok, map[string]any{"state": "ready"}, allow, capture.CA{}, devices, "b"), "\n")
	if !strings.Contains(got, "iphone-1 refuses") || strings.Contains(got, "no traffic") {
		t.Errorf("b's steps: %q", got)
	}
}

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
		{"login", exitnode.Status{Backend: "NeedsLogin", AuthURL: "https://login.example/a/1"}, ready, allow, nil, []string{"`reqcove links` prints it"}},
		{"lock", exitnode.Status{Backend: "Running", LockEnabled: true, NodeKey: "nodekey:ab", Health: []string{"tailnet lock: " + healthmsg.LockedOut}}, ready, allow, nil, []string{"tailscale lock sign nodekey:ab"}},
		// Just after start the key looks unsigned until the netmap is checked: no step yet.
		{"lock, not checked yet", exitnode.Status{Backend: "Running", LockEnabled: true, NodeKey: "nodekey:ab", ExitApproved: true, Devices: map[string]string{"n1": "phone"}}, ready, allow, nil, nil},
		{"approve", exitnode.Status{Backend: "Running", Node: "reqcove.ts.net"}, ready, allow, nil, []string{"approve the exit node", "reqcove.ts.net", "autoApprovers"}},
		{"device missing", exitnode.Status{Backend: "Running", ExitApproved: true, Problems: []string{`"phone": no such device`}}, ready, allow, nil, []string{`device "phone": no such device`}},
		{"mitmproxy down", ok, map[string]any{"state": "restarting", "state_detail": "exit 1"}, allow, nil, []string{"mitmproxy is restarting: exit 1"}},
		{"no allow-hosts", ok, ready, capture.HostRules{}, nil, []string{"--allow-hosts"}},
		{"rules reload failed", ok, map[string]any{"state": "ready", "rules_error": "map_remote[0]: bad"}, allow, nil, []string{"--rules file does not load (map_remote[0]: bad)", "rules before it still apply"}},
		{"CA not trusted", ok, ready, allow, []capture.DeviceInfo{{Name: "phone", Carried: true, TLSFailures: 3}}, []string{"phone refuses", "Reqcove CA (mac, 2026-11-07)", "http://mitm.it"}},
		{"CA fine", ok, ready, allow, []capture.DeviceInfo{{Name: "phone", Carried: true, TLSFailures: 3, Flows: 10}}, nil},
		{"silent device", ok, ready, allow, []capture.DeviceInfo{{Name: "phone", Carried: true}}, []string{"no traffic from phone yet", "reqcove.ts.net", "off and on again"}},
		{"busy device", ok, ready, allow, []capture.DeviceInfo{{Name: "phone", Carried: true, Flows: 1}}, nil},
		// The local proxy is not a phone: no exit node to turn on, and its CA step names the Simulator.
		{"local, silent", ok, ready, allow, []capture.DeviceInfo{{ID: "local", Name: "local", Carried: true}}, nil},
		{"local, CA", ok, ready, allow, []capture.DeviceInfo{{ID: "local", Name: "local", Carried: true, TLSFailures: 2}}, []string{"local proxy's apps refuse", "simctl keychain"}},
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
	read := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); read <- b }() // as it is written: a pipe holds only 64 KiB
	err := f()
	w.Close()
	os.Stdout = old
	b := <-read
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCleanup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if unlock, err := openState(dir); err != nil { // as run makes it
		t.Fatal(err)
	} else {
		unlock()
	}
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

	// A directory with a generic "lock" file (and later a tsnet/) is not taken for
	// reqcove's: neither used by run nor deleted by cleanup.
	generic := filepath.Join(t.TempDir(), "generic")
	os.MkdirAll(filepath.Join(generic, "tsnet"), 0o700)
	os.WriteFile(filepath.Join(generic, "lock"), nil, 0o644)
	os.WriteFile(filepath.Join(generic, "notes.txt"), []byte("mine"), 0o644)
	if unlock, err := openState(generic); err == nil {
		unlock()
		t.Error("run took a directory with a generic lock file")
	}
	if err := cleanup([]string{"--state", generic, "--delete-state"}); err == nil {
		t.Error("cleanup deleted a directory with a generic lock file")
	}
	// A state directory from before the marker: lock and the node's state file.
	legacy := filepath.Join(t.TempDir(), "legacy")
	os.MkdirAll(filepath.Join(legacy, "tsnet"), 0o700)
	os.WriteFile(filepath.Join(legacy, "lock"), nil, 0o600)
	os.WriteFile(filepath.Join(legacy, "tsnet", "tailscaled.state"), []byte("{}"), 0o600)
	if unlock, err := openState(legacy); err != nil {
		t.Errorf("run refused an older state directory: %v", err)
	} else {
		unlock()
	}
	if _, err := os.Stat(filepath.Join(legacy, stateMarker)); err != nil {
		t.Error("no marker written into the older state directory")
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
	os.WriteFile(filepath.Join(real, stateMarker), nil, 0o600)
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
	// ~/.reqcove before its first run, with a CA copied from another computer
	// (docs/guide.md, Use one CA on two computers) and the list of copies another node made: taken. Another
	// directory with a mitmproxy/ (a clone of mitmproxy, say), or ~/.reqcove's
	// mitmproxy/ without a key, is not.
	def := tempDefaultState(t)
	defer os.RemoveAll(def)
	os.MkdirAll(filepath.Join(def, "mitmproxy"), 0o700)
	if unlock, err := openState(def); err == nil {
		unlock()
		t.Error("openState took ~/.reqcove with a mitmproxy/ without a key")
	}
	os.WriteFile(filepath.Join(def, "mitmproxy", "mitmproxy-ca.pem"), []byte("key"), 0o600)
	os.WriteFile(filepath.Join(def, caCopies), []byte("/x/mitmproxy\n"), 0o600)
	if unlock, err := openState(def); err != nil {
		t.Errorf("openState refused ~/.reqcove with a copied CA: %v", err)
	} else {
		unlock()
	}
	clone := t.TempDir()
	os.MkdirAll(filepath.Join(clone, "mitmproxy", "mitmproxy"), 0o755)
	os.WriteFile(filepath.Join(clone, "mitmproxy", "mitmproxy-ca.pem"), []byte("key"), 0o600)
	if unlock, err := openState(clone); err == nil {
		unlock()
		t.Error("openState took another directory holding a mitmproxy/")
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
	if !strings.Contains(strings.Join(out.NextSteps, "\n"), "`reqcove links`") {
		t.Errorf("steps do not say where to log in: %v", out.NextSteps)
	}
}

// The QR code goes to a terminal only: not into a log file.
func TestPrintQR(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "log")
	printQR(f, "http://mitm.it", "scan")
	if fi, _ := f.Stat(); fi.Size() != 0 {
		t.Error("a QR code was written to a file")
	}
}

// The ready block puts the devices, the links and the numbered next steps in
// one place; the local proxy's step about this Mac is among them, but only
// with the local proxy on.
func TestReadyBlock(t *testing.T) {
	oldCA, oldSec, oldTTL := localCA, security, macTrustTTL
	defer func() { localCA, security, macTrustTTL = oldCA, oldSec, oldTTL }()
	localCA, macTrustTTL = "/s/ca.pem", 0
	trusted := false
	security = func(...string) error {
		if trusted {
			return nil
		}
		return errors.New("exit status 1")
	}
	ready := map[string]any{"state": "ready"}
	allow, _ := capture.ParseAllowHosts([]string{"api.example.com"})
	n := exitnode.Status{Backend: "Running", Node: "reqcove.ts.net", ExitApproved: true}
	devs := []capture.DeviceInfo{{ID: "local", Name: "local", Carried: true, Flows: 1}, {ID: "n1", Name: "iphone", Carried: true}}
	steps := nextSteps(n, ready, allow, capture.CA{}, devs)
	got := readyBlock(map[string]string{"n1": "iphone", "local": "local"}, "http://100.1.2.3/?k=K", "", "", "", "/s", steps, true, nil, nil)
	for _, w := range []string{"reqcove is ready", "devices:  iphone, local (this computer's apps", "--ui:     http://100.1.2.3/?k=K", "CA:       http://mitm.it", "rm -- /s/ui-token", "next:\n  1. this Mac's browsers warn", "  2. no traffic from iphone yet"} {
		if !strings.Contains(got, w) {
			t.Errorf("%q not in:\n%s", w, got)
		}
	}
	if only := readyBlock(map[string]string{"local": "local"}, "", "", "", "", "/s", nil, true, nil, nil); strings.Contains(only, "mitm.it") {
		t.Errorf("the CA's link with the local proxy alone (the Simulator gets it by itself):\n%s", only)
	}
	if strings.Contains(got, "--web:") {
		t.Errorf("mitmweb without --web:\n%s", got)
	}
	if strings.Contains(got, "--mcp-http") {
		t.Errorf("MCP over HTTP without --mcp-http:\n%s", got)
	}
	withMCP := readyBlock(map[string]string{"n1": "iphone"}, "", "", "http://reqcove.ts.net:8090/mcp", "TOK", "/s", nil, true, nil, nil)
	if !strings.Contains(withMCP, "--mcp-http: http://reqcove.ts.net:8090/mcp  with the header  Authorization: Bearer TOK") || !strings.Contains(withMCP, "rm -- /s/mcp-token") {
		t.Errorf("the MCP line:\n%s", withMCP)
	}
	if steps := nextSteps(n, ready, allow, capture.CA{}, devs[1:]); strings.Contains(strings.Join(steps, "\n"), "this Mac") {
		t.Errorf("the Mac step without the local proxy: %q", steps)
	}
	if steps := withoutMacStep(nextSteps(n, ready, allow, capture.CA{}, devs)); strings.Contains(strings.Join(steps, "\n"), "this Mac") || !strings.Contains(strings.Join(steps, "\n"), "no traffic from iphone") {
		t.Errorf("the page's steps keep the Mac step, or lose others: %q", steps)
	}
	// Trusted while run runs: the step goes, without a restart (the check is macOS's).
	if runtime.GOOS != "darwin" {
		return
	}
	trusted = true
	if steps := nextSteps(n, ready, allow, capture.CA{}, devs); strings.Contains(strings.Join(steps, "\n"), "this Mac") {
		t.Errorf("the Mac step once it trusts the CA: %q", steps)
	}
}

// Codes go side by side as many as the terminal's width takes, the rest on
// the next rows; low error correction keeps each at 37 columns.
func TestQRsSideBySide(t *testing.T) {
	items := []qrItem{{"http://100.111.81.14/?k=ABCDEFGHIJKLMNOPQRSTUVWXYZ", "ui"}, {"http://100.111.81.14:8081/?token=ABCDEFGHIJKLMNOPQRSTUVWXYZ", "web"}, {"http://mitm.it", "ca"}}
	rows := func(cols int) (lines []string, captions int) {
		lines = strings.Split(strings.TrimRight(sideBySide(items, cols), "\n"), "\n")
		for _, l := range lines {
			if strings.HasPrefix(l, "ui:") || strings.HasPrefix(l, "ca:") || strings.HasPrefix(l, "web:") {
				captions++
			}
		}
		return lines, captions
	}
	if lines, n := rows(130); n != 1 || utf8.RuneCountInString(lines[1]) > 130 || !strings.Contains(lines[0], "ca:") {
		t.Errorf("130 columns: %d rows, %q", n, lines[0])
	}
	if lines, n := rows(90); n != 2 || utf8.RuneCountInString(lines[1]) > 90 || !strings.Contains(lines[0], "web:") {
		t.Errorf("90 columns: %d rows (want 2 + 1), %q", n, lines[0])
	}
	if _, n := rows(40); n != 3 {
		t.Errorf("40 columns: %d rows", n)
	}
}

// The ready block waits for two Running polls that agree: the first one,
// before the netmap says the exit node is approved, does not count.
func TestReadyGate(t *testing.T) {
	var g readyGate
	unapproved := exitnode.Status{Backend: "Running", Node: "reqcove.ts.net"}
	approved := exitnode.Status{Backend: "Running", Node: "reqcove.ts.net", ExitApproved: true}
	for i, c := range []struct {
		s    exitnode.Status
		want bool
	}{{exitnode.Status{Backend: "Starting"}, false}, {unapproved, false}, {approved, false}, {approved, true}} {
		if got := g.ready(c.s); got != c.want {
			t.Errorf("poll %d: ready %v, want %v", i, got, c.want)
		}
	}
}

// Help lists flags with two dashes, as the README writes them.
func TestUsageTwoDashes(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.Bool("ui", false, "serve the page")
	fs.String("state", "", "state directory")
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	usageOf(fs)
	w.Close()
	os.Stderr = old
	b, _ := io.ReadAll(r)
	out := string(b)
	if !strings.Contains(out, "Usage: reqcove run [flags]") || !strings.Contains(out, "  --ui\n") || !strings.Contains(out, "  --state string") || strings.Contains(out, "\n  -ui") {
		t.Errorf("help:\n%s", out)
	}
}

// The status tool says which hosts are recorded, so an agent knows a host it
// finds nothing for may be outside them; [] when none.
func TestStatusAllowHosts(t *testing.T) {
	allow, _ := capture.ParseAllowHosts([]string{"API.example.com, *.cdn.example"})
	if got := statusOut(exitnode.Status{}, nil, allow, capture.CA{}, nil).AllowHosts; strings.Join(got, " ") != "api.example.com *.cdn.example" {
		t.Errorf("allow_hosts %q", got)
	}
	if got := statusOut(exitnode.Status{}, nil, capture.HostRules{}, capture.CA{}, nil).AllowHosts; got == nil || len(got) != 0 {
		t.Errorf("no --allow-hosts: %#v", got)
	}
}

// Refused hosts become a step per device, with the --pass-hosts to add,
// quoted for a shell; another device's page lists only its own.
func TestRefusedHostsStep(t *testing.T) {
	ok := exitnode.Status{Backend: "Running", Node: "reqcove.ts.net", ExitApproved: true}
	devices := []capture.DeviceInfo{{ID: "a", Name: "iphone", Carried: true, Flows: 5}, {ID: "b", Name: "ipad", Carried: true, Flows: 3}}
	stats := map[string]any{"state": "ready", "refused_hosts": []capture.RefusedHost{
		{Device: "a", Host: "api.x.com", Refusals: 12}, {Device: "a", Host: "*.weird", Refusals: 4}, {Device: "b", Host: "app4.paypay.ne.jp", Refusals: 19},
	}}
	got := strings.Join(nextSteps(ok, stats, capture.HostRules{All: true}, capture.CA{}, devices), "\n")
	for _, want := range []string{"iphone refused Reqcove's certificate again and again for api.x.com (12), *.weird (4)", "--pass-hosts 'api.x.com,*.weird'", "ipad refused", "--pass-hosts app4.paypay.ne.jp "} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	got = strings.Join(pageSteps(ok, stats, capture.HostRules{All: true}, capture.CA{}, devices, "b"), "\n")
	if strings.Contains(got, "api.x.com") || !strings.Contains(got, "app4.paypay.ne.jp") {
		t.Errorf("b's page:\n%s", got)
	}
}

// --pass-hosts and @FILE: hosts one a line, comments, ~/; a line that is not
// a host stops run, nothing in it run.
func TestPassHostsFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	os.WriteFile(filepath.Join(home, "pass.txt"), []byte("# pinned apps\n*.tiktokv.com\n\n api.x.com  # X\n"), 0o600)
	if got, err := hostList("@~/pass.txt"); err != nil || got != "*.tiktokv.com,api.x.com" {
		t.Errorf("@~/pass.txt: %q %v", got, err)
	}
	os.WriteFile(filepath.Join(home, "urls.txt"), []byte("https://api.example.com/v1\napi.example.com:443\n"), 0o600)
	if _, err := hostList("@~/urls.txt"); err != nil { // as inline values: hostsOnly takes their hosts
		t.Errorf("URL and host:port lines: %v", err)
	}
	if got, _ := hostList("api.x.com"); got != "api.x.com" {
		t.Errorf("plain: %q", got)
	}
	if _, err := hostList("@" + filepath.Join(home, "missing.txt")); err == nil {
		t.Error("a missing file taken")
	}
	// A line that is not a host (a command, or a wrong file's secret) stops it,
	// named by its line number only.
	os.WriteFile(filepath.Join(home, "evil.txt"), []byte("api.x.com\napi.x.com; rm -rf ~ # S3CRET\n"), 0o600)
	if _, err := hostList("@~/evil.txt"); err == nil || !strings.Contains(err.Error(), "line 2 is not a host list") || strings.Contains(err.Error(), "rm -rf") || strings.Contains(err.Error(), "S3CRET") {
		t.Errorf("evil.txt: %v", err)
	}
	os.WriteFile(filepath.Join(home, "empty.txt"), []byte("# nothing\n\n"), 0o600)
	if _, err := hostList("@~/empty.txt"); err == nil || !strings.Contains(err.Error(), "has no hosts") {
		t.Errorf("empty.txt: %v", err)
	}
	args := func(extra ...string) []string {
		return append([]string{"--device", "phone", "--state", t.TempDir(), "--uvx", "/nonexistent/uvx"}, extra...)
	}
	for _, c := range []struct {
		extra []string
		want  string
	}{
		{[]string{"--pass-hosts", "api.x.com"}, "--pass-hosts needs --allow-hosts"},
		{[]string{"--allow-hosts", "*", "--pass-hosts", "*"}, `not "*"`},
	} {
		if err := run(context.Background(), args(c.extra...)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v", c.extra, err)
		}
	}
}

// Suggestions group a domain's hosts (by the public suffix list), keep the
// pass hosts already given, and a device with only passed connections is not
// told to turn its exit node on.
func TestPassSuggestion(t *testing.T) {
	hosts, counts := passSuggestion(nil, nil)
	if hosts != nil {
		t.Errorf("nothing refused: %q %q", hosts, counts)
	}
	hosts, counts = passSuggestion([]capture.RefusedHost{
		{Host: "api31.tiktokv.com", Refusals: 30}, {Host: "log22.tiktokv.com", Refusals: 5},
		{Host: "app4.paypay.ne.jp", Refusals: 19}, {Host: "events.paypay.ne.jp", Refusals: 6},
		{Host: "api.x.com", Refusals: 4}, {Host: "34.102.215.99", Refusals: 61},
	}, nil)
	if strings.Join(hosts, ",") != "*.tiktokv.com,*.paypay.ne.jp,api.x.com,34.102.215.99" || !strings.Contains(strings.Join(counts, ";"), "2 hosts of tiktokv.com (35)") {
		t.Errorf("%q %q", hosts, counts)
	}
	ok := exitnode.Status{Backend: "Running", Node: "reqcove.ts.net", ExitApproved: true}
	allow, _ := capture.ParseAllowHosts([]string{"*"})
	allow, _ = allow.WithPass([]string{"api.x.com"})
	stats := map[string]any{"state": "ready", "refused_hosts": []capture.RefusedHost{{Device: "a", Host: "app4.paypay.ne.jp", Refusals: 9}}}
	got := strings.Join(nextSteps(ok, stats, allow, capture.CA{}, []capture.DeviceInfo{{ID: "a", Name: "iphone", Carried: true, Flows: 1}}), "\n")
	if !strings.Contains(got, "--pass-hosts 'api.x.com,app4.paypay.ne.jp' ") {
		t.Errorf("keeps the pass hosts given:\n%s", got)
	}
	got = strings.Join(nextSteps(ok, map[string]any{"state": "ready"}, allow, capture.CA{}, []capture.DeviceInfo{{ID: "a", Name: "iphone", Carried: true, Passthroughs: 4}}), "\n")
	if strings.Contains(got, "no traffic from iphone") {
		t.Errorf("a device with passed connections told it has no traffic:\n%s", got)
	}
}

// A new refused host under a domain a pass host has already becomes *.domain,
// which replaces that pass host in the command.
func TestPassSuggestionMerges(t *testing.T) {
	ok := exitnode.Status{Backend: "Running", Node: "reqcove.ts.net", ExitApproved: true}
	allow, _ := capture.ParseAllowHosts([]string{"*"})
	allow, _ = allow.WithPass([]string{"p16-sticker.ibyteimg.com", "app4.paypay.ne.jp", "api.x.com", "34.102.215.99"})
	stats := map[string]any{"state": "ready", "refused_hosts": []capture.RefusedHost{
		{Device: "a", Host: "p16-asset.ibyteimg.com", Refusals: 19}, {Device: "a", Host: "events.paypay.ne.jp", Refusals: 3}, {Device: "a", Host: "new.example.org", Refusals: 3},
	}}
	got := strings.Join(nextSteps(ok, stats, allow, capture.CA{}, []capture.DeviceInfo{{ID: "a", Name: "iphone", Carried: true, Flows: 1}}), "\n")
	if !strings.Contains(got, "--pass-hosts 'api.x.com,34.102.215.99,*.ibyteimg.com,*.paypay.ne.jp,new.example.org'") {
		t.Errorf("merged:\n%s", got)
	}
}

// On Android (as Tailscale says), the steps say its apps trust only the
// system's CAs, and narrowing --allow-hosts, rather than pinning or the CA.
func TestAndroidSteps(t *testing.T) {
	node := exitnode.Status{Backend: "Running", Node: "reqcove.ts.net", ExitApproved: true, DeviceOS: map[string]string{"a": "android", "i": "iOS"}}
	all := []capture.DeviceInfo{{ID: "a", Name: "beam-pro", Carried: true, TLSFailures: 40}, {ID: "i", Name: "iphone", Carried: true, TLSFailures: 3}}
	got := strings.Join(nextSteps(node, map[string]any{"state": "ready"}, capture.HostRules{All: true}, capture.CA{Name: "Reqcove CA"}, all), "\n")
	for _, want := range []string{"beam-pro refuses every certificate so far. It runs Android", "open a site in Chrome", "network_security_config", "iphone refuses every certificate so far: install and trust"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	some := []capture.DeviceInfo{{ID: "a", Name: "beam-pro", Carried: true, Flows: 6}, {ID: "i", Name: "iphone", Carried: true, Flows: 9}}
	stats := map[string]any{"state": "ready", "refused_hosts": []capture.RefusedHost{{Device: "a", Host: "api.app.example", Refusals: 30}, {Device: "i", Host: "api.x.com", Refusals: 12}}}
	got = strings.Join(nextSteps(node, stats, capture.HostRules{All: true}, capture.CA{}, some), "\n")
	for _, want := range []string{"beam-pro refused Reqcove's certificate again and again for api.app.example (30). It runs Android", "Keep --allow-hosts to the hosts you test", "--pass-hosts api.app.example ", "iphone refused Reqcove's certificate again and again for api.x.com (12), while it accepts it"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
}

// TestPassSuggestionKeepsRecorded: hosts refused under a domain whose other
// hosts are decrypted and recorded are named one by one, never *.domain, which
// would stop recording the app under test.
func TestPassSuggestionKeepsRecorded(t *testing.T) {
	refused := []capture.RefusedHost{
		{Device: "d", Host: "auth.example.com", Refusals: 5, SiblingsRecorded: true},
		{Device: "d", Host: "pay.example.com", Refusals: 4, SiblingsRecorded: true},
		{Device: "d", Host: "a.cdn.example", Refusals: 3},
		{Device: "d", Host: "b.cdn.example", Refusals: 3},
	}
	hosts, _ := passSuggestion(refused, nil)
	got := strings.Join(hosts, ",")
	if got != "auth.example.com,pay.example.com,*.cdn.example" {
		t.Errorf("suggested %s", got)
	}
}

// TestReadyRmQuoted: the rm a ready block suggests quotes the state path: a
// path with shell syntax in it is a path, not a command, when pasted.
func TestReadyRmQuoted(t *testing.T) {
	got := readyBlock(map[string]string{"local": "local"}, "http://100.1.2.3/?k=K", "", "", "", "/tmp/r-$(id) x", nil, true, nil, nil)
	if !strings.Contains(got, "rm -- '/tmp/r-$(id) x/ui-token'") {
		t.Errorf("rm not quoted:\n%s", got)
	}
}
