package main

import (
	"context"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/exitnode"
)

// What the tailnet node serves, or names, is refused with --lan, with a reason;
// --lan-interface without --lan, and --lan without a port, too.
func TestRunLANRefuses(t *testing.T) {
	base := []string{"--lan", "--allow-hosts", "api.example.com", "--state", t.TempDir(), "--uvx", "/nonexistent/uvx"}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--device", "phone"}, "--device does not go with --lan"},
		{[]string{"--ui"}, "--ui does not go with --lan"},
		{[]string{"--mcp-http"}, "--mcp-http does not go with --lan"},
		{[]string{"--hostname", "x"}, "--hostname does not go with --lan"},
		{[]string{"--dns", "1.1.1.1"}, "--dns does not go with --lan"},
		{[]string{"--proxy-port", "0"}, "--lan needs a --proxy-port"},
	} {
		err := run(context.Background(), append(append([]string{}, base...), c.args...))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.args, err, c.want)
		}
	}
	err := run(context.Background(), []string{"--device", "phone", "--lan-interface", "en0", "--state", t.TempDir(), "--uvx", "/nonexistent/uvx"})
	if err == nil || !strings.Contains(err.Error(), "--lan-interface goes with --lan") {
		t.Errorf("--lan-interface alone: %v", err)
	}
	// --web and --local-proxy go with it: run goes on to look for uv.
	err = run(context.Background(), append(append([]string{}, base...), "--web", "--lan-interface", loopback(t)))
	if err == nil || !strings.Contains(err.Error(), "uv not found") {
		t.Errorf("--lan --web: %v", err)
	}
}

func loopback(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"lo0", "lo"} {
		if _, _, err := exitnode.LANAddr(name); err == nil {
			return name
		}
	}
	t.Skip("no loopback interface")
	return ""
}

// --lan stays on the command line: no proxy for the LAN always on through a service.
func TestConfigRefusesLAN(t *testing.T) {
	fs, _, allow := testFlags()
	fs.Bool("lan", false, "")
	p := writeConfig(t, "--allow-hosts api.example.com\n--lan\n", 0o600)
	if err := parseConfig(fs, p, allow); err == nil || !strings.Contains(err.Error(), "--lan only on the command line") {
		t.Errorf("--lan in --config: %v", err)
	}
}

// Off a terminal (an agent's shell) the lan commands do nothing.
func TestLANNotATerminal(t *testing.T) {
	state := t.TempDir()
	for _, args := range [][]string{{"allow", "192.168.1.23"}, {"deny", "192.168.1.23"}, {"list"}} {
		err := lan(context.Background(), append(args, "--state", state))
		if err == nil || !strings.Contains(err.Error(), "only in a terminal") {
			t.Errorf("%q: %v", args, err)
		}
	}
	if _, err := os.Stat(filepath.Join(state, lanAllowedFile)); !os.IsNotExist(err) {
		t.Errorf("allowed off a terminal: %v", err)
	}
}

// The commands run's hints write parse, --state before or after the address.
func TestLANHintsParse(t *testing.T) {
	state := t.TempDir()
	for _, hint := range []string{
		withState("reqcove lan allow", state) + " 192.168.1.23",
		withState("reqcove lan deny", state) + " 192.168.1.23",
		withState("reqcove lan list", state),
		"reqcove lan --state " + state + " allow 192.168.1.23",
	} {
		err := lan(context.Background(), strings.Fields(hint)[2:])
		if err == nil || !strings.Contains(err.Error(), "only in a terminal") { // parsed: refused off a terminal
			t.Errorf("%s: %v", hint, err)
		}
	}
	if err := lan(context.Background(), []string{"allow", "192.168.1.23", "x"}); err == nil || !strings.Contains(err.Error(), "unexpected argument") {
		t.Errorf("a word too many: %v", err)
	}
}

// `lan allow` before the first run leaves a state directory run still takes.
func TestLANAllowBeforeRun(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if _, err := allowLAN(state, netip.MustParseAddr("192.168.1.23")); err != nil {
		t.Fatal(err)
	}
	unlock, err := openState(state)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}

func TestLANAllowedFile(t *testing.T) {
	state := t.TempDir()
	a, b := netip.MustParseAddr("192.168.1.23"), netip.MustParseAddr("192.168.1.24")
	for _, addr := range []netip.Addr{a, b, a} {
		if _, err := allowLAN(state, addr); err != nil {
			t.Fatal(err)
		}
	}
	list, err := readLANAllowed(state)
	if err != nil || len(list) != 2 || list[0].addr != a || list[1].addr != b || time.Since(list[0].when) > time.Minute {
		t.Fatalf("%v %v", list, err)
	}
	if fi, _ := os.Stat(filepath.Join(state, lanAllowedFile)); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	if got := lanAddrs(state)(); len(got) != 2 {
		t.Errorf("run reads %v", got)
	}
}

// run's prompt: y allows, anything else does not; the proxy never waits on it.
func TestLANAsker(t *testing.T) {
	state := t.TempDir()
	r, w := io.Pipe()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ask := lanAsker(ctx, r, io.Discard, state)
	a, b := netip.MustParseAddr("192.168.1.23"), netip.MustParseAddr("192.168.1.24")
	ask(a)
	ask(b)
	for range 20 {
		ask(netip.MustParseAddr("192.168.1.99")) // a full queue drops, never blocks
	}
	io.WriteString(w, "n\n")
	io.WriteString(w, "y\n")
	for range 100 {
		if list, _ := readLANAllowed(state); len(list) > 0 {
			if len(list) != 1 || list[0].addr != b {
				t.Errorf("allowed %v, want only %v", list, b)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("y did not allow")
}

// The ready block waits for LAN mode's status too.
func TestReadyGateLAN(t *testing.T) {
	var g readyGate
	s := exitnode.Status{Backend: "LAN", IPs: []string{"192.168.1.10"}}
	if g.ready(s) || !g.ready(s) {
		t.Error("LAN mode never ready")
	}
}
