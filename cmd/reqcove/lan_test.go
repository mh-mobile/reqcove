package main

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
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
	// No node port in LAN mode: --proxy-port 8081 does not clash with --web.
	err = run(context.Background(), append(append([]string{}, base...), "--web", "--proxy-port", "8081", "--lan-interface", loopback(t)))
	if err == nil || !strings.Contains(err.Error(), "uv not found") {
		t.Errorf("--lan --web --proxy-port 8081: %v", err)
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
		if err == nil || !strings.Contains(err.Error(), "only in a terminal") || strings.Contains(err.Error(), "this Mac") { // Linux too
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
	ask := lanAsker(ctx, r, io.Discard, state, lanTTY{foreground: func() bool { return true }, flush: func() {}})
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

// What was typed before the question is dropped before it is printed.
func TestLANAskerFlushesFirst(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	note := func(s string) { mu.Lock(); seen = append(seen, s); mu.Unlock() }
	r, w := io.Pipe()
	defer w.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ask := lanAsker(ctx, r, writerFunc(func(p []byte) (int, error) { note("question"); return len(p), nil }), t.TempDir(),
		lanTTY{foreground: func() bool { return true }, flush: func() { note("flush") }})
	ask(netip.MustParseAddr("192.168.1.23"))
	io.WriteString(w, "n\n") // read once the question is out
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(seen, ",") != "flush,question" {
		t.Errorf("%q, want the flush before the question", seen)
	}
}

// In the background (run &), stdin is never read: a read would stop run.
func TestLANAskerBackground(t *testing.T) {
	state := t.TempDir()
	var reads atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ask := lanAsker(ctx, readerFunc(func([]byte) (int, error) { reads.Add(1); return 0, io.EOF }), io.Discard, state,
		lanTTY{foreground: func() bool { return false }, flush: func() { reads.Add(100) }})
	ask(netip.MustParseAddr("192.168.1.23"))
	time.Sleep(200 * time.Millisecond)
	if n := reads.Load(); n != 0 {
		t.Errorf("stdin touched in the background (%d)", n)
	}
	if list, _ := readLANAllowed(state); len(list) != 0 {
		t.Errorf("allowed %v", list)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func lanStatus(listen string, refused []string, devices map[string]string) exitnode.Status {
	return exitnode.Status{Mode: "lan", Devices: devices, LAN: &exitnode.LANStatus{Interface: "en0", Network: "192.168.1.0/24", Listen: listen, Refused: refused,
		Allowed: []exitnode.LANAllowed{{Addr: "192.168.1.23", When: "2026-11-13T17:00:00.000+09:00"}}}}
}

// status in LAN mode: its mode and LAN part, and steps for a Wi-Fi proxy, not
// for an exit node or a tailnet node.
func TestStatusLAN(t *testing.T) {
	allow, _ := capture.ParseAllowHosts([]string{"api.example.com"})
	ready := map[string]any{"state": "ready"}
	if out := statusOut(exitnode.Status{}, ready, allow, capture.CA{}, nil); out.Mode != "tailnet" || out.LAN != nil {
		t.Errorf("tailnet: mode %q, lan %v", out.Mode, out.LAN)
	}
	s := lanStatus("192.168.1.10:8080", nil, map[string]string{})
	out := statusOut(s, ready, allow, capture.CA{}, nil)
	if out.Mode != "lan" || out.LAN == nil {
		t.Fatalf("lan: mode %q, lan %v", out.Mode, out.LAN)
	}
	steps := strings.Join(out.NextSteps, "\n")
	for _, want := range []string{"Server 192.168.1.10, Port 8080", "reqcove lan allow ADDR"} {
		if !strings.Contains(steps, want) {
			t.Errorf("steps lack %q:\n%s", want, steps)
		}
	}
	if strings.Contains(steps, "tailnet") || strings.Contains(steps, "exit node") {
		t.Errorf("tailnet steps in LAN mode:\n%s", steps)
	}
	// Refused addresses are named; an allowed address without traffic gets its own step.
	s = lanStatus("192.168.1.10:8080", []string{"192.168.1.40"}, map[string]string{"lan:192.168.1.23": "lan:192.168.1.23"})
	devs := []capture.DeviceInfo{{ID: "lan:192.168.1.23", Carried: true}}
	steps = strings.Join(statusOut(s, ready, allow, capture.CA{}, devs).NextSteps, "\n")
	if !strings.Contains(steps, "not allowed: 192.168.1.40") || !strings.Contains(steps, "no traffic from lan:192.168.1.23 yet") {
		t.Errorf("steps:\n%s", steps)
	}
	s.LAN.Listen, s.LAN.Stopped = "", "en0 is on another network now"
	if steps := strings.Join(statusOut(s, ready, allow, capture.CA{}, devs).NextSteps, "\n"); !strings.Contains(steps, "not listening: en0 is on another network now") {
		t.Errorf("stopped:\n%s", steps)
	}
	var b strings.Builder
	printLANStatus(&b, lanStatus("192.168.1.10:8080", []string{"192.168.1.40"}, nil).LAN)
	if got := b.String(); !strings.Contains(got, "192.168.1.10:8080 on en0, for clients on 192.168.1.0/24") || !strings.Contains(got, "allowed:     192.168.1.23 (since") || !strings.Contains(got, "refused:     192.168.1.40 (not") {
		t.Errorf("reqcove status:\n%s", got)
	}
	// More refused than the status lists: how many more, in the status and its step.
	s = lanStatus("192.168.1.10:8080", []string{"192.168.1.40"}, nil)
	s.LAN.RefusedMore = 7
	b.Reset()
	printLANStatus(&b, s.LAN)
	steps = strings.Join(statusOut(s, ready, allow, capture.CA{}, nil).NextSteps, "\n")
	if !strings.Contains(b.String(), "refused:     192.168.1.40 and 7 more (not") || !strings.Contains(steps, "not allowed: 192.168.1.40 and 7 more.") {
		t.Errorf("more:\n%s\n%s", b.String(), steps)
	}
}

// The ready block in LAN mode: what to enter on the iPhone, how to allow it,
// who is allowed, and the CA with its SHA-256 (plain HTTP on a LAN can be swapped).
func TestReadyBlockLAN(t *testing.T) {
	l := &lanReady{listen: "192.168.1.10:8080", allowed: lanStatus("", nil, nil).LAN.Allowed, state: "/s", prompt: true, caSHA256: "AB12CD0F", caFile: "/s/mitmproxy/mitmproxy-ca-cert.pem"}
	got := readyBlock(map[string]string{}, "", "", "", "", "/s", nil, true, nil, l)
	for _, want := range []string{"Server 192.168.1.10, Port 8080", "allowed:  192.168.1.23 (since", "answer run's question here, or `reqcove lan allow --state /s ADDR`",
		"`reqcove lan deny --state /s ADDR` takes it back", "AirDrop /s/mitmproxy/mitmproxy-ca-cert.pem", "SHA-256 (on the iPhone: Settings, General, VPN & Device Management, the profile, More Details) is ab 12 cd 0f\n", "devices:  none allowed yet"} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "exit node") {
		t.Errorf("tailnet wording in LAN mode:\n%s", got)
	}
}

// On the tailnet, no device matched yet: no LAN wording, and no CA line.
func TestReadyBlockTailnetNoDevices(t *testing.T) {
	got := readyBlock(map[string]string{}, "", "", "", "", "/s", nil, true, nil, nil)
	if strings.Contains(got, "allowed") || strings.Contains(got, "mitm.it") || !strings.Contains(got, "devices:  \n") {
		t.Errorf("tailnet, no devices:\n%s", got)
	}
}

// In LAN mode, `reqcove status` and `reqcove links` give the CA as the ready
// block does: through the Wi-Fi proxy, with the AirDrop and SHA-256 advice.
func TestCALAN(t *testing.T) {
	state := t.TempDir()
	os.MkdirAll(filepath.Join(state, "mitmproxy"), 0o700)
	os.WriteFile(caPEM(state), testCAPEM(t), 0o600)
	ca, err := capture.ReadCA(filepath.Join(state, "mitmproxy"))
	if err != nil {
		t.Fatal(err)
	}
	old := security
	defer func() { security = old }()
	security = func(...string) error { return errors.New("not trusted") }
	// As iOS shows it (More Details): lowercase pairs, spaced. The CA line keeps the form security -Z takes.
	ios := "More Details) is " + strings.ToLower(ca.SHA256[:2]+" "+ca.SHA256[2:4]+" ")
	for _, lan := range []bool{false, true} {
		var b strings.Builder
		printCA(&b, state, lan)
		got := b.String()
		if lan != strings.Contains(got, "with the Wi-Fi proxy set") || lan == strings.Contains(got, "exit node") || lan != strings.Contains(got, "AirDrop "+caPEM(state)) || lan != strings.Contains(got, ios) || !strings.Contains(got, "SHA-256 "+ca.SHA256+",") {
			t.Errorf("status, lan %v:\n%s", lan, got)
		}
	}
	for _, lan := range []bool{false, true} {
		u := &userLinks{state: state, lan: lan}
		u.ready("", "", "", "", "", "http://mitm.it")
		f, _ := os.CreateTemp(t.TempDir(), "out")
		if err := printLinks(f, state); err != nil {
			t.Fatal(err)
		}
		f.Close()
		b, _ := os.ReadFile(f.Name())
		got := string(b)
		if lan != strings.Contains(got, "with the Wi-Fi proxy set") || lan == strings.Contains(got, "exit node") || lan != strings.Contains(got, ios) {
			t.Errorf("links, lan %v:\n%s", lan, got)
		}
	}
}

// The ready block waits for LAN mode's status too.
func TestReadyGateLAN(t *testing.T) {
	var g readyGate
	s := exitnode.Status{Mode: "lan", IPs: []string{"192.168.1.10"}}
	if g.ready(s) || !g.ready(s) {
		t.Error("LAN mode never ready")
	}
}
