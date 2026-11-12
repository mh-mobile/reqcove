package exitnode

import (
	"context"
	"log"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// runAgainst starts reqcove's node against a fresh testcontrol, set up by
// prep, and returns the control and a way to wait for a status.
func runAgainst(t *testing.T, prep func(*testcontrol.Server), opts ...func(*Config)) (*testcontrol.Server, func(what string, ok func(Status) bool) Status) {
	t.Helper()
	netns.SetEnabled(false)
	t.Cleanup(func() { netns.SetEnabled(true) })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	control := &testcontrol.Server{DERPMap: integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1"), MagicDNSDomain: "tail-scale.ts.net"}
	if prep != nil {
		prep(control)
	}
	control.HTTPTestServer = httptest.NewServer(control)
	t.Cleanup(control.HTTPTestServer.Close)
	statuses := make(chan Status, 100)
	cfg := Config{
		Dir: filepath.Join(t.TempDir(), "reqcove"), Hostname: "reqcove", ControlURL: control.HTTPTestServer.URL,
		DNS: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}, Devices: []string{"phone"},
		OnStatus: func(s Status) {
			select {
			case statuses <- s:
			default:
			}
		},
	}
	for _, o := range opts {
		o(&cfg)
	}
	go Run(ctx, cfg)
	wait := func(what string, ok func(Status) bool) Status {
		t.Helper()
		var last Status
		deadline := time.After(60 * time.Second)
		for {
			select {
			case s := <-statuses:
				if last = s; ok(s) {
					return s
				}
			case <-deadline:
				t.Fatalf("never %s; last status %+v", what, last)
			}
		}
	}
	return control, wait
}

// run's terminal shows the login URL once it is there, not the status tool's
// "open the URL that reqcove run prints" while it is on its way.
// A step shows once two polls agree on it, and once only.
func TestSettledStep(t *testing.T) {
	var s settled
	for i, c := range []struct {
		in, want string
		show     bool
	}{
		{"sign", "", false}, // first sight: may be the start-up moment
		{"approve", "", false},
		{"", "", false}, // all done, seen once
		{"", "", false}, // all done, settled: nothing to show (shown starts empty)
		{"approve", "", false},
		{"approve", "approve", true},
		{"approve", "", false}, // once only
		{"", "", false},
		{"", "", true}, // back to nothing to do: shown as such
	} {
		got, show := s.next(c.in)
		if got != c.want || show != c.show {
			t.Errorf("step %d (%q): %q %v, want %q %v", i, c.in, got, show, c.want, c.show)
		}
	}
}

func TestRunStep(t *testing.T) {
	if step := runStep(Status{Backend: "NeedsLogin"}, "reqcove links"); step != "" {
		t.Errorf("before the URL: %q", step)
	}
	if step := runStep(Status{Backend: "NeedsLogin", AuthURL: "https://login.example/a/1"}, "reqcove links --state /s"); strings.Contains(step, "login.example") || !strings.Contains(step, "`reqcove links --state /s`") {
		t.Errorf("with the URL: %q", step)
	}
	if step := runStep(Status{Backend: "NeedsLogin", WasRunning: true}, "reqcove links"); !strings.Contains(step, "start it again") {
		t.Errorf("after the key expired: %q", step)
	}
}

func TestStatusLoginNeeded(t *testing.T) {
	var logs syncBuffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	control, wait := runAgainst(t, func(c *testcontrol.Server) { c.RequireAuth = true })
	s := wait("asked to log in", func(s Status) bool { return s.Backend == "NeedsLogin" && s.AuthURL != "" })
	time.Sleep(6 * time.Second) // tsnet would print its own login line every 5 s
	if got := logs.String(); !strings.Contains(got, "log in: open the login URL") || strings.Contains(got, s.AuthURL) || strings.Contains(got, "TS_AUTHKEY") {
		t.Errorf("run's log:\n%s", got)
	}
	if step := FirstStep(s); strings.Contains(step, s.AuthURL) || !strings.Contains(step, "`reqcove links`") {
		t.Errorf("step %q", step)
	}
	if !strings.HasPrefix(s.AuthURL, control.HTTPTestServer.URL) {
		t.Errorf("auth URL %q is not the control's", s.AuthURL)
	}
}

// Under --verbose tsnet logs the login URL itself (authURL=…, "AuthURL is
// …", every 5 s "go to: …"), some lines before run's first poll learns it:
// through the Redactor, none reach the log.
func TestVerboseLoginURLRedacted(t *testing.T) {
	var logs syncBuffer
	log.SetOutput(&Redactor{W: &logs})
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	_, wait := runAgainst(t, func(c *testcontrol.Server) { c.RequireAuth = true }, func(c *Config) { c.Verbose = true })
	s := wait("asked to log in", func(s Status) bool { return s.Backend == "NeedsLogin" && s.AuthURL != "" })
	time.Sleep(6 * time.Second) // tsnet's own login line, every 5 s
	got := logs.String()
	_, key, _ := strings.Cut(s.AuthURL, "/auth/")
	if key == "" || strings.Contains(got, key) || !strings.Contains(got, RedactedLink) {
		t.Errorf("key %q; log:\n%s", key, got)
	}
}

// After the key expires, tsnet prints no new login URL: the step says to restart.
func TestStatusKeyExpired(t *testing.T) {
	control, wait := runAgainst(t, nil)
	wait("running", func(s Status) bool { return s.Backend == "Running" })
	control.SetExpireAllNodes(true)
	s := wait("logged out", func(s Status) bool { return s.Backend == "NeedsLogin" })
	if step := FirstStep(s); !strings.Contains(step, "start it again") {
		t.Errorf("step %q", step)
	}
}

func TestStatusDeviceApproval(t *testing.T) {
	_, wait := runAgainst(t, func(c *testcontrol.Server) { c.RequireMachineAuth = true })
	s := wait("asked for device approval", func(s Status) bool { return s.Backend == "NeedsMachineAuth" })
	if step := FirstStep(s); !strings.Contains(step, "approve this device") {
		t.Errorf("step %q", step)
	}
}

func TestStatusExitApproval(t *testing.T) {
	control, wait := runAgainst(t, nil)
	s := wait("running", func(s Status) bool { return s.Backend == "Running" && s.Node != "" })
	if s.ExitApproved || !strings.Contains(FirstStep(s), "approve the exit node") || !strings.Contains(FirstStep(s), s.Node) {
		t.Errorf("before approval: %+v, step %q", s, FirstStep(s))
	}
	if len(s.Problems) == 0 || len(s.Devices) != 0 {
		t.Errorf("phone is not in the tailnet, yet: devices %v problems %v", s.Devices, s.Problems)
	}
	for _, n := range control.AllNodes() {
		control.SetSubnetRoutes(n.Key, tsaddr.ExitRoutes()) // the admin approves
	}
	s = wait("approved", func(s Status) bool { return s.ExitApproved })
	if step := FirstStep(s); step != "" {
		t.Errorf("after approval, step %q", step)
	}
}

// A tailnet that requires data plane audit logs stops a node that sends no
// logs; reqcove says so instead of turning logs on.
func TestStatusAuditLogsRequired(t *testing.T) {
	control, wait := runAgainst(t, nil)
	wait("running", func(s Status) bool { return s.Backend == "Running" })
	for _, n := range control.AllNodes() {
		control.SetNodeCapMap(n.Key, tailcfg.NodeCapMap{nodecap.DataPlaneAuditLogs: nil})
		control.SetSubnetRoutes(n.Key, tsaddr.ExitRoutes()) // pushes a new netmap
	}
	s := wait("refused for audit logs", func(s Status) bool { return strings.HasPrefix(FirstStep(s), "not supported") })
	if !strings.Contains(FirstStep(s), "audit logging") {
		t.Errorf("step %q", FirstStep(s))
	}
}
