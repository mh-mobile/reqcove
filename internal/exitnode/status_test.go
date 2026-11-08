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
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// runAgainst starts reqcove's node against a fresh testcontrol, set up by
// prep, and returns the control and a way to wait for a status.
func runAgainst(t *testing.T, prep func(*testcontrol.Server)) (*testcontrol.Server, func(what string, ok func(Status) bool) Status) {
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
	go Run(ctx, Config{
		Dir: filepath.Join(t.TempDir(), "reqcove"), Hostname: "reqcove", ControlURL: control.HTTPTestServer.URL,
		DNS: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}, Devices: []string{"phone"},
		OnStatus: func(s Status) {
			select {
			case statuses <- s:
			default:
			}
		},
	})
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
func TestRunStep(t *testing.T) {
	if step := runStep(Status{Backend: "NeedsLogin"}); step != "" {
		t.Errorf("before the URL: %q", step)
	}
	if step := runStep(Status{Backend: "NeedsLogin", AuthURL: "https://login.example/a/1"}); !strings.Contains(step, "https://login.example/a/1") {
		t.Errorf("with the URL: %q", step)
	}
	if step := runStep(Status{Backend: "NeedsLogin", WasRunning: true}); !strings.Contains(step, "start it again") {
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
	if got := logs.String(); !strings.Contains(got, "log in: open "+s.AuthURL) || strings.Contains(got, "TS_AUTHKEY") || strings.Contains(got, "prints in its terminal") {
		t.Errorf("run's log:\n%s", got)
	}
	if step := FirstStep(s); !strings.HasPrefix(step, "log in: open "+s.AuthURL) {
		t.Errorf("step %q", step)
	}
	if !strings.HasPrefix(s.AuthURL, control.HTTPTestServer.URL) {
		t.Errorf("auth URL %q is not the control's", s.AuthURL)
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
		control.SetNodeCapMap(n.Key, tailcfg.NodeCapMap{tailcfg.CapabilityDataPlaneAuditLogs: nil})
		control.SetSubnetRoutes(n.Key, tsaddr.ExitRoutes()) // pushes a new netmap
	}
	s := wait("refused for audit logs", func(s Status) bool { return strings.HasPrefix(FirstStep(s), "not supported") })
	if !strings.Contains(FirstStep(s), "audit logging") {
		t.Errorf("step %q", FirstStep(s))
	}
}
