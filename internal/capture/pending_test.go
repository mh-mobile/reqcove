package capture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// What happens to a change mitmproxy does not acknowledge: told again,
// failing closed, or restarting mitmdump.

// sleepProc is a stand-in for the mitmdump spawned last: it runs until killed.
func sleepProc(t *testing.T) *proc {
	t.Helper()
	sleep := exec.Command("sleep", "60")
	sleep.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := sleep.Start(); err != nil {
		t.Fatal(err)
	}
	p := &proc{cmd: sleep, done: make(chan struct{})}
	go func() { p.err = sleep.Wait(); close(p.done) }()
	t.Cleanup(func() { syscall.Kill(-sleep.Process.Pid, syscall.SIGKILL) })
	return p
}

func killed(p *proc, within time.Duration) bool {
	select {
	case <-p.done:
		return true
	case <-time.After(within):
		return false
	}
}

// ackUnless answers scope ops as the addon would: checks always, the others
// not while silent is set.
func ackUnless(silent *atomic.Bool) func(op map[string]any) map[string]any {
	return func(op map[string]any) map[string]any {
		switch {
		case op["check"] == true:
			return map[string]any{"ok": true}
		case silent.Load():
			return nil
		case op["op"] == "discover":
			return map[string]any{"ok": true}
		}
		return map[string]any{"ok": true, "gen": op["gen"], "instance": "inst-1"}
	}
}

// A stop during allow-all that mitmproxy does not acknowledge fails closed,
// as allow-all's end does: the mitmdump is killed (it would go on decrypting
// every host, with no end left here to expire it), and the next one starts
// stopped, without allow-all. A stop without allow-all kills nothing.
func TestStopDuringAllowAllUnacknowledged(t *testing.T) {
	ctx := context.Background()
	c := scopeCapture(t, rulesOf(t, "a.example.com"))
	var silent atomic.Bool
	fakeControl(t, c.cfg.Dir, ackUnless(&silent))
	if _, _, err := c.SetAllowAll(ctx, "capture allow-all --for 30m", 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	p := sleepProc(t)
	c.proc = p
	silent.Store(true)
	if _, err := c.SetStopped(ctx, "capture stop", true); !errors.Is(err, ErrPending) {
		t.Fatalf("stop, mitmproxy silent: %v", err)
	}
	if !killed(p, 5*time.Second) {
		t.Error("mitmdump not killed: it keeps allow-all, with no end")
	}
	if args := c.mitmArgs(); slices.Contains(args, "reqcove_allow_all=true") || !slices.Contains(args, "reqcove_stopped=true") {
		t.Errorf("the next mitmdump's args: %q", args)
	}

	silent.Store(false)
	if _, err := c.SetStopped(ctx, "capture start", false); err != nil {
		t.Fatal(err)
	}
	p = sleepProc(t)
	c.proc = p
	silent.Store(true)
	if _, err := c.SetStopped(ctx, "capture stop", true); !errors.Is(err, ErrPending) || killed(p, 300*time.Millisecond) {
		t.Errorf("a stop without allow-all: %v, killed %v", err, killed(p, 0))
	}
}

// A change whose answer was lost (the scope, discovery on) is told again
// every few seconds (expireLoop), not only at the mitmdump's next hello.
func TestRetryPending(t *testing.T) {
	c := scopeCapture(t, rulesOf(t, "a.example.com"))
	var silent atomic.Bool
	silent.Store(true)
	ops := fakeControl(t, c.cfg.Dir, ackUnless(&silent))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.SetScope(ctx, rulesOf(t, "a.example.com", "b.example.com")); !errors.Is(err, ErrPending) || c.ScopePending() != PendingAsked {
		t.Fatalf("unanswered: %v, pending %q", err, c.ScopePending())
	}
	if _, _, err := c.SetDiscover(ctx, "capture discover --for 1h", time.Hour); !errors.Is(err, ErrPending) || !c.DiscoverUntil().IsZero() {
		t.Fatalf("discovery unanswered: %v, on %v", err, c.DiscoverUntil())
	}
	silent.Store(false)
	go c.expireLoop(ctx)
	for deadline := time.Now().Add(10 * time.Second); c.ScopePending() != "" || c.DiscoverUntil().IsZero(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("still pending: scope %q, discovery on %v; ops %v", c.ScopePending(), !c.DiscoverUntil().IsZero(), ops())
		}
	}
	if !slices.Equal(c.Scope().Hosts, []string{"a.example.com", "b.example.com"}) {
		t.Errorf("scope %v", c.Scope().Hosts)
	}
}

// A reload whose new hosts and rules mitmproxy does not acknowledge kills
// the mitmdump: told again, it would get the hosts without the rules (a host
// recorded without its mock). The next one starts with both.
func TestReloadPendingRestarts(t *testing.T) {
	c := scopeCapture(t, rulesOf(t, "a.example.com"))
	c.cfg.Rules = filepath.Join(c.cfg.Dir, "rules.yaml")
	os.WriteFile(filepath.Join(c.cfg.Dir, rulesCopy), []byte("mock: []\n"), 0o600)
	var silent atomic.Bool
	silent.Store(true)
	fakeControl(t, c.cfg.Dir, ackUnless(&silent))
	p := sleepProc(t)
	c.proc = p
	if _, err := c.Reload(context.Background(), "reload", rulesOf(t, "a.example.com", "b.example.com"), []byte("mock: []\n")); !errors.Is(err, ErrPending) {
		t.Fatalf("reload unanswered: %v", err)
	}
	if !killed(p, 5*time.Second) {
		t.Error("mitmdump not killed: told again, it would get the hosts without the rules")
	}
}

// Discovery turned on while a mitmdump starts (after its arguments were
// made, before its control socket is up) is told at its hello; status says
// it on only once mitmproxy acknowledged it.
func TestDiscoverDuringStartup(t *testing.T) {
	ctx := context.Background()
	c := scopeCapture(t, rulesOf(t, "a.example.com")) // started with discovery off, no control socket yet
	if _, _, err := c.SetDiscover(ctx, "capture discover --for 1h", time.Hour); !errors.Is(err, ErrPending) || !c.DiscoverUntil().IsZero() || c.DiscoverAsked().IsZero() {
		t.Fatalf("before the control socket: %v, on %v, asked %v", err, c.DiscoverUntil(), c.DiscoverAsked())
	}
	var silent atomic.Bool
	ops := fakeControl(t, c.cfg.Dir, ackUnless(&silent))
	c.Store.Apply(fmt.Appendf(nil, `{"v":%d,"ev":"hello","instance":"inst-1","gen":0}`, wireVersion))
	c.syncScope(ctx)
	if got := ops(); len(got) != 1 || got[0]["op"] != "discover" || got[0]["on"] != true || c.DiscoverUntil().IsZero() {
		t.Errorf("after the hello: ops %v, on %v", got, c.DiscoverUntil())
	}
}
