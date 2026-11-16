package capture

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Live scope changes: the Store's per-event gate and the Capture's order of
// changes, fed lines as the addon sends them and a stand-in for its control
// socket. livescope_test.go has them with real mitmproxy.

func rulesOf(t testing.TB, hosts ...string) HostRules {
	t.Helper()
	r, err := ParseAllowHosts(hosts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func reqLine(id, host string, gen int64) []byte {
	return fmt.Appendf(nil, `{"v":%d,"ev":"request","id":%q,"device":"d","conn":"c1","ts":1,"method":"GET","url":"https://%s/ws","host":%q,"path":"/ws","http_version":"HTTP/1.1","headers":[["host",%q]],"gen":%d}`,
		wireVersion, id, host, host, host, gen)
}

func wsLine(id string) []byte {
	return fmt.Appendf(nil, `{"v":%d,"ev":"ws","id":%q,"from_client":true,"size":2,"text":true,"ts":2,"head":"aGk="}`, wireVersion, id)
}

func wsCount(t *testing.T, s *Store, id string) int {
	t.Helper()
	v, err := s.Get(id, false)
	if err != nil {
		return -1
	}
	return v.WSMessages
}

// TestScopeGate: a removed host's open WebSocket records nothing more and is
// closed with the error, and does not resume when its host is back; a request
// admitted under a generation since narrowed is not recorded, one admitted
// under the current one is.
func TestScopeGate(t *testing.T) {
	s := NewStore(100, 1<<20)
	s.SetScope(rulesOf(t, "a.example.com"), true)
	s.Apply(reqLine("f1", "a.example.com", 0))
	s.Apply(wsLine("f1"))
	s.setScopeGen(1, rulesOf(t, "b.example.com"), "")
	s.Apply(wsLine("f1"))
	v, _ := s.Get("f1", false)
	if v.WSMessages != 1 || v.State != "error" || v.Error != ScopeCut || v.answered == 0 {
		t.Fatalf("after the removal: %d messages, %s %q, answered %d", v.WSMessages, v.State, v.Error, v.answered)
	}
	s.setScopeGen(2, rulesOf(t, "a.example.com", "b.example.com"), "")
	s.Apply(wsLine("f1"))
	if n := wsCount(t, s, "f1"); n != 1 {
		t.Errorf("a back: f1 resumed, %d messages", n)
	}
	s.Apply(reqLine("f2", "a.example.com", 0)) // admitted before the removal, read after
	s.Apply(reqLine("f3", "a.example.com", 2))
	if wsCount(t, s, "f2") != -1 || wsCount(t, s, "f3") != 0 {
		t.Errorf("f2 %d (want none), f3 %d (want recorded)", wsCount(t, s, "f2"), wsCount(t, s, "f3"))
	}
}

// TestScopeGateStopStart: a stop (nothing recorded), then a start with the
// same host: what the addon queued before the stop, read only after the start,
// is not recorded, though the host is in scope again: a flow's messages, a new
// request, a TLS failure.
func TestScopeGateStopStart(t *testing.T) {
	s := NewStore(100, 1<<20)
	s.SetScope(rulesOf(t, "a.example.com"), true)
	s.Apply(reqLine("f1", "a.example.com", 0))
	s.Apply(wsLine("f1"))
	s.setScopeGen(1, HostRules{}, "")
	s.setScopeGen(2, rulesOf(t, "a.example.com"), "")
	s.Apply(wsLine("f1"))
	s.Apply(reqLine("f2", "a.example.com", 0))
	s.Apply(fmt.Appendf(nil, `{"v":%d,"ev":"tls_failed","conn":"c9","ts":1,"sni":"a.example.com","msg":"x","gen":0}`, wireVersion))
	if n := wsCount(t, s, "f1"); n != 1 {
		t.Errorf("f1: %d messages, want the one before the stop", n)
	}
	if wsCount(t, s, "f2") != -1 {
		t.Error("f2, admitted before the stop, recorded after the start")
	}
	if n := len(s.TLSFailures(Filter{})); n != 0 {
		t.Errorf("%d TLS failures from before the stop", n)
	}
}

// TestScopeGateMemo: an event checks only the changes since the flow's last
// event (its memo moves to the newest generation), but every one of them: a
// host taken out and put back between two events is cut.
func TestScopeGateMemo(t *testing.T) {
	s := NewStore(100, 1<<20)
	s.SetScope(rulesOf(t, "a.example.com"), true)
	s.Apply(reqLine("f1", "a.example.com", 0))
	s.setScopeGen(1, rulesOf(t, "a.example.com", "b.example.com"), "")
	s.Apply(wsLine("f1"))
	if f := s.flows["f1"]; f.checked != 1 || wsCount(t, s, "f1") != 1 {
		t.Fatalf("memo %d, %d messages", f.checked, wsCount(t, s, "f1"))
	}
	s.setScopeGen(2, rulesOf(t, "b.example.com"), "")
	s.setScopeGen(3, rulesOf(t, "a.example.com"), "")
	s.Apply(wsLine("f1"))
	if n := wsCount(t, s, "f1"); n != 1 || !s.flows["f1"].cut {
		t.Errorf("a out and back between two events: %d messages, cut %v", n, s.flows["f1"].cut)
	}
}

// TestScopeGateMaskedHost: a host label shaped like a token is masked in
// Flow.Host; the gate judges the host as sent, so a change that keeps it does
// not cut its flow.
func TestScopeGateMaskedHost(t *testing.T) {
	host := "s" + "k-" + strings.Repeat("abcdefghij", 3) + "012345.example.com" // built here: no token in the source
	s := NewStore(100, 1<<20)
	if s.mask(host) == host {
		t.Fatalf("masking no longer changes %s: pick another host", host)
	}
	s.SetScope(rulesOf(t, host), true)
	s.Apply(reqLine("f", host, 0))
	s.setScopeGen(1, rulesOf(t, host, "b.example.com"), "")
	s.Apply(wsLine("f"))
	v, _ := s.Get("f", false)
	if v.WSMessages != 1 || v.State != "open" || strings.Contains(v.Host, "abcdefghij") {
		t.Errorf("host %q: %d messages, %s %q", v.Host, v.WSMessages, v.State, v.Error)
	}
}

func TestNarrows(t *testing.T) {
	pass := func(r HostRules, p ...string) HostRules {
		r, err := r.WithPass(p)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	a, ab := rulesOf(t, "a.example.com"), rulesOf(t, "a.example.com", "b.example.com")
	for _, c := range []struct {
		name     string
		old, new HostRules
		want     bool
	}{
		{"add", a, ab, false},
		{"remove", ab, a, true},
		{"swap", a, rulesOf(t, "b.example.com"), true},
		{"to all", a, rulesOf(t, "*"), false},
		{"from all", rulesOf(t, "*"), ab, true},
		{"stop", a, HostRules{}, true},
		{"start", HostRules{}, a, false},
		{"pass added", ab, pass(ab, "b.example.com"), true},
		{"pass removed", pass(ab, "b.example.com"), ab, false},
	} {
		if got := narrows(c.old, c.new); got != c.want {
			t.Errorf("%s: narrows %v, want %v", c.name, got, c.want)
		}
	}
}

// fakeControl answers the control socket's scope ops as the addon would,
// with answer (nil: no answer); ops returns the ops it was sent.
func fakeControl(t *testing.T, dir string, answer func(op map[string]any) map[string]any) (ops func() []map[string]any) {
	t.Helper()
	ln, err := net.Listen("unix", filepath.Join(dir, ControlSock))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got []map[string]any
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(conn).ReadBytes('\n')
			var op map[string]any
			json.Unmarshal(line, &op)
			mu.Lock()
			got = append(got, op)
			out := answer(op)
			mu.Unlock()
			if out != nil {
				b, _ := json.Marshal(out)
				conn.Write(append(b, '\n'))
			}
			conn.Close()
		}
	}()
	return func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
}

func scopeCapture(t *testing.T, r HostRules) *Capture {
	dir, err := os.MkdirTemp("/tmp", "rcvs-") // short: a socket path
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	c := &Capture{Store: NewStore(100, 1<<20), cfg: Config{Dir: dir, Logf: t.Logf}, want: r, acked: r, instance: "inst-1"}
	c.Store.SetScope(r, true)
	return c
}

// TestSetScopeOrder: the addon checks first, and a refusal changes nothing;
// narrowing reaches the Store before the addon, even unacknowledged; widening
// reaches it only once the addon acknowledged; an answer naming another
// mitmdump or generation is not taken; status (Scope) shows what is
// acknowledged, ScopePending the rest; a new mitmdump's arguments carry the
// scope asked for last and its generation.
func TestSetScopeOrder(t *testing.T) {
	ctx := context.Background()
	a, ab := rulesOf(t, "a.example.com"), rulesOf(t, "a.example.com", "b.example.com")
	c := scopeCapture(t, a)
	var mode atomic.Value
	ops := fakeControl(t, c.cfg.Dir, func(op map[string]any) map[string]any {
		switch {
		case mode.Load() == "refuse":
			return map[string]any{"error": "mock[0]: a.example.com is not in the new scope"}
		case op["check"] == true:
			return map[string]any{"ok": true}
		case mode.Load() == "refuse-apply": // the rules changed since the check: this apply refused, the next taken
			mode.Store("ok")
			return map[string]any{"error": "mock[0]: a.example.com is not in the new scope"}
		case mode.Load() == "silent":
			return nil
		case mode.Load() == "other":
			return map[string]any{"ok": true, "gen": op["gen"], "instance": "inst-0"}
		}
		return map[string]any{"ok": true, "gen": op["gen"], "instance": "inst-1"}
	})
	storeHas := func(host string) bool {
		return c.Store.inScopeSince(c.Store.topGen(), func(r HostRules) bool { return r.Match(host) })
	}

	mode.Store("refuse")
	if err := c.SetScope(ctx, rulesOf(t, "b.example.com")); err == nil || !strings.Contains(err.Error(), "mock[0]") {
		t.Fatalf("refused: %v", err)
	}
	if len(ops()) != 1 || ops()[0]["check"] != true || c.wantGen != 0 || !storeHas("a.example.com") || c.ScopePending() != "" {
		t.Fatalf("a refusal changed something: ops %v, gen %d", ops(), c.wantGen)
	}

	mode.Store("silent") // widening, unacknowledged: the Store waits
	if err := c.SetScope(ctx, ab); err == nil {
		t.Fatal("no answer, no error")
	}
	if storeHas("b.example.com") || c.ScopePending() != PendingAsked || slices.Contains(c.Scope().Hosts, "b.example.com") {
		t.Errorf("widening before the ack: store b %v, pending %q, scope %v", storeHas("b.example.com"), c.ScopePending(), c.Scope().Hosts)
	}
	if args := strings.Join(c.mitmArgs(), " "); !strings.Contains(args, `b\.example\.com`) || !strings.Contains(args, "reqcove_scope_gen=1") {
		t.Errorf("a new mitmdump's args miss the change: %s", args)
	}

	mode.Store("other") // acknowledged by another mitmdump: not taken
	c.SetScope(ctx, ab)
	if storeHas("b.example.com") || c.ScopePending() == "" {
		t.Error("another mitmdump's answer taken")
	}

	mode.Store("ok")
	if err := c.SetScope(ctx, ab); err != nil {
		t.Fatal(err)
	}
	if !storeHas("b.example.com") || c.ScopePending() != "" || !slices.Equal(c.Scope().Hosts, ab.Hosts) {
		t.Errorf("acknowledged: store b %v, pending %q, scope %v", storeHas("b.example.com"), c.ScopePending(), c.Scope().Hosts)
	}

	// Checked, then refused at the apply: back to ab, at a newer generation,
	// in the Store, mitmdump and a new mitmdump's args (else a restart would
	// load rules against a scope they refuse, and fail for good).
	mode.Store("refuse-apply")
	if err := c.SetScope(ctx, rulesOf(t, "b.example.com")); err == nil || !strings.Contains(err.Error(), "mock[0]") {
		t.Fatalf("refused at the apply: %v", err)
	}
	args := strings.Join(c.mitmArgs(), " ")
	if !storeHas("a.example.com") || c.ScopePending() != "" || !slices.Equal(c.Scope().Hosts, ab.Hosts) || !strings.Contains(args, `a\.example\.com`) ||
		!strings.Contains(args, fmt.Sprintf("reqcove_scope_gen=%d", c.wantGen)) || c.Store.topGen() != c.wantGen || ops()[len(ops())-1]["gen"] != float64(c.wantGen) {
		t.Errorf("after the refusal: store a %v, pending %q, scope %v, gen %d, store's %d, args %s", storeHas("a.example.com"), c.ScopePending(), c.Scope().Hosts, c.wantGen, c.Store.topGen(), args)
	}

	mode.Store("silent") // narrowing, unacknowledged: the Store first all the same
	if err := c.SetScope(ctx, rulesOf(t, "b.example.com")); err == nil {
		t.Fatal("no answer, no error")
	}
	if storeHas("a.example.com") || c.ScopePending() != PendingNarrowed || !slices.Equal(c.Scope().Hosts, ab.Hosts) {
		t.Errorf("narrowing before the ack: store a %v, pending %q, scope %v", storeHas("a.example.com"), c.ScopePending(), c.Scope().Hosts)
	}

	// A new mitmdump says hello with an older generation: told again.
	mode.Store("ok")
	c.Store.Apply(fmt.Appendf(nil, `{"v":%d,"ev":"hello","instance":"inst-1","gen":1}`, wireVersion))
	c.syncScope(ctx)
	if c.ScopePending() != "" || !slices.Equal(c.Scope().Hosts, []string{"b.example.com"}) || ops()[len(ops())-1]["gen"] != float64(c.wantGen) {
		t.Errorf("after the hello: pending %q, scope %v, last op %v", c.ScopePending(), c.Scope().Hosts, ops()[len(ops())-1])
	}
}

// TestStoppedArgs: while stopped, mitmproxy decrypts mitm.it alone (never an
// empty allow_hosts, which decrypts everything), with "*" as the base too; the
// addon keeps the base (its rules are checked against it) and the generation.
// A stop narrows the Store first, unacknowledged too; a start reaches it once
// acknowledged; a change while stopped changes the base only.
func TestStoppedArgs(t *testing.T) {
	ctx := context.Background()
	mitmIt := `^mitm\.it(:\d+)?$`
	base, err := rulesOf(t, "a.example.com", "b.example.com").WithPass([]string{"b.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []HostRules{base, rulesOf(t, "*")} {
		c := scopeCapture(t, r)
		c.stopped, c.wantGen = true, 7
		args := c.mitmArgs()
		var allow []string
		for i, a := range args {
			if a == "--allow-hosts" {
				allow = append(allow, args[i+1])
			}
		}
		joined := strings.Join(args, " ")
		if !slices.Equal(allow, []string{mitmIt}) || !strings.Contains(joined, "reqcove_stopped=true") || !strings.Contains(joined, "reqcove_scope_gen=7") {
			t.Errorf("%v stopped: --allow-hosts %q, args %s", r.Hosts, allow, joined)
		}
		hosts, _ := json.Marshal(addonHosts(r))
		if !slices.Contains(args, "reqcove_allow_hosts="+string(hosts)) {
			t.Errorf("%v stopped: the addon is not given the base: %s", r.Hosts, joined)
		}
		if op := scopeOp(r, 7, false, true, false); !slices.Equal(op["allow_hosts"].([]string), []string{mitmIt}) || op["stopped"] != true {
			t.Errorf("%v stopped: the op %v", r.Hosts, op)
		}
	}

	c := scopeCapture(t, base)
	var mode atomic.Value
	mode.Store("silent")
	fakeControl(t, c.cfg.Dir, func(op map[string]any) map[string]any {
		if mode.Load() == "silent" {
			return nil
		}
		return map[string]any{"ok": true, "gen": op["gen"], "instance": "inst-1"}
	})
	storeHas := func(host string) bool {
		return c.Store.inScopeSince(c.Store.topGen(), func(r HostRules) bool { return r.Match(host) })
	}
	if _, err := c.SetStopped(ctx, "capture stop", true); !errors.Is(err, ErrPending) {
		t.Fatalf("stop, mitmproxy silent: %v, want pending", err)
	}
	if storeHas("a.example.com") || !c.Store.Stopped() || c.Stopped() || c.ScopePending() != PendingNarrowed || !strings.Contains(strings.Join(c.mitmArgs(), " "), "reqcove_stopped=true") {
		t.Errorf("stop before the ack: store a %v, store stopped %v, status stopped %v, pending %q", storeHas("a.example.com"), c.Store.Stopped(), c.Stopped(), c.ScopePending())
	}
	mode.Store("ok")
	if _, err := c.SetStopped(ctx, "capture stop", true); !errors.Is(err, ErrUnchanged) {
		t.Errorf("stop again: %v", err)
	}
	c.Store.Apply(fmt.Appendf(nil, `{"v":%d,"ev":"hello","instance":"inst-1","gen":0}`, wireVersion))
	c.syncScope(ctx) // a new mitmdump: told
	if !c.Stopped() || c.ScopePending() != "" {
		t.Errorf("after the hello: stopped %v, pending %q", c.Stopped(), c.ScopePending())
	}
	var saw bool
	if err := c.ChangeScope(ctx, "capture add c.example.com", func(r HostRules, rec string) (HostRules, error) {
		saw = rec == RecordingStopped
		return rulesOf(t, "a.example.com", "c.example.com"), nil
	}); err != nil || !saw {
		t.Fatalf("add while stopped: %v, told stopped %v", err, saw)
	}
	if storeHas("c.example.com") || !c.Stopped() || !slices.Equal(c.Scope().Hosts, []string{"a.example.com", "c.example.com"}) {
		t.Errorf("add while stopped: store c %v, stopped %v, base %v", storeHas("c.example.com"), c.Stopped(), c.Scope().Hosts)
	}
	if b, err := c.SetStopped(ctx, "capture start", false); err != nil || !slices.Equal(b.Hosts, []string{"a.example.com", "c.example.com"}) {
		t.Fatalf("start: %v %v", b.Hosts, err)
	}
	if !storeHas("c.example.com") || c.Store.Stopped() || c.Stopped() || strings.Contains(strings.Join(c.mitmArgs(), " "), "reqcove_stopped") {
		t.Errorf("started: store c %v, stopped %v %v", storeHas("c.example.com"), c.Store.Stopped(), c.Stopped())
	}
}

// allowHostsArgs is mitmArgs' --allow-hosts values.
func allowHostsArgs(args []string) []string {
	var allow []string
	for i, a := range args {
		if a == "--allow-hosts" {
			allow = append(allow, args[i+1])
		}
	}
	return allow
}

// TestAllowAll: during allow-all mitmproxy decrypts everything (no
// --allow-hosts: an empty allow_hosts), the addon keeps the base (its rules
// are checked against it) and the base's --pass-hosts still pass; the Store
// takes every host once acknowledged. Stopped, it is refused; add changes the
// base only (f is told allow-all); a stop ends it; at most 24h.
func TestAllowAll(t *testing.T) {
	ctx := context.Background()
	base, err := rulesOf(t, "a.example.com", "b.example.com").WithPass([]string{"b.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	c := scopeCapture(t, base)
	var mode atomic.Value
	mode.Store("ok")
	ops := fakeControl(t, c.cfg.Dir, func(op map[string]any) map[string]any {
		if mode.Load() == "silent" {
			return nil
		}
		return map[string]any{"ok": true, "gen": op["gen"], "instance": "inst-1"}
	})
	storeHas := func(host string) bool {
		return c.Store.inScopeSince(c.Store.topGen(), func(r HostRules) bool { return r.Match(host) })
	}
	for _, d := range []time.Duration{0, -time.Minute, MaxAllowAll + time.Second} {
		if _, _, err := c.SetAllowAll(ctx, "x", d); err == nil || c.allOn() {
			t.Errorf("allow-all for %v: taken", d)
		}
	}

	mode.Store("silent") // a widening: the Store waits for the ack
	if _, _, err := c.SetAllowAll(ctx, "capture allow-all --for 30m", 30*time.Minute); !errors.Is(err, ErrPending) || storeHas("other.example.net") || !c.AllowAllUntil().IsZero() {
		t.Errorf("allow-all, mitmproxy silent: %v, store other %v, acked %v", err, storeHas("other.example.net"), c.AllowAllUntil())
	}
	args := c.mitmArgs()
	hosts, _ := json.Marshal(addonHosts(base))
	if len(allowHostsArgs(args)) != 0 || !slices.Contains(args, "reqcove_allow_all=true") || !slices.Contains(args, "reqcove_allow_hosts="+string(hosts)) {
		t.Errorf("a new mitmdump's args during allow-all: %q", args)
	}
	if op := ops()[len(ops())-1]; fmt.Sprint(op["allow_hosts"]) != "[]" || op["allow_all"] != true || op["check"] != false {
		t.Errorf("the op: %v", op)
	}

	mode.Store("ok")
	until, was, err := c.SetAllowAll(ctx, "capture allow-all --for 1h", time.Hour) // on already: its end moves
	if err != nil || was.IsZero() || time.Until(was) > 31*time.Minute || time.Until(until) < 59*time.Minute {
		t.Errorf("again: %v, was %v, until %v", err, was, until)
	}
	c.Store.Apply(fmt.Appendf(nil, `{"v":%d,"ev":"hello","instance":"inst-1","gen":0}`, wireVersion))
	c.syncScope(ctx)
	if !storeHas("other.example.net") || storeHas("b.example.com") || !c.Recorded().All || !c.AllowAllUntil().Equal(until) || c.Store.Stats()["recording"] != RecordingAllowAll {
		t.Errorf("acknowledged: store other %v, store b (passed) %v, recorded %v, until %v, stats %v", storeHas("other.example.net"), storeHas("b.example.com"), c.Recorded().Hosts, c.AllowAllUntil(), c.Store.Stats()["recording"])
	}

	var told string
	if err := c.ChangeScope(ctx, "capture add c.example.com", func(r HostRules, rec string) (HostRules, error) {
		told = rec
		return rulesOf(t, "a.example.com", "c.example.com"), nil
	}); err != nil || told != RecordingAllowAll {
		t.Fatalf("add during allow-all: %v, told %q", err, told)
	}
	if !c.allOn() || !storeHas("other.example.net") || !slices.Equal(c.Scope().Hosts, []string{"a.example.com", "c.example.com"}) {
		t.Errorf("add during allow-all: on %v, store other %v, base %v", c.allOn(), storeHas("other.example.net"), c.Scope().Hosts)
	}

	if _, err := c.SetStopped(ctx, "capture stop", true); err != nil {
		t.Fatal(err)
	}
	if c.allOn() || !c.AllowAllUntil().IsZero() || storeHas("other.example.net") || storeHas("a.example.com") || slices.Contains(c.mitmArgs(), "reqcove_allow_all=true") {
		t.Errorf("a stop did not end allow-all: on %v, acked %v", c.allOn(), c.AllowAllUntil())
	}
	if _, _, err := c.SetAllowAll(ctx, "x", time.Hour); !errors.Is(err, ErrStopped) || c.allOn() {
		t.Errorf("allow-all while stopped: %v", err)
	}
	if err := c.EndAllowAll(ctx, "x"); !errors.Is(err, ErrUnchanged) {
		t.Errorf("end while off: %v", err)
	}
	if _, _, err := scopeCapture(t, rulesOf(t, "*")).SetAllowAll(ctx, "x", time.Hour); !errors.Is(err, ErrUnchanged) {
		t.Errorf(`allow-all with "*": %v`, err)
	}
}

// TestAllowAllExpiry: allow-all ends when the monotonic clock or the wall
// clock reaches its end, whichever first (a sleep stops the first; the
// second can be set back), and fails closed: with mitmproxy silent the Store
// narrows all the same and the mitmdump is killed (the next one starts
// without allow-all); the records made meanwhile stay, counted outside the
// base.
func TestAllowAllExpiry(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name   string
		mono   time.Duration // from the end, by the monotonic clock
		wall   time.Duration // by the wall clock
		expire bool
	}{
		{"before", -time.Second, -time.Second, false},
		{"monotonic", 0, -time.Hour, true},            // the wall clock set back an hour
		{"wall clock", -time.Hour, time.Second, true}, // an hour asleep: the monotonic clock behind
	} {
		cp := scopeCapture(t, rulesOf(t, "a.example.com"))
		var mode atomic.Value
		mode.Store("ok")
		fakeControl(t, cp.cfg.Dir, func(op map[string]any) map[string]any {
			if mode.Load() == "silent" {
				return nil
			}
			return map[string]any{"ok": true, "gen": op["gen"], "instance": "inst-1"}
		})
		until, _, err := cp.SetAllowAll(ctx, "capture allow-all --for 30m", 30*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		cp.Store.Apply(reqLine("f1", "other.example.net", cp.wantGen))
		sleep := exec.Command("sleep", "60") // the mitmdump
		sleep.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := sleep.Start(); err != nil {
			t.Fatal(err)
		}
		p := &proc{cmd: sleep, done: make(chan struct{})}
		go func() { p.err = sleep.Wait(); close(p.done) }()
		t.Cleanup(func() { syscall.Kill(-sleep.Process.Pid, syscall.SIGKILL) })
		cp.proc = p

		mode.Store("silent")
		cp.expire(ctx, until.Add(c.mono), until.Round(0).Add(c.wall))
		storeHas := cp.Store.inScopeSince(cp.Store.topGen(), func(r HostRules) bool { return r.Match("other.example.net") })
		if !c.expire {
			if !cp.allOn() || !storeHas {
				t.Errorf("%s: ended", c.name)
			}
			continue
		}
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			t.Errorf("%s: mitmdump not killed", c.name)
		}
		if cp.allOn() || storeHas || cp.ScopePending() != PendingNarrowed || slices.Contains(cp.mitmArgs(), "reqcove_allow_all=true") {
			t.Errorf("%s: on %v, store other %v, pending %q", c.name, cp.allOn(), storeHas, cp.ScopePending())
		}
		if _, err := cp.Store.Get("f1", false); err != nil || cp.Store.OutsideScope(cp.Base()) != 1 {
			t.Errorf("%s: allow-all's record not kept (%v), outside %d", c.name, err, cp.Store.OutsideScope(cp.Base()))
		}
		if _, why := cp.LastChange(); why != "allow-all ended: its time is up" {
			t.Errorf("%s: last change %q", c.name, why)
		}
	}
}
