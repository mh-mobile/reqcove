package capture

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
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
	s.setScopeGen(1, rulesOf(t, "b.example.com"))
	s.Apply(wsLine("f1"))
	v, _ := s.Get("f1", false)
	if v.WSMessages != 1 || v.State != "error" || v.Error != ScopeCut || v.answered == 0 {
		t.Fatalf("after the removal: %d messages, %s %q, answered %d", v.WSMessages, v.State, v.Error, v.answered)
	}
	s.setScopeGen(2, rulesOf(t, "a.example.com", "b.example.com"))
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
	s.setScopeGen(1, HostRules{})
	s.setScopeGen(2, rulesOf(t, "a.example.com"))
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
	s.setScopeGen(1, rulesOf(t, "a.example.com", "b.example.com"))
	s.Apply(wsLine("f1"))
	if f := s.flows["f1"]; f.checked != 1 || wsCount(t, s, "f1") != 1 {
		t.Fatalf("memo %d, %d messages", f.checked, wsCount(t, s, "f1"))
	}
	s.setScopeGen(2, rulesOf(t, "b.example.com"))
	s.setScopeGen(3, rulesOf(t, "a.example.com"))
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
	s.setScopeGen(1, rulesOf(t, host, "b.example.com"))
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
