package capture

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

func seenLine(host string) []byte {
	return fmt.Appendf(nil, `{"v":%d,"ev":"seen","host":%q}`, wireVersion, host)
}

func seenOf(s *Store) map[string]int {
	out := map[string]int{}
	for _, h := range s.SeenHosts(func(string) bool { return false }) {
		out[h.Host] = h.Count
	}
	return out
}

// The Store takes names only while discovery is on, and of them only valid
// host names, none of Apple's nor mitm.it, masked as other hosts are; at most
// maxSeenHosts, a new one taking the least seen's place; listed most seen
// first, those in the scope left out.
func TestSeenHosts(t *testing.T) {
	s := NewStore(100, 1<<20)
	s.Apply(seenLine("off.example.com"))
	if len(seenOf(s)) != 0 {
		t.Errorf("taken while off: %v", seenOf(s))
	}
	if err := SetMaskPolicy(nil, []string{`tok[0-9]{6}`}); err != nil {
		t.Fatal(err)
	}
	defer SetMaskPolicy(nil, nil)
	s.setDiscover(time.Now().Add(time.Hour), true)
	for _, h := range []string{"b.example.com", "A.Example.com.", "a.example.com", "gateway.icloud.com", "mitm.it", "bad host", "$(id).com", "tok123456.example.com"} {
		s.Apply(seenLine(h))
	}
	got := s.SeenHosts(func(h string) bool { return h == "b.example.com" })
	if len(got) != 2 || got[0] != (SeenHost{"a.example.com", 2}) || got[1].Count != 1 || got[1].Host == "tok123456.example.com" {
		t.Errorf("seen: %+v", got)
	}
	for i := range maxSeenHosts + 5 {
		s.Apply(seenLine(fmt.Sprintf("h%d.example.com", i)))
	}
	if m := seenOf(s); len(m) != maxSeenHosts || m["a.example.com"] != 2 {
		t.Errorf("bound: %d kept, a %d", len(m), m["a.example.com"])
	}
	s.setDiscover(time.Time{}, false)
	s.Apply(seenLine("after.example.com"))
	if m := seenOf(s); m["after.example.com"] != 0 || len(m) != maxSeenHosts {
		t.Errorf("after the end: %d kept, after %d", len(m), m["after.example.com"])
	}
}

// TestDiscoverExpiry: discovery ends when the monotonic clock or the wall
// clock reaches its end, whichever first, the Store first: with mitmproxy
// silent, a name told after the end is not taken. A new mitmdump's arguments
// carry it only while on; --for again moves the end and keeps the names, a
// new start empties them.
func TestDiscoverExpiry(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name   string
		mono   time.Duration
		wall   time.Duration
		expire bool
	}{
		{"before", -time.Second, -time.Second, false},
		{"monotonic", 0, -time.Hour, true},
		{"wall clock", -time.Hour, time.Second, true},
	} {
		cp := scopeCapture(t, rulesOf(t, "a.example.com"))
		var silent atomic.Bool
		ops := fakeControl(t, cp.cfg.Dir, func(op map[string]any) map[string]any {
			if silent.Load() {
				return nil
			}
			return map[string]any{"ok": true}
		})
		for _, d := range []time.Duration{0, MaxDiscover + time.Second} {
			if _, _, err := cp.SetDiscover(ctx, "x", d); err == nil || !cp.DiscoverUntil().IsZero() {
				t.Errorf("%s: discover for %v taken", c.name, d)
			}
		}
		until, _, err := cp.SetDiscover(ctx, "capture discover --for 30m", 30*time.Minute)
		if err != nil || !slices.Contains(cp.mitmArgs(), "reqcove_discover=true") || fmt.Sprint(ops()[0]) != "map[on:true op:discover secret:]" {
			t.Fatalf("%s: %v, args %q, ops %v", c.name, err, cp.mitmArgs(), ops())
		}
		cp.Store.Apply(seenLine("o.example.net"))
		if again, was, err := cp.SetDiscover(ctx, "capture discover --for 1h", time.Hour); err != nil || !was.Equal(until) || seenOf(cp.Store)["o.example.net"] != 1 || len(ops()) != 1 {
			t.Errorf("%s: again: %v, was %v, seen %v, ops %d", c.name, err, was, seenOf(cp.Store), len(ops()))
		} else {
			until = again
		}
		silent.Store(true)
		cp.expire(ctx, until.Add(c.mono), until.Round(0).Add(c.wall))
		cp.Store.Apply(seenLine("late.example.net"))
		late := seenOf(cp.Store)["late.example.net"]
		if !c.expire {
			if cp.DiscoverUntil().IsZero() || late != 1 {
				t.Errorf("%s: ended (late %d)", c.name, late)
			}
			continue
		}
		if !cp.DiscoverUntil().IsZero() || late != 0 || slices.Contains(cp.mitmArgs(), "reqcove_discover=true") || seenOf(cp.Store)["o.example.net"] != 1 {
			t.Errorf("%s: on %v, late %d, args %q, kept %v", c.name, cp.DiscoverUntil(), late, cp.mitmArgs(), seenOf(cp.Store))
		}
		if _, why := cp.LastChange(); why != "host discovery ended: its time is up" {
			t.Errorf("%s: last change %q", c.name, why)
		}
		if err := cp.EndDiscover(ctx, "x"); !errors.Is(err, ErrUnchanged) {
			t.Errorf("%s: end while off: %v", c.name, err)
		}
		silent.Store(false)
		if _, _, err := cp.SetDiscover(ctx, "x", time.Minute); err != nil || len(seenOf(cp.Store)) != 0 {
			t.Errorf("%s: a new start: %v, seen %v", c.name, err, seenOf(cp.Store))
		}
	}
	if _, _, err := scopeCapture(t, rulesOf(t, "*")).SetDiscover(ctx, "x", time.Hour); !errors.Is(err, ErrUnchanged) {
		t.Errorf(`discover with "*": %v`, err)
	}
}
