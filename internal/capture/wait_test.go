package capture

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"
)

func ev(s *Store, kind, id string, extra string) {
	s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":%q,"id":%q,"device":"d","host":"a.example","url":"https://a.example/%s"%s}`, kind, id, id, extra)))
}

func ids(r WaitResult) []string {
	var out []string
	for _, f := range r.Flows {
		out = append(out, f.ID)
	}
	return out
}

func waitNow(s *Store, q Filter, after int64) WaitResult {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	return s.Wait(ctx, q, after)
}

// TestWaitOrder: flows come in the order they were answered, each once, with
// a limit of one too; one never answered (a, open) holds nothing up, and an
// SSE stream (b: a status, still open) and a failure with no status (d) count.
func TestWaitOrder(t *testing.T) {
	s := NewStore(100, 1<<20)
	cp := s.Checkpoint()
	if s.OldCursor(cp) {
		t.Fatal("an empty store's checkpoint is taken for an earlier run's")
	}
	for _, id := range []string{"a", "b", "c", "d"} {
		ev(s, "request", id, "")
	}
	ev(s, "response", "c", `,"status":200`)
	ev(s, "done", "c", "")
	ev(s, "response", "b", `,"status":200`) // SSE: no done
	ev(s, "error", "d", `,"msg":"connection refused"`)

	var got []string
	after := cp
	for range 5 {
		r := waitNow(s, Filter{Limit: 1}, after)
		if len(r.Flows) == 0 {
			break
		}
		got, after = append(got, ids(r)...), r.After
	}
	if fmt.Sprint(got) != "[c b d]" {
		t.Errorf("one at a time: %v, want [c b d]", got)
	}
	if r := waitNow(s, Filter{}, cp); fmt.Sprint(ids(r)) != "[c b d]" || r.After != after {
		t.Errorf("all at once: %v after %d, want [c b d] after %d", ids(r), r.After, after)
	}
	// b's done and body later do not bring it back; a's answer does.
	ev(s, "done", "b", "")
	ev(s, "response", "a", `,"status":500`)
	if r := waitNow(s, Filter{}, after); fmt.Sprint(ids(r)) != "[a]" {
		t.Errorf("after a's answer: %v", ids(r))
	}
	// Filters apply: status, method.
	if r := waitNow(s, Filter{Status: "5xx"}, cp); fmt.Sprint(ids(r)) != "[a]" {
		t.Errorf("status 5xx: %v", ids(r))
	}
}

// TestWaitWakes: a waiter returns when a flow is answered, also by mitmdump
// exiting; it returns nothing, with the cursor it was given, when its context
// ends; and leaves no goroutine behind.
func TestWaitWakes(t *testing.T) {
	s := NewStore(100, 1<<20)
	cp := s.Checkpoint()
	ev(s, "request", "x", "")
	got := make(chan WaitResult)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		got <- s.Wait(ctx, Filter{}, cp)
	}()
	time.Sleep(20 * time.Millisecond)
	ev(s, "response", "x", `,"status":204`)
	select {
	case r := <-got:
		if fmt.Sprint(ids(r)) != "[x]" {
			t.Errorf("woken with %v", ids(r))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("not woken by the response")
	}

	cp = s.Checkpoint()
	ev(s, "request", "y", "")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		got <- s.Wait(ctx, Filter{}, cp)
	}()
	time.Sleep(20 * time.Millisecond)
	s.mitmdumpExited("mitmdump exited")
	if r := <-got; fmt.Sprint(ids(r)) != "[y]" {
		t.Errorf("after mitmdump exited: %v", ids(r))
	}

	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan WaitResult)
	cp = s.Checkpoint()
	go func() { done <- s.Wait(ctx, Filter{}, cp) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if r := <-done; len(r.Flows) != 0 || r.After != cp {
		t.Errorf("cancelled: %v after %d, want none after %d", ids(r), r.After, cp)
	}
	time.Sleep(20 * time.Millisecond)
	if n := runtime.NumGoroutine(); n > before {
		t.Errorf("goroutines: %d after, %d before", n, before)
	}
}

// TestWaitEvicted: a flow answered after the cursor but evicted before the
// wait read it is reported as a possible gap.
func TestWaitEvicted(t *testing.T) {
	s := NewStore(2, 1<<20)
	cp := s.Checkpoint()
	for _, id := range []string{"a", "b", "c"} {
		ev(s, "request", id, "")
		ev(s, "response", id, `,"status":200`)
	}
	r := waitNow(s, Filter{}, cp)
	if !r.Evicted || fmt.Sprint(ids(r)) != "[b c]" {
		t.Errorf("evicted %v, flows %v", r.Evicted, ids(r))
	}
	if r := waitNow(s, Filter{}, r.After); r.Evicted {
		t.Error("a gap reported after the eviction was passed")
	}
}

// TestWaitEvictedOpen: a flow still open when evicted, answered later, is
// reported as a possible gap (its answer would have come after the cursor).
func TestWaitEvictedOpen(t *testing.T) {
	s := NewStore(2, 1<<20)
	ev(s, "request", "a", "")
	cp := s.Checkpoint()
	for _, id := range []string{"b", "c"} {
		ev(s, "request", id, "")
	}
	ev(s, "response", "a", `,"status":200`) // a was evicted: an orphan update now
	if r := waitNow(s, Filter{}, cp); !r.Evicted {
		t.Errorf("an open flow evicted after the cursor: evicted %v", r.Evicted)
	}
}
