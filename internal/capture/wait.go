package capture

import (
	"context"
	"sort"
)

// answerLocked marks f answered (its response, or its error) the first time,
// with the next seq, and wakes the waiters.
func (s *Store) answerLocked(f *Flow) {
	if f.answered != 0 {
		return
	}
	s.seq++
	f.answered = s.seq
	if s.wake != nil {
		close(s.wake)
		s.wake = nil
	}
}

// Checkpoint is a cursor for Wait: flows answered after it is taken come
// after it. Take it before acting (a tap on the device), not after.
func (s *Store) Checkpoint() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// WaitResult is what Wait found.
type WaitResult struct {
	Flows []Summary
	// After is the cursor for the next Wait: the last flow's answer, or the
	// one given when none came.
	After int64
	// Evicted: flows answered after the cursor given were evicted before they
	// could be returned (they may or may not have matched).
	Evicted bool
}

// Wait returns the flows matching q (q.Query and q.Before are ignored)
// answered after cursor after, oldest answer first, at most q.Limit; it
// waits for one until ctx ends, and then returns none. With none to give
// but flows evicted after the cursor, it returns at once, Evicted set and
// After past the loss. Each flow comes once
// over successive calls that pass back After, even when flows are answered
// out of the order they arrived; one never answered holds nothing up. A flow
// may still be open when returned (its body streaming, as SSE's).
func (s *Store) Wait(ctx context.Context, q Filter, after int64) WaitResult {
	q.Query, q.Before = "", 0
	for {
		s.mu.Lock()
		// ponytail: a scan of every kept flow (at most maxFlows) per wake; an
		// index by answered if waits get many.
		var found []*Flow
		for _, id := range s.order {
			if f := s.flows[id]; f.answered > after && q.match(f, s.names[f.Device]) {
				found = append(found, f)
			}
		}
		r := WaitResult{After: after, Evicted: s.evictedMark > after}
		if len(found) > 0 {
			sort.Slice(found, func(i, j int) bool { return found[i].answered < found[j].answered })
			if q.Limit > 0 && len(found) > q.Limit {
				found = found[:q.Limit]
			}
			for _, f := range found {
				r.Flows = append(r.Flows, s.summary(f))
			}
			r.After = found[len(found)-1].answered
			s.mu.Unlock()
			return r
		}
		if r.Evicted {
			// Nothing to give, but some may have been lost: say so now, and
			// move past the loss so the next call does not say it again.
			r.After = s.evictedMark
			s.mu.Unlock()
			return r
		}
		if s.wake == nil {
			s.wake = make(chan struct{})
		}
		wake := s.wake
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return r
		case <-wake:
		}
	}
}
