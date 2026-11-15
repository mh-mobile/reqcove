package capture

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"
)

// Discovery (reqcove capture discover --for D): for a while, the addon tells
// the names of the hosts outside the scope the devices reach (the SNI of a
// TLS connection mitmproxy does not decrypt, the Host of a request on a
// decrypted connection that is not recorded), and the Store counts them:
// never content, a URL path or a time. Off by default; never in a file, so a
// restart of run ends it. It is apart from the scope: no generation, no
// pending state. The Store's gate fails closed: at the end it takes no name
// more, whether mitmproxy was told or not.

// MaxDiscover bounds SetDiscover's d, as MaxAllowAll bounds allow-all's.
const MaxDiscover = MaxAllowAll

// maxSeenHosts bounds the names kept; past it, a new name takes the place of
// the least seen one.
const maxSeenHosts = 1000

// SeenHost is a name seen outside the scope while discovery was on: Count
// TLS connections (by SNI) and requests (by Host).
type SeenHost struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// SetDiscover turns discovery on until now+d (on already: its end moves;
// was is the end before). A new start begins a new list of names. The Store
// first, then mitmproxy: ErrPending while it has not answered (told again at
// its hello and every few seconds: syncScope, retryPending; a restarted
// mitmdump starts with it on, until its end: mitmArgs). ErrUnchanged for a
// base of "*": no host is outside it.
func (c *Capture) SetDiscover(ctx context.Context, why string, d time.Duration) (until, was time.Time, err error) {
	if d <= 0 || d > MaxDiscover {
		return time.Time{}, time.Time{}, fmt.Errorf("discovery lasts more than 0 and at most %v, not %v", MaxDiscover, d)
	}
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	if c.want.All {
		return time.Time{}, time.Time{}, ErrUnchanged
	}
	until, was = time.Now().Add(d), c.discUntil
	c.discUntil = until
	c.Store.setDiscover(until, was.IsZero())
	c.NoteChange(why)
	if was.IsZero() || !c.discAcked() {
		err = c.discoverOp(ctx, true)
		c.setDiscAck(err == nil)
	}
	return until, was, err
}

// DiscoverUntil is when discovery ends; zero when off, or not acknowledged by
// mitmproxy (DiscoverAsked). The Store's copy: status never waits for a
// change that waits for mitmdump.
func (c *Capture) DiscoverUntil() time.Time {
	if !c.discAcked() {
		return time.Time{}
	}
	return c.DiscoverAsked()
}

// DiscoverAsked is when the discovery asked for ends, acknowledged or not;
// zero when off.
func (c *Capture) DiscoverAsked() time.Time {
	c.Store.mu.Lock()
	defer c.Store.mu.Unlock()
	return c.Store.discUntil
}

func (c *Capture) discAcked() bool {
	c.ackMu.Lock()
	defer c.ackMu.Unlock()
	return c.discAck
}

func (c *Capture) setDiscAck(on bool) {
	c.ackMu.Lock()
	c.discAck = on
	c.ackMu.Unlock()
}

// EndDiscover ends discovery now, as its time running out does (expire):
// ErrUnchanged when off; ErrPending when mitmproxy was not told (the Store
// takes no name more all the same).
func (c *Capture) EndDiscover(ctx context.Context, why string) error {
	c.scopeMu.Lock()
	defer c.scopeMu.Unlock()
	if c.discUntil.IsZero() {
		return ErrUnchanged
	}
	return c.endDiscoverLocked(ctx, why)
}

func (c *Capture) endDiscoverLocked(ctx context.Context, why string) error {
	c.discUntil = time.Time{}
	c.Store.setDiscover(time.Time{}, false) // first: a name told late is not taken
	c.setDiscAck(false)
	c.NoteChange(why)
	return c.discoverOp(ctx, false)
}

// discoverOp tells mitmdump discovery is on or off. Called with scopeMu held.
func (c *Capture) discoverOp(ctx context.Context, on bool) error {
	var ack struct {
		OK bool `json:"ok"`
	}
	if err := c.control(ctx, map[string]any{"op": "discover", "on": on}, &ack); err != nil || !ack.OK {
		return fmt.Errorf("mitmproxy did not answer (restarting?): %w", ErrPending)
	}
	return nil
}

// due: an end at t has come, by the monotonic reading of mono or by the wall
// clock (wall), whichever first (see expire).
func due(t, mono, wall time.Time) bool {
	return !mono.Before(t) || !wall.Round(0).Before(t.Round(0))
}

// setDiscover opens the gate of names until until, or shuts it (zero);
// fresh empties the list.
func (s *Store) setDiscover(until time.Time, fresh bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.discUntil = until
	if fresh {
		s.seen = map[string]int{}
	}
}

// seenHostLocked counts a name the addon saw outside the scope, while the
// gate is open: a valid host's, none of Apple's nor mitm.it, masked as other
// hosts are. Called with s.mu held.
func (s *Store) seenHostLocked(raw string) {
	h := normHost(raw)
	if s.discUntil.IsZero() || !ValidHost(h) || h == "mitm.it" || AppleIgnored(h) {
		return
	}
	h = s.mask(h)
	if _, ok := s.seen[h]; !ok && len(s.seen) >= maxSeenHosts {
		// ponytail: a scan of 1,000 for each name past the bound; a heap if the bound grows.
		least := ""
		for k, n := range s.seen {
			if least == "" || n < s.seen[least] || n == s.seen[least] && k > least {
				least = k
			}
		}
		delete(s.seen, least)
	}
	s.seen[h]++
}

// SeenHosts are the names discovery kept, most seen first (then by name),
// but those in says are in the scope: a name added since is no longer
// outside it.
func (s *Store) SeenHosts(in func(host string) bool) []SeenHost {
	s.mu.Lock()
	defer s.mu.Unlock()
	var hs []SeenHost
	for h, n := range s.seen {
		if !in(h) {
			hs = append(hs, SeenHost{h, n})
		}
	}
	slices.SortFunc(hs, func(a, b SeenHost) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Host, b.Host))
	})
	return hs
}
