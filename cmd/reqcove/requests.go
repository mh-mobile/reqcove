package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

// Since v1.2 an agent may ask to record more hosts (request_capture_add, a
// tool of `reqcove mcp` alone): run keeps the request, its hosts fixed, until
// the user approves it (`reqcove capture approve ID` in a terminal, or the
// client's dialog), denies it, or it expires. Approved, its hosts are added
// as `reqcove capture add` adds them. In memory only: a restart drops them.

const (
	requestTTL      = 10 * time.Minute // a pending one's life; finished ones are kept as long; the limits' window
	maxPending      = 3
	maxAsked        = 10 // made within requestTTL
	maxRequestHosts = 5
)

// requestOps are the ctl ops of requests, which a v1.1 run answers with its usage.
var requestOps = map[string]bool{"request": true, "requests": true, "approve": true, "deny": true}

type capReq struct {
	id, state, via, result string
	hosts                  []string
	made, expires, ended   time.Time // with monotonic readings
}

// captureRequests are run's requests. now gives the monotonic and the wall
// clock (tests set them apart): a request expires by whichever comes first,
// as allow-all ends (the monotonic clock stops while the computer sleeps; the
// wall clock can be set back).
type captureRequests struct {
	mu         sync.Mutex
	now        func() (mono, wall time.Time)
	reqs       []*capReq   // pending and finished, oldest first
	asked      []time.Time // when each was made, for maxAsked
	approveCmd string      // reqcove capture approve, with run's --state
}

func newCaptureRequests(state string) *captureRequests {
	return &captureRequests{
		now:        func() (time.Time, time.Time) { t := time.Now(); return t, t },
		approveCmd: withState("reqcove capture approve", state),
	}
}

// due: t has come by mono or by wall, whichever first.
func due(t, mono, wall time.Time) bool {
	return !mono.Before(t) || !wall.Round(0).Before(t.Round(0))
}

// sweepLocked expires the pending ones whose time is up and drops what is
// past keeping.
func (q *captureRequests) sweepLocked() {
	mono, wall := q.now()
	q.reqs = slices.DeleteFunc(q.reqs, func(r *capReq) bool {
		if r.state == "pending" && due(r.expires, mono, wall) {
			r.state, r.ended = "expired", r.expires
			log.Printf("capture request %s (%s): expired unanswered", r.id, strings.Join(r.hosts, " "))
		}
		return r.state != "pending" && r.state != "approved" && due(r.ended.Add(requestTTL), mono, wall)
	})
	q.asked = slices.DeleteFunc(q.asked, func(t time.Time) bool { return due(t.Add(requestTTL), mono, wall) })
}

func (q *captureRequests) view(r *capReq) mcpserver.CaptureRequest {
	v := mcpserver.CaptureRequest{ID: r.id, Hosts: r.hosts, State: r.state, ApprovedIn: r.via, Result: r.result,
		CreatedAt: r.made.Round(0).Format(time.RFC3339), ExpiresAt: r.expires.Round(0).Format(time.RFC3339)}
	if r.state == "pending" {
		v.Approve = q.approveCmd + " " + r.id
	}
	return v
}

func (q *captureRequests) findLocked(id string) *capReq {
	for _, r := range q.reqs {
		if r.id == id {
			return r
		}
	}
	return nil
}

func gone(id string) ctlAnswer {
	return ctlAnswer{Message: "refused: no request " + id + " (unknown, ended more than 10 minutes ago, or made before run restarted); nothing changed"}
}

// ask is the request op: hosts (requestHosts' already) asked of base, the
// base scope. The same hosts pending already answer that request.
func (q *captureRequests) ask(base capture.HostRules, hosts []string) ctlAnswer {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sweepLocked()
	for _, h := range hosts {
		if slices.Contains(base.PassHosts, h) {
			return ctlAnswer{Message: "refused: " + h + " is passed undecrypted (--pass-hosts), the user's choice; nothing asked"}
		}
	}
	if !slices.ContainsFunc(hosts, func(h string) bool { return coveredBy(base.Hosts, h) == "" }) {
		return ctlAnswer{Message: "refused: recorded already: " + strings.Join(hosts, ", ") + "; nothing asked"}
	}
	for _, r := range q.reqs {
		switch {
		case !slices.Equal(r.hosts, hosts):
		case r.state == "denied":
			return ctlAnswer{Message: "refused: the user denied these hosts at " + r.ended.Round(0).Local().Format("15:04:05") + ": not asked again within 10 minutes of that; nothing asked"}
		case r.state == "pending":
			return ctlAnswer{OK: true, Message: "pending already", Requests: []mcpserver.CaptureRequest{q.view(r)}}
		}
	}
	pending := 0
	for _, r := range q.reqs {
		if r.state == "pending" {
			pending++
		}
	}
	if pending >= maxPending {
		return ctlAnswer{Message: fmt.Sprintf("refused: %d requests wait for the user already; nothing asked", pending)}
	}
	if len(q.asked) >= maxAsked {
		return ctlAnswer{Message: fmt.Sprintf("refused: %d requests made in the last 10 minutes, the most; nothing asked", len(q.asked))}
	}
	id := ""
	for id == "" || q.findLocked(id) != nil {
		b := make([]byte, 4)
		rand.Read(b)
		id = hex.EncodeToString(b)
	}
	mono, _ := q.now()
	r := &capReq{id: id, state: "pending", hosts: hosts, made: mono, expires: mono.Add(requestTTL)}
	q.reqs = append(q.reqs, r)
	q.asked = append(q.asked, mono)
	log.Printf("capture request %s: an agent asks to record %s; pending until %s (%s)", id, strings.Join(hosts, " "), r.expires.Round(0).Local().Format("15:04:05"), q.approveCmd+" "+id)
	return ctlAnswer{OK: true, New: true, Message: "pending", Requests: []mcpserver.CaptureRequest{q.view(r)}}
}

// list is the requests op: id's, or all kept.
func (q *captureRequests) list(id string) ctlAnswer {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sweepLocked()
	a := ctlAnswer{OK: true, Requests: []mcpserver.CaptureRequest{}}
	for _, r := range q.reqs {
		if id == "" || r.id == id {
			a.Requests = append(a.Requests, q.view(r))
		}
	}
	if id != "" && len(a.Requests) == 0 {
		return gone(id)
	}
	return a
}

// pending are the requests waiting for the user, for status.
func (q *captureRequests) pending() []mcpserver.CaptureRequest {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sweepLocked()
	var out []mcpserver.CaptureRequest
	for _, r := range q.reqs {
		if r.state == "pending" {
			out = append(out, q.view(r))
		}
	}
	return out
}

// pendingLocked is id's request when it waits for the user, or why not.
func (q *captureRequests) pendingLocked(id string) (*capReq, ctlAnswer) {
	q.sweepLocked()
	r := q.findLocked(id)
	switch {
	case r == nil:
		return nil, gone(id)
	case r.state != "pending":
		return nil, ctlAnswer{Message: "refused: request " + id + " is " + r.state + " already; nothing changed", Requests: []mcpserver.CaptureRequest{q.view(r)}}
	}
	return r, ctlAnswer{}
}

// deny is the deny op: the same hosts are refused for 10 minutes.
func (q *captureRequests) deny(id, via string) ctlAnswer {
	q.mu.Lock()
	defer q.mu.Unlock()
	r, no := q.pendingLocked(id)
	if r == nil {
		return no
	}
	mono, _ := q.now()
	r.state, r.ended = "denied", mono
	log.Printf("capture request %s (%s): denied in the %s", id, strings.Join(r.hosts, " "), via)
	return ctlAnswer{OK: true, Message: "denied: " + strings.Join(r.hosts, ", ") + " not recorded; the agent's request for them again is refused for 10 minutes", Requests: []mcpserver.CaptureRequest{q.view(r)}}
}

// take approves id for hosts (exactly its own) in via: it is applied next
// (finish says how it went). r is nil, with the refusal, when it cannot be.
func (q *captureRequests) take(id string, hosts []string, via string) (*capReq, ctlAnswer) {
	q.mu.Lock()
	defer q.mu.Unlock()
	r, no := q.pendingLocked(id)
	if r == nil {
		return nil, no
	}
	if !slices.Equal(hosts, r.hosts) {
		return nil, ctlAnswer{Message: "refused: request " + id + " is for " + strings.Join(r.hosts, ", ") + ", not these hosts: an approval takes the hosts asked, no others; nothing changed"}
	}
	r.state, r.via = "approved", via
	log.Printf("capture request %s (%s): approved in the %s", id, strings.Join(r.hosts, " "), via)
	return r, ctlAnswer{}
}

// finish says how r's change went: a, the add's answer.
func (q *captureRequests) finish(r *capReq, a ctlAnswer) ctlAnswer {
	q.mu.Lock()
	defer q.mu.Unlock()
	mono, _ := q.now()
	r.state, r.result, r.ended = "applied", a.Message, mono
	if !a.OK {
		r.state = "failed"
		log.Printf("capture request %s (%s): approved, but %s", r.id, strings.Join(r.hosts, " "), a.Message)
	}
	a.Requests = []mcpserver.CaptureRequest{q.view(r)}
	return a
}

// unmasked marks a's requests while run does not mask (--no-redact): what
// the user is shown before approving says so.
func unmasked(cap *capture.Capture, a ctlAnswer) ctlAnswer {
	for i := range a.Requests {
		a.Requests[i].Unmasked = !cap.Store.Redacting()
	}
	return a
}

// requestMark is requestWhy as a marker: the hosts cut, never the words
// after them.
func requestMark(why string) string {
	i := strings.Index(why, " (asked by an agent")
	if i < 0 || utf8.RuneCountInString(why) <= capture.MaxMarkerText {
		return why
	}
	return cut(why[:i], capture.MaxMarkerText-utf8.RuneCountInString(why[i:])) + why[i:]
}

// requestWhy is an approved request's change, as the trace shows it.
func requestWhy(hosts []string, via string) string {
	return "capture add " + strings.Join(hosts, " ") + " (asked by an agent, approved in the " + via + ")"
}

// requestHosts are an agent's hosts as run takes them: 1 to 5 host names
// (no wildcard, no IP address), lowercased, without a final dot, sorted,
// each once. What is refused is not repeated.
func requestHosts(hs []string) ([]string, error) {
	if len(hs) == 0 || len(hs) > maxRequestHosts {
		return nil, fmt.Errorf("name 1 to %d hosts", maxRequestHosts)
	}
	out := make([]string, 0, len(hs))
	for i, h := range hs {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if _, err := netip.ParseAddr(h); err == nil {
			return nil, fmt.Errorf("host %d is an IP address: name the host", i+1)
		}
		if len(h) > 253 || !capture.ValidHost(h) {
			return nil, fmt.Errorf("host %d is not a host name (letters, digits, - and . only; no wildcard, scheme, port or path)", i+1)
		}
		out = append(out, h)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// validID: an id as ask makes them.
func validID(id string) bool {
	_, err := hex.DecodeString(id)
	return len(id) == 8 && err == nil && strings.ToLower(id) == id
}

// approve is the approve op: req.Hosts must be the request's own. The hosts
// go in through apply (capture add's change) with the request's trace.
func approve(q *captureRequests, req ctlRequest, apply func(why string, hosts []string) ctlAnswer) ctlAnswer {
	r, no := q.take(req.ID, req.Hosts, req.Via)
	if r == nil {
		return no
	}
	return q.finish(r, apply(requestWhy(r.hosts, req.Via), r.hosts))
}

// errOlderRun: a v1.1 run, which has no requests; errOlderUI: nor reqcove ui's page.
var (
	errOlderRun = errors.New("this run is v1.1, which has no agents' requests: restart it with v1.2 or later (a restart empties the records); nothing changed")
	errOlderUI  = errors.New("this run is v1.1, which has no page: restart it with v1.2 or later (a restart empties the records); nothing opened")
)

// v11Usage starts a v1.1 run's answer to an op it does not know.
const v11Usage = "refused: usage: reqcove capture add"

// approveIn is `reqcove capture approve ID`: the hosts shown, then y/N.
func approveIn(ctx context.Context, in io.Reader, out io.Writer, state string, req ctlRequest) error {
	a, err := askRun(ctx, state, ctlRequest{Cmd: "requests", ID: req.ID})
	if err != nil {
		return err
	}
	if !a.OK || len(a.Requests) != 1 {
		return errors.New(a.Message)
	}
	r := a.Requests[0]
	if r.State != "pending" {
		return fmt.Errorf("request %s is %s: nothing to approve", r.ID, r.State)
	}
	until := r.ExpiresAt
	if t, err := time.Parse(time.RFC3339, until); err == nil {
		until = t.Local().Format("15:04:05")
	}
	fmt.Fprintf(out, "An agent asks to record these hosts too (request %s, until %s):\n  %s\nTheir traffic is decrypted and recorded from new connections on, and agents will read it, %s. Not saved: a restart of run goes back to its hosts.\nApprove? [y/N] ", r.ID, until, strings.Join(r.Hosts, "\n  "), mcpserver.Masked(r))
	line, _ := bufio.NewReader(in).ReadString('\n')
	if yes := strings.ToLower(strings.TrimSpace(line)); yes != "y" && yes != "yes" {
		fmt.Fprintf(out, "not approved: it stays pending until %s (%s denies it)\n", until, withState("reqcove capture deny", state)+" "+r.ID)
		return nil
	}
	req.Hosts = r.Hosts
	return sendCapture(ctx, out, state, req)
}

// printRequests is `reqcove capture requests`.
func printRequests(ctx context.Context, out io.Writer, state string) error {
	a, err := askRun(ctx, state, ctlRequest{Cmd: "requests"})
	if err != nil {
		return err
	}
	if !a.OK {
		return errors.New(a.Message)
	}
	if len(a.Requests) == 0 {
		fmt.Fprintln(out, "no requests (agents ask with request_capture_add; kept 10 minutes after they end)")
	}
	for _, r := range a.Requests {
		s := fmt.Sprintf("%s  %-8s %s", r.ID, r.State, strings.Join(r.Hosts, ", "))
		switch r.State {
		case "pending":
			s += "  (until " + localClock(r.ExpiresAt) + "; " + r.Approve + ")"
		case "applied", "failed":
			s += "  (approved in the " + r.ApprovedIn + ": " + r.Result + ")"
		}
		fmt.Fprintln(out, s)
	}
	return nil
}

func localClock(rfc string) string {
	if t, err := time.Parse(time.RFC3339, rfc); err == nil {
		return t.Local().Format("15:04:05")
	}
	return rfc
}

// ctlRequests is mcpserver.Requests over ctl.sock, for `reqcove mcp`.
type ctlRequests struct{ state, notRunning string }

func (c ctlRequests) ask(ctx context.Context, req ctlRequest) (mcpserver.CaptureRequest, bool, error) {
	a, err := askRun(ctx, c.state, req)
	switch {
	case errors.Is(err, errNotRunning):
		return mcpserver.CaptureRequest{}, false, errors.New(c.notRunning)
	case err != nil:
		return mcpserver.CaptureRequest{}, false, err
	case !a.OK || len(a.Requests) != 1:
		return mcpserver.CaptureRequest{}, false, errors.New(a.Message)
	}
	return a.Requests[0], a.New, nil
}

func (c ctlRequests) Ask(ctx context.Context, hosts []string) (mcpserver.CaptureRequest, bool, error) {
	return c.ask(ctx, ctlRequest{Cmd: "request", Hosts: hosts})
}

func (c ctlRequests) Get(ctx context.Context, id string) (mcpserver.CaptureRequest, error) {
	if !validID(id) {
		return mcpserver.CaptureRequest{}, errors.New("id: not one request_capture_add gives")
	}
	r, _, err := c.ask(ctx, ctlRequest{Cmd: "requests", ID: id})
	return r, err
}

func (c ctlRequests) Approve(ctx context.Context, id string, hosts []string) (mcpserver.CaptureRequest, error) {
	r, _, err := c.ask(ctx, ctlRequest{Cmd: "approve", ID: id, Hosts: hosts, Via: "dialog"})
	return r, err
}
