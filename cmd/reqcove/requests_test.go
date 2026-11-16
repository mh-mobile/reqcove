package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/proxy"
)

// An agent's hosts: host names only, lowercased, each once, sorted; 1 to 5.
func TestRequestHosts(t *testing.T) {
	if got, err := requestHosts([]string{"B.com.", " a.com", "b.com"}); err != nil || !slices.Equal(got, []string{"a.com", "b.com"}) {
		t.Errorf("%q %v", got, err)
	}
	for _, hs := range [][]string{nil, {"a.com", "b.com", "c.com", "d.com", "e.com", "f.com"}, {"1.2.3.4"}, {"::1"}, {"*.a.com"}, {"*"},
		{"a.com:443"}, {"https://a.com"}, {"a.com/x"}, {"a b.com"}, {"$(id).com"}, {strings.Repeat("a", 250) + ".com"}, {""}} {
		if got, err := requestHosts(hs); err == nil {
			t.Errorf("%q: %q", hs, got)
		} else if strings.Contains(err.Error(), "$(id)") || strings.Contains(err.Error(), "https") {
			t.Errorf("%q: the refusal repeats it: %v", hs, err)
		}
	}
	for _, c := range []struct {
		req  ctlRequest
		want string
	}{
		{ctlRequest{Cmd: "request"}, "1 to 5"},
		{ctlRequest{Cmd: "request", Hosts: []string{"10.0.0.1"}}, "IP address"},
		{ctlRequest{Cmd: "request", Hosts: []string{"a.com"}, ID: "0a1b2c3d"}, "usage"},
		{ctlRequest{Cmd: "request", Hosts: []string{"a.com"}, Pass: true}, "usage"},
		{ctlRequest{Cmd: "approve", ID: "0a1b2c3d"}, "usage"}, // no via
		{ctlRequest{Cmd: "approve", ID: "0a1b2c3d", Via: "web"}, "usage"},
		{ctlRequest{Cmd: "approve", ID: "0A1B2C3D", Via: "terminal"}, "not a request's id"},
		{ctlRequest{Cmd: "approve", ID: "../../x", Via: "terminal"}, "not a request's id"},
		{ctlRequest{Cmd: "approve", ID: "0a1b2c3d", Via: "terminal", Hosts: []string{"*.a.com"}}, "not a host name"},
		{ctlRequest{Cmd: "deny"}, "usage"},
		{ctlRequest{Cmd: "deny", ID: "0a1b2c3d", Hosts: []string{"a.com"}}, "usage"},
		{ctlRequest{Cmd: "requests", Hosts: []string{"a.com"}}, "usage"},
		{ctlRequest{Cmd: "add", Hosts: []string{"a.com"}, ID: "0a1b2c3d"}, "usage"},
	} {
		if _, err := c.req.normalized(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.req, err, c.want)
		}
	}
	if r, err := (ctlRequest{Cmd: "approve", ID: "0a1b2c3d", Via: "dialog", Hosts: []string{"B.com", "a.com"}}).normalized(); err != nil || !slices.Equal(r.Hosts, []string{"a.com", "b.com"}) {
		t.Errorf("approve: %v %q", err, r.Hosts)
	}
	// The CLI: approve and deny take the id; request is the agents' op.
	for args, want := range map[string]string{
		"approve":                "takes the request's id",
		"approve 0a1b2c3d extra": "takes the request's id",
		"deny":                   "takes the request's id",
		"approve nothex1":        "not a request's id",
		"request a.com":          "usage",
		"requests a.com":         "usage",
		"approve 0a1b2c3d":       "only in a terminal",
		"deny 0a1b2c3d":          "only in a terminal",
		"requests":               "only in a terminal",
	} {
		if err := captureCmd(context.Background(), append(strings.Fields(args), "--state", t.TempDir())); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("capture %s: %v, want %q", args, err, want)
		}
	}
}

// clock is a monotonic and a wall clock that tests move apart.
type clock struct {
	mu         sync.Mutex
	base       time.Time
	mono, wall time.Duration
}

func (c *clock) now() (time.Time, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.base.Add(c.mono), c.base.Round(0).Add(c.wall)
}

func (c *clock) move(mono, wall time.Duration) {
	c.mu.Lock()
	c.mono += mono
	c.wall += wall
	c.mu.Unlock()
}

func testRequests() (*captureRequests, *clock) {
	q := newCaptureRequests(defaultState())
	c := &clock{base: time.Now()}
	q.now = c.now
	return q, c
}

func asked(t *testing.T, q *captureRequests, base capture.HostRules, hosts ...string) (mcpserver.CaptureRequest, ctlAnswer) {
	t.Helper()
	a := q.ask(base, hosts)
	if !a.OK {
		return mcpserver.CaptureRequest{}, a
	}
	if len(a.Requests) != 1 {
		t.Fatalf("%+v", a)
	}
	return a.Requests[0], a
}

// A request: pending with an id and the command; the same hosts again are
// the same request; recorded hosts, passed ones, and limits are refused.
func TestCaptureRequestsAsk(t *testing.T) {
	q, c := testRequests()
	none := capture.HostRules{}
	r, a := asked(t, q, none, "a.com")
	if !a.New || r.State != "pending" || !validID(r.ID) || r.Approve != "reqcove capture approve "+r.ID || !slices.Equal(r.Hosts, []string{"a.com"}) {
		t.Fatalf("%+v %+v", a, r)
	}
	if again, a := asked(t, q, none, "a.com"); a.New || again.ID != r.ID {
		t.Errorf("again: %+v", a)
	}
	base := scopeOf(t, []string{"*.example.com", "p.net"}, []string{"p.net"})
	if _, a := asked(t, q, base, "api.example.com"); a.OK || !strings.Contains(a.Message, "recorded already") || !strings.Contains(a.Message, "nothing asked") {
		t.Errorf("recorded already: %+v", a)
	}
	if _, a := asked(t, q, base, "p.net"); a.OK || !strings.Contains(a.Message, "passed undecrypted") {
		t.Errorf("passed: %+v", a)
	}
	if _, a := asked(t, q, base, "api.example.com", "b.com"); !a.OK { // one of them new
		t.Errorf("partly recorded: %+v", a)
	}
	asked(t, q, none, "c.com")
	if _, a := asked(t, q, none, "d.com"); a.OK || !strings.Contains(a.Message, "3 requests wait") {
		t.Errorf("a 4th pending: %+v", a)
	}
	if again, a := asked(t, q, none, "a.com"); !a.OK || again.ID != r.ID { // the limit is for new ones
		t.Errorf("again while 3 pending: %+v", a)
	}
	// 10 made in 10 minutes: deny them as they come (the pending limit aside).
	for _, x := range q.pending() {
		q.deny(x.ID, "terminal")
	}
	for i := 3; i < maxAsked; i++ {
		x, a := asked(t, q, none, string(rune('e'+i))+".com")
		if !a.OK {
			t.Fatalf("%d: %+v", i, a)
		}
		if i < maxAsked-1 {
			q.deny(x.ID, "terminal")
		}
	}
	last := q.pending()[0]
	if _, a := asked(t, q, none, "z.com"); a.OK || !strings.Contains(a.Message, "10 requests made in the last 10 minutes") {
		t.Errorf("an 11th: %+v", a)
	}
	if again, a := asked(t, q, none, last.Hosts...); !a.OK || again.ID != last.ID {
		t.Errorf("again at the rate limit: %+v", a)
	}
	c.move(requestTTL, 0) // 10 minutes later by the monotonic clock: room again
	if _, a := asked(t, q, none, "z.com"); !a.OK || !a.New {
		t.Errorf("10 minutes later: %+v", a)
	}
}

// A pending request expires by either clock; before that it stays; what
// ended is kept 10 minutes more, then gone.
func TestCaptureRequestsExpire(t *testing.T) {
	for _, by := range []struct {
		name       string
		mono, wall time.Duration
	}{{"monotonic", requestTTL, 0}, {"wall", 0, requestTTL}} {
		t.Run(by.name, func(t *testing.T) {
			q, c := testRequests()
			r, _ := asked(t, q, capture.HostRules{}, "a.com")
			c.move(by.mono-time.Second, by.wall-time.Second)
			if p := q.pending(); len(p) != 1 {
				t.Fatalf("before the end: %+v", p)
			}
			c.move(time.Second, time.Second)
			if _, a := q.take(r.ID, r.Hosts, "terminal"); !strings.Contains(a.Message, "is expired already") { // first: nothing else looked since
				t.Errorf("approve after the end: %+v", a)
			}
			if p := q.pending(); len(p) != 0 {
				t.Errorf("after the end: %+v", p)
			}
			if a := q.deny(r.ID, "terminal"); a.OK || !strings.Contains(a.Message, "expired") {
				t.Errorf("deny after the end: %+v", a)
			}
			if a := q.list(r.ID); !a.OK || a.Requests[0].State != "expired" {
				t.Errorf("kept: %+v", a)
			}
			c.move(by.mono, by.wall) // 10 minutes after it ended
			if a := q.list(r.ID); a.OK || !strings.Contains(a.Message, "no request "+r.ID) {
				t.Errorf("gone: %+v", a)
			}
		})
	}
}

// Approval: only the request's own hosts, once; applied through capture
// add's change with the request's trace; a failed change is failed; denied,
// the same hosts are refused 10 minutes; a restart (a new run) knows no id.
func TestCaptureRequestsApprove(t *testing.T) {
	q, c := testRequests()
	r, _ := asked(t, q, capture.HostRules{}, "a.com", "b.com")
	var whys []string
	apply := func(ok bool) func(string, []string) ctlAnswer {
		return func(why string, hosts []string) ctlAnswer {
			whys = append(whys, why+" | "+strings.Join(hosts, " "))
			return ctlAnswer{OK: ok, Message: "applied: a.com, b.com added"}
		}
	}
	if a := approve(q, ctlRequest{Cmd: "approve", ID: r.ID, Via: "terminal", Hosts: []string{"a.com"}}, apply(true)); a.OK || !strings.Contains(a.Message, "is for a.com, b.com, not these hosts") || len(whys) != 0 {
		t.Errorf("mismatch: %+v %q", a, whys)
	}
	if a := approve(q, ctlRequest{Cmd: "approve", ID: r.ID, Via: "terminal"}, apply(true)); a.OK || len(whys) != 0 {
		t.Errorf("no hosts: %+v", a)
	}
	a := approve(q, ctlRequest{Cmd: "approve", ID: r.ID, Via: "terminal", Hosts: []string{"a.com", "b.com"}}, apply(true))
	if !a.OK || a.Requests[0].State != "applied" || a.Requests[0].ApprovedIn != "terminal" || a.Requests[0].Result != "applied: a.com, b.com added" || a.Requests[0].Approve != "" {
		t.Errorf("approved: %+v", a)
	}
	if !slices.Equal(whys, []string{"capture add a.com b.com (asked by an agent, approved in the terminal) | a.com b.com"}) {
		t.Errorf("applied as: %q", whys)
	}
	if a := approve(q, ctlRequest{Cmd: "approve", ID: r.ID, Via: "dialog", Hosts: r.Hosts}, apply(true)); a.OK || !strings.Contains(a.Message, "is applied already") || len(whys) != 1 {
		t.Errorf("twice: %+v", a)
	}
	f, _ := asked(t, q, capture.HostRules{}, "f.com")
	if a := approve(q, ctlRequest{Cmd: "approve", ID: f.ID, Via: "dialog", Hosts: f.Hosts}, apply(false)); a.OK || a.Requests[0].State != "failed" || a.Requests[0].ApprovedIn != "dialog" {
		t.Errorf("failed: %+v", a)
	}
	d, _ := asked(t, q, capture.HostRules{}, "d.com")
	if a := q.deny(d.ID, "terminal"); !a.OK || a.Requests[0].State != "denied" {
		t.Errorf("deny: %+v", a)
	}
	if a := q.deny(d.ID, "terminal"); a.OK || !strings.Contains(a.Message, "denied already") {
		t.Errorf("deny twice: %+v", a)
	}
	c.move(requestTTL-time.Second, 0)
	if _, a := asked(t, q, capture.HostRules{}, "d.com"); a.OK || !strings.Contains(a.Message, "denied these hosts") {
		t.Errorf("denied recently: %+v", a)
	}
	c.move(0, requestTTL) // by the wall clock, 10 minutes after
	if _, a := asked(t, q, capture.HostRules{}, "d.com"); !a.OK {
		t.Errorf("10 minutes after the denial: %+v", a)
	}
	// A restart: the next run's ctl state has none of them.
	if a := newCtlState(&runOpts{}).reqs.list(r.ID); a.OK || !strings.Contains(a.Message, "no request") {
		t.Errorf("after a restart: %+v", a)
	}
}

// The marker of an approval keeps its words whole, the hosts cut to fit.
func TestRequestMark(t *testing.T) {
	short := requestWhy([]string{"a.com"}, "terminal")
	if requestMark(short) != short {
		t.Errorf("%q", requestMark(short))
	}
	m := requestMark(requestWhy([]string{"api.staging.example.com", "b.example.com"}, "dialog"))
	if !strings.HasSuffix(m, "… (asked by an agent, approved in the dialog)") || !strings.HasPrefix(m, "capture add api.staging") || utf8.RuneCountInString(m) != capture.MaxMarkerText {
		t.Errorf("%q", m)
	}
}

// fakeCtlSock answers ctl.sock in dir with answer, and records what it was asked.
func fakeCtlSock(t *testing.T, answer func(ctlRequest) ctlAnswer) (string, *[]ctlRequest) {
	t.Helper()
	dir, _ := os.MkdirTemp("/tmp", "rcvq-") // short socket paths
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, ctlSock))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	got := &[]ctlRequest{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var req ctlRequest
			json.NewDecoder(c).Decode(&req)
			mu.Lock()
			*got = append(*got, req)
			mu.Unlock()
			json.NewEncoder(c).Encode(answer(req))
			c.Close()
		}
	}()
	return dir, got
}

// v1.1's answer to an op it does not know (its normalized: the usage).
const v11Answer = "refused: usage: reqcove capture add [--pass] HOST… | capture remove [--pass] HOST… | capture set --allow-hosts HOSTS [--pass-hosts HOSTS] | capture stop | capture start | capture save | capture allow-all --for D | capture allow-all --end | capture discover --for D | capture discover --end  [--state DIR]; nothing changed"

// A v1.1 run (ctl.sock without the request ops), a v1.0 one (no ctl.sock)
// and none: the tool and the commands say what to do.
func TestCaptureRequestsOlderRun(t *testing.T) {
	ctx := context.Background()
	dir, _ := fakeCtlSock(t, func(ctlRequest) ctlAnswer { return ctlAnswer{Message: v11Answer} })
	reqs := ctlRequests{state: dir, notRunning: "not running (test)"}
	if _, _, err := reqs.Ask(ctx, []string{"a.com"}); !errors.Is(err, errOlderRun) || !strings.Contains(err.Error(), "restart it with v1.2") {
		t.Errorf("tool: %v", err)
	}
	if _, err := reqs.Get(ctx, "0a1b2c3d"); !errors.Is(err, errOlderRun) {
		t.Errorf("get: %v", err)
	}
	if err := printRequests(ctx, io.Discard, dir); !errors.Is(err, errOlderRun) {
		t.Errorf("requests: %v", err)
	}
	if err := sendCapture(ctx, io.Discard, dir, ctlRequest{Cmd: "deny", ID: "0a1b2c3d"}); !errors.Is(err, errOlderRun) {
		t.Errorf("deny: %v", err)
	}
	if err := approveIn(ctx, strings.NewReader("y\n"), io.Discard, dir, ctlRequest{Cmd: "approve", ID: "0a1b2c3d", Via: "terminal"}); !errors.Is(err, errOlderRun) {
		t.Errorf("approve: %v", err)
	}
	if err := sendCapture(ctx, io.Discard, dir, ctlRequest{Cmd: "add", Hosts: []string{"a.com"}}); err == nil || errors.Is(err, errOlderRun) { // its own answer, as it is
		t.Errorf("add: %v", err)
	}

	old, _ := os.MkdirTemp("/tmp", "rcvq-")
	defer os.RemoveAll(old)
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := mcpserver.Serve(sctx, filepath.Join(old, "mcp.sock"), mcp.NewServer(&mcp.Implementation{Name: "reqcove", Version: "v1.0.0"}, nil)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (ctlRequests{state: old}).Ask(ctx, []string{"a.com"}); err == nil || !strings.Contains(err.Error(), "this run is v1.0.0: restart it with v1.2") {
		t.Errorf("v1.0: %v", err)
	}
	none, _ := os.MkdirTemp("/tmp", "rcvq-")
	defer os.RemoveAll(none)
	if _, _, err := (ctlRequests{state: none, notRunning: "not running (test)"}).Ask(ctx, []string{"a.com"}); err == nil || err.Error() != "not running (test)" {
		t.Errorf("none running: %v", err)
	}
}

// approve shows the hosts and asks: only y approves, with the hosts shown.
func TestApproveIn(t *testing.T) {
	ctx := context.Background()
	pending := mcpserver.CaptureRequest{ID: "0a1b2c3d", Hosts: []string{"a.com", "b.com"}, State: "pending", ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339)}
	dir, got := fakeCtlSock(t, func(req ctlRequest) ctlAnswer {
		if req.Cmd == "requests" {
			return ctlAnswer{OK: true, Requests: []mcpserver.CaptureRequest{pending}}
		}
		return ctlAnswer{OK: true, Message: "applied: a.com, b.com added"}
	})
	for _, in := range []string{"\n", "n\n", "no\n", "", "yy\n"} {
		*got = nil
		var out strings.Builder
		if err := approveIn(ctx, strings.NewReader(in), &out, dir, ctlRequest{Cmd: "approve", ID: "0a1b2c3d", Via: "terminal"}); err != nil || !strings.Contains(out.String(), "not approved") {
			t.Errorf("%q: %v %q", in, err, out.String())
		}
		if len(*got) != 1 {
			t.Errorf("%q: asked %+v", in, *got)
		}
	}
	*got = nil
	var out strings.Builder
	if err := approveIn(ctx, strings.NewReader("Y\n"), &out, dir, ctlRequest{Cmd: "approve", ID: "0a1b2c3d", Via: "terminal"}); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "  a.com\n  b.com\n") || !strings.Contains(s, "agents will read it, masked") || !strings.HasSuffix(s, "applied: a.com, b.com added\n") {
		t.Errorf("%q", s)
	}
	if len(*got) != 2 || (*got)[1].Cmd != "approve" || (*got)[1].Via != "terminal" || !slices.Equal((*got)[1].Hosts, []string{"a.com", "b.com"}) {
		t.Errorf("sent: %+v", *got)
	}
	pending.Unmasked = true // run --no-redact: the prompt says so
	out.Reset()
	if err := approveIn(ctx, strings.NewReader("n\n"), &out, dir, ctlRequest{Cmd: "approve", ID: "0a1b2c3d", Via: "terminal"}); err != nil || !strings.Contains(out.String(), "agents will read it, unmasked (run masks nothing: --no-redact)") {
		t.Errorf("unmasked: %v %q", err, out.String())
	}
	pending.State = "denied"
	if err := approveIn(ctx, strings.NewReader("y\n"), io.Discard, dir, ctlRequest{Cmd: "approve", ID: "0a1b2c3d", Via: "terminal"}); err == nil || !strings.Contains(err.Error(), "is denied: nothing to approve") {
		t.Errorf("denied: %v", err)
	}
}

// Off a terminal the request commands refuse before run is asked; in LAN
// mode run refuses the agent's request.
func TestCaptureRequestsRefused(t *testing.T) {
	dir, got := fakeCtlSock(t, func(ctlRequest) ctlAnswer { return ctlAnswer{OK: true} })
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	for _, req := range []ctlRequest{{Cmd: "approve", ID: "0a1b2c3d", Via: "terminal"}, {Cmd: "deny", ID: "0a1b2c3d"}, {Cmd: "requests"}} {
		if err := captureIn(context.Background(), r, w, dir, req); err == nil || !strings.Contains(err.Error(), "only in a terminal") {
			t.Errorf("%s off a terminal: %v", req.Cmd, err)
		}
	}
	if len(*got) != 0 {
		t.Errorf("run was asked: %+v", *got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lanDir, _ := os.MkdirTemp("/tmp", "rcvq-")
	defer os.RemoveAll(lanDir)
	if _, err := serveCtl(ctx, lanDir, nil, &runOpts{lanMode: true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (ctlRequests{state: lanDir}).Ask(ctx, []string{"a.com"}); err == nil || !strings.Contains(err.Error(), "LAN mode") {
		t.Errorf("LAN mode: %v", err)
	}
}

type bearer struct{ rt http.RoundTripper }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer tok")
	return b.rt.RoundTrip(r)
}

// TestCaptureRequestE2E (REQCOVE_E2E=1, real mitmproxy): an agent asks
// through reqcove mcp's tool, the request shows in this computer's status
// (not --mcp-http's), the user approves it as `reqcove capture approve`
// does, and a new connection to the host is recorded; the trace is an mcp
// marker, scope_change and run's log. Approved while recording is stopped,
// it changes the hosts a start records, and recording stays stopped.
func TestCaptureRequestE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "rcvq-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	state := filepath.Join(dir, "s")
	c, err := capture.Start(ctx, capture.Config{Dir: state, Confdir: filepath.Join(dir, "m"),
		Uvx: "uvx", Python: defaultPython, MitmSpec: defaultMitmSpec,
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
		Log: os.Stderr, ReadyTimeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	logged := logTo(t)
	o := &runOpts{state: state, mcpHTTP: true}
	var node nodeState
	node.set(exitnode.Status{Backend: "Running"})
	ctl, err := serveCtl(ctx, state, c, o, func() mcpserver.StatusOut { return withDiscovery(withFiles(liveStatus(node.get(), c), o), c) })
	if err != nil {
		t.Fatal(err)
	}
	handler, err := serveMCP(ctx, o, c, &node, ctl.reqs, "tok")
	if err != nil {
		t.Fatal(err)
	}

	ct, pt := mcp.NewInMemoryTransports() // the agent, through reqcove mcp as main starts it
	go mcpserver.Proxy(ctx, filepath.Join(state, "mcp.sock"), notRunningMsg(state), ctlRequests{state: state, notRunning: notRunningMsg(state)}, pt)
	agent, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	tool := func(name string, args map[string]any) mcpserver.RequestOut {
		t.Helper()
		res, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil || res.IsError {
			t.Fatalf("%s: %v %+v", name, err, res)
		}
		var out mcpserver.RequestOut
		b, _ := json.Marshal(res.StructuredContent)
		json.Unmarshal(b, &out)
		return out
	}
	req := tool("request_capture_add", map[string]any{"hosts": []string{"LOCALHOST"}})
	if req.State != "pending" || !slices.Equal(req.Hosts, []string{"localhost"}) || req.Approve != withState("reqcove capture approve", state)+" "+req.ID {
		t.Fatalf("asked: %+v", req)
	}
	waitLog(t, logged, "capture request "+req.ID+": an agent asks to record localhost; pending until", 1)

	statusOf := func(cs *mcp.ClientSession) mcpserver.StatusOut {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "status"})
		if err != nil {
			t.Fatal(err)
		}
		var out mcpserver.StatusOut
		b, _ := json.Marshal(res.StructuredContent)
		json.Unmarshal(b, &out)
		return out
	}
	local, err := dialRun(ctx, state, "t")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	srv := httptest.NewServer(handler)
	defer srv.Close()
	remote, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: &http.Client{Transport: bearer{http.DefaultTransport}}, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if got := statusOf(local).CaptureRequests; len(got) != 1 || got[0].ID != req.ID {
		t.Errorf("local status: %+v", got)
	}
	if got := statusOf(remote); got.CaptureRequests != nil || got.Mode == "" {
		t.Errorf("--mcp-http's status: %+v", got.CaptureRequests)
	}
	for tool, err := range remote.Tools(ctx, nil) {
		if err != nil || strings.Contains(tool.Name, "capture_request") {
			t.Errorf("--mcp-http: %v %v", tool, err)
		}
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	url := strings.Replace(origin.URL, "127.0.0.1", "localhost", 1)
	socks, _ := proxy.SOCKS5("tcp", c.SocksAddr, &proxy.Auth{User: "dev", Password: c.SocksSecret}, proxy.Direct)
	hc := &http.Client{Transport: &http.Transport{DialContext: socks.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}, Timeout: 30 * time.Second}
	get := func(path string) {
		t.Helper()
		r, err := hc.Get(url + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	get("/before")
	var out strings.Builder
	if err := sendCapture(ctx, &out, state, ctlRequest{Cmd: "approve", ID: req.ID, Via: "terminal", Hosts: req.Hosts}); err != nil || !strings.HasPrefix(out.String(), "applied: localhost added") {
		t.Fatalf("approve: %v %q", err, out.String())
	}
	get("/after")
	for deadline := time.Now().Add(10 * time.Second); fmt.Sprint(c.Store.Stats()["flows"]) != "1"; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("flows: %v", c.Store.Stats()["flows"])
		}
	}
	if flows, _ := c.Store.List(capture.Filter{Limit: 10}); len(flows) != 1 || !strings.HasSuffix(flows[0].URL, "/after") {
		t.Errorf("recorded: %+v", flows)
	}
	why := "capture add localhost (asked by an agent, approved in the terminal)"
	if m := c.Store.Markers(0); len(m) != 1 || m[0].Source != "mcp" || m[0].Text != why {
		t.Errorf("markers: %+v", m)
	}
	if s := liveStatus(node.get(), c); s.ScopeChange != why || !slices.Equal(s.AllowHosts, []string{"localhost"}) {
		t.Errorf("status: %q %q", s.ScopeChange, s.AllowHosts)
	}
	waitLog(t, logged, "capture request "+req.ID+" (localhost): approved in the terminal", 1)
	waitLog(t, logged, why+": applied: localhost added", 1)
	if got := tool("get_capture_request", map[string]any{"id": req.ID}); got.State != "applied" || got.ApprovedIn != "terminal" {
		t.Errorf("get: %+v", got)
	}
	if got := statusOf(local).CaptureRequests; got != nil {
		t.Errorf("local status after: %+v", got)
	}

	// Stopped: an approval changes the base only.
	if err := sendCapture(ctx, io.Discard, state, ctlRequest{Cmd: "stop"}); err != nil {
		t.Fatal(err)
	}
	req = tool("request_capture_add", map[string]any{"hosts": []string{"api.staging.later.example"}})
	out.Reset()
	if err := sendCapture(ctx, &out, state, ctlRequest{Cmd: "approve", ID: req.ID, Via: "terminal", Hosts: req.Hosts}); err != nil || !strings.Contains(out.String(), "recording is stopped") {
		t.Errorf("approve while stopped: %v %q", err, out.String())
	}
	if !c.Stopped() || !slices.Equal(c.Base().Hosts, []string{"localhost", "api.staging.later.example"}) {
		t.Errorf("stopped %v, base %q", c.Stopped(), c.Base().Hosts)
	}
	if m := c.Store.Markers(0); len(m) != 3 || m[2].Source != "mcp" || !strings.HasSuffix(m[2].Text, "… (asked by an agent, approved in the terminal)") { // a long host: its words kept (the stop's marker between)
		t.Errorf("markers: %+v", m)
	}

	// reqcove ui's page approves it the same way.
	req = tool("request_capture_add", map[string]any{"hosts": []string{"page.example"}})
	base, code := openUI(t, state)
	token := trade(t, base, code)
	if _, s := pageStateOf(t, base, token); len(s.Requests) != 1 || s.Requests[0].ID != req.ID || s.Recording != capture.RecordingStopped {
		t.Errorf("the page: %+v", s)
	}
	r, b := call(t, base, "POST", "/api/approve", `{"id":"`+req.ID+`","hosts":["page.example"]}`, map[string]string{sessionHeader: token})
	if r.StatusCode != 200 || !strings.Contains(b, `"ok":true`) || !strings.Contains(b, "page.example added") {
		t.Errorf("approve in the page: %d %s", r.StatusCode, b)
	}
	why = "capture add page.example (asked by an agent, approved in the page)"
	if m := c.Store.Markers(0); len(m) != 4 || m[3].Source != "mcp" || m[3].Text != why || !slices.Contains(c.Base().Hosts, "page.example") {
		t.Errorf("markers: %+v; base %q", m, c.Base().Hosts)
	}
	waitLog(t, logged, why+": applied: page.example added", 1)
	if got := tool("get_capture_request", map[string]any{"id": req.ID}); got.State != "applied" || got.ApprovedIn != "page" {
		t.Errorf("get: %+v", got)
	}
	if strings.Contains(logged.String(), code) || strings.Contains(logged.String(), token) {
		t.Error("the code or the token logged")
	}
}
