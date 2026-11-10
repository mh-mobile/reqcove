package mcpserver

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func storeWith(id string) *capture.Store {
	st := capture.NewStore(10, 1<<20)
	st.Apply([]byte(`{"v":2,"ev":"request","id":"` + id + `","device":"d","host":"h.example","url":"https://h.example/"}`))
	return st
}

func sockPath(t *testing.T) string {
	dir, err := os.MkdirTemp("/tmp", "rcvp-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "mcp.sock")
}

// serve starts a stand-in for `run` on sock; the func it returns stops it.
func serve(t *testing.T, sock string, s *mcp.Server) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	if err := Serve(ctx, sock, s); err != nil {
		t.Fatal(err)
	}
	return func() { cancel(); time.Sleep(50 * time.Millisecond) }
}

// agent is `reqcove mcp` with an agent connected to it.
func agent(t *testing.T, sock string) *mcp.ClientSession {
	t.Helper()
	old := redialAfter
	redialAfter = 0 // runs come back at once here
	t.Cleanup(func() { redialAfter = old })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ct, st := mcp.NewInMemoryTransports()
	go Proxy(ctx, sock, "reqcove is not running (test)", st)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// ids calls list_flows: the flow ids, or the tool error's text. A note of
// the proxy's (a restart) is taken out and checked to be one.
func ids(t *testing.T, cs *mcp.ClientSession) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_flows"})
	if err != nil {
		t.Fatalf("protocol error: %v", err)
	}
	if res.IsError {
		return res.Content[0].(*mcp.TextContent).Text, true
	}
	// The note is in the structured answer, which Claude Code shows the model,
	// and in the text, as its JSON.
	lastNotes = nil
	var m map[string]any
	b, _ := json.Marshal(res.StructuredContent)
	json.Unmarshal(b, &m)
	if n, ok := m["note"].(string); ok {
		lastNotes = append(lastNotes, n)
		if len(res.Content) != 1 || res.Content[0].(*mcp.TextContent).Text != string(b) {
			t.Errorf("the text is not the structured answer with its note: %v", res.Content)
		}
	}
	var out ListOut
	json.Unmarshal(b, &out)
	var s []string
	for _, f := range out.Flows {
		s = append(s, f.ID)
	}
	return strings.Join(s, ","), false
}

// The agent's one session lives on while `run` is down, restarts, and comes
// back: no reconnecting on its side (Claude Code's /mcp).
var lastNotes []string

// notes calls list_flows and returns the proxy's notes in its answer.
func notes(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	ids(t, cs)
	return lastNotes
}

func TestProxyAcrossRestarts(t *testing.T) {
	sock := sockPath(t)
	cs := agent(t, sock)
	var names []string
	for tool, err := range cs.Tools(context.Background(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
		if tool.OutputSchema != nil {
			t.Errorf("%s has an output schema: a run of another version could fail it", tool.Name)
		}
	}
	if len(names) != 9 || !strings.Contains(strings.Join(names, ","), "status") { // the tools, without run
		t.Errorf("tools without run: %v", names)
	}
	if got, isErr := ids(t, cs); !isErr || got != "reqcove is not running (test)" {
		t.Errorf("before run: %q %v", got, isErr)
	}
	stop := serve(t, sock, New(storeWith("a"), nil))
	if got, _ := ids(t, cs); got != "a" || lastNotes != nil {
		t.Fatalf("first run: %q %v", got, lastNotes)
	}
	stop()
	stop = serve(t, sock, New(storeWith("b"), nil))
	if got, _ := ids(t, cs); got != "b" || len(lastNotes) != 1 || !strings.Contains(lastNotes[0], "flow ids and cursors from before it are gone") { // no call in between: the dead session is found by this one
		t.Fatalf("after a restart: %q %v", got, lastNotes)
	}
	// The first answer after a restart says so, once: ids and cursors from before are gone.
	if n := notes(t, cs); len(n) != 0 {
		t.Errorf("the note again: %v", n)
	}
	stop()
	if got, isErr := ids(t, cs); !isErr {
		t.Errorf("stopped: %q", got)
	}
	defer serve(t, sock, New(storeWith("c"), nil))()
	if got, _ := ids(t, cs); got != "c" {
		t.Fatalf("after a second restart: %q", got)
	}
}

// Calls that come together after a restart share one new session.
func TestProxyOneDial(t *testing.T) {
	sock := sockPath(t)
	ctx := context.Background()
	p := &proxy{sock: sock, ctx: ctx, client: mcp.NewClient(&mcp.Implementation{Name: "x", Version: "0"}, nil)}
	stop := serve(t, sock, New(storeWith("a"), nil))
	dead, err := p.session(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stop()
	defer serve(t, sock, New(storeWith("b"), nil))()
	first, err := p.session(ctx, dead)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.session(ctx, dead) // a slower call that failed on the same dead session
	if err != nil || second != first || p.dials.Load() != 2 {
		t.Fatalf("a second dial (%v, %d dials)", err, p.dials.Load())
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.call(ctx, &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "list_flows"}})
		}()
	}
	wg.Wait()
	if p.dials.Load() != 2 {
		t.Errorf("%d dials for calls on a live session", p.dials.Load())
	}
}

// `run`'s own answers go back as they are, sent once: a tool a `run` of
// another version lacks is not taken for `run` being down, and the
// arguments reach it.
func TestProxyRunAnswers(t *testing.T) {
	sock := sockPath(t)
	s := New(storeWith("a"), nil)
	var calls atomic.Int32
	s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/call" {
				calls.Add(1)
			}
			return next(ctx, method, req)
		}
	})
	defer serve(t, sock, s)()
	cs := agent(t, sock)
	// New(…, nil) has no status tool: as an older run without one of the tools.
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status"}); err == nil || calls.Load() != 1 {
		t.Errorf("a tool run lacks: %v, %d calls", err, calls.Load())
	}
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_flows", Arguments: map[string]any{"hots": "x"}})
	if err != nil || !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "hots") || calls.Load() != 2 {
		t.Errorf("a misspelt argument: %v %+v, %d calls", err, res, calls.Load())
	}
	for host, want := range map[string]int{"h.example": 1, "other.example": 0} { // the arguments reach run
		got := call[ListOut](t, cs, "list_flows", map[string]any{"host": host})
		if len(got.Flows) != want {
			t.Errorf("host %s through the proxy: %d flows, want %d", host, len(got.Flows), want)
		}
	}
}

// A `run` of another version: its first answer says to reconnect the agent.
func TestProxyOtherVersion(t *testing.T) {
	sock := sockPath(t)
	s := mcp.NewServer(&mcp.Implementation{Name: "reqcove", Version: "0.0.1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "list_flows"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, ListOut, error) {
		return nil, ListOut{}, nil
	})
	defer serve(t, sock, s)()
	cs := agent(t, sock)
	if n := notes(t, cs); len(n) != 1 || !strings.Contains(n[0], "reqcove run is version 0.0.1") || !strings.Contains(n[0], "reconnect") {
		t.Errorf("notes: %v", n)
	}
}

// A `run` that takes the connection but never answers (stopped with Ctrl-Z):
// calls together wait one handshake, not one each.
func TestProxyHungRun(t *testing.T) {
	sock := sockPath(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	oldH, oldR := handshake, redialAfter
	handshake, redialAfter = 200*time.Millisecond, time.Second
	defer func() { handshake, redialAfter = oldH, oldR }()
	p := &proxy{sock: sock, notRunning: "down", ctx: context.Background(), client: mcp.NewClient(&mcp.Implementation{Name: "x", Version: "0"}, nil)}
	start := time.Now()
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res, _ := p.call(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "list_flows"}}); res == nil || !res.IsError {
				t.Errorf("hung run: %+v", res)
			}
		}()
	}
	wg.Wait()
	if d := time.Since(start); d > 600*time.Millisecond {
		t.Errorf("3 calls took %v: each waited its own handshake", d)
	}
}

// A signal ends a call `run` does not answer (Proxy's context).
func TestProxySignalEndsCall(t *testing.T) {
	sock := sockPath(t)
	s := mcp.NewServer(&mcp.Implementation{Name: "reqcove", Version: Version}, nil)
	block := make(chan struct{})
	defer close(block)
	mcp.AddTool(s, &mcp.Tool{Name: "list_flows"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
		<-block // not even the cancel
		return nil, struct{}{}, nil
	})
	defer serve(t, sock, s)()
	pctx, signal := context.WithCancel(context.Background())
	p := &proxy{sock: sock, notRunning: "down", ctx: pctx, client: mcp.NewClient(&mcp.Implementation{Name: "x", Version: "0"}, nil)}
	done := make(chan struct{})
	go func() {
		p.call(context.Background(), &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "list_flows"}})
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	signal()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the call outlived the signal")
	}
}

// The agent's cancelling reaches `run`'s handler.
func TestProxyCancel(t *testing.T) {
	sock := sockPath(t)
	entered, cancelled := make(chan struct{}, 1), make(chan struct{}, 1)
	s := mcp.NewServer(&mcp.Implementation{Name: "slow", Version: Version}, nil)
	var first atomic.Bool
	mcp.AddTool(s, &mcp.Tool{Name: "list_flows"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, struct{}, error) {
		if first.CompareAndSwap(false, true) { // the first call waits for its cancel; later ones answer
			entered <- struct{}{}
			<-ctx.Done()
			cancelled <- struct{}{}
		}
		return nil, struct{}{}, nil
	})
	defer serve(t, sock, s)()
	cs := agent(t, sock)
	ctx, cancel := context.WithCancel(context.Background())
	go cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_flows"})
	<-entered
	cancel()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("run's handler never saw the cancel")
	}
	// The cancel was the agent's: the session to run stays, no note of a restart.
	if n := notes(t, cs); len(n) != 0 {
		t.Errorf("after a cancel: %v", n)
	}
}

// TestWithNoteKeepsOwn: the proxy's note joins a tool's own note (a
// --pass-hosts warning) rather than replacing it.
func TestWithNoteKeepsOwn(t *testing.T) {
	out := &mcp.CallToolResult{StructuredContent: map[string]any{"flows": []any{}, "note": "PASSNOTE"}}
	withNote(out, "RESTARTNOTE")
	m := out.StructuredContent.(map[string]any)
	if n, _ := m["note"].(string); !strings.Contains(n, "RESTARTNOTE") || !strings.Contains(n, "PASSNOTE") {
		t.Errorf("note: %q", n)
	}
}
