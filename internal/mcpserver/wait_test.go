package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestWaitForFlows, over the stdio proxy as an agent has it: a checkpoint
// taken before acting, a flow answered after it comes back; the next call,
// from its after, times out normally; a cursor of an earlier run is refused.
func TestWaitForFlows(t *testing.T) {
	sock := sockPath(t)
	st := capture.NewStore(10, 1<<20)
	defer serve(t, sock, New(st, nil))()
	cs := agent(t, sock)

	cp := call[ListOut](t, cs, "list_flows", map[string]any{}).Checkpoint
	go func() {
		time.Sleep(100 * time.Millisecond) // the agent's tap, then the app's request
		st.Apply([]byte(`{"v":2,"ev":"request","id":"tap","device":"d","host":"api.example.com","url":"https://api.example.com/like"}`))
		st.Apply([]byte(`{"v":2,"ev":"response","id":"tap","status":201}`))
	}()
	start := time.Now()
	w := call[WaitOut](t, cs, "wait_for_flows", map[string]any{"after": cp, "host": "example.com", "timeout": 10})
	if len(w.Flows) != 1 || w.Flows[0].ID != "tap" || w.Flows[0].Status != 201 || w.TimedOut || time.Since(start) > 5*time.Second {
		t.Fatalf("wait: %+v in %v", w, time.Since(start))
	}
	w2 := call[WaitOut](t, cs, "wait_for_flows", map[string]any{"after": w.After, "timeout": 1})
	if len(w2.Flows) != 0 || !w2.TimedOut || w2.After != w.After {
		t.Errorf("the next wait: %+v", w2)
	}

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "wait_for_flows", Arguments: map[string]any{"after": 1}})
	if err != nil || !res.IsError {
		t.Errorf("an earlier run's cursor: %v %+v", err, res)
	}
}

// TestWaitReleased: waits an agent gave up on free their place at once: a
// cancel over stdio, a disconnect over --mcp-http (the SDK does not end a
// tool when its HTTP request ends: endWithRequest does). More of each than
// maxWaiters, and a wait still runs after.
func TestWaitReleased(t *testing.T) {
	sock := sockPath(t)
	st := capture.NewStore(10, 1<<20)
	server := New(st, nil)
	defer serve(t, sock, server)()
	cs := agent(t, sock)
	srv := httptest.NewServer(HTTP(server, "tok", noCaller))
	hc, err := httpClient(t, srv.URL, "Bearer tok")
	if err != nil {
		t.Fatal(err)
	}
	abandon := func(s *mcp.ClientSession) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		s.CallTool(ctx, &mcp.CallToolParams{Name: "wait_for_flows", Arguments: map[string]any{"timeout": 30}})
	}
	for _, s := range []*mcp.ClientSession{cs, hc} {
		for range maxWaiters + 2 {
			abandon(s)
		}
		// Past --mcp-http's one-second window (at most 10 calls a second),
		// which the abandoned calls filled.
		time.Sleep(1100 * time.Millisecond)
		res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: "wait_for_flows", Arguments: map[string]any{"timeout": 1}})
		if err != nil || res.IsError {
			t.Fatalf("after the abandoned waits: %v %+v", err, res)
		}
	}
	start := time.Now()
	srv.Close() // waits for the handlers still running
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("HTTP handlers ran on %v after their callers left", d)
	}
}

// TestWaitCursorFromTheFuture: an after no checkpoint gave (a clock reading,
// say) is refused, not waited on forever.
func TestWaitCursorFromTheFuture(t *testing.T) {
	sock := sockPath(t)
	st := capture.NewStore(10, 1<<20)
	defer serve(t, sock, New(st, nil))()
	cs := agent(t, sock)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "wait_for_flows", Arguments: map[string]any{"after": st.Checkpoint() + 1000, "timeout": 1}})
	if err != nil || !res.IsError {
		t.Errorf("a cursor past the newest: %v %+v", err, res)
	}
	if cp := call[ListOut](t, cs, "search_flows", map[string]any{"query": "x"}).Checkpoint; cp == 0 {
		t.Error("search_flows gives no checkpoint")
	}
}

// TestWaitPlacesPerCaller: one device over --mcp-http holds at most
// maxWaitersPerCaller waits; the socket's agent still gets one.
func TestWaitPlacesPerCaller(t *testing.T) {
	sock := sockPath(t)
	st := capture.NewStore(10, 1<<20)
	server := New(st, nil)
	defer serve(t, sock, server)()
	srv := httptest.NewServer(HTTP(server, "tok", func(*http.Request) string { return "busy-device" }))
	defer srv.Close()
	hc, err := httpClient(t, srv.URL, "Bearer tok")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for range maxWaitersPerCaller {
		go hc.CallTool(ctx, &mcp.CallToolParams{Name: "wait_for_flows", Arguments: map[string]any{"timeout": 30}})
	}
	time.Sleep(300 * time.Millisecond)
	res, err := hc.CallTool(context.Background(), &mcp.CallToolParams{Name: "wait_for_flows", Arguments: map[string]any{"timeout": 1}})
	if err != nil || !res.IsError {
		t.Errorf("one more from the busy device: %v %+v", err, res)
	}
	if res, err := agent(t, sock).CallTool(context.Background(), &mcp.CallToolParams{Name: "wait_for_flows", Arguments: map[string]any{"timeout": 1}}); err != nil || res.IsError {
		t.Errorf("the local agent: %v %+v", err, res)
	}
}
