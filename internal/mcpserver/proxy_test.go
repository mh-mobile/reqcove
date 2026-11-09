package mcpserver

import (
	"context"
	"encoding/json"
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

// ids calls list_flows: the flow ids, or the tool error's text.
func ids(t *testing.T, cs *mcp.ClientSession) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_flows"})
	if err != nil {
		t.Fatalf("protocol error: %v", err)
	}
	if res.IsError {
		return res.Content[0].(*mcp.TextContent).Text, true
	}
	var out ListOut
	b, _ := json.Marshal(res.StructuredContent)
	json.Unmarshal(b, &out)
	var s []string
	for _, f := range out.Flows {
		s = append(s, f.ID)
	}
	return strings.Join(s, ","), false
}

// The agent's one session lives on while `run` is down, restarts, and comes
// back: no reconnecting on its side (Claude Code's /mcp).
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
	if len(names) != 8 || !strings.Contains(strings.Join(names, ","), "status") { // the tools, without run
		t.Errorf("tools without run: %v", names)
	}
	if got, isErr := ids(t, cs); !isErr || got != "reqcove is not running (test)" {
		t.Errorf("before run: %q %v", got, isErr)
	}
	stop := serve(t, sock, New(storeWith("a"), nil))
	if got, _ := ids(t, cs); got != "a" {
		t.Fatalf("first run: %q", got)
	}
	stop()
	stop = serve(t, sock, New(storeWith("b"), nil))
	if got, _ := ids(t, cs); got != "b" { // no call in between: the dead session is found by this one
		t.Fatalf("after a restart: %q", got)
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
	p := &proxy{sock: sock, client: mcp.NewClient(&mcp.Implementation{Name: "x", Version: "0"}, nil)}
	ctx := context.Background()
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

// `run`'s own answers go back as they are, sent once: an error of the tool's
// is not taken for `run` being down.
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
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "search_flows", Arguments: map[string]any{}})
	if err != nil || !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, `missing properties: ["query"]`) || calls.Load() != 1 {
		t.Errorf("search_flows without query: %v %q, %d calls", err, res.Content[0].(*mcp.TextContent).Text, calls.Load())
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_flows", Arguments: map[string]any{"hots": "x"}}); err == nil && calls.Load() != 2 {
		t.Errorf("a misspelt argument: %d calls", calls.Load())
	}
}

// The agent's cancelling reaches `run`'s handler.
func TestProxyCancel(t *testing.T) {
	sock := sockPath(t)
	entered, cancelled := make(chan struct{}, 1), make(chan struct{}, 1)
	s := mcp.NewServer(&mcp.Implementation{Name: "slow", Version: "0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "list_flows"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, struct{}, error) {
		entered <- struct{}{}
		<-ctx.Done()
		cancelled <- struct{}{}
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
}
