package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakePresets struct {
	activations atomic.Int32
	seconds     atomic.Int32
	onActivate  func()
	explained   atomic.Value // explain_rules' method, url and operation
}

func (f *fakePresets) Presets(context.Context) ([]capture.Preset, error) {
	return []capture.Preset{{Name: "p", Kind: "mock", URL: "https://api.example.com/x"}}, nil
}

func (f *fakePresets) Activate(_ context.Context, name string, seconds, times int) (capture.Activation, error) {
	f.activations.Add(1)
	f.seconds.Store(int32(seconds))
	if f.onActivate != nil {
		f.onActivate()
	}
	if name != "p" {
		return capture.Activation{}, errors.New("no preset named 'q'")
	}
	return capture.Activation{Name: name, ExpiresAt: 1.7e9}, nil
}

func (f *fakePresets) Deactivate(context.Context, string) (bool, error) {
	return true, nil
}

func (f *fakePresets) ListRules(context.Context) (capture.Rules, error) {
	return capture.Rules{Loaded: true, Rules: []capture.Rule{{Kind: "map_remote", Target: "https://staging.example.com"}}}, nil
}

func (f *fakePresets) Explain(_ context.Context, method, url, op string) (capture.Explanation, error) {
	f.explained.Store(method + " " + url + " " + op)
	return capture.Explanation{InScope: true, Loaded: true, Rewrites: []string{"map_remote"}}, nil
}

func callText(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error %v", name, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

func presetServer(f *fakePresets) *mcp.Server {
	s := New(storeWith("a"), nil)
	AddPresetTools(s, storeWith("a"), f)
	return s
}

func TestPresetTools(t *testing.T) {
	sock := sockPath(t)
	cs := agent(t, sock)
	f := &fakePresets{}
	defer serve(t, sock, presetServer(f))()
	if got, isErr := callText(t, cs, "activate_preset", map[string]any{"name": "p", "times": 1}); isErr || !strings.Contains(got, `"checkpoint"`) || !strings.Contains(got, `"expires_at"`) || f.seconds.Load() != 300 {
		t.Errorf("activate: %s %v (seconds %d)", got, isErr, f.seconds.Load())
	}
	if callText(t, cs, "activate_preset", map[string]any{"name": "p", "minutes": 0.5}); f.seconds.Load() != 30 {
		t.Errorf("half a minute: %d s", f.seconds.Load())
	}
	n := f.activations.Load()
	for _, m := range []any{6, 0, -1, 1e30} { // 0 is not "the default": a short time asked for
		if got, isErr := callText(t, cs, "activate_preset", map[string]any{"name": "p", "minutes": m}); !isErr || !strings.Contains(got, "at most 5") || f.activations.Load() != n {
			t.Errorf("%v minutes: %s %v", m, got, isErr)
		}
	}
	if got, isErr := callText(t, cs, "activate_preset", map[string]any{"name": "q"}); !isErr || !strings.Contains(got, "refused: no preset named 'q'") {
		t.Errorf("unknown: %s %v", got, isErr)
	}
	if got, isErr := callText(t, cs, "list_presets", nil); isErr || !strings.Contains(got, `"name":"p"`) {
		t.Errorf("list: %s %v", got, isErr)
	}
}

// run's two servers: the local one has the preset (and marker) tools, --mcp-http's none.
func TestServersPresetToolsLocalOnly(t *testing.T) {
	status := func() StatusOut { return StatusOut{} }
	local, remote := Servers(storeWith("a"), status, status, &fakePresets{})
	for _, c := range []struct {
		s    *mcp.Server
		want int
	}{{local, 7}, {remote, 0}} {
		ct, st := mcp.NewInMemoryTransports()
		if _, err := c.s.Connect(context.Background(), st, nil); err != nil {
			t.Fatal(err)
		}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for tool, err := range cs.Tools(context.Background(), nil) {
			if err != nil {
				t.Fatal(err)
			}
			if presetTools[tool.Name] {
				n++
			}
		}
		if n != c.want {
			t.Errorf("%d preset tools, want %d", n, c.want)
		}
	}
}

// --mcp-http's capture_stats, and the capture in its status, leave out where
// requests can be sent: resolve's addresses and the upstream proxy. The
// local server keeps them; counts and rules_error stay on both.
func TestRemoteStatsWithoutTargets(t *testing.T) {
	st := storeWith("a")
	st.Apply([]byte(`{"v":2,"ev":"hello","rules":{"resolve":1},"rules_error":"","resolve":["api.example.com -> 192.0.2.7:443"],"upstream":"127.0.0.1:8080"}`))
	status := func() StatusOut { return StatusOut{Capture: st.Stats()} }
	local, remote := Servers(st, status, status, &fakePresets{})
	for _, c := range []struct {
		s      *mcp.Server
		remote bool
	}{{local, false}, {remote, true}} {
		ct, sst := mcp.NewInMemoryTransports()
		if _, err := c.s.Connect(context.Background(), sst, nil); err != nil {
			t.Fatal(err)
		}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, tool := range []string{"capture_stats", "status"} {
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool})
			if err != nil || res.IsError {
				t.Fatalf("%s: %v %v", tool, err, res)
			}
			got := res.Content[0].(*mcp.TextContent).Text
			targets := strings.Contains(got, "192.0.2.7") || strings.Contains(got, "127.0.0.1:8080")
			if targets == c.remote || !strings.Contains(got, `"rules":{"resolve":1}`) {
				t.Errorf("%s (remote %v): %s", tool, c.remote, got)
			}
		}
	}
}

// list_rules and explain_rules are read-only (not in writeTools: the proxy may
// send them again); explain_rules takes a recorded flow's method, URL and
// operation, or method and url, not both.
func TestRuleTools(t *testing.T) {
	f := &fakePresets{}
	st := capture.NewStore(10, 1<<20)
	st.Apply([]byte(`{"v":2,"ev":"request","id":"f1","host":"h.example","method":"POST","url":"https://h.example/graphql","rewrites":["map_remote"],"mapped_url":"https://s.example:8443/graphql?x=1"}`))
	s := New(st, nil)
	AddPresetTools(s, st, f)
	ct, sst := mcp.NewInMemoryTransports()
	if _, err := s.Connect(context.Background(), sst, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	for tool, err := range cs.Tools(context.Background(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		if (tool.Name == "list_rules" || tool.Name == "explain_rules") && (tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || writeTools[tool.Name]) {
			t.Errorf("%s is not read-only", tool.Name)
		}
	}
	if got, isErr := callText(t, cs, "list_rules", nil); isErr || !strings.Contains(got, `"target":"https://staging.example.com"`) {
		t.Errorf("list_rules: %s %v", got, isErr)
	}
	got, isErr := callText(t, cs, "explain_rules", map[string]any{"flow_id": "f1"})
	if isErr || f.explained.Load() != "POST https://h.example/graphql " || !strings.Contains(got, `"recorded":{"mapped_to":"https://s.example:8443","mocked":false,"presets":[],"rewrites":["map_remote"]}`) {
		t.Errorf("flow_id: %s %v (%v)", got, isErr, f.explained.Load())
	}
	// An anonymous query's record says so to the addon (no operation mock answers it); a
	// hello since (a reconnect too) moves rules_loaded: the rules may have changed, not were.
	st.Apply([]byte(`{"v":2,"ev":"request","id":"f2","host":"h.example","method":"GET","url":"https://h.example/graphql?query=%7Ba%7D","ts":1}`))
	st.Apply([]byte(`{"v":2,"ev":"hello","rules":{"mock":0}}`))
	got, isErr = callText(t, cs, "explain_rules", map[string]any{"flow_id": "f2"})
	if isErr || f.explained.Load() != "GET https://h.example/graphql?query=%7Ba%7D (anonymous)" || !strings.Contains(got, "may have changed since this flow") {
		t.Errorf("anonymous: %s %v (%v)", got, isErr, f.explained.Load())
	}
	if got, isErr := callText(t, cs, "explain_rules", map[string]any{"method": "GET", "url": "https://h.example/", "operation": "Feed"}); isErr || f.explained.Load() != "GET https://h.example/ Feed" {
		t.Errorf("method and url: %s %v", got, isErr)
	}
	for _, args := range []map[string]any{nil, {"flow_id": "f1", "method": "GET"}, {"url": "https://h.example/"}, {"method": "GET", "url": "https://h.example/", "operation": "a b"}} {
		if got, isErr := callText(t, cs, "explain_rules", args); !isErr {
			t.Errorf("%v accepted: %s", args, got)
		}
	}
}

// A run without the preset tools (v0.5) answers activate_preset with a tool
// error that says so, not a protocol error.
func TestPresetToolsOlderRun(t *testing.T) {
	sock := sockPath(t)
	cs := agent(t, sock)
	defer serve(t, sock, New(storeWith("a"), nil))()
	for _, tool := range []string{"list_presets", "activate_preset"} {
		if got, isErr := callText(t, cs, tool, map[string]any{"name": "p"}); !isErr || !strings.Contains(got, "has no "+tool) {
			t.Errorf("%s: %q %v", tool, got, isErr)
		}
	}
}

// A write whose connection closes mid-call is never sent again: the first may
// have landed, and a second would reset a count of 1. The listener stays, so a
// resend would reach it.
func TestProxyNeverResendsAWrite(t *testing.T) {
	sock := sockPath(t)
	cs := agent(t, sock)
	f := &fakePresets{}
	st := storeWith("a")
	srv := New(st, nil)
	AddPresetTools(srv, st, f)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() {
				if ss, err := srv.Connect(context.Background(), &mcp.IOTransport{Reader: c, Writer: c}, nil); err == nil {
					ss.Wait()
				}
			}()
		}
	}()
	drop := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close() // run's side of the connection drops while the call is under way
		}
	}
	f.onActivate = drop
	got, isErr := callText(t, cs, "activate_preset", map[string]any{"name": "p", "times": 1})
	if !isErr || !strings.Contains(got, "may or may not have taken effect; call list_presets to see") || f.activations.Load() != 1 {
		t.Errorf("%q %v, %d activations", got, isErr, f.activations.Load())
	}
	// add_marker too: a second would be a second marker.
	srv.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			res, err := next(ctx, method, req)
			if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok && p.Name == "add_marker" {
				drop()
			}
			return res, err
		}
	})
	// The next write reaches run (dialled again), not the dropped session.
	got, isErr = callText(t, cs, "add_marker", map[string]any{"text": "tap"})
	if n := len(st.Markers(0)); !isErr || !strings.Contains(got, "call list_markers to see") || n != 1 {
		t.Errorf("add_marker: %q %v, %d markers", got, isErr, n)
	}
}

// status's active_presets has every kind on now, and active_presets_error
// when mitmproxy did not say; v0.6's active_mock_presets and
// active_mock_presets_error are gone (removed in v1.0).
func TestStatusActivePresets(t *testing.T) {
	keys := func(o StatusOut) map[string]any {
		var got map[string]any
		b, _ := json.Marshal(o)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	var o StatusOut
	o.SetActivePresets([]capture.Preset{{Name: "m", Kind: "mock", Active: true}, {Name: "s", Kind: "map_remote", Active: true}, {Name: "off", Kind: "mock"}}, nil)
	got := keys(o)
	if a, _ := got["active_presets"].([]any); len(a) != 2 || got["active_mock_presets"] != nil {
		t.Errorf("active_presets %v, active_mock_presets %v", got["active_presets"], got["active_mock_presets"])
	}
	o = StatusOut{}
	o.SetActivePresets(nil, errors.New("no answer"))
	if got := keys(o); got["active_presets_error"] != "no answer" || got["active_mock_presets_error"] != nil || got["active_presets"] != nil {
		t.Errorf("errors: %v", got)
	}
}

// v0.6's names, removed in v1.0, are in no tool list (run's local socket,
// --mcp-http, a v1.0 reqcove mcp), no tool's description and not the
// instructions.
func TestRemovedNamesGone(t *testing.T) {
	status := func() StatusOut { return StatusOut{} }
	local, remote := Servers(storeWith("a"), status, status, &fakePresets{})
	proxied, err := toolList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lists := map[string][]*mcp.Tool{"proxy": proxied}
	for name, s := range map[string]*mcp.Server{"local": local, "remote": remote} {
		ct, st := mcp.NewInMemoryTransports()
		if _, err := s.Connect(context.Background(), st, nil); err != nil {
			t.Fatal(err)
		}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := cs.InitializeResult().Instructions; strings.Contains(got, "_mock") {
			t.Errorf("%s: instructions name a removed tool", name)
		}
		for tool, err := range cs.Tools(context.Background(), nil) {
			if err != nil {
				t.Fatal(err)
			}
			lists[name] = append(lists[name], tool)
		}
	}
	for name, tools := range lists {
		if len(tools) < 10 {
			t.Errorf("%s: only %d tools", name, len(tools))
		}
		for _, tool := range tools {
			if _, old := removedTools[tool.Name]; old {
				t.Errorf("%s lists %s", name, tool.Name)
			}
			if strings.Contains(tool.Description, "mock_presets") || strings.Contains(tool.Description, "_mock") || strings.Contains(tool.Description, "eprecated") {
				t.Errorf("%s: %s's description names a removed name: %q", name, tool.Name, tool.Description)
			}
		}
	}
}

// A call to a removed tool is told what replaces it, as a tool error, not a
// protocol error: by run's local socket (what an older reqcove mcp, which
// still lists them, forwards the call to) and by a v1.0 reqcove mcp (whatever
// run it talks to: here one without any preset tool).
func TestRemovedToolsAnswer(t *testing.T) {
	ct, st := mcp.NewInMemoryTransports()
	status := func() StatusOut { return StatusOut{} }
	local, _ := Servers(storeWith("a"), status, status, &fakePresets{})
	if _, err := local.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	run, err := mcp.NewClient(&mcp.Implementation{Name: "reqcove-mcp", Version: "0.8.0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	sock := sockPath(t)
	proxy := agent(t, sock)
	defer serve(t, sock, New(storeWith("a"), nil))()
	for _, cs := range []*mcp.ClientSession{run, proxy} {
		for old, use := range removedTools {
			got, isErr := callText(t, cs, old, map[string]any{"name": "p"})
			if !isErr || !strings.HasPrefix(got, old+" was removed in v1.0: use "+use+" ") || !strings.Contains(got, "reconnect the agent's MCP server") {
				t.Errorf("%s: %q %v", old, got, isErr)
			}
		}
	}
	// Other unknown tools stay unknown.
	if _, err := run.CallTool(context.Background(), &mcp.CallToolParams{Name: "activate_mocks"}); err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("activate_mocks: %v", err)
	}
}
