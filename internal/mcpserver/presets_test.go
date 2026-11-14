package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
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
	kind        atomic.Value // the kind the last call passed
	explained   atomic.Value // explain_rules' method, url and operation
}

func (f *fakePresets) Presets(_ context.Context, kind string) ([]capture.Preset, error) {
	f.kind.Store(kind)
	return []capture.Preset{{Name: "p", Kind: "mock", URL: "https://api.example.com/x"}}, nil
}

func (f *fakePresets) Activate(_ context.Context, name, kind string, seconds, times int) (capture.Activation, error) {
	f.kind.Store(kind)
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

func (f *fakePresets) Deactivate(_ context.Context, _, kind string) (bool, error) {
	f.kind.Store(kind)
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
	if got, isErr := callText(t, cs, "activate_mock", map[string]any{"name": "p", "times": 1}); isErr || !strings.Contains(got, `"checkpoint"`) || !strings.Contains(got, `"expires_at"`) || f.seconds.Load() != 300 {
		t.Errorf("activate: %s %v (seconds %d)", got, isErr, f.seconds.Load())
	}
	if callText(t, cs, "activate_mock", map[string]any{"name": "p", "minutes": 0.5}); f.seconds.Load() != 30 {
		t.Errorf("half a minute: %d s", f.seconds.Load())
	}
	n := f.activations.Load()
	for _, m := range []any{6, 0, -1, 1e30} { // 0 is not "the default": a short time asked for
		if got, isErr := callText(t, cs, "activate_mock", map[string]any{"name": "p", "minutes": m}); !isErr || !strings.Contains(got, "at most 5") || f.activations.Load() != n {
			t.Errorf("%v minutes: %s %v", m, got, isErr)
		}
	}
	if got, isErr := callText(t, cs, "activate_mock", map[string]any{"name": "q"}); !isErr || !strings.Contains(got, "refused: no preset named 'q'") {
		t.Errorf("unknown: %s %v", got, isErr)
	}
	if got, isErr := callText(t, cs, "list_mock_presets", nil); isErr || !strings.Contains(got, `"name":"p"`) {
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
	}{{local, 10}, {remote, 0}} {
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

// A run without the preset tools (v0.5) answers activate_mock with a tool
// error that says so, not a protocol error.
func TestPresetToolsOlderRun(t *testing.T) {
	sock := sockPath(t)
	cs := agent(t, sock)
	defer serve(t, sock, New(storeWith("a"), nil))()
	for _, tool := range []string{"list_mock_presets", "activate_mock"} {
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
	got, isErr := callText(t, cs, "activate_mock", map[string]any{"name": "p", "times": 1})
	if !isErr || !strings.Contains(got, "may or may not have taken effect; call list_mock_presets to see") || f.activations.Load() != 1 {
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

// The v0.6 tools are for mocks only: a user who allowed activate_mock did not
// allow switching where requests go (map_remote, resolve). The *_preset tools
// take every kind.
func TestPresetToolKinds(t *testing.T) {
	f := &fakePresets{}
	ct, st := mcp.NewInMemoryTransports()
	if _, err := presetServer(f).Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tool string
		args map[string]any
		kind string
	}{
		{"list_mock_presets", nil, "mock"}, {"activate_mock", map[string]any{"name": "p"}, "mock"}, {"deactivate_mock", map[string]any{"name": "p"}, "mock"},
		{"list_presets", nil, ""}, {"activate_preset", map[string]any{"name": "p"}, ""}, {"deactivate_preset", map[string]any{"name": "p"}, ""},
	} {
		f.kind.Store("unset")
		if got, isErr := callText(t, cs, c.tool, c.args); isErr {
			t.Errorf("%s: %s", c.tool, got)
		}
		if k := f.kind.Load(); k != c.kind {
			t.Errorf("%s passed kind %q, want %q", c.tool, k, c.kind)
		}
	}
}

// status's active_presets has every kind on now; active_mock_presets (v0.6's
// name, removed in v1.0) the same until then, and so their errors.
func TestStatusActivePresets(t *testing.T) {
	var o StatusOut
	o.SetActivePresets([]capture.Preset{{Name: "m", Kind: "mock", Active: true}, {Name: "s", Kind: "map_remote", Active: true}, {Name: "off", Kind: "mock"}}, nil)
	var got map[string]any
	b, _ := json.Marshal(o)
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if a, _ := got["active_presets"].([]any); len(a) != 2 || !reflect.DeepEqual(got["active_mock_presets"], got["active_presets"]) {
		t.Errorf("active_presets %v, active_mock_presets %v", got["active_presets"], got["active_mock_presets"])
	}
	o = StatusOut{}
	o.SetActivePresets(nil, errors.New("no answer"))
	if o.PresetsError != "no answer" || o.MockPresetsError != o.PresetsError || o.ActivePresets != nil {
		t.Errorf("errors: %q %q", o.PresetsError, o.MockPresetsError)
	}
}

// The v0.6 tools say they go in v1.0, and what replaces them.
func TestMockToolsDeprecated(t *testing.T) {
	ct, st := mcp.NewInMemoryTransports()
	if _, err := presetServer(&fakePresets{}).Connect(context.Background(), st, nil); err != nil {
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
		deprecated := strings.HasPrefix(tool.Description, "Deprecated, removed in v1.0: use list_presets / activate_preset / deactivate_preset.")
		if old := tool.Name == mockPresets.list || tool.Name == mockPresets.activate || tool.Name == mockPresets.deactivate; old != deprecated {
			t.Errorf("%s: %q", tool.Name, tool.Description)
		} else if old {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d deprecated tools, want 3", n)
	}
}

// status and capture_stats name the new fields and the v0.6 ones as deprecated.
func TestDeprecatedFieldsDescribed(t *testing.T) {
	ct, st := mcp.NewInMemoryTransports()
	if _, err := New(storeWith("a"), func() StatusOut { return StatusOut{} }).Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"status":        "active_presets; active_mock_presets is the same list, deprecated, removed in v1.0",
		"capture_stats": "presets; mock_presets the same, deprecated, removed in v1.0",
	}
	for tool, err := range cs.Tools(context.Background(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		if w, ok := want[tool.Name]; ok {
			if !strings.Contains(tool.Description, w) {
				t.Errorf("%s: %q lacks %q", tool.Name, tool.Description, w)
			}
			delete(want, tool.Name)
		}
	}
	if len(want) != 0 {
		t.Errorf("tools not seen: %v", want)
	}
}
