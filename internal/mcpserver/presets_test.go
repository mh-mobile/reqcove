package mcpserver

import (
	"context"
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
}

func (f *fakePresets) Presets(context.Context) ([]capture.Preset, error) {
	return []capture.Preset{{Name: "p", URL: "https://api.example.com/x"}}, nil
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

func (f *fakePresets) Deactivate(context.Context, string) (bool, error) { return true, nil }

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

// run's two servers: the local one has the preset tools, --mcp-http's none.
func TestServersPresetToolsLocalOnly(t *testing.T) {
	status := func() StatusOut { return StatusOut{} }
	local, remote := Servers(storeWith("a"), status, status, &fakePresets{})
	for _, c := range []struct {
		s    *mcp.Server
		want int
	}{{local, 3}, {remote, 0}} {
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
	srv := presetServer(f)
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
	f.onActivate = func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close() // run's side of the connection drops while the call is under way
		}
	}
	got, isErr := callText(t, cs, "activate_mock", map[string]any{"name": "p", "times": 1})
	if !isErr || !strings.Contains(got, "may or may not have taken effect") || f.activations.Load() != 1 {
		t.Errorf("%q %v, %d activations", got, isErr, f.activations.Load())
	}
}
