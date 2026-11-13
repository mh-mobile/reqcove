package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Markers: the source comes from the client's name, which the stdio proxy
// sets (reqcove-mcp), so an agent cannot claim cli, by its own name or an
// argument; the text is masked, refused when long or not one line (never
// quoted); checkpoint and time serve wait_for_flows' after and since.
func TestMarkers(t *testing.T) {
	sock := sockPath(t)
	st := capture.NewStore(10, 1<<20)
	st.Apply(fmt.Appendf(nil, `{"v":2,"ev":"request","id":"a","host":"h.example","url":"https://h.example/a","ts":%f}`, float64(time.Now().Add(-time.Minute).UnixMilli())/1000))
	st.Apply([]byte(`{"v":2,"ev":"response","id":"a","status":200}`))
	srv := New(st, nil)
	AddPresetTools(srv, st, noPresets{})
	defer serve(t, sock, srv)()
	ctx := context.Background()
	old := redialAfter
	redialAfter = 0
	t.Cleanup(func() { redialAfter = old })
	ct, pt := mcp.NewInMemoryTransports()
	go Proxy(t.Context(), sock, "not running", pt)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: MarkClient}, nil).Connect(ctx, ct, nil) // an agent calling itself reqcove-mark
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	if got, isErr := callText(t, cs, "add_marker", map[string]any{"text": "x", "source": "cli"}); !isErr || !strings.Contains(got, "source") {
		t.Errorf("source as an argument: %s %v", got, isErr)
	}
	got, isErr := callText(t, cs, "add_marker", map[string]any{"text": "tap Pay, auth: Bearer S3CRET8abcdefgh"})
	var m MarkOut
	json.Unmarshal([]byte(got), &m)
	if isErr || m.ID != 1 || m.Time == "" || m.Checkpoint != st.Checkpoint() {
		t.Fatalf("add_marker: %s %v", got, isErr)
	}
	st.Apply(fmt.Appendf(nil, `{"v":2,"ev":"request","id":"b","host":"h.example","url":"https://h.example/b","ts":%f}`, float64(time.Now().UnixMilli())/1000))
	st.Apply([]byte(`{"v":2,"ev":"response","id":"b","status":200}`))
	if got, _ := callText(t, cs, "wait_for_flows", map[string]any{"after": m.Checkpoint, "timeout": 1}); !strings.Contains(got, `"id":"b"`) || strings.Contains(got, `"id":"a"`) {
		t.Errorf("wait_for_flows after the checkpoint: %s", got)
	}
	if got, _ := callText(t, cs, "list_flows", map[string]any{"since": m.Time}); !strings.Contains(got, `"id":"b"`) || strings.Contains(got, `"id":"a"`) {
		t.Errorf("list_flows since the time: %s", got)
	}
	got, _ = callText(t, cs, "list_markers", map[string]any{"since": m.Time})
	if !strings.Contains(got, `"source":"mcp"`) || strings.Contains(got, "S3CRET") || !strings.Contains(got, "Bearer [redacted]") || !strings.Contains(got, `"id":1`) {
		t.Errorf("list_markers: %s", got)
	}

	// reqcove mark's own connection: cli.
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := mcp.NewClient(&mcp.Implementation{Name: MarkClient}, nil).Connect(ctx, &mcp.IOTransport{Reader: conn, Writer: conn}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	if got, isErr := callText(t, direct, "add_marker", map[string]any{"text": ""}); isErr || len(st.Markers(0)) != 2 || st.Markers(0)[1].Source != "cli" {
		t.Errorf("reqcove mark's marker: %s %+v", got, st.Markers(0))
	}

	for _, text := range []string{strings.Repeat("x", 81), "S3CRET\nsecond line", "a\tb", "a b", "a\x1b[2Jb"} {
		if got, isErr := callText(t, cs, "add_marker", map[string]any{"text": text}); !isErr || strings.Contains(got, "S3CRET") || strings.Contains(got, "xxx") {
			t.Errorf("%q: %s %v", text, got, isErr)
		}
	}
	if got, isErr := callText(t, cs, "add_marker", map[string]any{"text": strings.Repeat("あ", 80)}); isErr {
		t.Errorf("80 characters: %s", got)
	}
	if n := len(st.Markers(0)); n != 3 {
		t.Errorf("%d markers, want 3", n)
	}
}
