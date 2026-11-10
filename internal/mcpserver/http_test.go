package mcpserver

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type withHeader struct {
	auth string
	rt   http.RoundTripper
}

func (h withHeader) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", h.auth)
	return h.rt.RoundTrip(r)
}

func httpClient(t *testing.T, url, auth string) (*mcp.ClientSession, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	ct := &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: &http.Client{Transport: withHeader{auth, http.DefaultTransport}}, MaxRetries: -1}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err == nil {
		t.Cleanup(func() { cs.Close() })
	}
	return cs, err
}

// TestHTTP: the tools over HTTP for the token only, with the instructions, and
// not from a browser page of another origin.
func TestHTTP(t *testing.T) {
	srv := httptest.NewServer(HTTP(New(testStore(t), nil), "tok", noCaller))
	defer srv.Close()

	for _, auth := range []string{"", "Bearer", "Bearer ", "Bearer tok2", "bearer tok", "tok"} {
		if _, err := httpClient(t, srv.URL, auth); err == nil {
			t.Errorf("Authorization %q: connected", auth)
		}
	}
	cs, err := httpClient(t, srv.URL, "Bearer tok")
	if err != nil {
		t.Fatal(err)
	}
	if got := cs.InitializeResult().Instructions; got != Instructions {
		t.Errorf("instructions: %q", got)
	}
	if list := call[ListOut](t, cs, "list_flows", map[string]any{}); len(list.Flows) != 1 {
		t.Errorf("list_flows: %+v", list)
	}

	// A page of another origin, with the token (it cannot read it, but say it guessed).
	req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin: %v %v", r.StatusCode, err)
	}
}

func TestHTTPNoToken(t *testing.T) {
	// Directly: over the wire a trailing space would be trimmed from the header.
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	r.Header.Set("Authorization", "Bearer ")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	HTTP(New(testStore(t), nil), "", noCaller).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("an empty token let a caller in: %d", w.Code)
	}
}

// TestHTTPAcrossRestarts: stateless, so a client goes on with the next run
// (another server at the same address) without reconnecting.
func TestHTTPAcrossRestarts(t *testing.T) {
	var h http.Handler = HTTP(New(testStore(t), nil), "tok", noCaller)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	defer srv.Close()
	cs, err := httpClient(t, srv.URL, "Bearer tok")
	if err != nil {
		t.Fatal(err)
	}
	call[StatsOut](t, cs, "capture_stats", map[string]any{})
	h = HTTP(New(capture.NewStore(10, 1<<20), nil), "tok", noCaller) // the next run, its records empty
	if list := call[ListOut](t, cs, "list_flows", map[string]any{}); len(list.Flows) != 0 {
		t.Errorf("after the restart: %+v", list)
	}
}

// TestProxyInstructions: agents on stdio get the instructions too.
func TestProxyInstructions(t *testing.T) {
	cs := agent(t, filepath.Join(t.TempDir(), "none.sock"))
	if got := cs.InitializeResult().Instructions; got != Instructions {
		t.Errorf("instructions over stdio: %q", got)
	}
}

// TestOldCursor: a cursor of an earlier run is refused, not read as this run's.
func TestOldCursor(t *testing.T) {
	old := capture.NewStore(10, 1<<20)
	old.Apply([]byte(`{"v":2,"ev":"request","id":"x","device":"d","host":"a.example","url":"https://a.example/"}`))
	old.Apply([]byte(`{"v":2,"ev":"request","id":"y","device":"d","host":"a.example","url":"https://a.example/"}`))
	_, cursor := old.List(capture.Filter{Limit: 1})
	if cursor == 0 {
		t.Fatal("no cursor")
	}
	time.Sleep(5 * time.Millisecond)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := New(testStore(t), nil).Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_flows", Arguments: map[string]any{"cursor": cursor}})
	if err != nil || !res.IsError {
		t.Errorf("an earlier run's cursor: %v %+v", err, res)
	}
	// This run's cursor still pages.
	cur := New(old, nil)
	ct2, st2 := mcp.NewInMemoryTransports()
	if _, err := cur.Connect(context.Background(), st2, nil); err != nil {
		t.Fatal(err)
	}
	cs2, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs2.Close()
	if page := call[ListOut](t, cs2, "list_flows", map[string]any{"cursor": cursor}); len(page.Flows) != 1 || page.Flows[0].ID != "x" {
		t.Errorf("this run's cursor: %+v", page)
	}
}

func noCaller(*http.Request) string { return "" }

// TestHTTPLog: a tool call over HTTP is logged with its caller and the tool's
// name, not its arguments; a wrong token too; calls on the socket are not.
func TestHTTPLog(t *testing.T) {
	var buf strings.Builder
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	server := New(testStore(t), nil)
	srv := httptest.NewServer(HTTP(server, "tok", func(*http.Request) string { return "grok-bot (100.64.0.7)" }))
	defer srv.Close()
	httpClient(t, srv.URL, "Bearer nope")
	cs, err := httpClient(t, srv.URL, "Bearer tok")
	if err != nil {
		t.Fatal(err)
	}
	call[ListOut](t, cs, "search_flows", map[string]any{"query": "secret-query"})

	ct, st := mcp.NewInMemoryTransports() // the socket's way in
	if _, err := server.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	local, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	call[ListOut](t, local, "list_flows", map[string]any{})

	got := buf.String()
	for _, w := range []string{"--mcp-http: grok-bot (100.64.0.7) sent no token or a wrong one", "--mcp-http: grok-bot (100.64.0.7) called search_flows"} {
		if !strings.Contains(got, w) {
			t.Errorf("%q not in the log:\n%s", w, got)
		}
	}
	if strings.Contains(got, "secret-query") || strings.Contains(got, "list_flows") || strings.Contains(got, "Bearer") {
		t.Errorf("arguments, socket calls or the token in the log:\n%s", got)
	}
}
