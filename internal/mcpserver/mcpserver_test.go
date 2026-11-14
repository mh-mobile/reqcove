package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func testStore(t *testing.T) *capture.Store {
	st := capture.NewStore(10, 1<<20)
	for _, l := range []string{
		`{"v":2,"ev":"request","id":"a","device":"dev-1","host":"api.example.net","url":"https://api.example.net/x","headers":[["Authorization","Bearer s3cret"]]}`,
		`{"v":2,"ev":"response","id":"a","status":200}`,
		`{"v":2,"ev":"body","id":"a","dir":"response","head":"aGVsbG8=","size":5,"final":true,"decoded":true}`,
		`{"v":2,"ev":"done","id":"a"}`,
		`{"v":2,"ev":"tls_failed","conn":"c1","device":"dev-1","sni":"pinned.example.net","ts":1794000000}`,
	} {
		st.Apply([]byte(l))
	}
	st.SetDeviceNames(map[string]string{"dev-1": "iphone-test"})
	return st
}

func call[T any](t *testing.T, s *mcp.ClientSession, name string, args any) T {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || res.IsError {
		t.Fatalf("%s: %v %+v", name, err, res)
	}
	var out T
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTools(t *testing.T) {
	ct, st := mcp.NewInMemoryTransports()
	server := New(testStore(t), nil)
	if _, err := server.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	list := call[ListOut](t, session, "list_flows", map[string]any{"device": "iphone-test"})
	if len(list.Flows) != 1 || list.Flows[0].DeviceName != "iphone-test" || list.Flows[0].Status != 200 {
		t.Fatalf("list_flows by device name = %+v", list.Flows)
	}
	v := call[capture.FlowView](t, session, "get_flow", map[string]any{"id": "a", "bodies": true})
	if v.RespBodyText != "hello" || v.ReqHeaders[0][1] != "[redacted]" || v.DeviceName != "iphone-test" {
		t.Fatalf("get_flow = %+v", v)
	}
	if v := call[capture.FlowView](t, session, "get_flow", map[string]any{"id": "a", "bodies": true, "max_body": 2}); v.RespBodyText != "he" || len(v.Notes) != 1 || !strings.Contains(v.Notes[0], "max_body") {
		t.Errorf("get_flow max_body 2: %q %v", v.RespBodyText, v.Notes)
	}
	if v := call[capture.FlowView](t, session, "get_flow", map[string]any{"id": "a", "bodies": true}); v.RespBodyText != "hello" || len(v.Notes) != 0 {
		t.Errorf("get_flow after a max_body: %q %v (the record changed)", v.RespBodyText, v.Notes)
	}
	if s := call[StatsOut](t, session, "capture_stats", nil); s.Stats["flows"] != float64(1) {
		t.Fatalf("capture_stats = %v", s.Stats)
	}

	// Filters reach the store through the embedded input structs.
	if got := call[ListOut](t, session, "list_flows", map[string]any{"host": "example.net", "status": "2xx", "limit": 1}); len(got.Flows) != 1 {
		t.Errorf("list_flows host+status = %+v", got)
	}
	if got := call[ListOut](t, session, "list_flows", map[string]any{"status": "4xx"}); len(got.Flows) != 0 || got.Flows == nil { // [], not null
		t.Errorf("list_flows 4xx = %+v", got)
	}
	found := call[ListOut](t, session, "search_flows", map[string]any{"query": "API.EXAMPLE"})
	if len(found.Flows) != 1 || found.Flows[0].MatchedIn[0] != "url" {
		t.Errorf("search_flows url = %+v", found)
	}
	if got := call[ListOut](t, session, "search_flows", map[string]any{"query": "hello"}); len(got.Flows) != 0 {
		t.Errorf("search_flows looked in bodies without bodies: %+v", got)
	}
	if got := call[ListOut](t, session, "search_flows", map[string]any{"query": "hello", "bodies": true}); len(got.Flows) != 1 || got.Flows[0].MatchedIn[0] != "response_body" {
		t.Errorf("search_flows bodies = %+v", got)
	}
	if got := call[ListOut](t, session, "search_flows", map[string]any{"query": "s3cret"}); len(got.Flows) != 0 {
		t.Errorf("a masked secret was found: %+v", got)
	}
	sum := call[capture.Counts](t, session, "summarize", map[string]any{"device": "iphone-test"})
	if sum.Flows != 1 || sum.ByHost[0] != (capture.Count{Key: "api.example.net", Count: 1}) || sum.ByStatus[0].Key != "200" || sum.ByDevice[0].Key != "iphone-test" {
		t.Errorf("summarize = %+v", sum)
	}
	devs := call[DevicesOut](t, session, "list_devices", nil)
	if len(devs.Devices) != 1 || devs.Devices[0].Name != "iphone-test" || devs.Devices[0].Flows != 1 || !devs.Devices[0].Carried {
		t.Errorf("list_devices = %+v", devs)
	}
	if tls := call[TLSOut](t, session, "list_tls_failures", map[string]any{"device": "iphone-test"}); len(tls.Failures) != 1 || tls.Failures[0].Host != "pinned.example.net" {
		t.Errorf("list_tls_failures = %+v", tls)
	}
	// Bad input is an error the agent sees, not a crash.
	if res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "search_flows", Arguments: map[string]any{}}); err == nil && !res.IsError {
		t.Error("search_flows without a query succeeded")
	}
}

// TestServeAndProxy: an agent, through `reqcove mcp`, reaches the tools on the socket `run` serves.
func TestServeAndProxy(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "rcvm-") // short socket path
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "mcp.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Serve returns once listening, so `run` can stop on its error instead of logging "MCP on".
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, sock, New(testStore(t), nil)) }()
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return once listening")
	}
	long := filepath.Join(dir, strings.Repeat("d", 120)) // a socket path is at most 104 bytes on macOS, 108 on Linux
	os.Mkdir(long, 0o700)
	if err := Serve(ctx, filepath.Join(long, "mcp.sock"), New(testStore(t), nil)); err == nil {
		t.Error("Serve on a path too long for a socket: no error")
	}

	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("MCP socket mode %v, want 0600", fi.Mode().Perm())
	}
	// The agent side: in-memory transports stand in for `reqcove mcp`'s stdio.
	ct, pt := mcp.NewInMemoryTransports()
	go Proxy(ctx, sock, "down", pt)
	session, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := call[ListOut](t, session, "list_flows", nil); len(got.Flows) != 1 {
		t.Fatalf("list_flows through reqcove mcp = %+v", got.Flows)
	}
	session.Close()
	cancel()
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(sock); err == nil {
		t.Error("socket left behind after Serve ended")
	}
}

func TestListFilterInput(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	q, err := filter(ListIn{Since: "10m", Until: "2026-11-07T21:00:00+09:00", Limit: 9999, Status: "4xx"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if q.Since != float64(now.Add(-10*time.Minute).Unix()) || q.Until != float64(now.Unix()) || q.Limit != 500 || q.Status != "4xx" {
		t.Errorf("filter = %+v", q)
	}
	if q, _ := filter(ListIn{}, now); q.Limit != 50 || q.Since != 0 {
		t.Errorf("defaults = %+v", q)
	}
	for _, in := range []ListIn{{Since: "yesterday"}, {Until: "12:00"}, {Status: "4XX"}, {Status: "abc"}} {
		if _, err := filter(in, now); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
}

// One app's traffic by its User-Agent, and look-alike hosts when a host
// filter matches nothing (acmeshop.com for acme-shop.com).
func TestUserAgentAndSimilarHosts(t *testing.T) {
	st := capture.NewStore(10, 1<<20)
	for _, l := range []string{
		`{"v":2,"ev":"request","id":"a","device":"d","host":"api.acme-shop.com","url":"https://api.acme-shop.com/x","ts":1794000000,"headers":[["User-Agent","EvenApp/2.1 CFNetwork/1568 Darwin/25.0"]]}`,
		`{"v":2,"ev":"request","id":"b","device":"d","host":"cdn.example.com","url":"https://cdn.example.com/y","ts":1794000001,"headers":[["User-Agent","Safari/605"]]}`,
	} {
		st.Apply([]byte(l))
	}
	ct, sst := mcp.NewInMemoryTransports()
	if _, err := New(st, nil).Connect(context.Background(), sst, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	if got := call[ListOut](t, session, "list_flows", map[string]any{"user_agent": "evenapp"}); len(got.Flows) != 1 || got.Flows[0].ID != "a" {
		t.Errorf("user_agent: %+v", got)
	}
	if got := call[SummarizeOut](t, session, "summarize", map[string]any{"user_agent": "SAFARI"}); got.Flows != 1 {
		t.Errorf("summarize user_agent: %+v", got)
	}
	for _, tool := range []string{"list_flows", "summarize"} {
		got := call[struct {
			SimilarHosts []string `json:"similar_hosts"`
		}](t, session, tool, map[string]any{"host": "acmeshop.com"})
		if !slices.Equal(got.SimilarHosts, []string{"api.acme-shop.com"}) {
			t.Errorf("%s similar_hosts: %v", tool, got.SimilarHosts)
		}
	}
	// The host is there, a since left nothing: no look-alikes, they would mislead.
	if got := call[ListOut](t, session, "list_flows", map[string]any{"host": "acme-shop.com", "since": "1m"}); len(got.Flows) != 0 || got.SimilarHosts != nil {
		t.Errorf("host there, since empty: %+v", got)
	}
	if got := call[ListOut](t, session, "list_flows", map[string]any{"host": "xa.com"}); got.SimilarHosts != nil { // too short to tell ("xacom")
		t.Errorf("short host: %v", got.SimilarHosts)
	}
	// A TLS failure has no headers nor response: those filters are refused, not silently empty.
	for _, k := range []string{"user_agent", "status", "method"} {
		if res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_tls_failures", Arguments: map[string]any{k: "x"}}); err != nil || !res.IsError {
			t.Errorf("list_tls_failures %s: %v %+v", k, err, res)
		}
	}
	// A URL, a port, a final dot: the host meant.
	for _, h := range []string{"https://api.acme-shop.com/x?y", "api.acme-shop.com:443", "acme-shop.com.", "ACME-SHOP.COM"} {
		if got := call[ListOut](t, session, "list_flows", map[string]any{"host": h}); len(got.Flows) != 1 {
			t.Errorf("host %q: %+v", h, got)
		}
	}
}

// Look-alikes: either way round, not short recorded hosts, at most n, sorted.
func TestSimilarHostsStore(t *testing.T) {
	st := capture.NewStore(100, 1<<20)
	for i, h := range []string{"x.com", "s.com", "dropbox.com", "acmeshop.com", "a.acmeshop.net", "b.acme-shop.com", "c.acme-shop.com", "d.acme-shop.com", "e.acme-shop.com", "f.acme-shop.com"} {
		st.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"request","id":"%d","device":"d","host":"%s","url":"https://%s/"}`, i, h, h)))
	}
	if got := st.SimilarHosts("box.com", 5); !slices.Equal(got, []string{"dropbox.com"}) { // not x.com
		t.Errorf("box.com: %v", got)
	}
	if got := st.SimilarHosts("api.acmeshop.com", 5); !slices.Equal(got, []string{"acmeshop.com"}) { // the other way round
		t.Errorf("api.acmeshop.com: %v", got)
	}
	if got := st.SimilarHosts("acme-shop.co", 3); !slices.Equal(got, []string{"acmeshop.com", "b.acme-shop.com", "c.acme-shop.com"}) {
		t.Errorf("at most 3: %v", got)
	}
}

// A --pass-hosts host: list_passthrough has its connections; a host filter
// naming it says why no flow is there; the description keeps the agent from
// saying what was requested, or that it was not sent.
func TestPassthroughTool(t *testing.T) {
	st := capture.NewStore(10, 1<<20)
	allow, _ := capture.ParseAllowHosts([]string{"*"})
	allow, _ = allow.WithPass([]string{"api.x.com"})
	st.SetScope(allow, true)
	st.Apply([]byte(`{"v":2,"ev":"pass_open","conn":"c1","device":"d","sni":"api.x.com","server":"203.0.113.1:443","ts":1794000000}`))
	ct, sst := mcp.NewInMemoryTransports()
	server := New(st, nil)
	if _, err := server.Connect(context.Background(), sst, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if got := call[PassOut](t, session, "list_passthrough", map[string]any{"host": "x.com"}); len(got.Connections) != 1 || !got.Connections[0].Open {
		t.Errorf("list_passthrough: %+v", got)
	}
	for _, tool := range []string{"list_flows", "summarize"} {
		if got := call[struct {
			Note string `json:"note"`
		}](t, session, tool, map[string]any{"host": "api.x.com"}); !strings.Contains(got.Note, "does not mean nothing was sent") {
			t.Errorf("%s note: %q", tool, got.Note)
		}
	}
	if got := call[ListOut](t, session, "list_flows", map[string]any{"host": "other.com"}); got.Note != "" {
		t.Errorf("a note for another host: %q", got.Note)
	}
	for tool, err := range session.Tools(context.Background(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		if tool.Name == "list_passthrough" {
			for _, want := range []string{"A connection is not a request", "no URLs", "never say what was requested, that a request was not sent, nor that it succeeded"} {
				if !strings.Contains(tool.Description, want) {
					t.Errorf("description lacks %q", want)
				}
			}
		}
	}
}

// TestCutHeadHuge: a max_body far past any head (a caller's) neither
// overflows nor cuts.
func TestCutHeadHuge(t *testing.T) {
	for _, enc := range []string{"", "base64"} {
		if got, cut := cutHead("QUJDRA==", enc, 7000000000000000000); got != "QUJDRA==" || cut {
			t.Errorf("%q: %q %v", enc, got, cut)
		}
	}
}

// TestRecoverCalls: a handler's panic is that call's error, not run's end.
func TestRecoverCalls(t *testing.T) {
	h := recoverCalls(func(context.Context, string, mcp.Request) (mcp.Result, error) { panic("boom") })
	if res, err := h(context.Background(), "tools/call", nil); res != nil || err == nil {
		t.Errorf("%v %v", res, err)
	}
}

// With masking off (--no-redact), every answer with flows in it says so at
// its top (note), as the --ui page has a badge; with it on, none does.
func TestUnmaskedNote(t *testing.T) {
	for _, redact := range []bool{false, true} {
		st := capture.NewStore(10, 1<<20)
		st.SetScope(capture.HostRules{All: true}, redact)
		for _, l := range []string{
			`{"v":2,"ev":"request","id":"a","host":"h.example","url":"https://h.example/x","headers":[["Authorization","Bearer s3cret"]]}`,
			`{"v":2,"ev":"response","id":"a","status":200}`,
			`{"v":2,"ev":"done","id":"a"}`,
			`{"v":2,"ev":"request","id":"b","host":"h.example","url":"https://h.example/y"}`,
		} {
			st.Apply([]byte(l))
		}
		ct, sst := mcp.NewInMemoryTransports()
		if _, err := New(st, nil).Connect(context.Background(), sst, nil); err != nil {
			t.Fatal(err)
		}
		session, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			tool string
			args map[string]any
		}{
			{"list_flows", nil}, {"search_flows", map[string]any{"query": "h.example"}}, {"summarize", nil},
			{"wait_for_flows", map[string]any{"timeout": 1}}, {"get_flow", map[string]any{"id": "a"}},
			{"list_ws_messages", map[string]any{"id": "a"}}, {"diff_flows", map[string]any{"a": "a", "b": "b"}},
		} {
			got := call[map[string]any](t, session, c.tool, c.args)
			if note, _ := got["note"].(string); strings.HasPrefix(note, "masking is off") == redact {
				t.Errorf("%s (redacting %v): note %q", c.tool, redact, note)
			}
		}
		session.Close()
	}
}
