package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestNoSecretInAnyTool feeds flows whose secrets hide in the usual odd
// places, then calls every tool (bodies off) and checks no secret comes out.
// Every secret value contains S3CRET.
func TestNoSecretInAnyTool(t *testing.T) {
	st := capture.NewStore(100, 1<<20)
	cp := st.Checkpoint()
	ev := func(m map[string]any) {
		m["v"] = 2
		b, _ := json.Marshal(m)
		st.Apply(b)
	}
	headers := [][2]string{
		{"Authorization", "Bearer S3CRET-1"},
		{"authorization", "Basic S3CRET-2"}, // repeated, other case
		{"PROXY-AUTHORIZATION", "Basic S3CRET-3"},
		{"Cookie", "sid=S3CRET-4; theme=dark"},
		{"cookie", "other=S3CRET-5"},
		{"X-Api-Key", "S3CRET-6"},
		{"X-Auth-Token", "S3CRET-7"},
		{"Ocp-Apim-Subscription-Key", "S3CRET-21"},
		{"X-Client-Key", "S3CRET-22"},
		{"Referer", "https://app.example/cb?code=S3CRET-8&state=ok"},
		{"Origin", "https://app.example"},
		{"User-Agent", "App/1.0"},
	}
	urls := []string{
		"https://api.example.com/a?token=S3CRET-9",
		"https://api.example.com/a?%74oken=S3CRET-10",              // encoded name
		"https://api.example.com/a?ACCESS_TOKEN=S3CRET-11&page=2",  // upper case
		"https://api.example.com/a?x=1&api_key=S3CRET-12#frag",     // before a fragment
		"https://api.example.com/cb#access_token=S3CRET-13&type=x", // OAuth implicit flow: in the fragment
		"https://api.example.com/a;sessionid=S3CRET-14",
		"https://api.example.com/a?accessToken=S3CRET-23&authToken=S3CRET-24&oauth_token=S3CRET-25&session_id=S3CRET-26",
		"https://bucket.s3.example.com/f?X-Amz-Signature=S3CRET-27&X-Amz-Security-Token=S3CRET-28&X-Goog-Signature=S3CRET-29&jsessionid=S3CRET-30",
		"https://api.example.com/a?view=1;token=S3CRET-31",
	}
	for i, u := range urls {
		id := string(rune('a' + i))
		ev(map[string]any{"ev": "request", "id": id, "device": "dev", "method": "GET", "host": "api.example.com", "url": u, "path": u[len("https://api.example.com"):], "ts": 1794000000 + i, "headers": headers})
		ev(map[string]any{"ev": "response", "id": id, "status": 302, "headers": [][2]string{
			{"Set-Cookie", "sid=S3CRET-15; HttpOnly"}, {"set-cookie", "x=S3CRET-16"},
			{"Location", "https://app.example/#/callback?access_token=S3CRET-17"}, {"Content-Location", "/c?key=S3CRET-18"},
			{"WWW-Authenticate", `Bearer realm="api", error="invalid_token"`},
		}})
		ev(map[string]any{"ev": "error", "id": id, "msg": "connection to https://api.example.com/a?token=S3CRET-19 failed; HTTP/1 protocol error: Invalid header line: b'Set-Cookie sid=S3CRET-32'"})
	}
	ev(map[string]any{"ev": "tls_failed", "conn": "c1", "device": "dev", "sni": "api.example.com", "ts": 1794000100, "msg": "handshake for https://api.example.com/?key=S3CRET-20"})
	st.SetDeviceNames(map[string]string{"dev": "iphone"})

	ct, sst := mcp.NewInMemoryTransports()
	if _, err := New(st, nil).Connect(context.Background(), sst, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	var all strings.Builder
	dump := func(name string, args map[string]any) {
		res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil || res.IsError {
			t.Fatalf("%s: %v %+v", name, err, res)
		}
		b, _ := json.Marshal(res)
		all.WriteString(name + ": " + string(b) + "\n")
	}
	dump("list_flows", map[string]any{"limit": 100})
	for _, q := range []string{"api", "S3CRET", "token", "Bearer"} {
		dump("search_flows", map[string]any{"query": q})
	}
	dump("wait_for_flows", map[string]any{"after": cp, "limit": 100})
	dump("summarize", map[string]any{"top": 100})
	dump("list_devices", nil)
	dump("list_tls_failures", nil)
	dump("capture_stats", nil)
	for i := range urls {
		dump("get_flow", map[string]any{"id": string(rune('a' + i))})
	}
	out := all.String()
	for line := range strings.Lines(out) {
		if i := strings.Index(line, "S3CRET"); i >= 0 {
			t.Errorf("%s ... %s", line[:strings.Index(line, ":")], line[max(0, i-60):min(len(line), i+20)])
		}
	}
	// The masking must not eat what is not secret.
	for _, keep := range []string{"state=ok", "page=2", "theme", "App/1.0", "https://app.example", "type=x", "view=1", `error=\"invalid_token\"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("over-masked: %q is gone", keep)
		}
	}
}
