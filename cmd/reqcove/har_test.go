package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

// TestHAR: `reqcove har` writes the flows the tools return, oldest first,
// masked, with the heads of bodies marked as such and bodies that are not text
// left out.
func TestHAR(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "rcvh-") // short socket path
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := capture.NewStore(1000, 1<<20)
	ev := func(m map[string]any) {
		m["v"] = 2
		b, _ := json.Marshal(m)
		st.Apply(b)
	}
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	ev(map[string]any{"ev": "request", "id": "f1", "device": "devA", "host": "api.example.com", "method": "GET", "ts": 100.0, "http_version": "HTTP/2.0",
		"url": "https://api.example.com/a?b=2&a=1&token=s3cr3t", "headers": [][2]string{{"Authorization", "Bearer s3cr3t"}}})
	ev(map[string]any{"ev": "response", "id": "f1", "status": 302, "reason": "Found", "headers": [][2]string{{"Location", "/b"}, {"Content-Type", "application/json"}}})
	ev(map[string]any{"ev": "body", "id": "f1", "dir": "response", "decoded": true, "final": true, "truncated": true, "size": 100000, "head": b64(`{"ok":true`)})
	ev(map[string]any{"ev": "done", "id": "f1", "ts_end": 100.25})
	ev(map[string]any{"ev": "request", "id": "f2", "device": "devA", "host": "img.example.com", "method": "POST", "ts": 101.0, "http_version": "HTTP/1.1",
		"url": "https://img.example.com/up", "headers": [][2]string{{"Content-Type", "application/json"}}})
	ev(map[string]any{"ev": "body", "id": "f2", "dir": "request", "decoded": true, "final": true, "size": 20, "head": b64(`{"password":"hunter2"}`)})
	ev(map[string]any{"ev": "response", "id": "f2", "status": 200, "headers": [][2]string{{"Content-Type", "image/png"}}})
	ev(map[string]any{"ev": "body", "id": "f2", "dir": "response", "decoded": true, "final": true, "size": 4, "head": b64("\x89PNG")})
	ev(map[string]any{"ev": "done", "id": "f2", "ts_end": 101.5})
	if err := mcpserver.Serve(ctx, filepath.Join(dir, "mcp.sock"), mcpserver.New(st, nil)); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() error { return har(ctx, []string{"--state", dir}) })
	if strings.Contains(out, "s3cr3t") || strings.Contains(out, "hunter2") {
		t.Errorf("a secret in the HAR:\n%s", out)
	}
	var h struct {
		Log struct {
			Version string
			Comment string
			Entries []harEntryOut
		}
	}
	if err := json.Unmarshal([]byte(out), &h); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	if h.Log.Version != "1.2" || len(h.Log.Entries) != 2 || !strings.HasPrefix(h.Log.Comment, "masked") {
		t.Fatalf("log: %+v", h.Log)
	}
	a, b := h.Log.Entries[0], h.Log.Entries[1]
	if !strings.HasPrefix(a.Request.URL, "https://api.example.com/a?") || a.Time != 250 {
		t.Errorf("first entry (oldest first): %+v", a)
	}
	if len(a.Request.QueryString) != 3 || a.Request.QueryString[0].Name != "a" || a.Response.RedirectURL != "/b" || a.Response.StatusText != "Found" {
		t.Errorf("query, redirect: %+v", a)
	}
	if a.Response.Content.Text != `{"ok":true` || !strings.Contains(a.Response.Content.Comment, "only the first part") || a.Response.Content.Size != 100000 {
		t.Errorf("a cut body: %+v", a.Response.Content)
	}
	if b.Request.PostData == nil || !strings.Contains(b.Request.PostData.Text, `"password"`) || b.Request.PostData.MimeType != "application/json" {
		t.Errorf("post data: %+v", b.Request.PostData)
	}
	if b.Response.Content.Text != "" || !strings.Contains(b.Response.Content.Comment, "omitted") || b.Device != "devA" {
		t.Errorf("a body that is not text: %+v", b)
	}
	// A whole body, sent gzipped in 9 bytes: HAR's size is the decoded one.
	ev(map[string]any{"ev": "request", "id": "f3", "device": "devA", "host": "gz.example.com", "method": "GET", "ts": 150.0, "url": "https://gz.example.com/"})
	ev(map[string]any{"ev": "response", "id": "f3", "status": 200, "headers": [][2]string{{"Content-Type", "text/plain"}, {"Content-Encoding", "gzip"}}})
	ev(map[string]any{"ev": "body", "id": "f3", "dir": "response", "decoded": true, "final": true, "size": 9, "encoding": "gzip", "head": b64("hello world")})
	out = captureStdout(t, func() error { return har(ctx, []string{"--state", dir, "--host", "gz.example.com"}) })
	h.Log.Entries = nil
	if err := json.Unmarshal([]byte(out), &h); err != nil || len(h.Log.Entries) != 1 || h.Log.Entries[0].Response.Content.Size != 11 || h.Log.Entries[0].Response.BodySize != 9 {
		t.Errorf("a gzipped body's sizes: %v\n%s", err, out)
	}
	// A WebSocket: its kept messages, masked, in _webSocketMessages, past one page.
	ev(map[string]any{"ev": "request", "id": "w1", "device": "devA", "host": "ws.example.com", "method": "GET", "ts": 160.0, "url": "wss://ws.example.com/"})
	ev(map[string]any{"ev": "response", "id": "w1", "status": 101, "headers": [][2]string{{"Upgrade", "websocket"}}})
	ev(map[string]any{"ev": "ws", "id": "w1", "from_client": true, "text": true, "size": 30, "ts": 160.5, "head": b64(`{"authToken":"wsS3cr3tHAR"}`)})
	for i := range 150 {
		ev(map[string]any{"ev": "ws", "id": "w1", "from_client": false, "text": true, "size": 8, "ts": 161.0 + float64(i), "head": b64(fmt.Sprintf(`{"n":%d}`, i))})
	}
	out = captureStdout(t, func() error { return har(ctx, []string{"--state", dir, "--host", "ws.example.com"}) })
	h.Log.Entries = nil
	if err := json.Unmarshal([]byte(out), &h); err != nil || len(h.Log.Entries) != 1 || strings.Contains(out, "wsS3cr3tHAR") {
		t.Fatalf("a WebSocket: %v\n%s", err, out)
	}
	if m := h.Log.Entries[0].WSMessages; len(m) != 105 || m[0].Type != "send" || m[0].Opcode != 1 || m[104].Data != `{"n":149}` || m[1].Type != "receive" {
		t.Errorf("_webSocketMessages: %d, %+v", len(m), m[:min(2, len(m))])
	}
	// gRPC's trailers (HAR has no field for them) in the comment.
	ev(map[string]any{"ev": "request", "id": "g1", "device": "devA", "host": "grpc.example.org", "method": "POST", "ts": 170.0, "url": "https://grpc.example.org/pkg.Svc/M"})
	ev(map[string]any{"ev": "response", "id": "g1", "status": 200, "headers": [][2]string{{"Content-Type", "application/grpc"}}})
	ev(map[string]any{"ev": "done", "id": "g1", "ts_end": 170.5, "trailers": [][2]string{{"grpc-status", "0"}}})
	out = captureStdout(t, func() error { return har(ctx, []string{"--state", dir, "--host", "grpc.example.org"}) })
	if !strings.Contains(out, "response trailers: grpc-status: 0") {
		t.Errorf("trailers in the HAR:\n%s", out)
	}
	// A rendering of protobuf says it is not the bytes.
	ev(map[string]any{"ev": "request", "id": "pb1", "device": "devA", "host": "grpc.example.org", "method": "POST", "ts": 171.0, "url": "https://grpc.example.org/v1/x", "headers": [][2]string{{"Content-Type", "application/x-protobuf"}}})
	ev(map[string]any{"ev": "body", "id": "pb1", "dir": "request", "decoded": true, "final": true, "size": 5, "head": b64("\x0a\x03abc")})
	out = captureStdout(t, func() error { return har(ctx, []string{"--state", dir, "--host", "grpc.example.org"}) })
	if !strings.Contains(out, "reqcove's rendering, not the body's bytes: protobuf structure") || !strings.Contains(out, "1: string(3)") {
		t.Errorf("trailers in the HAR:\n%s", out)
	}
	// More than a page of list_flows (500), and a flow still open: all of them,
	// in order, the open one said to be open.
	for i := 0; i < 600; i++ {
		ev(map[string]any{"ev": "request", "id": fmt.Sprintf("p%03d", i), "device": "devA", "host": "many.example.com", "method": "GET", "ts": 200.0 + float64(i), "url": "https://many.example.com/"})
	}
	out = captureStdout(t, func() error { return har(ctx, []string{"--state", dir, "--host", "many.example.com"}) })
	h.Log.Entries = nil
	if err := json.Unmarshal([]byte(out), &h); err != nil || len(h.Log.Entries) != 600 {
		t.Fatalf("600 flows: %d entries, %v", len(h.Log.Entries), err)
	}
	if e := h.Log.Entries[599]; e.Response.Status != 0 || e.Response.BodySize != -1 || !strings.Contains(e.Comment, "still open") || e.Started <= h.Log.Entries[0].Started {
		t.Errorf("the newest, open: %+v", e)
	}
	// Filters and the limit go through: the newest flow only.
	out = captureStdout(t, func() error {
		return har(ctx, []string{"--state", dir, "--limit", "1", "--host", "example.com", "--method", "POST"})
	})
	if !strings.Contains(out, "img.example.com") || strings.Contains(out, "api.example.com") {
		t.Errorf("--limit 1:\n%s", out)
	}
	out = captureStdout(t, func() error { return har(ctx, []string{"--state", dir, "--host", "api.example.com"}) })
	if strings.Contains(out, "img.example.com") || !strings.Contains(out, "api.example.com") {
		t.Errorf("--host:\n%s", out)
	}
	// --no-redact: the file says it is not masked.
	st.SetScope(capture.HostRules{All: true}, false)
	out = captureStdout(t, func() error { return har(ctx, []string{"--state", dir, "--limit", "1"}) })
	if !strings.Contains(out, `"comment":"NOT masked`) {
		t.Errorf("--no-redact not said:\n%.300s", out)
	}
}
