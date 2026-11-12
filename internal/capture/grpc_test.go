package capture

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func grpcFrame1(flag byte, payload string) string {
	var b [5]byte
	b[0] = flag
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
	return string(b[:]) + payload
}

func grpcApply(s *Store, m map[string]any) {
	m["v"] = 2
	b, _ := json.Marshal(m)
	s.Apply(b)
}

// TestGRPCStatus: the status from headers (trailers-only), from HTTP/2
// trailers, from gRPC-Web's trailer frame; pending until then; metadata
// conventions masked; framed JSON de-framed and masked.
func TestGRPCStatus(t *testing.T) {
	s := NewStore(100, 1<<20)
	b64 := func(x string) string { return base64.StdEncoding.EncodeToString([]byte(x)) }
	req := func(id, ct string) {
		grpcApply(s, map[string]any{"ev": "request", "id": id, "method": "POST", "url": "https://api.example/pkg.Svc/Get", "host": "api.example", "path": "/pkg.Svc/Get",
			"headers": [][2]string{{"Content-Type", ct}, {"authorization-bin", b64("GRPCsecretBin1")}, {"x-trace-bin", b64("abc")}}})
	}
	row := func(id string) Summary {
		rows, _ := s.List(Filter{Limit: 100})
		for _, r := range rows {
			if r.ID == id {
				return r
			}
		}
		t.Fatalf("no row %s", id)
		return Summary{}
	}
	// Trailers-only: an error in the headers, no message.
	req("a", "application/grpc")
	grpcApply(s, map[string]any{"ev": "response", "id": "a", "status": 200, "headers": [][2]string{{"Content-Type", "application/grpc"}, {"grpc-status", "16"}, {"grpc-message", "token%20GRPCsecretMsg1%3D%3D expired?access_token=GRPCsecretMsg2"}}})
	grpcApply(s, map[string]any{"ev": "done", "id": "a", "ts_end": 1.0})
	if r := row("a"); r.GRPCStatus != "16" || strings.Contains(r.GRPCMessage, "GRPCsecretMsg2") || !strings.Contains(r.GRPCMessage, "token ") {
		t.Errorf("trailers-only: %q %q", r.GRPCStatus, r.GRPCMessage)
	}
	v, _ := s.Get("a", false)
	for _, kv := range v.ReqHeaders {
		if strings.HasSuffix(kv[0], "-bin") && !strings.HasPrefix(kv[1], "[binary ") && kv[1] != "[redacted]" || kv[0] == "x-trace-bin" && kv[1] != "[binary 3 bytes]" {
			t.Errorf("a -bin value kept: %v", kv)
		}
	}
	// HTTP/2 trailers, pending before them; the messages described, not handed out.
	req("b", "application/grpc")
	grpcApply(s, map[string]any{"ev": "response", "id": "b", "status": 200, "headers": [][2]string{{"Content-Type", "application/grpc"}}})
	body := grpcFrame1(0, "\x0a\x03abc") + grpcFrame1(1, "zzzz") + grpcFrame1(0, "\x0a\x05hello")
	grpcApply(s, map[string]any{"ev": "body", "id": "b", "dir": "response", "decoded": true, "final": true, "size": len(body), "head": b64(body)})
	if r := row("b"); r.GRPCStatus != "pending" {
		t.Errorf("before its trailers: %q", r.GRPCStatus)
	}
	grpcApply(s, map[string]any{"ev": "done", "id": "b", "ts_end": 2.0, "trailers": [][2]string{{"grpc-status", "0"}, {"x-session-token", "GRPCsecretTrailer1"}}})
	v, _ = s.Get("b", true)
	if r := row("b"); r.GRPCStatus != "0" || strings.Contains(fmt.Sprint(v.RespTrailers), "GRPCsecretTrailer1") {
		t.Errorf("trailers: %q %v", r.GRPCStatus, v.RespTrailers)
	}
	if !strings.Contains(v.RespBody.Note, "gRPC: 3 messages (5, 4, 7 bytes), 1 compressed") || v.RespBodyText != "1: string(3)\n\n[compressed, 4 bytes]\n1: string(5)\n" || !strings.HasPrefix(v.RespBody.View, "protobuf structure") {
		t.Errorf("a proto body: note %q text %q", v.RespBody.Note, v.RespBodyText)
	}
	// gRPC-Web: its trailer frame; framed JSON (+json) de-framed and masked.
	req("c", "application/grpc-web+json")
	grpcApply(s, map[string]any{"ev": "response", "id": "c", "status": 200, "headers": [][2]string{{"Content-Type", "application/grpc-web+json"}}})
	body = grpcFrame1(0, `{"user":"a","password":"GRPCsecretJSON1"}`) + grpcFrame1(0x80, "grpc-status: 7\r\ngrpc-message: denied\r\n")
	grpcApply(s, map[string]any{"ev": "body", "id": "c", "dir": "response", "decoded": true, "final": true, "size": len(body), "head": b64(body)})
	v, _ = s.Get("c", true)
	if r := row("c"); r.GRPCStatus != "7" || r.GRPCMessage != "denied" {
		t.Errorf("gRPC-Web trailers: %q %q", r.GRPCStatus, r.GRPCMessage)
	}
	if strings.Contains(v.RespBodyText, "GRPCsecretJSON1") || !strings.Contains(v.RespBodyText, `"user":"a"`) {
		t.Errorf("framed JSON: %q (%s)", v.RespBodyText, v.RespBodyEnc)
	}
	// A frame declaring 4 GiB is described, not allocated; a cut one says so.
	if f := grpcFrames([]byte("\x00\xff\xff\xff\xffabc")); len(f) != 1 || f[0].payload != nil || f[0].size != 1<<32-1 {
		t.Errorf("a huge declared length: %+v", f)
	}
	if c := s.Summarize(Filter{}, 10); len(c.ByGRPCStatus) != 3 {
		t.Errorf("by_grpc_status: %+v", c.ByGRPCStatus)
	}
	// A flow that is no gRPC has no status, and no -bin rule changes others.
	s.Apply([]byte(`{"v":2,"ev":"request","id":"h","method":"GET","url":"https://x.example/","host":"x.example","path":"/","headers":[["X-Thing","GRPCnotbin"]]}`))
	if r := row("h"); r.GRPCStatus != "" {
		t.Errorf("an HTTP flow: %q", r.GRPCStatus)
	}
}

// TestGRPCE2E (REQCOVE_E2E=1): gRPC's shape over real HTTP/2 through
// mitmproxy, without grpc-go: a body over 64 KiB with its status in the
// trailers, and a trailers-only error.
func TestGRPCE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var mu sync.Mutex
	protos := map[string]int{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		protos[r.URL.Path] = r.ProtoMajor
		mu.Unlock()
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		if r.URL.Path == "/pkg.Svc/Deny" { // trailers-only
			w.Header().Set("Grpc-Status", "16")
			w.Header().Set("Grpc-Message", "token%20expired")
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message, X-Session-Token")
		w.WriteHeader(200)
		for range 3 {
			w.Write([]byte(grpcFrame1(0, strings.Repeat("\x0a\x01z", 10000))))
		}
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "")
		w.Header().Set("X-Session-Token", "GRPCe2eTrailer1")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "origin.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	// Through an upstream CONNECT proxy (TestUpstream's): its CA setting is
	// how a test makes mitmproxy trust a test server's certificate.
	up := startUpstream(t)
	defer up.ln.Close()
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.Upstream, c.UpstreamCA = up.ln.Addr().String(), caFile })
	if err != nil {
		t.Fatal(err)
	}
	tr := h.client("grpc-device").Transport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = true
	hc := &http.Client{Transport: tr, Timeout: time.Minute}
	call := func(path string) *http.Response {
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(grpcFrame1(0, "\x0a\x02id")))
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Logf("%s: %s %q", path, resp.Status, b[:min(len(b), 300)])
		}
		if resp.ProtoMajor != 2 {
			t.Errorf("%s: HTTP/%d to the app", path, resp.ProtoMajor)
		}
		return resp
	}
	if r := call("/pkg.Svc/Get"); r.Trailer.Get("Grpc-Status") != "0" {
		t.Errorf("the app's trailers: %v", r.Trailer)
	}
	call("/pkg.Svc/Deny")
	mu.Lock()
	if protos["/pkg.Svc/Get"] != 2 || protos["/pkg.Svc/Deny"] != 2 {
		t.Errorf("to the server: %v", protos)
	}
	mu.Unlock()
	var get, deny Summary
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		for _, f := range listAll(h.c.Store, 100) {
			switch {
			case strings.HasSuffix(f.URL, "/Get"):
				get = f
			case strings.HasSuffix(f.URL, "/Deny"):
				deny = f
			}
		}
		if get.GRPCStatus == "0" && deny.GRPCStatus == "16" {
			break
		}
	}
	if get.GRPCStatus != "0" || deny.GRPCStatus != "16" || deny.GRPCMessage != "token expired" {
		t.Fatalf("statuses: get %q, deny %q %q", get.GRPCStatus, deny.GRPCStatus, deny.GRPCMessage)
	}
	v, _ := h.c.Store.Get(get.ID, true)
	if strings.Contains(fmt.Sprint(v.RespTrailers), "GRPCe2eTrailer1") || header(v.RespTrailers, "grpc-status") != "0" {
		t.Errorf("trailers: %v", v.RespTrailers)
	}
	if !v.RespBody.Truncated || !strings.HasPrefix(v.RespBody.Note, "gRPC: 3 messages (30000, 30000, ") || !strings.HasPrefix(v.RespBodyText, "1: string(1)\n") || !strings.Contains(v.RespBodyText, "[cut: 30000 bytes]") && !strings.Contains(v.RespBodyText, "[more messages not read]") {
		t.Errorf("a body over 64 KiB: note %q truncated %v text %d", v.RespBody.Note, v.RespBody.Truncated, len(v.RespBodyText))
	}
}

// TestGRPCItemReview: the item review of gRPC status (Opus).
func TestGRPCItemReview(t *testing.T) {
	b64 := func(x string) string { return base64.StdEncoding.EncodeToString([]byte(x)) }
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJHUlBDcmV2aWV3MSJ9.R1JQQ3Jldmlld1NpZzAx"
	flow := func(s *Store, id, ct, body string) FlowView {
		grpcApply(s, map[string]any{"ev": "request", "id": id, "method": "POST", "url": "https://api.example/pkg.Svc/M", "host": "api.example", "path": "/pkg.Svc/M", "headers": [][2]string{{"Content-Type", ct}}})
		grpcApply(s, map[string]any{"ev": "response", "id": id, "status": 200, "headers": [][2]string{{"Content-Type", ct}}})
		grpcApply(s, map[string]any{"ev": "body", "id": id, "dir": "response", "decoded": true, "final": true, "size": len(body), "head": b64(body)})
		v, _ := s.Get(id, true)
		return v
	}
	s := NewStore(100, 1<<20)
	// An unframed text body under a gRPC type is masked as a body.
	for i, ct := range []string{"application/grpc+xml", "application/connect+xml", "application/grpc-json", "application/grpc+json"} {
		v := flow(s, fmt.Sprint("x", i), ct, `<error>Bearer `+jwt+` access_token=`+jwt+`</error>`)
		if strings.Contains(v.RespBodyText, "R1JQQ3Jldmlld1NpZzAx") {
			t.Errorf("%s: %q", ct, v.RespBodyText)
		}
	}
	if rows, _ := s.List(Filter{Query: "R1JQQ3Jldmlld1NpZzAx", QueryBodies: true, Limit: 10}); len(rows) != 0 {
		t.Errorf("search found a masked token: %+v", rows)
	}
	// gRPC-Web's text form is not read as frames; plain JSON under +json is a body.
	if v := flow(s, "wt", "application/grpc-web-text", b64(grpcFrame1(0, "\x0a\x01a"))); strings.Contains(v.RespBody.Note, "messages") {
		t.Errorf("grpc-web-text read as frames: %q", v.RespBody.Note)
	}
	if v := flow(s, "pj", "application/grpc+json", `{"error":"bad","password":"GRPCreview2"}`); !strings.Contains(v.RespBodyText, `"error":"bad"`) || strings.Contains(v.RespBodyText, "GRPCreview2") {
		t.Errorf("plain JSON under grpc+json: %q (%s)", v.RespBodyText, v.RespBodyEnc)
	}
	// Placeholders are never "equal" in diff_flows.
	for _, id := range []string{"d1", "d2"} {
		grpcApply(s, map[string]any{"ev": "request", "id": id, "method": "POST", "url": "https://api.example/pkg.Svc/D", "host": "api.example", "path": "/pkg.Svc/D", "headers": [][2]string{{"x-trace-bin", b64(id + "x")}}})
	}
	if d, _ := s.DiffFlows("d1", "d2"); !strings.Contains(fmt.Sprint(d.Masked), "x-trace-bin") {
		t.Errorf("diff of -bin values: %+v", d)
	}
	// Without masking, the status still comes from gRPC-Web's frame.
	s2 := NewStore(10, 1<<20)
	s2.SetScope(HostRules{All: true}, false)
	body := grpcFrame1(0, "\x0a\x01a") + grpcFrame1(0x80, "grpc-status: 5\r\n")
	flow(s2, "nr", "application/grpc-web+proto", body)
	if rows, _ := s2.List(Filter{Limit: 1}); rows[0].GRPCStatus != "5" {
		t.Errorf("--no-redact: %q", rows[0].GRPCStatus)
	}
	// Past the frame cap, the note says so; trailers cut by the addon say so.
	many := strings.Repeat(grpcFrame1(0, "a"), grpcMaxFrames+10)
	if v := flow(s, "many", "application/grpc", many); !strings.Contains(v.RespBody.Note, "more not read") || len(v.RespBody.Note) > 400 {
		t.Errorf("the frame cap: %d bytes, %q…", len(v.RespBody.Note), v.RespBody.Note[:min(80, len(v.RespBody.Note))])
	}
	grpcApply(s, map[string]any{"ev": "done", "id": "many", "ts_end": 1.0, "trailers": [][2]string{{"grpc-status", "0"}}, "note": "more headers not recorded"})
	if v, _ := s.Get("many", false); !strings.Contains(fmt.Sprint(v.Notes), "response trailers: more headers not recorded") {
		t.Errorf("trailers note: %v", v.Notes)
	}
	// Trailers are searched.
	if rows, _ := s.List(Filter{Query: "grpc-status", Limit: 10}); len(rows) == 0 {
		t.Errorf("trailers not searched")
	}
}

// TestConnectStream: a Connect stream's answer ends with a frame of flag 2
// (JSON: its error); the final review found such answers left out whole.
func TestConnectStream(t *testing.T) {
	s := NewStore(10, 1<<20)
	b64 := func(x string) string { return base64.StdEncoding.EncodeToString([]byte(x)) }
	body := grpcFrame1(0, `{"sentence":"hi"}`) + grpcFrame1(2, `{"error":{"code":"unauthenticated","message":"token GRPCconnect01x expired","details":[]},"metadata":{"x-session-token":["GRPCconnect02x"]}}`)
	grpcApply(s, map[string]any{"ev": "request", "id": "c", "method": "POST", "url": "https://demo.example/x.Y/Introduce", "host": "demo.example", "path": "/x.Y/Introduce", "headers": [][2]string{{"Content-Type", "application/connect+json"}}})
	grpcApply(s, map[string]any{"ev": "response", "id": "c", "status": 200, "headers": [][2]string{{"Content-Type", "application/connect+json"}}})
	grpcApply(s, map[string]any{"ev": "body", "id": "c", "dir": "response", "decoded": true, "final": true, "size": len(body), "head": b64(body)})
	v, _ := s.Get("c", true)
	if !strings.Contains(v.RespBodyText, `"sentence":"hi"`) || !strings.Contains(v.RespBodyText, "[end of stream]") || !strings.Contains(v.RespBodyText, "unauthenticated") || strings.Contains(v.RespBodyText, "GRPCconnect02x") {
		t.Errorf("a Connect stream: %q (%s)", v.RespBodyText, v.RespBodyEnc)
	}
}

// TestGRPCBodyCap: one output cap for a whole gRPC body (the final review:
// 980 messages nested 30 deep rendered to 1.9 MB).
func TestGRPCBodyCap(t *testing.T) {
	deep := []byte("\x01")
	for range 30 {
		deep = append([]byte{0x0a, byte(len(deep))}, deep...)
	}
	msg := []byte(strings.Repeat(grpcFrame1(0, string(deep)), (64<<10)/(len(deep)+5)))
	s := NewStore(10, 1<<20)
	out, note, _, _ := s.grpcBody(msg, "application/grpc", "/x.Y/Z", false, true, false)
	if len(out) > 2*protoMaxOut || !strings.Contains(string(out), "[more messages not read]") || !strings.HasPrefix(note, "gRPC: ") {
		t.Errorf("rendered %d bytes from %d; note %q", len(out), len(msg), note)
	}
}
