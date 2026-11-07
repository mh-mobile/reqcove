package capture

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func line(t *testing.T, m map[string]any) []byte {
	t.Helper()
	m["v"] = wireVersion
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestStoreMergesEventsAndRedacts(t *testing.T) {
	st := NewStore(10, 1<<20)
	st.Apply(line(t, map[string]any{"ev": "request", "id": "a", "device": "phone", "host": "api.example.net",
		"headers": [][2]string{{"Authorization", "Bearer s3cret"}, {"Cookie", "sid=1"}, {"Accept", "*/*"}}}))
	st.Apply(line(t, map[string]any{"ev": "response", "id": "a", "status": 200,
		"headers": [][2]string{{"Set-Cookie", "a=1"}, {"set-cookie", "b=2"}, {"Content-Type", "text/plain"}}}))
	// A partial head (still streaming), then the final one.
	st.Apply(line(t, map[string]any{"ev": "body", "id": "a", "dir": "response", "head": b64("hel"), "size": 3, "decoded": true}))
	if v, _ := st.Get("a", true); v.State != "open" || v.RespBodyText != "hel" || v.RespBody.Final {
		t.Fatalf("while streaming: state=%q head=%q final=%v", v.State, v.RespBodyText, v.RespBody.Final)
	}
	st.Apply(line(t, map[string]any{"ev": "body", "id": "a", "dir": "response", "head": b64("hello"), "size": 5, "final": true, "decoded": true}))
	st.Apply(line(t, map[string]any{"ev": "done", "id": "a", "ts_end": 1.5}))

	v, err := st.Get("a", true)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != 200 || v.RespBodyText != "hello" || v.Device != "phone" || v.State != "done" || !v.RespBody.Final {
		t.Fatalf("merged flow = %+v", v)
	}
	for _, h := range append(v.ReqHeaders, v.RespHeaders...) {
		if v := strings.ToLower(h[1]); strings.Contains(v, "s3cret") || strings.Contains(v, "=1") || strings.Contains(v, "=2") {
			t.Errorf("header %s not redacted: %q", h[0], h[1])
		}
	}
	if len(v.RespHeaders) != 3 {
		t.Errorf("repeated Set-Cookie lost: %v", v.RespHeaders)
	}
	if st.flows["a"].ReqHeaders[0][1] != "[redacted]" {
		t.Error("the stored flow kept the secret: masking must happen as it arrives")
	}
}

func TestStoreBoundsAndRejects(t *testing.T) {
	st := NewStore(100, 10) // 10 bytes of body heads
	st.Apply([]byte("not json"))
	st.Apply([]byte(`{"v":1,"ev":"request","id":"old"}`)) // wire version 1
	st.Apply(line(t, map[string]any{"ev": "done", "id": "nope"}))
	for _, id := range []string{"1", "2", "3"} {
		st.Apply(line(t, map[string]any{"ev": "request", "id": id, "host": "h"}))
		st.Apply(line(t, map[string]any{"ev": "body", "id": id, "dir": "response", "head": b64("abcdef"), "size": 6}))
	}
	s := st.Stats()
	if s["bad_lines"] != int64(1) || s["unknown_version"] != int64(1) || s["orphan_updates"] != int64(1) {
		t.Fatalf("stats = %v", s)
	}
	// 3 flows x 6 bytes > 10: the oldest go first until the heads fit.
	if s["flows"] != 1 || s["held_bytes"] != 6 || s["evicted"] != int64(2) {
		t.Fatalf("byte bound not enforced: %v", s)
	}
	if got := listAll(st, 10); len(got) != 1 || got[0].ID != "3" {
		t.Fatalf("list = %+v, want only 3", got)
	}
}

func TestStoreKeepsHelloAndTLSFailures(t *testing.T) {
	st := NewStore(10, 1<<20)
	st.Apply(line(t, map[string]any{"ev": "hello", "mitmproxy": "12.3.1", "brotli": "1.2.1", "brotli_decode": true, "dropped_bodies": 3}))
	st.Apply(line(t, map[string]any{"ev": "tls_failed", "conn": "c1", "sni": "pinned.example"}))
	s := st.Stats()
	if s["mitmproxy"] != "12.3.1" || s["brotli_decode"] != true || s["tls_failures"] != 1 || s["addon_dropped_bodies"] != int64(3) {
		t.Fatalf("stats = %v", s)
	}
}

func TestStoreScopeAndIngestRedaction(t *testing.T) {
	allow, _ := ParseAllowHosts([]string{"*.example.net"})
	st := NewStore(10, 1<<20)
	st.SetScope(allow, true)
	st.Apply(line(t, map[string]any{"ev": "request", "id": "out", "host": "tracker.example.org", "url": "https://tracker.example.org/"}))
	st.Apply(line(t, map[string]any{"ev": "done", "id": "out"}))
	st.Apply(line(t, map[string]any{"ev": "request", "id": "in", "host": "api.example.net",
		"url":     "https://api.example.net/v1?q=1&access_token=abc123&Key=k",
		"path":    "/v1?q=1&access_token=abc123&Key=k",
		"headers": [][2]string{{"Referer", "https://app.example.net/?session=s1&tab=2"}, {"X-Trace", "token=keep-me"}}}))
	st.Apply(line(t, map[string]any{"ev": "error", "id": "in", "msg": "failed: https://api.example.net/v1?token=t9"}))

	s := st.Stats()
	if s["flows"] != 1 || s["out_of_scope"] != int64(1) {
		t.Fatalf("out-of-scope host recorded: %v", s)
	}
	v, _ := st.Get("in", false)
	stored := st.flows["in"]
	for _, got := range []string{v.URL, v.Path, v.ReqHeaders[0][1], v.Error, stored.URL} {
		if strings.Contains(got, "abc123") || strings.Contains(got, "=k") || strings.Contains(got, "s1") || strings.Contains(got, "t9") {
			t.Errorf("secret survived ingest: %q", got)
		}
	}
	if !strings.Contains(v.URL, "q=1") || !strings.Contains(v.ReqHeaders[0][1], "tab=2") || v.ReqHeaders[1][1] != "token=keep-me" {
		t.Errorf("masked too much: url=%q referer=%q x-trace=%q", v.URL, v.ReqHeaders[0][1], v.ReqHeaders[1][1])
	}

	raw := NewStore(10, 1<<20)
	raw.SetScope(allow, false) // --no-redact
	raw.Apply(line(t, map[string]any{"ev": "request", "id": "r", "host": "api.example.net", "url": "https://api.example.net/?token=abc",
		"headers": [][2]string{{"Authorization", "Bearer s3cret"}}}))
	if v, _ := raw.Get("r", false); v.URL != "https://api.example.net/?token=abc" || v.ReqHeaders[0][1] != "Bearer s3cret" {
		t.Errorf("--no-redact masked anyway: %+v", v)
	}
}

func listAll(st *Store, n int) []Summary { fs, _ := st.List(Filter{Limit: n}); return fs }
func listHost(st *Store, host string) []Summary {
	fs, _ := st.List(Filter{Host: host, Limit: 10})
	return fs
}
