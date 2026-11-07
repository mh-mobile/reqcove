package main

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
	st := newStore(10, 1<<20)
	st.apply(line(t, map[string]any{"ev": "request", "id": "a", "device": "phone", "host": "api.example.net",
		"headers": [][2]string{{"Authorization", "Bearer s3cret"}, {"Cookie", "sid=1"}, {"Accept", "*/*"}}}))
	st.apply(line(t, map[string]any{"ev": "response", "id": "a", "status": 200,
		"headers": [][2]string{{"Set-Cookie", "a=1"}, {"set-cookie", "b=2"}, {"Content-Type", "text/plain"}}}))
	// A partial head (still streaming), then the final one.
	st.apply(line(t, map[string]any{"ev": "body", "id": "a", "dir": "response", "head": b64("hel"), "size": 3, "decoded": true}))
	if v, _ := st.get("a", true); v.State != "open" || v.RespBodyText != "hel" || v.RespBody.Final {
		t.Fatalf("while streaming: state=%q head=%q final=%v", v.State, v.RespBodyText, v.RespBody.Final)
	}
	st.apply(line(t, map[string]any{"ev": "body", "id": "a", "dir": "response", "head": b64("hello"), "size": 5, "final": true, "decoded": true}))
	st.apply(line(t, map[string]any{"ev": "done", "id": "a", "ts_end": 1.5}))

	v, err := st.get("a", true)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != 200 || v.RespBodyText != "hello" || v.Device != "phone" || v.State != "done" || !v.RespBody.Final {
		t.Fatalf("merged flow = %+v", v)
	}
	for _, h := range append(v.ReqHeaders, v.RespHeaders...) {
		if secretHeaders[strings.ToLower(h[0])] && h[1] != "[redacted]" {
			t.Errorf("header %s not redacted: %q", h[0], h[1])
		}
	}
	if len(v.RespHeaders) != 3 {
		t.Errorf("repeated Set-Cookie lost: %v", v.RespHeaders)
	}
	if st.flows["a"].ReqHeaders[0][1] != "Bearer s3cret" {
		t.Error("redaction modified the stored flow")
	}
}

func TestStoreBoundsAndRejects(t *testing.T) {
	st := newStore(100, 10) // 10 bytes of body heads
	st.apply([]byte("not json"))
	st.apply([]byte(`{"v":1,"ev":"request","id":"old"}`)) // wire version 1
	st.apply(line(t, map[string]any{"ev": "done", "id": "nope"}))
	for _, id := range []string{"1", "2", "3"} {
		st.apply(line(t, map[string]any{"ev": "request", "id": id, "host": "h"}))
		st.apply(line(t, map[string]any{"ev": "body", "id": id, "dir": "response", "head": b64("abcdef"), "size": 6}))
	}
	s := st.stats()
	if s["bad_lines"] != int64(1) || s["unknown_version"] != int64(1) || s["orphan_updates"] != int64(1) {
		t.Fatalf("stats = %v", s)
	}
	// 3 flows x 6 bytes > 10: the oldest go first until the heads fit.
	if s["flows"] != 1 || s["held_bytes"] != 6 || s["evicted"] != int64(2) {
		t.Fatalf("byte bound not enforced: %v", s)
	}
	if got := st.list("", "", 10); len(got) != 1 || got[0].ID != "3" {
		t.Fatalf("list = %+v, want only 3", got)
	}
}

func TestStoreKeepsHelloAndTLSFailures(t *testing.T) {
	st := newStore(10, 1<<20)
	st.apply(line(t, map[string]any{"ev": "hello", "mitmproxy": "12.3.1", "brotli": "1.2.1", "brotli_decode": true, "dropped_bodies": 3}))
	st.apply(line(t, map[string]any{"ev": "tls_failed", "conn": "c1", "sni": "pinned.example"}))
	s := st.stats()
	if s["mitmproxy"] != "12.3.1" || s["brotli_decode"] != true || s["tls_failures"] != 1 || s["addon_dropped_bodies"] != int64(3) {
		t.Fatalf("stats = %v", s)
	}
}
