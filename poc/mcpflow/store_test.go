package main

import (
	"encoding/json"
	"testing"
)

func line(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStoreMergesAndRedacts(t *testing.T) {
	st := newStore(10)
	st.apply(line(t, map[string]any{"v": 1, "ev": "request", "id": "a", "device": "phone", "host": "api.example.net",
		"headers": [][2]string{{"Authorization", "Bearer s3cret"}, {"Cookie", "sid=1"}, {"Accept", "*/*"}}}))
	st.apply(line(t, map[string]any{"v": 1, "ev": "response", "id": "a", "status": 200,
		"headers": [][2]string{{"Set-Cookie", "a=1"}, {"set-cookie", "b=2"}, {"Content-Type", "text/plain"}},
		"body":    "aGVsbG8=", "body_size": 5}))

	v, err := st.get("a", true)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != 200 || v.RespBody != "hello" || v.Device != "phone" {
		t.Fatalf("merged flow = %+v", v)
	}
	for _, h := range append(v.ReqHeaders, v.RespHeaders...) {
		if secretHeaders[lower(h[0])] && h[1] != "[redacted]" {
			t.Errorf("header %s not redacted: %q", h[0], h[1])
		}
	}
	if len(v.RespHeaders) != 3 {
		t.Errorf("repeated Set-Cookie lost: %v", v.RespHeaders)
	}
	// The stored flow itself keeps the real values; only views are masked.
	if st.flows["a"].ReqHeaders[0][1] != "Bearer s3cret" {
		t.Error("redaction modified the stored flow")
	}
}

func TestStoreRejectsAndEvicts(t *testing.T) {
	st := newStore(2)
	st.apply([]byte("not json"))
	st.apply(line(t, map[string]any{"v": 2, "ev": "request", "id": "x"}))
	st.apply(line(t, map[string]any{"v": 1, "ev": "response", "id": "nope"}))
	for _, id := range []string{"1", "2", "3"} {
		st.apply(line(t, map[string]any{"v": 1, "ev": "request", "id": id, "host": "h"}))
	}
	s := st.stats()
	if s["bad_lines"] != 1 || s["unknown_version"] != 1 || s["orphan_updates"] != 1 || s["flows"] != 2 {
		t.Fatalf("stats = %v", s)
	}
	if got := st.list("", "", 10); len(got) != 2 || got[0].ID != "3" || got[1].ID != "2" {
		t.Fatalf("list = %+v, want 3 then 2", got)
	}
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
