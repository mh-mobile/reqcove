package capture

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
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
		st.Apply(line(t, map[string]any{"ev": "body", "id": id, "dir": "response", "head": b64("abcdef"), "size": 6, "decoded": true}))
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

func TestBodyTextPerBody(t *testing.T) {
	if s, enc := bodyText([]byte(`{"a":1}`), false); s != `{"a":1}` || enc != "" {
		t.Errorf("json: %q %q", s, enc)
	}
	if _, enc := bodyText([]byte{0x1f, 0x8b, 0, 1}, false); enc != "base64" {
		t.Errorf("binary: %q", enc)
	}
	cut := []byte("日本語")[:7] // the head limit fell inside the third character
	if s, enc := bodyText(cut, true); s != "日本" || enc != "" {
		t.Errorf("cut text: %q %q", s, enc)
	}
	if s, enc := bodyText(cut, false); enc != "base64" || s == "" {
		t.Errorf("an untruncated invalid head is not text: %q %q", s, enc)
	}
	// One flow: binary request, JSON response.
	st := NewStore(10, 1<<20)
	st.Apply(line(t, map[string]any{"ev": "request", "id": "x", "host": "h"}))
	st.Apply(line(t, map[string]any{"ev": "body", "id": "x", "dir": "request", "head": base64.StdEncoding.EncodeToString([]byte{0x1f, 0x8b, 0}), "size": 3, "final": true, "decoded": true}))
	st.Apply(line(t, map[string]any{"ev": "body", "id": "x", "dir": "response", "head": b64(`{"ok":true}`), "size": 11, "final": true, "decoded": true}))
	v, _ := st.Get("x", true)
	// While masking, a head that is not text cannot be checked, so it is omitted.
	if v.ReqBodyText != "" || v.ReqBodyEnc != omittedBody || v.RespBodyEnc != "" || v.RespBodyText != `{"ok":true}` {
		t.Errorf("per body: req %q/%q resp %q/%q", v.ReqBodyText, v.ReqBodyEnc, v.RespBodyText, v.RespBodyEnc)
	}
	st.SetScope(HostRules{All: true}, false) // --no-redact
	if v, _ := st.Get("x", true); v.ReqBodyEnc != "base64" || v.ReqBodyText == "" {
		t.Errorf("--no-redact: req %q/%q", v.ReqBodyText, v.ReqBodyEnc)
	}
}

func TestSecretName(t *testing.T) {
	for name, want := range map[string]bool{
		"Authorization": true, "X-Auth-Token": true, "accessToken": true, "oauth_token": true, "session_id": true,
		"X-Amz-Signature": true, "X-Amz-Credential": true, "Ocp-Apim-Subscription-Key": true, "apiKey": true, "api-key": true,
		"jsessionid": true, "PHPSESSID": true, "code": true, "jwt": true, "client_secret": true,
		"accesstoken": true, "x-authtoken": true, "sessiontoken": true, "APIToken": true, "IDToken": true, "XAuth": true,
		"passcode": true, "passphrase": true, "secretkey": true, "privatekey": true, "otp": true, "pin": true, "verification_code": true,
		"author": false, "keyword": false, "monkey": false, "page": false, "state": false, "User-Agent": false,
		"Content-Type": false, "Accept": false, "view": false, "type": false, "codec": false,
		"token_type": false, "country_code": false, "error_code": false, "sort_key": false, "WWW-Authenticate": false,
		"sign": true, "X-Sign": true, "sign_type": true, "design": false, "signup": false, "assignee": false,
		"wsTicket": true, "ticket": true, "X-Ticket": true, "DPoP": true, "ticket_id": false, "ticketNumber": false,
	} {
		if got := secretName(name); got != want {
			t.Errorf("secretName(%q) = %v, want %v (words %q)", name, got, want, nameWords(name))
		}
	}
}

// Headers count toward the byte bound, not only body heads: a site can send big ones.
func TestHeadersCountTowardBytes(t *testing.T) {
	st := NewStore(1000, 64<<10) // 64 KiB
	big := strings.Repeat("h", 16<<10)
	for i := range 20 {
		id := fmt.Sprint(i)
		st.Apply(line(t, map[string]any{"ev": "request", "id": id, "host": "h", "url": "https://h/" + id}))
		st.Apply(line(t, map[string]any{"ev": "response", "id": id, "status": 200, "headers": [][2]string{{"X-Big", big}}}))
	}
	s := st.Stats()
	if s["held_bytes"].(int) > 64<<10 || s["evicted"].(int64) == 0 {
		t.Errorf("20 x 16 KiB of headers under a 64 KiB bound: %v", s)
	}
	// Many small headers cost more than their text: each counts its overhead too.
	st2 := NewStore(1000, 1<<20)
	var many [][2]string
	for i := range 4096 {
		many = append(many, [2]string{"h", fmt.Sprint(i % 10)})
	}
	st2.Apply(line(t, map[string]any{"ev": "request", "id": "m", "host": "h", "url": "https://h/", "headers": many}))
	if n := st2.Stats()["held_bytes"].(int); n < 4096*64 {
		t.Errorf("4096 small headers held as %d bytes", n)
	}
}

// A rules event (--rules-reload) replaces what the hello said about the
// rules, keeps the rest of it, and is told to SetRulesLog.
func TestRulesEvent(t *testing.T) {
	st := NewStore(10, 1<<20)
	st.Apply(line(t, map[string]any{"ev": "hello", "mitmproxy": "12.3.1", "rules": map[string]int{"map_remote": 1}}))
	var told []string
	st.SetRulesLog(func(r map[string]int, _, _ []string, _ map[string]string, problem string) {
		told = append(told, fmt.Sprintf("%v %s", r, problem))
	})
	st.Apply(line(t, map[string]any{"ev": "rules", "rules": map[string]int{"map_remote": 2}, "rules_error": ""}))
	st.Apply(line(t, map[string]any{"ev": "rules", "rules": map[string]int{"map_remote": 2}, "rules_error": "map_remote[1]: bad"}))
	s := st.Stats()
	if fmt.Sprint(s["rules"]) != "map[map_remote:2]" || s["rules_error"] != "map_remote[1]: bad" || s["mitmproxy"] != "12.3.1" {
		t.Errorf("stats: rules %v, error %v, mitmproxy %v", s["rules"], s["rules_error"], s["mitmproxy"])
	}
	if want := []string{"map[map_remote:2] ", "map[map_remote:2] map_remote[1]: bad"}; !slices.Equal(told, want) {
		t.Errorf("told %q", told)
	}
}

// The rules log is called with the store unlocked: run's calls the store
// (PresetTargets), which hung every record and tool for good (v0.7.0-v0.8.0).
// It is handed the presets' targets too.
func TestRulesLogUnlocked(t *testing.T) {
	st := NewStore(10, 1<<20)
	var got string
	st.SetRulesLog(func(_ map[string]int, _, presets []string, targets map[string]string, _ string) {
		got = fmt.Sprint(presets, targets, st.PresetTargets(), st.Stats()["rules"])
	})
	done := make(chan struct{})
	go func() {
		st.Apply(line(t, map[string]any{"ev": "rules", "rules": map[string]int{"map_remote": 1}, "presets": []string{"staging"},
			"preset_targets": map[string]string{"staging": "https://staging.example"}}))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Apply of a rules event did not return: the rules log ran under the store's lock")
	}
	if want := "[staging] map[staging:https://staging.example] map[staging:https://staging.example] map[map_remote:1]"; got != want {
		t.Errorf("told %q, want %q", got, want)
	}
}
