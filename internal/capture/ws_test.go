package capture

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// wsEvent feeds the store a ws event as the addon sends it.
func wsEvent(s *Store, id string, n int, fromClient bool, text string, capped bool) {
	head := ""
	if !capped {
		head = base64.StdEncoding.EncodeToString([]byte(text))
	}
	s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"ws","id":%q,"from_client":%t,"size":%d,"text":true,"ts":%d,"head":%q,"capped":%t}`, id, fromClient, len(text), 1700000000+n, head, capped)))
}

func wsFlow(s *Store, id string) {
	s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"request","id":%q,"method":"GET","url":"wss://chat.example/ws","host":"chat.example","path":"/ws","headers":[]}`, id)))
	s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"response","id":%q,"status":101,"headers":[["Upgrade","websocket"]]}`, id)))
	s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"done","id":%q,"ts_end":1700000000}`, id)))
}

// TestWSMessages: kept heads (the first 5 and the newest 100), masked with
// the direction's rules, paged with after, missed counted, the close.
func TestWSMessages(t *testing.T) {
	s := NewStore(100, 1<<20)
	wsFlow(s, "w1")
	if v, _ := s.Get("w1", false); v.State != "open" {
		t.Errorf("an open socket reads %q", v.State)
	}
	cp := s.Checkpoint()
	wsEvent(s, "w1", 1, true, `{"type":"connection_init","payload":{"authToken":"WSsecret01x"}}`, false)
	wsEvent(s, "w1", 2, true, `42["authenticate","WSsecret02opaque"]`, false)
	wsEvent(s, "w1", 3, true, `WSsecret03ZxQ8r7Lm4Pq`, false)
	wsEvent(s, "w1", 4, false, `{"code":"ok","msg":"hi"}`, false)
	wsEvent(s, "w1", 5, true, "CONNECT\npasscode:WSsecret05\n\n\x00", false)
	for n := 6; n <= 300; n++ {
		wsEvent(s, "w1", n, n%2 == 0, fmt.Sprintf(`{"n":%d}`, n), n == 299)
	}
	p, err := s.WSList("w1", WSQuery{After: cp, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	all := ""
	for _, m := range p.Messages {
		all += m.Head + "\n"
	}
	for _, sec := range []string{"WSsecret01", "WSsecret02", "WSsecret03", "WSsecret05"} {
		if strings.Contains(all, sec) {
			t.Errorf("%s left in %q", sec, all)
		}
	}
	if !strings.Contains(all, `{"code":"ok","msg":"hi"}`) {
		t.Errorf("a server message lost: %q", all)
	}
	if p.Total != 300 || p.Missed != 195 || len(p.Messages) != 100 || !p.More || !p.Open {
		t.Errorf("page 1: total %d missed %d messages %d more %v open %v", p.Total, p.Missed, len(p.Messages), p.More, p.Open)
	}
	p2, _ := s.WSList("w1", WSQuery{After: p.After, Limit: 100})
	if len(p2.Messages) != 5 || p2.Missed != 0 || p2.More || p2.Messages[4].N != 300 {
		t.Errorf("page 2: %d messages, missed %d, more %v", len(p2.Messages), p2.Missed, p2.More)
	}
	for _, m := range p2.Messages {
		if m.N == 299 && (m.Head != "" || m.Note == "") {
			t.Errorf("a capped message: %+v", m)
		}
	}
	fromClient := false
	if p3, _ := s.WSList("w1", WSQuery{After: cp, FromClient: &fromClient, Text: `"msg":"hi"`}); len(p3.Messages) != 1 || p3.Messages[0].N != 4 {
		t.Errorf("filtered: %+v", p3.Messages)
	}
	if rows, _ := s.List(Filter{Query: "WSsecret", QueryBodies: true, Limit: 10}); len(rows) != 0 {
		t.Errorf("a masked secret found by search: %+v", rows)
	}
	if rows, _ := s.List(Filter{Query: `"n":300`, QueryBodies: true, Limit: 10}); len(rows) != 1 || rows[0].MatchedIn[0] != "websocket_messages" || rows[0].WSMessages != 300 {
		t.Errorf("search in messages: %+v", rows)
	}
	s.Apply([]byte(`{"v":2,"ev":"ws_end","id":"w1","ts_end":1700000400,"code":1000,"by_client":true,"reason":"bye, Bearer WSsecret06abc"}`))
	v, _ := s.Get("w1", false)
	if v.State != "done" || v.WSClose == nil || v.WSClose.Code != 1000 || strings.Contains(v.WSClose.Reason, "WSsecret06") || v.WSKept != 105 {
		t.Errorf("closed: state %s close %+v kept %d", v.State, v.WSClose, v.WSKept)
	}
	// A binary message, and text masking cannot read, keep no head.
	wsFlow(s, "w2")
	s.Apply([]byte(`{"v":2,"ev":"ws","id":"w2","from_client":true,"size":4,"text":false,"ts":1}`))
	s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"ws","id":"w2","from_client":true,"size":4,"text":true,"ts":1,"head":%q}`, base64.StdEncoding.EncodeToString([]byte("a\x01b\x02")))))
	if p, _ := s.WSList("w2", WSQuery{}); len(p.Messages) != 2 || p.Messages[0].Head != "" || p.Messages[1].Head != "" || p.Messages[1].Note == "" {
		t.Errorf("binary and control characters: %+v", p.Messages)
	}
	// Messages for an evicted flow are orphans, never a new flow.
	before := s.Stats()["orphan_updates"]
	wsEvent(s, "gone", 1, true, "x", false)
	if _, err := s.Get("gone", false); err == nil || s.Stats()["orphan_updates"] == before {
		t.Errorf("a message without its flow made one")
	}
}

// TestWSEvictionAndWait: an open socket that talks is moved back once
// instead of evicted first; a timed-out wait names it.
func TestWSEvictionAndWait(t *testing.T) {
	s := NewStore(3, 1<<20)
	wsFlow(s, "sock")
	wsEvent(s, "sock", 1, true, "hello", false)
	for i := range 3 {
		s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"request","id":"h%d","method":"GET","url":"https://chat.example/%d","host":"chat.example","path":"/","headers":[]}`, i, i)))
	}
	if _, err := s.Get("sock", false); err != nil {
		t.Errorf("the talking socket was evicted first")
	}
	cp := s.Checkpoint()
	wsEvent(s, "sock", 2, true, "again", false)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	r := s.Wait(ctx, Filter{}, cp)
	if len(r.Flows) != 0 || len(r.WSActive) != 1 || r.WSActive[0].ID != "sock" || r.WSActive[0].Messages != 1 {
		t.Errorf("wait: %+v", r)
	}
}

// TestWSE2E (REQCOVE_E2E=1): a real socket through mitmproxy: text heads
// masked, binary size only, the close, and a flood that neither stalls an
// HTTP flow beside it nor loses its count.
func TestWSE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	mux := http.NewServeMux()
	var wg sync.WaitGroup
	ended := make(chan struct{}) // the server got the last message: closing then loses none in flight
	mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) {
		websocket.Message.Send(ws, `{"type":"welcome","session_token":"WSe2eServer01"}`)
		for {
			var m []byte
			if websocket.Message.Receive(ws, &m) != nil {
				return
			}
			if string(m) == "end" {
				close(ended)
			}
		}
	}))
	mux.HandleFunc("/beside", func(w http.ResponseWriter, r *http.Request) { w.Write(bytes.Repeat([]byte("b"), 100<<10)) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	h := startHarness(t, ctx, []string{"127.0.0.1"})
	dial := h.client("ws-device").Transport.(*http.Transport).DialContext
	raw, err := dial(ctx, "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := websocket.NewConfig("ws://"+srv.Listener.Addr().String()+"/ws", srv.URL)
	ws, err := websocket.NewClient(cfg, raw)
	if err != nil {
		t.Fatal(err)
	}
	websocket.Message.Send(ws, `{"type":"connection_init","payload":{"Authorization":"Bearer WSe2eClient01abc"}}`)
	websocket.Message.Send(ws, []byte{0, 1, 2, 3})
	websocket.Message.Send(ws, strings.Repeat("x", 10<<10))
	wg.Add(1)
	go func() { // the flood
		defer wg.Done()
		for range 50000 {
			websocket.Message.Send(ws, "f")
		}
	}()
	start := time.Now()
	resp, err := h.client("ws-device").Get(srv.URL + "/beside")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	wg.Wait()
	websocket.Message.Send(ws, "end")
	select {
	case <-ended:
	case <-time.After(60 * time.Second):
		t.Fatal("the server never got the last message")
	}
	ws.Close()
	t.Logf("an HTTP request beside the flood: %v", time.Since(start).Round(time.Millisecond))
	var id string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		v, ok := h.findFlow("/ws", false)
		if ok && v.WSMessages >= 50004 && v.WSClose != nil {
			id = v.ID
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if id == "" {
		v, _ := h.findFlow("/ws", false)
		t.Fatalf("socket: %d messages, close %+v", v.WSMessages, v.WSClose)
	}
	if b := h.flowFor("/beside", false); b.RespBody.Size != 100<<10 {
		t.Errorf("the HTTP flow beside: %+v", b.RespBody)
	}
	p, _ := h.c.Store.WSList(id, WSQuery{Limit: 5})
	heads := ""
	for _, m := range p.Messages {
		heads += m.Head
	}
	if strings.Contains(heads, "WSe2eServer01") || strings.Contains(heads, "WSe2eClient01") || !strings.Contains(heads, "welcome") {
		t.Errorf("heads: %q", heads)
	}
	if len(p.Messages) < 4 || p.Messages[2].Head != "" || p.Messages[2].Text || p.Messages[3].Size != 10<<10 || !p.Messages[3].Truncated || len(p.Messages[3].Head) != wsHeadLimit {
		t.Errorf("binary and long messages: %+v", p.Messages[:min(4, len(p.Messages))])
	}
	last, _ := h.c.Store.WSList(id, WSQuery{After: p.After, Limit: 100})
	capped := 0
	for _, m := range last.Messages {
		if m.Note != "" && m.Head == "" {
			capped++
		}
	}
	if last.Missed == 0 || capped == 0 {
		t.Errorf("after the flood: missed %d, capped among the newest %d", last.Missed, capped)
	}
}

// TestWSFramingsCut: a secret in each framing apps put JSON in leaks at no
// cut of the message (heads are cut at 4 KiB, anywhere).
func TestWSFramingsCut(t *testing.T) {
	S := fuzzSecret
	for _, m := range []string{
		`42["message",{"token":"` + S + `","text":"hi"}]`,
		`42/chat,["join",{"auth":{"password":"` + S + `"}}]`,
		`42["authenticate","` + S + `"]`,
		`{"type":1,"target":"Send","arguments":[{"password":"` + S + `"}]}` + "\x1e",
		`["1","1","room:lobby","phx_join",{"token":"` + S + `"}]`,
		`{"command":"subscribe","identifier":"{\"channel\":\"Chat\",\"token\":\"` + S + `\"}"}`,
		`{"type":"connection_init","payload":{"Authorization":"` + S + `"}}`,
		"CONNECT\naccept-version:1.2\npasscode:" + S + "\n\n\x00",
		`["CONNECT\nlogin:guest\npasscode:` + S + `\n\n\u0000"]`,
	} {
		at := strings.Index(m, S)
		for cut := at; cut <= len(m); cut++ {
			if got := maskWSMessage(m[:cut], true); leak(got, S[:min(len(S), cut-at)]) != "" && cut-at >= 5 {
				t.Errorf("%q cut at %d: %q", m, cut, got)
				break
			}
		}
	}
	// A bare token as the whole message (heads are cut at 4 KiB only, so a
	// short one comes whole); a server's is not looked at so, nor a sentence.
	if got := maskWSMessage(S+"Zq81", true); leak(got, S) != "" {
		t.Errorf("a bare token: %q", got)
	}
	for _, m := range []string{"ping", "hello there 123 Abc", "2probe", `{"n":1}`} {
		if got := maskWSMessage(m, true); got != m {
			t.Errorf("%q -> %q", m, got)
		}
	}
}

// TestWSItemReview: the item review of WebSocket messages (Opus).
func TestWSItemReview(t *testing.T) {
	S := fuzzSecret
	// Truncated framing never panics, and a panic anywhere in Apply is a bad
	// line, not a crash.
	for _, m := range []string{`["`, `42["`, `[ "`, `42/chat,["`, `{"target":"`, `{"target":"Authenticate","arguments":["`} {
		maskWSMessage(m, true)
	}
	s := NewStore(5, 1<<20)
	wsFlow(s, "p")
	wsEvent(s, "p", 1, true, `["`, false)
	if v, err := s.Get("p", false); err != nil || v.WSMessages != 1 {
		t.Errorf("a truncated message: %v %+v", err, v)
	}
	// socket.io with a namespace and an ack id; a token as one JSON string;
	// SignalR's records, an auth target's arguments among them.
	for _, m := range []string{
		`42/chat,12["authenticate","` + S + `"]`,
		`"` + S + `aa11"`,
		`{"protocol":"json","version":1}` + "\x1e" + `{"type":1,"target":"Authenticate","arguments":["` + S + `"]}` + "\x1e",
	} {
		if got := maskWSMessage(m, true); leak(got, S) != "" {
			t.Errorf("%q -> %q", m, got)
		}
	}
	wsFlow(s, "sr")
	sr := `{"type":1,"target":"Send","arguments":["hello"]}` + "\x1e"
	wsEvent(s, "sr", 1, true, sr, false)
	if p, _ := s.WSList("sr", WSQuery{}); len(p.Messages) != 1 || p.Messages[0].Head != sr {
		t.Errorf("a SignalR message: %+v", p.Messages)
	}
	// Paging stays newest first, and complete, while an open socket is passed
	// over at eviction.
	s = NewStore(5, 1<<20)
	wsFlow(s, "sock")
	wsEvent(s, "sock", 1, true, "hi", false)
	for i := range 8 {
		s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"request","id":"h%d","method":"GET","url":"https://x.example/%d","host":"x.example","path":"/","headers":[]}`, i, i)))
	}
	var ids []string
	for cursor := int64(0); ; {
		rows, next := s.List(Filter{Limit: 1, Before: cursor})
		for _, r := range rows {
			ids = append(ids, r.ID)
		}
		if next == 0 {
			break
		}
		cursor = next
	}
	if strings.Join(ids, ",") != "h7,h6,h5,h4,sock" {
		t.Errorf("pages after eviction: %v", ids)
	}
	// A 101 that is no WebSocket is done at once.
	s.Apply([]byte(`{"v":2,"ev":"request","id":"h2c","method":"GET","url":"http://x.example/","host":"x.example","path":"/","headers":[]}`))
	s.Apply([]byte(`{"v":2,"ev":"response","id":"h2c","status":101,"headers":[["Upgrade","h2c"]]}`))
	s.Apply([]byte(`{"v":2,"ev":"done","id":"h2c","ts_end":1700000000}`))
	if v, _ := s.Get("h2c", false); v.State != "done" {
		t.Errorf("an h2c 101: %s", v.State)
	}
	// A cursor among the dropped messages: missed is an upper bound.
	s = NewStore(10, 1<<20)
	wsFlow(s, "m")
	var cp int64
	for n := 1; n <= 500; n++ {
		wsEvent(s, "m", n, true, "x", false)
		if n == 300 {
			cp = s.Checkpoint()
		}
	}
	if p, _ := s.WSList("m", WSQuery{After: cp}); !p.MissedAtMost || p.Messages[0].N != 401 {
		t.Errorf("a cursor among dropped messages: %+v", p)
	}
	// Cursors are microseconds: a flood of messages cannot pass the next run's base.
	if c := NewStore(1, 1).Checkpoint(); c < time.Now().UnixMicro()-int64(time.Minute/time.Microsecond) {
		t.Errorf("checkpoint %d is not in µs", c)
	}
}

// FuzzWSMessage: masking a message, in either direction, never panics.
func FuzzWSMessage(f *testing.F) {
	for _, m := range []string{`42["authenticate","x"]`, `42/chat,1["login",{"a":1},"y"]`, `{"target":"Login","arguments":["z"]}` + "\x1e", `"tok"`, "CONNECT\npasscode:x\n\n\x00"} {
		f.Add(m, true)
	}
	f.Fuzz(func(t *testing.T, m string, fromClient bool) { maskWSMessage(m, fromClient) })
}

// TestWSReReview: the re-review of the fixes (Fable).
func TestWSReReview(t *testing.T) {
	S := fuzzSecret
	for _, m := range []string{`\` + S + `0`, `"` + S + `\/aa11"`} {
		if got := maskWSMessage(m, true); leak(got, S) != "" {
			t.Errorf("%q -> %q", m, got)
		}
	}
	// 0x1e outside SignalR's records is no framing: such text is not handed out.
	s := NewStore(10, 1<<20)
	wsFlow(s, "x")
	wsEvent(s, "x", 1, true, "password\x1e"+S, false)
	if p, _ := s.WSList("x", WSQuery{}); p.Messages[0].Head != "" {
		t.Errorf("0x1e not between objects: %q", p.Messages[0].Head)
	}
	// capture_stats' window starts after a passed-over socket.
	s = NewStore(3, 1<<20)
	wsFlow(s, "sock")
	wsEvent(s, "sock", 1, true, "hi", false)
	for i := range 5 {
		s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"request","id":"h%d","method":"GET","url":"https://x.example/%d","host":"x.example","path":"/","headers":[],"ts":%d}`, i, i, 1800000000+i)))
	}
	if o := s.Stats()["oldest_flow"]; o != unixTime(1800000003).Format("2006-01-02T15:04:05.000Z07:00") {
		t.Errorf("oldest_flow %v", o)
	}
}
