package capture

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// TestV05MaskingGaps: leaks the v0.5 plan review found in v0.4.0, and its
// leftovers (each fails with its fix taken out).
func TestV05MaskingGaps(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJHYXBzMDEifQ.R2Fwc1NpZ25hdHVyZTAx"
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	s := NewStore(10, 1<<20)

	// AppSync realtime: the Authorization header as base64 JSON in the URL.
	hdr := b64(`{"host":"x.appsync-api.example.com","Authorization":"GapsAppSync01x"}`)
	for _, v := range []string{hdr, url.QueryEscape(hdr), strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimRight(hdr, "=")), hdr[:len(hdr)-3]} {
		u := s.mask("wss://x.appsync-realtime-api.example.com/graphql?header=" + v + "&payload=e30=")
		if strings.Contains(u, v) || !strings.Contains(u, "header=REDACTED") || !strings.Contains(u, "payload=e30=") {
			t.Errorf("AppSync header: %s", u)
		}
	}
	if harmless := b64(`{"host":"x.example.com"}`); !strings.Contains(s.mask("wss://h.example/?header="+harmless), harmless) {
		t.Errorf("base64 JSON with nothing secret was masked")
	}

	// Sec-WebSocket-Protocol carrying a credential.
	for _, c := range []struct{ in, gone, keep string }{
		{"access_token, GapsProto01abcdef", "GapsProto01", "access_token"},
		{"graphql-ws, header-" + b64(`{"Authorization":"GapsProto02x"}`), b64(`{"Authorization":"GapsProto02x"}`), "graphql-ws, header-[redacted]"},
		{"base64url.bearer.authorization.k8s.io.R2Fwc1Byb3RvMDM, base64.binary.k8s.io", "R2Fwc1Byb3RvMDM", "base64.binary.k8s.io"},
		{"chat, Zx9" + strings.Repeat("Gaps04Ab", 4), "Gaps04Ab", "chat"},
	} {
		got := s.maskHeaders([][2]string{{"Sec-WebSocket-Protocol", c.in}})[0][1]
		if strings.Contains(got, c.gone) || !strings.Contains(got, c.keep) {
			t.Errorf("Sec-WebSocket-Protocol %q -> %q", c.in, got)
		}
	}
	for _, v := range []string{"graphql-ws", "graphql-transport-ws", "v12.stomp, v11.stomp", "mqtt"} {
		if got := s.maskHeaders([][2]string{{"Sec-WebSocket-Protocol", v}})[0][1]; got != v {
			t.Errorf("a plain protocol list %q -> %q", v, got)
		}
	}

	// name: value lines (STOMP, YAML).
	for _, c := range []struct {
		body       string
		request    bool
		gone, keep []string
	}{
		{"CONNECT\naccept-version:1.2\nlogin:alice\npasscode:GapsStomp01\nhost:/\n\n\x00", true, []string{"GapsStomp01"}, []string{"login:alice", "host:/", "passcode:[redacted]"}},
		{"SEND\ndestination:/q\nX-Auth-Token: GapsStomp02\n\nhello\x00", true, []string{"GapsStomp02"}, []string{"destination:/q", "hello"}},
		{"user: a\npassword: GapsYaml03\nretries: 3\n", true, []string{"GapsYaml03"}, []string{"user: a", "retries: 3"}},
		{"code: 123456\n", true, []string{"123456"}, nil},
		{"code: 404\nmessage: not found\n", false, nil, []string{"code: 404"}},
		{"auth: Bearer GapsBearer05abc\n", true, []string{"GapsBearer05"}, []string{"Bearer [redacted]"}},
	} {
		got := string(maskBody([]byte(c.body), "text/plain", c.request))
		for _, g := range c.gone {
			if strings.Contains(got, g) {
				t.Errorf("%q: %q left in %q", c.body, g, got)
			}
		}
		for _, k := range c.keep {
			if !strings.Contains(got, k) {
				t.Errorf("%q: %q lost in %q", c.body, k, got)
			}
		}
	}

	// Token shapes behind percent-encoding, in forms and URLs.
	for _, f := range []string{
		"data=" + url.QueryEscape(`{"t":"`+jwt+`"}`) + "&a=1",
		"a=1&msg=" + url.QueryEscape(`said "`+jwt),
		"msg=Bearer+GapsBearer06abcdef&a=1",
		"q=" + url.QueryEscape(`{a(id:"`+jwt+`")}`),
	} {
		got := string(maskBody([]byte(f), "application/x-www-form-urlencoded", true))
		if strings.Contains(got, "R2Fwc1NpZ25hdHVyZTAx") || strings.Contains(got, "GapsBearer06") || !strings.Contains(got, "=") {
			t.Errorf("form %q -> %q", f, got)
		}
	}
	for _, u := range []string{
		"https://h.example/x?q=" + url.QueryEscape(`{"t":"`+jwt+`"}`) + "&page=2",
		"https://h.example/x?q=" + url.QueryEscape("ghp_"+strings.Repeat("Gaps07ab", 5)),
		"https://h.example/x?auth=Bearer+GapsBearer08abcdef&page=2",
	} {
		if got := s.mask(u); strings.Contains(got, "R2Fwc1NpZ25hdHVyZTAx") || strings.Contains(got, "Gaps07ab") || strings.Contains(got, "GapsBearer08") || !strings.Contains(got, "page=2") && strings.Contains(u, "page=2") {
			t.Errorf("URL %q -> %q", u, got)
		}
	}

	// Content types that are JSON under another name are handed out.
	for _, ct := range []string{"application/x-amz-json-1.1", "application/vnd.api+json; charset=utf-8", "application/x-sentry-envelope"} {
		if !checkable(Body{Head: []byte(`{"a":1}`), Decoded: true}, [][2]string{{"Content-Type", ct}}) {
			t.Errorf("%s is not handed out", ct)
		}
	}
	if checkable(Body{Head: []byte("\x00\x00\x00\x00\x07{\"a\":1}"), Decoded: true}, [][2]string{{"Content-Type", "application/grpc+json"}}) {
		t.Errorf("a gRPC envelope is handed out as text")
	}
}

// TestV05OperationNits: the row reads an operation as mocks do.
func TestV05OperationNits(t *testing.T) {
	for _, c := range []struct{ body, op string }{
		{`{"OperationName":"Upper","query":"query Feed { a }"}`, "Feed"},                            // keys by their exact case, as mocks read them
		{`{"operationName":5,"query":"query Feed { a }"}`, "Feed"},                                  // a name that is not a string is absent
		{`{"variables":{"input":{"operationName":"Inner"}},"operationName":"Outer","x":"`, "Outer"}, // cut: the top-level key, not the nested one
		{`{"variables":{"input":{"operationName":"Inner"}},"x":"`, ""},
		{`[{"operationName":"A","query":"query A { a }"},{"query":"query B`, gqlBatched},
	} {
		if got := gqlBodyOperation([]byte(c.body)); got != c.op {
			t.Errorf("%s: %q, want %q", c.body, got, c.op)
		}
	}
}

// TestV05ItemReview: the item review of the masking gaps (Opus).
func TestV05ItemReview(t *testing.T) {
	b64 := func(x string) string { return base64.StdEncoding.EncodeToString([]byte(x)) }
	s := NewStore(10, 1<<20)

	// A GraphQL document one argument per line keeps its variables and
	// aliases, and its operation (lines are for text that is no document).
	doc := "fragment F on Q {\n  session: viewer {\n    id\n  }\n}\nmutation Login {\n  login(\n    password: $password\n  ) {\n    refreshToken: refresh_token\n  }\n}\n"
	got := string(maskBody([]byte(doc), "application/graphql", true))
	if !strings.Contains(got, "password: $password") || !strings.Contains(got, "refreshToken: refresh_token") || !strings.Contains(got, "session: viewer {") || gqlBodyOperation([]byte(got)) != "Login" {
		t.Errorf("a document: %q (operation %q)", got, gqlBodyOperation([]byte(got)))
	}
	// STOMP inside JSON strings (SockJS), whole and cut anywhere.
	for _, frame := range []string{
		`["CONNECT\nlogin:guest\npasscode:ReviewSockJS01\naccept-version:1.1,1.0\n\n\u0000"]`,
		`["SEND\ndestination:/q\npasscode:ReviewSockJS02\n\nhi"]`,
	} {
		at := strings.Index(frame, "passcode:") + len("passcode:")
		for cut := at; cut <= len(frame); cut++ {
			if got := string(maskBody([]byte(frame[:cut]), "text/plain", true)); strings.Contains(got, "ReviewSockJS0"[:min(cut-at, 13)]) && cut-at >= 5 {
				t.Errorf("SockJS cut at %d: %q", cut, got)
				break
			}
		}
	}
	// A binary type whose name says json is not handed out as text.
	if checkable(Body{Head: []byte("{i\x08passwordSi\x07hunter2}"), Decoded: true}, [][2]string{{"Content-Type", "application/ubjson"}}) {
		t.Errorf("UBJSON handed out")
	}
	// After access_token, a token that reads as a secret name in camelCase.
	if got := s.maskHeaders([][2]string{{"Sec-WebSocket-Protocol", "access_token, v3AGnKzk3uJV6jPw"}})[0][1]; strings.Contains(got, "v3AGnKzk") {
		t.Errorf("Sec-WebSocket-Protocol token: %q", got)
	}
	// Long dotted protocol names stay.
	for _, p := range []string{"json.reliable.webpubsub.azure.v1", "protobuf.reliable.webpubsub.azure.v1, json.webpubsub.azure.v1"} {
		if got := s.maskHeaders([][2]string{{"Sec-WebSocket-Protocol", p}})[0][1]; got != p {
			t.Errorf("Sec-WebSocket-Protocol %q -> %q", p, got)
		}
	}
	// Base64 of { then CR LF or a tab.
	for _, j := range []string{"{\r\n  \"Authorization\": \"ReviewB64a01\"\r\n}", "{\t\"token\":\"ReviewB64b01\"}"} {
		if got := s.mask("https://h.example/x?header=" + url.QueryEscape(b64(j)) + "&p=1"); !strings.Contains(got, "header=REDACTED") {
			t.Errorf("base64 JSON %q: %s", j, got)
		}
	}
	if got := s.mask("https://h.example/x?h=e30="); !strings.Contains(got, "h=e30=") {
		t.Errorf("base64 of {} masked: %s", got)
	}
}
