package capture

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMaskBody(t *testing.T) {
	for _, c := range []struct {
		name, ctype, in string
		gone            []string // must not survive
		keep            []string // must survive
	}{
		{"json fields, nested and camelCase", "application/json",
			`{"user":{"email":"a@example.com","password":"S3CRET-1"},"accessToken":"S3CRET-2","refresh_token":"S3CRET-3","expires_in":3600,"code":"invalid_grant"}`,
			[]string{"S3CRET-1", "S3CRET-2", "S3CRET-3"}, []string{`"email":"a@example.com"`, `"expires_in":3600`, `"code":"invalid_grant"`, `"password":"[redacted]"`}},
		{"escaped quote in a value", "application/json", `{"password":"a\"S3CRET-4","x":"y"}`,
			[]string{"S3CRET-4"}, []string{`"x":"y"`}},
		{"head cut inside the value", "application/json", `{"ok":true,"access_token":"S3CRET-5abc`,
			[]string{"S3CRET-5"}, []string{`"ok":true`}},
		{"form", "application/x-www-form-urlencoded; charset=UTF-8", `grant_type=authorization_code&code=S3CRET-6&client_secret=S3CRET-7&redirect_uri=x`,
			[]string{"S3CRET-6", "S3CRET-7"}, []string{"grant_type=authorization_code", "redirect_uri=x"}},
		{"shapes anywhere in text", "text/plain",
			"auth: Bearer S3CRET8abcdefgh\njwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.S3CRET9sigsig key AKIAS3CRETS3CRETABCD gh ghp_S3CRET0123456789012345678901234567 sk-S3CRETaaaaaaaaaaaaaaaaaa",
			[]string{"S3CRET8", "S3CRET9", "AKIAS3CRET", "ghp_S3CRET", "sk-S3CRET"}, []string{"auth: Bearer [redacted]"}},
		{"run-together and acronym names", "application/json", `{"accesstoken":"S3CRET-10","APIToken":"S3CRET-11","verification_code":"S3CRET-12","token_type":"Bearer","error_code":"E1"}`,
			[]string{"S3CRET-10", "S3CRET-11", "S3CRET-12"}, []string{`"token_type":"Bearer"`, `"error_code":"E1"`}},
		{"OpenTelemetry attributes: a key that names one stays", "application/json",
			`{"attributes":[{"key":"service.name","value":{"stringValue":"app"}},{"key":"http.request.method","value":{"stringValue":"GET"}}]}`,
			nil, []string{`"key":"service.name"`, `"key":"http.request.method"`}},
		{"a key that is one: masked", "application/json",
			`{"a":{"key":"AIzaS3CRET-18abcdefghijklmn"},"b":{"key":"sk_live_s3cret19abcdef"},"c":{"key":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.S3CRET20sig"},"d":{"api_key":"s3cret21.dotted.value"},"e":{"KEY":"S3CRET22.Abc"},"f":{"key":"live.s3cret23a8f3c9d2"},"g":{"key":"v1.s3cret24","note":"x"}}`,
			[]string{"S3CRET-18", "s3cret19", "S3CRET20", "s3cret21", "S3CRET22", "s3cret23", "s3cret24"}, nil},
		{"a WebSocket's ticket", "application/json", `{"wsTicket":"S3CRET-17","ticket_id":"T-42"}`,
			[]string{"S3CRET-17"}, []string{`"ticket_id":"T-42"`}},
		{"escaped key", "application/json", `{"pass\u0077ord":"S3CRET-13"}`, []string{"S3CRET-13"}, nil},
		{"cut right after a backslash", "application/json", `{"password":"S3CRET-14\`, []string{"S3CRET-14"}, nil},
		{"JSON sent as a form", "application/x-www-form-urlencoded", `{"password":"S3CRET-15"}`, []string{"S3CRET-15"}, nil},
		{"form sent as text", "text/plain", `user=u&password=S3CRET-16`, []string{"S3CRET-16"}, []string{"user=u"}},
		{"sentences stay", "text/html", `<p>Basic information about the token provided</p>`, nil, []string{"Basic information about the token provided"}},
		{"Basic credentials", "text/plain", `Authorization header was Basic dXNlcjpwYXNzd29yZA==`, []string{"dXNlcjpwYXNz"}, []string{"Basic [redacted]"}},
	} {
		got := string(maskBody([]byte(c.in), c.ctype, false))
		for _, g := range c.gone {
			if strings.Contains(got, g) {
				t.Errorf("%s: %q survived: %s", c.name, g, got)
			}
		}
		for _, k := range c.keep {
			if !strings.Contains(got, k) {
				t.Errorf("%s: %q was lost: %s", c.name, k, got)
			}
		}
	}
	bin := []byte{0x1f, 0x8b, 0, 'p', 'a', 's', 's'}
	if string(maskBody(bin, "application/json", false)) != string(bin) {
		t.Error("a head that is not text was changed")
	}
}

// Heads are masked as they arrive, a head that is not text is never handed
// out nor searched while masking, and --no-redact keeps them as they were.
func TestBodiesMaskedOnArrival(t *testing.T) {
	st := NewStore(10, 1<<20)
	st.Apply(line(t, map[string]any{"ev": "request", "id": "a", "host": "h", "url": "https://h/login", "headers": [][2]string{{"Content-Type", "application/json"}}}))
	st.Apply(line(t, map[string]any{"ev": "body", "id": "a", "dir": "request", "head": b64(`{"user":"u","password":"S3CRET-1"}`), "size": 30, "final": true, "decoded": true}))
	st.Apply(line(t, map[string]any{"ev": "response", "id": "a", "status": 200, "headers": [][2]string{{"Content-Type", "application/octet-stream"}, {"X-Debug", "Bearer S3CRET2abcdefgh"}}}))
	st.Apply(line(t, map[string]any{"ev": "body", "id": "a", "dir": "response", "head": b64("\x00\x01binary S3CRET-3"), "size": 20, "final": true, "decoded": true}))
	st.Apply(line(t, map[string]any{"ev": "request", "id": "b", "host": "h", "url": "https://h/upload"}))
	st.Apply(line(t, map[string]any{"ev": "body", "id": "b", "dir": "request", "head": b64("\x00\x02protobuf S3CRET-4"), "size": 20, "final": true, "decoded": true}))
	v, _ := st.Get("a", true)
	if strings.Contains(v.ReqBodyText, "S3CRET") || !strings.Contains(v.ReqBodyText, `"user":"u"`) {
		t.Errorf("request body: %q", v.ReqBodyText)
	}
	if v.RespBodyText != "" || v.RespBodyEnc != omittedBody {
		t.Errorf("binary response body handed out: %q %q", v.RespBodyText, v.RespBodyEnc)
	}
	if h := header(v.RespHeaders, "x-debug"); strings.Contains(h, "S3CRET") {
		t.Errorf("Bearer under an unmarked header: %q", h)
	}
	for _, q := range []string{"S3CRET-1", "S3CRET-3", "S3CRET-4", "binary", "protobuf"} {
		if fs, _ := st.List(Filter{Query: q, QueryBodies: true, Limit: 10}); len(fs) != 0 {
			t.Errorf("search %q found %v", q, fs[0].MatchedIn)
		}
	}
	if fs, _ := st.List(Filter{Query: "USER", QueryBodies: true, Limit: 10}); len(fs) != 1 {
		t.Error("case-insensitive body search lost")
	}
}

func TestMaskURLsNested(t *testing.T) {
	for _, in := range []string{
		"https://app.example/login?next=https://x.example/cb?token=S3CRET-1",
		"https://app.example/login?return_to=https%3A%2F%2Fx.example%2Fcb%3Faccess_token%3DS3CRET-2",
	} {
		if got := maskURLs(in); strings.Contains(got, "S3CRET") {
			t.Errorf("nested secret survived: %s", got)
		}
	}
	// In a URL, key= stays a secret whatever its value (Google's API keys).
	if got := maskURLs("https://maps.example/api?key=service.name"); got != "https://maps.example/api?key=REDACTED" {
		t.Errorf("key= in a URL: %s", got)
	}
	// A WebSocket's ticket in its URL (as an app sent one, seen in use).
	if got := maskURLs("wss://app.example/ws?wsTicket=S3CRETtkt0123&room=1"); got != "wss://app.example/ws?wsTicket=REDACTED&room=1" {
		t.Errorf("wsTicket: %s", got)
	}
	if got := maskURLs("https://app.example/s?q=hello&country_code=JP&sort_key=name"); got != "https://app.example/s?q=hello&country_code=JP&sort_key=name" {
		t.Errorf("ordinary values masked: %s", got)
	}
}

func TestMaskErrorAndReason(t *testing.T) {
	st := NewStore(10, 1<<20)
	if got := st.maskError("job's queue failed: Invalid header line: b'Set-Cookie sid=S3CRET-1'"); strings.Contains(got, "S3CRET") || !strings.Contains(got, "job's queue") {
		t.Errorf("maskError: %s", got)
	}
	st.Apply(line(t, map[string]any{"ev": "request", "id": "r", "host": "h", "url": "https://h/"}))
	st.Apply(line(t, map[string]any{"ev": "response", "id": "r", "status": 401, "reason": "Bearer S3CRET2abcdefgh rejected"}))
	if v, _ := st.Get("r", false); strings.Contains(v.Reason, "S3CRET") || st.flows["r"].bytes() < len("rejected") {
		t.Errorf("reason %q, bytes %d", v.Reason, st.flows["r"].bytes())
	}
}

func TestBodySearchNonASCII(t *testing.T) {
	st := NewStore(10, 1<<20)
	st.Apply(line(t, map[string]any{"ev": "request", "id": "a", "host": "h", "url": "https://h/"}))
	st.Apply(line(t, map[string]any{"ev": "body", "id": "a", "dir": "response", "head": b64(`{"city":"ÉCOLE Zürich"}`), "size": 20, "final": true, "decoded": true}))
	for _, q := range []string{"ÉCOLE", "Zürich", "zürich"} {
		if fs, _ := st.List(Filter{Query: q, QueryBodies: true, Limit: 10}); len(fs) != 1 {
			t.Errorf("search %q found nothing", q)
		}
	}
}

func BenchmarkMaskBody64K(b *testing.B) {
	var sb strings.Builder
	for sb.Len() < 64<<10 {
		sb.WriteString(`{"id":12345,"name":"widget","description":"a plain item with words","tags":["a","b"],"price":9.99},`)
	}
	head := []byte(sb.String()[:64<<10])
	b.SetBytes(int64(len(head)))
	for b.Loop() {
		maskBody(head, "application/json", false)
	}
}

// From the second review (Codex): each way a secret still got out.
func TestSecondReviewLeaks(t *testing.T) {
	st := NewStore(100, 1<<20)
	ev := func(m map[string]any) { st.Apply(line(t, m)) }
	// A head not decoded (wire bytes of an encoding not undone) or a protobuf
	// that happens to be valid UTF-8: neither handed out nor searched.
	ev(map[string]any{"ev": "request", "id": "a", "host": "h", "url": "https://h/a"})
	ev(map[string]any{"ev": "response", "id": "a", "status": 200, "headers": [][2]string{{"Content-Encoding", "br"}}})
	ev(map[string]any{"ev": "body", "id": "a", "dir": "response", "head": b64("U0VDUkVUX1dJUkU= S3CRET-1"), "size": 30, "decoded": false})
	ev(map[string]any{"ev": "request", "id": "b", "host": "h", "url": "https://h/b", "headers": [][2]string{{"Content-Type", "application/x-protobuf"}}})
	ev(map[string]any{"ev": "body", "id": "b", "dir": "request", "head": b64("\n\nBIN S3CRET-2"), "size": 20, "decoded": true})
	for _, id := range []string{"a", "b"} {
		v, _ := st.Get(id, true)
		if strings.Contains(v.ReqBodyText+v.RespBodyText, "S3CRET") {
			t.Errorf("%s: body handed out: %q %q", id, v.ReqBodyText, v.RespBodyText)
		}
	}
	for _, q := range []string{"S3CRET-1", "S3CRET-2"} {
		if fs, _ := st.List(Filter{Query: q, QueryBodies: true, Limit: 10}); len(fs) != 0 {
			t.Errorf("search %q found it", q)
		}
	}
	// Valid JSON escapes in a key: \/ and a surrogate-free \u.
	if got := string(maskBody([]byte(`{"password\/":"S3CRET-3","n":1}`), "application/json", false)); strings.Contains(got, "S3CRET") {
		t.Errorf("escaped key: %s", got)
	}
	// Header names in their own case, schemes in any case, challenges kept.
	h := st.maskHeaders([][2]string{{"X-ClientKey", "S3CRET-4"}, {"X-Debug", "BEARER Abcdefgh0123456789"}, {"WWW-Authenticate", `Bearer realm=production, error="invalid_token"`}})
	if h[0][1] != "[redacted]" || strings.Contains(h[1][1], "Abcdefgh0123") || h[2][1] != `Bearer realm=production, error="invalid_token"` {
		t.Errorf("headers: %q", h)
	}
	// A secret value with ';' in it is masked whole.
	if got := maskURLs("https://h/x?password=prefix;S3CRET-5&page=2"); strings.Contains(got, "S3CRET") || !strings.Contains(got, "page=2") {
		t.Errorf("semicolon value: %s", got)
	}
}

// A crafted value nested many times over cannot make masking slow.
// The v0.8.0 review: escapes that hide a credential's shape (\t, \r, \/),
// in a cut string too, and a secret-named line with a token in its value.
func TestV080ReviewBodies(t *testing.T) {
	suffix := `","note":"Basic\tdXNlcjpwYXNzd29yZA==`
	at64K := `{"pad":"` + strings.Repeat("a", 64<<10-len(`{"pad":"`)-len(suffix)) + suffix
	for in, secrets := range map[string][]string{
		`{"note":"Basic\tdXNlcjpwYXNzd29yZA=="}`:           {"dXNlcjpwYXNzd29yZA"},
		`{"note":"Basic YWJj\/ZGVmZ2hpamtsbW5vcA=="}`:      {"ZGVmZ2hpamtsbW5vcA"},
		`["Basic\rdXNlcjpwYXNzd29yZA=="]`:                  {"dXNlcjpwYXNzd29yZA"},
		`{"a":1,"note":"Basic\tdXNlcjpwYXNzd29yZA==`:       {"dXNlcjpwYXNzd29yZA"},
		`{"a":1,"note":"\x Basic\tdXNlcjpwYXNzd29yZA==`:    {"dXNlcjpwYXNzd29yZA"}, // cut, and not JSON
		`{"d":"{\"n\":\"Basic\\tdXNlcjpwYXNzd29yZA==\"}"}`: {"dXNlcjpwYXNzd29yZA"},
		at64K: {"dXNlcjpwYXNzd29yZA"},
		"password: plainSecret123 Bearer OtherToken456": {"plainSecret123", "OtherToken456"},
	} {
		got := string(maskBody([]byte(in), "", true))
		for _, s := range secrets {
			if leak(got, s) != "" {
				t.Errorf("%s left in %.200q", s, got[max(0, len(got)-200):])
			}
		}
	}
	// What the line keeps: its name, and a scheme only when the value is that credential alone.
	for in, want := range map[string]string{
		"password: plainSecret123 Bearer OtherToken456": "password: [redacted]",
		"authorization: Bearer OtherToken456  ":         "authorization: Bearer [redacted]",
		"auth: Basic dXNlcjpwYXNzd29yZA== extra":        "auth: [redacted]",
	} {
		if got := string(maskBody([]byte(in), "text/plain", true)); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	// Escaped strings with nothing to mask are left as they were written.
	for _, in := range []string{`{"url":"https:\/\/h.example\/a\/b?x=1","t":"a\tb"}`, `["line\r\nnext"]`} {
		if got := string(maskBody([]byte(in), "application/json", true)); got != in {
			t.Errorf("%q -> %q", in, got)
		}
	}
}

func TestMaskURLsDeepNestingIsBounded(t *testing.T) {
	v := "https://h/x" + strings.Repeat("?a=", 8192) + "end"
	start := time.Now()
	maskURLs(v)
	if d := time.Since(start); d > slow*200*time.Millisecond {
		t.Errorf("8192 levels took %v", d)
	}
}

// Third review: secrets whose names say so, in places masking did not look.
func TestThirdReviewLeaks(t *testing.T) {
	st := NewStore(100, 1<<20)
	ev := func(m map[string]any) { st.Apply(line(t, m)) }
	body := func(id, dir, ctype, text string) {
		ev(map[string]any{"ev": "request", "id": id, "host": "h", "url": "https://h/" + id, "headers": [][2]string{{"Content-Type", ctype}}})
		ev(map[string]any{"ev": "response", "id": id, "status": 200, "headers": [][2]string{{"Content-Type", ctype}}})
		ev(map[string]any{"ev": "body", "id": id, "dir": dir, "head": b64(text), "size": len(text), "decoded": true})
	}
	cases := map[string]struct{ dir, ctype, text, keep string }{
		"json in json":      {"request", "application/json", `{"event":"login","payload":"{\"user\":\"u\",\"password\":\"S3CRET\"}"}`, `\"user\":\"u\"`},
		"json in form":      {"request", "application/x-www-form-urlencoded", `a=1&data=%7B%22password%22%3A%22S3CRET%22%7D`, "a=1"},
		"names":             {"request", "application/json", `{"pass":"S3CRET-a","totp":"S3CRET-b","pw":"S3CRET-c","csrf":"S3CRET-d","authentication":"S3CRET-e","xsrf_value":"S3CRET-f"}`, ""},
		"lone code request": {"request", "application/json", `{"phone":"+1555","code":"S3CRET"}`, "+1555"},
		"numbers":           {"request", "application/json", `{"otp": 914253, "pin":-1234, "n": 7}`, `"n": 7`},
		"url in json":       {"response", "application/json", `{"upload_url":"https://s3.example/x?X-Amz-Signature=S3CRET&X-Amz-Security-Token=S3CRET","next":"https://h/p?page=2\u0026access_token=S3CRET"}`, "page=2"},
		"url in html":       {"response", "text/html", `<a href="/cb?code=S3CRET">go</a> <a href='https://user:S3CRET@h/x'>`, `">go</a>`},
	}
	for name, c := range cases {
		body(name, c.dir, c.ctype, c.text)
		v, _ := st.Get(name, true)
		got := v.ReqBodyText + v.RespBodyText
		if strings.Contains(got, "S3CRET") || !strings.Contains(got, c.keep) {
			t.Errorf("%s: %q", name, got)
		}
	}
	if v, _ := st.Get("numbers", true); strings.Contains(v.ReqBodyText, "914253") || strings.Contains(v.ReqBodyText, "1234") {
		t.Errorf("numeric OTP or PIN kept: %q", v.ReqBodyText)
	}
	// In a response, a lone code stays: it is an error code.
	body("lone code response", "response", "application/json", `{"code":"invalid_grant"}`)
	if v, _ := st.Get("lone code response", true); !strings.Contains(v.RespBodyText, "invalid_grant") {
		t.Errorf("response error code masked: %q", v.RespBodyText)
	}

	ev(map[string]any{"ev": "request", "id": "hd", "host": "h", "url": "https://h/hd"})
	ev(map[string]any{"ev": "response", "id": "hd", "status": 401, "headers": [][2]string{
		{"WWW-Authenticate", `Bearer realm="api", error_description="token eyJhbGciOiJI.eyJzdWIiOiIx.S3CRETsig expired"`},
		{"Link", `<https://h/x?access_token=S3CRET>; rel="next"`},
		{"Refresh", "0; url=https://h/cb?code=S3CRET"},
		{"X-Original-URL", "/cb?token=S3CRET"},
		{"Location", "https://user:S3CRET@h/"},
	}})
	v, _ := st.Get("hd", false)
	all := fmt.Sprint(v.RespHeaders)
	if strings.Contains(all, "S3CRET") || !strings.Contains(all, `realm="api"`) || !strings.Contains(all, `rel="next"`) {
		t.Errorf("headers: %s", all)
	}
}

// Text a site sends besides headers and bodies counts toward the bound, and
// a dead mitmdump's error on open flows too: held_bytes stays the sum.
func TestOtherTextCountsTowardBytes(t *testing.T) {
	st := NewStore(1000, 64<<10)
	big := strings.Repeat("e", 16<<10)
	for i := range 20 {
		id := fmt.Sprint(i)
		st.Apply(line(t, map[string]any{"ev": "request", "id": id, "host": "h", "url": "https://h/" + id}))
		st.Apply(line(t, map[string]any{"ev": "body", "id": id, "dir": "response", "head": b64("x"), "size": 1, "encoding": big, "note": "cannot decode " + big}))
	}
	if s := st.Stats(); s["held_bytes"].(int) > 64<<10 || s["evicted"].(int64) == 0 {
		t.Errorf("20 x 32 KiB of encoding and note under a 64 KiB bound: %v", s)
	}
	st2 := NewStore(1000, 1<<20)
	for i := range 3 {
		st2.Apply(line(t, map[string]any{"ev": "request", "id": fmt.Sprint(i), "host": "h", "url": "https://h/"}))
	}
	st2.mitmdumpExited("mitmdump exited: signal: killed")
	sum := 0
	for _, f := range st2.flows {
		sum += f.bytes()
	}
	if held := st2.Stats()["held_bytes"].(int); held != sum {
		t.Errorf("held_bytes %d, flows hold %d", held, sum)
	}
}

// A long query over many full heads stays fast (it holds the store).
func TestSearchLongQueryIsLinear(t *testing.T) {
	st := NewStore(1000, 64<<20)
	head := b64(strings.Repeat("a", 60<<10))
	for i := range 64 {
		id := fmt.Sprint(i)
		st.Apply(line(t, map[string]any{"ev": "request", "id": id, "host": "h", "url": "https://h/" + id, "headers": [][2]string{{"Content-Type", "text/plain"}}}))
		st.Apply(line(t, map[string]any{"ev": "body", "id": id, "dir": "request", "head": head, "size": 60 << 10, "decoded": true}))
	}
	start := time.Now()
	st.List(Filter{Query: strings.Repeat("a", 2000) + "b", QueryBodies: true, Limit: 100})
	if d := time.Since(start); d > slow*time.Second {
		t.Errorf("search took %v", d)
	}
}

// Fourth review: what the wider masking broke or still missed.
func TestFourthReview(t *testing.T) {
	// ';name=value' chains stay linear (a site sends them in a header or a body).
	chain := strings.Repeat(";a=1", 16<<10) // 64 KiB
	start := time.Now()
	maskBody([]byte("x?q=1"+chain), "text/plain", false)
	maskURLs("https://h/x?q=1" + chain + chain + chain + chain) // 256 KiB, a header's bound
	if d := time.Since(start); d > slow*2*time.Second {
		t.Errorf("';' chains took %v", d)
	}

	keep := map[string]string{
		// long values that only hold ordinary parameters are not masked for their length
		"long encoded json": "a=1&payload=" + url.QueryEscape(`{"next":"https://h/p?x=1","pad":"`+strings.Repeat("p", 12<<10)+`"}`),
		"long base64":       "name=x&image=" + strings.Repeat("QUJD", 3<<10) + "==",
		"names":             `{"authentication_type":"sms","authentication_method":"password"}`,
		"html in json":      `{"msg":"{\"html\":\"<b>&</b>\",\"password\":\"S3CRET\"}"}`,
	}
	for name, in := range keep {
		got := string(maskBody([]byte(in), "", true))
		if strings.Contains(got, "S3CRET") || strings.Count(got, "REDACTED")+strings.Count(got, "[redacted]") > strings.Count(in, "S3CRET") {
			t.Errorf("%s: %.200q", name, got)
		}
	}
	if got := string(maskBody([]byte(keep["html in json"]), "", true)); !strings.Contains(got, `<b>&</b>`) {
		t.Errorf("HTML escaped when written back: %q", got)
	}

	leak := map[string]string{
		"cut json in json": `{"event":"login","payload":"{\"user\":\"u\",\"password\":\"S3CRET\",\"pad\":\"xxx`,
		"form cut in %XX":  `a=1&data=%7B%22user%22%3A%22u%22%2C%22password%22%3A%22S3CRET%22%7`,
		"escaped slashes":  `{"url":"https:\/\/user:S3CRET@h\/x"}`,
		"encoded userinfo": `{"u":"https://h/?redirect=https%3A%2F%2Fuser%3AS3CRET%40h%2Fx"}`,
	}
	for name, in := range leak {
		if got := string(maskBody([]byte(in), "", true)); strings.Contains(got, "S3CRET") {
			t.Errorf("%s: %q", name, got)
		}
	}
	// A form's secret fields read the same, first or not.
	if got := string(maskBody([]byte("password=S3CRET&a=1&pass=S3CRET"), "application/x-www-form-urlencoded", true)); got != "password=[redacted]&a=1&pass=[redacted]" {
		t.Errorf("form: %q", got)
	}
	// An error message cut inside mitmproxy's b'…' is masked to its end.
	st := NewStore(10, 1<<20)
	if got := st.maskError("Invalid header line: b'Set-Cookie sid=S3CRET; " + strings.Repeat("x", 1000)); strings.Contains(got, "S3CRET") || !strings.HasPrefix(got, "Invalid header line: ") {
		t.Errorf("cut b'…': %.120q", got)
	}
}

// The v0.8.0 review (Opus): a nameless cookie after the first, name=value
// lines, key with a number or after "primary", cookies joined in one Set-Cookie.
func TestV080OpusReview(t *testing.T) {
	st := NewStore(10, 1<<20)
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.S3CRETsig0"
	for in, want := range map[[2]string]string{
		{"Cookie", "theme=dark; S3CRETnameless1; lang=ja; " + jwt}: "theme=[redacted]; [redacted]; lang=[redacted]; [redacted]",
		// one header line joining cookies (some servers send it): each is masked, a date's comma is not a cookie's
		{"Set-Cookie", "sid=S3CRET2; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT, auth=S3CRET3; HttpOnly,theme=dark"}: "sid=[redacted]; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT, auth=[redacted]; HttpOnly,theme=[redacted]",
		{"Set-Cookie", "sid=S3CRET4; Expires=Wednesday, 21-Oct-26 07:28:00 GMT; Path=/"}:                                "sid=[redacted]; Expires=Wednesday, 21-Oct-26 07:28:00 GMT; Path=/",
	} {
		if got := st.maskHeaders([][2]string{in})[0][1]; got != want {
			t.Errorf("%s: %q, want %q", in[0], got, want)
		}
	}
	if got := string(maskPart([]byte("\r\nContent-Disposition: form-data; name=\"x\"\r\nCookie: a=1; S3CRETnameless5\r\n\r\nplain"), true, false)); strings.Contains(got, "S3CRET") {
		t.Errorf("a part's Cookie: %q", got)
	}

	// name=value bodies with a newline: a form ending with one, .env lines.
	form := "password=S3CRET6&user=bob\n"
	for _, got := range []string{string(maskBody([]byte(form), "text/plain", true)), string(maskBody([]byte(form), "", true)), maskWSMessage(form, true)} {
		if got != "password=[redacted]&user=bob\n" {
			t.Errorf("form with a newline: %q", got)
		}
	}
	env := "DEBUG=true\nAPI_KEY=S3CRET7\n  DB_PASSWORD = \"S3CRET8\"\nexport AUTH_TOKEN=S3CRET9\nNAME=app\n"
	for _, got := range []string{string(maskBody([]byte(env), "text/plain", false)), maskWSMessage(env, false)} {
		if got != "DEBUG=true\nAPI_KEY=[redacted]\n  DB_PASSWORD = [redacted]\nexport AUTH_TOKEN=[redacted]\nNAME=app\n" {
			t.Errorf(".env lines: %q", got)
		}
	}

	// key as one word, a number after it too; primary is no everyday word.
	for _, n := range []string{"primaryKey", "PrimaryKey", "primary_key", "key1", "Key2", "apiKey2", "pin1", "x-key-2"} {
		if !secretName(n) {
			t.Errorf("%s not secret", n)
		}
	}
	for _, n := range []string{"sort_key", "country_code", "foreign_key", "keyword1", "author2", "monkey3", "sort_key2"} {
		if secretName(n) {
			t.Errorf("%s secret", n)
		}
	}
	if got := string(maskBody([]byte(`{"primaryKey":"S3CRET10","key1":"S3CRET11","sort_key":"name"}`), "application/json", false)); strings.Contains(got, "S3CRET") || !strings.Contains(got, `"sort_key":"name"`) {
		t.Errorf("JSON: %s", got)
	}

	// Each stays linear: a header's 256 KiB and a body's 64 KiB of the shapes.
	start := time.Now()
	st.maskHeaders([][2]string{
		{"Set-Cookie", strings.Repeat("a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT, ", 6<<10)},
		{"Set-Cookie", strings.Repeat(",", 256<<10)},
		{"Cookie", strings.Repeat("x; ", 85<<10)},
	})
	maskBody([]byte(strings.Repeat("API_KEY=x\n", 6<<10)), "text/plain", false)
	maskBody([]byte(strings.Repeat("a=", 32<<10)), "text/plain", false)
	maskBody([]byte(`[`+strings.Repeat(`"key1=x\n",`, 5<<10)+`""]`), "application/json", false)
	if d := time.Since(start); d > slow*time.Second {
		t.Errorf("took %v", d)
	}
}
