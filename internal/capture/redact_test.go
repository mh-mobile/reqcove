package capture

import (
	"strings"
	"testing"
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
			"auth: Bearer S3CRET8abcdefgh jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.S3CRET9sigsig key AKIAS3CRETS3CRETABCD gh ghp_S3CRET0123456789012345678901234567 sk-S3CRETaaaaaaaaaaaaaaaaaa",
			[]string{"S3CRET8", "S3CRET9", "AKIAS3CRET", "ghp_S3CRET", "sk-S3CRET"}, []string{"auth: Bearer [redacted]"}},
		{"run-together and acronym names", "application/json", `{"accesstoken":"S3CRET-10","APIToken":"S3CRET-11","verification_code":"S3CRET-12","token_type":"Bearer","error_code":"E1"}`,
			[]string{"S3CRET-10", "S3CRET-11", "S3CRET-12"}, []string{`"token_type":"Bearer"`, `"error_code":"E1"`}},
		{"escaped key", "application/json", `{"pass\u0077ord":"S3CRET-13"}`, []string{"S3CRET-13"}, nil},
		{"cut right after a backslash", "application/json", `{"password":"S3CRET-14\`, []string{"S3CRET-14"}, nil},
		{"JSON sent as a form", "application/x-www-form-urlencoded", `{"password":"S3CRET-15"}`, []string{"S3CRET-15"}, nil},
		{"form sent as text", "text/plain", `user=u&password=S3CRET-16`, []string{"S3CRET-16"}, []string{"user=u"}},
		{"sentences stay", "text/html", `<p>Basic information about the token provided</p>`, nil, []string{"Basic information about the token provided"}},
		{"Basic credentials", "text/plain", `Authorization header was Basic dXNlcjpwYXNzd29yZA==`, []string{"dXNlcjpwYXNz"}, []string{"Basic [redacted]"}},
	} {
		got := string(maskBody([]byte(c.in), c.ctype))
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
	if string(maskBody(bin, "application/json")) != string(bin) {
		t.Error("a head that is not text was changed")
	}
}

// Heads are masked as they arrive, a head that is not text is never handed
// out nor searched while masking, and --no-redact keeps them as they were.
func TestBodiesMaskedOnArrival(t *testing.T) {
	st := NewStore(10, 1<<20)
	st.Apply(line(t, map[string]any{"ev": "request", "id": "a", "host": "h", "url": "https://h/login", "headers": [][2]string{{"Content-Type", "application/json"}}}))
	st.Apply(line(t, map[string]any{"ev": "body", "id": "a", "dir": "request", "head": b64(`{"user":"u","password":"S3CRET-1"}`), "size": 30, "final": true}))
	st.Apply(line(t, map[string]any{"ev": "response", "id": "a", "status": 200, "headers": [][2]string{{"Content-Type", "application/octet-stream"}, {"X-Debug", "Bearer S3CRET2abcdefgh"}}}))
	st.Apply(line(t, map[string]any{"ev": "body", "id": "a", "dir": "response", "head": b64("\x00\x01binary S3CRET-3"), "size": 20, "final": true}))
	st.Apply(line(t, map[string]any{"ev": "request", "id": "b", "host": "h", "url": "https://h/upload"}))
	st.Apply(line(t, map[string]any{"ev": "body", "id": "b", "dir": "request", "head": b64("\x00\x02protobuf S3CRET-4"), "size": 20, "final": true}))
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
	st.Apply(line(t, map[string]any{"ev": "body", "id": "a", "dir": "response", "head": b64(`{"city":"ÉCOLE Zürich"}`), "size": 20, "final": true}))
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
		maskBody(head, "application/json")
	}
}
