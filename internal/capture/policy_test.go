package capture

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func setPolicy(t *testing.T, names, values []string) {
	t.Helper()
	if err := SetMaskPolicy(names, values); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { SetMaskPolicy(nil, nil) })
}

// TestMaskNames: a --mask-names name is secret wherever names count, in any
// spelling (ClientRef, client_ref, client-ref), and is counted.
func TestMaskNames(t *testing.T) {
	setPolicy(t, []string{"clientRef"}, nil)
	s := NewStore(10, 1<<20)
	if h := s.maskHeaders([][2]string{{"X-Client-Ref", "ab12"}, {"Client-Ref", "cd34"}}); h[1][1] != "[redacted]" {
		t.Errorf("header: %v", h)
	}
	if u := s.mask("https://a.example/?client_ref=ef56&page=2"); strings.Contains(u, "ef56") || !strings.Contains(u, "page=2") {
		t.Errorf("URL: %s", u)
	}
	if b := string(maskBody([]byte(`{"clientRef":"gh78","name":"x"}`), "application/json", false)); strings.Contains(b, "gh78") || !strings.Contains(b, `"x"`) {
		t.Errorf("JSON: %s", b)
	}
	if got := policyStats()["mask_names"].(map[string]int64)["clientref"]; got < 3 {
		t.Errorf("hits: %d", got)
	}
	// Without the policy, the same name is not secret.
	SetMaskPolicy(nil, nil)
	if b := string(maskBody([]byte(`{"clientRef":"gh78"}`), "application/json", false)); !strings.Contains(b, "gh78") {
		t.Errorf("without the policy: %s", b)
	}
}

// TestMaskValues: a --mask-values pattern's matches go wherever they appear:
// inside a User-Agent (the key= case seen), a URL, a body, an error.
func TestMaskValues(t *testing.T) {
	setPolicy(t, nil, []string{`key=[A-Za-z0-9]{16,}`})
	s := NewStore(10, 1<<20)
	ua := s.maskHeaders([][2]string{{"User-Agent", "Bank/5.1 (iPhone) key=AbCdEf0123456789xyz CFNetwork/1"}})[0][1]
	if strings.Contains(ua, "AbCdEf0123456789xyz") || !strings.Contains(ua, "Bank/5.1 (iPhone)") || !strings.Contains(ua, "CFNetwork/1") {
		t.Errorf("User-Agent: %s", ua)
	}
	if b := string(maskBody([]byte(`{"ua":"x key=AbCdEf0123456789xyz"}`), "application/json", false)); strings.Contains(b, "AbCdEf") {
		t.Errorf("body: %s", b)
	}
	if e := s.maskError("failed for key=AbCdEf0123456789xyz"); strings.Contains(e, "AbCdEf") {
		t.Errorf("error: %s", e)
	}
	if got := policyStats()["mask_values"].([]int64); len(got) != 1 || got[0] < 3 {
		t.Errorf("hits: %v", got)
	}
}

// TestMaskPolicyErrors: bad patterns are refused, by number, never quoted.
func TestMaskPolicyErrors(t *testing.T) {
	defer SetMaskPolicy(nil, nil)
	for _, c := range []struct {
		values []string
		want   string
	}{
		{[]string{`ok`, `S3CRETVALUE(`}, "pattern 2"},
		{[]string{`a*`}, "matches empty text"},
		{make([]string, maxMaskValues+1), "at most"},
		{[]string{strings.Repeat("S3CRETVALUE", 100)}, "longer than"},
	} {
		err := SetMaskPolicy(nil, c.values)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "S3CRET") {
			t.Errorf("%.30q: %v", c.values, err)
		}
	}
	if err := SetMaskPolicy([]string{"--"}, nil); err == nil {
		t.Error("a name with no letters")
	}
}

// TestMaskGraphQL: string arguments with secret names in a GraphQL document,
// which is one JSON string (escaped), a raw body, or a GET parameter; cut
// strings and block strings too; other arguments kept.
func TestMaskGraphQL(t *testing.T) {
	for _, c := range []struct{ body, gone, kept string }{
		{`{"query":"mutation { login(username: \"alice\", password: \"p4ssw0rd\") { token } }"}`, "p4ssw0rd", `username: \"alice\"`},
		{`{"query":"mutation {\n  login(\n    password: \"p4ssw0rd\"\n  ) { ok } }"}`, "p4ssw0rd", "login("},
		{"mutation { login(password: \"p4ssw0rd\", id: \"7\") { ok } }", "p4ssw0rd", `id: "7"`},
		{`{"query":"mutation { login(password: \"p4ssw0`, "p4ssw0", "login("},
		{"mutation { setKey(apiKey: \"\"\"k3yvalue\"\"\") { ok } }", "k3yvalue", "setKey("},
		{`{"query":"{ user(id: \"123\") { name } }"}`, "", `id: \"123\"`},
		// The query's own escaped quote inside the JSON string (\\\"), and a block string written in JSON.
		{`{"query":"mutation{login(password: \"ab\\\"cdSECRET\")}"}`, "cdSECRET", "login("},
		{`{"query":"mutation{setKey(apiKey: \"\"\"k3ySECRET\"\"\")}"}`, "k3ySECRET", "setKey("},
	} {
		got := string(maskBody([]byte(c.body), "application/json", true))
		if c.gone != "" && strings.Contains(got, c.gone) || !strings.Contains(got, c.kept) {
			t.Errorf("%s\n -> %s", c.body, got)
		}
	}
	s := NewStore(10, 1<<20)
	if u := s.mask("https://a.example/graphql?query=mutation%7Blogin(password%3A%22p4ssw0rd%22)%7D&op=Login"); strings.Contains(u, "p4ssw0rd") || !strings.Contains(u, "op=Login") {
		t.Errorf("GET: %s", u)
	}
	// GraphQL's GET variables: JSON in a parameter.
	if u := s.mask("https://a.example/graphql?query=q&variables=%7B%22password%22%3A%22hunter2%22%2C%22n%22%3A1%7D&op=Login"); strings.Contains(u, "hunter2") || !strings.Contains(u, "op=Login") {
		t.Errorf("GET variables: %s", u)
	}
}

// BenchmarkMaskBodyPolicy: a 64 KiB JSON head, with and without 32 patterns
// (masking runs under the Store's lock).
func BenchmarkMaskBodyPolicy(b *testing.B) {
	head := []byte(`{"items":[` + strings.Repeat(`{"id":12345,"name":"widget","note":"key=AbCdEf0123456789xyz https://x.example/?q=1"},`, 700) + `0]}`)[:64<<10]
	var pats []string
	for i := range maxMaskValues {
		pats = append(pats, fmt.Sprintf(`tok%d-[A-Za-z0-9]{20,}`, i))
	}
	for _, c := range []struct {
		name string
		pats []string
	}{{"none", nil}, {"32 patterns", pats}} {
		b.Run(c.name, func(b *testing.B) {
			if err := SetMaskPolicy(nil, c.pats); err != nil {
				b.Fatal(err)
			}
			defer SetMaskPolicy(nil, nil)
			b.SetBytes(int64(len(head)))
			for b.Loop() {
				maskBody(head, "application/json", false)
			}
		})
	}
}

// TestCORSCredentialsKept: the CORS header that names credentials holds
// only "true": it is not masked.
func TestCORSCredentialsKept(t *testing.T) {
	s := NewStore(10, 1<<20)
	h := s.maskHeaders([][2]string{{"Access-Control-Allow-Credentials", "true"}, {"X-Credential", "c"}})
	if h[0][1] != "true" || h[1][1] != "[redacted]" {
		t.Errorf("%v", h)
	}
}

// TestPolicyOverExceptions: the user's names and patterns win over the
// built-in exceptions: OTLP's dotted "key", WWW-Authenticate kept as a
// challenge, a cookie's attributes.
func TestPolicyOverExceptions(t *testing.T) {
	setPolicy(t, []string{"key", "WWW-Authenticate"}, []string{`S3CRETPATH[0-9]+`})
	s := NewStore(10, 1<<20)
	if b := string(maskBody([]byte(`{"key":"service.name","value":{"x":1}}`), "application/json", false)); strings.Contains(b, "service.name") {
		t.Errorf("--mask-names key and an OTLP key: %s", b)
	}
	h := s.maskHeaders([][2]string{{"WWW-Authenticate", `Bearer realm="api"`}, {"Set-Cookie", "sid=x; Path=/S3CRETPATH42"}})
	if h[0][1] != "[redacted]" || strings.Contains(h[1][1], "S3CRETPATH42") {
		t.Errorf("headers: %v", h)
	}
}

// TestMaskEscapedAndCommented: a shape hidden behind \u escapes, and GraphQL
// arguments after a line break or a comment, inside JSON.
func TestMaskEscapedAndCommented(t *testing.T) {
	for _, c := range []struct{ body, gone string }{
		{`{"data":"` + "\\" + "u0073k-abcdefghijklmnopqrstuvwxyz0123" + `"}`, "abcdefghijklmnopqrstuvwxyz0123"}, // \u-escaped s: no sk- in the raw text
		{`{"query":"mutation { login(password:\n  \"p4ssw0rdNL\") { ok } }"}`, "p4ssw0rdNL"},
		{`{"query":"mutation { login(password: # the user's\n \"p4ssw0rdCM\") { ok } }"}`, "p4ssw0rdCM"},
		{"mutation { login(\n # note\n password: \"p4ssw0rdRAW\") { ok } }", "p4ssw0rdRAW"},
	} {
		if got := string(maskBody([]byte(c.body), "application/json", true)); strings.Contains(got, c.gone) {
			t.Errorf("%s\n -> %s", c.body, got)
		}
	}
}

// TestMaskGson: Gson (Android) writes = and & as \u003d and \u0026; a token
// parameter so written is masked too, in an array as in a string.
func TestMaskGson(t *testing.T) {
	esc := func(s string) string { return strings.NewReplacer("=", "\\"+"u003d", "&", "\\"+"u0026").Replace(s) }
	for _, body := range []string{
		`{"urls":["` + esc("https://x.example/cb?a=1&access_token=S3CRETGSON") + `"]}`,
		`{"m":"see ` + "\\" + `"here` + "\\" + `": ` + esc("https://x.example/cb?access_token=S3CRETGSON") + `"}`,
	} {
		if got := string(maskBody([]byte(body), "application/json", false)); strings.Contains(got, "S3CRETGSON") {
			t.Errorf("%s\n -> %s", body, got)
		}
	}
}

// TestGraphQLCommentsLinear: a long body of comments with no line break
// (or a quote) does not make each match rescan it.
func TestGraphQLCommentsLinear(t *testing.T) {
	head := []byte(strings.Repeat(`(#,a:"v"`, 8200))[:64<<10]
	start := time.Now()
	maskBody(head, "application/json", true)
	if d := time.Since(start); d > slow*2*time.Second {
		t.Errorf("64 KiB took %v", d)
	}
}

// TestMaskSecondReview: what the second review found still leaking.
func TestMaskSecondReview(t *testing.T) {
	for _, c := range []struct {
		body, gone string
		request    bool
	}{
		{"{\"data\":\"say \\\"hello\\\" \\u0073k-abcdefghijklmnopqrstuvwxyz0123\"}", "abcdefghijklmnopqrstuvwxyz0123", true},
		{"{\"d\":\"{\\\"x\\\":\\\"\\\\u0073k-abcdefghijklmnopqrstuvwxyz0456\\\"}\"}", "abcdefghijklmnopqrstuvwxyz0456", true},
		{"{\"query\":\"mutation{login(username:\\\"a\\\"\\npassword:\\\"newlineSECRET\\\")}\"}", "newlineSECRET", true},
		{"mutation{login(password # note\n: \"commentSECRET\")}", "commentSECRET", true},
		{"mutation{login(password: \"\"\"ab\\\"\"\"blockSECRET\"\"\")}", "blockSECRET", true},
		{"{\"query\":\"mutation{login(password: \\\"echoSECRET\\\")}\"}", "echoSECRET", false}, // a response echoing the query
	} {
		if got := string(maskBody([]byte(c.body), "application/json", c.request)); strings.Contains(got, c.gone) {
			t.Errorf("%s\n -> %s", c.body, got)
		}
	}
	s := NewStore(10, 1<<20)
	if u := s.mask("https://a.example/graphql?variables=+%7B%22password%22%3A%22getSECRET%22%7D&op=x"); strings.Contains(u, "getSECRET") {
		t.Errorf("GET variables after a space: %s", u)
	}
}

// TestMaskNestingBounded: JSON in a URL parameter in JSON, level after
// level, with = hidden as an escape, costs linear time, not a rescan a level.
func TestMaskNestingBounded(t *testing.T) {
	bs := "\\"
	level := `"x"`
	for len(level) < 240<<10 {
		level = `{"k":"` + bs + "u0026q" + bs + "u003d" + url.QueryEscape(level) + `"}`
	}
	start := time.Now()
	maskBody([]byte(level), "application/json", false)
	if d := time.Since(start); d > slow*time.Second {
		t.Errorf("%d KiB of nesting took %v", len(level)>>10, d)
	}
}

// TestMaskEscapedArrays: escaped strings that are no field's value (array
// elements, a body that is one string) are looked at decoded too.
func TestMaskEscapedArrays(t *testing.T) {
	bs := "\\"
	for _, c := range []struct{ body, gone string }{
		{`{"a":["` + bs + `u0073k-abcdefghijklmnopqrstuvwxyz0789"]}`, "abcdefghijklmnopqrstuvwxyz0789"},
		{`{"a":["{` + bs + `"password` + bs + `":` + bs + `"arrSECRET` + bs + `"}"]}`, "arrSECRET"},
		{`"` + bs + `u0073k-abcdefghijklmnopqrstuvwxyz0790"`, "abcdefghijklmnopqrstuvwxyz0790"},
	} {
		if got := string(maskBody([]byte(c.body), "application/json", true)); strings.Contains(got, c.gone) {
			t.Errorf("%s\n -> %s", c.body, got)
		}
	}
}
