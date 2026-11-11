package capture

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestGraphQLByName: what a secret name holds goes whole (strings, numbers,
// lists, objects, a variable's default); enums, booleans, variables, aliases,
// types and other names' values stay.
func TestGraphQLByName(t *testing.T) {
	for _, c := range []struct{ doc, want string }{
		{`mutation { login(user: "a", pin: 1234, password: "x") { ok } }`, `mutation { login(user: "a", pin: "[redacted]", password: "[redacted]") { ok } }`},
		{`mutation { set(tokens: ["a", "b"], n: 2) { ok } }`, `mutation { set(tokens: "[redacted]", n: 2) { ok } }`},
		{`mutation { login(input: {user: "a", credentials: {k: "v"}}) { ok } }`, `mutation { login(input: {user: "a", credentials: "[redacted]"}) { ok } }`},
		{`query Q($password: String = "x", $id: ID = 7, $tokens: [String!] = ["t"]) { a }`, `query Q($password: String = "[redacted]", $id: ID = 7, $tokens: [String!] = "[redacted]") { a }`},
		{`mutation { login(password: $pw, auth: BEARER, token: true) { token: accessToken } }`, ``},
		{`mutation { setKey(apiKey: """a\"""b""") { ok } }`, `mutation { setKey(apiKey: "[redacted]") { ok } }`},
		{"mutation { login(\n# a \"quote\n password: \"x\") { ok } }", "mutation { login(\n# a \"quote\n password: \"[redacted]\") { ok } }"},
		{`{ viewer { login(secret: "x") } }`, `{ viewer { login(secret: "[redacted]") } }`},
		{`mutation { login(password: "cut`, `mutation { login(password: "[redacted]"`},
		{`mutation { login(tokens: ["a", "cu`, `mutation { login(tokens: "[redacted]"`},
		{`mutation { login(password: "x") ~ }`, `[redacted]`}, // not GraphQL past the start: all of it
	} {
		want := c.want
		if want == "" {
			want = c.doc
		}
		got, isDoc := maskGraphQLDoc(c.doc, true)
		if !isDoc || got != want {
			t.Errorf("%s\n -> %s (document %v)", c.doc, got, isDoc)
		}
	}
	// Text that only starts with a brace or a keyword is not a document.
	for _, s := range []string{"{count} items", "{name}'s photos: 3", "{name}'s", "{count} files: 3", "query", "mutations are slow", `{"a":1}`} {
		if got, isDoc := maskGraphQLDoc(s, true); isDoc || got != s {
			t.Errorf("%q -> %q (document %v)", s, got, isDoc)
		}
	}
}

// TestGraphQLWhereFound: documents in JSON strings at any key (batched,
// echoed in a response, inside JSON in a string), as the body, and in a GET
// parameter, escaped again rather than replaced.
func TestGraphQLWhereFound(t *testing.T) {
	for _, c := range []struct {
		body, gone, kept string
		request          bool
	}{
		{`[{"query":"mutation{a(password:\"S1\")}"},{"query":"mutation{b(pin:42424242)}"}]`, "S1", `mutation{b(pin:\"[redacted]\")}`, true},
		{`{"errors":[{"locations":[1],"source":"{ login(password: \"S2\") { ok } }"}]}`, "S2", "login(password:", false},
		{`{"payload":"{\"query\":\"mutation{login(password:\\\"S3\\\")}\"}"}`, "S3", "login(password:", true},
		{"query Q($password: String = \"S4\") { a }", "S4", "query Q(", true},
		{`{"msg":"see { login(password: \"S5\") }"}`, "", "S5", true}, // prose before it: not found
		// The second review: a spread after a field, an escaped first letter, a byte order mark.
		{"{__typename ...F} fragment F on Query {login(password:\"S8\"){ok}}", "S8", "fragment F", true},
		{"{ a } fragment F on Query {login(password:\"S9\"){ok}}", "S9", "fragment F", true},
		{`{"query":"\u006dutation{login(password:\"S10\"){ok}}"}`, "S10", "login(password:", true},
		{`{"query":"\ufeffmutation{login(password:\"S11\"){ok}}"}`, "S11", "login(password:", true},
		{"{\"query\":\"\xef\xbb\xbfmutation{login(password:\\\"S12\\\"){ok}}\"}", "S12", "login(password:", true},
	} {
		got := string(maskBody([]byte(c.body), "application/json", c.request))
		if c.gone != "" && strings.Contains(got, c.gone) || !strings.Contains(got, c.kept) {
			t.Errorf("%s\n -> %s", c.body, got)
		}
	}
	s := NewStore(10, 1<<20)
	u := s.mask("https://a.example/graphql?query=mutation+%7Blogin%28password%3A%22S6%22%29%7D&op=Login")
	if strings.Contains(u, "S6") || !strings.Contains(u, "query=mutation+%7Blogin%28password%3A%22%5Bredacted%5D%22%29%7D") || !strings.Contains(u, "op=Login") {
		t.Errorf("GET: %s", u)
	}
	if got := string(maskBody([]byte("query=mutation+%7Blogin%28password%3A%22S7%22%29%7D&a=1"), "application/x-www-form-urlencoded", true)); strings.Contains(got, "S7") || !strings.Contains(got, "login") {
		t.Errorf("a form's first field: %s", got)
	}
	if got := string(maskBody([]byte("query=%7Blogin%28password%3A%22S13%22%29%7Bok%7D%7D"), "application/x-www-form-urlencoded", true)); strings.Contains(got, "S13") || !strings.Contains(got, "login") {
		t.Errorf("a shorthand document in a form's first field: %s", got)
	}
	// The second review (Opus): a description first, raw line breaks in a JSON
	// string, a form field not percent-encoded.
	for _, c := range []struct{ body, ct, gone string }{
		{`"""Login""" mutation Login { login(password: "S14") { ok } }`, "application/graphql", "S14"},
		{`{"query":"\"\"\"Login\"\"\" mutation Login { login(password: \"S17\") { ok } }"}`, "application/json", "S17"},
		{"{\"query\":\"mutation {\n login(password: \\\"S15\\\") { ok } }\"}", "application/json", "S15"},
		{`a=1&query=mutation { login(password: "S16") { ok } }`, "application/x-www-form-urlencoded", "S16"},
	} {
		if got := string(maskBody([]byte(c.body), c.ct, true)); strings.Contains(got, c.gone) {
			t.Errorf("%s\n -> %s", c.body, got)
		}
	}
}

// TestGraphQLCost: a 64 KiB document of arguments, and one of nested lists,
// cost linear time.
func TestGraphQLCost(t *testing.T) {
	for _, doc := range []string{
		"mutation {" + strings.Repeat(`a(password: "x", b: [1, {c: "d"}]) `, 2000),
		`{"query":"mutation { a(tokens: ` + strings.Repeat("[", 30000) + `"}`,
		`{"q":[` + strings.Repeat(`"{ a(b: 1) }",`, 4000) + `0]}`,
	} {
		head := []byte(doc)[:min(len(doc), 64<<10)]
		start := time.Now()
		maskBody(head, "application/json", true)
		if d := time.Since(start); d > slow*time.Second/2 {
			t.Errorf("%.40s…: %v", doc, d)
		}
	}
}

// gqlGen writes a GraphQL document from fuzz bytes, from a small grammar:
// operations, variables with defaults, fields with aliases and arguments,
// every kind of value, comments (with quotes) and commas between tokens.
// Every value a secret name holds carries fuzzSecret or gqlSecretNumber.
type gqlGen struct {
	b     []byte
	i     int
	out   strings.Builder
	depth int
}

const gqlSecretNumber = "987654321"

func (g *gqlGen) pick(n int) int {
	if g.i >= len(g.b) {
		return 0
	}
	g.i++
	return int(g.b[g.i-1]) % n
}

func (g *gqlGen) w(s ...string) {
	for _, p := range s {
		g.out.WriteString(p)
	}
}

func (g *gqlGen) sp() { g.w([]string{" ", "", "\n", " # it's \"a\n", ",", "\t"}[g.pick(6)]) }

func (g *gqlGen) name(secretOK bool) (string, bool) {
	if secretOK && g.pick(2) == 0 {
		return []string{"password", "token", "pin", "apiKey", "client_secret"}[g.pick(5)], true
	}
	return []string{"id", "name", "first", "after", "kind"}[g.pick(5)], false
}

func (g *gqlGen) value(secret bool) {
	g.depth++
	defer func() { g.depth-- }()
	k := g.pick(7)
	if g.depth > 4 {
		k = 0
	}
	switch {
	case k == 0 && secret:
		g.w(`"a\"`, fuzzSecret, `"`)
	case k == 0:
		g.w(`"v\\"`)
	case k == 1 && secret:
		g.w(`"""a\"""`, fuzzSecret, `"""`)
	case k == 1:
		g.w(`"""b"""`)
	case k == 2 && secret:
		g.w("-", gqlSecretNumber)
	case k == 2:
		g.w("3.5e2")
	case k == 3:
		g.w("[")
		for range g.pick(3) + 1 {
			g.w(" ")
			g.sp()
			g.value(secret)
		}
		g.w("]")
	case k == 4:
		g.w("{")
		for range g.pick(3) + 1 {
			n, s := g.name(true)
			g.w(" ")
			g.sp()
			g.w(n, ":")
			g.sp()
			g.value(secret || s)
		}
		g.w("}")
	case secret: // enums and variables are not secret: a string instead
		g.w(`"`, fuzzSecret, `"`)
	case k == 5:
		g.w("ENUMV")
	default:
		g.w("$v")
	}
}

func (g *gqlGen) args() {
	g.w("(")
	for range g.pick(3) + 1 {
		n, s := g.name(true)
		g.w(" ")
		g.sp()
		g.w(n)
		g.sp()
		g.w(":")
		g.sp()
		g.value(s)
	}
	g.w(")")
}

func (g *gqlGen) selections() {
	g.depth++
	defer func() { g.depth-- }()
	g.w("{")
	for range g.pick(3) + 1 {
		g.sp()
		if g.pick(3) == 0 {
			n, _ := g.name(true) // an alias, secret-named or not
			g.w(n, ":")
			g.sp()
		}
		g.w([]string{"login", "user", "set"}[g.pick(3)])
		if g.pick(2) == 0 {
			g.args()
		}
		if g.depth < 3 && g.pick(2) == 0 {
			g.sp()
			g.selections()
		}
	}
	g.sp()
	g.w("}")
}

func (g *gqlGen) document() string {
	if op := g.pick(4); op > 0 {
		g.w([]string{"", "query", "mutation", "subscription"}[op], " ")
		if g.pick(2) == 0 {
			g.w("Op")
		}
		if g.pick(2) == 0 {
			g.w("(")
			for range g.pick(2) + 1 {
				n, s := g.name(true)
				g.w("$", n, ":")
				g.sp()
				g.w([]string{"String", "[String!]", "Int!"}[g.pick(3)])
				g.sp()
				g.w("=")
				g.sp()
				g.value(s)
				g.sp()
			}
			g.w(")")
		}
		g.sp()
	}
	g.selections()
	return g.out.String()
}

// FuzzGraphQLGrammar: in a document from the grammar, no value a secret name
// holds survives, as the body, in a JSON string (a request's, a response's),
// or a GET parameter, wherever the head is cut.
func FuzzGraphQLGrammar(f *testing.F) {
	f.Add([]byte{}, 0)
	f.Add([]byte{2, 0, 0, 1, 0, 0, 3, 0, 4, 1, 0, 2, 0, 0, 1}, 40)
	f.Add([]byte("mutation fuzz seed with many bytes 0123456789"), 1000)
	s := NewStore(10, 1<<20)
	f.Fuzz(func(t *testing.T, b []byte, cut int) {
		doc := (&gqlGen{b: b}).document()
		for _, c := range []struct {
			body    string
			request bool
		}{
			{doc, true},
			{`{"query":` + jsonString(doc) + `}`, true},
			{`{"errors":[{"source":` + jsonString(doc) + `}]}`, false},
		} {
			head := c.body
			if cut > 0 && cut < len(head) {
				head = head[:cut]
			}
			got := string(maskBody([]byte(head), "application/json", c.request))
			if l := leak(got, fuzzSecret) + leak(got, gqlSecretNumber); l != "" {
				t.Fatalf("%q survived in\n%s\n -> %s", l, head, got)
			}
		}
		if got := s.mask("https://a.example/g?query=" + url.QueryEscape(doc) + "&op=x"); leak(got, fuzzSecret)+leak(got, gqlSecretNumber) != "" {
			t.Fatalf("GET: %s\n -> %s", doc, got)
		}
	})
}
