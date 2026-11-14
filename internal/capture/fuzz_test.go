package capture

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// fuzzSecret: every 5 characters of it hold a capital, and fillers have none,
// so any 5 of them in the output came from the secret.
const fuzzSecret = "S3crQt7VxLu9Kz"

const fuzzShapes = 36 // a shape with no case of its own is the default one

// fuzzMarkup is the shape whose body is the fuzzer's own text, # standing for
// the secret: XML masking never panics on it, and a secret element and
// attribute before it are masked whatever follows, wherever the head is cut.
const fuzzMarkup = 25

// secretIn puts a secret under a secret name in one of the shapes masking
// knows, with filler (letters, digits, spaces, commas only: other text can
// change what the shape is) around it. at is where the part holding the
// secret starts: every cut from there on is tried.
func secretIn(shape uint8, filler, secret string) (body, contentType string, at int) {
	filler = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == ' ' || r == ',' {
			return r
		}
		return -1
	}, filler)
	pre := func(head, tail, ct string) (string, string, int) { return head + tail, ct, len(head) }
	switch shape % fuzzShapes {
	case 0:
		return pre(`{"note":"`+filler, `","password":"`+secret+`"}`, "application/json")
	case 1:
		return pre(`{"data":"{\"a\":\"`+filler, `\",\"access_token\":\"`+secret+`\"}"}`, "application/json")
	case 2:
		return pre("a="+url.QueryEscape(filler), "&client_secret="+secret, "application/x-www-form-urlencoded")
	case 3:
		return pre(`{"url":"https://x.example/cb?`+"q="+url.QueryEscape(filler), `&token=`+secret+`"}`, "application/json")
	case 4:
		inner := "https://x.example/cb?code=" + secret
		return pre(`{"note":"`+filler+`",`, `"next":"https://y.example/?r=`+url.QueryEscape(url.QueryEscape(inner))+`"}`, "application/json")
	case 5:
		return pre(`{"query":"mutation { `+filler, ` login(password: \"`+secret+`\") { ok } }"}`, "application/json")
	case 6:
		return pre("mutation { login("+filler, " secret: \""+secret+"\") { ok } }", "application/graphql")
	case 7:
		return pre(`{"items":[1,2],"note":"`+filler+`",`, `"session":"`+secret+`"}`, "application/json")
	case 8: // a list under a secret name
		return pre(`{"note":"`+filler+`",`, `"password":["x","`+secret+`"]}`, "application/json")
	case 9: // an object under one
		return pre(`{"note":"`+filler+`",`, `"credentials":{"user":"a","value":"`+secret+`"}}`, "application/json")
	case 10: // a URL in a form's first field
		return "next=" + url.QueryEscape("https://x.example/cb?token="+secret) + "&a=" + url.QueryEscape(filler), "application/x-www-form-urlencoded", 0
	case 11: // JSON in a form's first field
		return "data=" + url.QueryEscape(`{"password":"`+secret+`"}`) + "&a=" + url.QueryEscape(filler), "application/x-www-form-urlencoded", 0
	case 12: // a URL's value going on after an escaped slash
		return pre(`{"note":"`+filler+`",`, `"url":"https:\/\/x.example\/cb?token=Kx\/`+secret+`"}`, "application/json")
	case 13: // after a quote as Gson writes it
		return pre(`{"note":"`+filler+`",`, `"url":"https://x.example/cb?token=Kx\u0027`+secret+`"}`, "application/json")
	case 15: // GraphQL: a variable's default
		return pre(`{"query":"query Q(`+filler, `$password: String = \"`+secret+`\") { a }"}`, "application/json")
	case 16: // a list as an argument
		return pre(`{"query":"mutation { `+filler, ` set(tokens: [\"x\", \"`+secret+`\"]) { ok } }"}`, "application/json")
	case 17: // an input object's field
		return pre("mutation { login(input: {user: \""+filler, "\", password: \""+secret+"\"}) { ok } }", "application/graphql")
	case 18: // a comment holding a quote
		return pre("mutation { login(# it's \"x "+filler, "\n password: \""+secret+"\") { ok } }", "application/graphql")
	case 19: // quotes written as an escape
		q := "\\" + "u0022"
		return pre(`{"query":"mutation { `+filler, ` login(password: `+q+secret+q+`) { ok } }"}`, "application/json")
	case 20: // a response echoing a query under any key, with no trigger word
		return pre(`{"errors":[{"message":"`+filler+`",`, `"doc":"{ login(password: \"`+secret+`\") { ok } }"}]}`, "application/json")
	case 21: // a STOMP frame's header line
		return pre("CONNECT\naccept-version:1.2\nlogin:"+filler, "\npasscode:"+secret+"\n\n\x00", "text/plain")
	case 30: // a secret-named line whose value also holds a token's shape
		return pre("note: "+filler+"\n", "password: "+secret+" Bearer OtherToken456\n", "text/plain")
	case 31: // a .env file's line
		return pre("NAME="+filler+"\n", "export API_KEY="+secret+"\n", "text/plain")
	case 22: // SOAP: a namespaced element
		return pre(`<s:Envelope xmlns:s="urn:s"><s:Body><m:Note>`+filler+`</m:Note>`, `<wsse:Password>`+secret+`</wsse:Password></s:Body></s:Envelope>`, "application/soap+xml")
	case 23: // an XML attribute
		return pre(`<Login note="`+filler+`" `, `api_key="`+secret+`"/>`, "text/xml")
	case 24: // a plist: the value after a secret key
		return pre(`<plist><dict><key>note</key><string>`+filler+`</string>`, `<key>sessionToken</key><string>`+secret+`</string></dict></plist>`, "application/xml")
	case 26: // an OAuth form_post: a response's hidden field
		return pre(`<form method="post"><input type="hidden" name="state" value="`+filler+`">`, `<input type="hidden" name="code" value="`+secret+`"></form>`, "text/html")
	case 27: // a CSRF token in a meta tag
		return pre(`<head><meta name="description" content="`+filler+`">`, `<meta name="csrf-token" content="`+secret+`"></head>`, "text/html")
	case 28: // the value before the name that says it is secret
		return pre(`<p>`+filler+`</p>`, `<input value="`+secret+`" type="hidden" name="authenticity_token">`, "text/html")
	case 29: // a script's object, its key unquoted
		return pre(`<script>var s = {note: "`+filler+`", `, `accessToken: "`+secret+`"};</script>`, "text/html")
	case 32: // a script's string that would open an attribute, then a field
		return pre(`<script>var s="<a x='";</script><p>`+filler+`</p>`, `<input type="hidden" name="csrf" value="`+secret+`">`, "text/html")
	case 33: // a comment's quote, then a field
		return pre(`<!-- it's <a x=' `+filler+` -->`, `<input name="authenticity_token" value="`+secret+`">`, "text/html")
	case 34: // a comment between a script's key and its value
		return pre(`<script>var s = {note: "`+filler+`", `, `accessToken: /* c */ '`+secret+`'};</script>`, "text/html")
	case 35: // a script's string continued on the next line
		return pre(`var c = {note: "`+filler+`", `, "idToken: \"x\\\n"+secret+"\"};", "application/javascript")
	default: // a secret name hidden by an escape, in a URL in a string
		return pre(`{"msg":"`+filler, ` https://x.example/cb?\u0074oken=`+secret+`"}`, "application/json")
	}
}

// leak returns 5 characters of secret found in got, read as written and
// decoded (JSON's escapes, then percent-escapes, twice), or "".
func leak(got, secret string) string {
	forms := []string{got}
	d := jsonUnescapeAll(got)
	forms = append(forms, d)
	for range 2 {
		d = percentUnescapeAll(d)
		forms = append(forms, d)
	}
	for _, f := range forms {
		for i := 0; i+5 <= len(secret); i++ {
			if strings.Contains(f, secret[i:i+5]) {
				return secret[i : i+5]
			}
		}
	}
	return ""
}

func trimCutRunes(s string) string { return string(trimCutRune([]byte(s))) }

var jsonEscapeRE = regexp.MustCompile(`\\(u[0-9a-fA-F]{4}|.)`)

func jsonUnescapeAll(s string) string {
	return jsonEscapeRE.ReplaceAllStringFunc(s, func(m string) string {
		if m[1] == 'u' {
			n, _ := strconv.ParseUint(m[2:], 16, 32)
			return string(rune(n))
		}
		return m[1:]
	})
}

var percentRE = regexp.MustCompile(`%[0-9a-fA-F]{2}`)

func percentUnescapeAll(s string) string {
	return percentRE.ReplaceAllStringFunc(strings.ReplaceAll(s, "+", " "), func(m string) string {
		n, _ := strconv.ParseUint(m[1:], 16, 8)
		return string(rune(n))
	})
}

// fuzzSlow, deferred around masking, fails an input whose masking takes
// seconds (a 64 KiB head takes milliseconds): go test -fuzz then hunts inputs
// that grow faster than their size too, as TestMaskingLinear's units do.
func fuzzSlow(t *testing.T, n int) func() {
	start := time.Now()
	return func() {
		if d := time.Since(start); d > 2*slow*time.Second {
			t.Errorf("masking %d bytes took %v", n, d)
		}
	}
}

// FuzzMaskBody: no 5 characters of a secret in a known shape survive masking,
// read as written or decoded, whatever comes around it and wherever the head
// is cut (a cut inside the value masks to the end): every cut over the part
// holding it, and the fuzzed one. Seeds run with go test; go test
// -fuzz=FuzzMaskBody explores.
func FuzzMaskBody(f *testing.F) {
	for shape := range uint8(fuzzShapes) {
		f.Add(shape, "", 0)
		f.Add(shape, "some words, 42", 7)
		f.Add(shape, strings.Repeat("x", 65530), 65536) // the 64 KiB boundary
	}
	for _, m := range []string{
		`<a><Password>#</Password></a></b>`, `password=#</dict>>password=#`, `<Password>abc</i>#</Password>`,
		`<?xml version="1.1"?><a token='#'/>`, `<a x="1"password="#"/>`, `<plist><dict><key>pin</key><string>#</string>`,
		`<a>{"secret":"#"}</a>`, `<b>"</b>{"token":"#"}`, `<a>Bearer #</a><!-- -- --><Key>#`,
		`<Password>"password":"</Password>password=#`, `<Password a=b!c>#</Password>`, `<a password="#<VxLu9Kz`,
		`<plist><dict><!-- -- </dict> --><key>pin</key><string>#</string>`,
	} {
		f.Add(uint8(fuzzMarkup), m, 0)
		f.Add(uint8(fuzzMarkup), m, len(m)-3)
	}
	f.Fuzz(func(t *testing.T, shape uint8, filler string, cut int) {
		if shape%fuzzShapes == fuzzMarkup {
			defer fuzzSlow(t, 2*len(filler))()
			maskBody([]byte(strings.ReplaceAll(filler, "#", fuzzSecret)), "text/xml", true)
			// The filler may hold pieces of the secret itself: past the
			// prefix, the output must start with it masked.
			prefix := `<r><Password>` + fuzzSecret + `</Password><a token="` + fuzzSecret + `"/>`
			const masked = `<r><Password>[redacted]</Password><a token="[redacted]"/>`
			in := prefix + filler
			if cut > 0 && cut < len(in) {
				in = in[:cut]
			}
			if !utf8.ValidString(trimCutRunes(in)) {
				return
			}
			got := string(maskBody([]byte(in), "text/xml", true))
			if len(in) < len(prefix) && leak(got, fuzzSecret) != "" || len(in) >= len(prefix) && !strings.HasPrefix(got, masked) {
				t.Errorf("a secret element or attribute left:\n%q\n%q", in, got)
			}
			return
		}
		body, ct, at := secretIn(shape, filler, fuzzSecret)
		check := func(cut int) {
			head := []byte(body)
			if cut > 0 && cut < len(head) {
				head = head[:cut]
			}
			defer fuzzSlow(t, len(head))()
			got := string(maskBody(head, ct, shape%fuzzShapes != 20 && shape%fuzzShapes != 26)) // 20, 26: responses
			if l := leak(got, fuzzSecret); l != "" {
				t.Errorf("shape %d, cut %d: %q survived:\n%s", shape%fuzzShapes, cut, l, got[max(0, len(got)-200):])
			}
		}
		check(cut)
		for c := at; c <= min(len(body), at+300); c++ {
			check(c)
		}
	})
}
