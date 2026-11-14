package capture

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maskBody masks the secrets it can recognise in a kept body head, as it
// arrives: the string values of JSON fields whose names are secret (any
// content type: a JSON body may come labelled as a form), the values of such
// form fields (when the body is, or looks like, a form), and anywhere,
// values whose shape gives them away (maskTokens) and secret parameters of
// URLs in it (maskURLs). An XML body is masked by names first (maskXML).
// The head may be cut anywhere, so it is scanned as
// text, not parsed: a value cut before its closing quote is masked to the end.
// Heads that are not text are left alone here and never handed out while
// masking (Store.bodyOut). Secrets under names that do not say so are not
// found. In a request, a lone "code" is a secret (an OTP, an OAuth code); in
// a response it is usually an error code.
func maskBody(head []byte, contentType string, request bool) []byte {
	if len(head) == 0 || !utf8.Valid(trimCutRune(head)) {
		return head
	}
	s := string(head)
	if isXML(contentType, s) { // by names first; the text masking below still applies
		s = maskXML(s, request)
	}
	// A GraphQL document as the body (application/graphql, or shaped like
	// one); those in JSON strings are found by maskJSON.
	s, isDoc := maskGraphQLDoc(s, request)
	s = maskJSON(s, request, 0)
	if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") || looksLikeForm(s) {
		s = maskForm(s, request)
	}
	if !isDoc {
		s = maskLines(s, request)
	}
	return []byte(maskTokens(maskURLs(s)))
}

// trimCutRune drops a UTF-8 character cut at the end of a head, for the check.
func trimCutRune(b []byte) []byte {
	for cut := 0; cut < utf8.UTFMax && cut < len(b); cut++ {
		if utf8.Valid(b[:len(b)-cut]) {
			return b[:len(b)-cut]
		}
	}
	return b
}

// maskJSON replaces the string or number value of every "name": value pair
// whose name is secret with [redacted], in one pass over the text. A value
// that runs to the end of the head (cut, even right after a backslash) is
// masked to the end. A string that holds JSON itself ("{\"password\":…}") is
// looked into, one level deep.
func maskJSON(s string, loneCode bool, depth int) string {
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); {
		q := strings.IndexByte(s[i:], '"')
		if q < 0 {
			break
		}
		keyStart := i + q
		keyEnd, closed := jsonStringEnd(s, keyStart)
		if !closed {
			// A string cut by the head's end, not a field's value: an array
			// element, or a key.
			if depth <= 2 {
				if m, ok := gqlString(s[keyStart:], false, loneCode, depth <= 1); ok {
					b.WriteString(s[last:keyStart])
					b.WriteString(m)
					last = len(s)
					break
				}
			}
			if cutSecret(s[keyStart:], loneCode, depth) {
				b.WriteString(s[last : keyStart+1])
				b.WriteString("[redacted]")
				last = len(s)
			}
			break
		}
		j := skipSpace(s, keyEnd+1)
		if j >= len(s) || s[j] != ':' {
			// A value that is no field's: an array element, or the whole body.
			// Escaped, it is looked at decoded too, as a field's value is.
			lit := s[keyStart : keyEnd+1]
			if m, ok := gqlString(lit, true, loneCode, depth <= 1); depth <= 2 && ok {
				b.WriteString(s[last:keyStart])
				b.WriteString(m)
				last = keyEnd + 1
			} else if escaped(lit, depth) {
				if m, ok := maskDecodedString(lit, loneCode, depth); ok {
					b.WriteString(s[last:keyStart])
					b.WriteString(m)
					last = keyEnd + 1
				}
			}
			i = keyEnd + 1
			continue
		}
		j = skipSpace(s, j+1)
		if j < len(s) && (s[j] == '{' || s[j] == '[') && secretKind(jsonKey(s[keyStart+1:keyEnd]), loneCode) {
			// {"password": ["…"]}, {"credentials": {"value": "…"}}: the whole
			// value, to the end of the head if it is cut.
			end, closed := containerEnd(s, j)
			b.WriteString(s[last:j])
			if closed {
				b.WriteString(`"[redacted]"`)
			} else {
				b.WriteString(`"[redacted]`)
			}
			last, i = end+1, end+1
			continue
		}
		if j >= len(s) || (s[j] != '"' && s[j] != '-' && (s[j] < '0' || s[j] > '9')) {
			i = j // an object, array, true, false or null: its own keys come next
			continue
		}
		secret := secretKind(jsonKey(s[keyStart+1:keyEnd]), loneCode)
		if secret && s[j] != '"' { // {"otp": 123456}
			k := j
			for k < len(s) && strings.IndexByte("-+.eE0123456789", s[k]) >= 0 {
				k++
			}
			b.WriteString(s[last:j])
			b.WriteString(`"[redacted]"`)
			last, i = k, k
			continue
		}
		if s[j] != '"' {
			i = j
			continue
		}
		valEnd, valClosed := jsonStringEnd(s, j)
		if secret && valClosed && attributeName(jsonKey(s[keyStart+1:keyEnd]), s[j+1:valEnd], s[valEnd+1:]) && !hasUserName(jsonKey(s[keyStart+1:keyEnd])) {
			secret = false
		}
		if !secret && depth <= 2 { // depth 2: JSON in a URL parameter (?operations={"query":…})
			if m, ok := gqlString(s[j:valEnd+1], valClosed, loneCode, depth <= 1); ok {
				b.WriteString(s[last:j])
				b.WriteString(m)
				last = valEnd + 1
				if !valClosed {
					break
				}
				i = valEnd + 1
				continue
			}
		}
		switch {
		case secret:
			b.WriteString(s[last : j+1])
			b.WriteString("[redacted]")
			if valClosed {
				b.WriteByte('"')
			}
			last = valEnd + 1
		case valClosed && escaped(s[j:valEnd], depth):
			// A string with escapes is looked at decoded, as diff_flows and the
			// agent read it: JSON inside it (one level), and shapes and URLs that
			// escapes can hide (\u0073k-… is sk-…, Basic\t… is Basic and a tab).
			if m, ok := maskDecodedString(s[j:valEnd+1], loneCode, depth); ok {
				b.WriteString(s[last:j])
				b.WriteString(m)
				last = valEnd + 1
			}
		case !valClosed && cutSecret(s[j:], loneCode, depth):
			b.WriteString(s[last : j+1])
			b.WriteString("[redacted]")
			last = len(s)
		}
		if !valClosed {
			break
		}
		i = valEnd + 1
	}
	if last == 0 {
		return s
	}
	if last < len(s) {
		b.WriteString(s[last:])
	}
	return b.String()
}

// dottedName is an attribute's name as OpenTelemetry and the like write them:
// lowercase words with dots (service.name, http.request.method).
var dottedName = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)

// attributeName says a "key" field holds an attribute's name, not a key:
// {"key": "service.name", "value": …} in an OTLP body. A key is mixed case, or
// has no dots; and the shapes maskTokens knows (JWTs and others) are masked
// after this, whatever the field.
func attributeName(name, value, after string) bool {
	return strings.EqualFold(name, "key") && len(value) <= 64 && dottedName.MatchString(value) && valueNext.MatchString(after)
}

// valueNext: a "value" field comes right after, as in OpenTelemetry's
// {"key": "http.method", "value": {...}}. A lone {"key": "live.a8f3…"} is a key.
var valueNext = regexp.MustCompile(`^\s*,\s*"value"\s*:`)

// maskDecodedString masks a JSON string literal read decoded: the JSON in it
// (at depth 0, one level down), then the shapes and URLs in it; written again
// only if anything was masked.
func maskDecodedString(lit string, loneCode bool, depth int) (string, bool) {
	var v string
	if json.Unmarshal([]byte(lit), &v) != nil {
		return "", false
	}
	m := v
	if t := strings.TrimLeft(m, " \t\r\n"); depth == 0 && t != "" && strings.ContainsAny(t[:1], "{[") {
		m = maskJSON(m, loneCode, 1)
	}
	if _, isDoc := maskGraphQLDoc(m, loneCode); !isDoc {
		m = maskLines(m, loneCode)
	}
	m = maskTokens(maskURLs(m))
	if m == v {
		return "", false
	}
	return jsonString(m), true
}

// jsonString writes v as a JSON string literal.
func jsonString(v string) string {
	var out strings.Builder
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false) // keep < > & as the site wrote them
	enc.Encode(v)
	return strings.TrimSuffix(out.String(), "\n")
}

// jsonStringEnd returns the index of the quote closing the string that opens
// at s[open], or len(s)-1 and false if the string runs to the end.
func jsonStringEnd(s string, open int) (int, bool) {
	for k := open + 1; k < len(s); k++ {
		switch s[k] {
		case '\\':
			k++
		case '"':
			return k, true
		}
	}
	return len(s) - 1, false
}

// containerEnd returns the index of the bracket closing the object or array
// that opens at s[open], skipping strings, or len(s)-1 and false if it runs
// to the end.
func containerEnd(s string, open int) (int, bool) {
	depth := 0
	for k := open; k < len(s); k++ {
		switch s[k] {
		case '"':
			end, closed := jsonStringEnd(s, k)
			if !closed {
				return len(s) - 1, false
			}
			k = end
		case '{', '[':
			depth++
		case '}', ']':
			if depth--; depth == 0 {
				return k, true
			}
		}
	}
	return len(s) - 1, false
}

// cutSecret: a string literal cut by the head's end (lit runs from its
// opening quote to the end) holds a secret once its escapes are undone, as a
// closed one is read decoded: JSON in it (at depth 0), and shapes and URLs
// escapes can hide. Only escaped ones are looked at, as closed ones.
func cutSecret(lit string, loneCode bool, depth int) bool {
	if !escaped(lit, depth) {
		return false
	}
	var v string
	if json.Unmarshal([]byte(trimCutEscape(lit)+`"`), &v) != nil {
		// Not JSON (a page's script, raw newlines): undo the common escapes.
		v = cutEscapes.Replace(uEscapeRE.ReplaceAllStringFunc(lit[1:], undoUEscape))
	}
	m := v
	if depth == 0 {
		m = maskJSON(m, loneCode, 1)
	}
	if _, isDoc := maskGraphQLDoc(m, loneCode); !isDoc {
		m = maskLines(m, loneCode)
	}
	return maskTokens(maskURLs(m)) != v
}

// escaped: a string literal at this depth is read decoded too (every escape
// can hide a shape: \t, \/, \u…), at the top level and in JSON in a string.
func escaped(lit string, depth int) bool { return depth <= 1 && strings.Contains(lit, `\`) }

// uEscapeRE: a \u escape, a surrogate pair as one.
var uEscapeRE = regexp.MustCompile(`\\u[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}`)

func undoUEscape(e string) string {
	var r string
	if json.Unmarshal([]byte(`"`+e+`"`), &r) != nil {
		return e
	}
	return r
}

var cutEscapes = strings.NewReplacer(`\\`, `\`, `\"`, `"`, `\/`, `/`, `\t`, "\t", `\r`, "\r", `\n`, "\n", `\b`, "\b", `\f`, "\f")

// trimCutEscape drops an escape the head's end cut (a lone \, or \u with
// fewer than four digits) from a cut string literal.
func trimCutEscape(lit string) string {
	k := strings.LastIndexByte(lit, '\\')
	if k < 0 {
		return lit
	}
	n := 0 // the backslashes in the run ending at k: \\ is a whole escape
	for k-n >= 0 && lit[k-n] == '\\' {
		n++
	}
	if rest := lit[k+1:]; n%2 == 1 && (rest == "" || rest[0] == 'u' && len(rest) < 5) {
		return lit[:k]
	}
	return lit
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

// jsonKey decodes escapes in a key ("password" is password).
func jsonKey(raw string) string {
	if !strings.Contains(raw, `\`) {
		return raw
	}
	var k string
	if json.Unmarshal([]byte(`"`+raw+`"`), &k) == nil { // JSON's escapes: \/, \uXXXX, surrogate pairs
		return k
	}
	return raw
}

// looksLikeForm: no JSON, XML or HTML, one line (a newline may end it), and
// name=value at the start.
func looksLikeForm(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" || strings.ContainsAny(t[:1], "{[<\"") {
		return false
	}
	head := t[:min(len(t), 256)]
	eq := strings.IndexByte(head, '=')
	return eq > 0 && !strings.ContainsAny(head[:eq], " \t\r\n") && !strings.Contains(head, "\n")
}

// maskForm masks the values of secret fields in a form body (a=1&password=x),
// and secret fields of JSON sent as a field's value (data={"password":…}).
// A lone code counts here: a form is how an OAuth authorization code is sent.
func maskForm(s string, request bool) string {
	parts := strings.Split(s, "&")
	for i, p := range parts {
		name, val, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		if secretName(formName(name)) || i == 0 && nestedSecret(val, 0) || b64JSONSecret(val) { // maskURLs looks into the fields after an &, not the first; before JSON and documents, which start with { too
			parts[i] = name + "=[redacted]"
		} else if m, ok := gqlParam(val, 0); ok { // before JSON: {login(…)} starts with { too; a field not encoded as it should be too
			parts[i] = name + "=" + m
		} else if v := unescapeCut(val); strings.ContainsAny(v[:min(len(v), 1)], "{[") {
			if m := maskJSON(v, request, 1); m != v {
				parts[i] = name + "=" + url.QueryEscape(m)
			}
		}
		// A token's shape hidden by percent-encoding (%22eyJ…, Bearer+…): the
		// shapes need a word boundary before it, and %22 or + gives none.
		if _, cur, _ := strings.Cut(parts[i], "="); strings.ContainsAny(cur, "%+") {
			if d := unescapeCut(cur); maskTokens(d) != d {
				parts[i] = name + "=" + url.QueryEscape(maskTokens(d))
			}
		}
	}
	return strings.Join(parts, "&")
}

// encodedToken: a URL parameter's value hides a token's shape behind
// percent-encoding (?q=%7B%22t%22%3A%22eyJ…, Bearer+…).
func encodedToken(v string) bool {
	if !strings.ContainsAny(v, "%+") {
		return false
	}
	d := unescapeCut(v)
	return maskTokens(d) != d
}

// b64JSONSecret: a value that is base64 of a JSON object with a secret in it
// (AppSync's ?header=eyJ…, AppSync's header-… protocol): no dots, so not a
// JWT's shape. Only the first run of base64 is read, once.
func b64JSONSecret(v string) bool {
	v = unescapeCut(v)
	if len(v) < 4 || v[0] != 'e' || !strings.ContainsRune("wxyz0123456789+/-_", rune(v[1])) { // base64 of {
		return false
	}
	n := 0
	for n < len(v) && (v[n] >= 'A' && v[n] <= 'Z' || v[n] >= 'a' && v[n] <= 'z' || v[n] >= '0' && v[n] <= '9' || strings.IndexByte("+/-_", v[n]) >= 0) {
		n++
	}
	raw := strings.NewReplacer("-", "+", "_", "/").Replace(v[:n-n%4]) // a cut quantum dropped
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return false
	}
	d := strings.ToValidUTF8(string(b), "")
	if d == "" || d[0] != '{' || !strings.HasPrefix(strings.TrimLeft(d[1:], " \t\r\n"), `"`) {
		return false
	}
	return maskJSON(d, true, 2) != d || maskTokens(d) != d
}

// A "name: value" or "name=value" line (STOMP's passcode:, YAML, headers
// written into a body, a .env file's lines, export too) whose name is
// secret: the rest of the line is masked.
var lineFieldRE = regexp.MustCompile(`(?m)^([ \t]*(?:export[ \t]+)?)([A-Za-z][A-Za-z0-9_.-]{0,63})([ \t]*[:=][ \t]*)([^\r\n]+)`)

// maskedValueRE: a value masking already wrote, whole (a marker, quoted or
// not, or a scheme and a marker); a value that only starts with one is masked.
var maskedValueRE = regexp.MustCompile(`^(?:"\[redacted\]"|\[redacted\]|REDACTED|[A-Za-z][A-Za-z0-9-]{0,31} \[redacted\])[ \t,;]*$`)

func maskLines(s string, loneCode bool) string {
	if !strings.ContainsAny(s, ":=") {
		return s
	}
	return lineFieldRE.ReplaceAllStringFunc(s, func(m string) string {
		sub := lineFieldRE.FindStringSubmatch(m)
		v, done := sub[4], sub[4]
		if strings.Contains(sub[3], "=") {
			done, _, _ = strings.Cut(v, "&") // a form's field (password=[redacted]&user=bob): its value ends at &
		}
		if !secretKind(sub[2], loneCode) || maskedValueRE.MatchString(done) {
			return m
		}
		// The whole value; "Bearer [redacted]" keeps the scheme when the value is that credential alone.
		if c := schemeRE.FindStringSubmatchIndex(v); c != nil && c[0] == 0 && c[1] == len(strings.TrimRight(v, " \t")) && credentialLike(v[c[6]:c[7]]) {
			return sub[1] + sub[2] + sub[3] + v[c[2]:c[5]] + "[redacted]"
		}
		return sub[1] + sub[2] + sub[3] + "[redacted]"
	})
}

// maskWSProtocols: Sec-WebSocket-Protocol lists names, but some clients carry
// a credential in it: after a name that says so (access_token, <token>), as
// base64 JSON (AppSync's header-<…>), after Kubernetes' bearer prefix, or
// as a long value shaped like one.
var wsProtoNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,40}$`) // a bare name such as access_token

func maskWSProtocols(v string) string {
	items := strings.Split(v, ",")
	out := make([]string, len(items))
	for i, it := range items {
		t := strings.TrimSpace(it)
		lead := it[:len(it)-len(strings.TrimLeft(it, " \t"))]
		const k8s = "base64url.bearer.authorization.k8s.io."
		switch {
		case i > 0 && wsProtoNameRE.MatchString(strings.TrimSpace(items[i-1])) && secretName(strings.TrimSpace(items[i-1])) && !(t == strings.ToLower(t) && secretName(t)):
			out[i] = lead + "[redacted]"
		case strings.HasPrefix(t, "header-") && b64JSONSecret(t[len("header-"):]):
			out[i] = lead + "header-[redacted]"
		case strings.HasPrefix(t, k8s):
			out[i] = lead + k8s + "[redacted]"
		case len(t) >= 32 && credentialLike(t) && !dottedName.MatchString(t):
			out[i] = lead + "[redacted]"
		default:
			out[i] = it
		}
	}
	return strings.Join(out, ",")
}

func formName(n string) string {
	if u, err := url.QueryUnescape(n); err == nil {
		return u
	}
	return n
}

// A credential recognisable by its shape, wherever it appears (headers of any
// name, URLs, bodies, error messages). Each pattern runs only if one of its
// literal prefixes is in the text, which keeps a 64 KiB head cheap.
type tokenShape struct {
	prefixes []string
	re       *regexp.Regexp
}

var tokenShapes = []tokenShape{
	{[]string{"eyJ"}, regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`)}, // JWT
	{[]string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}, regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})`)},
	{[]string{"sk-"}, regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`)}, // OpenAI, Anthropic, Stripe and others
	{[]string{"xox"}, regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{[]string{"AKIA", "ASIA"}, regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{[]string{"AIza"}, regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
}

// An HTTP credential: the scheme, then a value that looks like one (not the
// next word of a sentence: "Basic information" stays).
var schemeRE = regexp.MustCompile(`(?i)\b(bearer|basic|token)(\s+)([A-Za-z0-9._~+/=-]{8,})`)

func credentialLike(v string) bool {
	var digitOrSym, upper, lower bool
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', strings.ContainsRune("._~+/=-", r):
			digitOrSym = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		}
	}
	return digitOrSym || (upper && lower)
}

func maskTokens(s string) string {
	if containsFold(s, "bearer") || containsFold(s, "basic") || containsFold(s, "token") {
		s = schemeRE.ReplaceAllStringFunc(s, func(m string) string {
			sub := schemeRE.FindStringSubmatch(m)
			if !credentialLike(sub[3]) {
				return m
			}
			return sub[1] + sub[2] + "[redacted]"
		})
	}
	return maskShapes(s)
}

// maskShapes masks the tokenShapes, and the matches of --mask-values.
func maskShapes(s string) string {
	s = maskUserValues(s)
	for _, t := range tokenShapes {
		for _, p := range t.prefixes {
			if strings.Contains(s, p) {
				s = t.re.ReplaceAllString(s, "[redacted]")
				break
			}
		}
	}
	return s
}

// mask and the Store's other mask methods need no lock: s.redact is atomic,
// set by SetScope before events arrive.
func (s *Store) mask(v string) string {
	if !s.redact.Load() {
		return v
	}
	return maskTokens(maskURLs(v))
}

// maskError is mask for error messages, which can also quote raw bytes from
// the wire (mitmproxy: "Invalid header line: b'Set-Cookie sid=…'").
func (s *Store) maskError(v string) string {
	if !s.redact.Load() {
		return v
	}
	return quotedBytesRE.ReplaceAllString(maskTokens(maskURLs(v)), "${1}b'[redacted]'")
}

// Python's repr of bytes, b'…' or b"…", not the b' of a word such as "job's".
// One cut before its closing quote (the addon cuts messages at 1 KiB) runs to the end.
var quotedBytesRE = regexp.MustCompile(`(^|[^A-Za-z0-9_])b(?:'(?:[^'\\]|\\.)*(?:'|\\?$)|"(?:[^"\\]|\\.)*(?:"|\\?$))`)

func (s *Store) maskHeaders(h [][2]string) [][2]string {
	if !s.redact.Load() {
		return h
	}
	out := make([][2]string, len(h))
	for i, kv := range h {
		out[i] = kv
		if v, ok := grpcHeaderValue(strings.ToLower(kv[0]), kv[1], func(v string) string { return maskTokens(maskURLs(v)) }); ok && !userName(flatName(kv[0])) && !secretName(kv[0]) {
			out[i][1] = maskUserValues(v)
			continue
		}
		switch name := strings.ToLower(kv[0]); {
		case userName(flatName(kv[0])): // the user's names come before every built-in case
			out[i][1] = "[redacted]"
			continue
		case name == "cookie":
			out[i][1] = maskCookies(kv[1], "; ", false)
		case name == "set-cookie":
			out[i][1] = maskSetCookie(kv[1])
		case name == "sec-websocket-protocol":
			out[i][1] = maskTokens(maskWSProtocols(kv[1]))
		case strings.HasSuffix(name, "-authenticate"):
			// WWW-Authenticate, Proxy-Authenticate: a challenge (scheme, realm, error),
			// not a credential, and what says why a 401 came; a token it quotes still goes
			out[i][1] = maskShapes(maskURLs(kv[1]))
		case secretName(kv[0]): // the name as sent: X-ClientKey splits into client and key
			out[i][1] = "[redacted]"
		default:
			// a credential by its shape, or a URL's (Referer, Location, Link, Refresh, …), under any name
			out[i][1] = maskTokens(maskURLs(kv[1]))
		}
		out[i][1] = maskUserValues(out[i][1]) // every branch: a cookie's attributes too
	}
	return out
}

// secretName reports whether a header or parameter name says it carries a
// secret (secretKind with a lone "code" counted: in URLs and forms it is an
// OAuth authorization code). Masking a harmless value by mistake costs
// little; missing a key does not.
func secretName(name string) bool { return secretKind(name, true) }

// secretKind decides by two kinds of words. Strong ones are secret wherever
// they appear, even run together (accesstoken, x-authtoken, sessiontoken,
// passcode). Short ones only as a whole word, so author, keyword and monkey
// are not; code and key next to an everyday word (country_code, error_code,
// sort_key) are everyday values; a lone code counts only if loneCode.
func secretKind(name string, loneCode bool) bool {
	lower := strings.ToLower(name)
	flat := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return -1
	}, lower)
	if userName(flatName(name)) {
		return true
	}
	if notSecretNames[flat] {
		return false
	}
	for _, part := range strongSecretParts {
		if strings.Contains(flat, part) {
			return true
		}
	}
	words := nameWords(name)
	everyday := false
	for _, w := range words {
		everyday = everyday || everydayWords[w]
	}
	for _, w := range words {
		if w = strings.TrimRight(w, "0123456789"); !shortSecretWords[w] { // key1, pin2: the word with a number after it
			continue
		}
		switch {
		case (w == "code" || w == "key") && everyday:
		case w == "code" && len(words) == 1 && !loneCode:
		default:
			return true
		}
	}
	return false
}

var strongSecretParts = []string{
	"token", "secret", "password", "passwd", "passphrase", "passcode", "credential",
	"signature", "session", "sessid", "jwt", "apikey", "privatekey", "authorization",
	"authentication", "csrf", "xsrf",
	"ticket", // a WebSocket's or a login's (wsTicket, ticket=): one use lets in
	"dpop",   // a DPoP proof, a JWT already, also when not shaped like one
}

var shortSecretWords = map[string]bool{
	"auth": true, "key": true, "sid": true, "sig": true, "sign": true, "pwd": true, "otp": true, "totp": true,
	"pin": true, "code": true, "pass": true, "pw": true,
}

// everydayWords next to code or key make them ordinary values.
var everydayWords = map[string]bool{
	"error": true, "status": true, "reason": true, "response": true, "http": true, "result": true,
	"country": true, "currency": true, "lang": true, "language": true, "locale": true, "region": true,
	"zip": true, "postal": true, "area": true, "state": true, "iso": true, "sort": true, "order": true,
	"foreign": true, // primary is not: primaryKey is a key
}

// notSecretNames look secret but carry what debugging needs (letters and digits only).
var notSecretNames = map[string]bool{
	"tokentype": true, "authenticationtype": true, "authenticationmethod": true,
	"ticketid": true, "ticketnumber": true, // a support ticket's
	"accesscontrolallowcredentials": true, // CORS: true or absent, never a credential (seen masked in use)
}

// nameWords splits a name at non-alphanumerics and case changes, in lower
// case: "X-Amz-Signature" -> x amz signature, "accessToken" -> access token,
// "APIToken" -> api token.
func nameWords(name string) []string {
	rs := []rune(name)
	var words []string
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			words = append(words, strings.ToLower(string(rs[start:end])))
		}
		start = -1
	}
	for i, r := range rs {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush(i)
			continue
		}
		if start >= 0 && unicode.IsUpper(r) {
			prev := rs[i-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush(i)
			}
		}
		if start < 0 {
			start = i
		}
	}
	flush(len(rs))
	return words
}

// maskCookies keeps each cookie's name, so it shows which cookies went, and
// masks its value. In Set-Cookie (oneCookie), only the first pair is a
// cookie; the attributes after it (Path, HttpOnly, ...) stay.
func maskCookies(v, sep string, oneCookie bool) string {
	parts := strings.Split(v, sep)
	for i, p := range parts {
		if oneCookie && i > 0 {
			break
		}
		if name, _, ok := strings.Cut(p, "="); ok {
			parts[i] = name + "=[redacted]"
		} else if strings.TrimSpace(p) != "" {
			parts[i] = "[redacted]" // a value without a name, first or not
		}
	}
	return strings.Join(parts, sep)
}

// A comma that starts another cookie in a Set-Cookie line joining several (a
// server can send one line for many): a name and = follow. A date's comma
// (Expires=Wed, 21 Oct …) is followed by a word and a space.
var cookieJoinRE = regexp.MustCompile(`,[ \t]*[^=;, \t]+=`)

// maskSetCookie masks each cookie of a Set-Cookie value, its attributes kept.
func maskSetCookie(v string) string {
	var b strings.Builder
	last := 0
	for _, m := range cookieJoinRE.FindAllStringIndex(v, -1) {
		b.WriteString(maskCookies(v[last:m[0]], ";", true) + ",")
		last = m[0] + 1
	}
	b.WriteString(maskCookies(v[last:], ";", true))
	return b.String()
}

// A name=value after ?, &, ; or # (OAuth's implicit flow puts the token in the
// fragment, sometimes after a route: #/callback?access_token=). Names stop at
// / and ?. A value runs to & or #: a secret's is masked whole, ';' included
// (some servers keep it in the value); another's is split at ';', so
// "?view=1;token=" is seen too.
// In bodies, a value also stops at a quote, < or > and a backslash (HTML
// attributes, JSON strings), and JSON may write & as \u0026 and = as
// \u003d (Gson, on Android, does). A value goes on after \/ and the
// \u0027 and \u003d Gson writes for ' and =.
var queryRE = regexp.MustCompile(`([?&;#]|\\u0026)([^=&#;?/\s"<>\\]+)(?:=|\\u003[dD])((?:[^&#\s"<>\\]|\\/|\\u00(?:27|3[dD]))*)`)

// A URL's password (https://user:pass@host), also with JSON's escaped slashes
// (https:\/\/user:pass@host, as PHP writes it).
var userinfoRE = regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*:\\?/\\?/[^/?#@\s:"'<>\\]*:)[^/?#@\s"'<>]+@`)

func maskUserinfo(v string) string {
	if strings.Contains(v, ":/") || strings.Contains(v, `:\/`) {
		return userinfoRE.ReplaceAllString(v, "${1}REDACTED@")
	}
	return v
}

func maskURLs(v string) string {
	if strings.IndexByte(v, '=') < 0 && !strings.Contains(v, "@") && !containsFold(v, `\u003d`) {
		return v // no parameter, no password: skip the regexps (most of a 64 KiB JSON head)
	}
	return maskURLsAt(maskUserinfo(v), 0)
}

// maskURLsAt is maskURLs for a URL found depth levels inside another's value.
func maskURLsAt(v string, depth int) string {
	return queryRE.ReplaceAllStringFunc(v, func(m string) string {
		sub := queryRE.FindStringSubmatch(m)
		name, err := url.QueryUnescape(sub[2])
		if err != nil {
			name = sub[2]
		}
		if secretName(name) {
			if sub[3] == "[redacted]" {
				return m // masked already (a form field)
			}
			return sub[1] + sub[2] + "=REDACTED"
		}
		if m, ok := gqlParam(sub[3], depth); ok { // GET ?query=…: the whole value, ';' included
			return sub[1] + sub[2] + "=" + m
		}
		// The value up to ';' is this name's; each ';name=value' after it is
		// looked at once, in one pass (recursing on the rest was quadratic).
		pieces := strings.Split(sub[3], ";")
		if nestedSecret(pieces[0], depth) || jsonSecret(pieces[0]) || encodedToken(pieces[0]) || b64JSONSecret(pieces[0]) {
			pieces[0] = "REDACTED"
		}
		for i := 1; i < len(pieces); i++ {
			n, v, ok := strings.Cut(pieces[i], "=")
			if k := strings.Index(strings.ToLower(pieces[i]), `\u003d`); k >= 0 && (!ok || k < len(n)) { // Gson's =
				n, v, ok = pieces[i][:k], pieces[i][k+6:], true
			}
			if !ok {
				continue
			}
			if secretName(unescapeCut(n)) {
				pieces[i] = n + "=REDACTED"
				pieces = pieces[:i+1] // a secret's value is masked whole, ';' included
				break
			}
			if nestedSecret(v, depth) {
				pieces[i] = n + "=REDACTED"
			}
		}
		return sub[1] + sub[2] + "=" + strings.Join(pieces, ";")
	})
}

// jsonSecret: a URL parameter's value is JSON with a secret field in it
// (GraphQL's GET ?variables={"password":…}).
func jsonSecret(v string) bool {
	if !strings.Contains(v, "%7B") && !strings.Contains(v, "%7b") && !strings.Contains(v, "{") && !strings.Contains(v, "%5B") && !strings.Contains(v, "[") {
		return false
	}
	u := strings.TrimLeft(unescapeCut(v), " \t\r\n+") // + is a space in a query
	if !strings.ContainsAny(u[:min(len(u), 1)], "{[") {
		return false
	}
	return maskJSON(u, true, 2) != u // depth 2: its strings are not decoded again, or nesting would be unbounded (each level a full rescan)
}

// unescapeCut is url.QueryUnescape for text that may be cut inside a %XX
// escape (a head ends anywhere): the cut escape is dropped.
func unescapeCut(v string) string {
	for cut := 0; cut <= 2 && cut <= len(v); cut++ {
		if u, err := url.QueryUnescape(v[:len(v)-cut]); err == nil {
			return u
		}
	}
	return v
}

// nestedSecret: does a value hold a URL or parameters (?redirect=https://x/cb?token=…,
// also percent-encoded, a URL's password included) with a secret in them? Two
// levels are looked into, and a deeper one that could hold parameters counts
// as secret; each level scans its own part of the text once, so the cost stays
// linear in the text whatever its length.
func nestedSecret(v string, depth int) bool {
	if !strings.ContainsAny(v, "?=%@") {
		return false
	}
	inner := unescapeCut(v)
	// Encoded more than once (a redirect's redirect): decode again, twice at most.
	for range 2 {
		if strings.ContainsAny(inner, "?=@") || !strings.Contains(inner, "%") {
			break
		}
		inner = unescapeCut(inner)
	}
	if !strings.ContainsAny(inner, "?=@") {
		return false
	}
	if depth >= 2 {
		return true
	}
	return maskTokens(maskURLsAt(maskUserinfo(inner), depth+1)) != inner
}
