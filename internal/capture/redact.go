package capture

import (
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
// URLs in it (maskURLs). The head may be cut anywhere, so it is scanned as
// text, not parsed: a value cut before its closing quote is masked to the end.
// Heads that are not text are left alone here and never handed out while
// masking (Store.bodyOut). Secrets under names that do not say so are not
// found. In a request, a lone "code" is a secret (an OTP, an OAuth code); in
// a response it is usually an error code.
func maskBody(head []byte, contentType string, request bool) []byte {
	if len(head) == 0 || !utf8.Valid(trimCutRune(head)) {
		return head
	}
	s := maskJSON(string(head), request, 0)
	if request { // GraphQL documents go in requests; scanning every response's text for them was ~20x slower on script-heavy pages
		s = maskGraphQL(s, request)
	}
	if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") || looksLikeForm(s) {
		s = maskForm(s, request)
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
			break
		}
		j := skipSpace(s, keyEnd+1)
		if j >= len(s) || s[j] != ':' {
			i = keyEnd + 1 // a value or array element, not a key
			continue
		}
		j = skipSpace(s, j+1)
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
		switch {
		case secret:
			b.WriteString(s[last : j+1])
			b.WriteString("[redacted]")
			if valClosed {
				b.WriteByte('"')
			}
			last = valEnd + 1
		case valClosed && depth == 0 && strings.Contains(s[j:valEnd], `\u`) && !strings.Contains(s[j:valEnd], `\"`):
			// \u escapes can hide a shape (\u0073k-… is sk-…): look at the
			// string decoded, as diff_flows and the agent would read it.
			if m, ok := maskEscapedString(s[j : valEnd+1]); ok {
				b.WriteString(s[last:j])
				b.WriteString(m)
				last = valEnd + 1
			}
		case valClosed && depth == 0 && strings.Contains(s[j:valEnd], `\"`):
			if m, ok := maskInJSONString(s[j:valEnd+1], loneCode); ok {
				b.WriteString(s[last:j])
				b.WriteString(m)
				last = valEnd + 1
			}
		case !valClosed && depth == 0 && strings.Contains(s[j:], `\"`):
			// Cut before its closing quote, so not decodable: undo the common
			// escapes and, if a secret shows, mask the rest of the head.
			inner := strings.NewReplacer(`\\`, `\`, `\"`, `"`).Replace(s[j+1:])
			if maskJSON(inner, loneCode, 1) != inner {
				b.WriteString(s[last : j+1])
				b.WriteString("[redacted]")
				last = len(s)
			}
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

// maskInJSONString masks a JSON string literal whose text is JSON itself.
func maskInJSONString(lit string, loneCode bool) (string, bool) {
	var inner string
	if json.Unmarshal([]byte(lit), &inner) != nil || !strings.ContainsAny(inner[:min(len(inner), 1)], "{[") {
		return "", false
	}
	m := maskJSON(inner, loneCode, 1)
	if m == inner {
		return "", false
	}
	var out strings.Builder
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false) // keep < > & as the site wrote them
	enc.Encode(m)
	return strings.TrimSuffix(out.String(), "\n"), true
}

// maskEscapedString masks the shapes and URLs in a JSON string literal read
// decoded, and writes it again if anything was masked.
func maskEscapedString(lit string) (string, bool) {
	var v string
	if json.Unmarshal([]byte(lit), &v) != nil {
		return "", false
	}
	m := maskTokens(maskURLs(v))
	if m == v {
		return "", false
	}
	var out strings.Builder
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.Encode(m)
	return strings.TrimSuffix(out.String(), "\n"), true
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

// looksLikeForm: no JSON, XML or HTML, one line, and name=value at the start.
func looksLikeForm(s string) bool {
	t := strings.TrimLeft(s, " \t\r\n")
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
		if secretName(formName(name)) {
			parts[i] = name + "=[redacted]"
		} else if v := unescapeCut(val); strings.ContainsAny(v[:min(len(v), 1)], "{[") {
			if m := maskJSON(v, request, 1); m != v {
				parts[i] = name + "=" + url.QueryEscape(m)
			}
		}
	}
	return strings.Join(parts, "&")
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

// mask and the Store's other mask methods: the caller holds s.mu (s.redact,
// set by SetScope).
func (s *Store) mask(v string) string {
	if !s.redact {
		return v
	}
	return maskTokens(maskURLs(v))
}

// maskError is mask for error messages, which can also quote raw bytes from
// the wire (mitmproxy: "Invalid header line: b'Set-Cookie sid=…'").
func (s *Store) maskError(v string) string {
	if !s.redact {
		return v
	}
	return quotedBytesRE.ReplaceAllString(maskTokens(maskURLs(v)), "${1}b'[redacted]'")
}

// Python's repr of bytes, b'…' or b"…", not the b' of a word such as "job's".
// One cut before its closing quote (the addon cuts messages at 1 KiB) runs to the end.
var quotedBytesRE = regexp.MustCompile(`(^|[^A-Za-z0-9_])b(?:'(?:[^'\\]|\\.)*(?:'|\\?$)|"(?:[^"\\]|\\.)*(?:"|\\?$))`)

func (s *Store) maskHeaders(h [][2]string) [][2]string {
	if !s.redact {
		return h
	}
	out := make([][2]string, len(h))
	for i, kv := range h {
		out[i] = kv
		switch name := strings.ToLower(kv[0]); {
		case userName(flatName(kv[0])): // the user's names come before every built-in case
			out[i][1] = "[redacted]"
			continue
		case name == "cookie":
			out[i][1] = maskCookies(kv[1], "; ", false)
		case name == "set-cookie":
			out[i][1] = maskCookies(kv[1], ";", true)
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
		if !shortSecretWords[w] {
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
	"primary": true, "foreign": true,
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
		} else if i == 0 {
			parts[i] = "[redacted]" // a value without a name
		}
	}
	return strings.Join(parts, sep)
}

// A name=value after ?, &, ; or # (OAuth's implicit flow puts the token in the
// fragment, sometimes after a route: #/callback?access_token=). Names stop at
// / and ?. A value runs to & or #: a secret's is masked whole, ';' included
// (some servers keep it in the value); another's is split at ';', so
// "?view=1;token=" is seen too.
// In bodies, a value also stops at a quote, < or > and a backslash (HTML
// attributes, JSON strings), and JSON may write & as \u0026.
var queryRE = regexp.MustCompile(`([?&;#]|\\u0026)([^=&#;?/\s"<>\\]+)=([^&#\s"<>\\]*)`)

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
	if strings.IndexByte(v, '=') < 0 && !strings.Contains(v, "@") {
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
		// The value up to ';' is this name's; each ';name=value' after it is
		// looked at once, in one pass (recursing on the rest was quadratic).
		pieces := strings.Split(sub[3], ";")
		if nestedSecret(pieces[0], depth) || graphQLSecret(pieces[0]) || jsonSecret(pieces[0]) {
			pieces[0] = "REDACTED"
		}
		for i := 1; i < len(pieces); i++ {
			n, v, ok := strings.Cut(pieces[i], "=")
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
	u := unescapeCut(v)
	if !strings.ContainsAny(u[:min(len(u), 1)], "{[") {
		return false
	}
	return maskJSON(u, true, 1) != u
}

// graphQLSecret: a URL parameter's value is a GraphQL document (GET
// ?query=…) with a secret argument in it.
func graphQLSecret(v string) bool {
	if !strings.Contains(v, "%28") && !strings.Contains(v, "(") {
		return false
	}
	u := unescapeCut(v)
	return maskGraphQL(u, true) != u
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
