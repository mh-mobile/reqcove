package capture

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
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
		switch {
		case secret:
			b.WriteString(s[last : j+1])
			b.WriteString("[redacted]")
			if valClosed {
				b.WriteByte('"')
			}
			last = valEnd + 1
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

// maskShapes masks the tokenShapes only.
func maskShapes(s string) string {
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
