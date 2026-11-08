package capture

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maskBody masks the secrets it can recognise in a kept body head, as it
// arrives: the string values of JSON fields whose names are secret (any
// content type: a JSON body may come labelled as a form), the values of such
// form fields (when the body is, or looks like, a form), and anywhere,
// values whose shape gives them away (maskTokens). The head may be cut
// anywhere, so it is scanned as text, not parsed: a value cut before its
// closing quote is masked to the end. Heads that are not text are left alone
// here and never handed out while masking (Store.bodyOut). Secrets under
// names that do not say so are not found.
func maskBody(head []byte, contentType string) []byte {
	if len(head) == 0 || !utf8.Valid(trimCutRune(head)) {
		return head
	}
	s := maskJSON(string(head))
	if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") || looksLikeForm(s) {
		s = maskForm(s)
	}
	return []byte(maskTokens(s))
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

// maskJSON replaces the string value of every "name": "value" pair whose name
// is secret (secretBodyName) with [redacted], in one pass over the text. A
// value that runs to the end of the head (cut, even right after a backslash)
// is masked to the end.
func maskJSON(s string) string {
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
		if j >= len(s) || s[j] != '"' {
			i = j
			continue
		}
		valEnd, valClosed := jsonStringEnd(s, j)
		if secretBodyName(jsonKey(s[keyStart+1 : keyEnd])) {
			b.WriteString(s[last : j+1])
			b.WriteString("[redacted]")
			if valClosed {
				b.WriteByte('"')
			}
			last = valEnd + 1
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
	if k, err := strconv.Unquote(`"` + raw + `"`); err == nil {
		return k
	}
	return raw
}

// secretBodyName is the rule for JSON fields: a lone code is usually an error
// code ({"code": "invalid_token"}), which debugging needs, so it does not
// count; verification_code, device_code and auth_code do.
func secretBodyName(name string) bool { return secretKind(name, false) }

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

// maskForm masks the values of secret fields in a form body (a=1&password=x).
// A lone code counts here: a form is how an OAuth authorization code is sent.
func maskForm(s string) string {
	parts := strings.Split(s, "&")
	for i, p := range parts {
		name, _, ok := strings.Cut(p, "=")
		if ok && secretName(formName(name)) {
			parts[i] = name + "=[redacted]"
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
var schemeRE = regexp.MustCompile(`\b([Bb]earer|[Bb]asic|[Tt]oken)(\s+)([A-Za-z0-9._~+/=-]{8,})`)

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
	if strings.Contains(s, "earer") || strings.Contains(s, "asic") || strings.Contains(s, "oken") {
		s = schemeRE.ReplaceAllStringFunc(s, func(m string) string {
			sub := schemeRE.FindStringSubmatch(m)
			if !credentialLike(sub[3]) {
				return m
			}
			return sub[1] + sub[2] + "[redacted]"
		})
	}
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
