package capture

import (
	"regexp"
	"strings"
)

// isHTML: an HTML page by its content type, or a head that starts like one.
func isHTML(ct, s string) bool {
	if strings.Contains(strings.ToLower(ct), "html") { // text/html, application/xhtml+xml
		return true
	}
	t := strings.ToLower(strings.TrimLeft(s, " \t\r\n\ufeff"))
	return strings.HasPrefix(t, "<!doctype html") || strings.HasPrefix(t, "<html")
}

// isScript: JavaScript, which writes object keys unquoted ({accessToken: "…"}).
func isScript(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
}

// maskHTML masks, in each tag of an HTML page, the value or content of a tag
// whose name, id or property says it is secret (a hidden form field: an
// OAuth form_post's code or id_token, Rails' authenticity_token, ASP.NET's
// __RequestVerificationToken; <meta name="csrf-token" content=…>), and the
// value of an attribute whose own name is (data-token=…), as XML's are. A
// lone code counts: a form field so named carries an OAuth code. A tag the
// head's end cuts has its value and content masked whatever its name, which
// may come after them. One pass: each tag is read once, from < to >.
func maskHTML(s string) string {
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); {
		lt := strings.IndexByte(s[i:], '<')
		if lt < 0 {
			break
		}
		j := i + lt + 1
		if j >= len(s) || !(s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z') {
			i = j // an end tag, a comment, a doctype, a < in text
			continue
		}
		for j < len(s) && !htmlSpace(s[j]) && s[j] != '>' && s[j] != '/' {
			j++ // the tag's name
		}
		var vals, own [][2]int // value or content; attributes secret by their own name
		secret, closed := false, false
		for j < len(s) {
			for j < len(s) && (htmlSpace(s[j]) || s[j] == '/') {
				j++
			}
			if j >= len(s) {
				break
			}
			if s[j] == '>' {
				closed = true
				j++
				break
			}
			ns := j
			for j < len(s) && !htmlSpace(s[j]) && s[j] != '=' && s[j] != '>' && s[j] != '/' {
				j++
			}
			name := strings.ToLower(s[ns:j])
			k := htmlSkipSpace(s, j)
			if k >= len(s) || s[k] != '=' {
				continue // an attribute with no value (hidden, disabled)
			}
			k = htmlSkipSpace(s, k+1)
			vs, ve := k, k
			if k < len(s) && (s[k] == '"' || s[k] == '\'') {
				vs = k + 1
				if e := strings.IndexByte(s[vs:], s[k]); e >= 0 {
					ve, j = vs+e, vs+e+1
				} else {
					ve, j = len(s), len(s) // cut inside the value
				}
			} else {
				for k < len(s) && !htmlSpace(s[k]) && s[k] != '>' {
					k++
				}
				ve, j = k, k
			}
			switch v := s[vs:ve]; {
			case name == "value" || name == "content":
				vals = append(vals, [2]int{vs, ve})
			case name == "name" || name == "id" || name == "property":
				secret = secret || secretName(v)
			case secretName(name):
				own = append(own, [2]int{vs, ve})
			}
		}
		if !secret && closed {
			vals = nil
		}
		// Spans come in order, each after the last, as attributes do.
		for _, sp := range mergeSpans(vals, own) {
			if sp[1] > sp[0] && s[sp[0]:sp[1]] != "[redacted]" {
				b.WriteString(s[last:sp[0]])
				b.WriteString("[redacted]")
				last = sp[1]
			}
		}
		i = j
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// mergeSpans puts two lists of spans, each in order, in one order.
func mergeSpans(a, b [][2]int) [][2]int {
	out := make([][2]int, 0, len(a)+len(b))
	for len(a) > 0 || len(b) > 0 {
		if len(b) == 0 || len(a) > 0 && a[0][0] < b[0][0] {
			out, a = append(out, a[0]), a[1:]
		} else {
			out, b = append(out, b[0]), b[1:]
		}
	}
	return out
}

func htmlSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }

func htmlSkipSpace(s string, i int) int {
	for i < len(s) && htmlSpace(s[i]) {
		i++
	}
	return i
}

// A script's object field with an unquoted name ({accessToken: "…"},
// {pin: 1234}): JSON's masking reads quoted names only. A string cut by the
// head's end (its closing quote missing) runs to it.
var scriptFieldRE = regexp.MustCompile(`([{,]\s*)([A-Za-z_$][A-Za-z0-9_$]*)(\s*:\s*)(?:(")(?:[^"\\\n]|\\.)*("|\\?$)|(')(?:[^'\\\n]|\\.)*('|\\?$)|-?[0-9][0-9.eE+-]*)`)

// maskScript masks the values of such fields whose names are secret, as
// maskJSON does (a lone code by loneCode).
func maskScript(s string, loneCode bool) string {
	if !strings.Contains(s, ":") {
		return s
	}
	return scriptFieldRE.ReplaceAllStringFunc(s, func(m string) string {
		sub := scriptFieldRE.FindStringSubmatch(m)
		if !secretKind(sub[2], loneCode) {
			return m
		}
		switch field := sub[1] + sub[2] + sub[3]; {
		case sub[4] != "":
			return field + `"[redacted]` + strings.TrimLeft(sub[5], `\`) // the closing quote, if it came
		case sub[6] != "":
			return field + `'[redacted]` + strings.TrimLeft(sub[7], `\`)
		default:
			return field + `"[redacted]"`
		}
	})
}
