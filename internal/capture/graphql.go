package capture

import (
	"encoding/json"
	"net/url"
	"strings"
)

// GraphQL documents are read by a lexer, not a pattern: an argument, an
// input object's field or a variable whose name is secret has its whole value
// masked (a string, a number, a list, an object), as a JSON field's is; enum
// and boolean values, variables ($x) and aliases stay. A document is found
// where it starts like one: a JSON string at depth 0 or 1 (any key, in
// requests and responses), a raw body, a URL parameter. One that cannot be
// lexed is masked whole; a value cut by the head's end, to the end.

// gqlTok is a token by byte offsets: kind is 'n' (name), 's' (string), 'b'
// (block string), '0' (number), '.' (...) or the punctuator itself.
type gqlTok struct {
	kind       byte
	start, end int
}

// gqlMaxTokens bounds one document (a 64 KiB head holds fewer).
const gqlMaxTokens = 1 << 16

// gqlLex returns s's first limit tokens, and false (with the tokens before
// it) at a character GraphQL does not allow, a line break in a string, or
// past gqlMaxTokens. A string or block string cut by the end runs to it.
func gqlLex(s string, limit int) ([]gqlTok, bool) {
	var toks []gqlTok
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++
			continue
		case c == '#':
			for i < len(s) && s[i] != '\n' && s[i] != '\r' {
				i++
			}
			continue
		case strings.HasPrefix(s[i:], "\xef\xbb\xbf"): // a byte order mark
			i += 3
			continue
		}
		if len(toks) == limit {
			return toks, limit < gqlMaxTokens
		}
		t := gqlTok{start: i}
		switch {
		case c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
			for i++; i < len(s) && (s[i] == '_' || s[i] >= 'A' && s[i] <= 'Z' || s[i] >= 'a' && s[i] <= 'z' || s[i] >= '0' && s[i] <= '9'); i++ {
			}
			t.kind = 'n'
		case c == '-' || c >= '0' && c <= '9':
			// laxer than the grammar: whatever it is, it is a number's place
			for i++; i < len(s) && (s[i] >= '0' && s[i] <= '9' || strings.IndexByte(".eE+-", s[i]) >= 0); i++ {
			}
			t.kind = '0'
		case strings.HasPrefix(s[i:], `"""`):
			i += 3
			for {
				k := strings.Index(s[i:], `"""`)
				if k < 0 {
					i = len(s)
					break
				}
				i += k + 3
				if s[i-4] != '\\' { // \""" is the one escape in a block string
					break
				}
			}
			t.kind = 'b'
		case c == '"':
			for i++; ; i++ {
				if i >= len(s) {
					i = len(s)
					break
				}
				if s[i] == '\\' {
					i++
				} else if s[i] == '"' {
					i++
					break
				} else if s[i] == '\n' || s[i] == '\r' {
					return toks, false
				}
			}
			t.kind = 's'
		case strings.HasPrefix(s[i:], "..."):
			i += 3
			t.kind = '.'
		case strings.IndexByte("!$&():=@[]{|}", c) >= 0:
			i++
			t.kind = c
		case len(s)-i < 3 && strings.HasPrefix("...", s[i:]): // ... cut by the end
			i = len(s)
			t.kind = '.'
		default:
			return toks, false
		}
		t.end = i
		toks = append(toks, t)
	}
	return toks, true
}

// gqlStart: the tokens start a document. An operation (query, mutation or
// subscription, then a name or not, then its variables, directives or
// selections), a fragment, or { then a field with arguments, selections, an
// alias, another field or a spread. "{count} items" is not one.
func gqlStart(s string, toks []gqlTok) bool {
	is := func(k int, kind byte, text string) bool {
		return k < len(toks) && toks[k].kind == kind && (text == "" || s[toks[k].start:toks[k].end] == text)
	}
	opens := func(k int) bool { return k < len(toks) && strings.IndexByte("({@", toks[k].kind) >= 0 }
	switch {
	case is(0, 'n', "query") || is(0, 'n', "mutation") || is(0, 'n', "subscription"):
		return opens(1) || is(1, 'n', "") && opens(2)
	case is(0, 'n', "fragment"):
		return is(1, 'n', "") && is(2, 'n', "on")
	case is(0, '{', ""):
		return is(1, '.', "") || is(1, 'n', "") && (opens(2) || is(2, 'n', "") || is(2, ':', "") && is(3, 'n', ""))
	}
	return false
}

// maskGraphQLDoc masks s if it is a document (isDoc): the values of secret
// names (an argument's or input field's after :, a variable's default after
// =); all of it if it cannot be lexed.
func maskGraphQLDoc(s string, loneCode bool) (masked string, isDoc bool) {
	if head, _ := gqlLex(s, 4); !gqlStart(s, head) {
		return s, false
	}
	toks, ok := gqlLex(s, gqlMaxTokens)
	if !ok {
		return "[redacted]", true
	}
	var b strings.Builder
	last := 0
	def := "" // the name a default (= value) belongs to: $password: String = "…"
	for k := 0; k < len(toks); k++ {
		v := -1
		switch t := toks[k]; {
		case t.kind == 'n' && k+1 < len(toks) && toks[k+1].kind == ':':
			def = s[t.start:t.end]
			if k > 0 && toks[k-1].kind == '$' {
				continue // a variable: its type comes next, not a value
			}
			if secretKind(def, loneCode) {
				v = k + 2
			}
		case t.kind == '=' && def != "" && secretKind(def, loneCode):
			v = k + 1
		}
		if v < 0 || v >= len(toks) {
			continue
		}
		end, toEnd, ok := gqlValueEnd(toks, v)
		if !ok {
			continue // an enum, true, false, null or $variable; an alias's field
		}
		b.WriteString(s[last:toks[v].start])
		b.WriteString(`"[redacted]"`)
		last = toks[end].end
		if toEnd {
			last = len(s)
		}
		k = end
	}
	if last == 0 {
		return s, true
	}
	b.WriteString(s[last:])
	return b.String(), true
}

// gqlValueEnd: the last token of the value at toks[v], if it is a kind that
// is masked; toEnd if it runs to the end (a list or object cut by it).
func gqlValueEnd(toks []gqlTok, v int) (end int, toEnd, ok bool) {
	switch toks[v].kind {
	case 's', 'b', '0':
		return v, false, true
	case '[', '{':
		depth := 0
		for k := v; k < len(toks); k++ {
			switch toks[k].kind {
			case '[', '{':
				depth++
			case ']', '}':
				if depth--; depth == 0 {
					return k, false, true
				}
			}
		}
		return len(toks) - 1, true, true
	}
	return 0, false, false
}

// gqlPrefix: raw text (a JSON string's, after its quote) may start a
// document: after spaces, commas and escaped line breaks, a keyword, { or #.
func gqlPrefix(raw string) bool {
	for len(raw) > 0 {
		if c := raw[0]; c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' {
			raw = raw[1:]
		} else if len(raw) > 1 && c == '\\' && strings.IndexByte("nrt", raw[1]) >= 0 {
			raw = raw[2:]
		} else {
			break
		}
	}
	if raw == "" {
		return false
	}
	if raw[0] == '{' || raw[0] == '#' {
		return true
	}
	for _, w := range []string{"query", "mutation", "subscription", "fragment"} {
		if strings.HasPrefix(raw, w) {
			return true
		}
	}
	return false
}

// gqlString masks a document held in a JSON string literal (lit, from its
// opening quote, closed or cut by the head's end), read decoded and written
// again; false if it holds none, or nothing was masked.
func gqlString(lit string, closed, loneCode bool) (string, bool) {
	if !gqlPrefix(lit[1:]) {
		return "", false
	}
	raw := lit
	if !closed {
		raw = trimCutEscape(lit) + `"`
	}
	var v string
	if json.Unmarshal([]byte(raw), &v) != nil {
		return "", false
	}
	m, isDoc := maskGraphQLDoc(v, loneCode)
	if !isDoc {
		return "", false
	}
	if m = maskTokens(maskURLs(m)); m == v {
		return "", false
	}
	out := jsonString(m)
	if !closed {
		out = strings.TrimSuffix(out, `"`)
	}
	return out, true
}

// gqlParam masks a document in a URL parameter's value (GET ?query=…, a form
// field), decoded and escaped again.
func gqlParam(v string) (string, bool) {
	if !strings.Contains(v, ":") && !containsFold(v, "%3a") {
		return "", false // no argument, nothing to mask
	}
	u := unescapeCut(v)
	m, isDoc := maskGraphQLDoc(u, true)
	if !isDoc || m == u {
		return "", false
	}
	return url.QueryEscape(m), true
}
