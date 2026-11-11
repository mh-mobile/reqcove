package capture

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
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
// alias, another field or a spread, or { name } alone or before another
// definition. "{count} items" and "{name}'s" are not one. ended: s has no
// more tokens than toks.
func gqlStart(s string, toks []gqlTok, ended bool) bool {
	if len(toks) > 0 && (toks[0].kind == 's' || toks[0].kind == 'b') {
		toks = toks[1:] // a description: """Login""" mutation Login { … }
	}
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
		if is(1, '.', "") {
			return true
		}
		if !is(1, 'n', "") {
			return false
		}
		return opens(2) || is(2, 'n', "") || is(2, '.', "") || is(2, ':', "") && is(3, 'n', "") ||
			is(2, '}', "") && (ended && len(toks) == 3 || is(3, 'n', "fragment") || is(3, 'n', "query") || is(3, 'n', "mutation") || is(3, 'n', "subscription"))
	}
	return false
}

// maskGraphQLDoc masks s if it is a document (isDoc): the values of secret
// names (an argument's or input field's after :, a variable's default after
// =); all of it if it cannot be lexed.
func maskGraphQLDoc(s string, loneCode bool) (masked string, isDoc bool) {
	head, hok := gqlLex(s, 5)
	if !gqlStart(s, head, hok && len(head) < 5) {
		return s, false
	}
	toks, ok := gqlLex(s, gqlMaxTokens)
	if !ok {
		if len(head) >= 4 && head[0].kind == '{' && head[2].kind == ':' && head[3].kind == 'n' && strings.HasPrefix(strings.TrimLeft(s[head[3].end:], " \t\r\n"), ",") {
			return s, false // {success:true,msg:'done'}: a script's object that GraphQL cannot read, not a broken document
		}
		return "[redacted]", true
	}
	var b strings.Builder
	last := 0
	defSecret := false // the name a default (= value) belongs to is secret: $password: String = "…"
	for k := 0; k < len(toks); k++ {
		v := -1
		switch t := toks[k]; {
		case t.kind == 'n' && k+1 < len(toks) && toks[k+1].kind == ':':
			defSecret = secretKind(s[t.start:t.end], loneCode) // once a name: "=" after "=" must not ask again
			if k > 0 && toks[k-1].kind == '$' {
				continue // a variable: its type comes next, not a value
			}
			if defSecret {
				v = k + 2
			}
		case t.kind == '=' && defSecret:
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
// document: after spaces, commas, byte order marks and escaped line breaks, a
// keyword, { or #, or an escape (\u006d is m: decoded to be sure).
func gqlPrefix(raw string) bool {
	for len(raw) > 0 {
		if c := raw[0]; c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',' {
			raw = raw[1:]
		} else if strings.HasPrefix(raw, "\xef\xbb\xbf") {
			raw = raw[3:]
		} else if len(raw) > 1 && c == '\\' && strings.IndexByte("nrt", raw[1]) >= 0 {
			raw = raw[2:]
		} else {
			break
		}
	}
	if raw == "" {
		return false
	}
	if raw[0] == '{' || raw[0] == '#' || strings.HasPrefix(raw, `\u`) || strings.HasPrefix(raw, `\"`) { // \" may open a description
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
//
// urls: the URLs and shapes in it are looked at too (not at depth 2, where
// nesting must stop).
func gqlString(lit string, closed, loneCode, urls bool) (string, bool) {
	if !gqlPrefix(lit[1:]) {
		return "", false
	}
	raw := lit
	if !closed {
		raw = trimCutEscape(lit) + `"`
	}
	var v string
	if json.Unmarshal([]byte(raw), &v) != nil {
		// Not JSON as written (raw line breaks or tabs in it): read leniently.
		lenient := strings.NewReplacer("\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(raw)
		if json.Unmarshal([]byte(lenient), &v) != nil {
			return "", false
		}
	}
	m, isDoc := maskGraphQLDoc(v, loneCode)
	if !isDoc {
		return "", false
	}
	if urls {
		m = maskTokens(maskURLs(m))
	}
	if m == v {
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
func gqlParam(v string, depth int) (string, bool) {
	if !strings.Contains(v, ":") && !containsFold(v, "%3a") {
		return "", false // no argument, nothing to mask
	}
	u := unescapeCut(v)
	m, isDoc := maskGraphQLDoc(u, true)
	if !isDoc || m == u {
		return "", false // nestedSecret then looks at it whole
	}
	if depth < 2 { // and the URLs and shapes in it (login(next: "https://…?token=…")), as nestedSecret would
		m = maskTokens(maskURLsAt(maskUserinfo(m), depth+1))
	} else if strings.ContainsAny(m, "?=@") {
		return "REDACTED", true // deeper than is looked into, and it could hold parameters: as nestedSecret does
	}
	return url.QueryEscape(m), true
}

// The operation a GraphQL request names, for rows and summarize: its
// operationName first (JSON, or ?operationName=), else its document's first
// operation; "(anonymous)" for one without a name, "(batched)" for an array
// of them; "" for a request that is not GraphQL. Persisted queries carry no
// document, so only their operationName names them. Worked out from what was
// masked, as it arrives, outside the Store's lock.
const (
	gqlAnonymous = "(anonymous)"
	gqlBatched   = "(batched)"
)

// gqlName: a name GraphQL allows, at most 100 characters; anything else
// (text an app or a site chose) is not shown.
func gqlName(s string) string {
	if s == "" || len(s) > 100 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9') {
			return ""
		}
	}
	return s
}

// gqlDocOperation names the first operation of document doc.
// gqlDocOperation names the first operation of document doc, past fragments
// and descriptions.
func gqlDocOperation(doc string) string {
	if head, ok := gqlLex(doc, 5); !gqlStart(doc, head, ok && len(head) < 5) {
		return ""
	}
	toks, _ := gqlLex(doc, gqlMaxTokens)
	depth, fragment := 0, false // fragment: past "fragment", before its selections
	for k, t := range toks {
		switch {
		case t.kind == '{' && depth == 0 && !fragment:
			return gqlAnonymous // a selection set alone: { … }
		case t.kind == '{' || t.kind == '(' || t.kind == '[':
			fragment = fragment && !(t.kind == '{' && depth == 0)
			depth++
		case t.kind == '}' || t.kind == ')' || t.kind == ']':
			depth--
		case depth == 0 && t.kind == 'n' && strings.Contains(" query mutation subscription ", " "+doc[t.start:t.end]+" "):
			if k+1 < len(toks) && toks[k+1].kind == 'n' {
				return gqlName(doc[toks[k+1].start:toks[k+1].end])
			}
			return gqlAnonymous
		case depth == 0 && t.kind == 'n' && doc[t.start:t.end] == "fragment":
			fragment = true
		}
	}
	return gqlAnonymous
}

// gqlURLOperation: from a URL's ?operationName=, else its ?query= document.
func gqlURLOperation(u string) string {
	_, q, ok := strings.Cut(u, "?")
	if !ok {
		return ""
	}
	vals, _ := url.ParseQuery(q)
	if op := gqlName(vals.Get("operationName")); op != "" {
		return op
	}
	return gqlDocOperation(vals.Get("query"))
}

// gqlOperationField finds "operationName" in a head json cannot read (cut).
var gqlOperationField = regexp.MustCompile(`"operationName"\s*:\s*"([_A-Za-z][_0-9A-Za-z]{0,99})"`)

// gqlBodyOperation: from a request body (masked: names and documents stay).
func gqlBodyOperation(head []byte) string {
	t := bytes.TrimLeft(head, " \t\r\n")
	if len(t) == 0 {
		return ""
	}
	if t[0] != '{' && t[0] != '[' {
		return gqlDocOperation(string(t)) // application/graphql
	}
	var one struct {
		OperationName string `json:"operationName"`
		Query         string `json:"query"`
	}
	var many []json.RawMessage
	switch {
	case t[0] == '[' && json.Unmarshal(t, &many) == nil:
		for _, m := range many {
			if json.Unmarshal(m, &one) == nil && (one.OperationName != "" || gqlDocOperation(one.Query) != "") {
				return gqlBatched
			}
		}
		return ""
	case t[0] == '{' && json.Unmarshal(t, &one) == nil:
		if op := gqlName(one.OperationName); op != "" {
			return op
		}
		return gqlDocOperation(one.Query)
	}
	if m := gqlOperationField.FindSubmatch(t); m != nil { // cut by the head's end
		if t[0] == '[' {
			return gqlBatched
		}
		return string(m[1])
	}
	return ""
}
