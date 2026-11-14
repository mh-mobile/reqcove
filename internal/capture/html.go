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
// value of an attribute whose own name is (data-token=…), as XML's are; a
// <textarea> so named has its text masked. A lone code counts: a form field
// so named carries an OAuth code. A tag the head's end cuts has its value
// and content masked whatever its name, which may come after them, and a
// secret <textarea> cut has its text masked to the end. A comment, and the
// text of an element whose text is no markup (<script>, <style>, <title>,
// …), is read as a region of its own: a quote or a < in it never runs on
// into the markup after it (a script's "<a x='" made the next real tag read
// as an attribute's value), and tags in it are still read, up to its end
// (a commented-out field; HTML in a script's string, as Rails'
// append('<input … value="…">')). Scripts' objects are maskScript's. One
// pass: each tag is read once, from < to >.
func maskHTML(s string) string {
	var b strings.Builder
	last := 0
	mask := func(from, to int) {
		if to > from && from >= last && s[from:to] != "[redacted]" {
			b.WriteString(s[last:from])
			b.WriteString("[redacted]")
			last = to
		}
	}
	// end bounds the scan: inside a region, its end (resume: where markup
	// goes on after it); else len(s), resume -1.
	end, resume := len(s), -1
	for i := 0; ; {
		if i >= end {
			if resume < 0 {
				break
			}
			i, end, resume = resume, len(s), -1
			continue
		}
		lt := strings.IndexByte(s[i:end], '<')
		if lt < 0 {
			i = end
			continue
		}
		j := i + lt + 1
		if resume < 0 && strings.HasPrefix(s[j:], "!--") {
			i = j + 3
			end, resume = commentEnd(s, i)
			continue
		}
		if j >= end || !(s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z') {
			i = j // an end tag, a doctype, a < in text
			continue
		}
		ns := j
		for j < end && !htmlSpace(s[j]) && s[j] != '>' && s[j] != '/' {
			j++ // the tag's name
		}
		tag := strings.ToLower(s[ns:j])
		var vals, own [][2]int // value or content; attributes secret by their own name
		secret, closed := false, false
		for j < end {
			for j < end && (htmlSpace(s[j]) || s[j] == '/') {
				j++
			}
			if j >= end {
				break
			}
			if s[j] == '>' {
				closed = true
				j++
				break
			}
			ns := j
			for j < end && !htmlSpace(s[j]) && s[j] != '=' && s[j] != '>' && s[j] != '/' {
				j++
			}
			name := strings.ToLower(s[ns:j])
			k := htmlSkipSpace(s[:end], j)
			if k >= end || s[k] != '=' {
				continue // an attribute with no value (hidden, disabled)
			}
			k = htmlSkipSpace(s[:end], k+1)
			vs, ve := k, k
			if k < end && (s[k] == '"' || s[k] == '\'') {
				vs = k + 1
				if e := strings.IndexByte(s[vs:end], s[k]); e >= 0 {
					ve, j = vs+e, vs+e+1
				} else {
					ve, j = end, end // cut inside the value (or, in a region, it runs to its end)
				}
			} else {
				for k < end && !htmlSpace(s[k]) && s[k] != '>' {
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
		// Cut: the head ends inside the tag (a region's end cuts nothing).
		if !secret && (closed || end < len(s)) {
			vals = nil
		}
		// Spans come in order, each after the last, as attributes do.
		for _, sp := range mergeSpans(vals, own) {
			mask(sp[0], sp[1])
		}
		i = j
		if resume < 0 && closed && rawText[tag] {
			e := rawTextEnd(s, j, tag)
			if tag == "textarea" && secret {
				mask(j, e) // its text is its value
				i = e
			} else {
				end, resume = e, e
			}
		}
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// rawText: elements whose text is no markup to a browser, up to their end
// tag (noscript's, with scripts on).
var rawText = map[string]bool{"script": true, "style": true, "textarea": true, "title": true, "xmp": true, "iframe": true, "noembed": true, "noframes": true, "noscript": true}

// rawTextEnd: where such an element's text from i ends, at its end tag (its
// name in any case, then a space, a / or a >), or len(s).
func rawTextEnd(s string, i int, tag string) int {
	for {
		k := strings.Index(s[i:], "</")
		if k < 0 {
			return len(s)
		}
		k += i
		e := k + 2 + len(tag)
		// EqualFold on as many bytes as the ASCII name: only ASCII can match.
		if e <= len(s) && strings.EqualFold(s[k+2:e], tag) && (e == len(s) || htmlSpace(s[e]) || s[e] == '/' || s[e] == '>') {
			return k
		}
		i = k + 2
	}
}

// commentEnd: where a comment's text from i (past its <!--) ends, and where
// markup goes on after it: past -->, --!>, or the > of <!--> and <!--->.
// Uncut, both are len(s).
func commentEnd(s string, i int) (int, int) {
	switch {
	case strings.HasPrefix(s[i:], ">"):
		return i, i + 1
	case strings.HasPrefix(s[i:], "->"):
		return i, i + 2
	}
	for k := i; ; {
		d := strings.Index(s[k:], "--")
		if d < 0 {
			return len(s), len(s)
		}
		d += k
		if strings.HasPrefix(s[d+2:], ">") {
			return d, d + 3
		}
		if strings.HasPrefix(s[d+2:], "!>") {
			return d, d + 4
		}
		k = d + 1
	}
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
// {pin: 1234}): JSON's masking reads quoted names only. Comments may come
// around the name and the colon ({accessToken: /* c */ '…'}); a string may
// go on past a line's end after a backslash, a template literal over lines
// (one with a template literal inside it is masked up to that one's start
// only). A string cut by the head's end (its closing quote missing) runs to it.
var scriptFieldRE = regexp.MustCompile(`([{,]` + jsGap + `)([A-Za-z_$][A-Za-z0-9_$]*)(` + jsGap + `:` + jsGap + `)(?:` +
	`(")(?:[^"\\\n]|` + jsEscape + `)*("|\\?$)|` +
	`(')(?:[^'\\\n]|` + jsEscape + `)*('|\\?$)|` +
	"(`)(?:[^`\\\\]|" + jsEscape + ")*(`|\\\\?$)|" +
	`-?[0-9][0-9.eE+-]*)`)

const (
	jsGap    = `(?:\s|/\*(?s:.)*?\*/|//[^\n]*\n)*` // spaces and comments
	jsEscape = `\\(?:\r\n|(?s:.))`                 // one, a line's end (a continuation) included
)

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
		field := sub[1] + sub[2] + sub[3]
		for q := 4; q <= 8; q += 2 { // ", ', `
			if sub[q] != "" {
				return field + sub[q] + "[redacted]" + strings.TrimLeft(sub[q+1], `\`) // the closing quote, if it came
			}
		}
		return field + `"[redacted]"`
	})
}
