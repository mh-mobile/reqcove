package capture

import (
	"encoding/xml"
	"io"
	"regexp"
	"strings"
)

// XML bodies are read token by token (encoding/xml's RawToken: it reads no
// DTD and expands no entity). An element whose local name (wsse:Password is
// Password) is secret by JSON's rule has its whole content masked (text,
// CDATA, child elements, comments) up to an end tag of the same name, as a
// SAML Assertion has (a bearer credential); an attribute whose local name is
// has its value masked. Masked spans are replaced in the text as it came,
// never written again by the encoder (it rewrites prefixes). In an Apple
// plist a <key> names the value after it: that value is masked if the key's
// text is secret. The head may be cut, or not tokenize: inside a secret
// element the rest is masked; elsewhere reading goes on from the next <. The
// text masking maskBody does on every body still applies.

// isXML: text/xml, application/xml or application/*+xml (SOAP's
// application/soap+xml), or a body that starts with an XML declaration.
func isXML(ct, s string) bool {
	mt, _, _ := strings.Cut(strings.ToLower(ct), ";")
	mt = strings.TrimSpace(mt)
	return mt == "text/xml" || mt == "application/xml" || strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+xml") ||
		strings.HasPrefix(strings.TrimLeft(s, " \t\r\n\ufeff"), "<?xml")
}

func secretXMLName(local string, request bool) bool {
	return secretKind(local, request) || strings.EqualFold(local, "Assertion") || strings.EqualFold(local, "EncryptedAssertion")
}

func maskXML(s string, request bool) string {
	var b strings.Builder
	last := 0
	mask := func(from, to int) {
		b.WriteString(s[last:from])
		b.WriteString("[redacted]")
		last = to
	}
	var open []string           // the local names of the elements open
	inSecret := false           // inside a secret element:
	secret, nest := "", 0       // its local name, and how many of that name are open inside it
	content := 0                // where its content starts
	keyAt := 0                  // a plist <key> open: its depth,
	var keyText strings.Builder // its text (written to, not added to: a key cut in many pieces stays linear)
	nextSecret := false         // the element after a plist key whose text is secret
	startElement := func(local string, start, end int) {
		for _, sp := range secretAttrs(s[start:end], request) {
			mask(start+sp[0], start+sp[1])
		}
		open = append(open, local)
		plistKey := local == "key" && len(open) > 1 && open[len(open)-2] == "dict"
		switch {
		case nextSecret || secretXMLName(local, request) && !plistKey:
			inSecret, secret, nest, content = true, local, 0, end
		case plistKey:
			keyAt = len(open)
			keyText.Reset()
		}
		nextSecret = false
	}
read:
	for base := 0; base < len(s); {
		d := xml.NewDecoder(strings.NewReader(s[base:]))
		d.Strict = false                                                                   // an undeclared entity (&nbsp;) does not end the reading
		d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil } // the head is UTF-8 (maskBody checked), whatever it declares
		for {
			start := base + int(d.InputOffset())
			tok, err := d.RawToken()
			end := base + int(d.InputOffset())
			if err != nil {
				if inSecret { // cut (or broken) inside a secret element
					mask(content, len(s))
					break read
				}
				if err == io.EOF {
					break read
				}
				// What does not tokenize: read on past it. Each way on starts
				// after what was read, so the reading stays linear.
				next := max(end, start+1, last)
				switch rest := s[start:]; {
				case strings.HasPrefix(rest, "<!--"): // a bad comment: after its end
					next = max(next, closeAfter(s, start+4, "-->"))
				case len(rest) > 1 && rest[0] == '<' && (rest[1] >= 'A' || rest[1] == ':'):
					// A start tag the decoder refuses (Type=http://x#y, a=b!c, a
					// head cut in it): read as one, then on in its content.
					tagEnd, closed := xmlTagEnd(s, start)
					name := s[start+1 : tagEnd]
					if k := strings.IndexAny(name, " \t\r\n/>=<\"'"); k >= 0 {
						name = name[:k]
					}
					if closed && s[tagEnd-2] == '/' { // self-closing
						for _, sp := range secretAttrs(s[start:tagEnd], request) {
							mask(start+sp[0], start+sp[1])
						}
						nextSecret = false
					} else {
						startElement(name[strings.LastIndexByte(name, ':')+1:], start, tagEnd)
					}
					base = max(tagEnd, end, last, start+1)
					continue read
				}
				k := strings.IndexByte(s[min(next, len(s)):], '<')
				if k < 0 {
					break read
				}
				base = next + k
				continue read
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if inSecret {
					open = append(open, t.Name.Local)
					if t.Name.Local == secret {
						nest++
					}
					continue
				}
				startElement(t.Name.Local, start, end)
			case xml.CharData:
				if keyAt > 0 {
					keyText.Write(t)
				}
			case xml.EndElement:
				switch {
				case inSecret:
					if t.Name.Local != secret { // </i> inside <Password>: still in it
						break
					}
					if nest > 0 {
						nest--
						break
					}
					if start > content { // <Password/> stays as it is
						mask(content, start)
					}
					inSecret = false
				case keyAt > 0 && len(open) == keyAt:
					nextSecret, keyAt = secretKind(strings.TrimSpace(keyText.String()), request), 0
				default:
					nextSecret = false
				}
				if len(open) > 0 {
					open = open[:len(open)-1]
				}
			}
		}
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// xmlAttrRE: an attribute in a start tag, its value quoted (a quote the
// head's end cut runs to it) or, read leniently, unquoted. Nothing need come
// before its name: x="1"password="…" is read too.
var xmlAttrRE = regexp.MustCompile(`([^\s=/<>"']+)\s*=\s*(?:"([^"]*)"?|'([^']*)'?|([^\s>"']+))`)

// closeAfter returns the index after the first end at or after i in s, or len(s).
func closeAfter(s string, i int, end string) int {
	if k := strings.Index(s[i:], end); k >= 0 {
		return i + k + len(end)
	}
	return len(s)
}

// xmlTagEnd returns where the tag opening at s[i] ends: after its first >
// outside quotes (closed), or at a < outside quotes or the end of s (a
// quoted value runs on past < and >, as it may).
func xmlTagEnd(s string, i int) (int, bool) {
	var q byte
	for k := i + 1; k < len(s); k++ {
		switch c := s[k]; {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '>':
			return k + 1, true
		case c == '<':
			return k, false
		}
	}
	return len(s), false
}

// secretAttrs returns the spans of the values of secret attributes in the
// start tag s, whole or cut.
func secretAttrs(s string, request bool) [][2]int {
	var spans [][2]int
	for _, m := range xmlAttrRE.FindAllStringSubmatchIndex(s, -1) {
		name := s[m[2]:m[3]]
		local := name[strings.LastIndexByte(name, ':')+1:]
		if name == "xmlns" || strings.HasPrefix(name, "xmlns:") || !secretXMLName(local, request) {
			continue
		}
		for g := 4; g < 10; g += 2 {
			if m[g] >= 0 {
				spans = append(spans, [2]int{m[g], m[g+1]})
			}
		}
	}
	return spans
}
