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
	var open []string       // the local names of the elements open
	inSecret := false       // inside a secret element:
	secret, nest := "", 0   // its local name, and how many of that name are open inside it
	content := 0            // where its content starts
	keyAt, keyText := 0, "" // a plist <key> open: its depth, its text
	nextSecret := false     // the element after a plist key whose text is secret
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
				// What does not tokenize (XML 1.1's declaration, 1 < 2, a head
				// cut in a tag): a secret attribute in it (up to the next <, as
				// a tag holds none), then on from the next < after it.
				tag := s[start:]
				if k := strings.IndexByte(tag[min(1, len(tag)):], '<'); k >= 0 {
					tag = tag[:k+1]
				}
				for _, sp := range secretAttrs(tag, request) {
					mask(start+sp[0], start+sp[1])
				}
				next := max(end, start+1, last)
				k := strings.IndexByte(s[min(next, len(s)):], '<')
				if k < 0 {
					break read
				}
				base = next + k
				continue read
			}
			switch t := tok.(type) {
			case xml.StartElement:
				open = append(open, t.Name.Local)
				if inSecret {
					if t.Name.Local == secret {
						nest++
					}
					continue
				}
				for _, sp := range secretAttrs(s[start:end], request) {
					mask(start+sp[0], start+sp[1])
				}
				plistKey := t.Name.Local == "key" && len(open) > 1 && open[len(open)-2] == "dict"
				switch {
				case nextSecret || secretXMLName(t.Name.Local, request) && !plistKey:
					inSecret, secret, nest, content = true, t.Name.Local, 0, end
				case plistKey:
					keyAt, keyText = len(open), ""
				}
				nextSecret = false
			case xml.CharData:
				if keyAt > 0 {
					keyText += string(t)
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
					nextSecret, keyAt = secretKind(strings.TrimSpace(keyText), request), 0
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

// secretAttrs returns the spans of the values of secret attributes in the
// start tag s begins with, if it does (up to its first > outside quotes).
func secretAttrs(s string, request bool) [][2]int {
	if len(s) < 2 || s[0] != '<' || strings.IndexByte("/!?", s[1]) >= 0 {
		return nil
	}
	var q byte
	for i := 1; i < len(s); i++ {
		if c := s[i]; q != 0 {
			if c == q {
				q = 0
			}
		} else if c == '"' || c == '\'' {
			q = c
		} else if c == '>' {
			s = s[:i]
			break
		}
	}
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
