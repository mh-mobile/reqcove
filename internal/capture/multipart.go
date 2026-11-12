package capture

import (
	"bytes"
	"fmt"
	"mime"
	"strings"
	"unicode/utf8"
)

// multipart/form-data (uploads, forms with files): reqcove hands out the body
// with each part masked, never a file's bytes. A part whose name is secret is
// masked whole; a text part (no filename, a text or JSON type) is masked as a
// body is; a file part, and any part that is not text, keeps its headers and
// its size only. At most multipartMaxParts parts are read.
const multipartMaxParts = 256

// isMultipartForm returns the boundary of a multipart/form-data body.
func isMultipartForm(ct string) (boundary string, ok bool) {
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || mt != "multipart/form-data" || params["boundary"] == "" || len(params["boundary"]) > 70 {
		return "", false
	}
	return params["boundary"], true
}

// renderMultipart masks a multipart/form-data head part by part; cut: the
// head ends before the body does.
func renderMultipart(head []byte, boundary string, request, cut bool) []byte {
	delim := []byte("--" + boundary)
	first := mpDelimiter(head, delim, 0, true)
	if first < 0 {
		return []byte("(multipart: no part found: not shown)\n")
	}
	var b bytes.Buffer
	if first > 0 { // a preamble: clients send none, servers ignore it
		b.WriteString(fmt.Sprintf("[preamble: %d bytes, not shown]\r\n", first))
	}
	rest := head[first:]
	for n := 0; len(rest) > 0; n++ {
		if n == multipartMaxParts {
			b.WriteString(fmt.Sprintf("\r\n[more parts not read: %d bytes]", len(rest)))
			break
		}
		// rest starts with the delimiter
		rest = rest[len(delim):]
		if bytes.HasPrefix(rest, []byte("--")) { // the closing delimiter; the epilogue after it is not shown
			b.Write(delim)
			b.WriteString("--")
			break
		}
		b.Write(delim)
		end := mpDelimiter(rest, delim, 0, false)
		part := rest
		if end >= 0 {
			part, rest = rest[:end], rest[end+2:]
		} else {
			rest = nil
		}
		b.Write(maskPart(part, request, end < 0 && cut))
		if end >= 0 {
			b.WriteString("\r\n")
		}
	}
	return b.Bytes()
}

// mpDelimiter finds the next delimiter line in s from i: at the start (first)
// or after CR LF, followed by "--", by optional spaces and CR LF, or by the
// head's end. It returns where its CR LF begins (or the delimiter, at the
// start), -1 if none; a longer line that only starts with it is content.
func mpDelimiter(s, delim []byte, i int, first bool) int {
	if first && bytes.HasPrefix(s, delim) && mpDelimEnd(s[len(delim):]) {
		return 0
	}
	sep := append([]byte("\r\n"), delim...)
	for {
		k := bytes.Index(s[i:], sep)
		if k < 0 {
			return -1
		}
		at := i + k
		if mpDelimEnd(s[at+len(sep):]) {
			if first {
				return at + 2
			}
			return at
		}
		i = at + 2
	}
}

func mpDelimEnd(after []byte) bool {
	t := bytes.TrimLeft(after, " \t")
	return len(t) == 0 || bytes.HasPrefix(t, []byte("--")) || bytes.HasPrefix(t, []byte("\r\n")) || len(t) == 1 && t[0] == '\r'
}

// maskPart masks one part: its line end and headers, then its content.
func maskPart(part []byte, request, cut bool) []byte {
	sep := bytes.Index(part, []byte("\r\n\r\n"))
	if sep < 0 { // its headers cut by the head's end
		return []byte(fmt.Sprintf("\r\n[part headers cut: %d bytes]", len(part)))
	}
	hdr, content := string(part[:sep]), part[sep+4:]
	if strings.Contains(strings.ReplaceAll(hdr, "\r\n", ""), "\n") || strings.Contains(strings.ReplaceAll(hdr, "\r\n", ""), "\r") {
		return []byte(fmt.Sprintf("\r\n[part: %d bytes, headers not read]", len(part))) // LF-only lines: where its headers end is not known
	}
	var name, filename, ctype, cte string
	var lines []string
	dispositions, unread, redacted := 0, false, false
	for _, l := range strings.Split(strings.TrimPrefix(hdr, "\r\n"), "\r\n") {
		if strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") { // folded: the header before it goes on
			if redacted {
				continue
			}
			lines = append(lines, maskTokens(maskURLs(l)))
			continue
		}
		k, v, _ := strings.Cut(l, ":")
		key := strings.ToLower(strings.TrimSpace(k))
		redacted = false
		switch key {
		case "content-disposition":
			dispositions++
			if _, p, err := mime.ParseMediaType(strings.TrimSpace(v)); err == nil {
				name, filename = p["name"], p["filename"]
			} else {
				unread = true
			}
		case "content-type":
			ctype = strings.TrimSpace(v)
		case "content-transfer-encoding":
			cte = strings.ToLower(strings.TrimSpace(v))
		}
		switch {
		case secretName(strings.TrimSpace(k)):
			l, redacted = k+": [redacted]", true
		case key == "cookie":
			l = k + ": " + maskCookies(strings.TrimSpace(v), "; ", false)
		}
		lines = append(lines, maskTokens(maskURLs(l)))
	}
	out := "\r\n" + strings.Join(lines, "\r\n") + "\r\n\r\n"
	textType := ctype == "" || strings.HasPrefix(strings.ToLower(ctype), "text/") || strings.Contains(strings.ToLower(ctype), "json")
	switch {
	case dispositions != 1 || unread: // its name and filename are not known: neither a field nor a file can be told
		return []byte(out + fmt.Sprintf("[part: %d bytes, its Content-Disposition not read]", len(content)))
	case secretKind(name, request): // a lone "code" in a request, as in a form
		return []byte(out + "[redacted]")
	case filename != "" || !textType:
		note := fmt.Sprintf("[file: %d bytes", len(content))
		if cut {
			note += ", cut"
		}
		return []byte(out + note + "]")
	case cte != "" && cte != "7bit" && cte != "8bit" && cte != "binary":
		return []byte(out + fmt.Sprintf("[encoded (%s): %d bytes]", cte, len(content)))
	case !utf8.Valid(trimCutRune(content)) || !strictText(trimCutRune(content)):
		return []byte(out + fmt.Sprintf("[not text: %d bytes]", len(content)))
	}
	return append([]byte(out), maskBody(content, ctype, request)...)
}
