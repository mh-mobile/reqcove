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
	first := bytes.Index(head, delim)
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
		if bytes.HasPrefix(rest, []byte("--")) { // the closing delimiter
			b.Write(delim)
			b.WriteString("--")
			break
		}
		b.Write(delim)
		end := bytes.Index(rest, append([]byte("\r\n"), delim...))
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

// maskPart masks one part: its line end and headers, then its content.
func maskPart(part []byte, request, cut bool) []byte {
	sep := bytes.Index(part, []byte("\r\n\r\n"))
	if sep < 0 { // its headers cut by the head's end
		return []byte(fmt.Sprintf("\r\n[part headers cut: %d bytes]", len(part)))
	}
	hdr, content := string(part[:sep]), part[sep+4:]
	var name, filename, ctype string
	var lines []string
	for _, l := range strings.Split(strings.TrimPrefix(hdr, "\r\n"), "\r\n") {
		k, v, _ := strings.Cut(l, ":")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "content-disposition":
			if _, p, err := mime.ParseMediaType(strings.TrimSpace(v)); err == nil {
				name, filename = p["name"], p["filename"]
			}
		case "content-type":
			ctype = strings.TrimSpace(v)
		}
		if secretName(strings.TrimSpace(k)) {
			l = k + ": [redacted]"
		}
		lines = append(lines, maskTokens(maskURLs(l)))
	}
	out := "\r\n" + strings.Join(lines, "\r\n") + "\r\n\r\n"
	textType := ctype == "" || strings.HasPrefix(strings.ToLower(ctype), "text/") || strings.Contains(strings.ToLower(ctype), "json")
	switch {
	case secretKind(name, request): // a lone "code" in a request, as in a form
		return []byte(out + "[redacted]")
	case filename != "" || !textType:
		note := fmt.Sprintf("[file: %d bytes", len(content))
		if cut {
			note += ", cut"
		}
		return []byte(out + note + "]")
	case !utf8.Valid(trimCutRune(content)) || !strictText(trimCutRune(content)):
		return []byte(out + fmt.Sprintf("[not text: %d bytes]", len(content)))
	}
	return append([]byte(out), maskBody(content, ctype, request)...)
}
