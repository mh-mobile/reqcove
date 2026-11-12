package capture

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func mpBody(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--XyZ\r\n" + p + "\r\n")
	}
	b.WriteString("--XyZ--\r\n")
	return b.String()
}

// TestMultipart: each part masked, files by size, cut anywhere.
func TestMultipart(t *testing.T) {
	S := fuzzSecret
	body := mpBody(
		"Content-Disposition: form-data; name=\"user\"\r\n\r\nalice",
		"Content-Disposition: form-data; name=\"password\"\r\n\r\n"+S,
		"Content-Disposition: form-data; name=\"meta\"\r\nContent-Type: application/json\r\n\r\n{\"device\":\"x\",\"access_token\":\""+S+"\"}",
		"Content-Disposition: form-data; name=\"notes\"; filename=\"notes.txt\"\r\nContent-Type: text/plain\r\n\r\n"+S+" in a file",
		"Content-Disposition: form-data; name=\"avatar\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n"+S,
		"Content-Disposition: form-data; name=\"x\"\r\nX-Api-Key: "+S+"\r\n\r\nplain",
	)
	got := string(renderMultipart([]byte("pre "+S+"\r\n"+body), "XyZ", true, false))
	if leak(got, S) != "" {
		t.Errorf("a secret shown:\n%s", got)
	}
	for _, want := range []string{"\r\n\r\nalice\r\n", `"device":"x"`, "[file: 24 bytes]", "[file: 22 bytes]", "[preamble: ", "--XyZ--", "name=\"avatar\"; filename=\"a.png\""} {
		if !strings.Contains(got, want) {
			t.Errorf("%q missing:\n%s", want, got)
		}
	}
	// Cut anywhere from the password part on: no 5 characters of it.
	at := strings.Index(body, "name=\"password\"")
	for cut := at; cut <= len(body); cut++ {
		if got := string(renderMultipart([]byte(body[:cut]), "XyZ", true, true)); leak(got, S[:min(len(S), max(0, cut-at-len("name=\"password\"\r\n\r\n")))]) != "" && cut-at > 30 {
			t.Errorf("cut at %d:\n%s", cut, got)
			break
		}
	}
	// Through the store: handed out (view), searched as rendered.
	s := NewStore(10, 1<<20)
	s.Apply([]byte(`{"v":2,"ev":"request","id":"m","method":"POST","url":"https://up.example/u","host":"up.example","path":"/u","headers":[["Content-Type","multipart/form-data; boundary=XyZ"]]}`))
	s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"body","id":"m","dir":"request","decoded":true,"final":true,"size":%d,"head":%q}`, len(body), base64.StdEncoding.EncodeToString([]byte(body)))))
	v, _ := s.Get("m", true)
	if v.ReqBody.View == "" || !strings.Contains(v.ReqBodyText, "alice") || leak(v.ReqBodyText, S) != "" {
		t.Errorf("stored: view %q text %q", v.ReqBody.View, v.ReqBodyText)
	}
	if rows, _ := s.List(Filter{Query: S[:6], QueryBodies: true, Limit: 5}); len(rows) != 0 {
		t.Errorf("a secret found by search")
	}
	// Bounds: at most 256 parts; a huge part; no boundary at all.
	many := strings.Repeat("--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n", 2000)
	start := time.Now()
	if got := string(renderMultipart([]byte(many), "XyZ", true, true)); !strings.Contains(got, "[more parts not read") || time.Since(start) > 100*time.Millisecond {
		t.Errorf("many parts: %v %q", time.Since(start), got[len(got)-80:])
	}
	if got := string(renderMultipart([]byte("no boundary here "+S), "XyZ", true, false)); leak(got, S) != "" {
		t.Errorf("no boundary: %q", got)
	}
	if _, ok := isMultipartForm("multipart/mixed; boundary=XyZ"); ok {
		t.Errorf("multipart/mixed read as a form")
	}
}

// TestMultipartE2E (REQCOVE_E2E=1): an upload through mitmproxy, written by
// Go's multipart writer: fields masked, the file by size.
func TestMultipartE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body) }))
	defer srv.Close()
	h := startHarness(t, ctx, []string{"127.0.0.1"})
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("user", "alice")
	mw.WriteField("password", "MPe2eSecret01")
	fw, _ := mw.CreateFormFile("avatar", "a.jpg")
	fw.Write(bytes.Repeat([]byte{0xff, 0xd8, 0x00}, 1000))
	mw.Close()
	resp, err := h.client("mp-device").Post(srv.URL+"/upload", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var v FlowView
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if f, ok := h.findFlow("/upload", true); ok && f.ReqBody.Final {
			v = f
			break
		}
	}
	if strings.Contains(v.ReqBodyText, "MPe2eSecret01") || !strings.Contains(v.ReqBodyText, "alice") || !strings.Contains(v.ReqBodyText, "[file: 3000 bytes]") || v.ReqBody.View == "" {
		t.Errorf("upload: view %q\n%s", v.ReqBody.View, v.ReqBodyText)
	}
}
