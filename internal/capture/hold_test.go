package capture

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestHTTP2EmptyDataEnd (REQCOVE_E2E=1): an HTTP/2 GET without a length that
// a mock or map_local may answer, whose stream ends with an empty DATA frame
// rather than with its headers (Go's client, for a body of unknown length
// that is empty), is answered as a bodyless one; one with a single body byte
// still gets the 502 (it got the 502 too until this fix, as soon as its
// headers came).
func TestHTTP2EmptyDataEnd(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var reached atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		fmt.Fprintf(w, "origin %s", r.URL.Path)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "origin.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	os.Mkdir(filepath.Join(dir, "files"), 0o700)
	os.WriteFile(filepath.Join(dir, "files", "a.json"), []byte(`{"local":true}`), 0o600)
	rules := filepath.Join(dir, "rules.yaml")
	os.WriteFile(rules, []byte(fmt.Sprintf(`mock:
  - match: {url: "%[1]s/mocked"}
    body: mocked
  - match: {url: "%[1]s/graphql", operation: Feed}
    body: feed
map_local:
  - "|//%[2]s/local/|files"
`, srv.URL, srv.Listener.Addr().String())), 0o600)
	up := startUpstream(t) // its CA setting is how mitmproxy trusts the test server
	defer up.ln.Close()
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.Upstream, c.UpstreamCA, c.Rules = up.ln.Addr().String(), caFile, rules })
	if err != nil {
		t.Fatal(err)
	}
	tr := h.client("dev").Transport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = true
	h2 := &http.Client{Transport: tr, Timeout: time.Minute}
	get := func(path string, body io.Reader) (int, string) {
		t.Helper()
		rctx, rcancel := context.WithTimeout(ctx, 20*time.Second)
		defer rcancel()
		req, _ := http.NewRequestWithContext(rctx, "GET", srv.URL+path, body)
		req.ContentLength = -1 // HEADERS without END_STREAM, then DATA frames
		resp, err := h2.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.ProtoMajor != 2 {
			t.Errorf("%s: HTTP/%d", path, resp.ProtoMajor)
		}
		return resp.StatusCode, string(b)
	}
	for _, c := range []struct{ path, want string }{{"/mocked", "mocked"}, {"/local/a.json", `{"local":true}`}} {
		if st, b := get(c.path, emptyBody{}); st != 200 || b != c.want {
			t.Errorf("%s, ended with an empty DATA frame: %d %.200q, want %q", c.path, st, b, c.want)
		}
		if v := h.doneFlow(c.path, false); v.State != "done" || v.Status != 200 || v.Mocked != (c.path == "/mocked") {
			t.Errorf("%s, recorded: %s %d mocked=%v", c.path, v.State, v.Status, v.Mocked)
		}
		if st, b := get(c.path+"?byte=1", strings.NewReader("x")); st != 502 || !strings.Contains(b, "not held in memory") {
			t.Errorf("%s, one body byte: %d %.200q, want a 502", c.path, st, b)
		}
	}
	if n := reached.Load(); n != 0 {
		t.Errorf("the origin got %d requests", n)
	}
	// Held (a mock's method and URL match), then not answered: it names no operation.
	if st, b := get("/graphql", emptyBody{}); st != 200 || b != "origin /graphql" || reached.Load() != 1 {
		t.Errorf("held, then sent on: %d %q (the origin got %d)", st, b, reached.Load())
	}
}

// emptyBody is a request body of unknown length that turns out empty (not a
// strings.Reader: NewRequest would make that NoBody, sent with its headers).
type emptyBody struct{}

func (emptyBody) Read([]byte) (int, error) { return 0, io.EOF }
