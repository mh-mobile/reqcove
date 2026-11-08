package webui

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
)

func apply(t *testing.T, st *capture.Store, m map[string]any) {
	t.Helper()
	m["v"] = 2 // the addon's wire version
	b, _ := json.Marshal(m)
	st.Apply(b)
}

// A store with one flow from device A (its headers and body carry markup a
// site could send) and one from device B.
func store(t *testing.T) *capture.Store {
	st := capture.NewStore(100, 1<<20)
	apply(t, st, map[string]any{"ev": "request", "id": "fa", "device": "devA", "host": "api.example.com", "url": "https://api.example.com/a", "method": "GET", "ts": 1.0})
	apply(t, st, map[string]any{"ev": "response", "id": "fa", "status": 200, "headers": [][2]string{{"X-Evil", `<script>alert("h")</script>`}, {"Content-Type", "application/json"}}})
	apply(t, st, map[string]any{"ev": "body", "id": "fa", "dir": "response", "decoded": true, "final": true, "size": 40,
		"head": base64.StdEncoding.EncodeToString([]byte(`{"html":"<img src=x onerror=alert(1)>"}`))})
	apply(t, st, map[string]any{"ev": "done", "id": "fa", "ts_end": 2.0})
	apply(t, st, map[string]any{"ev": "request", "id": "fb", "device": "devB", "host": "other.example.com", "url": "https://other.example.com/b", "method": "POST", "ts": 1.5})
	return st
}

// get asks the page as device dev, with the cookie when it is not empty.
func get(u *UI, dev, path, cookieValue string) *http.Response {
	r := httptest.NewRequest("GET", path, nil)
	if cookieValue != "" {
		r.AddCookie(&http.Cookie{Name: cookie, Value: cookieValue})
	}
	w := httptest.NewRecorder()
	u.Serve(w, r, dev)
	return w.Result()
}

func body(r *http.Response) string { b, _ := io.ReadAll(r.Body); return string(b) }

func TestToken(t *testing.T) {
	u := New(store(t), nil)
	if r := get(u, "devA", "/", ""); r.StatusCode != 403 {
		t.Errorf("no cookie: %d", r.StatusCode)
	}
	if r := get(u, "devA", "/", "wrong"); r.StatusCode != 403 {
		t.Errorf("wrong cookie: %d", r.StatusCode)
	}
	if r := get(u, "devA", "/?k=wrong", ""); r.StatusCode != 403 {
		t.Errorf("wrong link: %d", r.StatusCode)
	}
	r := get(u, "devA", "/?k="+u.Token(), "")
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/" {
		t.Fatalf("link: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	var c *http.Cookie
	for _, x := range r.Cookies() {
		if x.Name == cookie {
			c = x
		}
	}
	if c == nil || c.Value != u.Token() || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie: %+v", c)
	}
	if r := get(u, "devA", "/", c.Value); r.StatusCode != 200 {
		t.Errorf("with the cookie: %d", r.StatusCode)
	}
}

func TestPageEscapesAndHeaders(t *testing.T) {
	u := New(store(t), func(string) []string { return []string{"<b>step</b>"} })
	for _, path := range []string{"/", "/flow?id=fa"} {
		r := get(u, "devA", path, u.Token())
		page := body(r)
		if r.StatusCode != 200 {
			t.Fatalf("%s: %d", path, r.StatusCode)
		}
		for _, raw := range []string{"<script>", "<img", "<b>step"} {
			if strings.Contains(page, raw) {
				t.Errorf("%s: %q not escaped", path, raw)
			}
		}
		if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
			t.Errorf("%s: CSP %q", path, csp)
		}
		if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: headers %v", path, r.Header)
		}
	}
	if page := body(get(u, "devA", "/flow?id=fa", u.Token())); !strings.Contains(page, "&lt;script&gt;") || !strings.Contains(page, "&#34;html&#34;: ") {
		t.Errorf("detail: headers or indented body missing:\n%s", page)
	}
}

// A device sees only its own flows: not in the list, not by ID.
func TestOwnFlowsOnly(t *testing.T) {
	u := New(store(t), nil)
	list := body(get(u, "devA", "/", u.Token()))
	if !strings.Contains(list, "api.example.com") || strings.Contains(list, "other.example.com") {
		t.Errorf("devA's list:\n%s", list)
	}
	if r := get(u, "devA", "/flow?id=fb", u.Token()); r.StatusCode != 404 {
		t.Errorf("devB's flow from devA: %d", r.StatusCode)
	}
	if r := get(u, "devB", "/flow?id=fb", u.Token()); r.StatusCode != 200 {
		t.Errorf("devB's own flow: %d", r.StatusCode)
	}
}

// A body of deep nesting is not indented: json.Indent would build gigabytes
// before returning, whatever is kept of it.
func TestPrettyBounded(t *testing.T) {
	deep := strings.Repeat("[", 3000) + strings.Repeat("]", 3000)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got := pretty(deep)
	runtime.ReadMemStats(&after)
	if got != deep || after.TotalAlloc-before.TotalAlloc > 1<<20 {
		t.Errorf("deep JSON: %d bytes allocated, indented %v", after.TotalAlloc-before.TotalAlloc, got != deep)
	}
	if got := pretty(`{"s":"\"` + strings.Repeat("[", 40) + `"}`); !strings.Contains(got, "\n  ") {
		t.Errorf("brackets in a string count as nesting: %q", got)
	}
	if got := pretty(`{"a":1}`); got != "{\n  \"a\": 1\n}" {
		t.Errorf("small JSON: %q", got)
	}
}

// The header counts and the steps are this device's. A display name equal to
// another device's ID changes nothing. (Which steps: pageSteps in cmd/reqcove.)
func TestOwnCountsAndSteps(t *testing.T) {
	st := store(t)
	st.SetDeviceNames(map[string]string{"devA": "alice-phone", "devB": "devA"})
	var asked string
	u := New(st, func(id string) []string { asked = id; return []string{"approve the exit node"} })
	page := body(get(u, "devB", "/", u.Token()))
	if asked != "devB" || !strings.Contains(page, "approve the exit node") {
		t.Errorf("steps asked for %q:\n%s", asked, page)
	}
	if !strings.Contains(page, " 1 flows") {
		t.Errorf("devB's count:\n%s", page)
	}
	if list := body(get(u, "devA", "/", u.Token())); strings.Contains(list, "other.example.com") {
		t.Errorf("devB, named devA, in devA's list:\n%s", list)
	}
	if !strings.Contains(page, `http-equiv="refresh" content="1"`) || !strings.Contains(page, "telephone=no") {
		t.Errorf("refresh or format detection:\n%s", page)
	}
}

// Records kept unmasked (--no-redact) say so on the page.
func TestUnmaskedSaid(t *testing.T) {
	st := store(t)
	u := New(st, nil)
	if page := body(get(u, "devA", "/", u.Token())); strings.Contains(page, "not masked") {
		t.Errorf("masked, said unmasked:\n%s", page)
	}
	st.SetScope(capture.HostRules{All: true}, false)
	if page := body(get(u, "devA", "/", u.Token())); !strings.Contains(page, "not masked (--no-redact)") {
		t.Errorf("unmasked, not said:\n%s", page)
	}
}
