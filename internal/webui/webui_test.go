package webui

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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

// get asks the page as device dev (a --device device of another user), with
// the cookie when it is not empty.
func get(u *UI, dev, path, cookieValue string) *http.Response {
	return ask(u, dev, false, path, cookieValue)
}

// ask is get, as one of the user's own devices when all.
func ask(u *UI, dev string, all bool, path, cookieValue string) *http.Response {
	r := httptest.NewRequest("GET", path, nil)
	if cookieValue != "" {
		r.AddCookie(&http.Cookie{Name: cookie, Value: cookieValue})
	}
	w := httptest.NewRecorder()
	u.Serve(w, r, dev, all)
	return w.Result()
}

func body(r *http.Response) string { b, _ := io.ReadAll(r.Body); return string(b) }

const testToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func TestToken(t *testing.T) {
	u := New(store(t), testToken, nil)
	if r := get(u, "devA", "/", ""); r.StatusCode != 403 {
		t.Errorf("no cookie: %d", r.StatusCode)
	}
	if r := get(u, "devA", "/", "wrong"); r.StatusCode != 403 {
		t.Errorf("wrong cookie: %d", r.StatusCode)
	}
	if r := get(u, "devA", "/?k=wrong", ""); r.StatusCode != 403 {
		t.Errorf("wrong link: %d", r.StatusCode)
	}
	r := get(u, "devA", "/?k="+testToken, "")
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/" {
		t.Fatalf("link: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	var c *http.Cookie
	for _, x := range r.Cookies() {
		if x.Name == cookie {
			c = x
		}
	}
	if c == nil || c.Value != testToken || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 400*24*3600 {
		t.Fatalf("cookie: %+v", c)
	}
	if r := get(u, "devA", "/", c.Value); r.StatusCode != 200 {
		t.Errorf("with the cookie: %d", r.StatusCode)
	}
}

func TestPageEscapesAndHeaders(t *testing.T) {
	u := New(store(t), testToken, func(string, bool) []string { return []string{"<b>step</b>"} })
	for _, path := range []string{"/", "/flow?id=fa"} {
		r := get(u, "devA", path, testToken)
		page := body(r)
		if r.StatusCode != 200 {
			t.Fatalf("%s: %d", path, r.StatusCode)
		}
		for _, raw := range []string{"<script>", "<img", "<b>step"} {
			if strings.Contains(page, raw) {
				t.Errorf("%s: %q not escaped", path, raw)
			}
		}
		if csp := r.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self';") || strings.Contains(csp, "unsafe") {
			t.Errorf("%s: CSP %q", path, csp)
		}
		if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: headers %v", path, r.Header)
		}
	}
	if page := body(get(u, "devA", "/flow?id=fa", testToken)); !strings.Contains(page, "&lt;script&gt;") || !strings.Contains(page, "&#34;html&#34;: ") {
		t.Errorf("detail: headers or indented body missing:\n%s", page)
	}
}

// A device sees only its own flows: not in the list, not by ID.
func TestOwnFlowsOnly(t *testing.T) {
	u := New(store(t), testToken, nil)
	list := body(get(u, "devA", "/", testToken))
	if !strings.Contains(list, "api.example.com") || strings.Contains(list, "other.example.com") {
		t.Errorf("devA's list:\n%s", list)
	}
	if r := get(u, "devA", "/flow?id=fb", testToken); r.StatusCode != 404 {
		t.Errorf("devB's flow from devA: %d", r.StatusCode)
	}
	if r := get(u, "devB", "/flow?id=fb", testToken); r.StatusCode != 200 {
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
	u := New(st, testToken, func(id string, _ bool) []string { asked = id; return []string{"approve the exit node"} })
	page := body(get(u, "devB", "/", testToken))
	if asked != "devB" || !strings.Contains(page, "approve the exit node") {
		t.Errorf("steps asked for %q:\n%s", asked, page)
	}
	if !strings.Contains(page, " 1 flows") {
		t.Errorf("devB's count:\n%s", page)
	}
	if list := body(get(u, "devA", "/", testToken)); strings.Contains(list, "other.example.com") {
		t.Errorf("devB, named devA, in devA's list:\n%s", list)
	}
	if !strings.Contains(page, `http-equiv="refresh" content="1"`) || !strings.Contains(page, "telephone=no") {
		t.Errorf("refresh or format detection:\n%s", page)
	}
}

// Records kept unmasked (--no-redact) say so on the page.
func TestUnmaskedSaid(t *testing.T) {
	st := store(t)
	u := New(st, testToken, nil)
	if page := body(get(u, "devA", "/", testToken)); strings.Contains(page, "not masked") {
		t.Errorf("masked, said unmasked:\n%s", page)
	}
	st.SetScope(capture.HostRules{All: true}, false)
	if page := body(get(u, "devA", "/", testToken)); !strings.Contains(page, "not masked (--no-redact)") {
		t.Errorf("unmasked, not said:\n%s", page)
	}
}

// /flows.json is the list's data, for app.js: this device's flows only, and
// only with the cookie. app.js puts text in as text.
func TestFlowsJSON(t *testing.T) {
	u := New(store(t), testToken, func(string, bool) []string { return []string{"approve"} })
	r := get(u, "devB", "/flows.json", testToken)
	var d struct {
		Line  string
		Steps []string
		Rows  []row
	}
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil || r.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%v, %s", err, r.Header.Get("Content-Type"))
	}
	if len(d.Rows) != 1 || d.Rows[0].ID != "fb" || d.Rows[0].Text != "POST /b" || d.Rows[0].S != "…" || d.Line != "mitmproxy starting · 1 flows" || len(d.Steps) != 1 {
		t.Errorf("devB's data: %+v", d)
	}
	if r := get(u, "devB", "/flows.json", ""); r.StatusCode != http.StatusForbidden {
		t.Errorf("without the cookie: %d", r.StatusCode)
	}
	js := get(u, "devB", "/app.js", testToken)
	src := body(js)
	if !strings.HasPrefix(js.Header.Get("Content-Type"), "text/javascript") {
		t.Errorf("app.js type %q", js.Header.Get("Content-Type"))
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function("} {
		if strings.Contains(src, bad) {
			t.Errorf("app.js uses %s", bad)
		}
	}
	if page := body(get(u, "devB", "/?pause=1", testToken)); strings.Contains(page, "app.js") || strings.Contains(page, "refresh") {
		t.Errorf("paused, still following:\n%s", page)
	}
}

// app.js run in node over a stand-in DOM: rows come from /flows.json with the
// page's filters, a site's markup stays text, and it asks again.
func TestAppJS(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node")
	}
	harness := `
const els = {};
function mk(tag) {
  return { tag, className: "", textContent: "", href: "", children: [],
    appendChild(c) { this.children.push(c); return c; },
    replaceChildren(...c) { this.children = c; } };
}
for (const id of ["line", "steps", "rows"]) els[id] = mk("div");
globalThis.document = { createElement: mk, getElementById: (id) => els[id],
  createTextNode: (t) => ({ tag: "#text", textContent: t, children: [] }) };
globalThis.location = { search: "?host=api.example.com" };
const asked = [];
let reloaded = 0;
globalThis.location.reload = () => { reloaded++; };
const answers = [
  () => Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve(JSON.stringify({
    line: "mitmproxy ready · 1 flows", steps: ["approve"], empty: "No flows yet.",
    rows: [{ id: "a&b", class: "ok", s: "200", text: "GET /<img src=x onerror=alert(1)>", time: "10:00:00", host: "api.example.com", ms: 12 }] })) }),
  () => Promise.reject(new Error("down")),
  () => Promise.resolve({ ok: false, status: 403 }),
];
globalThis.fetch = (url) => { asked.push(url); return answers[asked.length - 1](); };
const timers = [];
globalThis.setTimeout = (f) => timers.push(f);
` + appJS + `
const settle = () => new Promise((r) => setImmediate(r));
(async () => {
  timers.shift()();
  await settle();
  const tr = els.rows.children[0], a = tr.children[1].children[0];
  const out = { asked, line: els.line.textContent, step: els.steps.children[0].textContent,
    cls: tr.className, status: tr.children[0].textContent, text: a.textContent, href: a.href,
    again: timers.length };
  timers.shift()(); // reqcove down
  await settle();
  out.down = els.line.textContent;
  timers.shift()(); // a new start: the link is old
  await settle();
  out.reloaded = reloaded;
  console.log(JSON.stringify(out));
})();
`
	f := filepath.Join(t.TempDir(), "app_test.js")
	if err := os.WriteFile(f, []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, f).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var got struct {
		Asked                                     []string
		Line, Step, Cls, Status, Text, Href, Down string
		Again, Reloaded                           int
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if len(got.Asked) != 3 || got.Asked[2] != "/flows.json?host=api.example.com" || got.Line != "mitmproxy ready · 1 flows" || got.Step != "next: approve" ||
		got.Cls != "ok" || got.Status != "200" || got.Text != "GET /<img src=x onerror=alert(1)>" || got.Href != "/flow?id=a%26b" || got.Again != 1 ||
		got.Down != "reqcove is not answering; trying again" || got.Reloaded != 1 {
		t.Errorf("app.js: %+v", got)
	}
}

// One of the user's own devices sees every device's flows, says whose, and
// opens any of them; the steps are asked for all.
func TestOwnDeviceSeesAll(t *testing.T) {
	st := store(t)
	st.SetDeviceNames(map[string]string{"devA": "iphone", "devB": "ipad"})
	var forAll bool
	u := New(st, testToken, func(_ string, all bool) []string { forAll = all; return nil })
	page := body(ask(u, "macbook", true, "/", testToken))
	if !strings.Contains(page, "api.example.com") || !strings.Contains(page, "other.example.com") || !strings.Contains(page, " · iphone") || !strings.Contains(page, " 2 flows") || !forAll {
		t.Errorf("own device's list (steps for all: %v):\n%s", forAll, page)
	}
	if r := ask(u, "macbook", true, "/flow?id=fa", testToken); r.StatusCode != 200 {
		t.Errorf("another device's flow: %d", r.StatusCode)
	}
	var d struct{ Rows []row }
	json.NewDecoder(ask(u, "macbook", true, "/flows.json", testToken).Body).Decode(&d)
	if len(d.Rows) != 2 || d.Rows[0].Device == "" {
		t.Errorf("own device's data: %+v", d)
	}
	if page := body(get(u, "devB", "/", testToken)); strings.Contains(page, "api.example.com") || strings.Contains(page, " · ipad") {
		t.Errorf("a --device device of another user sees more than its own:\n%s", page)
	}
}
