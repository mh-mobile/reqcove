package webui

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

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
	if !strings.Contains(page, "/app.js") || strings.Contains(page, `http-equiv="refresh"`) || !strings.Contains(page, "telephone=no") {
		t.Errorf("script, no refresh (it would wipe the search field), format detection:\n%s", page)
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
	if page := body(get(u, "devB", "/?pause=1", testToken)); !strings.Contains(page, "/app.js") || strings.Contains(page, "refresh") || !strings.Contains(page, `aria-pressed="true"`) {
		t.Errorf("paused: the script stays (search), no refresh, the toggle says paused:\n%s", page)
	}
}

// app.js run in node over a stand-in DOM: rows come from /flows.json with the
// page's filters, a site's markup stays text; scrolled down, the list waits and
// says how many are new; a search rewrites the URL and asks again; paused, it
// does not ask at all.
func TestAppJS(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node")
	}
	run := func(search string) map[string]any {
		harness := `
const els = {};
function mk(tag) {
  return { tag, className: "", textContent: "", href: "", hidden: true, value: "", checked: false, children: [], handlers: {},
    appendChild(c) { this.children.push(c); return c; },
    replaceChildren(...c) { this.children = c; },
    addEventListener(ev, f) { this.handlers[ev] = f; },
    getAttribute(k) { return this[k]; } };
}
for (const id of ["line", "steps", "rows", "new", "q", "bodies"]) els[id] = mk("div");
globalThis.document = { createElement: mk, getElementById: (id) => els[id],
  querySelectorAll: () => els.rows.children.map((li) => li.children[0]).filter((a) => a && a.tag === "a") };
globalThis.window = { scrollY: 0, scrollTo() { window.scrollY = 0; } };
globalThis.location = { search: __SEARCH__, reload() { reloaded++; } };
let reloaded = 0;
const replaced = [];
globalThis.history = { replaceState: (a, b, u) => { replaced.push(u); location.search = u.slice(1); } };
const row = (id, s, text) => ({ id, class: "ok", s, text, time: "10:00:00", host: "api.example.com", ms: 12, where: "url" });
const ok = (rows) => () => Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve(JSON.stringify({
  line: "mitmproxy ready · 1 flows", steps: ["approve"], empty: "No flows yet.", rows })) });
const answers = [
  ok([row("a&b", "200", "GET /<img src=x onerror=alert(1)>")]),
  ok([row("c", "201", "POST /new"), row("a&b", "200", "GET /<img src=x onerror=alert(1)>")]),
  () => Promise.reject(new Error("down")),
  () => Promise.resolve({ ok: false, status: 403 }),
  ok([]),
  ok([]),
];
const asked = [];
globalThis.fetch = (url) => { asked.push(url); return answers[asked.length - 1](); };
const timers = [];
globalThis.setTimeout = (f) => { timers.push(f); return timers.length; };
globalThis.clearTimeout = () => {};
` + appJS + `
const settle = () => new Promise((r) => setImmediate(r));
const texts = () => els.rows.children.map((li) => li.children[0].children.map((c) => c.textContent).join("|"));
(async () => {
  const out = { startTimers: timers.length };
  if (!timers.length) { console.log(JSON.stringify(out)); return; }
  timers.shift()();
  await settle();
  const a = els.rows.children[0].children[0];
  Object.assign(out, { first: texts(), cls: a.className, href: a.href, step: els.steps.children[0].textContent });
  window.scrollY = 100; // scrolled down: the next answer waits
  timers.shift()();
  await settle();
  Object.assign(out, { heldRows: texts().length, pill: els.new.hidden ? "" : els.new.textContent });
  els.new.handlers.click({ preventDefault() {} });
  out.shown = texts();
  timers.shift()(); // reqcove down
  await settle();
  out.down = els.line.textContent;
  timers.shift()(); // a new start: the link is old
  await settle();
  out.reloaded = reloaded;
  els.q.value = "tok";
  els.q.handlers.input();
  timers.pop()(); // the search, after the pause in typing
  await settle();
  out.pollsAfterSearch = timers.length; // a search of URLs and headers: it asks again
  const before = timers.length;
  els.bodies.checked = true;
  els.bodies.handlers.change(); // bodies too: asked once, then no polling
  await settle();
  out.pollsAfterBodies = timers.length - before;
  Object.assign(out, { replaced, asked });
  console.log(JSON.stringify(out));
})();
`
		harness = strings.Replace(harness, "__SEARCH__", strconv.Quote(search), 1)
		f := filepath.Join(t.TempDir(), "app_test.js")
		if err := os.WriteFile(f, []byte(harness), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(node, f).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		var got map[string]any
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return got
	}
	got := run("?host=api.example.com")
	first, _ := got["first"].([]any)
	shown, _ := got["shown"].([]any)
	asked, _ := got["asked"].([]any)
	replaced, _ := got["replaced"].([]any)
	if len(first) != 1 || first[0] != "200|GET /<img src=x onerror=alert(1)>|10:00:00 · api.example.com · 12 ms · in url" || got["cls"] != "row ok" || got["href"] != "/flow?id=a%26b" || got["step"] != "next: approve" {
		t.Errorf("rows: %v", got)
	}
	if got["heldRows"] != float64(1) || got["pill"] != "1 new · show" || len(shown) != 2 {
		t.Errorf("scrolled down: held %v, pill %q, then %v", got["heldRows"], got["pill"], shown)
	}
	if got["down"] != "reqcove is not answering; trying again" || got["reloaded"] != float64(1) {
		t.Errorf("down %q, reloaded %v", got["down"], got["reloaded"])
	}
	if len(replaced) != 2 || replaced[0] != "/?host=api.example.com&q=tok" || len(asked) != 6 || asked[0] != "/flows.json?host=api.example.com" || asked[4] != "/flows.json?host=api.example.com&q=tok" || asked[5] != "/flows.json?host=api.example.com&q=tok&bodies=1" {
		t.Errorf("search: replaced %v, asked %v", replaced, asked)
	}
	if got["pollsAfterSearch"] == float64(0) || got["pollsAfterBodies"] != float64(0) {
		t.Errorf("polling: after a search %v timers, after bodies too %v more", got["pollsAfterSearch"], got["pollsAfterBodies"])
	}
	if got := run("?pause=1"); got["startTimers"] != float64(0) {
		t.Errorf("paused, it asks: %v", got)
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

// Search narrows the list and says where it matched; Clear goes on to the
// list since now, by this computer's clock, keeping the other filters; the
// chip that is on says so; the CSP lets the search form go to the page only.
func TestSearchClearChips(t *testing.T) {
	st := store(t)
	u := New(st, testToken, nil)
	page := body(ask(u, "mac", true, "/?q=other.example", testToken))
	if !strings.Contains(page, "POST /b") || strings.Contains(page, "GET /a") || !strings.Contains(page, " · in url") {
		t.Errorf("search:\n%s", page)
	}
	if page := body(ask(u, "mac", true, "/?q=nothing-like-this", testToken)); !strings.Contains(page, "No flows match.") {
		t.Errorf("no match:\n%s", page)
	}
	before := time.Now().Unix()
	r := ask(u, "mac", true, "/?status=4xx&clear=1", testToken)
	loc, _ := url.Parse(r.Header.Get("Location"))
	since, _ := strconv.ParseInt(loc.Query().Get("since"), 10, 64)
	if r.StatusCode != http.StatusSeeOther || loc.Query().Get("status") != "4xx" || loc.Query().Has("clear") || since < before || since > time.Now().Unix() {
		t.Errorf("clear: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	// The flows in store() started at 1 and 1.5 (unix seconds): since 2 hides both.
	if page := body(ask(u, "mac", true, "/?since=2", testToken)); strings.Contains(page, "GET /a") || !strings.Contains(page, "Show all") {
		t.Errorf("since:\n%s", page)
	}
	if page := body(ask(u, "mac", true, "/?status=4xx", testToken)); !strings.Contains(page, `href="/?status=4xx" aria-current="true">4xx`) {
		t.Errorf("the chip that is on:\n%s", page)
	}
	if csp := ask(u, "mac", true, "/", testToken).Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP %q", csp)
	}
}
