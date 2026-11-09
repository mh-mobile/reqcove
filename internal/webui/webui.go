// Package webui is Reqcove's own read-only page, served on the tailnet node to
// the user's own devices, which see every device's flows, and to the other
// --device devices, which see their own (exitnode checks who asks); as the MCP
// tools return them, already masked. It is rendered on the
// server with html/template; its one script, app.js, refreshes the list as text
// only, so what remote sites wrote into headers and bodies stays text.
package webui

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// cookie holds the token: only the browser that opened the link with it (the
// QR code reqcove run prints) reads the page, not any app on the device.
const cookie = "reqcove"

type UI struct {
	store *capture.Store
	steps func(deviceID string, all bool) []string // the next steps for one device, or for all, as the status tool words them (no login URL)
	token string
}

// New serves the page with token, what the link to it carries
// (http://NODE/?k=TOKEN); run keeps it in the state directory.
func New(st *capture.Store, token string, steps func(deviceID string, all bool) []string) *UI {
	return &UI{store: st, steps: steps, token: token}
}

// Serve answers a GET from the device deviceID (its StableID). With all (one of
// the user's own devices) it shows every device's flows; else deviceID's only.
func (u *UI) Serve(w http.ResponseWriter, r *http.Request, deviceID string, all bool) {
	h := w.Header()
	// One script, /app.js, from here; nothing inline. It fetches /flows.json and
	// puts what sites wrote in as text only.
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	if k := r.URL.Query().Get("k"); k != "" {
		if !u.valid(k) {
			http.Error(w, "reqcove: this link's token was changed; open the link reqcove run prints now", http.StatusForbidden)
			return
		}
		// Kept 400 days (the token lasts until its file is deleted), so a device that
		// opened the link once opens the page after a restart too.
		http.SetCookie(w, &http.Cookie{Name: cookie, Value: k, Path: "/", MaxAge: 400 * 24 * 3600, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if c, err := r.Cookie(cookie); err != nil || !u.valid(c.Value) {
		http.Error(w, "reqcove: open the link reqcove run prints (its QR code) to see this page", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/":
		if r.URL.Query().Has("clear") {
			// Clear: from now on, by this computer's clock (the flows' times are its own).
			p := params(r.URL.Query())
			http.Redirect(w, r, p.with("clear", "").with("since", strconv.FormatFloat(float64(time.Now().UnixMilli())/1000, 'f', 3, 64)).String(), http.StatusSeeOther)
			return
		}
		render(w, listPage, u.view(r, deviceID, all))
	case "/flows.json":
		v := u.view(r, deviceID, all)
		h.Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"line": v["Line"], "steps": v["Steps"], "rows": v["Rows"], "empty": v["Empty"]})
	case "/flow":
		u.flow(w, r, deviceID, all)
	case "/style.css":
		h.Set("Content-Type", "text/css; charset=utf-8")
		w.Write([]byte(css))
	case "/app.js":
		h.Set("Content-Type", "text/javascript; charset=utf-8")
		w.Write([]byte(appJS))
	default:
		http.NotFound(w, r)
	}
}

func (u *UI) valid(k string) bool { return subtle.ConstantTimeCompare([]byte(k), []byte(u.token)) == 1 }

// row is one flow in the list, as the page and /flows.json show it.
type row struct {
	ID     string `json:"id"`
	Class  string `json:"class"`
	S      string `json:"s"`      // status, "err" or "…"
	Method string `json:"method"` // its class (m-get…) comes from methodClass
	MClass string `json:"mclass"`
	Text   string `json:"text"` // the path
	Slow   bool   `json:"slow,omitempty"`
	Time   string `json:"time"`
	Host   string `json:"host"`
	MS     int64  `json:"ms,omitempty"`
	Device string `json:"device,omitempty"` // whose, when the page shows every device's
	Where  string `json:"where,omitempty"`  // with a search: where it matched (url, request headers…)
}

// params are the list's filters as in its URL; with gives a link with one
// changed (an empty value drops it), keeping the others.
type params url.Values

func (p params) with(k, v string) params {
	n := url.Values{}
	for key, vs := range p {
		n[key] = slices.Clone(vs)
	}
	n.Del(k)
	if v != "" {
		n.Set(k, v)
	}
	return params(n)
}

// With is with for the templates: the link itself.
func (p params) With(k, v string) string { return p.with(k, v).String() }

func (p params) String() string {
	if e := url.Values(p).Encode(); e != "" {
		return "/?" + e
	}
	return "/"
}

// view is the list for deviceID: its own flows, counts and steps only; with
// all, every device's.
func (u *UI) view(r *http.Request, deviceID string, all bool) map[string]any {
	q := r.URL.Query()
	f := capture.Filter{Host: q.Get("host"), Query: q.Get("q"), QueryBodies: q.Get("bodies") != "", Limit: 50}
	if !all {
		f.Device = deviceID
	}
	if s := q.Get("status"); capture.ValidStatus(s) {
		f.Status = s
	}
	if since, err := strconv.ParseFloat(q.Get("since"), 64); err == nil && since > 0 {
		f.Since = since // to the millisecond: a flow started just before Clear is not left in
	}
	listed, _ := u.store.List(f)
	flows := listed[:0]
	for _, s := range listed {
		if all || s.Device == deviceID { // the filter also takes a display name; the page, the ID only
			flows = append(flows, s)
		}
	}
	// This device's counts and steps only, not the others' nor their names;
	// with all, everyone's.
	var me capture.DeviceInfo
	for _, d := range u.store.Devices() {
		if all || d.ID == deviceID {
			me.Flows += d.Flows
			me.TLSFailures += d.TLSFailures
		}
	}
	var steps []string
	if u.steps != nil {
		steps = u.steps(deviceID, all)
	}
	stats := u.store.Stats()
	line := fmt.Sprintf("mitmproxy %v · %d flows", stats["state"], me.Flows)
	if me.TLSFailures > 0 {
		line += fmt.Sprintf(" · %d TLS failures", me.TLSFailures)
	}
	rows := make([]row, 0, len(flows))
	for _, s := range flows {
		st := "…"
		if s.Status != 0 {
			st = strconv.Itoa(s.Status)
		} else if s.State == "error" {
			st = "err"
		}
		rw := row{ID: s.ID, Class: class(s.Status, s.State), S: st, Method: s.Method, MClass: methodClass(s.Method), Text: path(s.URL),
			Time: clock(s.Time), Host: s.Host, MS: s.DurationMS, Slow: s.DurationMS >= 1000,
			Where: strings.ReplaceAll(strings.Join(s.MatchedIn, ", "), "_", " ")}
		if all {
			rw.Device = s.DeviceName
			if rw.Device == "" {
				rw.Device = s.Device
			}
		}
		rows = append(rows, rw)
	}
	if steps == nil {
		steps = []string{}
	}
	empty := "No flows from this device yet."
	if all {
		empty = "No flows yet."
	}
	if f.Query != "" || f.Status != "" || f.Host != "" || f.Since != 0 {
		empty = "No flows match."
	}
	var statuses []chip
	for _, c := range []struct{ label, v string }{{"All", ""}, {"2xx", "2xx"}, {"3xx", "3xx"}, {"4xx", "4xx"}, {"5xx", "5xx"}, {"No answer", "none"}} {
		statuses = append(statuses, chip{c.label, params(q).With("status", c.v), f.Status == c.v})
	}
	return map[string]any{
		"Rows": rows, "Empty": empty, "Host": f.Host, "Status": f.Status, "Q": f.Query, "Bodies": f.QueryBodies,
		"Since": q.Get("since"), "Paused": q.Get("pause") != "", "P": params(q), "Statuses": statuses,
		"Unmasked": stats["redacting"] == false, "Line": line, "Steps": steps,
	}
}

// chip is a filter button: its link, and whether it is the one on.
type chip struct {
	Label, Href string
	On          bool
}

func (u *UI) flow(w http.ResponseWriter, r *http.Request, deviceID string, all bool) {
	v, err := u.store.Get(r.URL.Query().Get("id"), true)
	if err != nil || !all && v.Device != deviceID { // another device's flow is not there for this one
		http.NotFound(w, r)
		return
	}
	render(w, flowPage, map[string]any{"F": v, "ReqBody": pretty(v.ReqBodyText), "RespBody": pretty(v.RespBodyText)})
}

// pretty indents a JSON body; anything else is shown as it is. Deep nesting
// makes indenting grow with its square (a 60 KB head of "[[[…" took gigabytes
// in json.Indent, which builds all of it before returning), so a body nested
// deeper than maxDepth is shown as it is, checked before indenting.
func pretty(s string) string {
	t := strings.TrimSpace(s)
	if !(strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")) || depth(t) > maxDepth {
		return s
	}
	var b bytes.Buffer
	if json.Indent(&b, []byte(t), "", "  ") != nil {
		return s
	}
	return b.String()
}

const maxDepth = 32

// depth is how deep JSON nests, outside strings.
func depth(s string) int {
	d, most, inString := 0, 0, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case inString && c == '\\':
			i++
		case c == '"':
			inString = !inString
		case inString:
		case c == '{' || c == '[':
			d++
			most = max(most, d)
		case c == '}' || c == ']':
			d--
		}
	}
	return most
}

func render(w http.ResponseWriter, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		http.Error(w, "reqcove: "+err.Error(), http.StatusInternalServerError)
	}
}

var funcs = template.FuncMap{"class": class, "mclass": methodClass}

// methodClass colours methods: reading (GET, HEAD), writing (POST), changing
// (PUT, PATCH), removing (DELETE), and the rest.
func methodClass(m string) string {
	switch m {
	case "GET", "HEAD":
		return "m-get"
	case "POST":
		return "m-post"
	case "PUT", "PATCH":
		return "m-put"
	case "DELETE":
		return "m-del"
	}
	return "m-other"
}

func clock(s string) string {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.Format("15:04:05")
	}
	return s
}

// path is a URL without its scheme and host, which the row shows apart.
func path(u string) string {
	if _, rest, ok := strings.Cut(u, "://"); ok {
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			return rest[i:]
		}
		return "/"
	}
	return u
}

func class(status int, state string) string {
	switch {
	case state == "error" || status >= 500:
		return "bad"
	case status >= 400:
		return "warn"
	case status == 0:
		return "open"
	case status >= 300:
		return "redir"
	}
	return "ok"
}

const head = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="format-detection" content="telephone=no">
<link rel="stylesheet" href="/style.css"><title>Reqcove</title>`

// The list follows new flows with /app.js, without reloading (a reload a second
// made Safari's address bar flicker). Without scripts, it is a page to reload.
var listPage = template.Must(template.New("list").Funcs(funcs).Parse(head + `
<script src="/app.js" defer></script></head><body>
<header>
<div class="top"><b>Reqcove</b>{{if .Unmasked}} <b class="badge bad">not masked (--no-redact)</b>{{end}} <span id="line" class="muted">{{.Line}}</span></div>
<form class="search" action="/" method="get" role="search">
<input id="q" type="search" name="q" value="{{.Q}}" placeholder="Search URLs and headers" aria-label="Search URLs and headers" enterkeyhint="search" autocapitalize="off" autocorrect="off" spellcheck="false">
<label class="check"><input id="bodies" type="checkbox" name="bodies" value="1"{{if .Bodies}} checked{{end}}> also search bodies (pauses live)</label>
{{with .Host}}<input type="hidden" name="host" value="{{.}}">{{end}}{{with .Status}}<input type="hidden" name="status" value="{{.}}">{{end}}{{with .Since}}<input type="hidden" name="since" value="{{.}}">{{end}}{{if .Paused}}<input type="hidden" name="pause" value="1">{{end}}
</form>
<nav class="chips" aria-label="Filters and view">
{{range .Statuses}}<a class="chip{{if .On}} on{{end}}" href="{{.Href}}"{{if .On}} aria-current="true"{{end}}>{{.Label}}</a>{{end}}
{{with .Host}}<a class="chip on" href="{{$.P.With "host" ""}}" aria-label="Stop showing only {{.}}">{{.}} ×</a>{{end}}
<span class="sep"></span>
{{if .Paused}}<a class="chip" role="button" href="{{.P.With "pause" ""}}" aria-pressed="true">Paused</a>{{else}}<a class="chip on" role="button" href="{{.P.With "pause" "1"}}" aria-pressed="false">Live</a>{{end}}
<a class="chip" href="{{.P.With "clear" "1"}}">Clear</a>{{if .Since}}<a class="chip" href="{{.P.With "since" ""}}">Show all</a>{{end}}
<noscript><a class="chip" href="{{.P}}">Reload</a></noscript>
<a id="new" class="chip on" href="#" hidden aria-live="polite"></a>
</nav></header>
<div id="steps">{{range .Steps}}<p class="step">next: {{.}}</p>{{end}}</div>
<ul id="rows">{{range .Rows}}<li><a class="row {{.Class}}" href="/flow?id={{.ID}}"><span class="s">{{.S}}</span> <span class="t"><b class="{{.MClass}}">{{.Method}}</b> {{.Text}}</span>
<span class="meta">{{.Time}} · {{.Host}}{{if .MS}} · <span{{if .Slow}} class="slow"{{end}}>{{.MS}} ms</span>{{end}}{{with .Device}} · {{.}}{{end}}{{with .Where}} · in {{.}}{{end}}</span></a></li>
{{else}}<li class="empty muted">{{.Empty}}</li>{{end}}</ul></body></html>`))

// appJS asks /flows.json (with the page's own filters) and puts the rows in
// with textContent and DOM calls only: never markup from a site. It does not
// poll while paused, nor for a search of bodies (the store is walked under its
// lock); it waits while the list is scrolled down, saying how many are new;
// the search field filters as you type.
const appJS = `"use strict";
(function () {
  var shown = "", pending = null, gen = 0, timer = 0;
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function row(f) {
    var li = el("li"), a = el("a", "row " + f.class);
    a.href = "/flow?id=" + encodeURIComponent(f.id);
    a.appendChild(el("span", "s", f.s + " "));
    var t = el("span", "t");
    t.appendChild(el("b", f.mclass, f.method));
    t.appendChild(document.createTextNode(" " + f.text));
    a.appendChild(t);
    var meta = el("span", "meta", f.time + " · " + f.host);
    if (f.ms) {
      meta.appendChild(document.createTextNode(" · "));
      meta.appendChild(el("span", f.slow ? "slow" : "", f.ms + " ms"));
    }
    var rest = "";
    if (f.device) rest += " · " + f.device;
    if (f.where) rest += " · in " + f.where;
    if (rest) meta.appendChild(document.createTextNode(rest));
    a.appendChild(meta);
    li.appendChild(a);
    return li;
  }
  function params() { return new URLSearchParams(location.search); }
  function rowsKey(d) { return JSON.stringify(d.rows); }
  function showRows(d) {
    var lis = d.rows.map(row);
    if (!lis.length) lis = [el("li", "empty muted", d.empty)];
    var rows = document.getElementById("rows");
    rows.replaceChildren.apply(rows, lis);
    shown = rowsKey(d);
    pending = null;
    document.getElementById("new").hidden = true;
  }
  // The line and the steps follow at once; the rows wait while the list is
  // scrolled down (not to move it under the finger).
  function apply(d) {
    document.getElementById("line").textContent = d.line;
    var steps = document.getElementById("steps");
    steps.replaceChildren.apply(steps, d.steps.map(function (s) { return el("p", "step", "next: " + s); }));
    if (rowsKey(d) === shown) { pending = null; document.getElementById("new").hidden = true; return; }
    if (shown === "" || window.scrollY <= 40) { showRows(d); return; } // the first answer always shows
    var seen = {};
    Array.prototype.forEach.call(document.querySelectorAll("#rows a.row"), function (a) { seen[a.getAttribute("href")] = true; });
    var fresh = d.rows.filter(function (f) { return !seen["/flow?id=" + encodeURIComponent(f.id)]; }).length;
    pending = d;
    var n = document.getElementById("new");
    n.textContent = fresh ? fresh + " new · show" : "updated · show";
    n.hidden = false;
  }
  // One request at a time: a newer one (a search) makes the older one's answer
  // and its next poll count for nothing.
  function tick() {
    clearTimeout(timer);
    var my = ++gen;
    fetch("/flows.json?" + params().toString(), {credentials: "same-origin", cache: "no-store"})
      .then(function (r) {
        // A new start of reqcove run: the link is old. Reloading shows the page saying so.
        if (r.status === 403) { location.reload(); return Promise.reject(r.status); }
        return r.ok ? r.json() : Promise.reject(r.status);
      })
      .then(function (d) { if (my === gen) apply(d); })
      .catch(function () {
        if (my === gen) document.getElementById("line").textContent = "reqcove is not answering; trying again";
      })
      .then(function () {
        var q = params();
        if (my !== gen || q.get("pause") || q.get("bodies")) return; // paused, or a search of bodies: no polling
        timer = setTimeout(tick, q.get("q") ? 2000 : 1000);
      });
  }
  document.getElementById("new").addEventListener("click", function (e) {
    e.preventDefault();
    window.scrollTo(0, 0);
    if (pending) showRows(pending);
  });
  window.addEventListener("scroll", function () { if (pending && window.scrollY <= 40) showRows(pending); });
  var q = document.getElementById("q"), bodies = document.getElementById("bodies"), typing = 0;
  // The filter links keep the search typed since the page was drawn.
  function relink(p) {
    Array.prototype.forEach.call(document.querySelectorAll("nav a.chip"), function (a) {
      var href = a.getAttribute("href");
      if (!href || href.charAt(0) !== "/") return;
      var parts = href.split("?"), lp = new URLSearchParams(parts[1] || "");
      ["q", "bodies"].forEach(function (k) { if (p.get(k)) lp.set(k, p.get(k)); else lp.delete(k); });
      a.href = lp.toString() ? parts[0] + "?" + lp.toString() : parts[0];
    });
  }
  function search() {
    var p = params();
    if (q.value) p.set("q", q.value); else p.delete("q");
    if (bodies.checked) p.set("bodies", "1"); else p.delete("bodies");
    history.replaceState(null, "", p.toString() ? "/?" + p.toString() : "/");
    relink(p);
    window.scrollTo(0, 0); // at the top, the results come in at once
    tick();
  }
  q.addEventListener("input", function () { clearTimeout(typing); typing = setTimeout(search, 400); });
  bodies.addEventListener("change", search);
  if (!params().get("pause") && !params().get("bodies")) timer = setTimeout(tick, 1000);
})();
`

var flowPage = template.Must(template.New("flow").Funcs(funcs).Parse(head + `</head><body>
<header><a class="chip" href="/">← flows</a> <a class="chip" href="/?host={{.F.Host}}">only {{.F.Host}}</a></header>
<h1><b class="{{mclass .F.Method}}">{{.F.Method}}</b> <span class="badge {{class .F.Status .F.State}}">{{if .F.Status}}{{.F.Status}} {{.F.Reason}}{{else}}{{.F.State}}{{end}}</span></h1>
<p class="url">{{.F.URL}}</p>
{{with .F.MappedURL}}<p class="muted">sent to {{.}}</p>{{end}}
{{with .F.Error}}<p class="bad">{{.}}</p>{{end}}
{{range .F.Rewrites}}<p class="muted">rule: {{.}}</p>{{end}}
{{range .F.Notes}}<p class="muted">{{.}}</p>{{end}}
<details open><summary>Request headers</summary><dl>{{range .F.ReqHeaders}}<dt>{{index . 0}}</dt><dd>{{index . 1}}</dd>{{end}}</dl></details>
<details><summary>Request body</summary>{{with .F.ReqBodyEnc}}<p class="muted">{{.}}</p>{{end}}<pre>{{.ReqBody}}</pre></details>
<details open><summary>Response headers</summary><dl>{{range .F.RespHeaders}}<dt>{{index . 0}}</dt><dd>{{index . 1}}</dd>{{end}}</dl></details>
<details open><summary>Response body</summary>{{with .F.RespBodyEnc}}<p class="muted">{{.}}</p>{{end}}<pre>{{.RespBody}}</pre></details>
</body></html>`))

const css = `:root{color-scheme:light dark;font:16px -apple-system,system-ui,sans-serif}
body{margin:0 10px}a{color:inherit}
header{position:sticky;top:0;z-index:1;background:Canvas;padding:8px 0 6px;border-bottom:1px solid #8884}
.top{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.muted{color:GrayText;font-size:14px}
.search{display:flex;gap:8px;align-items:center;margin:8px 0 4px}
.search input[type=search]{flex:1;min-width:0;font-size:16px;padding:8px 10px;border:1px solid #8886;border-radius:8px;background:Field;color:FieldText}
.check{font-size:14px;white-space:nowrap;display:flex;align-items:center;gap:4px;min-height:44px}
[hidden]{display:none!important}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:4px 0;align-items:center}
.chip{display:inline-flex;align-items:center;min-height:34px;padding:0 11px;border:1px solid #8886;border-radius:17px;text-decoration:none;font-size:14px}
.chip.on{background:#1a5fd0;border-color:#1a5fd0;color:#fff}
.sep{width:6px}
.step{font-size:14px;margin:6px 0;padding:6px 8px;border-left:3px solid #e08a00;background:#e08a0014;white-space:pre-wrap;overflow-wrap:anywhere}
ul{list-style:none;margin:0;padding:0}
li{border-bottom:1px solid #8883}
.row{display:grid;grid-template-columns:3.2em 1fr;column-gap:8px;min-height:44px;padding:8px 0;text-decoration:none}
.row .s{grid-row:span 2;align-self:start;text-align:center;font-weight:600;font-size:14px;padding:2px 0;border-radius:6px}
.row .t{overflow-wrap:anywhere}.row .t b{font-weight:700;font-size:14px}
.row .meta{grid-column:2;color:GrayText;font-size:14px;overflow-wrap:anywhere}
.empty{padding:16px 0}
.badge{font-size:14px;font-weight:600;padding:2px 8px;border-radius:6px}
.ok .s,.badge.ok{color:#1a8a3a;background:#1a8a3a1f}.redir .s,.badge.redir{color:#2f6fd6;background:#2f6fd61f}
.warn .s,.badge.warn{color:#c46a00;background:#e08a0024}.bad .s,.badge.bad{color:#d33;background:#dd33331f}
.open .s,.badge.open{color:GrayText;background:#8882}
.m-get{color:#2f6fd6}.m-post{color:#1a8a3a}.m-put{color:#c46a00}.m-del{color:#d33}.m-other{color:GrayText}
.slow{color:#c46a00;font-weight:600}.bad{color:#d33}
h1{font-size:18px}.url{overflow-wrap:anywhere;-webkit-user-select:all;user-select:all}
summary{min-height:44px;display:flex;align-items:center;font-weight:600}
dl{margin:0}dt{font-weight:600;font-size:14px;margin-top:8px;overflow-wrap:anywhere}dd{margin:0 0 4px;overflow-wrap:anywhere;font-size:14px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}`
