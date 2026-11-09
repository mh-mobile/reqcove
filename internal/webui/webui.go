// Package webui is Reqcove's own read-only page, served on the tailnet node to
// the user's own devices, which see every device's flows, and to the other
// --device devices, which see their own (exitnode checks who asks); as the MCP
// tools return them, already masked. It is rendered on the
// server with html/template; its one script, app.js, refreshes the list as text
// only, so what remote sites wrote into headers and bodies stays text.
package webui

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// cookie holds the start's token: only the browser that opened the link with
// it (the QR code reqcove run prints) reads the page, not any app on the device.
const cookie = "reqcove"

type UI struct {
	store *capture.Store
	steps func(deviceID string, all bool) []string // the next steps for one device, or for all, as the status tool words them (no login URL)
	token string
}

func New(st *capture.Store, steps func(deviceID string, all bool) []string) *UI {
	return &UI{store: st, steps: steps, token: rand.Text()}
}

// Token is what the link to the page carries: http://NODE/?k=TOKEN.
func (u *UI) Token() string { return u.token }

// Serve answers a GET from the device deviceID (its StableID). With all (one of
// the user's own devices) it shows every device's flows; else deviceID's only.
func (u *UI) Serve(w http.ResponseWriter, r *http.Request, deviceID string, all bool) {
	h := w.Header()
	// One script, /app.js, from here; nothing inline. It fetches /flows.json and
	// puts what sites wrote in as text only.
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	if k := r.URL.Query().Get("k"); k != "" {
		if !u.valid(k) {
			http.Error(w, "reqcove: this link is from an earlier start of reqcove run; open the one it prints now", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: cookie, Value: k, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if c, err := r.Cookie(cookie); err != nil || !u.valid(c.Value) {
		http.Error(w, "reqcove: open the link reqcove run prints (its QR code) to see this page", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/":
		render(w, listPage, u.view(r, deviceID, all))
	case "/flows.json":
		v := u.view(r, deviceID, all)
		h.Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"line": v["Line"], "steps": v["Steps"], "rows": v["Rows"]})
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
	S      string `json:"s"`    // status, "err" or "…"
	Text   string `json:"text"` // method and path
	Time   string `json:"time"`
	Host   string `json:"host"`
	MS     int64  `json:"ms,omitempty"`
	Device string `json:"device,omitempty"` // whose, when the page shows every device's
}

// view is the list for deviceID: its own flows, counts and steps only; with
// all, every device's.
func (u *UI) view(r *http.Request, deviceID string, all bool) map[string]any {
	q := r.URL.Query()
	f := capture.Filter{Host: q.Get("host"), Limit: 50}
	if !all {
		f.Device = deviceID
	}
	if s := q.Get("status"); capture.ValidStatus(s) {
		f.Status = s
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
		rw := row{ID: s.ID, Class: class(s.Status, s.State), S: st, Text: s.Method + " " + path(s.URL), Time: clock(s.Time), Host: s.Host, MS: s.DurationMS}
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
	return map[string]any{
		"Rows": rows, "Host": f.Host, "Status": f.Status, "Paused": q.Get("pause") != "",
		"Unmasked": stats["redacting"] == false, "Line": line, "Steps": steps,
	}
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

var funcs = template.FuncMap{"class": class}

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
	}
	return "ok"
}

const head = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="format-detection" content="telephone=no">
<link rel="stylesheet" href="/style.css"><title>Reqcove</title>`

// The list follows new flows with /app.js, without reloading (a reload a second
// made Safari's address bar flicker); without scripts, a refresh does it.
var listPage = template.Must(template.New("list").Funcs(funcs).Parse(head + `
{{if not .Paused}}<script src="/app.js" defer></script><noscript><meta http-equiv="refresh" content="1"></noscript>{{end}}</head><body>
<header><b>Reqcove</b>{{if .Unmasked}} <b class="bad">not masked (--no-redact)</b>{{end}} <span id="line" class="muted">{{.Line}}</span>
<nav>{{if .Paused}}<a href="/?host={{.Host}}&amp;status={{.Status}}">resume</a>{{else}}<a href="/?host={{.Host}}&amp;status={{.Status}}&amp;pause=1">pause</a>{{end}}
 · <a href="/?status=4xx">4xx</a> <a href="/?status=5xx">5xx</a> <a href="/?status=none">no answer</a>{{if or .Host .Status}} · <a href="/">all</a>{{end}}</nav>
{{if or .Host .Status}}<p class="muted">{{with .Host}}host {{.}} {{end}}{{with .Status}}status {{.}}{{end}}</p>{{end}}
<div id="steps">{{range .Steps}}<p class="step">next: {{.}}</p>{{end}}</div></header>
<table><tbody id="rows">{{range .Rows}}<tr class="{{.Class}}">
<td class="s">{{.S}}</td>
<td><a class="u" href="/flow?id={{.ID}}">{{.Text}}</a>
<div class="muted">{{.Time}} · <a href="/?host={{.Host}}">{{.Host}}</a>{{if .MS}} · {{.MS}} ms{{end}}{{with .Device}} · {{.}}{{end}}</div></td></tr>
{{else}}<tr><td class="muted">No flows from this device yet.</td></tr>{{end}}</tbody></table></body></html>`))

// appJS asks /flows.json (with the page's own filters) once a second and puts
// the rows in with textContent and DOM calls only: never markup from a site.
const appJS = `"use strict";
(function () {
  var last = "";
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function row(f) {
    var tr = el("tr", f.class), td = el("td");
    tr.appendChild(el("td", "s", f.s));
    var a = el("a", "u", f.text);
    a.href = "/flow?id=" + encodeURIComponent(f.id);
    td.appendChild(a);
    var meta = el("div", "muted", f.time + " · "), h = el("a", null, f.host);
    h.href = "/?host=" + encodeURIComponent(f.host);
    meta.appendChild(h);
    if (f.ms) meta.appendChild(document.createTextNode(" · " + f.ms + " ms"));
    if (f.device) meta.appendChild(document.createTextNode(" · " + f.device));
    td.appendChild(meta);
    tr.appendChild(td);
    return tr;
  }
  function tick() {
    fetch("/flows.json" + location.search, {credentials: "same-origin", cache: "no-store"})
      .then(function (r) { return r.ok ? r.text() : Promise.reject(r.status); })
      .then(function (t) {
        if (t === last) return;
        last = t;
        var d = JSON.parse(t), rows = document.getElementById("rows"), steps = document.getElementById("steps");
        document.getElementById("line").textContent = d.line;
        steps.replaceChildren.apply(steps, d.steps.map(function (s) { return el("p", "step", "next: " + s); }));
        var trs = d.rows.map(row);
        if (!trs.length) {
          var empty = el("tr");
          empty.appendChild(el("td", "muted", "No flows from this device yet."));
          trs = [empty];
        }
        rows.replaceChildren.apply(rows, trs);
      })
      .catch(function () {})
      .then(function () { setTimeout(tick, 1000); });
  }
  setTimeout(tick, 1000);
})();
`

var flowPage = template.Must(template.New("flow").Funcs(funcs).Parse(head + `</head><body>
<header><a href="/">← flows</a></header>
<h1>{{.F.Method}} <span class="{{class .F.Status .F.State}}">{{if .F.Status}}{{.F.Status}} {{.F.Reason}}{{else}}{{.F.State}}{{end}}</span></h1>
<p class="u">{{.F.URL}}</p>
{{with .F.MappedURL}}<p class="muted">sent to {{.}}</p>{{end}}
{{with .F.Error}}<p class="bad">{{.}}</p>{{end}}
{{range .F.Rewrites}}<p class="muted">rule: {{.}}</p>{{end}}
{{range .F.Notes}}<p class="muted">{{.}}</p>{{end}}
<details open><summary>Request headers</summary><table>{{range .F.ReqHeaders}}<tr><th>{{index . 0}}</th><td>{{index . 1}}</td></tr>{{end}}</table></details>
<details><summary>Request body</summary>{{with .F.ReqBodyEnc}}<p class="muted">{{.}}</p>{{end}}<pre>{{.ReqBody}}</pre></details>
<details open><summary>Response headers</summary><table>{{range .F.RespHeaders}}<tr><th>{{index . 0}}</th><td>{{index . 1}}</td></tr>{{end}}</table></details>
<details open><summary>Response body</summary>{{with .F.RespBodyEnc}}<p class="muted">{{.}}</p>{{end}}<pre>{{.RespBody}}</pre></details>
</body></html>`))

const css = `:root{color-scheme:light dark;font:14px -apple-system,system-ui,sans-serif}
body{margin:0 8px}header{position:sticky;top:0;background:Canvas;padding:6px 0;border-bottom:1px solid #8884}
nav,.muted{color:#888;font-size:12px}table{width:100%;border-collapse:collapse}td,th{padding:4px;vertical-align:top;text-align:left}
tr{border-bottom:1px solid #8882}.s{font-weight:600;width:3em}
.u{word-break:break-all;text-decoration:none;display:block}a{color:inherit}
.bad{color:#d33}.warn{color:#c80}.open{color:#888}.step{color:#c80;font-size:12px;margin:2px 0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}th{font-weight:600;word-break:break-all;width:30%}h1{font-size:16px}`
