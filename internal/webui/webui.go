// Package webui is Reqcove's own read-only page, served on the tailnet node to
// the --device devices (exitnode checks who asks): each device sees the flows
// it made, as the MCP tools return them, already masked. It is rendered on the
// server with html/template and carries no script, so what remote sites wrote
// into headers and bodies stays text.
package webui

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// cookie holds the start's token: only the browser that opened the link with
// it (the QR code reqcove run prints) reads the page, not any app on the device.
const cookie = "reqcove"

type UI struct {
	store *capture.Store
	steps func() []string // the next steps, as the status tool gives them (no login URL)
	token string
}

func New(st *capture.Store, steps func() []string) *UI {
	return &UI{store: st, steps: steps, token: rand.Text()}
}

// Token is what the link to the page carries: http://NODE/?k=TOKEN.
func (u *UI) Token() string { return u.token }

// Serve answers a GET from the device deviceID (its StableID).
func (u *UI) Serve(w http.ResponseWriter, r *http.Request, deviceID string) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
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
		u.list(w, r, deviceID)
	case "/flow":
		u.flow(w, r, deviceID)
	case "/style.css":
		h.Set("Content-Type", "text/css; charset=utf-8")
		w.Write([]byte(css))
	default:
		http.NotFound(w, r)
	}
}

func (u *UI) valid(k string) bool { return subtle.ConstantTimeCompare([]byte(k), []byte(u.token)) == 1 }

func (u *UI) list(w http.ResponseWriter, r *http.Request, deviceID string) {
	q := r.URL.Query()
	f := capture.Filter{Device: deviceID, Host: q.Get("host"), Limit: 50}
	if s := q.Get("status"); capture.ValidStatus(s) {
		f.Status = s
	}
	all, _ := u.store.List(f)
	flows := all[:0]
	for _, s := range all {
		if s.Device == deviceID { // the filter also takes a display name; the page, the ID only
			flows = append(flows, s)
		}
	}
	// This device's counts and steps only: not the others', nor their names.
	var me capture.DeviceInfo
	var others []string
	for _, d := range u.store.Devices() {
		if d.ID == deviceID {
			me = d
		} else if d.Name != "" {
			others = append(others, d.Name)
		}
	}
	var steps []string
	if u.steps != nil {
	step:
		for _, s := range u.steps() {
			for _, n := range others {
				if strings.Contains(s, n) {
					continue step
				}
			}
			steps = append(steps, s)
		}
	}
	render(w, listPage, map[string]any{
		"Flows": flows, "Host": f.Host, "Status": f.Status, "Paused": q.Get("pause") != "",
		"State": u.store.Stats()["state"], "Count": me.Flows, "TLSFailures": me.TLSFailures, "Steps": steps,
	})
}

func (u *UI) flow(w http.ResponseWriter, r *http.Request, deviceID string) {
	v, err := u.store.Get(r.URL.Query().Get("id"), true)
	if err != nil || v.Device != deviceID { // another device's flow is not there for this one
		http.NotFound(w, r)
		return
	}
	render(w, flowPage, map[string]any{"F": v, "ReqBody": pretty(v.ReqBodyText), "RespBody": pretty(v.RespBodyText)})
}

// pretty indents a JSON body; anything else is shown as it is. Deep nesting
// makes indenting grow with its square (a 60 KB head of "[[[…" became 600 MB),
// so a result past a few times the body's size is dropped for the body itself.
func pretty(s string) string {
	var b bytes.Buffer
	if t := strings.TrimSpace(s); (strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")) && json.Indent(&b, []byte(t), "", "  ") == nil && b.Len() <= 4*len(t)+4096 {
		return b.String()
	}
	return s
}

func render(w http.ResponseWriter, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		http.Error(w, "reqcove: "+err.Error(), http.StatusInternalServerError)
	}
}

var funcs = template.FuncMap{
	"clock": func(s string) string {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.Format("15:04:05")
		}
		return s
	},
	// path is a URL without its scheme and host, which the row shows apart.
	"path": func(u string) string {
		if _, rest, ok := strings.Cut(u, "://"); ok {
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				return rest[i:]
			}
			return "/"
		}
		return u
	},
	"class": func(status int, state string) string {
		switch {
		case state == "error" || status >= 500:
			return "bad"
		case status >= 400:
			return "warn"
		case status == 0:
			return "open"
		}
		return "ok"
	},
}

const head = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="format-detection" content="telephone=no">
<link rel="stylesheet" href="/style.css"><title>Reqcove</title>`

var listPage = template.Must(template.New("list").Funcs(funcs).Parse(head + `
{{if not .Paused}}<meta http-equiv="refresh" content="1">{{end}}</head><body>
<header><b>Reqcove</b> <span class="muted">mitmproxy {{.State}} · {{.Count}} flows{{if .TLSFailures}} · {{.TLSFailures}} TLS failures{{end}}</span>
<nav>{{if .Paused}}<a href="/?host={{.Host}}&amp;status={{.Status}}">resume</a>{{else}}<a href="/?host={{.Host}}&amp;status={{.Status}}&amp;pause=1">pause</a>{{end}}
 · <a href="/?status=4xx">4xx</a> <a href="/?status=5xx">5xx</a> <a href="/?status=none">no answer</a>{{if or .Host .Status}} · <a href="/">all</a>{{end}}</nav>
{{if or .Host .Status}}<p class="muted">{{with .Host}}host {{.}} {{end}}{{with .Status}}status {{.}}{{end}}</p>{{end}}
{{range .Steps}}<p class="step">next: {{.}}</p>{{end}}</header>
<table>{{range .Flows}}<tr class="{{class .Status .State}}">
<td class="s">{{if .Status}}{{.Status}}{{else if eq .State "error"}}err{{else}}…{{end}}</td>
<td><a class="u" href="/flow?id={{.ID}}">{{.Method}} {{path .URL}}</a>
<div class="muted">{{clock .Time}} · <a href="/?host={{.Host}}">{{.Host}}</a>{{if .DurationMS}} · {{.DurationMS}} ms{{end}}</div></td></tr>
{{else}}<tr><td class="muted">No flows from this device yet.</td></tr>{{end}}</table></body></html>`))

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
