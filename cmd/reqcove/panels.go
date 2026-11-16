package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/skip2/go-qrcode"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

// The console's other panels (the local page; since v1.3): the --rules
// file's presets, on and off with their limits, and its rules by kind and
// name, never a value; a marker; the CA, its public certificate's name,
// fingerprint and expiry alone; and the records as a HAR file. Every route
// goes through ServeHTTP's checks and authed.

// presetWarnings are said before a preset of each kind is turned on: what it
// changes and who then gets the requests (map_remote's destination is
// added, as the page shows it).
var presetWarnings = map[string]string{
	"mock":           "the device's matching requests are answered here, not sent to the server: the app gets what the --rules file says",
	"map_remote":     "the device's matching requests, with their cookies and tokens, go to this destination instead of their server, which reads them",
	"modify_headers": "a request header the --rules file names is set on the device's matching requests, sent to their server",
	"resolve":        "the device's connections to this rule's host go to another address, which gets those requests, with their cookies and tokens",
}

type pagePreset struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Active    bool   `json:"active"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Remaining *int   `json:"remaining,omitempty"`
	Target    string `json:"target,omitempty"` // map_remote: its destination (pageTarget)
}

type pageRule struct {
	Kind   string `json:"kind"`
	Index  int    `json:"index"`
	Preset string `json:"preset,omitempty"`
	Active *bool  `json:"active,omitempty"`
}

// pagePresets is GET /api/presets: names and kinds, never a rule's values
// (no URL, filter, header, body, address or the file's error text).
type pagePresets struct {
	Message  string            `json:"message,omitempty"`
	Loaded   bool              `json:"loaded"`
	Problem  bool              `json:"problem,omitempty"` // the file, or its last change, did not load
	Presets  []pagePreset      `json:"presets"`
	Rules    []pageRule        `json:"rules"`
	Warnings map[string]string `json:"warnings"`
}

// pageTarget is a map_remote destination as the page shows it: a scheme
// (http, https) and a host name or IPv4 address, with a port; anything else
// not shown.
func pageTarget(t string) string {
	const hidden = "(not shown: not a plain scheme and host)"
	if t == "path only" {
		return "the same host (the path only changes)"
	}
	u, err := url.Parse(t)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return hidden
	}
	if !capture.ValidHost(u.Hostname()) {
		return hidden
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return hidden
		}
	}
	return u.Scheme + "://" + u.Host
}

// presetsNow are the presets as the page shows them.
func (p *page) presetsNow(ctx context.Context) ([]pagePreset, error) {
	ps, err := p.presets.Presets(ctx)
	out := []pagePreset{}
	for _, x := range ps {
		if !capture.PresetName.MatchString(x.Name) {
			continue
		}
		v := pagePreset{Name: x.Name, Kind: x.Kind, Active: x.Active, Remaining: x.Remaining}
		if x.ExpiresAt != nil {
			sec, frac := math.Modf(*x.ExpiresAt)
			v.ExpiresAt = time.Unix(int64(sec), int64(frac*1e9)).Format(time.RFC3339)
		}
		if x.Kind == "map_remote" {
			v.Target = pageTarget(x.Target)
		}
		out = append(out, v)
	}
	return out, err
}

func (p *page) presetList(w http.ResponseWriter, r *http.Request) {
	out := pagePresets{Presets: []pagePreset{}, Rules: []pageRule{}, Warnings: presetWarnings}
	if p.presets == nil {
		out.Message = "no mitmproxy in this run"
		answer(w, http.StatusOK, out)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ps, err := p.presetsNow(ctx)
	if err != nil {
		out.Message = "mitmproxy did not answer (restarting?): try again in a moment"
		answer(w, http.StatusOK, out)
		return
	}
	out.Presets = ps
	rules, err := p.presets.ListRules(ctx)
	if err != nil {
		out.Message = "mitmproxy did not answer (restarting?): try again in a moment"
		answer(w, http.StatusOK, out)
		return
	}
	out.Loaded, out.Problem = rules.Loaded, rules.RulesError != ""
	for _, x := range rules.Rules {
		v := pageRule{Kind: x.Kind, Index: x.Index, Active: x.Active}
		if capture.PresetName.MatchString(x.Preset) {
			v.Preset = x.Preset
		}
		out.Rules = append(out.Rules, v)
	}
	answer(w, http.StatusOK, out)
}

// presetSet is POST /api/preset: one preset on (minutes, at most 5; times,
// a mock's) or off, as activate_preset and deactivate_preset make it; a
// map_remote preset only with the destination the page's confirm named
// (target), the one it has now.
func (p *page) presetSet(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string  `json:"name"`
		On      bool    `json:"on"`
		Minutes float64 `json:"minutes"`
		Times   int     `json:"times"`
		Target  string  `json:"target"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || !capture.PresetName.MatchString(in.Name) {
		answer(w, http.StatusBadRequest, map[string]any{"error": "refused: not JSON of the page"})
		return
	}
	reply := func(ok bool, msg string) { answer(w, http.StatusOK, map[string]any{"ok": ok, "message": msg}) }
	if p.presets == nil {
		reply(false, "refused: no mitmproxy in this run")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if !in.On {
		was, err := p.presets.Deactivate(ctx, in.Name)
		switch {
		case errors.Is(err, capture.ErrUncertain):
			reply(false, "mitmproxy did not answer in time: "+in.Name+" may still be on (the page shows it as it is now)")
		case err != nil:
			reply(false, "refused: "+err.Error())
		case was:
			log.Printf("reqcove console: the preset %s turned off%s", in.Name, from(r))
			reply(true, in.Name+" is off")
		default:
			reply(true, in.Name+" was off already")
		}
		return
	}
	minutes := in.Minutes
	if minutes == 0 {
		minutes = 5
	}
	if !(minutes > 0 && minutes <= 5) {
		reply(false, "refused: on for more than 0 and at most 5 minutes")
		return
	}
	ps, err := p.presetsNow(ctx)
	if err != nil {
		reply(false, "refused: mitmproxy did not answer (restarting?): nothing turned on")
		return
	}
	i := -1
	for j, x := range ps {
		if x.Name == in.Name {
			i = j
		}
	}
	if i < 0 {
		reply(false, "refused: no preset by that name in the --rules file now")
		return
	}
	if ps[i].Kind == "map_remote" && in.Target != ps[i].Target {
		reply(false, "refused: "+in.Name+" sends the requests to "+ps[i].Target+" now, not where the page's confirm said (the --rules file changed?): nothing turned on; the page shows it as it is now")
		return
	}
	seconds := max(int(math.Round(minutes*60)), 1)
	a, err := p.presets.Activate(ctx, in.Name, seconds, in.Times)
	switch {
	case errors.Is(err, capture.ErrUncertain):
		reply(false, "mitmproxy did not answer in time: "+in.Name+" may be on (the page shows it as it is now)")
		return
	case err != nil && strings.HasPrefix(err.Error(), "recording is stopped"):
		reply(false, "refused: recording is stopped: no rule applies, presets included, so none can be turned on; Start recording first")
		return
	case err != nil:
		reply(false, "refused: "+err.Error())
		return
	}
	log.Printf("reqcove console: the preset %s turned on for %ds%s%s%s", a.Name, seconds, timesNote(a.Times), offNote(a.TurnedOff), from(r))
	msg := fmt.Sprintf("%s is on for %s", a.Name, (time.Duration(seconds) * time.Second).String())
	if a.Times != nil {
		msg += fmt.Sprintf(" or %d requests", *a.Times)
	}
	if len(a.TurnedOff) > 0 {
		msg += "; turned off (the same match): " + strings.Join(a.TurnedOff, ", ")
	}
	reply(true, msg)
}

func timesNote(t *int) string {
	if t == nil {
		return ""
	}
	return fmt.Sprintf(", %d requests", *t)
}

func offNote(off []string) string {
	if len(off) == 0 {
		return ""
	}
	return " (turned off: " + strings.Join(off, ", ") + ")"
}

// marker is POST /api/marker {text}: a marker among the records, source
// console (as reqcove mark's are cli and an agent's mcp).
func (p *page) marker(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Text string `json:"text"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil {
		answer(w, http.StatusBadRequest, map[string]any{"error": "refused: not JSON of the page"})
		return
	}
	if p.cap == nil {
		answer(w, http.StatusOK, map[string]any{"ok": false, "message": "refused: no records in this run"})
		return
	}
	m, _, err := p.cap.Store.AddMarker(in.Text, "console")
	if err != nil {
		answer(w, http.StatusOK, map[string]any{"ok": false, "message": "refused: " + err.Error()})
		return
	}
	answer(w, http.StatusOK, map[string]any{"ok": true, "message": fmt.Sprintf("marker %d at %s", m.ID, m.Time.Format("15:04:05"))})
}

// caURL is where a device gets the CA, through run.
const caURL = "http://mitm.it"

// pageCA is GET /api/ca: the public certificate's name, fingerprint and
// expiry (capture.CA holds nothing else), a QR code of caURL, and the steps.
type pageCA struct {
	Message  string   `json:"message,omitempty"`
	Name     string   `json:"name,omitempty"`
	SHA256   string   `json:"sha256,omitempty"`
	NotAfter string   `json:"not_after,omitempty"`
	URL      string   `json:"url"`
	QR       []string `json:"qr"` // its rows, 1 dark, quiet zone included
	Add      []string `json:"add"`
	Remove   string   `json:"remove,omitempty"`
}

func (p *page) ca(w http.ResponseWriter, _ *http.Request) {
	out := pageCA{URL: caURL, QR: []string{}, Add: []string{}}
	var ca capture.CA
	if p.cap != nil {
		ca = p.cap.CA
	}
	if ca.Name == "" {
		out.Message = "no CA yet: run makes it at its first start"
		answer(w, http.StatusOK, out)
		return
	}
	out.Name, out.SHA256, out.NotAfter = ca.Name, ca.SHA256, ca.NotAfter.Format("2006-01-02")
	add, remove := caSteps(ca.Name, p.st.o.lanMode)
	out.Add, out.Remove = add[:], remove
	if q, err := qrcode.New(caURL, qrcode.Low); err == nil {
		for _, row := range q.Bitmap() {
			var b strings.Builder
			for _, dark := range row {
				b.WriteByte("01"[boolInt(dark)])
			}
			out.QR = append(out.QR, b.String())
		}
	}
	answer(w, http.StatusOK, out)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// harFile is GET /api/har: the records as a HAR file, as reqcove har writes
// it (the tools' answers, masked, body heads), in the answer's body as an
// attachment; the page fetches it with its session header and saves it from
// a blob: never a link with a token. Refused while nothing is masked
// (--no-redact): such a file belongs where the user chose, from reqcove har.
func (p *page) harFile(w http.ResponseWriter, r *http.Request) {
	refuse := func(msg string) {
		answer(w, http.StatusConflict, map[string]any{"error": "refused: " + msg})
	}
	if p.cap == nil {
		refuse("no records in this run")
		return
	}
	if !p.cap.Store.Redacting() {
		refuse("run was started with --no-redact: nothing is masked, so the page gives no HAR file. reqcove har in your terminal writes one, marked unmasked, where you choose")
		return
	}
	// A full store (10,000 flows, 64 MiB) took 5.6 s here: longer than the
	// server's other answers may take.
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(3 * time.Minute))
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	srv := mcpserver.New(p.cap.Store, nil)
	ct, stt := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, stt, nil)
	if err != nil {
		refuse(err.Error())
		return
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "reqcove-console", Version: version}, nil).Connect(ctx, ct, nil)
	if err != nil {
		refuse(err.Error())
		return
	}
	defer cs.Close()
	var buf bytes.Buffer
	n, redacting, err := writeHAR(ctx, toolCaller(ctx, cs), &buf, mcpserver.FilterIn{}, 0)
	if !redacting { // masking went off since (it cannot today): fail closed
		refuse("the records are not masked")
		return
	}
	if err != nil {
		refuse(err.Error())
		return
	}
	log.Printf("reqcove console: %d flows given as a HAR file%s", n, fromConsole)
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Disposition", `attachment; filename="reqcove-`+time.Now().Format("20060102-150405")+`.har"`)
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.Write(buf.Bytes())
}

// flowsURL is --ui's page, bare (never its token): "" without --ui, in LAN
// mode, or before the node has an address.
func flowsURL(o *runOpts, ips []string) string {
	if !o.ui || o.lanMode {
		return ""
	}
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
			return "http://" + ip + "/"
		}
	}
	return ""
}

// serviceCommands are the commands of the service run runs under (local
// paths in them: the local page's alone), or how to start it as one.
func serviceCommands(service, manager, state string) []string {
	if service == "" {
		if manager != "terminal" {
			return nil
		}
		return []string{"to start it at login, in the background, in your terminal: " + withState("reqcove service install", state) + " (Homebrew's: brew services start reqcove)"}
	}
	out := []string{serviceHint(service, state)}
	if c := restartCmd(service); c != "" {
		out = append(out, "restart: "+c)
	}
	return out
}
