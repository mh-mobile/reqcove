package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// fakePresets stands in for mitmproxy's presets: what the --rules file holds,
// values the page must never show among them; what was asked.
type fakePresets struct {
	mu      sync.Mutex
	stopped bool
	asked   []string
}

func (f *fakePresets) Presets(context.Context) ([]capture.Preset, error) {
	exp := float64(time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC).Unix())
	two := 2
	return []capture.Preset{
		{Name: "staging", Kind: "map_remote", Target: "https://staging.example.com:8443", Description: leak},
		{Name: "odd", Kind: "map_remote", Target: "https://u:" + leak + "@x.example.com/" + leak},
		{Name: "slow", Kind: "mock", URL: "https://api.example.com/" + leak, Method: new("GET"), Description: leak, Active: true, ExpiresAt: &exp, Remaining: &two},
		{Name: "hdr", Kind: "modify_headers", Header: "X-" + leak},
		{Name: "dns", Kind: "resolve", Host: leak + ".example.com", Address: "10.9.9.9"},
		{Name: "bad name " + leak, Kind: "mock"},
	}, nil
}

func (f *fakePresets) Activate(_ context.Context, name string, seconds, times int) (capture.Activation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopped {
		return capture.Activation{}, errors.New("recording is stopped (reqcove capture stop): no rule applies, presets included, so none can be turned on")
	}
	f.asked = append(f.asked, "on "+name+" "+time.Duration(seconds*int(time.Second)).String()+" "+strings.Repeat("x", times))
	a := capture.Activation{Name: name, ExpiresAt: float64(time.Now().Unix() + int64(seconds))}
	if times > 0 {
		a.Times = &times
	}
	return a, nil
}

func (f *fakePresets) Deactivate(_ context.Context, name string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, "off "+name)
	return true, nil
}

func (f *fakePresets) ListRules(context.Context) (capture.Rules, error) {
	on := true
	return capture.Rules{Loaded: true, RulesError: "line 3: " + leak, Rules: []capture.Rule{
		{Kind: "mock", Index: 0, Preset: "slow", Active: &on, URL: "https://api.example.com/" + leak, Method: new("GET")},
		{Kind: "map_remote", Index: 0, Preset: "staging", Target: "https://" + leak + ".example.com"},
		{Kind: "modify_headers", Index: 0, Header: "X-" + leak, Direction: "request"},
		{Kind: "resolve", Index: 0, Host: leak + ".example.com", Address: "10.9.9.9"},
		{Kind: "map_local", Index: 0, Preset: "../" + leak},
	}}, nil
}

func (f *fakePresets) Explain(context.Context, string, string, string) (capture.Explanation, error) {
	return capture.Explanation{}, nil
}

func (f *fakePresets) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.asked)
}

// pageWith is a page open with a session, its presets a fakePresets.
func pageWith(t *testing.T, o *runOpts) (base, token string, st *ctlState, f *fakePresets) {
	t.Helper()
	state, st := pageRun(t, o)
	base, code := openUI(t, state)
	f = &fakePresets{}
	st.page.presets = f
	return base, trade(t, base, code), st, f
}

func postJSON(t *testing.T, base, token, path, body string) (bool, string) {
	t.Helper()
	r, b := call(t, base, "POST", path, body, map[string]string{sessionHeader: token})
	var out struct {
		OK      bool
		Message string
	}
	if r.StatusCode != 200 || json.Unmarshal([]byte(b), &out) != nil {
		t.Fatalf("%s %s: %d %s", path, body, r.StatusCode, b)
	}
	return out.OK, out.Message
}

// The presets and rules: names and kinds, a map_remote preset's destination
// as a scheme and host alone; never a rule's values (URL, header, address,
// filter, the file's error text, a description). Turned on for at most 5
// minutes, a map_remote one only with the destination the confirm named;
// refused while recording is stopped (mitmproxy's word, here a stand-in's:
// TestPagePresetsE2E has mitmproxy's own); each traced as the console's.
func TestPagePresets(t *testing.T) {
	logged := logTo(t)
	base, token, _, f := pageWith(t, &runOpts{})
	r, b := call(t, base, "GET", "/api/presets", "", map[string]string{sessionHeader: token})
	if r.StatusCode != 200 || strings.Contains(b, leak) || strings.Contains(b, "10.9.9.9") || strings.Contains(b, "api.example.com") || strings.Contains(b, "line 3") {
		t.Fatalf("shows what it must not: %d %s", r.StatusCode, b)
	}
	var d pagePresets
	json.Unmarshal([]byte(b), &d)
	names := []string{}
	for _, p := range d.Presets {
		names = append(names, p.Name+" "+p.Kind+" "+p.Target)
	}
	if !slices.Equal(names, []string{"staging map_remote https://staging.example.com:8443", "odd map_remote (not shown: not a plain scheme and host)", "slow mock ", "hdr modify_headers ", "dns resolve "}) {
		t.Errorf("presets: %q", names)
	}
	if s := d.Presets[2]; !s.Active || s.ExpiresAt != "2026-11-17T10:00:00Z" && !strings.HasPrefix(s.ExpiresAt, "2026-11-17T") || *s.Remaining != 2 {
		t.Errorf("an active one: %+v", s)
	}
	if !d.Loaded || !d.Problem || len(d.Rules) != 5 || d.Rules[0].Preset != "slow" || d.Rules[4].Preset != "" || !strings.Contains(d.Warnings["map_remote"], "cookies and tokens") {
		t.Errorf("rules: %+v", d)
	}
	for _, c := range []struct{ body, want string }{
		{`{"name":"staging","on":true}`, "not where the page's confirm said"},
		{`{"name":"staging","on":true,"target":"https://evil.example.com"}`, "not where the page's confirm said"},
		{`{"name":"slow","on":true,"minutes":6}`, "at most 5 minutes"},
		{`{"name":"slow","on":true,"minutes":-1}`, "at most 5 minutes"},
		{`{"name":"gone","on":true}`, "no preset by that name"},
	} {
		if ok, msg := postJSON(t, base, token, "/api/preset", c.body); ok || !strings.Contains(msg, c.want) {
			t.Errorf("%s: %v %s", c.body, ok, msg)
		}
	}
	for _, body := range []string{`{"name":"slow","on":true,"url":"x"}`, `{"name":"../x","on":true}`, `not json`} {
		if r, _ := call(t, base, "POST", "/api/preset", body, map[string]string{sessionHeader: token}); r.StatusCode != 400 {
			t.Errorf("%s: %d", body, r.StatusCode)
		}
	}
	if got := f.got(); len(got) != 0 {
		t.Errorf("a refused one reached mitmproxy: %q", got)
	}
	if ok, msg := postJSON(t, base, token, "/api/preset", `{"name":"staging","on":true,"minutes":2,"target":"https://staging.example.com:8443"}`); !ok || msg != "staging is on for 2m0s" {
		t.Errorf("on: %v %s", ok, msg)
	}
	if ok, msg := postJSON(t, base, token, "/api/preset", `{"name":"slow","on":true,"times":3}`); !ok || msg != "slow is on for 5m0s or 3 requests" {
		t.Errorf("a mock: %v %s", ok, msg)
	}
	if ok, msg := postJSON(t, base, token, "/api/preset", `{"name":"slow","on":false}`); !ok || msg != "slow is off" {
		t.Errorf("off: %v %s", ok, msg)
	}
	if got := f.got(); !slices.Equal(got, []string{"on staging 2m0s ", "on slow 5m0s xxx", "off slow"}) {
		t.Errorf("asked: %q", got)
	}
	f.mu.Lock()
	f.stopped = true
	f.mu.Unlock()
	if ok, msg := postJSON(t, base, token, "/api/preset", `{"name":"slow","on":true}`); ok || !strings.HasPrefix(msg, "refused: recording is stopped") {
		t.Errorf("stopped: %v %s", ok, msg)
	}
	for _, want := range []string{"reqcove console: the preset staging turned on for 120s" + fromConsole, "reqcove console: the preset slow turned off" + fromConsole} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("log: no %q in %s", want, logged.String())
		}
	}
	if strings.Contains(logged.String(), token) {
		t.Errorf("logged: %s", logged.String())
	}
}

func TestPageTarget(t *testing.T) {
	for in, want := range map[string]string{
		"https://staging.example.com":      "https://staging.example.com",
		"http://10.0.0.5:8080":             "http://10.0.0.5:8080",
		"path only":                        "the same host (the path only changes)",
		"not shown":                        "(not shown: not a plain scheme and host)",
		"https://u:p@x.example.com":        "(not shown: not a plain scheme and host)",
		"https://x.example.com/a?k=v":      "(not shown: not a plain scheme and host)",
		"https://X.example.com":            "(not shown: not a plain scheme and host)",
		"https://x.example.com:99999":      "(not shown: not a plain scheme and host)",
		"javascript://x.example.com":       "(not shown: not a plain scheme and host)",
		"https://<img src=x>.example.com":  "(not shown: not a plain scheme and host)",
		"https://[::1]:8443":               "(not shown: not a plain scheme and host)",
		"https://x.example.com#" + leak:    "(not shown: not a plain scheme and host)",
		"ftp://x.example.com":              "(not shown: not a plain scheme and host)",
		"https://x.example.com:8443":       "https://x.example.com:8443",
		"https://" + leak + ".example.com": "(not shown: not a plain scheme and host)",
	} {
		if got := pageTarget(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// A marker from the page: source console, masked and checked as an agent's.
func TestPageMarker(t *testing.T) {
	base, token, st, _ := pageWith(t, &runOpts{})
	if ok, msg := postJSON(t, base, token, "/api/marker", `{"text":"about to tap Pay"}`); !ok || !strings.HasPrefix(msg, "marker 1 at ") {
		t.Errorf("%v %s", ok, msg)
	}
	for _, text := range []string{strings.Repeat("x", 81), "two\\nlines", "esc\\u001b[31m"} {
		if ok, msg := postJSON(t, base, token, "/api/marker", `{"text":"`+text+`"}`); ok || !strings.HasPrefix(msg, "refused: text") {
			t.Errorf("%q: %v %s", text, ok, msg)
		}
	}
	m := st.page.cap.Store.Markers(0)
	if len(m) != 1 || m[0].Source != "console" || m[0].Text != "about to tap Pay" {
		t.Errorf("markers: %+v", m)
	}
}

// The CA panel: the certificate's name, fingerprint and expiry, the QR code
// of http://mitm.it and the steps, nothing else: no key material, whatever
// the state directory holds.
func TestPageCA(t *testing.T) {
	state, st := pageRun(t, &runOpts{})
	os.MkdirAll(filepath.Join(state, "mitmproxy"), 0o700)
	key := "-----BEGIN PRIVATE KEY-----\n" + leak + "\n-----END PRIVATE KEY-----\n"
	os.WriteFile(filepath.Join(state, "mitmproxy", "mitmproxy-ca.pem"), []byte(key), 0o600)
	base, code := openUI(t, state)
	token := trade(t, base, code)
	r, b := call(t, base, "GET", "/api/ca", "", map[string]string{sessionHeader: token})
	if r.StatusCode != 200 || !strings.Contains(b, "no CA yet") {
		t.Errorf("none yet: %s", b)
	}
	st.page.cap.CA = capture.CA{Name: "Reqcove CA (mac, 2026-11-17)", SHA256: "AB12", NotAfter: time.Date(2036, 11, 17, 0, 0, 0, 0, time.UTC)}
	r, b = call(t, base, "GET", "/api/ca", "", map[string]string{sessionHeader: token})
	var m map[string]json.RawMessage
	if r.StatusCode != 200 || json.Unmarshal([]byte(b), &m) != nil || strings.Contains(b, "PRIVATE") || strings.Contains(b, leak) || strings.Contains(b, "BEGIN") {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	})
	if !slices.Equal(keys, []string{"add", "name", "not_after", "qr", "remove", "sha256", "url"}) {
		t.Errorf("fields: %q", keys)
	}
	var ca pageCA
	json.Unmarshal([]byte(b), &ca)
	add, remove := caSteps(ca.Name, false)
	if ca.SHA256 != "AB12" || ca.NotAfter != "2036-11-17" || ca.URL != "http://mitm.it" || !slices.Equal(ca.Add, add[:]) || ca.Remove != remove || !strings.Contains(ca.Remove, `"Reqcove CA (mac, 2026-11-17)", Remove Profile`) {
		t.Errorf("ca: %+v", ca)
	}
	if len(ca.QR) < 21 || len(ca.QR[0]) != len(ca.QR) || strings.Trim(strings.Join(ca.QR, ""), "01") != "" {
		t.Errorf("qr: %q", ca.QR)
	}
}

// The records as a HAR file: fetched with the session header alone (no
// route takes a token in its query), an attachment of JSON, nosniff and
// no-store, masked as the tools give it; refused while nothing is masked.
func TestPageHAR(t *testing.T) {
	logged := logTo(t)
	base, token, st, _ := pageWith(t, &runOpts{})
	store := st.page.cap.Store
	ev := func(m map[string]any) {
		m["v"] = 2
		b, _ := json.Marshal(m)
		store.Apply(b)
	}
	ev(map[string]any{"ev": "request", "id": "f1", "device": "devA", "host": "api.example.com", "method": "GET", "ts": 100.0,
		"url": "https://api.example.com/a?token=s3cr3t", "headers": [][2]string{{"Authorization", "Bearer s3cr3t"}}})
	ev(map[string]any{"ev": "response", "id": "f1", "status": 200, "headers": [][2]string{{"Content-Type", "application/json"}}})
	ev(map[string]any{"ev": "body", "id": "f1", "dir": "response", "decoded": true, "final": true, "size": 10, "head": base64.StdEncoding.EncodeToString([]byte(`{"ok":true}`))})
	ev(map[string]any{"ev": "done", "id": "f1", "ts_end": 100.25})

	r, b := call(t, base, "GET", "/api/har", "", map[string]string{sessionHeader: token})
	h := r.Header
	if r.StatusCode != 200 || h.Get("Content-Type") != "application/json" || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" ||
		!regexp.MustCompile(`^attachment; filename="reqcove-\d{8}-\d{6}\.har"$`).MatchString(h.Get("Content-Disposition")) {
		t.Errorf("%d %v", r.StatusCode, h)
	}
	var har struct {
		Log struct {
			Comment string
			Entries []harEntryOut
		}
	}
	if err := json.Unmarshal([]byte(b), &har); err != nil || len(har.Log.Entries) != 1 || !strings.HasPrefix(har.Log.Comment, "masked") || strings.Contains(b, "s3cr3t") || strings.Contains(b, token) {
		t.Errorf("har: %v %s", err, b)
	}
	if !strings.Contains(logged.String(), "reqcove console: 1 flows given as a HAR file"+fromConsole) {
		t.Errorf("log: %s", logged.String())
	}
	for _, q := range []string{"?k=" + token, "?session=" + token, "?token=" + token, "?" + sessionHeader + "=" + token} {
		for _, path := range []string{"/api/har", "/api/state", "/api/presets", "/api/ca"} {
			if r, _ := call(t, base, "GET", path+q, "", nil); r.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s%s: %d", path, q, r.StatusCode)
			}
		}
	}
	store.SetScope(capture.HostRules{}, false) // --no-redact
	r, b = call(t, base, "GET", "/api/har", "", map[string]string{sessionHeader: token})
	if r.StatusCode != http.StatusConflict || !strings.Contains(b, "--no-redact: nothing is masked, so the page gives no HAR file") || r.Header.Get("Content-Disposition") != "" || strings.Contains(b, "api.example.com") {
		t.Errorf("unmasked: %d %v %s", r.StatusCode, r.Header, b)
	}
}

// v1.2's guards on every route PR 7 added: the Host, the session in its
// header alone, a POST from this page as JSON, the method; and the headers.
func TestPagePanelChecks(t *testing.T) {
	base, token, _, f := pageWith(t, &runOpts{})
	port := strings.TrimPrefix(base, "http://127.0.0.1")
	s := map[string]string{sessionHeader: token}
	with := func(kv ...string) map[string]string {
		m := map[string]string{sessionHeader: token}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	type route struct{ method, path, body string }
	routes := []route{{"GET", "/api/presets", ""}, {"GET", "/api/ca", ""}, {"GET", "/api/har", ""},
		{"POST", "/api/preset", `{"name":"slow","on":true}`}, {"POST", "/api/marker", `{"text":"x"}`}}
	var all []*http.Response
	for _, rt := range routes {
		cases := []struct {
			why  string
			hdr  map[string]string
			want int
		}{
			{"no session", nil, 401},
			{"a wrong session", map[string]string{sessionHeader: token[:63] + "x"}, 401},
			{"a cookie alone", map[string]string{"Cookie": sessionHeader + "=" + token + "; reqcove-session=" + token}, 401},
			{"another Host", with("Host", "localhost"+port), 421},
			{"a rebinding Host", with("Host", "evil.example"+port), 421},
		}
		if rt.method == "POST" {
			cases = append(cases, []struct {
				why  string
				hdr  map[string]string
				want int
			}{
				{"cross Origin", with("Origin", "http://evil.example"), 403},
				{"no Origin", with("Origin", ""), 403},
				{"a form", with("Content-Type", "text/plain"), 415},
			}...)
		}
		for _, c := range cases {
			r, _ := call(t, base, rt.method, rt.path, rt.body, c.hdr)
			all = append(all, r)
			if r.StatusCode != c.want {
				t.Errorf("%s %s, %s: %d, want %d", rt.method, rt.path, c.why, r.StatusCode, c.want)
			}
		}
		other := map[string]string{"GET": "POST", "POST": "GET"}[rt.method]
		r, _ := call(t, base, other, rt.path, rt.body, s)
		all = append(all, r)
		if r.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d", other, rt.path, r.StatusCode)
		}
	}
	if got := f.got(); len(got) != 0 {
		t.Errorf("a refused request reached mitmproxy: %q", got)
	}
	for _, r := range all {
		h := r.Header
		if csp := h.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") ||
			h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s: headers %v", r.Request.Method, r.Request.URL.Path, h)
		}
		for k := range h {
			if strings.HasPrefix(k, "Access-Control-") {
				t.Errorf("%s %s: %s", r.Request.Method, r.Request.URL.Path, k)
			}
		}
	}
}

// This run's lines: --ui's page bare (never its token), and none without
// --ui or in LAN mode; the service's commands.
func TestPageFlowsAndService(t *testing.T) {
	base, token, _, _ := pageWith(t, &runOpts{ui: true})
	_, s := pageStateOf(t, base, token)
	if s.FlowsURL != "http://100.64.0.1/" || len(s.ServiceCmds) == 0 || !strings.Contains(s.ServiceCmds[0], "brew services stop reqcove") {
		t.Errorf("--ui: %q %q", s.FlowsURL, s.ServiceCmds)
	}
	for _, o := range []*runOpts{{}, {ui: true, lanMode: true}} {
		base, token, _, _ := pageWith(t, o)
		if _, s := pageStateOf(t, base, token); s.FlowsURL != "" {
			t.Errorf("%+v: %q", o, s.FlowsURL)
		}
	}
	if got := flowsURL(&runOpts{ui: true}, []string{"fd7a::1", "100.64.0.9"}); got != "http://100.64.0.9/" || strings.Contains(got, "k=") {
		t.Errorf("%q", got)
	}
}

// --upstream-proxy's words, run -h's and the page's confirm alike, say the
// proxy reads the decrypted requests unmasked; so do --mask-names' (a name
// taken out) and --device's (one added).
func TestWideningWarnings(t *testing.T) {
	for flag, want := range map[string]string{
		"upstream-proxy": "which reads them unmasked (cookies, tokens, bodies",
		"mask-names":     "a name taken out leaves its values unmasked",
		"device":         "decrypted and recorded, for the agents to read",
	} {
		if u := runFlagSet().Lookup(flag).Usage; !strings.Contains(u, want) || settingWarning(flag) != u {
			t.Errorf("--%s: %q", flag, u)
		}
	}
	base, token, _, _, _ := settingsRun(t, "--device=phone\n--allow-hosts=a.example.com")
	if w := settingOf(t, getSettings(t, base, token), "upstream-proxy").Warning; !strings.Contains(w, "reads them unmasked") {
		t.Errorf("the page's confirm: %q", w)
	}
}

// TestPagePresetsE2E (REQCOVE_E2E=1, real mitmproxy): the page's presets
// and rules from a real --rules file, no value of a rule in the answer; a
// map_remote preset turned on with the destination its confirm named, a
// mock for a count; once recording is stopped, mitmproxy refuses one.
func TestPagePresetsE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "rcvr-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	rules := filepath.Join(dir, "rules.yaml")
	os.WriteFile(rules, []byte(`mock:
  - match: {url: "http://127.0.0.1:1/MOCKMARK"}
    preset: slow
    description: DESCMARK
    status: 503
    body: BODYMARK
map_remote:
  - {rule: '|~d 127.0.0.1|^http://127\.0\.0\.1:\d+/REGEXMARK/|https://stage.test:8443/', preset: staging}
modify_headers:
  - '|~d 127.0.0.1|X-Mark|HDRMARK'
`), 0o600)
	state := filepath.Join(dir, "s")
	allow, _ := capture.ParseAllowHosts([]string{"127.0.0.1"})
	c, err := capture.Start(ctx, capture.Config{Dir: state, Confdir: filepath.Join(dir, "m"),
		Uvx: "uvx", Python: defaultPython, MitmSpec: defaultMitmSpec,
		BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
		Log: os.Stderr, ReadyTimeout: 2 * time.Minute, AllowHosts: allow, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	logged := logTo(t)
	if _, err := serveCtl(ctx, state, c, &runOpts{}, nil); err != nil {
		t.Fatal(err)
	}
	base, code := openUI(t, state)
	token := trade(t, base, code)
	r, b := call(t, base, "GET", "/api/presets", "", map[string]string{sessionHeader: token})
	for _, m := range []string{"MOCKMARK", "DESCMARK", "BODYMARK", "REGEXMARK", "HDRMARK", "X-Mark", "~d", "127.0.0.1"} {
		if strings.Contains(b, m) {
			t.Errorf("%s in %s", m, b)
		}
	}
	var d pagePresets
	if r.StatusCode != 200 || json.Unmarshal([]byte(b), &d) != nil || len(d.Presets) != 2 || len(d.Rules) != 3 || !d.Loaded || d.Problem {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	target := ""
	for _, p := range d.Presets {
		if p.Name == "staging" {
			target = p.Target
		}
	}
	if target != "https://stage.test:8443" {
		t.Errorf("target: %q", target)
	}
	if ok, msg := postJSON(t, base, token, "/api/preset", `{"name":"staging","on":true,"minutes":1}`); ok || !strings.Contains(msg, "not where the page's confirm said") {
		t.Errorf("no target: %v %s", ok, msg)
	}
	if ok, msg := postJSON(t, base, token, "/api/preset", `{"name":"staging","on":true,"minutes":1,"target":"`+target+`"}`); !ok || msg != "staging is on for 1m0s" {
		t.Errorf("on: %v %s", ok, msg)
	}
	if ok, msg := postJSON(t, base, token, "/api/preset", `{"name":"slow","on":true,"times":2}`); !ok || msg != "slow is on for 5m0s or 2 requests" {
		t.Errorf("a mock: %v %s", ok, msg)
	}
	ps, _ := c.Presets(ctx)
	for _, p := range ps {
		if !p.Active {
			t.Errorf("not on: %+v", p)
		}
	}
	if ok, msg := postJSON(t, base, token, "/api/preset", `{"name":"slow","on":false}`); !ok || msg != "slow is off" {
		t.Errorf("off: %v %s", ok, msg)
	}
	if a, err := askRun(ctx, state, ctlRequest{Cmd: "stop"}); err != nil || !a.OK {
		t.Fatalf("stop: %v %+v", err, a)
	}
	if ok, msg := postJSON(t, base, token, "/api/preset", `{"name":"slow","on":true}`); ok || !strings.HasPrefix(msg, "refused: recording is stopped") {
		t.Errorf("stopped: %v %s", ok, msg)
	}
	waitLog(t, logged, "reqcove console: the preset staging turned on for 60s"+fromConsole, 1)
}
