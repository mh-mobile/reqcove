package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"maps"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

// `reqcove console` (since v1.2) opens a page of run's state and the agents'
// requests, with Approve and Deny, in this computer's browser. run serves it
// on 127.0.0.1 alone (a port the OS picks), never the tailnet node, the LAN or
// --ui's page, from the first `reqcove console` until run ends. The link carries a
// one-use code (60 s) in its fragment, which the page trades for a session
// token it keeps in sessionStorage and sends as a header: no cookie, so a page
// of another site open in the browser sends nothing that counts. Only in a
// terminal, as the capture commands: a speed bump for an agent, not a
// boundary (any process of this user reaches ctl.sock).

const (
	pageCodeTTL   = 60 * time.Second
	pageIdle      = 12 * time.Hour // a session not used that long ends
	maxSessions   = 4              // a 5th ends the one used least recently
	maxPageCodes  = 32             // codes remembered, used or not, to tell one used twice
	maxPageBody   = 4 << 10
	sessionHeader = "X-Reqcove-Session"
)

//go:embed ui
var pageFiles embed.FS

// openBrowser opens url in the browser (tests stand in for it). The url is
// in its arguments, so `ps` shows the code while it runs (SECURITY says so).
var openBrowser = func(ctx context.Context, url string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second) // xdg-open can wait for the browser
	defer cancel()
	return exec.CommandContext(ctx, name, url).Run()
}

func consoleCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("console", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return uiIn(ctx, os.Stdin, os.Stdout, *state)
}

func uiIn(ctx context.Context, in, out *os.File, state string) error {
	if !terminal(in) || !terminal(out) {
		return errors.New("reqcove console runs only in a terminal: its page approves what agents ask, which is the user's choice (an agent never runs it). Run it in your own terminal")
	}
	a, err := askRun(ctx, state, ctlRequest{Cmd: "console"})
	if err != nil {
		return err
	}
	if !a.OK || a.Port == 0 || a.Code == "" {
		return errors.New(a.Message)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/#c=%s", a.Port, a.Code)
	fmt.Fprintf(out, "%s\n  %s\n", a.Message, url)
	if err := openBrowser(ctx, url); err != nil {
		fmt.Fprintf(out, "not opened in a browser (%v): open the link above yourself\n", err)
	}
	return nil
}

// page is reqcove console's server. Codes and sessions are kept by their hash:
// a lookup times nothing of the value.
type page struct {
	st   *ctlState
	cap  *capture.Capture
	host string // 127.0.0.1:PORT: the only Host taken, and as http://, the only Origin
	mux  *http.ServeMux
	now  func() (mono, wall time.Time)

	mu       sync.Mutex
	codes    map[[32]byte]*pageCode
	sessions map[[32]byte]time.Time // last used (monotonic reading)
}

type pageCode struct {
	made, expires time.Time
	used          bool
}

// openPage is the console op (st.mu held): the page, opened once, and a new code.
func openPage(cap *capture.Capture, st *ctlState) ctlAnswer {
	if st.page == nil {
		p, err := servePage(st.ctx, cap, st)
		if err != nil {
			return ctlAnswer{Message: "refused: the page: " + err.Error()}
		}
		st.page = p
		log.Printf("reqcove console: the page listens on http://%s (this computer only) until run ends", p.host)
	}
	code := st.page.mint()
	_, port, _ := net.SplitHostPort(st.page.host)
	n := 0
	fmt.Sscan(port, &n)
	log.Print("reqcove console: a one-use code given to the terminal (60 s)") // never the code
	return ctlAnswer{OK: true, Port: n, Code: code,
		Message: "the page of this run, on this computer only (until run ends): open the link within 60 s; it works once (run reqcove console again for another)"}
}

// servePage listens on 127.0.0.1 alone until ctx ends.
func servePage(ctx context.Context, cap *capture.Capture, st *ctlState) (*page, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := newPage(cap, st, ln.Addr().String())
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go srv.Serve(ln)
	go func() { <-ctx.Done(); srv.Close() }()
	return p, nil
}

func newPage(cap *capture.Capture, st *ctlState, host string) *page {
	p := &page{st: st, cap: cap, host: host, mux: http.NewServeMux(),
		now:   func() (time.Time, time.Time) { t := time.Now(); return t, t },
		codes: map[[32]byte]*pageCode{}, sessions: map[[32]byte]time.Time{}}
	for path, file := range map[string]string{"/{$}": "index.html", "/app.js": "app.js", "/app.css": "app.css"} {
		p.mux.HandleFunc("GET "+path, p.file(file))
	}
	p.mux.HandleFunc("POST /api/session", p.trade)
	p.mux.HandleFunc("GET /api/state", p.authed(p.state))
	p.mux.HandleFunc("POST /api/approve", p.authed(p.approve))
	p.mux.HandleFunc("POST /api/deny", p.authed(p.deny))
	return p
}

func secret(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// mint is a new code, the oldest remembered dropped past maxPageCodes.
func (p *page) mint() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.codes) >= maxPageCodes {
		oldest := slices.MinFunc(slices.Collect(maps.Keys(p.codes)), func(a, b [32]byte) int { return p.codes[a].made.Compare(p.codes[b].made) })
		delete(p.codes, oldest)
	}
	code := secret(16)
	mono, _ := p.now()
	p.codes[sha256.Sum256([]byte(code))] = &pageCode{made: mono, expires: mono.Add(pageCodeTTL)}
	return code
}

// ServeHTTP checks what every request must pass, then routes it.
func (p *page) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	if r.Host != p.host { // DNS rebinding: a site's own name pointed at 127.0.0.1
		answer(w, http.StatusMisdirectedRequest, map[string]any{"error": "refused: this page answers http://" + p.host + " only"})
		return
	}
	if r.Method == http.MethodPost {
		if o := r.Header.Values("Origin"); len(o) != 1 || o[0] != "http://"+p.host {
			answer(w, http.StatusForbidden, map[string]any{"error": "refused: a change comes from this page only"})
			return
		}
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			answer(w, http.StatusUnsupportedMediaType, map[string]any{"error": "refused: JSON only"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxPageBody)
	}
	p.mux.ServeHTTP(w, r)
}

func answer(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (p *page) file(name string) http.HandlerFunc {
	b, _ := pageFiles.ReadFile("ui/" + name)
	ct := map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "app.css": "text/css; charset=utf-8"}[name]
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.Write(b)
	}
}

// trade is POST /api/session {code}: a session token for a code, once. A
// code used twice (someone else had the link) ends every session.
func (p *page) trade(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code string }
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		answer(w, http.StatusBadRequest, map[string]any{"error": "refused: not a code"})
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	mono, wall := p.now()
	c := p.codes[sha256.Sum256([]byte(in.Code))]
	switch {
	case c == nil:
		answer(w, http.StatusForbidden, map[string]any{"error": "this link's code is not one this run gave (run restarted?): run reqcove console again in your terminal"})
		return
	case c.used:
		clear(p.sessions)
		log.Print("reqcove console: a code was used twice: every session of the page ended (someone else opened the link?)")
		answer(w, http.StatusForbidden, map[string]any{"error": "this link was opened already: every page of reqcove console is closed now, as someone else may have it; run reqcove console again in your terminal"})
		return
	case due(c.expires, mono, wall):
		answer(w, http.StatusForbidden, map[string]any{"error": "this link expired (it lasts 60 s): run reqcove console again in your terminal"})
		return
	}
	c.used = true
	if len(p.sessions) >= maxSessions {
		lru := slices.MinFunc(slices.Collect(maps.Keys(p.sessions)), func(a, b [32]byte) int { return p.sessions[a].Compare(p.sessions[b]) })
		delete(p.sessions, lru)
	}
	token := secret(32)
	p.sessions[sha256.Sum256([]byte(token))] = mono
	answer(w, http.StatusOK, map[string]any{"token": token})
}

// authed takes requests with a live session in their header alone.
func (p *page) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.live(r.Header.Get(sessionHeader)) {
			answer(w, http.StatusUnauthorized, map[string]any{"error": "no session (ended, or run restarted): run reqcove console again in your terminal"})
			return
		}
		next(w, r)
	}
}

func (p *page) live(token string) bool {
	if token == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k := sha256.Sum256([]byte(token))
	last, ok := p.sessions[k]
	mono, wall := p.now()
	if ok && due(last.Add(pageIdle), mono, wall) {
		delete(p.sessions, k)
		ok = false
	}
	if ok {
		p.sessions[k] = mono
	}
	return ok
}

// pageState is what the page shows: named fields of the status, never the
// whole (no flow contents, no token or link, no agent's or client's text:
// markers, presets, scope_change, the hosts seen outside the scope).
type pageState struct {
	Version      string        `json:"version"`
	Executable   string        `json:"executable,omitempty"`
	Service      string        `json:"service,omitempty"`
	Manager      string        `json:"manager,omitempty"`
	ConfigFile   string        `json:"config_file,omitempty"`
	ConfigUnused string        `json:"config_unused,omitempty"`
	HostsFiles   []string      `json:"hosts_files,omitempty"`
	KeepAwake    string        `json:"keep_awake,omitempty"`
	Mode         string        `json:"mode"`
	Node         string        `json:"node,omitempty"`
	IPs          []string      `json:"ips,omitempty"`
	ExitApproved bool          `json:"exit_node_approved"`
	Devices      []string      `json:"devices"`
	Recording    string        `json:"recording"`
	Hosts        []string      `json:"hosts"` // base_allow_hosts: recorded while on
	PassHosts    []string      `json:"pass_hosts,omitempty"`
	AllowAll     string        `json:"allow_all_until,omitempty"`
	ScopePending string        `json:"scope_pending,omitempty"`
	NextSteps    []string      `json:"next_steps"`
	Requests     []pageRequest `json:"requests"`
}

type pageRequest struct {
	ID        string   `json:"id"`
	Hosts     []string `json:"hosts"`
	ExpiresAt string   `json:"expires_at"`
	Masked    string   `json:"masked"`
}

func (p *page) state(w http.ResponseWriter, _ *http.Request) {
	var s mcpserver.StatusOut
	if p.st.status != nil {
		s = p.st.status()
	}
	n, _ := s.Node.(exitnode.Status)
	out := pageState{Version: s.Version, Executable: s.Executable, Service: s.Service, Manager: s.Manager,
		ConfigFile: s.ConfigFile, ConfigUnused: s.ConfigUnused, HostsFiles: s.HostsFiles, Mode: s.Mode,
		Node: n.Node, IPs: n.IPs, ExitApproved: n.ExitApproved, Devices: slices.Sorted(maps.Values(n.Devices)),
		Recording: s.Recording, Hosts: s.BaseAllowHosts, PassHosts: s.BasePassHosts, AllowAll: s.AllowAllUntil,
		ScopePending: s.ScopePending, NextSteps: s.NextSteps, Requests: []pageRequest{}}
	if s.KeepAwake != "" {
		out.KeepAwake = keepAwakeText(s.KeepAwake)
	}
	for _, r := range p.st.reqs.pending() {
		out.Requests = append(out.Requests, pageRequest{ID: r.ID, Hosts: r.Hosts, ExpiresAt: r.ExpiresAt, Masked: mcpserver.Masked(r)})
	}
	answer(w, http.StatusOK, out)
}

// approve and deny go as reqcove capture approve and deny do (answerCtl):
// approve with the hosts the page showed, which run checks are the request's.
func (p *page) approve(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID    string
		Hosts []string
	}
	p.change(w, r, &in, func() ctlRequest { return ctlRequest{Cmd: "approve", ID: in.ID, Hosts: in.Hosts, Via: "console"} })
}

func (p *page) deny(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	p.change(w, r, &in, func() ctlRequest { return ctlRequest{Cmd: "deny", ID: in.ID, Via: "console"} })
}

func (p *page) change(w http.ResponseWriter, r *http.Request, in any, req func() ctlRequest) {
	if json.NewDecoder(r.Body).Decode(in) != nil {
		answer(w, http.StatusBadRequest, map[string]any{"error": "refused: not JSON of the page"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), ctlWait-time.Second)
	defer cancel()
	a := answerCtl(ctx, p.cap, p.st, req()) // never under p.mu: the console op takes st.mu, then p.mu
	answer(w, http.StatusOK, map[string]any{"ok": a.OK, "message": a.Message})
}
