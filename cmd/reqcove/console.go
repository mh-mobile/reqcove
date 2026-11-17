package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"maps"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

// `reqcove console` (since v1.2) opens a page of run's state and the agents'
// requests, with Approve and Deny, in this computer's browser. run serves it
// on 127.0.0.1 alone (a port the OS picks), never the tailnet node, the LAN or
// --ui's page, from the first `reqcove console` until run ends (reqcove
// restart carries it and its sessions across: restart.go). The link carries a
// one-use code (60 s) in its fragment, which the page trades for a session
// token it keeps in sessionStorage and sends as a header: no cookie, so a page
// of another site open in the browser sends nothing that counts. The browser
// gets the link from a file run writes in the state directory (since v1.3),
// never from the opener's arguments, which `ps` shows other users. Only in a
// terminal, as the capture commands: a speed bump for an agent, not a
// boundary (any process of this user reaches ctl.sock). `reqcove console
// --end` ends every session and unused code.
//
// `reqcove console --tailnet` (since v1.3) opens a second page, for this
// user's own devices on the tailnet (an iPhone scanning its QR code): on the
// node's tailnet address, a port of its own (not --ui's :80: another origin),
// with its own codes and sessions. It serves only what ends with the run (no
// file written, no setting, no restart, no HAR: refused there), and checks on
// every request who calls, from the connection (never a header): one of this
// user's own devices (untagged, of the node's user), the one that traded the
// code. Its sessions last 1 h idle and 12 h in all, and end with the run.

const (
	pageCodeTTL   = 60 * time.Second
	pageIdle      = 12 * time.Hour // a session not used that long ends
	maxSessions   = 4              // a 5th ends the one used least recently
	maxPageCodes  = 32             // codes remembered, used or not, to tell one used twice
	maxPageBody   = 4 << 10
	sessionHeader = capture.ConsoleSessionHeader
	tailnetIdle   = time.Hour      // the tailnet page's: a session not used that long ends
	tailnetCap    = 12 * time.Hour // and none lasts longer
)

// The tailnet page's listener (on the node's tailnet IPv4 address), who a
// connection's address is (one of this user's own devices), and the Remote
// Proxy's relay of the page's requests (a phone whose Wi-Fi proxy is the
// Remote Proxy sends them there); tests stand in for them.
var (
	listenTailnet = exitnode.ListenConsole
	ownDeviceAt   = exitnode.OwnDeviceAt
	relayTailnet  = exitnode.RelayConsole
)

//go:embed ui
var pageFiles embed.FS

// openBrowser opens file, the code file run wrote, in the browser (tests
// stand in for it). Never the link: `ps` shows other users the arguments.
var openBrowser = func(ctx context.Context, file string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second) // xdg-open can wait for the browser
	defer cancel()
	return exec.CommandContext(ctx, name, file).Run()
}

func consoleCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("console", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	end := fs.Bool("end", false, "end every session of the pages and every link not opened yet")
	tailnet := fs.Bool("tailnet", false, "open the page for your own devices on the tailnet (a QR code for the iPhone): only what ends with the run, never a file written, a setting or a restart")
	printLink := fs.Bool("print", false, "print a link to this computer's page (it works once, for 60 s) and open nothing")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	switch {
	case *end && (*tailnet || *printLink):
		return errors.New("reqcove console --end ends every page's sessions, the tailnet page's too: give it alone")
	case *tailnet && *printLink:
		return errors.New("reqcove console --tailnet prints its link already and opens nothing: give it without --print")
	case *end:
		return endIn(ctx, os.Stdin, os.Stdout, *state)
	case *tailnet:
		return tailnetIn(ctx, os.Stdin, os.Stdout, *state)
	}
	return uiIn(ctx, os.Stdin, os.Stdout, *state, *printLink)
}

// errOlderTailnet: a run older than v1.3 takes the tailnet op as the local
// page's (it does not know the field) and answers no tailnet address.
var errOlderTailnet = errors.New("this run is older than v1.3, which has no page on the tailnet: restart it with v1.3 or later (a restart empties the records); nothing opened on the tailnet")

// tailnetIn is `reqcove console --tailnet`: the link, with its code, as a QR
// code and as text, in this terminal alone (no browser opened, no file).
func tailnetIn(ctx context.Context, in, out *os.File, state string) error {
	if !terminal(in) || !terminal(out) {
		return errNotTerminal
	}
	a, err := askRun(ctx, state, ctlRequest{Cmd: "console", Tailnet: true})
	if errors.Is(err, errOlderUI) {
		return errOlderTailnet
	}
	if err != nil {
		return err
	}
	if !a.OK || a.Code == "" {
		return errors.New(a.Message)
	}
	if ap, err := netip.ParseAddrPort(a.Addr); err != nil || !ap.Addr().Is4() {
		return errOlderTailnet
	}
	url := fmt.Sprintf("http://%s/#c=%s", a.Addr, a.Code)
	fmt.Fprintf(out, "%s\n%s  %s\n", a.Message, sideBySide([]qrItem{{caption: "the page, for the iPhone's camera", url: url}}, 0), url)
	return nil
}

var errNotTerminal = errors.New("reqcove console runs only in a terminal: its page approves what agents ask, which is the user's choice (an agent never runs it). Run it in your own terminal")

// uiIn is `reqcove console`: the page opened in the browser through the code
// file, and its link printed only when it was not (printing it too would let
// the user use the code twice, which ends every session, the one just
// opened too); printLink (--print): the link printed, nothing opened.
func uiIn(ctx context.Context, in, out *os.File, state string, printLink bool) error {
	if !terminal(in) || !terminal(out) {
		return errNotTerminal
	}
	a, err := askRun(ctx, state, ctlRequest{Cmd: "console"})
	if err != nil {
		return err
	}
	if !a.OK || a.Port == 0 || a.Code == "" {
		return errors.New(a.Message)
	}
	hasFile := codeFileName.MatchString(a.File) // none: a v1.2 run, or run could not write it
	why := ""
	switch {
	case printLink:
		if hasFile {
			os.Remove(filepath.Join(state, a.File)) // nothing opens it (run would remove it after 60 s)
		}
	case !hasFile:
		why = "not opened in a browser (that would show the link to this computer's other users): open the link above yourself"
	default:
		file, err := filepath.Abs(filepath.Join(state, a.File))
		if err == nil {
			err = openBrowser(ctx, file)
		}
		if err == nil {
			fmt.Fprintf(out, "%s\nopened in your browser (the link works once). Not opened, or another browser? reqcove console --print prints a link instead and opens nothing\n", a.Message)
			return nil
		}
		why = fmt.Sprintf("not opened in a browser (%v): open the link above yourself", err)
	}
	fmt.Fprintf(out, "%s\n  http://127.0.0.1:%d/#c=%s\n", a.Message, a.Port, a.Code)
	if why != "" {
		fmt.Fprintln(out, why)
	}
	return nil
}

// endIn is `reqcove console --end`.
func endIn(ctx context.Context, in, out *os.File, state string) error {
	if !terminal(in) || !terminal(out) {
		return errNotTerminal
	}
	return sendCapture(ctx, out, state, ctlRequest{Cmd: "console-end"})
}

// The code file: a page that sends the browser to the link, in the state
// directory (0700), 0600, removed after codeFileTTL, at --end and when run
// starts and ends.
var (
	codeFileName = regexp.MustCompile(`^console-[0-9a-f]{32}\.html$`)
	codeFileTTL  = pageCodeTTL // tests shorten it
)

// writeCodeFile creates path, never one there already nor through a
// symlink, holding a page that sends the browser to url.
func writeCodeFile(path, url string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	u := html.EscapeString(url)
	_, err = fmt.Fprintf(f, `<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url=%s"><title>Reqcove</title><p><a href="%s">Open reqcove console</a> (this file is removed within 60 s)</p>`+"\n", u, u)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}

// sweepCodeFiles removes the code files in dir; how many.
func sweepCodeFiles(dir string) int {
	n := 0
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if codeFileName.MatchString(e.Name()) && os.Remove(filepath.Join(dir, e.Name())) == nil {
			n++
		}
	}
	return n
}

// page is reqcove console's server. Codes and sessions are kept by their hash:
// a lookup times nothing of the value.
type page struct {
	st      *ctlState
	cap     *capture.Capture
	presets mcpserver.Presets // cap's, or none (tests stand in for it)
	host    string            // 127.0.0.1:PORT: the only Host taken, and as http://, the only Origin
	sock    *os.File          // the listening socket, kept for a restart (serveOn)
	mux     *http.ServeMux
	now     func() (mono, wall time.Time)

	tailnet  bool // the tailnet page (console --tailnet)
	mu       sync.Mutex
	codes    map[[32]byte]*pageCode
	sessions map[[32]byte]pageSession
}

// pageSession is a session's: when it was last used and made (monotonic
// readings), and on the tailnet page, the device that traded the code (its
// StableID, and its name for status and the traces).
type pageSession struct {
	last, made time.Time
	device     exitnode.Device
}

type pageCode struct {
	made, expires time.Time
	used, ended   bool // ended: by reqcove console --end, unused
}

// openPage is the console op (st.mu held): the page, opened once, and a new code.
func openPage(cap *capture.Capture, st *ctlState, tailnet bool) ctlAnswer {
	if tailnet {
		return openTailnet(cap, st)
	}
	if st.page == nil {
		p, err := servePage(st.ctx, cap, st)
		if err != nil {
			return ctlAnswer{Message: "refused: the page: " + err.Error()}
		}
		st.page = p
		st.pageNow.Store(p)
		log.Printf("reqcove console: the page listens on http://%s (this computer only) until run ends", p.host)
	}
	code := st.page.mint()
	_, port, _ := net.SplitHostPort(st.page.host)
	n := 0
	fmt.Sscan(port, &n)
	log.Print("reqcove console: a one-use code given to the terminal (60 s)") // never the code
	a := ctlAnswer{OK: true, Port: n, Code: code,
		Message: "the page of this run, on this computer only (until run ends): open the link within 60 s; it works once (run reqcove console again for another)"}
	name := "console-" + secret(16) + ".html"
	path := filepath.Join(st.dir, name)
	if err := writeCodeFile(path, fmt.Sprintf("http://127.0.0.1:%d/#c=%s", n, code)); err != nil {
		log.Printf("reqcove console: the file that opens the page not written (%v): the terminal prints the link alone", err) // the path only
		return a
	}
	time.AfterFunc(codeFileTTL, func() { os.Remove(path) })
	a.File = name
	return a
}

// endPage is the console-end op (st.mu held): every session and unused code
// ended, the code files removed.
func endPage(st *ctlState) ctlAnswer {
	sweepCodeFiles(st.dir)
	if st.page == nil && st.tailnet.Load() == nil {
		return ctlAnswer{OK: true, Message: "no page of reqcove console was opened in this run: nothing to end"}
	}
	sessions, codes := 0, 0
	for _, p := range []*page{st.page, st.tailnet.Load()} {
		if p == nil {
			continue
		}
		p.mu.Lock()
		sessions += len(p.sessions)
		clear(p.sessions)
		mono, wall := p.now()
		for _, c := range p.codes {
			if !c.used && !c.ended && !due(c.expires, mono, wall) {
				codes++
			}
			c.ended = !c.used
		}
		p.mu.Unlock()
	}
	log.Printf("reqcove console --end: %d sessions and %d unused links ended", sessions, codes)
	return ctlAnswer{OK: true, Message: fmt.Sprintf("ended: %d sessions of the page and %d links not opened yet; open pages say so (reqcove console opens a new one)", sessions, codes)}
}

// servePage listens on 127.0.0.1 alone until ctx ends.
func servePage(ctx context.Context, cap *capture.Capture, st *ctlState) (*page, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f, err := ln.(*net.TCPListener).File() // close-on-exec, as Go makes every fd
	if err != nil {
		ln.Close()
		return nil, err
	}
	return serveOn(ctx, cap, st, ln, f, nil), nil
}

// serveOn serves the page on ln until ctx ends, with sessions (a restart's,
// each as idle as it was) in place before the first request; f, a copy of
// ln's socket kept open for run's life, holds the port while ln is closed,
// until a restart carries it across its exec (restart.go).
func serveOn(ctx context.Context, cap *capture.Capture, st *ctlState, ln net.Listener, f *os.File, sessions []carriedSession) *page {
	p := newPage(cap, st, ln.Addr().String(), false)
	p.sock = f
	p.mu.Lock()
	mono, _ := p.now()
	for _, s := range sessions {
		p.sessions[s.hash] = pageSession{last: mono.Add(-s.idle), made: mono.Add(-s.idle)}
	}
	p.mu.Unlock()
	srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go srv.Serve(ln)
	go func() { <-ctx.Done(); srv.Close() }()
	return p
}

// carriedPage is the page a restart carried across its exec (h.pageLn), with
// its sessions, each as idle as it was.
// A retry carries this page's sessions as they are then (h.served): never
// the list handed over, which --end or a session traded may have changed.
func carriedPage(ctx context.Context, cap *capture.Capture, st *ctlState, h *handover) *page {
	p := serveOn(ctx, cap, st, h.pageLn, h.page, h.sessions)
	h.served = p
	log.Printf("reqcove console: the page carried across the restart, on http://%s (this computer only), with %d sessions", p.host, len(h.sessions))
	return p
}

// carry is the page's live sessions, by hash (never a token), for a restart.
func (p *page) carry() []carriedSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	mono, wall := p.now()
	var out []carriedSession
	for k, s := range p.sessions {
		if !p.over(s, mono, wall) {
			out = append(out, carriedSession{hash: k, idle: mono.Sub(s.last)})
		}
	}
	return out
}

// pageRoutes are the page's API, behind a session; tailnet: served on the
// tailnet page too (only what ends with the run). Any other is refused there:
// a route added later stays this computer's until it says otherwise.
type pageRoute struct {
	pattern string
	h       func(*page, http.ResponseWriter, *http.Request)
	tailnet bool
}

func pageRoutes() []pageRoute {
	return []pageRoute{
		{"GET /api/state", (*page).state, true},
		{"POST /api/approve", (*page).approve, true},
		{"POST /api/deny", (*page).deny, true},
		{"POST /api/change", (*page).scope, true}, // save refused there (scope)
		{"GET /api/presets", (*page).presetList, true},
		{"POST /api/preset", (*page).presetSet, true},
		{"POST /api/marker", (*page).marker, true},
		{"GET /api/ca", (*page).ca, true},
		{"GET /api/save", (*page).saveDiff, false},
		{"GET /api/settings", (*page).settings, false},
		{"POST /api/settings", (*page).setSetting, false},
		{"GET /api/restart", (*page).restartDiff, false},
		{"POST /api/restart", (*page).restartNow, false},
		{"GET /api/har", (*page).harFile, false},
	}
}

// localOnly is the tailnet page's answer to this computer's routes.
const localOnly = "refused: on the tailnet page only what ends with the run (no file written, no setting, no restart, no HAR): this is the page on this computer's (reqcove console)"

func newPage(cap *capture.Capture, st *ctlState, host string, tailnet bool) *page {
	p := &page{st: st, cap: cap, host: host, mux: http.NewServeMux(), tailnet: tailnet,
		now:   func() (time.Time, time.Time) { t := time.Now(); return t, t },
		codes: map[[32]byte]*pageCode{}, sessions: map[[32]byte]pageSession{}}
	if cap != nil {
		p.presets = cap
	}
	for path, file := range map[string]string{"/{$}": "index.html", "/app.js": "app.js", "/app.css": "app.css"} {
		p.mux.HandleFunc("GET "+path, p.file(file))
	}
	p.mux.HandleFunc("POST /api/session", p.trade)
	for _, rt := range pageRoutes() {
		h := func(w http.ResponseWriter, r *http.Request) { rt.h(p, w, r) }
		if tailnet && !rt.tailnet {
			h = func(w http.ResponseWriter, _ *http.Request) {
				answer(w, http.StatusForbidden, map[string]any{"error": localOnly})
			}
		}
		p.mux.HandleFunc(rt.pattern, p.authed(h))
	}
	return p
}

// openTailnet is the console op with --tailnet (st.mu held): the tailnet
// page, opened once, and a new code. Never a code file: the terminal shows
// the link and its QR code.
func openTailnet(cap *capture.Capture, st *ctlState) ctlAnswer {
	if st.o.lanMode {
		return ctlAnswer{Message: "refused: in LAN mode there is no tailnet node, so no page on it (reqcove console opens this computer's); nothing opened"}
	}
	p := st.tailnet.Load()
	if p == nil {
		ln, err := listenTailnet()
		if err != nil {
			return ctlAnswer{Message: "refused: the page on the tailnet: " + err.Error() + "; nothing opened"}
		}
		p = newPage(cap, st, ln.Addr().String(), true)
		srv := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second,
			IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
		go srv.Serve(ln)
		go func() { <-st.ctx.Done(); srv.Close() }()
		relayTailnet(st.ctx, p.host, p) // the page's own handler: its checks on every request, as here
		st.tailnet.Store(p)
		log.Printf("reqcove console --tailnet: the page listens on http://%s, for your own devices on the tailnet, until run ends", p.host)
	}
	code := p.mint()
	log.Print("reqcove console --tailnet: a one-use code given to the terminal (60 s)") // never the code
	return ctlAnswer{OK: true, Code: code, Addr: p.host,
		Message: "the page of this run for your own devices on the tailnet (only what ends with the run: no file written, no setting, no restart), until run ends: scan the QR code, or open the link, within 60 s, on one of your own devices with the tailnet on; it works once, and the page then works on that device alone (run reqcove console --tailnet again for another)"}
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
	if p.tailnet {
		// Who calls, from the connection alone, on every request: a kept-alive
		// connection outlives a device retagged or removed.
		d, ok := ownDeviceAt(r.RemoteAddr)
		d.Name = cmp.Or(d.Name, d.ID) // a peer without a MagicDNS name: never traced as this computer's
		if !ok {
			h.Set("Connection", "close")
			answer(w, http.StatusForbidden, map[string]any{"error": "refused: only your own devices on the tailnet (the same user as reqcove's node, neither tagged)"})
			return
		}
		// Another origin's request (--ui's page on :80 among them) is never one of this page's.
		if o := r.Header.Values("Origin"); len(o) > 0 && (len(o) != 1 || o[0] != "http://"+p.host) {
			h.Set("Connection", "close")
			answer(w, http.StatusForbidden, map[string]any{"error": "refused: this page's requests come from this page only"})
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), callerKey{}, d))
		np := &noPaths{ResponseWriter: w, dir: p.st.dir}
		defer np.flush()
		w = np
	}
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
	case c.ended:
		answer(w, http.StatusForbidden, map[string]any{"error": "this link was ended (reqcove console --end): run reqcove console again in your terminal"})
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
		lru := slices.MinFunc(slices.Collect(maps.Keys(p.sessions)), func(a, b [32]byte) int { return p.sessions[a].last.Compare(p.sessions[b].last) })
		delete(p.sessions, lru)
	}
	token := secret(32)
	d, _ := caller(r) // the tailnet page's: the device that traded the code (ServeHTTP checked it)
	p.sessions[sha256.Sum256([]byte(token))] = pageSession{last: mono, made: mono, device: d}
	if p.tailnet {
		log.Printf("reqcove console --tailnet: a session for %s", d.Name)
	}
	answer(w, http.StatusOK, map[string]any{"token": token})
}

// callerKey: the tailnet page's caller, in a request's context.
type callerKey struct{}

// caller is the device that sent r to the tailnet page (ServeHTTP's check);
// none on this computer's page.
func caller(r *http.Request) (exitnode.Device, bool) {
	d, ok := r.Context().Value(callerKey{}).(exitnode.Device)
	return d, ok
}

// from ends the trace of a change made on the page r came to.
func from(r *http.Request) string {
	d, _ := caller(r)
	return consoleFrom(d.Name)
}

// over: s has ended (idle too long; on the tailnet page, or made too long ago).
func (p *page) over(s pageSession, mono, wall time.Time) bool {
	if !p.tailnet {
		return due(s.last.Add(pageIdle), mono, wall)
	}
	return due(s.last.Add(tailnetIdle), mono, wall) || due(s.made.Add(tailnetCap), mono, wall)
}

// count is the live sessions, by device name on the tailnet page.
func (p *page) count() (n int, by map[string]int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	mono, wall := p.now()
	for _, s := range p.sessions {
		if p.over(s, mono, wall) {
			continue
		}
		n++
		if p.tailnet {
			if by == nil {
				by = map[string]int{}
			}
			by[s.device.Name]++
		}
	}
	return n, by
}

// authed takes requests with a live session in their header alone.
func (p *page) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, _ := caller(r)
		if !p.live(r.Header.Get(sessionHeader), d) {
			why := "no session: ended (by reqcove console --end, a link opened twice or 12 h idle), or run was stopped and started again: run reqcove console again in your terminal"
			if p.tailnet {
				why = "no session on this device: ended (by reqcove console --end, a link opened twice, 1 h idle or 12 h in all, or used from another device), or run restarted: run reqcove console --tailnet again in your terminal"
			}
			answer(w, http.StatusUnauthorized, map[string]any{"error": why})
			return
		}
		next(w, r)
	}
}

// live: token is a session of this page's, not ended; on the tailnet page,
// the one device d traded the code for (its StableID). Used from another
// device, it ends: someone else has the token.
func (p *page) live(token string, d exitnode.Device) bool {
	if token == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	k := sha256.Sum256([]byte(token))
	s, ok := p.sessions[k]
	mono, wall := p.now()
	switch {
	case !ok:
		return false
	case p.over(s, mono, wall):
		delete(p.sessions, k)
		return false
	case p.tailnet && (s.device.ID == "" || s.device.ID != d.ID):
		delete(p.sessions, k)
		log.Printf("reqcove console --tailnet: %s's session used from %s: ended", s.device.Name, d.Name)
		return false
	}
	s.last = mono
	p.sessions[k] = s
	return true
}

// pageState is what the page shows: named fields of the status, never the
// whole (no flow contents, no token or link, no agent's or client's text:
// markers, presets, scope_change); of the hosts seen outside the scope
// (discovery's), the names that are hosts alone, with their counts.
type pageState struct {
	Version      string        `json:"version"`
	Executable   string        `json:"executable,omitempty"`
	Service      string        `json:"service,omitempty"`
	Manager      string        `json:"manager,omitempty"`
	ServiceCmds  []string      `json:"service_commands,omitempty"` // local paths: the local page's alone
	FlowsURL     string        `json:"flows_url,omitempty"`        // --ui's page, bare: never its token
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
	// The scope panel's: the revision a change sends back (a change on an
	// older one is refused); the hosts the hosts files hold now and those given
	// as they are (pinned: a start takes them whatever the files say), for
	// the "unsaved" badges; discovery's; the warnings shown before a confirm.
	Rev            string       `json:"rev"`
	Saved          []string     `json:"saved"`
	PassSaved      []string     `json:"pass_saved"`
	Pinned         []string     `json:"pinned"`
	PassPinned     []string     `json:"pass_pinned"`
	DiscoverUntil  string       `json:"discover_until,omitempty"`
	Discovered     []pageHost   `json:"discovered"`
	DiscoveredKept int          `json:"discovered_kept,omitempty"`
	Warnings       pageWarnings `json:"warnings"`
	// Tailnet: the tailnet page's state: no local path, discovery's names
	// as their count alone (discovered_kept); its panels are what ends with the run.
	Tailnet bool `json:"tailnet,omitempty"`
	// Started is when this process started: a restart (an exec) changes it.
	Started string `json:"started"`
}

// pageStarted is pageState.Started.
var pageStarted = time.Now().Format(time.RFC3339)

// pageHost is a name host discovery saw: a host (capture.ValidHost) alone,
// never a command; the page puts it in as text.
type pageHost struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// pageWarnings are the CLI's own warnings of stop, remove and allow-all
// (their answers carry the same words), shown before the page's confirm.
type pageWarnings struct {
	Stop     string `json:"stop"`
	Remove   string `json:"remove"`
	AllowAll string `json:"allow_all"`
}

type pageRequest struct {
	ID        string   `json:"id"`
	Hosts     []string `json:"hosts"`
	ExpiresAt string   `json:"expires_at"`
	Masked    string   `json:"masked"`
}

func (p *page) state(w http.ResponseWriter, r *http.Request) {
	rev := p.st.revision() // before the scope: a change in between makes it stale, never the other way
	var s mcpserver.StatusOut
	if p.st.status != nil {
		s = p.st.status()
	}
	n, _ := s.Node.(exitnode.Status)
	o := p.st.originNow.Load()
	out := pageState{Version: s.Version, Executable: s.Executable, Service: s.Service, Manager: s.Manager,
		ConfigFile: s.ConfigFile, ConfigUnused: s.ConfigUnused, HostsFiles: p.st.hostsFiles(), Mode: s.Mode,
		Node: n.Node, IPs: n.IPs, ExitApproved: n.ExitApproved, Devices: slices.Sorted(maps.Values(n.Devices)),
		Recording: s.Recording, Hosts: s.BaseAllowHosts, PassHosts: s.BasePassHosts, AllowAll: s.AllowAllUntil,
		ScopePending: s.ScopePending, NextSteps: s.NextSteps, Requests: []pageRequest{},
		Rev: rev, Saved: fileHosts(o.files), PassSaved: fileHosts(o.passOrigin().files),
		Pinned: slices.Sorted(maps.Keys(o.given)), PassPinned: slices.Sorted(maps.Keys(o.passOrigin().given)),
		DiscoverUntil: s.DiscoverUntil, Discovered: []pageHost{}, DiscoveredKept: s.OutOfScopeHostsKept,
		Warnings: pageWarnings{Stop: stopWarning, Remove: removeWarning(), AllowAll: allowAllWarning()}}
	if s.KeepAwake != "" {
		out.KeepAwake = keepAwakeText(s.KeepAwake)
	}
	out.Started = pageStarted
	out.ServiceCmds = serviceCommands(s.Service, s.Manager, p.st.dir)
	out.FlowsURL = flowsURL(p.st.o, n.IPs)
	for _, r := range p.st.reqs.pending() {
		out.Requests = append(out.Requests, pageRequest{ID: r.ID, Hosts: r.Hosts, ExpiresAt: r.ExpiresAt, Masked: mcpserver.Masked(r)})
	}
	for _, h := range s.OutOfScopeHosts {
		if capture.ValidHost(h.Host) && len(out.Discovered) < mcpserver.MaxOutHosts && !p.tailnet {
			out.Discovered = append(out.Discovered, pageHost{Host: h.Host, Count: h.Count})
		}
	}
	if p.tailnet { // this computer's paths and files stay on its page (noPaths takes those in the words)
		out.Tailnet, out.Executable, out.ConfigFile, out.ConfigUnused, out.HostsFiles, out.ServiceCmds = true, "", "", "", nil, nil
		out.NextSteps = tailnetSteps(out.NextSteps, p.st.dir)
		out.DiscoveredKept = s.OutOfScopeHostsKept
	}
	answer(w, http.StatusOK, out)
}

// fileHosts are the hosts in files now (a file not read gives none).
func fileHosts(files []string) []string {
	out := []string{}
	for _, f := range files {
		v, err := hostList("@" + f)
		if err != nil || v == "" {
			continue
		}
		r, _ := capture.ParseAllowHosts(hostsOf(v))
		out = append(out, r.Hosts...)
	}
	return out
}

// pageOps are the changes the page makes, as reqcove capture does: never
// set (the CLI's alone), reload, restart, console, nor the request ops
// (approve and deny have their own).
var pageOps = map[string]bool{"add": true, "remove": true, "stop": true, "start": true, "save": true, "allow-all": true, "discover": true}

// scope is POST /api/change: one of pageOps, with the scope revision the
// page read, made as reqcove capture makes it (answerCtl checks it again),
// traced as made from the console.
func (p *page) scope(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Cmd     string   `json:"cmd"`
		Hosts   []string `json:"hosts"`
		Pass    bool     `json:"pass"`
		For     string   `json:"for"`
		End     bool     `json:"end"`
		Confirm string   `json:"confirm"`
		Rev     string   `json:"rev"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil {
		answer(w, http.StatusBadRequest, map[string]any{"error": "refused: not JSON of the page"})
		return
	}
	if p.tailnet && in.Cmd == "save" { // a file written: this computer's page's
		answer(w, http.StatusForbidden, map[string]any{"error": localOnly + "; nothing written"})
		return
	}
	if !pageOps[in.Cmd] || in.Rev == "" {
		answer(w, http.StatusBadRequest, map[string]any{"error": "refused: the page changes the hosts with add, remove, stop, start, save, allow-all and discover alone, and the scope it read (capture set and reload are your terminal's; a restart is the Restart button's); nothing changed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), ctlWait-time.Second)
	defer cancel()
	d, _ := caller(r)
	a := answerCtl(ctx, p.cap, p.st, ctlRequest{Cmd: in.Cmd, Hosts: in.Hosts, Pass: in.Pass, For: in.For, End: in.End, Confirm: in.Confirm, rev: in.Rev, from: "console", device: d.Name})
	answer(w, http.StatusOK, map[string]any{"ok": a.OK, "message": a.Message})
}

// pageSave is GET /api/save: what Save would write, before the page's
// confirm. message: refused, or nothing to save (no confirm then).
type pageSave struct {
	Message string         `json:"message,omitempty"`
	Files   []pageSaveFile `json:"files,omitempty"`
	Pinned  []string       `json:"pinned,omitempty"`     // hosts on now, given as they are: not written
	Config  string         `json:"config,omitempty"`     // the --config file the lines go to
	Add     []string       `json:"config_add,omitempty"` // the lines added to it (a file created)
	Notes   []string       `json:"notes,omitempty"`
	Confirm string         `json:"confirm,omitempty"` // the token of this change, sent back with save
}

type pageSaveFile struct {
	Path    string   `json:"path"`
	Pass    bool     `json:"pass,omitempty"`
	Created bool     `json:"created,omitempty"`
	Now     []string `json:"now"`   // its hosts now
	Write   []string `json:"write"` // its hosts once saved
}

// saveDiff is GET /api/save: capture save's plan (planSave), nothing written.
func (p *page) saveDiff(w http.ResponseWriter, _ *http.Request) {
	if p.st.o.lanMode || p.cap == nil {
		answer(w, http.StatusOK, pageSave{Message: "refused: in LAN mode the hosts recorded are the ones run started with: nothing to save; nothing written"})
		return
	}
	p.st.mu.Lock()
	defer p.st.mu.Unlock()
	base := p.cap.Base()
	sp, no := planSave(base, p.st)
	if no != "" {
		answer(w, http.StatusOK, pageSave{Message: no + "; nothing written"})
		return
	}
	if len(sp.saves) == 0 {
		answer(w, http.StatusOK, pageSave{Message: strings.Join(append([]string{"nothing to save: the hosts are all given as they are (a start takes them again)"}, sp.notes...), "; ")})
		return
	}
	out := pageSave{Notes: sp.notes, Confirm: sp.token}
	for _, s := range sp.saves {
		f := pageSaveFile{Path: s.path, Pass: s.pass, Created: s.created, Now: []string{}, Write: append([]string{}, s.hosts...)}
		if !s.created {
			f.Now = fileHosts([]string{s.path})
		}
		out.Files = append(out.Files, f)
	}
	for _, l := range []struct {
		o     hostsOrigin
		hosts []string
	}{{p.st.origin, base.Hosts}, {p.st.origin.passOrigin(), base.PassHosts}} {
		written := savable(l.hosts, l.o)
		for _, h := range l.hosts {
			if _, ok := l.o.given[h]; ok && !slices.Contains(written, h) && !slices.Contains(out.Pinned, h) {
				out.Pinned = append(out.Pinned, h)
			}
		}
	}
	if sp.plan != nil {
		out.Config, out.Add = p.st.o.config, sp.plan.added
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
	d, _ := caller(r)
	p.change(w, r, &in, func() ctlRequest {
		return ctlRequest{Cmd: "approve", ID: in.ID, Hosts: in.Hosts, Via: "console", device: d.Name}
	})
}

func (p *page) deny(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID string }
	d, _ := caller(r)
	p.change(w, r, &in, func() ctlRequest { return ctlRequest{Cmd: "deny", ID: in.ID, Via: "console", device: d.Name} })
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

// noPaths holds the tailnet page's answer and gives it with every path of
// this computer taken out of its JSON's words: the state directory (in the
// commands next steps and answers name), and any absolute or ~ path. An
// answer it cannot read is refused whole.
type noPaths struct {
	http.ResponseWriter
	dir  string
	code int
	buf  bytes.Buffer
}

func (n *noPaths) WriteHeader(code int)        { n.code = code }
func (n *noPaths) Write(b []byte) (int, error) { return n.buf.Write(b) }

func (n *noPaths) flush() {
	b := n.buf.Bytes()
	if mt, _, _ := mime.ParseMediaType(n.Header().Get("Content-Type")); mt == "application/json" {
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			n.code, b = http.StatusInternalServerError, []byte(`{"error":"refused: an answer not checked for this computer's paths"}`)
		} else {
			b, _ = json.Marshal(withoutPaths(v, n.dir))
		}
		n.Header().Del("Content-Length")
	}
	n.ResponseWriter.WriteHeader(cmp.Or(n.code, http.StatusOK))
	n.ResponseWriter.Write(b)
}

// localPath is a path in words: absolute or from ~, after a space, a quote,
// a parenthesis or = (a URL's // follows a colon).
var localPath = regexp.MustCompile(`(^|[\s'"(=])~?/[^\s'",;)]*[^\s'",;).]`)

const pathHidden = "(a path on this computer)"

// withoutDir is x with the state directory dir taken out, whole (spaces and all).
func withoutDir(x, dir string) string {
	if dir != "" {
		if abs, err := filepath.Abs(dir); err == nil {
			x = strings.ReplaceAll(x, shellWord(abs), pathHidden)
			x = strings.ReplaceAll(x, abs, pathHidden)
		}
	}
	return x
}

// tailnetSteps are the next steps for the tailnet page: those naming a path
// on this computer other than the state directory left out, as localPath
// would cut a path with a space short (other reqcove on PATH: /Users/x/My
// Tools/bin/reqcove), leaving its tail.
func tailnetSteps(steps []string, dir string) []string {
	return slices.DeleteFunc(slices.Clone(steps), func(s string) bool { return localPath.MatchString(withoutDir(s, dir)) })
}

func withoutPaths(v any, dir string) any {
	switch x := v.(type) {
	case string:
		return localPath.ReplaceAllString(withoutDir(x, dir), "${1}"+pathHidden)
	case []any:
		for i := range x {
			x[i] = withoutPaths(x[i], dir)
		}
	case map[string]any:
		for k := range x {
			x[k] = withoutPaths(x[k], dir)
		}
	}
	return v
}
