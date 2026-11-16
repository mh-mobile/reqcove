package main

import (
	"bufio"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

// `reqcove capture` changes the hosts the running reqcove records, without a
// restart: over ctl.sock in the state directory (0600, in the 0700
// directory), one JSON line asked and one answered. Not mcp.sock, the agents'
// path: no tool changes what is recorded. Only in a terminal, as mark and
// lan: a guard against an agent running it by mistake, not a boundary (any
// process of this user can reach the socket). run decides: it checks the
// request again, and refuses in LAN mode.

const ctlSock = "ctl.sock"

// ctlWait bounds a change, both ways: run answers within it (the addon's
// two round trips take milliseconds), and the CLI waits no longer (a run
// stopped with Ctrl-Z takes the connection and never answers).
var ctlWait = 15 * time.Second

// ctlRequest is one change asked of run.
type ctlRequest struct {
	Cmd        string   `json:"cmd"`                   // add, remove, set, stop, start, save, allow-all, discover, reload (reqcove reload), console (reqcove console), console-end (its --end, since v1.3) or restart (reqcove restart, since v1.3)
	Hosts      []string `json:"hosts,omitempty"`       // add, remove
	Pass       bool     `json:"pass,omitempty"`        // add, remove: of --pass-hosts
	AllowHosts []string `json:"allow_hosts,omitempty"` // set: all of them
	PassHosts  []string `json:"pass_hosts,omitempty"`  // set
	For        string   `json:"for,omitempty"`         // allow-all, discover: how long, as 30m or 2h
	End        bool     `json:"end,omitempty"`         // allow-all, discover: end it now
	ID         string   `json:"id,omitempty"`          // requests (one), approve, deny: an agent's request (since v1.2)
	Via        string   `json:"via,omitempty"`         // approve: terminal, dialog or console; deny: console (or none: terminal)
	Confirm    string   `json:"confirm,omitempty"`     // save: the token of the change to the config run showed, confirmed (since v1.3)
	Tailnet    bool     `json:"tailnet,omitempty"`     // console: the tailnet page's (reqcove console --tailnet, since v1.3)
	// Set by reqcove console's page alone, never read from ctl.sock: the scope
	// revision the page read (a change on an older one is refused), from:
	// "console", traced as such, and device: the tailnet page's caller's
	// machine name, which the trace names (none: this computer's page).
	rev, from, device string
}

// ctlAnswer is run's answer, for the user: what happened.
type ctlAnswer struct {
	OK       bool                       `json:"ok"`
	Message  string                     `json:"message"`
	Requests []mcpserver.CaptureRequest `json:"requests,omitempty"` // the request ops' (since v1.2)
	New      bool                       `json:"new,omitempty"`      // request: made now, not pending already
	Port     int                        `json:"port,omitempty"`     // console: the page's, on 127.0.0.1 (since v1.2)
	Code     string                     `json:"code,omitempty"`     // ui: the one-use code the link carries
	File     string                     `json:"file,omitempty"`     // console: the code file's name, in the state directory (since v1.3)
	Addr     string                     `json:"addr,omitempty"`     // console --tailnet: the tailnet page's IPv4:PORT (since v1.3)
	Confirm  string                     `json:"confirm,omitempty"`  // save: the change to the config Message shows, to confirm with this token (since v1.3)
	after    func()                     // run once the answer is sent (restart)
}

const captureUse = "reqcove capture add [--pass] HOST… | capture remove [--pass] HOST… | capture set --allow-hosts HOSTS [--pass-hosts HOSTS] | capture stop | capture start | capture save | capture allow-all --for D | capture allow-all --end | capture discover --for D | capture discover --end | capture requests | capture approve ID | capture deny ID  [--state DIR]"

func captureCmd(ctx context.Context, args []string) error {
	words, flags := wordsAndFlags(args, "allow-hosts", "pass-hosts", "for")
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	pass := fs.Bool("pass", false, "with add and remove: the hosts carried undecrypted (run's --pass-hosts), not the hosts recorded")
	var allow, passHosts []string
	fs.Func("allow-hosts", `with set: every host recorded, as run's --allow-hosts (not "*")`, func(v string) error { allow = append(allow, v); return nil })
	fs.Func("pass-hosts", "with set: the allowed hosts carried undecrypted, as run's --pass-hosts", func(v string) error { passHosts = append(passHosts, v); return nil })
	forD := fs.String("for", "", "with allow-all: how long every host is recorded; with discover: how long the names of the others are kept; as 30m or 2h (at most 24h)")
	end := fs.Bool("end", false, "with allow-all or discover: end it now")
	if err := parseFlags(fs, flags); err != nil {
		return err
	}
	req := ctlRequest{Pass: *pass, AllowHosts: allow, PassHosts: passHosts, For: *forD, End: *end}
	if len(words) > 0 {
		req.Cmd, req.Hosts = words[0], words[1:]
	}
	switch req.Cmd {
	case "request", "console", "console-end", "restart": // the agents' op, through reqcove mcp; reqcove console's; reqcove restart's
		return errors.New("usage: " + captureUse)
	case "approve", "deny":
		if len(req.Hosts) != 1 {
			return fmt.Errorf("capture %s takes the request's id (reqcove capture requests lists them)", req.Cmd)
		}
		req.ID, req.Hosts = req.Hosts[0], nil
		if req.Cmd == "approve" {
			req.Via = "terminal"
		}
	}
	if _, err := req.normalized(); err != nil { // before reaching run: run checks it again
		return err
	}
	return captureIn(ctx, os.Stdin, os.Stdout, *state, req)
}

// normalized is r with its hosts lowercased, or why it is refused: not one
// of the commands, a bad host, or "*" (every app's traffic is not a change
// made in passing).
func (r ctlRequest) normalized() (ctlRequest, error) {
	if r.Cmd != "allow-all" && r.Cmd != "discover" && (r.For != "" || r.End) {
		return r, fmt.Errorf("--for and --end go with capture allow-all and capture discover (usage: %s)", captureUse)
	}
	if r.Confirm != "" && r.Cmd != "save" || r.Tailnet && r.Cmd != "console" {
		return r, errors.New("usage: " + captureUse)
	}
	if requestOps[r.Cmd] {
		return r.request()
	}
	if r.ID != "" || r.Via != "" {
		return r, errors.New("usage: " + captureUse)
	}
	switch r.Cmd {
	case "allow-all", "discover":
		if len(r.Hosts)+len(r.AllowHosts)+len(r.PassHosts) > 0 || r.Pass {
			what := "records every host for a while (--for D), or ends that (--end)"
			if r.Cmd == "discover" {
				what = "keeps the names of the hosts outside the ones recorded for a while (--for D), or ends that (--end)"
			}
			return r, fmt.Errorf("capture %s takes no hosts: it %s", r.Cmd, what)
		}
		if r.End == (r.For != "") {
			return r, fmt.Errorf("capture %s takes --for D (how long, as 30m or 2h; at most 24h) or --end", r.Cmd)
		}
		if r.For != "" {
			if _, err := allowAllFor(r.For); err != nil {
				return r, err
			}
		}
		return r, nil
	case "add", "remove":
		if len(r.Hosts) == 0 {
			return r, fmt.Errorf("capture %s: name the hosts (usage: %s)", r.Cmd, captureUse)
		}
		if len(r.AllowHosts)+len(r.PassHosts) > 0 {
			return r, fmt.Errorf("--allow-hosts and --pass-hosts go with capture set; capture %s takes the hosts (with --pass for those carried undecrypted)", r.Cmd)
		}
	case "stop", "start", "save", "console", "console-end", "restart":
		if len(r.Hosts)+len(r.AllowHosts)+len(r.PassHosts) > 0 || r.Pass {
			return r, fmt.Errorf("capture %s takes no hosts (usage: %s)", r.Cmd, captureUse)
		}
	case "reload":
		if len(r.Hosts)+len(r.AllowHosts)+len(r.PassHosts) > 0 || r.Pass {
			return r, errors.New("usage: " + reloadUse)
		}
	case "set":
		if len(r.Hosts) > 0 || r.Pass {
			return r, fmt.Errorf("capture set takes --allow-hosts and --pass-hosts only (usage: %s)", captureUse)
		}
		if len(r.AllowHosts) == 0 {
			return r, errors.New("capture set needs --allow-hosts: every host to record (capture remove takes hosts out)")
		}
	default:
		return r, errors.New("usage: " + captureUse)
	}
	var err error
	for _, l := range []*[]string{&r.Hosts, &r.AllowHosts, &r.PassHosts} {
		if *l, err = hostSpecs(*l); err != nil {
			return r, err
		}
	}
	return r, nil
}

// request is normalized for the request ops: request takes the agent's hosts
// (requestHosts), approve the request's id and its hosts (the ones shown:
// run checks them), deny the id alone, requests the id or none.
func (r ctlRequest) request() (ctlRequest, error) {
	if r.ID != "" && !validID(r.ID) {
		return r, errors.New("not a request's id (reqcove capture requests lists them)")
	}
	bad := len(r.AllowHosts)+len(r.PassHosts) > 0 || r.Pass
	switch r.Cmd {
	case "request":
		bad = bad || r.ID != "" || r.Via != ""
	case "approve":
		bad = bad || r.ID == "" || r.Via != "terminal" && r.Via != "dialog" && r.Via != "console"
	case "deny":
		bad = bad || r.ID == "" || r.Via != "" && r.Via != "console" || len(r.Hosts) > 0
	case "requests":
		bad = bad || r.Via != "" || len(r.Hosts) > 0
	}
	if bad {
		return r, errors.New("usage: " + captureUse)
	}
	if r.Cmd == "request" || len(r.Hosts) > 0 {
		var err error
		r.Hosts, err = requestHosts(r.Hosts)
		return r, err
	}
	return r, nil
}

// hostSpecs are specs as --allow-hosts takes them (commas too), lowercased; never "*".
func hostSpecs(specs []string) ([]string, error) {
	r, err := capture.ParseAllowHosts(specs)
	if err != nil {
		return nil, errors.New(strings.TrimPrefix(err.Error(), "--allow-hosts: "))
	}
	if r.All {
		return nil, errors.New(`"*" is refused: it records every app's and site's traffic; name your app's hosts`)
	}
	return r.Hosts, nil
}

// allowAllFor is --for's duration: more than 0, at most capture.MaxAllowAll.
func allowAllFor(v string) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 || d > capture.MaxAllowAll {
		return 0, fmt.Errorf("--for %q: a duration such as 30m or 2h, at most %s", v, strings.TrimSuffix(capture.MaxAllowAll.String(), "0m0s"))
	}
	return d, nil
}

// String is the command as the trace shows it.
func (r ctlRequest) String() string {
	s := "capture " + r.Cmd
	switch {
	case (r.Cmd == "allow-all" || r.Cmd == "discover") && r.End:
		return s + " --end"
	case r.Cmd == "allow-all" || r.Cmd == "discover":
		return s + " --for " + r.For // a duration: ParseDuration took it
	case r.Cmd == "stop" || r.Cmd == "start" || r.Cmd == "save":
		return s
	case r.Cmd == "reload" || r.Cmd == "restart":
		return r.Cmd
	}
	if r.Pass {
		s += " --pass"
	}
	if r.Cmd == "set" {
		s += " --allow-hosts " + strings.Join(r.AllowHosts, ",")
		if len(r.PassHosts) > 0 {
			s += " --pass-hosts " + strings.Join(r.PassHosts, ",")
		}
		return s
	}
	return s + " " + strings.Join(r.Hosts, " ")
}

func captureIn(ctx context.Context, in, out *os.File, state string, req ctlRequest) error {
	if !isTerminal(in) || !isTerminal(out) {
		name := "reqcove capture"
		if req.Cmd == "reload" {
			name = "reqcove reload"
		}
		return errors.New(name + " runs only in a terminal: it changes what is recorded, which is the user's choice (an agent never runs it). Run it in your own terminal")
	}
	switch req.Cmd {
	case "approve":
		return approveIn(ctx, in, out, state, req)
	case "requests":
		return printRequests(ctx, out, state)
	case "save":
		return saveIn(ctx, in, out, state, req)
	}
	return sendCapture(ctx, out, state, req)
}

// saveIn is capture save: when the save would add a line to the config (a
// hosts file created beside it), run's answer shows the change, and it is
// asked again with run's token once the user says y.
func saveIn(ctx context.Context, in io.Reader, out io.Writer, state string, req ctlRequest) error {
	a, err := askRun(ctx, state, req)
	if err != nil {
		return err
	}
	if a.Confirm == "" {
		if !a.OK {
			return errors.New(a.Message)
		}
		fmt.Fprintln(out, a.Message)
		return nil
	}
	fmt.Fprint(out, a.Message+"Go on? [y/N] ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	if yes := strings.ToLower(strings.TrimSpace(line)); yes != "y" && yes != "yes" {
		fmt.Fprintln(out, "nothing written")
		return nil
	}
	req.Confirm = a.Confirm
	return sendCapture(ctx, out, state, req)
}

// sendCapture asks the running reqcove for the change and prints its answer.
func sendCapture(ctx context.Context, w io.Writer, state string, req ctlRequest) error {
	a, err := askRun(ctx, state, req)
	if err != nil {
		return err
	}
	if !a.OK {
		return errors.New(a.Message)
	}
	fmt.Fprintln(w, a.Message)
	return nil
}

// askRun sends req to the running reqcove and returns its answer; an error
// when none answers (errNotRunning among them), or when the run is too old
// for req.
func askRun(ctx context.Context, state string, req ctlRequest) (ctlAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, ctlWait)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", filepath.Join(state, ctlSock))
	if err != nil {
		need := "v1.1"
		switch {
		case req.Cmd == "console-end" || req.Cmd == "restart":
			need = "v1.3"
		case requestOps[req.Cmd] || req.Cmd == "console":
			need = "v1.2"
		}
		return ctlAnswer{}, noCtl(ctx, state, need)
	}
	defer conn.Close()
	dl, _ := ctx.Deadline()
	conn.SetDeadline(dl)
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return ctlAnswer{}, err
	}
	var a ctlAnswer
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&a); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return a, fmt.Errorf("the running reqcove (%s) did not answer in %v (stopped, with Ctrl-Z?): whether it took the change, `%s` says", state, ctlWait, withState("reqcove status", state))
		}
		return a, fmt.Errorf("the running reqcove did not answer: %w", err)
	}
	if older := !a.OK && (strings.HasPrefix(a.Message, v11Usage) || strings.HasPrefix(a.Message, lanRefusal)); older && req.Cmd == "console-end" {
		return a, errOlderEnd
	} else if older && req.Cmd == "restart" {
		return a, errOlderRestart
	}
	if !a.OK && strings.HasPrefix(a.Message, v11Usage) {
		switch {
		case req.Cmd == "console":
			return a, errOlderUI
		case requestOps[req.Cmd]:
			return a, errOlderRun
		}
	}
	return a, nil
}

// noCtl says why no run answers on ctl.sock: none runs, one is starting, or
// it is older than v1.1 (it serves mcp.sock only; a v1.1 run serves ctl.sock
// first). need is the version the request needs.
func noCtl(ctx context.Context, state, need string) error {
	cs, err := dialRun(ctx, state, "reqcove-capture")
	switch {
	case errors.Is(err, errNotRunning):
		return fmt.Errorf("%w (%s): nothing to change", errNotRunning, state)
	case err != nil:
		return fmt.Errorf("%w: nothing changed", err)
	}
	defer cs.Close()
	v := "older"
	if ir := cs.InitializeResult(); ir != nil && ir.ServerInfo != nil && ir.ServerInfo.Version != "" {
		v = ir.ServerInfo.Version
	}
	return fmt.Errorf("this run is %s: restart it with %s or later to change what it records while it runs (a restart empties the records: `%s > flows.har` keeps them first); nothing changed", v, need, withState("reqcove har", state))
}

// ctlState is what ctl.sock answers from: run's options as it started (in
// LAN mode, whose hosts are set at the start, as its proxy takes their names
// then, every change is refused), and, guarded by mu, which also takes one
// change at a time, where the hosts come from (capture save writes there)
// and the hosts the files gave when last read or written (reload says what
// it replaces of the changes made since).
type ctlState struct {
	o      *runOpts
	mu     sync.Mutex
	origin hostsOrigin
	loaded capture.HostRules
	reqs   *captureRequests // the agents' requests (its own lock)
	// For reqcove console: run's context, which the page lives as long as; its
	// status (as this computer's status tool gives it; nil: none); the page,
	// once opened (guarded by mu).
	ctx    context.Context
	status func() mcpserver.StatusOut
	page   *page
	dir    string // the state directory: the code files'
	// pageNow is page, read without mu (status counts its sessions); tailnet,
	// the tailnet page once opened (reqcove console --tailnet; never carried
	// across a restart).
	pageNow atomic.Pointer[page]
	tailnet atomic.Pointer[page]
	// startConfig is the --config file's bytes as run read them at its start,
	// with the lines capture save added since (restart.go's snapshot);
	// restart, run's: it stops and execs again, with that snapshot's path.
	startConfig []byte
	restart     func(snapshot string)
	// originNow is origin as last set (setOrigin), read without mu: status
	// and the page list the hosts files from it. run and gen make the scope
	// revision (revision): a change asked bumps gen.
	originNow atomic.Pointer[hostsOrigin]
	run       string
	gen       atomic.Uint64
}

func newCtlState(o *runOpts) *ctlState {
	st := &ctlState{o: o, reqs: newCaptureRequests(o.state), ctx: context.Background(), startConfig: o.configText, run: secret(4)}
	st.setOrigin(o.origin, o.allow)
	return st
}

// setOrigin is where the hosts come from now, and the hosts the files gave
// (st.mu held, or before serving).
func (st *ctlState) setOrigin(o hostsOrigin, loaded capture.HostRules) {
	st.origin, st.loaded = o, loaded
	st.originNow.Store(&o)
}

// hostsFiles are the files --allow-hosts=@FILE and --pass-hosts=@FILE name
// now: a save that created one, or a reload, shows at once.
func (st *ctlState) hostsFiles() []string {
	o := st.originNow.Load()
	return append(slices.Clone(o.files), o.passOrigin().files...)
}

// revision is the scope's revision: another one after every scope change
// asked (scopeOps), from a terminal, a page or an agent's request approved,
// and in another run.
func (st *ctlState) revision() string {
	return fmt.Sprintf("%s.%d", st.run, st.gen.Load())
}

// scopeOps are the ops that may change the scope, or its saved hosts.
var scopeOps = map[string]bool{"add": true, "remove": true, "set": true, "stop": true, "start": true, "save": true, "allow-all": true, "discover": true, "reload": true, "approve": true}

// consoleSessions are reqcove console's live sessions, for this computer's
// status: nil before a page is opened.
func (st *ctlState) consoleSessions() *mcpserver.ConsoleSessions {
	l, tn := st.pageNow.Load(), st.tailnet.Load()
	if l == nil && tn == nil {
		return nil
	}
	out := &mcpserver.ConsoleSessions{}
	if l != nil {
		out.Local, _ = l.count()
	}
	if tn != nil {
		_, out.Tailnet = tn.count()
	}
	return out
}

// fromConsole ends the trace of a change made on reqcove console's page.
const fromConsole = " (from the console on this computer)"

// consoleFrom ends the trace of a change made on a page of reqcove console:
// device, the tailnet page's caller's machine name; "": this computer's.
func consoleFrom(device string) string {
	if device == "" {
		return fromConsole
	}
	return " (from the console on " + device + ", over the tailnet)"
}

// serveCtl serves ctl.sock until ctx ends, for the run o started, and
// returns the state it answers from; restart is run's (nil: none), set
// before anything is served; status is what reqcove console's page shows.
func serveCtl(ctx context.Context, state string, cap *capture.Capture, o *runOpts, restart func(snapshot string), status func() mcpserver.StatusOut) (*ctlState, error) {
	st := newCtlState(o)
	st.ctx, st.status, st.dir, st.restart = ctx, status, state, restart
	if cap != nil { // nil: tests of LAN mode
		st.reqs.redacting = cap.Store.Redacting
	}
	if h := carried; h != nil && h.pageLn != nil {
		st.page = carriedPage(ctx, cap, st, h)
		st.pageNow.Store(st.page)
	}
	path := filepath.Join(state, ctlSock)
	os.Remove(path) // stale: run holds the state's lock
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("control socket: %w (a shorter --state path helps if it is too long)", err)
	}
	if err := os.Chmod(path, 0o600); err != nil { // the directory is 0700 already
		ln.Close()
		return nil, err
	}
	go func() { <-ctx.Done(); ln.Close() }() // Close removes the file
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(ctlWait))
				var req ctlRequest
				if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&req); err != nil {
					return
				}
				ctx, cancel := context.WithTimeout(ctx, ctlWait-time.Second) // the answer before the CLI gives up
				defer cancel()
				a := answerCtl(ctx, cap, st, req)
				json.NewEncoder(conn).Encode(a)
				if a.after != nil {
					conn.Close() // the answer out before run stops
					a.after()
				}
			}()
		}
	}()
	return st, nil
}

// errUnchanged: the request changes nothing.
var errUnchanged = errors.New("unchanged")

// answerCtl makes the change and says what happened. A change taken
// (applied, or pending) leaves a trace: run's log line, a cli marker, and
// status's scope_changed_at.
func answerCtl(ctx context.Context, cap *capture.Capture, st *ctlState, req ctlRequest) ctlAnswer {
	st.mu.Lock()
	defer st.mu.Unlock()
	if req.Cmd == "console" { // in LAN mode too: the page shows the state (what LAN mode refuses, it refuses there too)
		if _, err := req.normalized(); err != nil {
			return ctlAnswer{Message: "refused: " + err.Error() + "; nothing changed"}
		}
		return openPage(cap, st, req.Tailnet)
	}
	if req.Cmd == "console-end" { // in LAN mode too, as console
		if _, err := req.normalized(); err != nil {
			return ctlAnswer{Message: "refused: " + err.Error() + "; nothing changed"}
		}
		return endPage(st)
	}
	if req.Cmd == "restart" { // in LAN mode too
		if _, err := req.normalized(); err != nil {
			return ctlAnswer{Message: "refused: " + err.Error() + "; nothing stopped"}
		}
		if req.from == "console" && req.rev != configRevNow(st.o.config) {
			return ctlAnswer{Message: "refused: the config changed since the page listed what a restart changes (another tab, or an edit): look again; nothing stopped"}
		}
		return restartOp(ctx, st, recordCount(cap))
	}
	lan := st.o.lanMode
	if lan && req.Cmd == "save" {
		return ctlAnswer{Message: "refused: in LAN mode the hosts recorded are the ones run started with: nothing to save; nothing written"}
	}
	if lan {
		return ctlAnswer{Message: lanRefusal + " while run runs (not in this version): restart run with the hosts you want in --allow-hosts; nothing changed"}
	}
	req, err := req.normalized()
	if err != nil {
		return ctlAnswer{Message: "refused: " + err.Error() + "; nothing changed"}
	}
	why := req.String()
	if req.from == "console" {
		if req.rev != st.revision() {
			return ctlAnswer{Message: "refused: the hosts changed since this page read them (in another tab, or by reqcove capture in a terminal): the page shows them as they are now; nothing changed"}
		}
		why += consoleFrom(req.device)
	}
	if req.device != "" && (req.Cmd == "approve" || req.Cmd == "deny") {
		req.Via = "console on " + req.device + " (tailnet)"
	}
	if scopeOps[req.Cmd] {
		defer st.gen.Add(1)
	}
	switch req.Cmd {
	case "stop", "start":
		return stopStart(ctx, cap, req.Cmd == "stop", why, req.from)
	case "save":
		return save(cap, st, req.Confirm, why, req.from)
	case "allow-all":
		return allowAll(ctx, cap, req, why)
	case "discover":
		return discover(ctx, cap, req, why)
	case "reload":
		return reload(ctx, cap, st, why)
	case "request":
		return st.reqs.ask(cap.Base(), req.Hosts)
	case "requests":
		return st.reqs.list(req.ID)
	case "deny":
		return st.reqs.deny(req.ID, cmp.Or(req.Via, "terminal"))
	case "approve":
		return approve(st.reqs, req, func(why string, hosts []string) ctlAnswer {
			return scopeChange(ctx, cap, ctlRequest{Cmd: "add", Hosts: hosts}, why, true)
		})
	}
	return scopeChange(ctx, cap, req, why, false)
}

// scopeChange is add, remove or set (req, normalized): asked is an agent's
// request approved, traced as such.
func scopeChange(ctx context.Context, cap *capture.Capture, req ctlRequest, why string, asked bool) ctlAnswer {
	var cur, next capture.HostRules
	var notes []string
	var rec string
	err := cap.ChangeScope(ctx, why, func(c capture.HostRules, r string) (capture.HostRules, error) {
		var err error
		cur, rec = c, r
		if next, notes, err = newScope(c, req); err != nil {
			return c, err
		}
		if changes(cur, next) == "" {
			return c, errUnchanged
		}
		return next, nil
	})
	pending := errors.Is(err, capture.ErrPending)
	switch {
	case errors.Is(err, errUnchanged):
		return ctlAnswer{OK: true, Message: strings.Join(append([]string{"nothing changed"}, notes...), "; ")}
	case err != nil && !pending:
		msg := err.Error()
		if !strings.Contains(msg, "nothing changed") {
			msg = "refused: " + msg + "; nothing changed"
		}
		return ctlAnswer{Message: msg}
	}
	msg := "applied: " + changes(cur, next)
	if pending {
		msg = "pending: " + changes(cur, next) + " (mitmproxy has not acknowledged it yet: restarting? it applies once mitmproxy is back; status shows scope_pending meanwhile)"
	}
	msg += fmt.Sprintf("; %v records kept; not saved: a restart of run goes back to the hosts it was started with (reqcove capture save writes them to its hosts file)", cap.Store.Stats()["flows"])
	switch rec {
	case capture.RecordingStopped: // nothing is recorded either way until the start
		msg += "; recording is stopped: these are the hosts `reqcove capture start` records, nothing is recorded until then"
	case capture.RecordingAllowAll: // every host is recorded either way until it ends
		msg += "; allow-all is on: every host is recorded until" + allAt(cap.AllowAllUntil()) + ", these hosts after; the --rules file's rules apply to these hosts alone"
	default:
		if len(minus(cur.Hosts, next.Hosts))+len(minus(next.PassHosts, cur.PassHosts)) > 0 {
			msg += "; " + removeWarning()
		}
		if len(minus(next.Hosts, cur.Hosts))+len(minus(cur.PassHosts, next.PassHosts)) > 0 {
			msg += "; new connections only: reopen the app to see it now"
		}
	}
	msg = strings.Join(append([]string{msg}, notes...), "; ")
	if asked {
		return tracedAs(cap, requestMark(why), "mcp", why+": "+msg, msg)
	}
	return traced(cap, why, req.from, msg)
}

// traced is the answer to a change taken, leaving its trace: run's log line
// and a cli marker (status's scope_changed_at comes from the change itself).
// from is "console" for reqcove console's page (why ends with fromConsole
// then), else "": a terminal's.
func traced(cap *capture.Capture, why, from, msg string) ctlAnswer {
	if from == "console" {
		return tracedAs(cap, why, "cli", why+": "+msg, msg)
	}
	cmd := "reqcove capture"
	if why == "reload" {
		cmd = "reqcove reload"
	}
	return tracedAs(cap, why, "cli", fmt.Sprintf("%s (%s, from a terminal): %s", why, cmd, msg), msg)
}

// tracedAs is traced with the marker's text and source and run's log line
// given: an agent's request approved is source mcp.
func tracedAs(cap *capture.Capture, mark, source, line, msg string) ctlAnswer {
	log.Print(line)
	if _, _, err := cap.Store.AddMarker(cut(mark, capture.MaxMarkerText), source); err != nil {
		log.Printf("WARN: the marker of %s: %v", mark, err)
	}
	return ctlAnswer{OK: true, Message: msg}
}

// stopStart is capture stop (stop) or capture start. A stop's answer warns
// that the rules stop too: a mock's or map_remote's requests go to the real
// servers then. A stop ends allow-all.
func stopStart(ctx context.Context, cap *capture.Capture, stop bool, why, from string) ctlAnswer {
	wasAll := !cap.AllowAllUntil().IsZero()
	base, err := cap.SetStopped(ctx, why, stop)
	pending := errors.Is(err, capture.ErrPending)
	switch {
	case errors.Is(err, capture.ErrUnchanged) && stop:
		return ctlAnswer{OK: true, Message: "nothing changed: recording is stopped already (`reqcove capture start` records again)"}
	case errors.Is(err, capture.ErrUnchanged):
		return ctlAnswer{OK: true, Message: "nothing changed: recording is not stopped"}
	case err != nil && !pending:
		return ctlAnswer{Message: "refused: " + err.Error() + "; nothing changed"}
	}
	kept := fmt.Sprintf("%v records kept (still readable)", cap.Store.Stats()["flows"])
	var msg string
	if stop {
		msg = "applied: recording stopped; "
		if pending {
			msg = "pending: recording stopped in reqcove's records, mitmproxy not told yet (restarting? it stops once mitmproxy is back; status shows scope_pending meanwhile); "
		}
		switch {
		case wasAll && pending:
			msg += "allow-all ended (a stop ends it; mitmproxy, not told, is restarted without it); "
		case wasAll:
			msg += "allow-all ended (a stop ends it); "
		}
		msg += kept + "; " + stopWarning +
			"; connections already decrypted stay decrypted (unrecorded) until they close" + openNote + "; not saved: a restart of run records again; `reqcove capture start` records again"
	} else {
		msg = "applied: recording started again: " + scopeText(base) + "; "
		if pending {
			msg = "pending: recording started again, mitmproxy not told yet (restarting? it applies once mitmproxy is back; status shows scope_pending meanwhile): " + scopeText(base) + "; "
		}
		msg += kept + "; the rules apply again (presets stay off until turned on); new connections only: reopen the app to see it now (a connection or WebSocket open before the stop is not recorded again)"
	}
	return traced(cap, why, from, msg)
}

// The warnings of stop, remove and allow-all: in their answers, and on
// reqcove console's page before its confirm (pageWarnings), word for word.
const stopWarning = "WARNING: the --rules file's rules apply no more (mock, map_local, map_remote, modify_headers, resolve; presets turned off), so the app's requests go to the real servers as it sends them, a mocked API's too"

// removeWarning is a removal's, while recording is on (openNote: run sets it).
func removeWarning() string {
	return "not recorded from now on, but their open connections stay decrypted (unrecorded) until they close" + openNote
}

// allowAllWarning is allow-all's, with run's other flags' (allowAllNotes).
func allowAllWarning() string {
	return strings.Join(append([]string{"WARNING: every app's and site's traffic on the devices is recorded (but Apple's, passed through undecrypted), and agents, and their model providers, can read it" +
		"; apps that pin their certificates (banks, say) fail meanwhile" +
		"; the --rules file's rules apply to the hosts recorded before alone" +
		"; new connections only: reopen an app to see it" +
		"; the records stay after it ends (until evicted, or run restarts), and fill max_flows sooner"}, allowAllNotes...), "; ")
}

// allowAllNotes are the warnings of run's other flags that apply while every
// host is recorded (--upstream-proxy, --mcp-http, --web, --local-proxy):
// run sets them.
var allowAllNotes []string

// openNote follows "stay decrypted (unrecorded) until they close": with
// --web (run sets it), what mitmweb still shows of those connections. A body
// under way is copied no more (the addon's cut), but mitmweb lists each
// request as mitmproxy reads it.
var openNote string

const webOpenNote = " (--web: mitmweb still lists their requests, URLs and headers unmasked, without their bodies)"

// allowAllWarnings are run's warnings of --allow-hosts '*' for o's other
// flags, and --mcp-http's reach.
func allowAllWarnings(o *runOpts) []string {
	var w []string
	if o.upstream != "" {
		w = append(w, "--upstream-proxy: every decrypted request goes on to it, and it connects to HTTPS hosts by name, looked up again on this computer, so a site the device visits can point it at this computer or the LAN")
	}
	if o.mcpHTTP {
		w = append(w, "--mcp-http: agents on your other devices (Grok Bot in xAI's cloud) read these records too")
	}
	if o.web {
		w = append(w, "--web: mitmweb shows every one of them too, unmasked")
	}
	if o.localProxy {
		w = append(w, "--local-proxy: every HTTPS site this computer's apps open is decrypted too (failing in those that do not trust Reqcove's CA)")
	}
	return w
}

// allowAll is capture allow-all --for D (every host recorded until then, the
// records kept after) or --end. Its answer repeats what --allow-hosts '*'
// warns of.
func allowAll(ctx context.Context, cap *capture.Capture, req ctlRequest, why string) ctlAnswer {
	if req.End {
		err := cap.EndAllowAll(ctx, why)
		pending := errors.Is(err, capture.ErrPending)
		switch {
		case errors.Is(err, capture.ErrUnchanged):
			return ctlAnswer{OK: true, Message: "nothing changed: allow-all is not on"}
		case err != nil && !pending:
			return ctlAnswer{Message: "refused: " + err.Error() + "; nothing changed"}
		}
		msg := "applied: allow-all ended: " + scopeText(cap.Base())
		if pending {
			msg = "applied in reqcove's records (nothing outside these hosts is recorded from now), mitmproxy restarted without allow-all, as it did not answer: allow-all ended: " + scopeText(cap.Base())
		}
		return traced(cap, why, req.from, msg+"; "+endedText(cap))
	}
	d, err := allowAllFor(req.For)
	if err != nil {
		return ctlAnswer{Message: "refused: " + err.Error() + "; nothing changed"}
	}
	until, was, err := cap.SetAllowAll(ctx, why, d)
	pending := errors.Is(err, capture.ErrPending)
	switch {
	case errors.Is(err, capture.ErrStopped):
		return ctlAnswer{Message: "refused: recording is stopped: `reqcove capture start` first; nothing changed"}
	case errors.Is(err, capture.ErrUnchanged):
		return ctlAnswer{OK: true, Message: `nothing changed: this run records every host already (--allow-hosts "*")`}
	case err != nil && !pending:
		return ctlAnswer{Message: "refused: " + err.Error() + "; nothing changed"}
	}
	msg := "applied: allow-all on: every host is recorded until" + allAt(until)
	switch {
	case !was.IsZero():
		msg = "applied: allow-all was on until" + allAt(was) + ": now until" + allAt(until)
	case pending:
		msg = "pending: allow-all asked, until" + allAt(until) + " (mitmproxy has not acknowledged it yet: restarting? it applies once mitmproxy is back; status shows scope_pending meanwhile)"
	}
	if base := cap.Base(); len(base.PassHosts) > 0 {
		msg += "; still passed undecrypted: " + strings.Join(base.PassHosts, ", ")
	}
	msg += "; " + allowAllWarning() + "; `reqcove capture allow-all --end` ends it sooner; not saved: a restart of run ends it"
	return traced(cap, why, req.from, msg)
}

// allAt is " HH:MM:SS (in 29m)" for allow-all's end t; the date too when
// not today.
func allAt(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	l, layout := t.Local(), "15:04:05"
	if y, m, d := time.Now().Date(); l.Day() != d || l.Month() != m || l.Year() != y {
		layout = "2006-01-02 15:04:05"
	}
	return fmt.Sprintf(" %s (in %v)", l.Format(layout), time.Until(t).Round(time.Second))
}

// endedText says what is left once allow-all ends: its records kept.
func endedText(cap *capture.Capture) string {
	return fmt.Sprintf("%v records kept, %d of them of hosts not recorded now (allow-all's: still readable, until evicted or run restarts); connections already decrypted stay decrypted (unrecorded) until they close%s",
		cap.Store.Stats()["flows"], cap.Store.OutsideScope(cap.Base()), openNote)
}

// save is capture save: the base scope into run's hosts files (saveScope); a
// save made leaves its trace.
func save(cap *capture.Capture, st *ctlState, confirm, why, from string) ctlAnswer {
	a, saved := saveScope(cap.Base(), st, confirm)
	if !saved {
		return a
	}
	cap.NoteChange(why)
	t := traced(cap, why, from, a.Message)
	t.OK = a.OK // a save cut short: what was written, and what not
	return t
}

// hostsSave is a hosts file a save writes: its hosts and text, and the
// revision of the file the text was made from ("" for none); created: new,
// beside the config, which gets its line.
type hostsSave struct {
	path, text    string
	rev           string
	hosts         []string
	pass, created bool
}

const (
	savedHostsHead = "# The hosts reqcove records, one a line (# starts a comment); the config reads them\n" +
		"# with --allow-hosts=@FILE. Written by reqcove capture save, which rewrites the hosts,\n" +
		"# keeping the comments.\n"
	savedPassHead = "# The hosts reqcove carries undecrypted (--pass-hosts), one a line (# starts a\n" +
		"# comment); the config reads them with --pass-hosts=@FILE. Written by reqcove capture\n" +
		"# save, which rewrites the hosts, keeping the comments.\n"
)

// saveScope writes base into run's hosts files: --allow-hosts=@FILE's the
// hosts recorded, --pass-hosts=@FILE's those passed undecrypted, without the
// hosts given as they are but not in the file (pinned: a restart takes those
// again whatever the file says; one in the file too stays there, and removed,
// is named). Never "*". A file may be left without hosts when the next start
// would still take the whole flag set (checkFlags), as written. When the
// config names no such file and there are hosts to write, the file is created
// beside it (hostsFileFor; refused when one is there already) and its line
// added to the config through the writer, once confirm is the token of the
// change, which an answer without it shows (a token given is always
// checked: reqcove console's page gives the one of the change it showed).
// saved: something was written. Called with st.mu held.
func saveScope(base capture.HostRules, st *ctlState, confirm string) (ctlAnswer, bool) {
	refuse := func(msg string) (ctlAnswer, bool) { return ctlAnswer{Message: msg + "; nothing written"}, false }
	sp, no := planSave(base, st)
	if no != "" {
		return refuse(no)
	}
	saves, plan, notes, config := sp.saves, sp.plan, sp.notes, st.o.config
	if len(saves) == 0 {
		return ctlAnswer{OK: true, Message: strings.Join(append([]string{"nothing to save: the hosts are all given as they are (a start takes them again)"}, notes...), "; ")}, false
	}
	if confirm != "" && confirm != sp.token {
		return refuse("refused: the config or the hosts changed since the change was shown: save again")
	}
	if plan != nil && confirm == "" {
		var b strings.Builder
		fmt.Fprintf(&b, "The config names no hosts file to save these to, so capture save would:\n")
		for _, s := range saves {
			what := "create %s (yours only, 0600) with: %s\n"
			if !s.created {
				what = "write %s: %s\n"
			}
			fmt.Fprintf(&b, "  "+what, s.path, cmp.Or(strings.Join(s.hosts, ", "), "no hosts"))
		}
		fmt.Fprintf(&b, "  add to %s (its other lines kept, the old file kept as %s.prev):\n", config, filepath.Base(config))
		b.WriteString(indent(plan.diff(), "    ", "\n"))
		return ctlAnswer{Message: b.String(), Confirm: sp.token}, false
	}
	var created []string
	undo := func() {
		for _, c := range created {
			os.Remove(c)
		}
	}
	for _, s := range saves {
		if !s.created {
			continue
		}
		if err := createPrivate(s.path, s.text); err != nil {
			undo()
			return refuse("refused: " + err.Error())
		}
		created = append(created, s.path)
	}
	if plan != nil {
		if err := plan.commit(); err != nil {
			undo() // so that a retry's exclusive create works
			return refuse("refused: the config: " + err.Error())
		}
		// A failed start after a restart puts back the start config with it:
		// the config never loses the hosts file saved to.
		st.startConfig = withLines(st.startConfig, plan.added)
	}
	var did []string // what was written, the files created first
	if plan != nil {
		did = append(did, "added to "+config+": "+strings.Join(plan.added, ", "))
	}
	for _, s := range saves {
		if s.created {
			did = append(did, savedText(s))
		}
	}
	for _, s := range saves {
		if s.created {
			continue
		}
		if err := writeHostsText(s.path, s.text, s.hosts, s.rev); err != nil {
			if len(did) == 0 {
				return refuse("refused: " + err.Error())
			}
			refreshOrigin(st, saves)
			return ctlAnswer{Message: "partly saved: " + strings.Join(did, "; ") + "; but " + s.path + " was not written: " + err.Error()}, true
		}
		did = append(did, savedText(s))
	}
	refreshOrigin(st, saves)
	return ctlAnswer{OK: true, Message: strings.Join(append(did, notes...), "; ")}, true
}

// savePlan is a save worked out, nothing written: the files (their text
// made), the config's change for the files created (nil: none), the notes,
// and the token of it all (a save confirms it).
type savePlan struct {
	saves []hostsSave
	plan  *configPlan
	notes []string
	token string
}

// planSave is saveScope's save worked out, or why it is refused (no: the
// answer's words, "nothing written" left out). Called with st.mu held.
func planSave(base capture.HostRules, st *ctlState) (sp savePlan, no string) {
	o, pass, config := st.origin, st.origin.passOrigin(), st.o.config
	switch {
	case base.All:
		return sp, `refused: this run records every host ("*"), which a hosts file never holds`
	case len(o.files) > 1:
		return sp, "nothing to save to: this run's hosts come from several files (" + strings.Join(o.files, ", ") + "): keep one `--allow-hosts=@FILE`"
	case len(pass.files) > 1:
		return sp, "nothing to save to: this run's hosts passed undecrypted come from several files (" + strings.Join(pass.files, ", ") + "): keep one `--pass-hosts=@FILE`"
	case len(o.files) == 1 && slices.Contains(pass.files, o.files[0]):
		return sp, "refused: " + o.files[0] + " is run's --pass-hosts file too: saving would change the hosts passed undecrypted"
	case len(o.files) == 0 && config == "":
		return sp, "nothing to save to: this run's hosts do not come from a hosts file, nor from a --config file beside which one could be made; put `--allow-hosts=@FILE` on run's command line (FILE: one host a line), or start run from a --config file, as reqcove setup writes it"
	}
	for _, l := range []struct {
		o     hostsOrigin
		hosts []string
		pass  bool
	}{{o, base.Hosts, false}, {pass, base.PassHosts, true}} {
		hosts := savable(l.hosts, l.o)
		switch {
		case len(l.o.files) == 1:
			sp.saves = append(sp.saves, hostsSave{path: l.o.files[0], hosts: hosts, pass: l.pass})
		case len(hosts) > 0 && config != "":
			sp.saves = append(sp.saves, hostsSave{path: hostsFileFor(config, l.pass), hosts: hosts, pass: l.pass, created: true})
		}
	}
	files := map[string]string{}
	var edits []configEdit
	for i, s := range sp.saves {
		head := savedHostsHead
		if s.pass {
			head = savedPassHead
		}
		if s.created {
			if _, err := os.Lstat(s.path); !errors.Is(err, fs.ErrNotExist) {
				line := "--" + hostsFileLine(config, s.pass).Flag + "=@" + s.path
				return sp, "refused: " + s.path + " is there already, and the config does not name it: capture save never takes over a file it did not make. Either add the line " + line + " to " + config + " yourself (then `reqcove reload`), or move " + s.path + " away and save again"
			}
			edits = append(edits, hostsFileLine(config, s.pass))
		}
		text, rev, err := hostsText(s.path, s.hosts, head)
		if err != nil {
			return sp, "refused: " + err.Error()
		}
		sp.saves[i].text, sp.saves[i].rev, files[s.path] = text, rev, text
	}
	sp.notes = saveNotes(base, o, pass, sp.saves)
	if len(sp.saves) == 0 {
		return sp, ""
	}
	var err error
	if len(edits) > 0 {
		sp.plan, err = planConfig(config, st.o.args, files, edits...)
	} else if _, err = checkFlags(st.o.args, nil, files); err != nil {
		err = fmt.Errorf("the next start of run would refuse it: %w", err)
	}
	if err != nil {
		return sp, "refused: " + err.Error()
	}
	// The token of the files read as well as of what is written: an edit to
	// one since the change was shown refuses it, whatever it would write.
	h := sha256.New()
	if sp.plan != nil {
		fmt.Fprintf(h, "%s\x00", sp.plan.rev)
		h.Write(sp.plan.new)
	} else {
		fmt.Fprintf(h, "%s\x00", configRevNow(config))
	}
	for _, s := range sp.saves {
		fmt.Fprintf(h, "\x00%s\x00%s\x00%s", s.path, s.rev, s.text)
	}
	sp.token = hex.EncodeToString(h.Sum(nil))
	return sp, ""
}

// savedText says what s saved.
func savedText(s hostsSave) string {
	what := "no hosts (a start records none from it)"
	if s.pass {
		what = "no hosts (a start passes none from it)"
	}
	if len(s.hosts) > 0 {
		what = strings.Join(s.hosts, ", ")
	}
	return "saved to " + s.path + ": " + what
}

// refreshOrigin makes run's hosts origin and loaded hosts the files' now, as
// reload does: a second save writes a file the first created.
func refreshOrigin(st *ctlState, saves []hostsSave) {
	if n, err := reloadFlags(st.o.args); err == nil {
		st.setOrigin(n.origin, n.allow)
		return
	}
	o := st.origin
	for _, s := range saves { // the new files at least
		switch {
		case s.created && s.pass:
			p := o.passOrigin()
			p.files = []string{s.path}
			o.pass = &p
		case s.created:
			o.files = []string{s.path}
		}
	}
	st.setOrigin(o, st.loaded)
}

// savable is list without the hosts given as they are (o.given), but those
// in o's file too.
func savable(list []string, o hostsOrigin) []string {
	var out []string
	for _, h := range list {
		if _, ok := o.given[h]; (!ok || o.inFiles[h]) && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// saveNotes say what a save leaves to the hosts given as they are, and the
// hosts passed undecrypted it cannot save.
func saveNotes(base capture.HostRules, o, pass hostsOrigin, saves []hostsSave) []string {
	var notes []string
	saved := map[bool]bool{}
	for _, s := range saves {
		saved[s.pass] = true
	}
	for _, l := range []struct {
		o    hostsOrigin
		base []string
		pass bool
		does string
	}{{o, base.Hosts, false, "records"}, {pass, base.PassHosts, true, "passes"}} {
		written := savable(l.base, l.o)
		for _, from := range []string{"the command line", "the --config file"} {
			var on, back []string
			for _, h := range slices.Sorted(maps.Keys(l.o.given)) {
				switch {
				case l.o.given[h] != from, slices.Contains(written, h):
				case slices.Contains(l.base, h):
					on = append(on, h)
				default:
					back = append(back, h)
				}
			}
			if len(on) > 0 {
				notes = append(notes, fmt.Sprintf("not written, as given on %s (a start with it %s them again): %s", from, l.does, strings.Join(on, ", ")))
			}
			if len(back) > 0 {
				notes = append(notes, fmt.Sprintf("removed now, but given on %s, so a start with it %s them again: %s", from, l.does, strings.Join(back, ", ")))
			}
		}
		if l.pass && len(written) > 0 && !saved[true] {
			notes = append(notes, "the hosts passed undecrypted are not saved: no --config file to name a hosts file in (a start passes run's --pass-hosts)")
		}
	}
	return notes
}

// createPrivate writes text to path as a new file of this user's only (0600):
// never one there already, nor through a link.
func createPrivate(path, text string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(text)
	if err = errors.Join(err, f.Close()); err != nil {
		os.Remove(path)
	}
	return err
}

// scopeText says what base records.
func scopeText(base capture.HostRules) string {
	if len(base.Hosts) == 0 {
		return "nothing recorded (no hosts: `reqcove capture add HOST` adds one)"
	}
	s := "recording " + strings.Join(base.Hosts, ", ")
	if len(base.PassHosts) > 0 {
		s += "; passed undecrypted: " + strings.Join(base.PassHosts, ", ")
	}
	return s
}

// cut is s in at most n characters, … ending one cut short.
func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// newScope is cur with req's change, or why it is refused; notes say what
// was left as it was. Removing a host that a wildcard (or "*") takes in is
// refused, naming it: the host would still be recorded.
func newScope(cur capture.HostRules, req ctlRequest) (capture.HostRules, []string, error) {
	allow, pass := slices.Clone(cur.Hosts), slices.Clone(cur.PassHosts)
	list, kind := &allow, "recorded"
	if req.Pass {
		list, kind = &pass, "passed undecrypted"
	}
	var notes []string
	switch req.Cmd {
	case "set":
		allow, pass = req.AllowHosts, req.PassHosts
	case "add":
		for _, h := range req.Hosts {
			if p := coveredBy(*list, h); p != "" {
				notes = append(notes, fmt.Sprintf("%s is %s already%s", h, kind, through(h, p)))
				continue
			}
			*list = append(*list, h)
		}
	case "remove":
		for _, h := range req.Hosts {
			i := slices.Index(*list, h)
			if i < 0 {
				if p := coveredBy(*list, h); p != "" {
					return cur, nil, fmt.Errorf("%s is %s through %s: remove %s instead, or name the hosts with capture set", h, kind, p, p)
				}
				notes = append(notes, fmt.Sprintf("%s was not %s", h, kind))
				continue
			}
			*list = slices.Delete(*list, i, i+1)
			if p := coveredBy(*list, h); p != "" {
				return cur, nil, fmt.Errorf("%s stays %s through %s: remove %s too, or name the hosts with capture set", h, kind, p, p)
			}
			if !req.Pass { // no longer recorded: no longer passed either
				pass = slices.DeleteFunc(pass, func(p string) bool { return p == h })
			}
		}
	}
	next, err := capture.ParseAllowHosts(allow)
	if err != nil {
		return cur, nil, err
	}
	if len(pass) > 0 {
		if !next.All && len(next.Patterns) == 0 {
			return cur, nil, errors.New("hosts passed undecrypted need hosts recorded (as run's --pass-hosts needs --allow-hosts)")
		}
		if next, err = next.WithPass(pass); err != nil {
			return cur, nil, err
		}
	}
	for _, h := range minus(next.PassHosts, cur.PassHosts) { // as run warns of --pass-hosts
		this, _ := capture.ParseAllowHosts([]string{h})
		if !next.Allowed(strings.TrimPrefix(h, "*.")) && !slices.ContainsFunc(next.Hosts, func(a string) bool { return this.Allowed(strings.TrimPrefix(a, "*.")) }) {
			notes = append(notes, h+" is not among the hosts recorded: it passes undecrypted anyway, and nothing about it is kept")
		}
	}
	return next, notes, nil
}

// coveredBy is the spec of list that takes in h: h itself, or a wildcard or
// "*" over it; "" for none.
func coveredBy(list []string, h string) string {
	if slices.Contains(list, h) {
		return h
	}
	for _, p := range list {
		if r, _ := capture.ParseAllowHosts([]string{p}); (p == "*" || strings.HasPrefix(p, "*.")) && r.Allowed(strings.TrimPrefix(h, "*.")) {
			return p
		}
	}
	return ""
}

func through(h, p string) string {
	if h == p {
		return ""
	}
	return " (through " + p + ")"
}

// changes says what next changes of cur; "" for nothing.
func changes(cur, next capture.HostRules) string {
	var out []string
	for _, c := range []struct {
		hosts []string
		what  string
	}{
		{minus(next.Hosts, cur.Hosts), "added"},
		{minus(cur.Hosts, next.Hosts), "removed"},
		{minus(next.PassHosts, cur.PassHosts), "passed undecrypted"},
		{minus(cur.PassHosts, next.PassHosts), "no longer passed undecrypted"},
	} {
		if len(c.hosts) > 0 {
			out = append(out, strings.Join(c.hosts, ", ")+" "+c.what)
		}
	}
	return strings.Join(out, ", ")
}

// minus is a's specs that b has not.
func minus(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}
