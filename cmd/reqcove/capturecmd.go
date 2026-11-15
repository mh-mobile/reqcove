package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mh-mobile/reqcove/internal/capture"
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
	Cmd        string   `json:"cmd"`                   // add, remove, set, stop, start, save or allow-all
	Hosts      []string `json:"hosts,omitempty"`       // add, remove
	Pass       bool     `json:"pass,omitempty"`        // add, remove: of --pass-hosts
	AllowHosts []string `json:"allow_hosts,omitempty"` // set: all of them
	PassHosts  []string `json:"pass_hosts,omitempty"`  // set
	For        string   `json:"for,omitempty"`         // allow-all: how long, as 30m or 2h
	End        bool     `json:"end,omitempty"`         // allow-all: end it now
}

// ctlAnswer is run's answer, for the user: what happened.
type ctlAnswer struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

const captureUse = "reqcove capture add [--pass] HOST… | capture remove [--pass] HOST… | capture set --allow-hosts HOSTS [--pass-hosts HOSTS] | capture stop | capture start | capture save | capture allow-all --for D | capture allow-all --end  [--state DIR]"

func captureCmd(ctx context.Context, args []string) error {
	words, flags := wordsAndFlags(args, "allow-hosts", "pass-hosts", "for")
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	pass := fs.Bool("pass", false, "with add and remove: the hosts carried undecrypted (run's --pass-hosts), not the hosts recorded")
	var allow, passHosts []string
	fs.Func("allow-hosts", `with set: every host recorded, as run's --allow-hosts (not "*")`, func(v string) error { allow = append(allow, v); return nil })
	fs.Func("pass-hosts", "with set: the allowed hosts carried undecrypted, as run's --pass-hosts", func(v string) error { passHosts = append(passHosts, v); return nil })
	forD := fs.String("for", "", "with allow-all: how long every host is recorded, as 30m or 2h (at most 24h)")
	end := fs.Bool("end", false, "with allow-all: end it now")
	if err := parseFlags(fs, flags); err != nil {
		return err
	}
	req := ctlRequest{Pass: *pass, AllowHosts: allow, PassHosts: passHosts, For: *forD, End: *end}
	if len(words) > 0 {
		req.Cmd, req.Hosts = words[0], words[1:]
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
	if r.Cmd != "allow-all" && (r.For != "" || r.End) {
		return r, fmt.Errorf("--for and --end go with capture allow-all (usage: %s)", captureUse)
	}
	switch r.Cmd {
	case "allow-all":
		if len(r.Hosts)+len(r.AllowHosts)+len(r.PassHosts) > 0 || r.Pass {
			return r, errors.New("capture allow-all takes no hosts: it records every host for a while (--for D), or ends that (--end)")
		}
		if r.End == (r.For != "") {
			return r, errors.New("capture allow-all takes --for D (how long, as 30m or 2h; at most 24h) or --end")
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
	case "stop", "start", "save":
		if len(r.Hosts)+len(r.AllowHosts)+len(r.PassHosts) > 0 || r.Pass {
			return r, fmt.Errorf("capture %s takes no hosts (usage: %s)", r.Cmd, captureUse)
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
	case r.Cmd == "allow-all" && r.End:
		return s + " --end"
	case r.Cmd == "allow-all":
		return s + " --for " + r.For // a duration: ParseDuration took it
	case r.Cmd == "stop" || r.Cmd == "start" || r.Cmd == "save":
		return s
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
		return errors.New("reqcove capture runs only in a terminal: it changes what is recorded, which is the user's choice (an agent never runs it). Run it in your own terminal")
	}
	return sendCapture(ctx, out, state, req)
}

// sendCapture asks the running reqcove for the change and prints its answer.
func sendCapture(ctx context.Context, w io.Writer, state string, req ctlRequest) error {
	ctx, cancel := context.WithTimeout(ctx, ctlWait)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", filepath.Join(state, ctlSock))
	if err != nil {
		return noCtl(ctx, state)
	}
	defer conn.Close()
	dl, _ := ctx.Deadline()
	conn.SetDeadline(dl)
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	var a ctlAnswer
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&a); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return fmt.Errorf("the running reqcove (%s) did not answer in %v (stopped, with Ctrl-Z?): whether it took the change, `%s` says", state, ctlWait, withState("reqcove status", state))
		}
		return fmt.Errorf("the running reqcove did not answer: %w", err)
	}
	if !a.OK {
		return errors.New(a.Message)
	}
	fmt.Fprintln(w, a.Message)
	return nil
}

// noCtl says why no run answers on ctl.sock: none runs, one is starting, or
// it is older than v1.1 (it serves mcp.sock only; a v1.1 run serves ctl.sock
// first).
func noCtl(ctx context.Context, state string) error {
	cs, err := dialRun(ctx, state, "reqcove-capture")
	switch {
	case errors.Is(err, errNotRunning):
		return fmt.Errorf("reqcove is not running (%s): nothing to change", state)
	case err != nil:
		return fmt.Errorf("%w: nothing changed", err)
	}
	defer cs.Close()
	v := "older"
	if ir := cs.InitializeResult(); ir != nil && ir.ServerInfo != nil && ir.ServerInfo.Version != "" {
		v = ir.ServerInfo.Version
	}
	return fmt.Errorf("this run is %s: restart it with v1.1 or later to change what it records while it runs (a restart empties the records: `%s > flows.har` keeps them first); nothing changed", v, withState("reqcove har", state))
}

// serveCtl serves ctl.sock until ctx ends. lan: LAN mode, whose hosts are
// set at the start (its proxy takes their names then); origin: where run's
// hosts came from (capture save).
func serveCtl(ctx context.Context, state string, cap *capture.Capture, lan bool, origin hostsOrigin) error {
	path := filepath.Join(state, ctlSock)
	os.Remove(path) // stale: run holds the state's lock
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("control socket: %w (a shorter --state path helps if it is too long)", err)
	}
	if err := os.Chmod(path, 0o600); err != nil { // the directory is 0700 already
		ln.Close()
		return err
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
				json.NewEncoder(conn).Encode(answerCtl(ctx, cap, lan, origin, req))
			}()
		}
	}()
	return nil
}

// errUnchanged: the request changes nothing.
var errUnchanged = errors.New("unchanged")

// answerCtl makes the change and says what happened. A change taken
// (applied, or pending) leaves a trace: run's log line, a cli marker, and
// status's scope_changed_at.
func answerCtl(ctx context.Context, cap *capture.Capture, lan bool, origin hostsOrigin, req ctlRequest) ctlAnswer {
	if lan && req.Cmd == "save" {
		return ctlAnswer{Message: "refused: in LAN mode the hosts recorded are the ones run started with: nothing to save; nothing written"}
	}
	if lan {
		return ctlAnswer{Message: "refused: in LAN mode what is recorded cannot change while run runs (not in this version): restart run with the hosts you want in --allow-hosts; nothing changed"}
	}
	req, err := req.normalized()
	if err != nil {
		return ctlAnswer{Message: "refused: " + err.Error() + "; nothing changed"}
	}
	why := req.String()
	switch req.Cmd {
	case "stop", "start":
		return stopStart(ctx, cap, req.Cmd == "stop", why)
	case "save":
		return save(cap, origin, why)
	case "allow-all":
		return allowAll(ctx, cap, req, why)
	}
	var cur, next capture.HostRules
	var notes []string
	var rec string
	err = cap.ChangeScope(ctx, why, func(c capture.HostRules, r string) (capture.HostRules, error) {
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
			msg += "; not recorded from now on, but their open connections stay decrypted (unrecorded) until they close"
		}
		if len(minus(next.Hosts, cur.Hosts))+len(minus(cur.PassHosts, next.PassHosts)) > 0 {
			msg += "; new connections only: reopen the app to see it now"
		}
	}
	return traced(cap, why, strings.Join(append([]string{msg}, notes...), "; "))
}

// traced is the answer to a change taken, leaving its trace: run's log line
// and a cli marker (status's scope_changed_at comes from the change itself).
func traced(cap *capture.Capture, why, msg string) ctlAnswer {
	log.Printf("%s (reqcove capture, from a terminal): %s", why, msg)
	if _, _, err := cap.Store.AddMarker(cut(why, capture.MaxMarkerText), "cli"); err != nil {
		log.Printf("WARN: the marker of %s: %v", why, err)
	}
	return ctlAnswer{OK: true, Message: msg}
}

// stopStart is capture stop (stop) or capture start. A stop's answer warns
// that the rules stop too: a mock's or map_remote's requests go to the real
// servers then. A stop ends allow-all.
func stopStart(ctx context.Context, cap *capture.Capture, stop bool, why string) ctlAnswer {
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
		if wasAll {
			msg += "allow-all ended (a stop ends it); "
		}
		msg += kept + "; WARNING: the --rules file's rules apply no more (mock, map_local, map_remote, modify_headers, resolve; presets turned off), so the app's requests go to the real servers as it sends them, a mocked API's too" +
			"; connections already decrypted stay decrypted (unrecorded) until they close; not saved: a restart of run records again; `reqcove capture start` records again"
	} else {
		msg = "applied: recording started again: " + scopeText(base) + "; "
		if pending {
			msg = "pending: recording started again, mitmproxy not told yet (restarting? it applies once mitmproxy is back; status shows scope_pending meanwhile): " + scopeText(base) + "; "
		}
		msg += kept + "; the rules apply again (presets stay off until turned on); new connections only: reopen the app to see it now (a connection or WebSocket open before the stop is not recorded again)"
	}
	return traced(cap, why, msg)
}

// allowAllNotes are the warnings of run's other flags that apply while every
// host is recorded (--upstream-proxy, --mcp-http, --web, --local-proxy):
// run sets them.
var allowAllNotes []string

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
		return traced(cap, why, msg+"; "+endedText(cap))
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
	msg += "; WARNING: every app's and site's traffic on the devices is recorded (but Apple's, passed through undecrypted), and agents, and their model providers, can read it" +
		"; apps that pin their certificates (banks, say) fail meanwhile" +
		"; the --rules file's rules apply to the hosts recorded before alone" +
		"; new connections only: reopen an app to see it" +
		"; the records stay after it ends (until evicted, or run restarts), and fill max_flows sooner" +
		"; `reqcove capture allow-all --end` ends it sooner; not saved: a restart of run ends it"
	return traced(cap, why, strings.Join(append([]string{msg}, allowAllNotes...), "; "))
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
	return fmt.Sprintf("%v records kept, %d of them of hosts not recorded now (allow-all's: still readable, until evicted or run restarts); connections already decrypted stay decrypted (unrecorded) until they close",
		cap.Store.Stats()["flows"], cap.Store.OutsideScope(cap.Base()))
}

// save is capture save: the base scope (the hosts a start records) into the
// one hosts file run's --allow-hosts read, without the hosts given as they
// are (a restart takes those again whatever the file says): never "*", never
// none (run refuses a hosts file without hosts). Hosts passed undecrypted are
// not saved.
func save(cap *capture.Capture, o hostsOrigin, why string) ctlAnswer {
	msg, err := saveHosts(cap.Base(), o)
	if err != nil {
		return ctlAnswer{Message: err.Error()}
	}
	cap.NoteChange(why)
	return traced(cap, why, msg)
}

// saveHosts writes base into o's hosts file, and says what it did; an error
// says why nothing was written.
func saveHosts(base capture.HostRules, o hostsOrigin) (string, error) {
	switch {
	case len(o.files) == 0:
		return "", errors.New("nothing to save to: this run's hosts do not come from a hosts file; put `--allow-hosts=@FILE` in the config (FILE: one host a line), as reqcove setup writes it; nothing written")
	case len(o.files) > 1:
		return "", errors.New("nothing to save to: this run's hosts come from several files (" + strings.Join(o.files, ", ") + "): keep one `--allow-hosts=@FILE`; nothing written")
	case slices.Contains(o.passFiles, o.files[0]):
		return "", errors.New("refused: " + o.files[0] + " is run's --pass-hosts file too: saving would change the hosts passed undecrypted; nothing written")
	}
	file, pinned := o.files[0], o.pinned()
	if base.All {
		return "", errors.New(`refused: this run records every host ("*"), which a hosts file never holds; nothing written`)
	}
	var hosts []string
	for _, h := range base.Hosts {
		if _, ok := pinned[h]; !ok && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return "", errors.New("refused: no hosts to write, and run refuses a hosts file without hosts at its next start (whatever --rules, --pass-hosts or --upstream-proxy need): add one first (reqcove capture add HOST), or take the --allow-hosts=@" + file + " line out of the config; nothing written")
	}
	if err := writeHosts(file, hosts, ""); err != nil {
		return "", errors.New("refused: " + err.Error() + "; nothing written")
	}
	msg := "saved to " + file + ": " + strings.Join(hosts, ", ")
	for _, from := range []string{"the command line", "the --config file"} {
		var on, back []string
		for _, h := range slices.Sorted(maps.Keys(pinned)) {
			switch {
			case pinned[h] != from:
			case slices.Contains(base.Hosts, h):
				on = append(on, h)
			default:
				back = append(back, h)
			}
		}
		if len(on) > 0 {
			msg += fmt.Sprintf("; not written, as given on %s (a start with it records them again): %s", from, strings.Join(on, ", "))
		}
		if len(back) > 0 {
			msg += fmt.Sprintf("; removed now, but given on %s, so a start with it records them again: %s", from, strings.Join(back, ", "))
		}
	}
	if len(base.PassHosts) > 0 {
		msg += "; the hosts passed undecrypted are not saved: a start passes run's --pass-hosts"
	}
	return msg, nil
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
