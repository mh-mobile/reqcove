package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
)

// The console's Settings panel (the local page; since v1.3): run's settings
// the config writer writes (configFlags), as the --config file has them,
// those given on run's command line pinned (they win over the file), and the
// terminal's own shown, never written (--upstream-ca may be cleared). A
// change goes through the writer alone (planConfig: typed, checked, the
// file's revision, config.prev) and is taken at the next restart, which the
// page asks for too (restartOp), after listing what it would change.

// settingFlags are the settings the page writes, in its order; confirmFlags
// those written only once the page showed run's own words for the flag
// (run -h) and asked (--device too when one is added); manyFlags those that
// repeat.
var (
	settingFlags = []string{"device", "keep-awake", "proxy-port", "hostname", "verbose", "ui", "mcp-http", "local-proxy", "dns", "upstream-proxy", "mask-names"}
	confirmFlags = map[string]bool{"ui": true, "mcp-http": true, "local-proxy": true, "dns": true, "upstream-proxy": true, "mask-names": true}
	manyFlags    = map[string]bool{"device": true, "mask-names": true}
)

// terminalSettings are shown read-only, with why.
var terminalSettings = []struct{ flag, why string }{
	{"upstream-ca", "a CA to trust: set in your terminal (the page may only clear it)"},
	{"rules", "a file of rules that change where requests go: set in your terminal"},
	{"proto", "a file reqcove reads: set in your terminal"},
	{"mask-values", "patterns that can be secrets: never shown, set in your terminal"},
}

// settingWarning is run's own words for flag (run -h), shown before the
// page's confirm.
func settingWarning(flag string) string {
	return runFlagSet().Lookup(flag).Usage
}

type pageSettings struct {
	Config   string        `json:"config,omitempty"`
	Rev      string        `json:"rev"`                 // the config's revision: a change sends it back
	ReadOnly string        `json:"read_only,omitempty"` // why none is written
	Settings []pageSetting `json:"settings"`
	Devices  []pageDevice  `json:"devices"` // the picker: the user's own devices, untagged
}

type pageSetting struct {
	Flag    string   `json:"flag"`
	Values  []string `json:"values"`           // the file's (an @FILE's path, never what it holds)
	Pinned  []string `json:"pinned,omitempty"` // given on run's command line
	Default string   `json:"default"`
	Edit    string   `json:"edit,omitempty"` // restart, confirm or clear; none: read-only
	Why     string   `json:"why,omitempty"`  // why read-only
	Warning string   `json:"warning,omitempty"`
	Set     string   `json:"set,omitempty"` // --mask-values: how many, never what
}

type pageDevice struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// values are the values of flag among uses.
func values(uses []flagUse, flag string) []string {
	out := []string{}
	for _, u := range uses {
		if u.name == flag {
			out = append(out, u.value)
		}
	}
	return out
}

// shown are a flag's values as the page shows them: an --upstream-proxy run
// would refuse (a user and password in it, say, edited in by hand) never.
func shown(flag string, vs []string) []string {
	for i, v := range vs {
		if _, err := upstreamAddr(v, ""); flag == "upstream-proxy" && err != nil {
			vs[i] = "(set, not shown: not a URL run takes)"
		}
	}
	return vs
}

// ownDevices are the user's own untagged devices from run's netmap.
func (p *page) ownDevices() map[string]string {
	if p.st.status == nil {
		return nil
	}
	n, _ := p.st.status().Node.(exitnode.Status)
	return n.Own
}

// settings is GET /api/settings.
func (p *page) settings(w http.ResponseWriter, _ *http.Request) {
	fs := runFlagSet()
	cmd, _ := commandLine(fs, p.st.o.args)
	config := p.st.o.config
	out := pageSettings{Config: config, Settings: []pageSetting{}, Devices: []pageDevice{}}
	var file []flagUse
	if config == "" {
		out.ReadOnly = "run was started from flags alone (no --config file): its settings are its command line's; change them there and start it again"
	} else if b, err := configBytes(config, 0); err != nil {
		out.ReadOnly = "the config does not read: " + err.Error()
	} else if file, _, err = configUses(fs, config, b); err != nil {
		out.ReadOnly = "the config does not read: " + err.Error()
	} else {
		out.Rev = configRev(b)
	}
	show := func(flag string) pageSetting {
		s := pageSetting{Flag: flag, Values: shown(flag, values(file, flag)), Default: fs.Lookup(flag).DefValue}
		if pinned := values(cmd, flag); len(pinned) > 0 {
			s.Pinned = shown(flag, pinned)
		}
		return s
	}
	for _, f := range settingFlags {
		s := show(f)
		switch {
		case out.ReadOnly != "":
		case s.Pinned != nil:
			s.Why = "given on run's command line, which wins over the file: change it there"
		case slices.ContainsFunc(s.Values, func(v string) bool { return strings.HasPrefix(v, "@") }):
			s.Why = "read from a file (@FILE): change it in your terminal"
		case confirmFlags[f]:
			s.Edit = "confirm"
		default:
			s.Edit = "restart"
		}
		if s.Edit != "" && (confirmFlags[f] || f == "device") {
			s.Warning = settingWarning(f)
		}
		out.Settings = append(out.Settings, s)
	}
	for _, t := range terminalSettings {
		s := show(t.flag)
		s.Why = t.why
		if t.flag == "mask-values" {
			if n := len(s.Values) + len(s.Pinned); n > 0 {
				s.Set = fmt.Sprintf("set (%d)", n)
			}
			s.Values, s.Pinned, s.Default = []string{}, nil, ""
		} else if t.flag == "upstream-ca" && out.ReadOnly == "" && s.Pinned == nil && len(s.Values) > 0 {
			s.Edit = "clear"
		}
		out.Settings = append(out.Settings, s)
	}
	own := p.ownDevices()
	for _, id := range slices.SortedFunc(maps.Keys(own), func(a, b string) int { return strings.Compare(own[a], own[b]) }) {
		out.Devices = append(out.Devices, pageDevice{ID: id, Name: own[id]})
	}
	answer(w, http.StatusOK, out)
}

// setSetting is POST /api/settings: one setting's values written to the
// config through the writer, on the revision the page read.
func (p *page) setSetting(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Flag      string   `json:"flag"`
		Values    []string `json:"values"`
		Rev       string   `json:"rev"`
		Confirmed bool     `json:"confirmed"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil {
		answer(w, http.StatusBadRequest, map[string]any{"error": "refused: not JSON of the page"})
		return
	}
	refuse := func(msg string) {
		answer(w, http.StatusOK, map[string]any{"ok": false, "message": "refused: " + msg + "; nothing written"})
	}
	if !slices.Contains(settingFlags, in.Flag) && (in.Flag != "upstream-ca" || len(in.Values) > 0) {
		answer(w, http.StatusBadRequest, map[string]any{"error": "refused: the page writes " + strings.Join(settingFlags, ", ") + " and clears upstream-ca alone (the others are your terminal's); nothing written"})
		return
	}
	if len(in.Values) > 1 && !manyFlags[in.Flag] {
		refuse("--" + in.Flag + " takes one value")
		return
	}
	if in.Rev == "" {
		refuse("no revision of the config")
		return
	}
	st := p.st
	st.mu.Lock() // as capture save: one write at a time
	defer st.mu.Unlock()
	config := st.o.config
	if config == "" {
		refuse("run was started from flags alone (no --config file): change its command line")
		return
	}
	plan, err := planConfig(config, st.o.args, nil, configEdit{Flag: in.Flag, Values: in.Values})
	if err != nil {
		refuse(err.Error())
		return
	}
	if plan.rev != in.Rev {
		refuse("the config changed since this page read it (another tab, or an edit): the page shows it as it is now")
		return
	}
	added := false
	if in.Flag == "device" {
		file, _, _ := configUses(runFlagSet(), config, plan.old)
		had, own := values(file, "device"), p.ownDevices()
		for _, v := range in.Values {
			if slices.Contains(had, v) {
				continue
			}
			if _, ok := own[v]; !ok {
				refuse("a device added here is one of your own devices from the list (its StableID); another one in your terminal")
				return
			}
			added = true
		}
	}
	if (confirmFlags[in.Flag] || added) && !in.Confirmed {
		refuse("confirm first: " + settingWarning(in.Flag))
		return
	}
	if bytes.Equal(plan.old, plan.new) {
		answer(w, http.StatusOK, map[string]any{"ok": true, "message": "unchanged: the config has that already"})
		return
	}
	if err := plan.commit(); err != nil {
		refuse(err.Error())
		return
	}
	log.Printf("reqcove console: --%s written to %s%s; run takes it at its next restart", in.Flag, config, fromConsole) // never its values
	diff := plan.diff()
	if in.Flag == "upstream-proxy" { // the line taken out may hold what shown hides
		diff = "--upstream-proxy\n"
	}
	answer(w, http.StatusOK, map[string]any{"ok": true, "message": fmt.Sprintf("written to %s (the file before kept as %s.prev):\n%srun takes it at its next restart", config, config, diff)})
}

// pageRestart is GET /api/restart: what a restart would change, before the
// page's confirm. message: why it would be refused (no diff then).
type pageRestart struct {
	Message string     `json:"message,omitempty"`
	Rev     string     `json:"rev"`
	Diff    []pageDiff `json:"diff"`
	Records any        `json:"records"`
	Warning string     `json:"warning"`
}

// pageDiff is a setting the config on disk has otherwise than run started
// with: changed alone where its values are never shown.
type pageDiff struct {
	Flag    string   `json:"flag"`
	Was     []string `json:"was,omitempty"`
	Now     []string `json:"now,omitempty"`
	Changed bool     `json:"changed,omitempty"`
	Pinned  bool     `json:"pinned,omitempty"` // given on run's command line too
}

// configRevNow is the revision of the config on disk ("" for none or unread).
func configRevNow(config string) string {
	if config == "" {
		return ""
	}
	b, err := configBytes(config, 0)
	if err != nil {
		return ""
	}
	return configRev(b)
}

// fileFlags are the flags whose @FILE a restart reads: the hosts and the masking.
var fileFlags = []string{"allow-hosts", "pass-hosts", "mask-names", "mask-values"}

// restartInputs are what a restart would read: b, the config's text (nil for
// none), and the @FILEs of fileFlags in it and on run's command line, each
// read once (texts: by absolute path; one not read left out); rev is the
// revision of them all, which the page's restart confirms.
func restartInputs(config string, args []string, b []byte) (texts map[string]string, rev string) {
	fs := runFlagSet()
	uses, _ := commandLine(fs, args)
	if config != "" {
		file, _, _ := configUses(fs, config, b)
		uses = append(file, uses...)
	}
	texts = map[string]string{}
	h := sha256.New()
	h.Write(b)
	for _, u := range uses {
		p, ok, err := atFile(u.value)
		if !slices.Contains(fileFlags, u.name) || !ok || err != nil {
			continue
		}
		t, err := os.ReadFile(p)
		fmt.Fprintf(h, "\x00%s\x00%v\x00%d\x00", p, err == nil, len(t))
		h.Write(t)
		if err == nil {
			texts[p] = string(t)
		}
	}
	return texts, hex.EncodeToString(h.Sum(nil))
}

// restartRevNow is restartInputs' rev for the config on disk ("" unread).
func restartRevNow(o *runOpts) string {
	var b []byte
	if o.config != "" {
		var err error
		if b, err = configBytes(o.config, 0); err != nil {
			return ""
		}
	}
	_, rev := restartInputs(o.config, o.args, b)
	return rev
}

func recordCount(cap *capture.Capture) any {
	if cap == nil {
		return 0
	}
	return cap.Store.Stats()["flows"]
}

// restartDiff is GET /api/restart: every flag of the config on disk that
// differs from the config run started from (st.startConfig, with capture
// save's lines), the terminal's own too, --mask-values and what masking
// @FILEs hold as changed alone, and the hosts that hosts files give otherwise
// than when run last read or wrote them. Its rev covers the config and those
// files (restartInputs).
func (p *page) restartDiff(w http.ResponseWriter, _ *http.Request) {
	st := p.st
	records := recordCount(p.cap)
	out := pageRestart{Diff: []pageDiff{}, Records: records, Warning: "A restart empties the records: " + restartEmpties(records) + " (the markers, the agents' requests, hosts not saved, allow-all and discovery, the presets turned on go too)"}
	st.mu.Lock()
	start, origin := st.startConfig, st.origin
	st.mu.Unlock()
	config := st.o.config
	var now []byte
	if config != "" {
		var err error
		if now, err = configBytes(config, 0); err != nil {
			out.Message = "a restart would be refused: " + err.Error()
			answer(w, http.StatusOK, out)
			return
		}
	}
	texts, rev := restartInputs(config, st.o.args, now)
	out.Rev = rev
	n, err := checkFlags(st.o.args, now, texts)
	if err != nil {
		out.Message = "a restart would be refused: the next start would refuse the settings: " + err.Error()
		answer(w, http.StatusOK, out)
		return
	}
	fs := runFlagSet()
	was, _, _ := configUses(fs, config, start)
	is, _, _ := configUses(fs, config, now)
	cmd, _ := commandLine(fs, st.o.args)
	flags := map[string]bool{}
	for _, u := range append(slices.Clone(was), is...) {
		flags[u.name] = true
	}
	for _, f := range slices.Sorted(maps.Keys(flags)) {
		a, b := values(was, f), values(is, f)
		if slices.Equal(a, b) {
			continue
		}
		d := pageDiff{Flag: f, Was: a, Now: b, Pinned: len(values(cmd, f)) > 0}
		if f == "mask-values" {
			d.Was, d.Now, d.Changed = nil, nil, true
		}
		out.Diff = append(out.Diff, d)
	}
	for _, m := range []struct {
		flag      string
		was, next []string
	}{{"mask-names", st.o.maskNames, n.maskNames}, {"mask-values", st.o.maskValues, n.maskValues}} {
		if !slices.Equal(m.was, m.next) && !slices.ContainsFunc(out.Diff, func(d pageDiff) bool { return d.Flag == m.flag }) {
			out.Diff = append(out.Diff, pageDiff{Flag: m.flag, Changed: true}) // in an @FILE
		}
	}
	for _, h := range []struct {
		flag     string
		was, now hostsOrigin
	}{{"allow-hosts", origin, n.origin}, {"pass-hosts", origin.passOrigin(), n.origin.passOrigin()}} {
		a, b := slices.Sorted(maps.Keys(h.was.inFiles)), slices.Sorted(maps.Keys(h.now.inFiles))
		if !slices.Equal(a, b) { // an edit to a hosts file, which the config's lines do not show
			out.Diff = append(out.Diff, pageDiff{Flag: h.flag + "=@FILE (its hosts)", Was: a, Now: b})
		}
	}
	answer(w, http.StatusOK, out)
}

// restartNow is POST /api/restart {rev}: the restart op, as reqcove restart
// asks it, on the config the page listed; it starts once the answer is out.
func (p *page) restartNow(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Rev string `json:"rev"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil {
		answer(w, http.StatusBadRequest, map[string]any{"error": "refused: not JSON of the page"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), ctlWait-time.Second)
	defer cancel()
	a := answerCtl(ctx, p.cap, p.st, ctlRequest{Cmd: "restart", rev: in.Rev, from: "console"})
	// Whole, with its length, before the restart closes the server's
	// connections: not chunked, whose last chunk waits for the handler's end.
	b, _ := json.Marshal(map[string]any{"ok": a.OK, "message": a.Message})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Write(b)
	http.NewResponseController(w).Flush()
	if a.after != nil {
		a.after()
	}
}
