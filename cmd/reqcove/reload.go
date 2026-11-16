package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// `reqcove reload` reads run's files again (its --config, the hosts files it
// names and the --rules file) and puts their hosts and rules in force
// together, without a restart: everything is checked first, and on any
// failure nothing changes. Over ctl.sock as `reqcove capture`, with its
// guards (a terminal only, refused in LAN mode, a trace). Run's other
// settings take a restart.

const reloadUse = "reqcove reload [--state DIR]"

func reloadCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("reload", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return captureIn(ctx, os.Stdin, os.Stdout, *state, ctlRequest{Cmd: "reload"})
}

// reload answers reqcove reload. Called with st.mu held.
func reload(ctx context.Context, cap *capture.Capture, st *ctlState, why string) ctlAnswer {
	o := st.o
	if o.config == "" && len(st.origin.files)+len(st.origin.passOrigin().files) == 0 && o.rules == "" {
		return ctlAnswer{Message: "nothing to reload: this run was started from flags alone (no --config, no --allow-hosts=@FILE, no --rules): `reqcove capture` changes its hosts, a restart the rest; nothing changed"}
	}
	n, err := reloadFlags(o.args)
	if err != nil {
		return ctlAnswer{Message: "refused: " + err.Error() + "; nothing changed"}
	}
	other := restartOnly(o, n)
	var rules []byte
	if o.rules != "" && !slices.Contains(other, "--rules") {
		if rules, err = os.ReadFile(o.rules); err != nil {
			return ctlAnswer{Message: "refused: --rules: " + err.Error() + "; nothing changed"}
		}
	}
	otherLine := ""
	if len(other) > 0 {
		otherLine = "\nother settings take effect at the next start of run: " + strings.Join(other, ", ")
	}
	cur := cap.Base()
	if n.allow.All && !cur.All { // as capture set refuses it: never every host by a file's edit
		return ctlAnswer{Message: `refused: the files give "*", every app's and site's traffic, which reload never turns on: ` + "`reqcove capture allow-all --for D`" + ` records every host for a while, a restart of run with "*" for good; nothing changed` + otherLine}
	}
	if changes(cur, n.allow) == "" && rules == nil {
		return ctlAnswer{OK: true, Message: "nothing changed: the hosts are the files' already" + otherLine}
	}
	loaded, err := cap.Reload(ctx, why, n.allow, rules)
	pending := errors.Is(err, capture.ErrPending)
	if err != nil && !pending {
		msg := err.Error()
		if !strings.Contains(msg, "nothing changed") {
			msg = "refused: " + msg + "; nothing changed"
		}
		return ctlAnswer{Message: msg}
	}
	lost := undone(st.loaded, cur, n.allow)
	st.setOrigin(n.origin, n.allow)
	hosts := changes(cur, n.allow)
	if hosts == "" {
		hosts = "the hosts as they were"
	}
	msg := "applied: " + hosts
	if pending {
		msg = "pending: " + hosts + " (mitmproxy has not acknowledged it yet: restarting? it applies once mitmproxy is back; status shows scope_pending meanwhile)"
	}
	if lost != "" {
		msg += "; this replaces what reqcove capture changed and did not save: " + lost
	}
	switch {
	case rules != nil && loaded == nil: // pending
		msg += "; the rules of " + o.rules + " come with these hosts (mitmproxy, not told, is restarted with both)"
	case rules != nil:
		msg += "; rules from " + o.rules + ": " + ruleCounts(loaded) + "; presets are off (new rules turn them off)"
	}
	msg += fmt.Sprintf("; %v records kept", cap.Store.Stats()["flows"])
	switch {
	case cap.Stopped():
		msg += "; recording is stopped: these are the hosts `reqcove capture start` records, nothing is recorded until then"
	case !cap.AllowAllUntil().IsZero():
		msg += "; allow-all is on: every host is recorded until" + allAt(cap.AllowAllUntil()) + ", these hosts after"
	default:
		if len(minus(cur.Hosts, n.allow.Hosts))+len(minus(n.allow.PassHosts, cur.PassHosts)) > 0 {
			msg += "; not recorded from now on, but their open connections stay decrypted (unrecorded) until they close" + openNote
		}
		if len(minus(n.allow.Hosts, cur.Hosts))+len(minus(cur.PassHosts, n.allow.PassHosts)) > 0 {
			msg += "; new connections only: reopen the app to see it now"
		}
	}
	return traced(cap, why, "", msg+otherLine)
}

// undone is what next undoes of the changes made since loaded (to cur): the
// hosts added that it leaves out, those removed that it brings back.
func undone(loaded, cur, next capture.HostRules) string {
	var out []string
	for _, l := range []struct {
		from, to, next []string
		what           string
	}{
		{loaded.Hosts, cur.Hosts, next.Hosts, "recorded"},
		{loaded.PassHosts, cur.PassHosts, next.PassHosts, "passed undecrypted"},
	} {
		for _, h := range l.to {
			if !slices.Contains(l.from, h) && !slices.Contains(l.next, h) {
				out = append(out, h+" no longer "+l.what+" (added)")
			}
		}
		for _, h := range l.from {
			if !slices.Contains(l.to, h) && slices.Contains(l.next, h) {
				out = append(out, h+" "+l.what+" again (removed)")
			}
		}
	}
	return strings.Join(out, ", ")
}

// ruleCounts is the rules by kind, as "mock 2, map_remote 1".
func ruleCounts(counts map[string]int) string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(counts)) {
		if counts[k] > 0 {
			out = append(out, fmt.Sprintf("%s %d", k, counts[k]))
		}
	}
	if len(out) == 0 {
		return "no rules"
	}
	return strings.Join(out, ", ")
}

// restartOnly names run's settings, other than the hosts, that differ
// between a and b: only a restart takes them. Never their values (a
// --mask-values pattern may be a secret).
func restartOnly(a, b *runOpts) []string {
	var out []string
	for _, s := range restartSettings {
		if s.of(a) != s.of(b) {
			out = append(out, "--"+s.name)
		}
	}
	return out
}

// restartSettings are run's flags but those reload takes (--allow-hosts,
// --pass-hosts), those that cannot change (--config, --lan: refused in a
// config file, and the command line is as it was), each as a string.
var restartSettings = []struct {
	name string
	of   func(*runOpts) string
}{
	{"device", func(o *runOpts) string { return strings.Join(o.devices, "\n") }},
	{"rules", func(o *runOpts) string { return o.rules }},
	{"rules-reload", func(o *runOpts) string { return fmt.Sprint(o.rulesReload) }},
	{"web", func(o *runOpts) string { return fmt.Sprint(o.web) }},
	{"no-redact", func(o *runOpts) string { return fmt.Sprint(o.noRedact) }},
	{"proto", func(o *runOpts) string { return o.proto }},
	{"mask-names", func(o *runOpts) string { return strings.Join(o.maskNames, "\n") }},
	{"mask-values", func(o *runOpts) string { return strings.Join(o.maskValues, "\n") }},
	{"state", func(o *runOpts) string { return o.state }},
	{"hostname", func(o *runOpts) string { return o.hostname }},
	{"dns", func(o *runOpts) string { return o.dnsFlag }},
	{"mitmproxy-spec", func(o *runOpts) string { return o.mitmSpec }},
	{"python", func(o *runOpts) string { return o.python }},
	{"uvx", func(o *runOpts) string { return o.uvx }},
	{"proxy-port", func(o *runOpts) string { return fmt.Sprint(o.proxyPort) }},
	{"mcp-http", func(o *runOpts) string { return fmt.Sprint(o.mcpHTTP) }},
	{"ui", func(o *runOpts) string { return fmt.Sprint(o.ui) }},
	{"upstream-proxy", func(o *runOpts) string { return o.upstreamProxy }},
	{"upstream-ca", func(o *runOpts) string { return o.upstreamCA }},
	{"verbose", func(o *runOpts) string { return fmt.Sprint(o.verbose) }},
	{"lan-interface", func(o *runOpts) string { return o.lanIface }},
	{"local-proxy", func(o *runOpts) string { return fmt.Sprint(o.localProxy) }},
	{"keep-awake", func(o *runOpts) string { return o.keepAwake }},
}
