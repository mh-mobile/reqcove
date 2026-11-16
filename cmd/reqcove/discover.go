package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

// `reqcove capture discover --for D | --end`: for a while, the names of the
// hosts outside the scope the devices reach, and how often, for this
// computer's agents (status, summarize) and reqcove status alone: never over
// --mcp-http nor on the --ui page (withDiscovery is the local status's).

// discoverEndCmd is `reqcove capture discover --end` for this run (run sets
// its --state).
var discoverEndCmd = "reqcove capture discover --end"

// discover answers capture discover.
func discover(ctx context.Context, cap *capture.Capture, req ctlRequest, why string) ctlAnswer {
	if req.End {
		err := cap.EndDiscover(ctx, why)
		switch {
		case errors.Is(err, capture.ErrUnchanged):
			return ctlAnswer{OK: true, Message: "nothing changed: host discovery is not on"}
		case err != nil && !errors.Is(err, capture.ErrPending):
			return ctlAnswer{Message: "refused: " + err.Error() + "; nothing changed"}
		}
		return traced(cap, why, fmt.Sprintf("applied: host discovery ended: no name is taken from now; the %d names seen stay (reqcove status, and this computer's agents) until run restarts or discovery starts again", len(cap.Store.SeenHosts(func(string) bool { return false }))))
	}
	d, err := allowAllFor(req.For)
	if err != nil {
		return ctlAnswer{Message: "refused: " + err.Error() + "; nothing changed"}
	}
	until, was, err := cap.SetDiscover(ctx, why, d)
	pending := errors.Is(err, capture.ErrPending)
	switch {
	case errors.Is(err, capture.ErrUnchanged):
		return ctlAnswer{OK: true, Message: `nothing changed: this run records every host (--allow-hosts "*"): none is outside them`}
	case err != nil && !pending:
		return ctlAnswer{Message: "refused: " + err.Error() + "; nothing changed"}
	}
	msg := "applied: host discovery on until" + allAt(until)
	switch {
	case pending:
		msg = "pending: host discovery asked, until" + allAt(until) + " (mitmproxy has not answered yet: restarting? it starts once mitmproxy is back; status says so meanwhile)"
	case !was.IsZero():
		msg = "applied: host discovery was on until" + allAt(was) + ": now until" + allAt(until) + " (the names seen so far kept)"
	}
	msg += "; kept: the names of the hosts outside the ones recorded that the devices reach (the SNI of a TLS connection, the Host of a request), and how often: never what they send, a URL path or a time" +
		"; shown to this computer's agents (status, summarize) and in reqcove status, never over --mcp-http or on the --ui page" +
		"; not every host: a connection without a name (an address dialed) or with ECH (its outer name only) is missed, and Apple's are left out" +
		"; `reqcove capture add HOST` records one; `reqcove capture discover --end` ends it sooner; not saved: a restart of run ends it"
	return traced(cap, why, msg)
}

// outsideHosts are the names discovery saw that the base scope does not
// record, most seen first, as status and summarize show them. The base
// mitmproxy acknowledged (Scope): status never waits for a change.
func outsideHosts(cap *capture.Capture) (shown []mcpserver.OutHost, kept int) {
	base := cap.Scope()
	hs := cap.Store.SeenHosts(base.Allowed)
	return mcpserver.OutHosts(hs), len(hs)
}

// withDiscovery adds discovery to this computer's status: when it ends, and
// the names it saw (outsideHosts), with a step to end it while on.
func withDiscovery(out mcpserver.StatusOut, cap *capture.Capture) mcpserver.StatusOut {
	out.OutOfScopeHosts, out.OutOfScopeHostsKept = outsideHosts(cap)
	if until := cap.DiscoverUntil(); !until.IsZero() {
		left := max(time.Until(until), 0).Round(time.Second)
		out.DiscoverUntil, out.DiscoverLeft = until.Format(time.RFC3339), left.String()
		out.NextSteps = append(out.NextSteps, fmt.Sprintf("host discovery is on until %s (%v left): the names of hosts outside the ones recorded are kept; to end it now, in your terminal: %s", until.Local().Format("15:04:05"), left, discoverEndCmd))
	} else if asked := cap.DiscoverAsked(); !asked.IsZero() {
		out.NextSteps = append(out.NextSteps, fmt.Sprintf("host discovery is asked until %s, not on yet: mitmproxy has not acknowledged it (restarting?); it starts once mitmproxy is back; to give it up, in your terminal: %s", asked.Local().Format("15:04:05"), discoverEndCmd))
	}
	return out
}
