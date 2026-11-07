package main

import (
	"net/netip"
	"slices"
)

type verdict int

const (
	reject verdict = iota // TCP: RST
	direct                // dial the destination from this Mac
	socks                 // hand to mitmproxy over SOCKS5 (stage 3)
)

func (v verdict) String() string {
	return [...]string{"reject", "direct", "socks"}[v]
}

// policy is read by the fallback handler on every new flow, so it is
// replaced as a whole (atomic.Pointer) and never mutated in place.
type policy struct {
	allowSrc []netip.Addr // tailnet IPs whose traffic we carry
	self     []netip.Addr // this tsnet node's tailnet IPs
	local    []netip.Addr // this Mac's interface addresses
	socks    bool         // send TCP 80/443 to mitmproxy
}

// Never carried: unspecified, loopback, tailnet, link-local, private LANs,
// multicast, reserved. Tailscale's filter drops most of these before us,
// but 0.0.0.0 and 127.0.0.1 reach us, and they lead to this Mac's own services.
var denied = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var apple = netip.MustParsePrefix("17.0.0.0/8")

// decideTCP must stay a pure table lookup: tsnet calls it with its lock held.
func decideTCP(p *policy, src, dst netip.AddrPort) verdict {
	if p == nil {
		return reject // not configured yet
	}
	s, d := src.Addr().Unmap(), dst.Addr().Unmap()
	switch {
	case !slices.Contains(p.allowSrc, s):
		return reject
	case !d.Is4():
		return reject // IPv6: the Linux setup rejected it too; this Mac has no IPv6 uplink
	case slices.Contains(p.self, d), slices.Contains(p.local, d):
		return reject
	}
	for _, pfx := range denied {
		if pfx.Contains(d) {
			return reject
		}
	}
	if apple.Contains(d) {
		return direct
	}
	if p.socks && (dst.Port() == 80 || dst.Port() == 443) {
		return socks
	}
	return direct
}
