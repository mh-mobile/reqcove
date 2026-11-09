package exitnode

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

// Device is a tailnet node whose traffic reqcove carries.
type Device struct {
	ID   string // StableID: what the SOCKS5 user name and the records carry
	Name string // machine (MagicDNS) name, for display
}

// policy is read by the fallback handlers on every new flow, so it is
// replaced as a whole (atomic.Pointer) and never mutated in place.
type policy struct {
	allowSrc []netip.Addr          // tailnet IPs whose traffic we carry
	devices  map[netip.Addr]Device // the same IPs, with who they are
	own      map[netip.Addr]Device // this user's own devices (untagged), carried or not: they may see every flow
	self     []netip.Addr          // this tsnet node's tailnet IPs
	local    []netip.Addr          // this Mac's interface addresses
	onLink   []netip.Prefix        // the networks those addresses are on: the LAN, whatever its range
	socks    bool                  // send TCP 80/443 to mitmproxy
	names    []string              // this node's MagicDNS name and its first label, lower case
}

// Never carried: unspecified, loopback, tailnet, link-local, private LANs,
// special purpose (RFC 6890: never routed on the internet, so whatever answers
// is local), multicast, reserved. Tailscale's filter drops most of these before
// us, but 0.0.0.0 and 127.0.0.1 reach us, and they lead to this Mac's own services.
// The TEST-NETs are left out: nothing answers there, and the tests use them.
var denied = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("192.88.99.0/24"), // 6to4 relay anycast, deprecated (RFC 7526)
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking (RFC 2544)
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

var apple = netip.MustParsePrefix("17.0.0.0/8")

// carried reports whether a flow may leave this Mac at all, for TCP and UDP.
func carried(p *policy, src, dst netip.AddrPort) bool {
	if p == nil {
		return false // not configured yet
	}
	s, d := src.Addr().Unmap(), dst.Addr().Unmap()
	switch {
	case !slices.Contains(p.allowSrc, s):
		return false
	case !d.Is4():
		return false // IPv6: the Linux setup rejected it too; this Mac has no IPv6 uplink
	case slices.Contains(p.self, d), slices.Contains(p.local, d):
		return false
	}
	for _, pfx := range p.onLink {
		if pfx.Contains(d) {
			return false // a LAN numbered from public space is still this Mac's LAN
		}
	}
	for _, pfx := range denied {
		if pfx.Contains(d) {
			return false
		}
	}
	return true
}

// decidePing reports whether netstack may answer a ping by pinging dst from
// this Mac: where TCP and UDP may go, from the same devices.
func decidePing(p *policy, src, dst netip.Addr) bool {
	return carried(p, netip.AddrPortFrom(src, 0), netip.AddrPortFrom(dst, 0))
}

// decideUDP reports whether netstack should forward a UDP flow. It runs
// inside netstack's packet processing, so it must stay a pure table lookup.
func decideUDP(p *policy, src, dst netip.AddrPort) bool {
	if !carried(p, src, dst) {
		return false
	}
	// Drop QUIC except to Apple, so apps fall back to TCP, where mitmproxy sees them.
	return dst.Port() != 443 || apple.Contains(dst.Addr().Unmap())
}

// decideTCP must stay a pure table lookup: tsnet calls it with its lock held.
func decideTCP(p *policy, src, dst netip.AddrPort) verdict {
	if !carried(p, src, dst) {
		return reject
	}
	if apple.Contains(dst.Addr().Unmap()) {
		return direct
	}
	if p.socks && (dst.Port() == 80 || dst.Port() == 443) {
		return socks
	}
	return direct
}
