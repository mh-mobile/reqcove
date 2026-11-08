package exitnode

import (
	"net/netip"
	"testing"
)

func TestDecideTCP(t *testing.T) {
	iphone := netip.MustParseAddr("100.101.0.1")
	other := netip.MustParseAddr("100.101.0.2")
	self := netip.MustParseAddr("100.101.0.3")
	p := &policy{
		allowSrc: []netip.Addr{iphone},
		self:     []netip.Addr{self, netip.MustParseAddr("fd7a:115c:a1e0::1")},
		local:    []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("203.0.113.7")},
	}
	withSocks := *p
	withSocks.socks = true

	tests := []struct {
		p    *policy
		src  netip.Addr
		dst  string
		want verdict
	}{
		{p, iphone, "1.1.1.1:443", direct},
		{p, iphone, "17.253.144.10:443", direct},
		{p, iphone, "93.184.215.14:8443", direct},
		{&withSocks, iphone, "1.1.1.1:443", socks},
		{&withSocks, iphone, "1.1.1.1:80", socks},
		{&withSocks, iphone, "17.253.144.10:443", direct}, // Apple never goes to mitmproxy
		{&withSocks, iphone, "1.1.1.1:22", direct},

		{nil, iphone, "1.1.1.1:443", reject},           // before startup finished
		{p, other, "1.1.1.1:443", reject},              // not an allowed device
		{p, iphone, "127.0.0.1:8081", reject},          // mitmweb
		{p, iphone, "127.0.0.1:1080", reject},          // SOCKS5
		{p, iphone, "0.0.0.0:80", reject},              // reaches localhost on macOS
		{p, iphone, "100.101.0.3:22", reject},          // this node
		{p, iphone, "100.101.0.4:22", reject},          // other tailnet node
		{p, iphone, "192.168.1.10:22", reject},         // this Mac on the LAN
		{p, iphone, "203.0.113.7:22", reject},          // this Mac, outside RFC 1918
		{p, iphone, "192.168.1.1:53", reject},          // home router
		{p, iphone, "169.254.1.1:80", reject},          // link-local
		{p, iphone, "224.0.0.251:5353", reject},        // multicast
		{p, iphone, "255.255.255.255:9", reject},       // broadcast
		{p, iphone, "198.18.0.1:80", reject},           // benchmarking: never on the internet
		{p, iphone, "192.0.0.192:80", reject},          // IETF protocol assignments
		{p, iphone, "192.88.99.1:80", reject},          // deprecated 6to4 relay
		{p, iphone, "[2606:4700::1111]:443", reject},   // IPv6
		{p, iphone, "[::ffff:127.0.0.1]:8081", reject}, // IPv4-mapped loopback
		{&withSocks, other, "1.1.1.1:443", reject},
	}
	for _, tt := range tests {
		got := decideTCP(tt.p, netip.AddrPortFrom(tt.src, 50000), netip.MustParseAddrPort(tt.dst))
		if got != tt.want {
			t.Errorf("decideTCP(src=%v, dst=%v, socks=%v) = %v, want %v", tt.src, tt.dst, tt.p != nil && tt.p.socks, got, tt.want)
		}
	}
}

func TestDecideUDP(t *testing.T) {
	iphone := netip.MustParseAddr("100.101.0.1")
	other := netip.MustParseAddr("100.101.0.2")
	p := &policy{
		allowSrc: []netip.Addr{iphone},
		self:     []netip.Addr{netip.MustParseAddr("100.101.0.3")},
		local:    []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("203.0.113.7")},
	}
	tests := []struct {
		p    *policy
		src  netip.Addr
		dst  string
		want bool
	}{
		{p, iphone, "17.248.225.4:443", true}, // Apple QUIC passes
		{p, iphone, "1.1.1.1:443", false},     // other QUIC falls back to TCP
		{p, iphone, "1.1.1.1:53", true},       // DNS to a public resolver
		{p, iphone, "8.8.8.8:3478", true},     // STUN for calls
		{p, iphone, "203.0.113.50:50000", true},

		{nil, iphone, "1.1.1.1:53", false},
		{p, other, "1.1.1.1:53", false},
		{p, iphone, "100.101.0.3:53", false}, // this node
		{p, iphone, "127.0.0.1:53", false},   // netstack would hand it to this Mac's loopback
		{p, iphone, "0.0.0.0:53", false},
		{p, iphone, "192.168.1.1:53", false},   // home router
		{p, iphone, "203.0.113.7:5353", false}, // this Mac, outside RFC 1918
		{p, iphone, "224.0.0.251:5353", false},
		{p, iphone, "198.18.0.1:53", false},
		{p, iphone, "[2606:4700::1111]:53", false},
	}
	for _, tt := range tests {
		got := decideUDP(tt.p, netip.AddrPortFrom(tt.src, 50000), netip.MustParseAddrPort(tt.dst))
		if got != tt.want {
			t.Errorf("decideUDP(src=%v, dst=%v) = %v, want %v", tt.src, tt.dst, got, tt.want)
		}
	}
}

// Any peer's UDP reaches logUDPOnce (with --verbose), so what it remembers stays bounded.
func TestDecidePing(t *testing.T) {
	iphone := netip.MustParseAddr("100.101.0.1")
	p := &policy{allowSrc: []netip.Addr{iphone}, local: []netip.Addr{netip.MustParseAddr("192.168.1.10")}}
	for _, tt := range []struct {
		src, dst string
		want     bool
	}{
		{"100.101.0.1", "1.1.1.1", true},
		{"100.101.0.2", "1.1.1.1", false}, // not a --device
		{"100.101.0.1", "127.0.0.1", false},
		{"100.101.0.1", "192.168.1.1", false},
		{"100.101.0.1", "2606:4700::1111", false},
	} {
		if got := decidePing(p, netip.MustParseAddr(tt.src), netip.MustParseAddr(tt.dst)); got != tt.want {
			t.Errorf("decidePing(%s, %s) = %v, want %v", tt.src, tt.dst, got, tt.want)
		}
	}
}

func TestLogUDPOnceBounded(t *testing.T) {
	for i := range 3 * maxSeen {
		logUDPOnce(netip.MustParseAddrPort("100.101.0.2:1"), netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)}), uint16(i)), false)
	}
	n := int64(0)
	seen.Range(func(_, _ any) bool { n++; return true })
	if n > maxSeen {
		t.Errorf("remembers %d flows, want at most %d", n, maxSeen)
	}
	for len(events) > 0 { // drop the lines this made
		<-events
	}
}

// A LAN numbered from public space (11.22.33.0/24 here) is refused like any
// other LAN: its neighbours, not only this Mac's own address.
func TestOnLinkNetworksRefused(t *testing.T) {
	iphone := netip.MustParseAddr("100.101.0.1")
	p := &policy{
		allowSrc: []netip.Addr{iphone},
		local:    []netip.Addr{netip.MustParseAddr("11.22.33.10")},
		onLink:   []netip.Prefix{netip.MustParsePrefix("11.22.33.0/24")},
		socks:    true,
	}
	src := netip.AddrPortFrom(iphone, 50000)
	for _, dst := range []string{"11.22.33.10:80", "11.22.33.20:80", "11.22.33.20:22", "11.22.33.255:53"} {
		d := netip.MustParseAddrPort(dst)
		if v := decideTCP(p, src, d); v != reject {
			t.Errorf("TCP to %s: %v", dst, v)
		}
		if decideUDP(p, src, d) {
			t.Errorf("UDP to %s carried", dst)
		}
	}
	if v := decideTCP(p, src, netip.MustParseAddrPort("11.22.34.20:443")); v != socks {
		t.Errorf("the next network over: %v, want socks", v)
	}
}

func TestInterfaceAddrsOnLink(t *testing.T) {
	_, nets := interfaceAddrs()
	for _, n := range nets {
		if !n.Addr().Is4() || n.Bits() < 8 || n.Bits() >= 32 || n.Addr().IsLoopback() || n != n.Masked() {
			t.Errorf("unexpected on-link network %v", n)
		}
	}
}
