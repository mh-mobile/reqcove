package main

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
