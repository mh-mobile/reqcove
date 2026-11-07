package exitnode

import (
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

func TestMatchDevices(t *testing.T) {
	peer := func(id, dns, host string, ips ...string) *ipnstate.PeerStatus {
		p := &ipnstate.PeerStatus{ID: tailcfg.StableNodeID(id), DNSName: dns, HostName: host}
		for _, ip := range ips {
			p.TailscaleIPs = append(p.TailscaleIPs, netip.MustParseAddr(ip))
		}
		return p
	}
	peers := []*ipnstate.PeerStatus{
		peer("nA1", "iphone-test.tail.ts.net.", "Taro's iPhone", "100.101.0.1", "fd7a:115c:a1e0::1"),
		peer("nB2", "ipad-test.tail.ts.net.", "Taro's iPad", "100.101.0.2"),
		peer("nC3", "ipad-test-1.tail.ts.net.", "Taro's iPad", "100.101.0.3"),
	}
	for _, spec := range []string{"iphone-test", "IPHONE-TEST", "Taro's iPhone", "100.101.0.1", "nA1"} {
		got, problems := matchDevices([]string{spec}, peers)
		if len(problems) != 0 || got[netip.MustParseAddr("100.101.0.1")] != (Device{"nA1", "iphone-test"}) || got[netip.MustParseAddr("fd7a:115c:a1e0::1")].ID != "nA1" {
			t.Errorf("spec %q: got %v, problems %v", spec, got, problems)
		}
	}
	got, problems := matchDevices([]string{"iphone-test", "ipad-test-1"}, peers)
	if len(got) != 3 || len(problems) != 0 {
		t.Errorf("two devices: got %v, problems %v", got, problems)
	}
	if _, problems := matchDevices([]string{"Taro's iPad"}, peers); len(problems) != 1 || !strings.Contains(problems[0], "use the machine name") {
		t.Errorf("ambiguous name: problems %v", problems)
	}
	if _, problems := matchDevices([]string{"nope"}, peers); len(problems) != 1 {
		t.Errorf("missing device: problems %v", problems)
	}
}
