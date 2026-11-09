package exitnode

import (
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

func TestMatchDevices(t *testing.T) {
	peer := func(id, dns, host string, user tailcfg.UserID, ips ...string) *ipnstate.PeerStatus {
		p := &ipnstate.PeerStatus{ID: tailcfg.StableNodeID(id), DNSName: dns, HostName: host, UserID: user}
		for _, ip := range ips {
			p.TailscaleIPs = append(p.TailscaleIPs, netip.MustParseAddr(ip))
		}
		return p
	}
	self := peer("nSELF", "reqcove.tail.ts.net.", "reqcove", 1, "100.101.0.100")
	peers := []*ipnstate.PeerStatus{
		peer("nA1", "iphone-test.tail.ts.net.", "Taro's iPhone", 1, "100.101.0.1", "fd7a:115c:a1e0::1"),
		peer("nB2", "ipad-test.tail.ts.net.", "Taro's iPad", 1, "100.101.0.2"),
		peer("nC3", "ipad-test-1.tail.ts.net.", "Taro's iPad", 1, "100.101.0.3"),
		peer("nT4", "tester-phone.tail.ts.net.", "Tester's iPhone", 2, "100.101.0.4"),
	}
	for _, spec := range []string{"iphone-test", "IPHONE-TEST", "Taro's iPhone", "100.101.0.1", "nA1"} {
		got, problems := matchDevices([]string{spec}, self, peers)
		if len(problems) != 0 || got[netip.MustParseAddr("100.101.0.1")] != (Device{"nA1", "iphone-test"}) || got[netip.MustParseAddr("fd7a:115c:a1e0::1")].ID != "nA1" {
			t.Errorf("spec %q: got %v, problems %v", spec, got, problems)
		}
	}
	got, problems := matchDevices([]string{"iphone-test", "ipad-test-1"}, self, peers)
	if len(got) != 3 || len(problems) != 0 {
		t.Errorf("two devices: got %v, problems %v", got, problems)
	}
	if _, problems := matchDevices([]string{"Taro's iPad"}, self, peers); len(problems) != 1 || !strings.Contains(problems[0], "use the machine name") {
		t.Errorf("ambiguous name: problems %v", problems)
	}
	if _, problems := matchDevices([]string{"nope"}, self, peers); len(problems) != 1 {
		t.Errorf("missing device: problems %v", problems)
	}
	// Another user's device: by machine name, not by the name it gives itself.
	if got, _ := matchDevices([]string{"tester-phone"}, self, peers); got[netip.MustParseAddr("100.101.0.4")].ID != "nT4" {
		t.Errorf("another user's device by machine name: %v", got)
	}

	// Names nobody can claim: while the real iPhone is not in the netmap (say,
	// under Tailnet Lock), another user's laptop calling itself "Taro's iPhone",
	// or a node shared in from another tailnet with the same first label, is
	// not taken for it. Exact identifiers (IP, StableID) still pick the shared node.
	impostor := peer("nEVIL", "bobs-laptop.tail.ts.net.", "Taro's iPhone", 2, "100.101.9.9")
	shared := peer("nSHARED", "iphone-test.other-tailnet.ts.net.", "Taro's iPhone", 1, "100.101.9.8")
	for _, spec := range []string{"Taro's iPhone", "iphone-test"} {
		if got, _ := matchDevices([]string{spec}, self, []*ipnstate.PeerStatus{impostor, shared}); len(got) != 0 {
			t.Errorf("spec %q matched a device that is not it: %v", spec, got)
		}
	}
	for _, spec := range []string{"100.101.9.8", "nSHARED"} {
		if got, _ := matchDevices([]string{spec}, self, []*ipnstate.PeerStatus{shared}); got[netip.MustParseAddr("100.101.9.8")].ID != "nSHARED" {
			t.Errorf("spec %q: %v", spec, got)
		}
	}
	// A tagged node keeps its tagger's UserID but is no one's device: its
	// self-chosen name is not taken, and neither are names when reqcove is tagged.
	tags := views.SliceOf([]string{"tag:ci"})
	tagged := peer("nTAG", "ci-box.tail.ts.net.", "Taro's iPhone", 1, "100.101.9.7")
	tagged.Tags = &tags
	if got, _ := matchDevices([]string{"Taro's iPhone"}, self, []*ipnstate.PeerStatus{tagged}); len(got) != 0 {
		t.Errorf("a tagged node matched by the name it gives itself: %v", got)
	}
	taggedSelf := *self
	taggedSelf.Tags = &tags
	if got, _ := matchDevices([]string{"Taro's iPhone"}, &taggedSelf, peers); len(got) != 0 {
		t.Errorf("reqcove tagged: a device matched by the name it gives itself: %v", got)
	}
	if got, _ := matchDevices([]string{"ci-box"}, self, []*ipnstate.PeerStatus{tagged}); len(got) != 1 {
		t.Errorf("a tagged node by machine name: %v", got)
	}
	if got, _ := matchDevices([]string{"iphone-test"}, nil, peers); len(got) != 0 {
		t.Errorf("before login (no self), a name matched: %v", got)
	}
}

// The user's own devices are its untagged peers of the same user: not another
// user's, not a tagged node, and none when reqcove's node is tagged.
func TestOwnDevices(t *testing.T) {
	peer := func(id string, user tailcfg.UserID, ip string) *ipnstate.PeerStatus {
		return &ipnstate.PeerStatus{ID: tailcfg.StableNodeID(id), DNSName: id + ".tail.ts.net.", UserID: user, TailscaleIPs: []netip.Addr{netip.MustParseAddr(ip)}}
	}
	self := peer("reqcove", 1, "100.101.0.100")
	tags := views.SliceOf([]string{"tag:ci"})
	tagged := peer("ci", 1, "100.101.0.3")
	tagged.Tags = &tags
	peers := []*ipnstate.PeerStatus{peer("macbook", 1, "100.101.0.1"), peer("colleague", 2, "100.101.0.2"), tagged}
	got := ownDevices(self, peers)
	if len(got) != 1 || got[netip.MustParseAddr("100.101.0.1")] != (Device{"macbook", "macbook"}) {
		t.Errorf("own: %v", got)
	}
	taggedSelf := *self
	taggedSelf.Tags = &tags
	if got := ownDevices(&taggedSelf, peers); len(got) != 0 {
		t.Errorf("reqcove tagged: %v", got)
	}
}
