package exitnode

import (
	"fmt"
	"net/netip"
	"strings"

	"tailscale.com/ipn/ipnstate"
)

// matchDevices finds each --device spec among the peers. A spec may be the
// machine (MagicDNS) name, the device's own name, a tailnet IP, or a StableID.
// Names compare case-insensitively, and match only where they name one device
// of yours: a machine name only in this node's tailnet (a node shared in from
// another can have the same first label), and a device name, which each device
// reports for itself, only among the devices of this node's user.
func matchDevices(specs []string, self *ipnstate.PeerStatus, peers []*ipnstate.PeerStatus) (map[netip.Addr]Device, []string) {
	out := map[netip.Addr]Device{}
	var problems []string
	for _, spec := range specs {
		var hits []*ipnstate.PeerStatus
		for _, p := range peers {
			if matches(spec, self, p) {
				hits = append(hits, p)
			}
		}
		switch len(hits) {
		case 0:
			problems = append(problems, fmt.Sprintf("%q: no such device in the tailnet (yet); another user's device needs its machine name", spec))
		case 1:
			d := Device{ID: string(hits[0].ID), Name: machineName(hits[0])}
			for _, ip := range hits[0].TailscaleIPs {
				out[ip.Unmap()] = d
			}
		default:
			var names []string
			for _, h := range hits {
				names = append(names, machineName(h))
			}
			problems = append(problems, fmt.Sprintf("%q matches %d devices (%s); use the machine name", spec, len(hits), strings.Join(names, ", ")))
		}
	}
	return out, problems
}

func matches(spec string, self, p *ipnstate.PeerStatus) bool {
	if spec == string(p.ID) {
		return true
	}
	if ip, err := netip.ParseAddr(spec); err == nil {
		for _, a := range p.TailscaleIPs {
			if a.Unmap() == ip.Unmap() {
				return true
			}
		}
		return false
	}
	if self == nil {
		return false
	}
	_, tailnet, _ := strings.Cut(self.DNSName, ".")
	if _, t, _ := strings.Cut(p.DNSName, "."); tailnet == "" || t != tailnet {
		return false // not this tailnet's node
	}
	return strings.EqualFold(spec, machineName(p)) || (p.UserID == self.UserID && strings.EqualFold(spec, p.HostName))
}

// machineName is the first label of the MagicDNS name: lowercase, digits and hyphens.
func machineName(p *ipnstate.PeerStatus) string {
	name, _, _ := strings.Cut(p.DNSName, ".")
	return name
}
