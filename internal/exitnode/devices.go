package exitnode

import (
	"fmt"
	"net/netip"
	"strings"

	"tailscale.com/ipn/ipnstate"
)

// matchDevices finds each --device spec among the peers. A spec may be the
// machine (MagicDNS) name, the device's own name, a tailnet IP, or a StableID.
// Names compare case-insensitively.
func matchDevices(specs []string, peers []*ipnstate.PeerStatus) (map[netip.Addr]Device, []string) {
	out := map[netip.Addr]Device{}
	var problems []string
	for _, spec := range specs {
		var hits []*ipnstate.PeerStatus
		for _, p := range peers {
			if matches(spec, p) {
				hits = append(hits, p)
			}
		}
		switch len(hits) {
		case 0:
			problems = append(problems, fmt.Sprintf("%q: no such device in the tailnet (yet)", spec))
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

func matches(spec string, p *ipnstate.PeerStatus) bool {
	if strings.EqualFold(spec, machineName(p)) || strings.EqualFold(spec, p.HostName) || spec == string(p.ID) {
		return true
	}
	if ip, err := netip.ParseAddr(spec); err == nil {
		for _, a := range p.TailscaleIPs {
			if a.Unmap() == ip.Unmap() {
				return true
			}
		}
	}
	return false
}

// machineName is the first label of the MagicDNS name: lowercase, digits and hyphens.
func machineName(p *ipnstate.PeerStatus) string {
	name, _, _ := strings.Cut(p.DNSName, ".")
	return name
}
