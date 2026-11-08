package exitnode

import (
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// uiGuard stands before Reqcove's own page on the node: reading only, asked by
// the node's own name or address (a page the device visits cannot rebind its
// name to the node), and from a --device device, checked on every request.
type uiGuard struct {
	policy func() *policy
	serve  func(w http.ResponseWriter, r *http.Request, deviceID string)
}

func (g uiGuard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "reqcove: read only", http.StatusMethodNotAllowed)
		return
	}
	p := g.policy()
	if !p.isSelf(r.Host) {
		w.Header().Set("Connection", "close")
		http.Error(w, "reqcove: ask for this page by the node's name or address", http.StatusMisdirectedRequest)
		return
	}
	dev, ok := deviceAt(p, r.RemoteAddr)
	if !ok {
		w.Header().Set("Connection", "close")
		http.Error(w, "reqcove: this device is not one of reqcove's --device", http.StatusForbidden)
		return
	}
	g.serve(w, r, dev.ID)
}

// isSelf: host (from a Host header) names this node: its MagicDNS name, the
// name's first label, or one of its tailnet addresses.
func (p *policy) isSelf(host string) bool {
	if p == nil {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		return slices.Contains(p.self, ip.Unmap())
	}
	return host != "" && slices.Contains(p.names, host)
}
