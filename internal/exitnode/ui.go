package exitnode

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// uiGuard stands before Reqcove's own page on the node: reading only, asked by
// the node's own name or address (a page the device visits cannot rebind its
// name to the node), and from a --device device or one of this user's own,
// checked on every request.
type uiGuard struct {
	policy func() *policy
	serve  func(w http.ResponseWriter, r *http.Request, deviceID string, all bool)
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
	dev, all, ok := viewerAt(p, r.RemoteAddr)
	if !ok {
		w.Header().Set("Connection", "close")
		http.Error(w, "reqcove: neither one of reqcove's --device nor one of your own devices", http.StatusForbidden)
		return
	}
	g.serve(w, r, dev.ID, all)
}

// viewerAt is who at addr may see the page: one of this user's own devices
// (all: every device's flows), or else a --device device (its own flows).
func viewerAt(p *policy, addr string) (d Device, all, ok bool) {
	src, err := netip.ParseAddrPort(addr)
	if err != nil || p == nil {
		return Device{}, false, false
	}
	if d, ok := p.own[src.Addr().Unmap()]; ok {
		return d, true, true
	}
	d, ok = p.devices[src.Addr().Unmap()]
	return d, false, ok
}

// onlyViewers accepts connections from those viewerAt lets in; with ownOnly,
// from this user's own devices alone.
type onlyViewers struct {
	net.Listener
	policy  func() *policy
	ownOnly bool
}

func (l onlyViewers) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if ra := c.RemoteAddr(); ra != nil {
			if _, all, ok := viewerAt(l.policy(), ra.String()); ok && (all || !l.ownOnly) {
				return c, nil
			}
		}
		c.Close()
	}
}

// webRelay hands mitmweb (on this computer, at addr) to this user's own
// devices: asked by the node's name or address, as the page is, and with the
// Host header kept, so mitmweb's WebSocket origin check holds. mitmweb's own
// token still guards it; it shows traffic unmasked and can edit and replay.
func webRelay(policy func() *policy, addr string) http.Handler {
	target := &url.URL{Scheme: "http", Host: addr}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := policy()
		if !p.isSelf(r.Host) {
			w.Header().Set("Connection", "close")
			http.Error(w, "reqcove: ask for mitmweb by the node's name or address", http.StatusMisdirectedRequest)
			return
		}
		if _, all, ok := viewerAt(p, r.RemoteAddr); !ok || !all {
			w.Header().Set("Connection", "close")
			http.Error(w, "reqcove: mitmweb is for your own devices only", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	})
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
