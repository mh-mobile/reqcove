package exitnode

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// LAN is LAN mode (run --lan): the proxy listens on one LAN interface's
// address, for clients on its network whose address the user allowed (as
// Charles's access control). No tsnet is started.
type LAN struct {
	Interface string                          // the interface to listen on
	Allowed   func() map[netip.Addr]time.Time // the client addresses allowed, and when; read again every few seconds
	Names     []string                        // the exact --allow-hosts names (no *): private destinations for them (D4)
	AllowCmd  string                          // the command that allows an address (reqcove lan allow, with --state)
	// Refused, if set, is called once per client address on the network that
	// is not allowed (yet), from the proxy's accept loop: it must not block.
	Refused func(netip.Addr)
}

// LANStatus is LAN mode's part of the status.
type LANStatus struct {
	Interface string       `json:"interface"`
	Network   string       `json:"network"`           // the clients' network
	Listen    string       `json:"listen,omitempty"`  // ADDR:PORT, the iPhone's Wi-Fi proxy, while listening
	Stopped   string       `json:"stopped,omitempty"` // why it does not listen
	Allowed   []LANAllowed `json:"allowed"`
	Refused   []string     `json:"refused,omitempty"` // client addresses on the network refused this run and not allowed now, the last seen first: at most maxRefusedShown (the list seen is emptied past maxSeen)
	// RefusedMore is how many more there are than Refused lists.
	RefusedMore int `json:"refused_more,omitempty"`
}

// LANAllowed is an allowed client address and when it was allowed: this
// computer's local time with milliseconds, as the records' times.
type LANAllowed struct {
	Addr string `json:"addr"`
	When string `json:"allowed_at,omitempty"`
}

// LANAddr is the interface's IPv4 address with its network's prefix length,
// for LAN mode; name "" is the default route's interface. Tunnels (a VPN's
// utun), link-local and single-address networks are not a LAN to listen on.
func LANAddr(name string) (string, netip.Prefix, error) {
	if name == "" {
		if name = routeDevice("1.1.1.1"); name == "" {
			return "", netip.Prefix{}, fmt.Errorf("no default route to listen on: give --lan-interface, such as en0")
		}
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return name, netip.Prefix{}, fmt.Errorf("--lan-interface %s: %w", name, err)
	}
	if ifi.Flags&net.FlagPointToPoint != 0 {
		return name, netip.Prefix{}, fmt.Errorf("%s is a tunnel (a VPN's?), not a LAN: give --lan-interface, such as en0", name)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return name, netip.Prefix{}, err
	}
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		if ip := p.Addr().Unmap(); ip.Is4() && !ip.IsLinkLocalUnicast() && p.Bits() < 32 {
			return name, netip.PrefixFrom(ip, p.Bits()), nil
		}
	}
	return name, netip.Prefix{}, fmt.Errorf("%s has no IPv4 network address (not connected?)", name)
}

// lanPoll is how often LAN mode reads the allowed addresses and the
// interface again (a variable for tests).
var lanPoll = 2 * time.Second

// lanAddr is LANAddr, swapped by tests.
var lanAddr = LANAddr

// runLAN serves the LAN proxy until ctx ends. It re-binds when the
// interface's address changes within its network, and stops listening when
// the interface moves to another network (a restart binds that one).
func runLAN(ctx context.Context, cfg Config) error {
	name, first, err := lanAddr(cfg.LAN.Interface)
	if err != nil {
		return err
	}
	network := first.Masked()
	rp := &remoteProxy{policy: current.Load, resolve: resolver(nil), dial: cfg.dial} // the system's resolver: /etc/hosts first
	seen := &onceSet{}
	var srv *http.Server
	var bound netip.Addr
	unbind := func() {
		if srv != nil {
			srv.Close()
			srv = nil
		}
	}
	defer func() { unbind() }()
	gone := false
	stopped := ""
	lastIDs := ""
	t := time.NewTicker(lanPoll)
	defer t.Stop()
	for {
		_, now, err := lanAddr(name)
		switch {
		case gone:
		case err == nil && now.Masked() != network:
			unbind()
			gone = true
			stopped = fmt.Sprintf("%s is on another network now (%v, was %v): restart run to listen there", name, now.Masked(), network)
			log.Printf("LAN proxy stopped: %s", stopped)
		case err != nil:
			stopped = fmt.Sprintf("not listening until %s is back on %v: %v", name, network, err)
			if srv != nil {
				unbind()
				log.Printf("LAN proxy: %s", stopped)
			}
		case srv == nil || now.Addr() != bound:
			unbind()
			addr := netip.AddrPortFrom(now.Addr(), uint16(cfg.ProxyPort)).String()
			ln, err := net.Listen("tcp4", addr) // that address only, never 0.0.0.0
			if err != nil {
				if !bound.IsValid() {
					return fmt.Errorf("LAN proxy on %s: %w", addr, err)
				}
				stopped = fmt.Sprintf("%s: %v (trying again)", addr, err)
				log.Printf("LAN proxy on %s", stopped)
				break
			}
			stopped = ""
			srv = proxyServer(rp)
			go srv.Serve(lanClients{Listener: ln, network: network, policy: current.Load, seen: seen, refused: cfg.LAN.Refused, allowCmd: cfg.LAN.AllowCmd})
			if bound.IsValid() {
				log.Printf("LAN proxy: %s's address changed: listening on %s now", name, addr)
			} else {
				log.Printf("LAN proxy on %s (%s), for clients on %v that you allow", addr, name, network)
			}
			bound = now.Addr()
		}
		local, onLink := interfaceAddrs()
		p := &policy{lan: true, network: network, local: local, onLink: onLink, socks: cfg.SocksAddr != "", devices: map[netip.Addr]Device{}}
		for _, n := range cfg.LAN.Names {
			p.exact = append(p.exact, strings.ToLower(strings.TrimSuffix(n, ".")))
		}
		names := map[string]string{}
		if cfg.LocalProxy != nil {
			names[Local.ID] = Local.Name
		}
		ls := &LANStatus{Interface: name, Network: network.String(), Stopped: stopped, Allowed: []LANAllowed{}}
		if srv != nil {
			ls.Listen = netip.AddrPortFrom(bound, uint16(cfg.ProxyPort)).String()
		}
		var allowed map[netip.Addr]time.Time
		if cfg.LAN.Allowed != nil {
			allowed = cfg.LAN.Allowed()
		}
		for _, a := range slices.SortedFunc(maps.Keys(allowed), netip.Addr.Compare) {
			when := ""
			if t := allowed[a]; !t.IsZero() {
				when = t.Local().Format("2006-01-02T15:04:05.000Z07:00")
			}
			ls.Allowed = append(ls.Allowed, LANAllowed{a.String(), when})
			if a = a.Unmap(); network.Contains(a) {
				d := Device{ID: "lan:" + a.String(), Name: "lan:" + a.String()}
				p.devices[a] = d
				names[d.ID] = d.Name
			}
		}
		ls.Refused, ls.RefusedMore = refusedNow(seen, p.devices)
		current.Store(p)
		if ids := fmt.Sprint(names); ids != lastIDs {
			lastIDs = ids
			logCarrying(names)
			if cfg.OnDevices != nil {
				cfg.OnDevices(names)
			}
		}
		if cfg.OnStatus != nil {
			s := Status{Mode: "lan", LAN: ls, Devices: names}
			if srv != nil {
				s.IPs = []string{bound.String()}
			}
			cfg.OnStatus(s)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// lanClients closes connections from outside the network and from addresses
// not allowed (yet) as they are accepted, logging each address once. ServeHTTP
// checks each request again (deviceAt): an address can be denied meanwhile.
type lanClients struct {
	net.Listener
	network  netip.Prefix
	policy   func() *policy
	seen     *onceSet
	refused  func(netip.Addr)
	allowCmd string
}

func (l lanClients) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
		a := ap.Addr().Unmap()
		switch {
		case err != nil:
		case !l.network.Contains(a):
			if l.seen.first(a, "off") {
				log.Printf("LAN client %v refused: not on %v, the network the proxy is on", a, l.network)
			}
		default:
			if _, ok := deviceAt(l.policy(), ap.String()); ok {
				if l.seen.first(a, "allowed") {
					log.Printf("LAN client %v: allowed, carried", a)
				}
				return c, nil
			}
			if l.seen.first(a, "refused") {
				log.Printf("LAN client %v refused: not allowed (to allow it: %s %v)", a, cmp.Or(l.allowCmd, "reqcove lan allow"), a)
				if l.refused != nil {
					l.refused(a)
				}
			}
		}
		c.Close()
	}
}

// onceSet remembers what was logged, so each client address is logged once,
// and when it was last seen; anyone on the network adds to it, so it is
// emptied past maxSeen.
// ponytail: emptying it logs (and asks about) some addresses twice.
type onceSet struct {
	mu sync.Mutex
	m  map[string]uint64 // the n of its last time seen
	n  uint64
}

func (s *onceSet) first(a netip.Addr, what string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := a.String() + " " + what
	s.n++
	if _, ok := s.m[k]; ok {
		s.m[k] = s.n
		return false
	}
	if s.m == nil || len(s.m) >= maxSeen {
		s.m = map[string]uint64{}
	}
	s.m[k] = s.n
	return true
}

// with lists the addresses logged as what, the last seen first.
func (s *onceSet) with(what string) []netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	type seenAt struct {
		a netip.Addr
		n uint64
	}
	var all []seenAt
	for k, n := range s.m {
		if a, w, _ := strings.Cut(k, " "); w == what {
			if ip, err := netip.ParseAddr(a); err == nil {
				all = append(all, seenAt{ip, n})
			}
		}
	}
	slices.SortFunc(all, func(x, y seenAt) int { return cmp.Compare(y.n, x.n) })
	out := make([]netip.Addr, len(all))
	for i, x := range all {
		out[i] = x.a
	}
	return out
}

// maxRefusedShown is how many refused addresses the status lists: anyone on
// the network adds to them, and the status goes into every answer.
const maxRefusedShown = 50

// refusedNow is the status's refused addresses: those refused this run and
// not allowed now, the last seen first, at most maxRefusedShown, and how many
// more there are.
func refusedNow(seen *onceSet, allowed map[netip.Addr]Device) (shown []string, more int) {
	for _, a := range seen.with("refused") {
		if _, ok := allowed[a]; ok {
			continue
		}
		if len(shown) == maxRefusedShown {
			more++
			continue
		}
		shown = append(shown, a.String())
	}
	return shown, more
}
