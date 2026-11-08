// Package exitnode runs reqcove's tsnet node: it advertises itself as an exit
// node, carries TCP and UDP from the allowed devices, and hands TCP 80/443 to
// mitmproxy's SOCKS5 listener with the device's StableID as the user name.
package exitnode

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsnet"
)

type Config struct {
	Dir         string           // tsnet state
	Hostname    string           // tailnet node name
	ControlURL  string           // coordination server; empty: Tailscale's (tests use testcontrol)
	DNS         []netip.AddrPort // exit node DNS upstreams; empty: /etc/resolv.conf
	Devices     []string         // --device specs
	SocksAddr   string           // mitmproxy's SOCKS5 listener; empty: TCP 80/443 goes direct too
	SocksSecret string           // its password
	ProxyPort   int              // Remote Proxy port on the tailnet; 0: off
	Verbose     bool             // log tsnet's backend and every flow decision
	// OnDevices is called with StableID -> machine name whenever the matched devices change.
	OnDevices func(map[string]string)
	// OnStatus is called every few seconds, from start, with where the node stands.
	OnStatus func(Status)
}

// Status is where reqcove's node stands with its tailnet: what `reqcove
// status` reports, with the next step for the user.
type Status struct {
	Backend      string            `json:"backend"`            // NeedsLogin, NeedsMachineAuth, Starting, Running, ...
	AuthURL      string            `json:"auth_url,omitempty"` // to log in
	Node         string            `json:"node,omitempty"`     // MagicDNS name
	IPs          []string          `json:"ips,omitempty"`
	ExitApproved bool              `json:"exit_node_approved"` // the admin approved its exit routes
	LockEnabled  bool              `json:"tailnet_lock"`
	LockSigned   bool              `json:"tailnet_lock_signed"`
	NodeKey      string            `json:"node_key,omitempty"` // to sign under Tailnet Lock
	Devices      map[string]string `json:"devices"`            // carried: StableID -> name
	Problems     []string          `json:"device_problems,omitempty"`
	Health       []string          `json:"health,omitempty"` // tsnet's own warnings
	// WasRunning: logged out after running (key expired, removed). tsnet prints
	// a login URL only while starting, so only a restart brings one.
	WasRunning bool `json:"-"`
}

var current atomic.Pointer[policy]

// Run brings the node up and serves until ctx ends. It logs what the user
// must do (log in, sign under Tailnet Lock, approve the exit node) and keeps
// looking for the devices instead of failing.
func Run(ctx context.Context, cfg Config) error {
	envknob.SetNoLogsNoSupport() // keep tsnet from uploading logs (they carry destination IPs)
	preflight(cfg.DNS)
	s := &tsnet.Server{
		Dir:         cfg.Dir,
		Hostname:    cfg.Hostname,
		ControlURL:  cfg.ControlURL,
		ExitNodeDNS: cfg.DNS,
		FallbackUDP: func(src, dst netip.AddrPort) bool {
			ok := decideUDP(current.Load(), src, dst)
			if cfg.Verbose {
				logUDPOnce(src, dst, ok)
			}
			return ok
		},
		// A ping is answered by pinging dst from this Mac: only where TCP and UDP may go.
		FallbackPing: func(src, dst netip.Addr) bool {
			return decidePing(current.Load(), src, dst)
		},
	}
	if cfg.Verbose {
		s.Logf = log.Printf
	} else {
		// tsnet's own lines (state paths, and the login URL every 5 s with
		// advice about TS_AUTHKEY): reqcove says what to do itself, in watch.
		s.UserLogf = func(string, ...any) {}
	}
	go logLoop()
	// Registered before Start; until current is set, decideTCP rejects everything.
	s.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		p := current.Load()
		v := decideTCP(p, src, dst)
		if v == reject {
			if cfg.Verbose {
				logEvent("tcp %v -> %v reject", src, dst)
			}
			return nil, true // RST
		}
		return func(c net.Conn) {
			relay(c, src, dst, v, p.devices[src.Addr().Unmap()].ID, cfg.SocksAddr, cfg.SocksSecret, cfg.Verbose)
		}, true
	})
	if err := s.Start(); err != nil {
		return err
	}
	defer s.Close()
	lc, err := s.LocalClient()
	if err != nil {
		return err
	}
	// From the start, before login: the status is most useful while the node is stuck.
	go watch(ctx, lc, cfg)
	log.Printf("waiting for %s to log in (`reqcove status` says what is missing)", cfg.Hostname)
	if _, err := s.Up(ctx); err != nil {
		return err
	}
	// tsnet rebuilds prefs on every start, so advertise every time.
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:              ipn.Prefs{AdvertiseRoutes: tsaddr.ExitRoutes()},
		AdvertiseRoutesSet: true,
	}); err != nil {
		return err
	}
	ip4, ip6 := s.TailscaleIPs()
	log.Printf("up as %s (%v, %v), advertising exit routes", cfg.Hostname, ip4, ip6) // approval, if missing, is the next step logged
	if cfg.ProxyPort != 0 {
		ln, err := s.Listen("tcp", fmt.Sprintf(":%d", cfg.ProxyPort))
		if err != nil {
			return fmt.Errorf("remote proxy: %w", err)
		}
		srv := &http.Server{
			Handler: &remoteProxy{
				policy:  current.Load,
				resolve: resolver(cfg.DNS),
				dial: func(ctx context.Context, v verdict, device string, dst netip.AddrPort) (net.Conn, error) {
					return dialVia(ctx, v, device, cfg.SocksAddr, cfg.SocksSecret, dst)
				},
			},
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          log.New(io.Discard, "", 0),
		}
		go srv.Serve(onlyDevices{ln, current.Load})
		defer srv.Close()
		log.Printf("Remote Proxy on %v:%d: instead of the exit node, set the iPhone's Wi-Fi HTTP proxy (Manual) to it", ip4, cfg.ProxyPort)
	}
	<-ctx.Done()
	return nil
}

// watch rebuilds the policy from the netmap every few seconds, so devices
// that appear late (Tailnet Lock), join later or change IP are found, and
// reports the node's status.
func watch(ctx context.Context, lc *local.Client, cfg Config) {
	var lastProblems, lastStep string
	var wasRunning bool
	lastIDs := fmt.Sprint(map[string]string{}) // no "carrying traffic from map[]" before login
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		st, err := lc.Status(ctx)
		if err == nil {
			status := nodeStatus(ctx, lc, st)
			wasRunning = wasRunning || status.Backend == "Running"
			status.WasRunning = wasRunning
			if step := runStep(status); step != lastStep {
				lastStep = step
				if step != "" {
					log.Print(step)
				}
			}
			var self []netip.Addr
			for _, ip := range st.TailscaleIPs {
				self = append(self, ip)
			}
			peers := make([]*ipnstate.PeerStatus, 0, len(st.Peer))
			for _, p := range st.Peer {
				peers = append(peers, p)
			}
			devices, problems := matchDevices(cfg.Devices, st.Self, peers)
			local, onLink := interfaceAddrs()
			p := &policy{devices: devices, self: self, local: local, onLink: onLink, socks: cfg.SocksAddr != ""}
			names := map[string]string{}
			for ip, d := range devices {
				p.allowSrc = append(p.allowSrc, ip)
				names[d.ID] = d.Name
			}
			current.Store(p)
			ids := fmt.Sprint(names)
			if ids != lastIDs {
				lastIDs = ids
				log.Printf("carrying traffic from %v", names)
				if cfg.OnDevices != nil {
					cfg.OnDevices(names)
				}
			}
			if pr := strings.Join(problems, "; "); pr != lastProblems {
				lastProblems = pr
				if pr != "" && status.Backend == "Running" {
					log.Printf("devices: %s. See `tailscale status` for names.", pr)
				}
			}
			status.Devices, status.Problems = names, problems
			if cfg.OnStatus != nil {
				cfg.OnStatus(status)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func nodeStatus(ctx context.Context, lc *local.Client, st *ipnstate.Status) Status {
	s := Status{Backend: st.BackendState, AuthURL: st.AuthURL, Health: st.Health}
	for _, ip := range st.TailscaleIPs {
		s.IPs = append(s.IPs, ip.String())
	}
	if st.Self != nil {
		s.Node = strings.TrimSuffix(st.Self.DNSName, ".")
		s.ExitApproved = st.Self.AllowedIPs != nil && tsaddr.ContainsExitRoutes(*st.Self.AllowedIPs)
	}
	if ls, err := lc.NetworkLockStatus(ctx); err == nil {
		s.LockEnabled, s.LockSigned = ls.Enabled, ls.NodeKeySigned
		if ls.NodeKey != nil {
			s.NodeKey = ls.NodeKey.String()
		}
	}
	return s
}

// runStep is FirstStep for `reqcove run`'s own terminal: while the login URL
// is still on its way (a few seconds), nothing, rather than "open the URL that
// `reqcove run` prints".
func runStep(s Status) string {
	if s.Backend == "NeedsLogin" && s.AuthURL == "" && !s.WasRunning {
		return ""
	}
	return FirstStep(s)
}

// FirstStep is the one thing the user must do next for the node, or "".
func FirstStep(s Status) string {
	for _, h := range s.Health {
		// tsnet stops the node: reqcove keeps logs off (SetNoLogsNoSupport) and never turns them on.
		if strings.Contains(h, "tailnet requires logging") {
			return "not supported: this tailnet requires data plane audit logging, and reqcove never sends logs to Tailscale, so tsnet stops the node. Use a tailnet without that setting"
		}
	}
	switch {
	case s.Backend == "NeedsLogin" && s.WasRunning:
		return "log in again (the node's key expired or it was logged out): stop `reqcove run`, start it again, and open the login URL it prints"
	case s.Backend == "NeedsLogin" && s.AuthURL != "":
		return "log in: open " + s.AuthURL
	case s.Backend == "NeedsLogin":
		// No URL yet, or left out on purpose (the status tool never carries it).
		return "log in: open the login URL that `reqcove run` prints in its terminal"
	case s.Backend == "NeedsMachineAuth":
		return "approve this device in the admin console (Machines): your tailnet requires device approval"
	case s.LockEnabled && !s.LockSigned && s.NodeKey != "":
		return "Tailnet Lock: on a signing device run `tailscale lock sign " + s.NodeKey + "`"
	case s.Backend == "Running" && !s.ExitApproved:
		return "approve the exit node: admin console, Machines, " + s.Node + ", Edit route settings, Use as exit node"
	}
	return ""
}

func relay(c net.Conn, src, dst netip.AddrPort, v verdict, device, socksAddr, socksSecret string, verbose bool) {
	defer c.Close()
	out, err := dialVia(context.Background(), v, device, socksAddr, socksSecret, dst)
	if err != nil {
		logEvent("tcp %v -> %v %v: %v", src, dst, v, err)
		return
	}
	defer out.Close()
	if verbose {
		logEvent("tcp %v -> %v %v: connected", src, dst, v)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go pipe(&wg, out, c)
	go pipe(&wg, c, out)
	wg.Wait()
}

// pipe copies until EOF, then half-closes dst so the other direction can finish.
func pipe(wg *sync.WaitGroup, dst, src net.Conn) {
	defer wg.Done()
	io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		dst.Close()
	}
}

// A dropped UDP flow is decided again on every retransmit, so log each flow
// once. Any peer's UDP reaches here, so seen is emptied every maxSeen flows.
// ponytail: emptying it logs some flows twice; an LRU if that ever matters.
var (
	seen  sync.Map
	seenN atomic.Int64
)

const maxSeen = 10000

func logUDPOnce(src, dst netip.AddrPort, forward bool) {
	if _, dup := seen.LoadOrStore([2]netip.AddrPort{src, dst}, struct{}{}); !dup {
		if seenN.Add(1) > maxSeen {
			seen.Clear()
			seenN.Store(0)
		}
		logEvent("udp %v -> %v forward=%v", src, dst, forward)
	}
}

// Logging must not block: TCP decisions run under tsnet's lock, UDP ones in
// netstack's packet processing.
var (
	events  = make(chan string, 1024)
	dropped atomic.Int64
)

func logEvent(format string, a ...any) {
	select {
	case events <- fmt.Sprintf(format, a...):
	default:
		dropped.Add(1)
	}
}

func logLoop() {
	t := time.NewTicker(10 * time.Second)
	for {
		select {
		case e := <-events:
			log.Print(e)
		case <-t.C:
			if n := dropped.Swap(0); n > 0 {
				log.Printf("dropped %d log lines", n)
			}
		}
	}
}

// interfaceAddrs returns this Mac's addresses and the IPv4 networks they are
// on (not single-address ones such as a tunnel's /32, and not wider than /8).
func interfaceAddrs() ([]netip.Addr, []netip.Prefix) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil
	}
	var out []netip.Addr
	var nets []netip.Prefix
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		addr := p.Addr().Unmap()
		out = append(out, addr)
		if addr.Is4() && p.Bits() >= 8 && p.Bits() < 32 && !addr.IsLoopback() {
			nets = append(nets, netip.PrefixFrom(addr, p.Bits()).Masked())
		}
	}
	return slices.Clip(out), nets
}
