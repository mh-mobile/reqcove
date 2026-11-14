// Package exitnode runs reqcove's tsnet node: it advertises itself as an exit
// node, carries TCP and UDP from the allowed devices, and hands TCP 80/443 to
// mitmproxy's SOCKS5 listener with the device's StableID as the user name.
package exitnode

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log"
	"maps"
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
	"tailscale.com/health/healthmsg"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsnet"
)

// WebPort is the node's port for mitmweb (--web), the same on every node, so
// a link kept on the iPhone keeps working; mitmweb itself may listen on
// another port of this computer (Config.Web).
const WebPort = 8081

// MCPPort is the node's port for the MCP tools over HTTP (--mcp-http), at /mcp.
const MCPPort = 8090

type Config struct {
	Dir         string           // tsnet state
	Hostname    string           // tailnet node name
	ControlURL  string           // coordination server; empty: Tailscale's (tests use testcontrol)
	DNS         []netip.AddrPort // exit node DNS upstreams; empty: /etc/resolv.conf
	Devices     []string         // --device specs
	SocksAddr   string           // mitmproxy's SOCKS5 listener; empty: TCP 80/443 goes direct too
	SocksSecret string           // its password
	ProxyPort   int              // Remote Proxy port on the tailnet (LAN mode: on the LAN); 0: off
	// SocksReady, if set, returns once mitmproxy is ready to take SOCKS dials
	// (capture.WaitReady); until then they wait, at most socksHold.
	SocksReady func(context.Context) error
	// UI, if set, serves Reqcove's own page on the node's port 80 to the
	// --device devices and to this user's own devices, with the asking device's
	// StableID; all says it is one of this user's own, which see every device's flows.
	UI func(w http.ResponseWriter, r *http.Request, deviceID string, all bool)
	// Web, if set, is mitmweb's address on this computer (127.0.0.1:PORT): the
	// node relays its own WebPort there, for this user's own devices only.
	Web string
	// MCP, if set, serves the MCP tools on the node's MCPPort, at /mcp, to
	// this user's own devices only, asked by the node's name or address. It
	// checks the caller's token itself.
	MCP http.Handler
	// LocalProxy, if set (listening on 127.0.0.1), serves an HTTP proxy for
	// this computer's own apps (the iOS Simulator), recorded as the device Local.
	// The caller listens, so a port taken stops run before anything changes.
	LocalProxy net.Listener
	Verbose    bool // log tsnet's backend and every flow decision
	// LinksCmd is the command that prints this node's login URL and links, for the log.
	LinksCmd string
	// StatusCmd is the command that shows this node's status, for the log
	// (with --state for a node of another state); empty: reqcove status.
	StatusCmd string
	// OnDevices is called with StableID -> machine name whenever the matched devices change.
	OnDevices func(map[string]string)
	// OnStatus is called every few seconds, from start, with where the node stands.
	OnStatus func(Status)
	// LAN, if set, is LAN mode (run --lan): no tsnet; the proxy listens on
	// ProxyPort of a LAN interface for the clients allowed there.
	LAN *LAN
}

// dial dials dst for a device as a flow decided v.
func (cfg Config) dial(ctx context.Context, v verdict, device string, dst netip.AddrPort) (net.Conn, error) {
	return dialVia(ctx, v, device, cfg.SocksAddr, cfg.SocksSecret, cfg.SocksReady, dst)
}

// proxyServer serves a proxy entry (the Remote Proxy, the local and the LAN one).
func proxyServer(rp *remoteProxy) *http.Server {
	return &http.Server{
		Handler:           rp,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
}

// Status is where reqcove's node stands with its tailnet: what `reqcove
// status` reports, with the next step for the user.
type Status struct {
	// Mode is "tailnet" (the exit node and the Remote Proxy) or "lan" (run
	// --lan: no tailnet node, LAN set). The status tool shows both at its top.
	Mode         string            `json:"-"`
	LAN          *LANStatus        `json:"-"`
	Backend      string            `json:"backend,omitempty"`  // NeedsLogin, NeedsMachineAuth, Starting, Running, ...; none in LAN mode
	AuthURL      string            `json:"auth_url,omitempty"` // to log in
	Node         string            `json:"node,omitempty"`     // MagicDNS name
	IPs          []string          `json:"ips,omitempty"`
	ExitApproved bool              `json:"exit_node_approved"` // the admin approved its exit routes
	LockEnabled  bool              `json:"tailnet_lock"`
	LockSigned   bool              `json:"tailnet_lock_signed"`
	NodeKey      string            `json:"node_key,omitempty"`  // to sign under Tailnet Lock
	Devices      map[string]string `json:"devices"`             // carried: StableID -> name
	DeviceOS     map[string]string `json:"device_os,omitempty"` // carried: StableID -> OS, as Tailscale has it (iOS, android, macOS, ...)
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
	if cfg.LAN == nil {
		preflight(cfg.DNS)
	}
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
	logOnce.Do(func() { go logLoop() }) // one for every Run in this process
	if ln := cfg.LocalProxy; ln != nil {
		srv := proxyServer(&remoteProxy{
			local:   true,
			policy:  current.Load,
			resolve: localResolve, // this computer's apps: its own lookups (VPNs, split DNS, search domains), as without the proxy
			dial:    cfg.dial,
		})
		go srv.Serve(ln)
		defer srv.Close()
	}
	if cfg.LAN != nil {
		return runLAN(ctx, cfg) // no tsnet
	}
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
			relay(c, src, dst, v, p.devices[src.Addr().Unmap()].ID, cfg.SocksAddr, cfg.SocksSecret, cfg.SocksReady, cfg.Verbose)
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
	statusCmd := cmp.Or(cfg.StatusCmd, "reqcove status")
	log.Printf("waiting for %s to log in (`%s` says what is missing)", cfg.Hostname, statusCmd)
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
		var page, web http.Handler
		if cfg.UI != nil {
			page = uiGuard{policy: current.Load, serve: cfg.UI}
		}
		if cfg.Web != "" {
			web = webRelay(current.Load, cfg.Web)
		}
		srv := proxyServer(&remoteProxy{
			ui:      page,
			web:     web,
			webAddr: cfg.Web,
			policy:  current.Load,
			resolve: resolver(cfg.DNS),
			dial:    cfg.dial,
		})
		go srv.Serve(onlyDevices{ln, current.Load})
		defer srv.Close()
		log.Printf("Remote Proxy on %v:%d: instead of the exit node, set the iPhone's Wi-Fi HTTP proxy (Manual) to it", ip4, cfg.ProxyPort)
	}
	if cfg.UI != nil {
		ln, err := s.Listen("tcp", ":80")
		if err != nil {
			return fmt.Errorf("page: %w", err)
		}
		srv := &http.Server{
			Handler:           uiGuard{policy: current.Load, serve: cfg.UI},
			ReadHeaderTimeout: 30 * time.Second,
			WriteTimeout:      pageWriteTimeout, // a slow reader does not hold a page's memory longer
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          log.New(io.Discard, "", 0),
		}
		go srv.Serve(onlyViewers{Listener: ln, policy: current.Load})
		defer srv.Close()
	}
	if cfg.Web != "" {
		ln, err := s.Listen("tcp", fmt.Sprintf(":%d", WebPort))
		if err != nil {
			return fmt.Errorf("mitmweb: %w", err)
		}
		srv := &http.Server{
			Handler:           webRelay(current.Load, cfg.Web),
			ReadHeaderTimeout: 30 * time.Second, // no WriteTimeout: mitmweb's updates are one long WebSocket
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          log.New(io.Discard, "", 0),
		}
		go srv.Serve(onlyViewers{Listener: ln, policy: current.Load, ownOnly: true})
		defer srv.Close()
	}
	if cfg.MCP != nil {
		ln, err := s.Listen("tcp", fmt.Sprintf(":%d", MCPPort))
		if err != nil {
			return fmt.Errorf("MCP over HTTP: %w", err)
		}
		mux := http.NewServeMux()
		mux.Handle("/mcp", selfHost{current.Load, cfg.MCP})
		srv := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 30 * time.Second,
			WriteTimeout:      2 * time.Minute, // each call is one request and its answer
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          log.New(io.Discard, "", 0),
		}
		var once sync.Map
		go srv.Serve(onlyViewers{Listener: ln, policy: current.Load, ownOnly: true, refused: func(a net.Addr) {
			if ap, err := netip.ParseAddrPort(a.String()); err == nil {
				if _, seen := once.LoadOrStore(ap.Addr(), true); !seen {
					log.Printf("--mcp-http: refused %v: only your own devices on the tailnet may call it (the same user as reqcove's node, neither tagged)", ap.Addr())
				}
			}
		}})
		defer srv.Close()
	}
	<-ctx.Done()
	return nil
}

// watch rebuilds the policy from the netmap every few seconds, so devices
// that appear late (Tailnet Lock), join later or change IP are found, and
// reports the node's status.
func watch(ctx context.Context, lc *local.Client, cfg Config) {
	var lastProblems string
	var steps settled
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
			if step, changed := steps.next(runStep(status, cmp.Or(cfg.LinksCmd, "reqcove links"))); changed {
				if step != "" {
					log.Print(step)
				}
			}
			self := slices.Clone(st.TailscaleIPs)
			peers := make([]*ipnstate.PeerStatus, 0, len(st.Peer))
			for _, p := range st.Peer {
				peers = append(peers, p)
			}
			devices, problems := matchDevices(cfg.Devices, st.Self, peers)
			local, onLink := interfaceAddrs()
			p := &policy{devices: devices, own: ownDevices(st.Self, peers), self: self, local: local, onLink: onLink, socks: cfg.SocksAddr != ""}
			if st.Self != nil {
				if fqdn := strings.ToLower(strings.TrimSuffix(st.Self.DNSName, ".")); fqdn != "" {
					short, _, _ := strings.Cut(fqdn, ".")
					p.names = []string{fqdn, short}
				}
			}
			names := map[string]string{}
			if cfg.LocalProxy != nil {
				names[Local.ID] = Local.Name
			}
			for ip, d := range devices {
				p.allowSrc = append(p.allowSrc, ip)
				names[d.ID] = d.Name
			}
			current.Store(p)
			ids := fmt.Sprint(names)
			if ids != lastIDs {
				lastIDs = ids
				list := slices.Sorted(maps.Values(names))
				log.Printf("carrying traffic from %s", strings.Join(list, ", "))
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
			status.DeviceOS = map[string]string{}
			for _, p := range peers {
				if names[string(p.ID)] != "" && p.OS != "" {
					status.DeviceOS[string(p.ID)] = p.OS
				}
			}
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
	s := Status{Mode: "tailnet", Backend: st.BackendState, AuthURL: st.AuthURL, Health: st.Health}
	for _, ip := range st.TailscaleIPs {
		s.IPs = append(s.IPs, ip.String())
	}
	if st.Self != nil {
		s.Node = strings.TrimSuffix(st.Self.DNSName, ".")
		s.ExitApproved = st.Self.AllowedIPs != nil && tsaddr.ContainsExitRoutes(*st.Self.AllowedIPs)
	}
	if ls, err := lc.TailnetLockStatus(ctx); err == nil {
		s.LockEnabled, s.LockSigned = ls.Enabled, ls.NodeKeySigned
		if ls.NodeKey != nil {
			s.NodeKey = ls.NodeKey.String()
		}
	}
	return s
}

// settled reports a step once two polls in a row agree on it: just after
// start, before the netmap and Tailnet Lock status arrive, a node already
// signed and approved looks unsigned and unapproved for a moment.
type settled struct{ shown, seen string }

func (s *settled) next(step string) (string, bool) {
	stable := step == s.seen
	s.seen = step
	if !stable || step == s.shown {
		return "", false
	}
	s.shown = step
	return step, true
}

// runStep is FirstStep for `reqcove run`'s own terminal: while the login URL
// is still on its way (a few seconds), nothing, rather than "open the URL that
// `reqcove run` prints".
func runStep(s Status, linksCmd string) string {
	if s.Backend == "NeedsLogin" && s.AuthURL == "" && !s.WasRunning {
		return ""
	}
	return FirstStepWith(s, linksCmd)
}

// lockedOut: Tailscale's own warning, raised once the netmap was checked
// against Tailnet Lock (until then the key looks unsigned even when it is).
func lockedOut(health []string) bool {
	return slices.ContainsFunc(health, func(h string) bool { return strings.Contains(h, healthmsg.LockedOut) })
}

// FirstStep is the one thing the user must do next for the node, or "". It
// never carries the login URL: whoever opens it first puts this node in their
// tailnet, so it stays in run's terminal and `reqcove links`.
func FirstStep(s Status) string { return FirstStepWith(s, "reqcove links") }

// FirstStepWith is FirstStep naming linksCmd (`reqcove links --state DIR`).
func FirstStepWith(s Status, linksCmd string) string {
	for _, h := range s.Health {
		// tsnet stops the node: reqcove keeps logs off (SetNoLogsNoSupport) and never turns them on.
		if strings.Contains(h, "tailnet requires logging") {
			return "not supported: this tailnet requires data plane audit logging, and reqcove never sends logs to Tailscale, so tsnet stops the node. Use a tailnet without that setting"
		}
	}
	switch {
	case s.Backend == "NeedsLogin" && s.WasRunning:
		return "log in again (the node's key expired or it was logged out): restart `reqcove run` (or its service: brew services restart reqcove, or reqcove service restart), and open the login URL (`" + linksCmd + "` prints it)"
	case s.Backend == "NeedsLogin":
		return "log in: open the login URL (`" + linksCmd + "` prints it)"
	case s.Backend == "NeedsMachineAuth":
		return "approve this device in the admin console (Machines): your tailnet requires device approval"
	case s.LockEnabled && s.NodeKey != "" && lockedOut(s.Health):
		return "Tailnet Lock: on a signing device run `tailscale lock sign " + s.NodeKey + "`"
	case s.Backend == "Running" && !s.ExitApproved:
		return "approve the exit node: admin console, Machines, " + s.Node + ", Edit route settings, Use as exit node (to skip this next time, add \"autoApprovers\": {\"exitNode\": [\"you@example.com\"]} to the tailnet policy)"
	}
	return ""
}

func relay(c net.Conn, src, dst netip.AddrPort, v verdict, device, socksAddr, socksSecret string, ready func(context.Context) error, verbose bool) {
	defer c.Close()
	out, err := dialVia(context.Background(), v, device, socksAddr, socksSecret, ready, dst)
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

var logOnce sync.Once

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
