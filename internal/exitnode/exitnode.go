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
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
	"tailscale.com/client/local"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsnet"
)

type Config struct {
	Dir       string           // tsnet state
	Hostname  string           // tailnet node name
	DNS       []netip.AddrPort // exit node DNS upstreams; empty: /etc/resolv.conf
	Devices   []string         // --device specs
	SocksAddr string           // mitmproxy's SOCKS5 listener; empty: TCP 80/443 goes direct too
	Verbose   bool             // log tsnet's backend and every flow decision
	// OnDevices is called with StableID -> machine name whenever the matched devices change.
	OnDevices func(map[string]string)
}

var current atomic.Pointer[policy]

// Run brings the node up and serves until ctx ends. It logs what the user
// must do (log in, sign under Tailnet Lock, approve the exit node) and keeps
// looking for the devices instead of failing.
func Run(ctx context.Context, cfg Config) error {
	envknob.SetNoLogsNoSupport() // keep tsnet from uploading logs (they carry destination IPs)
	preflight(len(cfg.DNS) == 0)
	s := &tsnet.Server{
		Dir:         cfg.Dir,
		Hostname:    cfg.Hostname,
		ExitNodeDNS: cfg.DNS,
		FallbackUDP: func(src, dst netip.AddrPort) bool {
			ok := decideUDP(current.Load(), src, dst)
			if cfg.Verbose {
				logUDPOnce(src, dst, ok)
			}
			return ok
		},
	}
	if cfg.Verbose {
		s.Logf = log.Printf
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
		return func(c net.Conn) { relay(c, src, dst, v, p.devices[src.Addr().Unmap()].ID, cfg.SocksAddr, cfg.Verbose) }, true
	})
	if err := s.Start(); err != nil {
		return err
	}
	defer s.Close()
	lc, err := s.LocalClient()
	if err != nil {
		return err
	}
	log.Printf("waiting for %s to log in. Under Tailnet Lock, then run `tailscale lock status` on a signing device and sign the locked-out %s", cfg.Hostname, cfg.Hostname)
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
	log.Printf("up as %s (%v, %v), advertising exit routes. Approve them in the admin console if this is a new node.", cfg.Hostname, ip4, ip6)
	return watchDevices(ctx, lc, cfg, []netip.Addr{ip4, ip6})
}

// watchDevices rebuilds the policy from the netmap every few seconds, so
// devices that appear late (Tailnet Lock), join later or change IP are found.
func watchDevices(ctx context.Context, lc *local.Client, cfg Config, self []netip.Addr) error {
	var lastProblems, lastIDs string
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		st, err := lc.Status(ctx)
		if err == nil {
			peers := make([]*ipnstate.PeerStatus, 0, len(st.Peer))
			for _, p := range st.Peer {
				peers = append(peers, p)
			}
			devices, problems := matchDevices(cfg.Devices, peers)
			p := &policy{devices: devices, self: self, local: interfaceAddrs(), socks: cfg.SocksAddr != ""}
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
				if pr != "" {
					log.Printf("devices: %s. Peers appear after this node is signed (Tailnet Lock) and approved; see `tailscale status` for names.", pr)
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func relay(c net.Conn, src, dst netip.AddrPort, v verdict, device, socksAddr string, verbose bool) {
	defer c.Close()
	var d proxy.Dialer = &net.Dialer{Timeout: 10 * time.Second}
	if v == socks {
		// The SOCKS5 user name carries the device's StableID to mitmproxy.
		auth := &proxy.Auth{User: device, Password: "-"}
		var err error
		if d, err = proxy.SOCKS5("tcp", socksAddr, auth, d); err != nil {
			logEvent("tcp %v -> %v socks: %v", src, dst, err)
			return
		}
	}
	out, err := d.Dial("tcp", dst.String())
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

// A dropped UDP flow is decided again on every retransmit, so log each flow once.
// ponytail: seen grows without bound; only used with Verbose.
var seen sync.Map

func logUDPOnce(src, dst netip.AddrPort, forward bool) {
	if _, dup := seen.LoadOrStore([2]netip.AddrPort{src, dst}, struct{}{}); !dup {
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

func interfaceAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return slices.Clip(out)
}
