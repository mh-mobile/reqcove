// Command poc is the stage 0–1 prototype of reqcove: a tsnet exit node that
// carries TCP from one allowed device. UDP is left to tsnet, which drops it.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsnet"
)

var (
	allowSrc = flag.String("allow-src", "", "tailnet IP of the device whose traffic is carried (required)")
	hostname = flag.String("hostname", "reqcove-poc", "tailnet node name")
	stateDir = flag.String("state", "", "tsnet state directory (default ~/.reqcove-poc/tsnet)")
	verbose  = flag.Bool("verbose", false, "print tsnet backend logs (DNS, magicsock, ...)")
)

var current atomic.Pointer[policy]

func main() {
	flag.Parse()
	src, err := netip.ParseAddr(*allowSrc)
	if err != nil {
		log.Fatalf("-allow-src: %v", err)
	}
	if *stateDir == "" {
		home, _ := os.UserHomeDir()
		*stateDir = filepath.Join(home, ".reqcove-poc", "tsnet")
	}
	envknob.SetNoLogsNoSupport() // keep tsnet from uploading logs (they carry destination IPs)
	preflight()

	s := &tsnet.Server{Dir: *stateDir, Hostname: *hostname}
	if *verbose {
		s.Logf = log.Printf
	}
	go logLoop()
	// Registered before Start; until current is set, decideTCP rejects everything.
	s.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		v := decideTCP(current.Load(), src, dst)
		if v != direct {
			logEvent("tcp %v -> %v %v", src, dst, v)
			return nil, true // RST; socks is stage 3
		}
		return func(c net.Conn) { relay(c, src, dst) }, true
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := s.Start(); err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	lc, err := s.LocalClient()
	if err != nil {
		log.Fatal(err)
	}
	// The node key only exists after login, so point at where it shows up.
	log.Printf("under Tailnet Lock, after login run `tailscale lock status` on a signing device and sign the locked-out %s", *hostname)
	if _, err := s.Up(ctx); err != nil {
		log.Fatal(err)
	}
	// tsnet rebuilds prefs on every start, so advertise every time.
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:              ipn.Prefs{AdvertiseRoutes: tsaddr.ExitRoutes()},
		AdvertiseRoutesSet: true,
	}); err != nil {
		log.Fatal(err)
	}
	ip4, ip6 := s.TailscaleIPs()
	// ponytail: Mac addresses are read once; restart after a DHCP change.
	current.Store(&policy{
		allowSrc: []netip.Addr{src},
		self:     []netip.Addr{ip4, ip6},
		local:    interfaceAddrs(),
	})
	log.Printf("up as %s (%v, %v), advertising exit routes, carrying TCP from %v", *hostname, ip4, ip6, src)
	<-ctx.Done()
}

func relay(c net.Conn, src, dst netip.AddrPort) {
	defer c.Close()
	out, err := (&net.Dialer{Timeout: 10 * time.Second}).Dial("tcp", dst.String())
	if err != nil {
		logEvent("tcp %v -> %v direct: %v", src, dst, err)
		return
	}
	defer out.Close()
	logEvent("tcp %v -> %v direct: connected", src, dst)
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

// Logging must not block: TCP decisions run under tsnet's lock.
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
		log.Fatal(err)
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// preflight warns about host settings that break the exit node (plan, stage 0).
func preflight() {
	// The exit node's DoH forwards to the first nameserver in /etc/resolv.conf.
	ns, err := firstNameserver("/etc/resolv.conf")
	switch {
	case err != nil:
		log.Printf("WARN: /etc/resolv.conf: %v (exit-node DNS will fail)", err)
	case ns == "100.100.100.100" || !netip.MustParseAddr(ns).Is4():
		log.Printf("WARN: first nameserver is %s; exit-node DNS needs an IPv4 resolver other than 100.100.100.100", ns)
	}
	// If this Mac uses an exit node or accepts routes, our outbound goes back into the tailnet.
	if out, err := exec.Command("route", "-n", "get", "1.1.1.1").Output(); err == nil &&
		strings.Contains(string(out), "interface: utun") {
		log.Printf("WARN: 1.1.1.1 routes via utun; this Mac seems to use an exit node or accepted routes")
	}
}

func firstNameserver(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) >= 2 && fields[0] == "nameserver" {
			if _, err := netip.ParseAddr(fields[1]); err != nil {
				return "", fmt.Errorf("bad nameserver %q", fields[1])
			}
			return fields[1], nil
		}
	}
	return "", errors.New("no nameserver")
}
