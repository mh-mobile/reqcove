package exitnode

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// D4: in LAN mode, private destinations only for an exact --allow-hosts name;
// this Mac, link-local and the proxy's own network never, even for one.
func TestDecideLAN(t *testing.T) {
	p := &policy{lan: true, socks: true,
		network: netip.MustParsePrefix("192.168.1.0/24"),
		local:   []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("100.101.102.103")},
		onLink:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("10.8.0.0/24"), netip.MustParsePrefix("203.0.113.0/24")}, // a VPN's network; one numbered from public space
	}
	for _, c := range []struct {
		dst   string
		exact bool
		want  verdict
	}{
		{"198.51.100.7:443", false, socks},
		{"17.253.1.1:443", false, direct}, // Apple's, as on the exit node
		{"10.1.2.3:443", false, reject},   // private
		{"10.1.2.3:443", true, socks},     // private, for an exact name
		{"172.16.0.9:80", true, socks},
		{"100.64.0.7:443", false, reject}, // CGNAT, the tailnet
		{"100.64.0.7:443", true, socks},
		{"10.8.0.5:443", false, reject}, // another network of this Mac (its VPN)
		{"10.8.0.5:443", true, socks},
		{"203.0.113.9:443", false, reject}, // a network of this Mac numbered from public space, whatever the name
		{"203.0.113.9:443", true, reject},
		{"192.168.1.20:443", true, reject},    // the proxy's own network, even for an exact name
		{"192.168.1.10:443", true, reject},    // this Mac
		{"100.101.102.103:443", true, reject}, // this Mac's tailnet address
		{"127.0.0.1:80", true, reject},
		{"0.0.0.0:80", true, reject},
		{"169.254.1.1:80", true, reject},
		{"224.0.0.1:80", true, reject},
		{"198.18.0.1:80", true, reject}, // special purpose, not private
		{"[2001:db8::1]:443", true, reject},
	} {
		if got, why := decideLAN(p, netip.MustParseAddrPort(c.dst), c.exact); got != c.want || (got == reject) != (why != "") {
			t.Errorf("%s exact=%v: %v %q, want %v", c.dst, c.exact, got, why, c.want)
		}
	}
}

// lanHarness serves the LAN proxy's handler on loopback (the network
// 127.0.0.0/8, with 127.0.0.1 allowed), names resolving from a table and
// every dial logged instead of made.
func lanHarness(t *testing.T, exact ...string) (*url.URL, func() []dialed, *atomic.Int32) {
	t.Helper()
	names := map[string]string{"app.test": "203.0.113.5", "lan.test": "10.1.2.3", "here.test": "127.0.0.1", "home.test": "192.168.1.20"}
	var lookups atomic.Int32
	var mu sync.Mutex
	var log []dialed
	me := netip.MustParseAddr("127.0.0.1")
	p := &policy{lan: true, socks: true, network: netip.MustParsePrefix("127.0.0.0/8"), exact: exact,
		onLink:  []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		devices: map[netip.Addr]Device{me: {ID: "lan:127.0.0.1", Name: "lan:127.0.0.1"}}}
	rp := &remoteProxy{
		policy: func() *policy { return p },
		resolve: func(_ context.Context, host string) (netip.Addr, error) {
			lookups.Add(1)
			if s, ok := names[host]; ok {
				return netip.MustParseAddr(s), nil
			}
			return netip.ParseAddr(host)
		},
		dial: func(ctx context.Context, v verdict, device string, dst netip.AddrPort) (net.Conn, error) {
			mu.Lock()
			log = append(log, dialed{v, device, dst})
			mu.Unlock()
			return nil, fmt.Errorf("dial logged")
		},
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := proxyServer(rp)
	go srv.Serve(lanClients{Listener: ln, network: p.network, policy: func() *policy { return p }, seen: &onceSet{}})
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse("http://" + ln.Addr().String())
	return u, func() []dialed { mu.Lock(); defer mu.Unlock(); return append([]dialed(nil), log...) }, &lookups
}

// connectVia sends CONNECT hostport through the proxy and returns the status.
func connectVia(t *testing.T, proxy *url.URL, hostport string) int {
	t.Helper()
	c, err := net.Dial("tcp", proxy.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostport, hostport)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0 // closed
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestLANProxyDestinations(t *testing.T) {
	proxy, dials, lookups := lanHarness(t, "lan.test", "here.test")
	// Ports other than 80 and 443 are refused before any lookup.
	for _, hp := range []string{"app.test:22", "app.test:8081", "lan.test:5432"} {
		if code := connectVia(t, proxy, hp); code != http.StatusForbidden {
			t.Errorf("CONNECT %s: %d, want 403", hp, code)
		}
	}
	if n := lookups.Load(); n != 0 {
		t.Errorf("%d lookups for refused ports", n)
	}
	// Refused whatever the name: this Mac, the proxy's network; and private for a name not exact.
	for _, hp := range []string{"here.test:443", "127.0.0.1:80", "home.test:443", "10.9.9.9:443", "169.254.1.1:80"} {
		if code := connectVia(t, proxy, hp); code != http.StatusForbidden {
			t.Errorf("CONNECT %s: %d, want 403", hp, code)
		}
	}
	if d := dials(); len(d) != 0 {
		t.Fatalf("refused destinations dialed: %v", d)
	}
	connectVia(t, proxy, "app.test:443")
	connectVia(t, proxy, "lan.test:443") // private, an exact name
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	if resp, err := client.Get("http://app.test/x"); err == nil {
		resp.Body.Close()
	}
	want := []dialed{
		{socks, "lan:127.0.0.1", netip.MustParseAddrPort("203.0.113.5:443")},
		{socks, "lan:127.0.0.1", netip.MustParseAddrPort("10.1.2.3:443")},
		{socks, "lan:127.0.0.1", netip.MustParseAddrPort("203.0.113.5:80")},
	}
	if got := dials(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("dialed %v, want %v", got, want)
	}
}

// accepted reports whether the listener served a request from this client (a
// 400 for a request that is no proxy's), or closed it.
func accepted(t *testing.T, addr string) bool {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	_, err = http.ReadResponse(bufio.NewReader(c), nil)
	return err == nil
}

// Clients off the network, and addresses not allowed, are closed as accepted;
// a refused address is reported once (run's prompt), an allowed one served.
func TestLANClients(t *testing.T) {
	me := netip.MustParseAddr("127.0.0.1")
	var p atomic.Pointer[policy]
	p.Store(&policy{lan: true, devices: map[netip.Addr]Device{}})
	var asked []netip.Addr
	var mu sync.Mutex
	serve := func(network string) string {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := proxyServer(&remoteProxy{policy: p.Load})
		go srv.Serve(lanClients{Listener: ln, network: netip.MustParsePrefix(network), policy: p.Load, seen: &onceSet{},
			refused: func(a netip.Addr) { mu.Lock(); asked = append(asked, a); mu.Unlock() }})
		t.Cleanup(func() { srv.Close() })
		return ln.Addr().String()
	}
	off := serve("10.0.0.0/8")
	on := serve("127.0.0.0/8")
	// Twice: the second connection is refused too, and not asked about again.
	if first, again := accepted(t, on), accepted(t, on); first || again {
		t.Errorf("an address not allowed was served (first %v, again %v)", first, again)
	}
	mu.Lock()
	if len(asked) != 1 || asked[0] != me {
		t.Errorf("asked %v, want 127.0.0.1 once", asked)
	}
	mu.Unlock()
	p.Store(&policy{lan: true, devices: map[netip.Addr]Device{me: {ID: "lan:127.0.0.1"}}})
	if !accepted(t, on) {
		t.Error("an allowed address was refused")
	}
	if accepted(t, off) {
		t.Error("a client off the network was served")
	}
	mu.Lock()
	if len(asked) != 1 {
		t.Errorf("asked again: %v", asked)
	}
	mu.Unlock()
}

func loopbackName(t *testing.T) string {
	t.Helper()
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// Run in LAN mode starts no tsnet (its state directory is never made),
// reports itself as LAN with the allowed addresses as devices, and serves the
// LAN proxy on the interface's address.
func TestRunLANNoTsnet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tsnet")
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	statuses := make(chan Status, 100)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{Dir: dir, Hostname: "reqcove-lan-test", ProxyPort: port, ControlURL: "http://127.0.0.1:1", // never reached: no tsnet
			LAN: &LAN{Interface: loopbackName(t), Allowed: allowedAt("127.0.0.1", "192.0.2.9")}, // the second off the network
			OnStatus: func(s Status) {
				select {
				case statuses <- s:
				default:
				}
			}})
	}()
	select {
	case s := <-statuses:
		if s.Mode != "lan" || s.LAN == nil || s.LAN.Listen != fmt.Sprintf("127.0.0.1:%d", port) || fmt.Sprint(s.LAN.Allowed) != "[{127.0.0.1 2026-11-13T08:00:00Z} {192.0.2.9 2026-11-13T08:00:00Z}]" || fmt.Sprint(s.IPs) != "[127.0.0.1]" || fmt.Sprint(s.Devices) != "map[lan:127.0.0.1:lan:127.0.0.1]" {
			t.Errorf("status %+v", s)
		}
	case err := <-done:
		t.Fatalf("Run returned %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no status")
	}
	proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if code := connectVia(t, proxy, "example.com:22"); code != http.StatusForbidden {
		t.Errorf("CONNECT to port 22: %d, want 403", code)
	}
	cancel()
	if err := <-done; err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("tsnet's state directory made: %v", err)
	}
}

// The interface moving to another network stops the proxy, for good; its
// address changing within the network moves the listener there.
func TestRunLANRebind(t *testing.T) {
	if ln, err := net.Listen("tcp4", "127.0.0.2:0"); err != nil {
		t.Skipf("127.0.0.2 not on loopback here: %v", err) // macOS has only 127.0.0.1
	} else {
		ln.Close()
	}
	testRunLANMoves(t, "127.0.0.2/8", true)
}

func TestRunLANNetworkChange(t *testing.T) { testRunLANMoves(t, "10.0.0.1/24", false) }

func testRunLANMoves(t *testing.T, next string, listens bool) {
	defer func(old func(string) (string, netip.Prefix, error), poll time.Duration) { lanAddr, lanPoll = old, poll }(lanAddr, lanPoll)
	var at atomic.Pointer[netip.Prefix]
	first := netip.MustParsePrefix("127.0.0.1/8")
	at.Store(&first)
	lanAddr = func(string) (string, netip.Prefix, error) { return "lo", *at.Load(), nil }
	lanPoll = 20 * time.Millisecond
	port := freePort(t)
	var last atomic.Pointer[Status]
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{ProxyPort: port, LAN: &LAN{Allowed: allowedAt("127.0.0.1")}, OnStatus: func(s Status) { last.Store(&s) }})
	}()
	defer func() { cancel(); <-done }()
	listening := func(ip string) bool {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), time.Second)
		if err == nil {
			c.Close()
		}
		return err == nil
	}
	waitFor(t, func() bool { return listening("127.0.0.1") }, "listening on 127.0.0.1")
	n := netip.MustParsePrefix(next)
	at.Store(&n)
	waitFor(t, func() bool { return !listening("127.0.0.1") }, "stopped on 127.0.0.1")
	if listens {
		waitFor(t, func() bool { return listening(n.Addr().String()) }, "listening on "+n.Addr().String())
		return
	}
	at.Store(&first) // back: it does not listen again until a restart
	time.Sleep(10 * lanPoll)
	if listening("127.0.0.1") {
		t.Error("listening again after the network changed")
	}
	if s := last.Load(); s.LAN == nil || s.LAN.Listen != "" || !strings.Contains(s.LAN.Stopped, "another network") {
		t.Errorf("status after the network changed: %+v", s.LAN)
	}
}

// The status lists the addresses refused this run until they are allowed.
func TestRunLANStatusRefused(t *testing.T) {
	defer func(poll time.Duration) { lanPoll = poll }(lanPoll)
	lanPoll = 20 * time.Millisecond
	var allowed atomic.Pointer[map[netip.Addr]time.Time]
	none := map[netip.Addr]time.Time{}
	allowed.Store(&none)
	var last atomic.Pointer[Status]
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{ProxyPort: port, LAN: &LAN{Interface: loopbackName(t), Allowed: func() map[netip.Addr]time.Time { return *allowed.Load() }},
			OnStatus: func(s Status) { last.Store(&s) }})
	}()
	defer func() { cancel(); <-done }()
	refused := func() string {
		if s := last.Load(); s != nil && s.LAN != nil {
			return fmt.Sprint(s.LAN.Refused)
		}
		return ""
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitFor(t, func() bool {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
		}
		return err == nil
	}, "listening (and a connection refused)")
	waitFor(t, func() bool { return refused() == "[127.0.0.1]" }, "127.0.0.1 listed as refused")
	now := allowedAt("127.0.0.1")()
	allowed.Store(&now)
	waitFor(t, func() bool { return refused() == "[]" }, "127.0.0.1 off the refused list once allowed")
}

func waitFor(t *testing.T, ok func() bool, what string) {
	t.Helper()
	for range 250 {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("not %s", what)
}

// Each address is logged once, until the list of those seen fills: then it is
// emptied, and an address seen before counts as new again.
func TestOnceSetBounded(t *testing.T) {
	var s onceSet
	a := netip.MustParseAddr("192.168.1.23")
	if !s.first(a, "refused") || s.first(a, "refused") {
		t.Fatal("not once")
	}
	for i := range maxSeen {
		s.first(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), "off")
	}
	if len(s.m) > maxSeen || !s.first(a, "refused") {
		t.Errorf("%d kept; seen again: the list was not emptied", len(s.m))
	}
}

// One pool per client, but not without end: on a LAN anyone adds clients.
func TestRemoteProxyPoolsBounded(t *testing.T) {
	rp := &remoteProxy{}
	for i := range 3 * maxPlain {
		a := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, byte(i >> 8), byte(i)}), 1)
		rp.reverseProxy(a, Device{ID: "lan:" + a.Addr().String()})
	}
	n := 0
	rp.plain.Range(func(_, _ any) bool { n++; return true })
	if n > maxPlain {
		t.Errorf("%d pools kept, want at most %d", n, maxPlain)
	}
}

// allowedAt is a LAN.Allowed of these addresses, allowed at 08:00 UTC on 2026-11-13.
func allowedAt(addrs ...string) func() map[netip.Addr]time.Time {
	m := map[netip.Addr]time.Time{}
	for _, a := range addrs {
		m[netip.MustParseAddr(a)] = time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)
	}
	return func() map[netip.Addr]time.Time { return m }
}
