package exitnode

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// TestTwoNodes runs reqcove's node against a local control server (testcontrol)
// with real tsnet peers: the --device peer is carried to SOCKS5 with its
// StableID, denied destinations are refused, and a peer that is not one of
// --device gets nothing, on the exit node and on the Remote Proxy.
func TestTwoNodes(t *testing.T) {
	netns.SetEnabled(false) // as tailscale's own tsnet tests do
	t.Cleanup(func() { netns.SetEnabled(true) })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	control := &testcontrol.Server{DERPMap: integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1"), MagicDNSDomain: "tail-scale.ts.net"}
	control.HTTPTestServer = httptest.NewServer(control)
	t.Cleanup(control.HTTPTestServer.Close)
	url := control.HTTPTestServer.URL

	// This Mac's own services: nothing must reach them.
	local, _ := net.Listen("tcp", "127.0.0.1:0")
	defer local.Close()
	localHits := make(chan struct{}, 10)
	go func() {
		for {
			c, err := local.Accept()
			if err != nil {
				return
			}
			localHits <- struct{}{}
			c.Close()
		}
	}()
	socks := startFakeSOCKS(t)

	// reqcove's verbose log is the evidence of what it refused.
	var logBuf syncBuffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// The device and the outsider join first, so reqcove finds the device on its first look.
	phone := startPeer(t, ctx, url, "phone")
	outsider := startPeer(t, ctx, url, "outsider")
	matched := make(chan map[string]string, 4)
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, Config{
			Dir: filepath.Join(t.TempDir(), "reqcove"), Hostname: "reqcove", ControlURL: url,
			DNS: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:53")}, Devices: []string{"phone"},
			SocksAddr: socks.addr, SocksSecret: "pw", ProxyPort: 8080, Verbose: true,
			UI:        func(w http.ResponseWriter, r *http.Request, id string) { fmt.Fprint(w, "page for "+id) },
			OnDevices: func(m map[string]string) { matched <- m },
		})
	}()
	var names map[string]string
	for len(names) == 0 { // the first reports come before login, with no devices
		select {
		case names = <-matched:
		case err := <-runErr:
			t.Fatalf("Run: %v", err)
		case <-ctx.Done():
			t.Fatal("reqcove never matched the device")
		}
	}
	var reqcove *tailcfg.Node
	for _, n := range control.AllNodes() {
		if strings.HasPrefix(n.Name, "reqcove.") {
			reqcove = n
		}
	}
	if reqcove == nil {
		t.Fatal("reqcove's node is not in the tailnet")
	}
	control.SetSubnetRoutes(reqcove.Key, tsaddr.ExitRoutes()) // the admin's approval
	phoneID := useExitNode(t, ctx, phone, reqcove)
	useExitNode(t, ctx, outsider, reqcove)
	if names[phoneID] != "phone" || len(names) != 1 {
		t.Fatalf("matched devices %v, want only phone (%s)", names, phoneID)
	}
	rcIP := reqcove.Addresses[0].Addr()
	// tsnet uploads its logs (they carry destination IPs) unless this is set.
	// In tests logpolicy never uploads anyway, so the knob is what can be checked.
	if !envknob.NoLogsNoSupport() {
		t.Error("Run did not turn off tsnet's log upload")
	}

	// TCP 443 through the exit node goes to SOCKS5 as the device.
	echo := func(c net.Conn) string {
		defer c.Close()
		io.WriteString(c, "ping")
		b := make([]byte, 4)
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		io.ReadFull(c, b)
		return string(b)
	}
	for _, peer := range []*tsnet.Server{phone, outsider} {
		lc, _ := peer.LocalClient()
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if _, err := lc.Ping(pctx, reqcove.Addresses[0].Addr(), tailcfg.PingTSMP); err != nil {
			t.Fatalf("ping reqcove: %v", err)
		}
		cancel()
	}
	c, err := dialExit(t, ctx, phone, "203.0.113.5:443", true)
	if err != nil {
		t.Fatalf("phone through the exit node: %v", err)
	}
	if got := echo(c); got != "ping" {
		t.Fatalf("echo through the exit node: %q", got)
	}
	if r := socks.last(); r.user != phoneID || r.pass != "pw" || r.dst != "203.0.113.5:443" {
		t.Errorf("SOCKS5 saw %+v, want user %s to 203.0.113.5:443", r, phoneID)
	}

	// IPv6 is refused at once (an RST), so Happy Eyeballs falls back to IPv4
	// without waiting: no delay per new connection.
	start := time.Now()
	c6, err6 := phone.Dial(ctx, "tcp", "[2001:db8::1]:443")
	if err6 == nil {
		c6.SetReadDeadline(time.Now().Add(3 * time.Second))
		if n, _ := c6.Read(make([]byte, 1)); n > 0 {
			t.Error("IPv6 was carried")
		}
		c6.Close()
	}
	t.Logf("IPv6 dial refused after %v: %v", time.Since(start).Round(time.Millisecond), err6)
	if errors.Is(err6, errSystemDial) {
		t.Error("IPv6 never reached the exit node (no route), so this measures nothing")
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("IPv6 took %v to fail: new connections would wait for it", d)
	}

	// The page on the node's port 80: the device gets it, as itself, and the
	// request is not carried (nothing reaches SOCKS5); the outsider gets nothing.
	pageVia := func(n *tsnet.Server) (string, error) {
		hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: n.Dial}}
		r, err := hc.Get(fmt.Sprintf("http://%v/", rcIP))
		if err != nil {
			return "", err
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return string(b), nil
	}
	socksBefore := socks.count()
	if got, err := pageVia(phone); err != nil || got != "page for "+phoneID {
		t.Errorf("phone to the page: %q %v", got, err)
	}
	if socks.count() != socksBefore {
		t.Error("the page's request was carried to SOCKS5")
	}
	if got, err := pageVia(outsider); err == nil {
		t.Errorf("outsider got the page: %q", got)
	}

	// Remote Proxy: CONNECT over the tailnet, also to SOCKS5 as the device.
	if pc, err := phone.Dial(ctx, "tcp", fmt.Sprintf("%v:8080", rcIP)); err != nil {
		t.Errorf("phone to the Remote Proxy: %v", err)
	} else if code, conn := connect(pc, "203.0.113.6:443"); code != 200 {
		t.Errorf("CONNECT from phone: %d", code)
	} else if got := echo(conn); got != "ping" || socks.last().dst != "203.0.113.6:443" || socks.last().user != phoneID {
		t.Errorf("Remote Proxy: echo %q, SOCKS5 saw %+v", got, socks.last())
	}
	// Plain http:// on the Remote Proxy: to SOCKS5 as the device too. (The fake
	// SOCKS5 echoes the request back, so the answer itself is a 502.)
	if pc, err := phone.Dial(ctx, "tcp", fmt.Sprintf("%v:8080", rcIP)); err != nil {
		t.Errorf("phone to the Remote Proxy: %v", err)
	} else {
		fmt.Fprint(pc, "GET http://203.0.113.7/x HTTP/1.1\r\nHost: 203.0.113.7\r\n\r\n")
		pc.SetReadDeadline(time.Now().Add(10 * time.Second))
		http.ReadResponse(bufio.NewReader(pc), nil)
		pc.Close()
		if r := socks.last(); r.dst != "203.0.113.7:80" || r.user != phoneID {
			t.Errorf("plain HTTP on the Remote Proxy: SOCKS5 saw %+v", r)
		}
	}

	// Denied destinations from the device: this Mac and the LAN.
	before := socks.count()
	_, lport, _ := net.SplitHostPort(local.Addr().String())
	for _, dst := range []string{"127.0.0.1:" + lport, "192.168.1.1:80", "10.0.0.1:443"} {
		if c, err := dialExit(t, ctx, phone, dst, false); err == nil {
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if n, _ := c.Read(make([]byte, 1)); n > 0 {
				t.Errorf("%s answered through the exit node", dst)
			}
			c.Close()
		}
	}
	// On the exit node, tsnet and Tailscale's filter drop most of these before
	// reqcove; on the Remote Proxy only reqcove's own list stands in the way.
	for _, dst := range []string{"127.0.0.1:" + lport, "192.168.255.254:80", "10.255.255.254:443", "100.100.100.100:80"} {
		if pc, err := phone.Dial(ctx, "tcp", fmt.Sprintf("%v:8080", rcIP)); err == nil {
			if code, _ := connect(pc, dst); code != 403 {
				t.Errorf("CONNECT to %s: %d, want 403", dst, code)
			}
		}
	}

	// A peer that is not one of --device: nothing, either way.
	if c, err := dialExit(t, ctx, outsider, "203.0.113.5:443", false); err == nil {
		if got := echo(c); got == "ping" {
			t.Error("the outsider was carried through the exit node")
		}
	} else if errors.Is(err, errSystemDial) {
		t.Errorf("the outsider never got the exit route: %v", err)
	}
	if pc, err := outsider.Dial(ctx, "tcp", fmt.Sprintf("%v:8080", rcIP)); err == nil {
		if code, _ := connect(pc, "203.0.113.6:443"); code != 0 {
			t.Errorf("CONNECT from the outsider: %d, want the connection closed at once", code)
		}
	}

	// UDP: the device's goes out (netstack forwards it: one datagram to TEST-NET-3,
	// where nothing answers); the outsider's, and the device's to a denied range, do not.
	for _, u := range []struct {
		from *tsnet.Server
		dst  string
	}{{phone, "203.0.113.9:9"}, {outsider, "203.0.113.9:9"}, {phone, "198.18.0.1:9"}} {
		if c, err := u.from.Dial(ctx, "udp", u.dst); err == nil {
			c.Write([]byte("x"))
			c.Close()
		}
	}
	time.Sleep(time.Second) // the log lines are written in the background
	p4, _ := phone.TailscaleIPs()
	o4udp, _ := outsider.TailscaleIPs()
	for _, want := range []string{
		fmt.Sprintf(`udp %v:\d+ -> 203\.0\.113\.9:9 forward=true\n`, regexp.QuoteMeta(p4.String())),
		fmt.Sprintf(`udp %v:\d+ -> 203\.0\.113\.9:9 forward=false\n`, regexp.QuoteMeta(o4udp.String())),
		`udp \S+ -> 198\.18\.0\.1:9 forward=false\n`,
	} {
		if !regexp.MustCompile(want).MatchString(logBuf.String()) {
			t.Errorf("UDP: no log line like %q", want)
		}
	}
	if n := strings.Count(logBuf.String(), "forward=true"); n != 1 {
		t.Errorf("%d UDP flows forwarded, want 1 (the device's to 203.0.113.9:9)", n)
	}

	// A forwarded flow's host socket listens on all addresses, at the device's
	// source port. Only the flow's destination may answer through it: a
	// datagram from anyone else that reaches the port must not reach the device.
	if uc, err := phone.Dial(ctx, "udp", "203.0.113.9:10"); err == nil {
		_, port, _ := net.SplitHostPort(uc.LocalAddr().String())
		// Wait for the flow's host socket at the device's port: without it the
		// forged datagram goes nowhere and the check proves nothing.
		inUse := false
		uc.Write([]byte("x"))
		time.Sleep(300 * time.Millisecond) // let the flow bind first: probing races its bind
		for deadline := time.Now().Add(5 * time.Second); !inUse && time.Now().Before(deadline); {
			uc.Write([]byte("x"))
			time.Sleep(100 * time.Millisecond)
			l, err := net.ListenPacket("udp", ":"+port)
			if inUse = err != nil; !inUse {
				l.Close()
			}
		}
		if !inUse {
			t.Errorf("no host socket at the device's port %s: the forged-reply check is void", port)
		}
		if forger, err := net.Dial("udp", "127.0.0.1:"+port); err == nil {
			forger.Write([]byte("forged-reply"))
			forger.Close()
		}
		uc.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := uc.Read(make([]byte, 64)); err == nil {
			t.Errorf("a datagram from another sender reached the device as a reply (%d bytes)", n)
		}
		uc.Close()
	}

	// A ping is answered by pinging from this Mac: never to where TCP and UDP
	// may not go (loopback here), from anyone. Before the hook it came back.
	for _, peer := range []*tsnet.Server{phone, outsider} {
		lc, _ := peer.LocalClient()
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if pr, err := lc.Ping(pctx, netip.MustParseAddr("127.0.0.1"), tailcfg.PingICMP); err == nil && pr.Err == "" {
			t.Errorf("%s: a ping to 127.0.0.1 through the exit node was answered", peer.Hostname)
		}
		cancel()
	}

	time.Sleep(time.Second)
	if socks.count() != before {
		t.Errorf("refused flows reached SOCKS5: %+v", socks.all()[before:])
	}
	select {
	case <-localHits:
		t.Error("a flow reached this Mac's own service")
	default:
	}
	o4, _ := outsider.TailscaleIPs()
	if l := logBuf.String(); !strings.Contains(l, "-> [2001:db8::1]:443 reject") {
		t.Error("the IPv6 refusal was not reqcove's")
	}
	if l := logBuf.String(); !strings.Contains(l, fmt.Sprintf("tcp %v:", o4)) || !strings.Contains(l, "-> 203.0.113.5:443 reject") {
		t.Errorf("no reject logged for the outsider (%v)", o4)
	}
}

func startPeer(t *testing.T, ctx context.Context, controlURL, name string) *tsnet.Server {
	t.Helper()
	s := &tsnet.Server{Dir: filepath.Join(t.TempDir(), name), ControlURL: controlURL, Hostname: name, Store: new(mem.Store), Ephemeral: true, Logf: logger.Discard}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Up(ctx); err != nil {
		t.Fatal(err)
	}
	// Never the host network: a flow either goes through reqcove or fails.
	s.Sys().Dialer.Get().SetSystemDialerForTest(func(_ context.Context, _, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("%w %s", errSystemDial, addr)
	})
	return s
}

var errSystemDial = errors.New("system dial (no exit route yet)")

// dialExit dials through the exit node once its route is installed. With
// untilOK it also retries other errors (the first packets can be lost while
// the peers' path comes up).
func dialExit(t *testing.T, ctx context.Context, s *tsnet.Server, dst string, untilOK bool) (net.Conn, error) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(300 * time.Millisecond) {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		c, err := s.Dial(dctx, "tcp", dst)
		cancel()
		retry := errors.Is(err, errSystemDial) || (untilOK && err != nil)
		if !retry || time.Now().After(deadline) {
			return c, err
		}
	}
}

// useExitNode points s at the exit node and returns s's StableID.
func useExitNode(t *testing.T, ctx context.Context, s *tsnet.Server, exit *tailcfg.Node) string {
	t.Helper()
	lc, _ := s.LocalClient()
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{ExitNodeID: exit.StableID}, ExitNodeIDSet: true}); err != nil {
		t.Fatal(err)
	}
	st, err := lc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return string(st.Self.ID)
}

// connect sends CONNECT on c and returns the status code and the tunnel.
func connect(c net.Conn, target string) (int, net.Conn) {
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return 0, nil
	}
	return resp.StatusCode, c // the 200 has no body, so nothing of the tunnel is buffered
}

type socksReq struct{ user, pass, dst string }

type fakeSOCKS struct {
	addr string
	mu   sync.Mutex
	reqs []socksReq
}

func (f *fakeSOCKS) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.reqs) }
func (f *fakeSOCKS) all() []socksReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]socksReq(nil), f.reqs...)
}
func (f *fakeSOCKS) last() (r socksReq) {
	if a := f.all(); len(a) > 0 {
		r = a[len(a)-1]
	}
	return r
}

// startFakeSOCKS stands in for mitmproxy: a SOCKS5 server (user/password,
// RFC 1928 and 1929) that records each request and echoes the stream.
func startFakeSOCKS(t *testing.T) *fakeSOCKS {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeSOCKS{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				b := func(n int) []byte { p := make([]byte, n); io.ReadFull(r, p); return p }
				b(int(b(2)[1])) // version, methods
				c.Write([]byte{5, 2})
				b(1)
				user := string(b(int(b(1)[0])))
				pass := string(b(int(b(1)[0])))
				c.Write([]byte{1, 0})
				var host string
				switch hdr := b(4); hdr[3] {
				case 1:
					host = netip.AddrFrom4([4]byte(b(4))).String()
				case 3:
					host = string(b(int(b(1)[0])))
				}
				port := binary.BigEndian.Uint16(b(2))
				f.mu.Lock()
				f.reqs = append(f.reqs, socksReq{user, pass, net.JoinHostPort(host, fmt.Sprint(port))})
				f.mu.Unlock()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				io.Copy(c, r) // echo
			}()
		}
	}()
	return f
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
