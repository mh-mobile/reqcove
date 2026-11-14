package exitnode

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
	"time"
)

type dialed struct {
	v      verdict
	device string
	dst    netip.AddrPort
}

// proxyHarness serves remoteProxy on loopback. Names resolve from a table and
// every allowed dial lands on a local backend, so the decisions are what is tested.
func proxyHarness(t *testing.T, deviceIP string) (*url.URL, func() []dialed) {
	t.Helper()
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", r.Host, r.URL.Path)
	}))
	backend.EnableHTTP2 = false
	backend.StartTLS()
	plain := httptest.NewServer(backend.Config.Handler)
	t.Cleanup(backend.Close)
	t.Cleanup(plain.Close)

	names := map[string]string{"app.test": "203.0.113.5", "other.test": "198.51.100.7", "lan.test": "192.168.1.1", "apple.test": "17.253.1.1"}
	var mu sync.Mutex
	var log []dialed
	p := &policy{devices: map[netip.Addr]Device{netip.MustParseAddr(deviceIP): {ID: "nPHONE", Name: "iphone"}},
		allowSrc: []netip.Addr{netip.MustParseAddr(deviceIP)}, socks: true}
	rp := &remoteProxy{
		policy: func() *policy { return p },
		resolve: func(_ context.Context, host string) (netip.Addr, error) {
			if ip, err := netip.ParseAddr(host); err == nil {
				return ip, nil
			}
			if s, ok := names[host]; ok {
				return netip.MustParseAddr(s), nil
			}
			return netip.Addr{}, fmt.Errorf("no such host %s", host)
		},
		dial: func(ctx context.Context, v verdict, device string, dst netip.AddrPort) (net.Conn, error) {
			mu.Lock()
			log = append(log, dialed{v, device, dst})
			mu.Unlock()
			to := plain.Listener.Addr().String()
			if dst.Port() == 443 {
				to = backend.Listener.Addr().String()
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", to)
		},
	}
	srv := httptest.NewServer(rp)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u, func() []dialed { mu.Lock(); defer mu.Unlock(); return append([]dialed(nil), log...) }
}

func get(t *testing.T, c *http.Client, u string) (int, string) {
	t.Helper()
	r, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b)
}

func TestRemoteProxyCarries(t *testing.T) {
	pu, dials := proxyHarness(t, "127.0.0.1")
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	// CONNECT, then two plain requests to different hosts on one keep-alive connection.
	if code, body := get(t, c, "https://app.test/secure"); code != 200 || body != "app.test /secure" {
		t.Errorf("CONNECT: %d %q", code, body)
	}
	for _, uw := range [][2]string{{"http://app.test/a", "app.test /a"}, {"http://other.test/b", "other.test /b"}} {
		if code, body := get(t, c, uw[0]); code != 200 || body != uw[1] {
			t.Errorf("%s: %d %q", uw[0], code, body)
		}
	}
	get(t, c, "https://apple.test/")
	want := []dialed{
		{socks, "nPHONE", netip.MustParseAddrPort("203.0.113.5:443")},
		{socks, "nPHONE", netip.MustParseAddrPort("203.0.113.5:80")},
		{socks, "nPHONE", netip.MustParseAddrPort("198.51.100.7:80")},
		{direct, "nPHONE", netip.MustParseAddrPort("17.253.1.1:443")}, // Apple goes direct, as on the exit node
	}
	if got := dials(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("dials:\n got %v\nwant %v", got, want)
	}
}

func TestRemoteProxyRefuses(t *testing.T) {
	pu, dials := proxyHarness(t, "127.0.0.1")
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	// The same destinations an exit node refuses: LAN, loopback (this Mac's services).
	for _, u := range []string{"http://lan.test/", "http://127.0.0.1:22/", "http://localhost.invalid/"} {
		r, err := c.Get(u)
		if err == nil {
			r.Body.Close()
			if r.StatusCode < 400 {
				t.Errorf("%s: %d", u, r.StatusCode)
			}
		}
	}
	if _, err := c.Get("https://lan.test/"); err == nil {
		t.Error("CONNECT to the LAN succeeded")
	}
	// Not a proxy request.
	if code, _ := get(t, &http.Client{}, pu.String()+"/"); code != 400 {
		t.Errorf("origin-form request: %d", code)
	}
	// A device that is not one of --device.
	pu2, dials2 := proxyHarness(t, "100.64.0.9")
	c2 := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu2)}}
	if code, _ := get(t, c2, "http://app.test/"); code != 403 {
		t.Errorf("unknown device: %d", code)
	}
	if d := append(dials(), dials2()...); len(d) != 0 {
		t.Errorf("refused requests were dialed: %v", d)
	}
}

// Pooled plain-HTTP connections carry one device's SOCKS user, so devices never share them.
func TestRemoteProxyPoolsPerDevice(t *testing.T) {
	rp := &remoteProxy{}
	a, b := netip.MustParseAddrPort("100.64.0.1:1"), netip.MustParseAddrPort("100.64.0.2:2")
	pa := rp.reverseProxy(a, Device{ID: "nA"})
	if pa != rp.reverseProxy(netip.MustParseAddrPort("100.64.0.1:9"), Device{ID: "nA"}) {
		t.Error("the same device got a second pool")
	}
	if pa == rp.reverseProxy(b, Device{ID: "nB"}) {
		t.Error("two devices share a pool")
	}
}

// Failed plain requests are logged by host only: paths and queries carry secrets.
func TestRemoteProxyLogsNoURL(t *testing.T) {
	pu, _ := proxyHarness(t, "127.0.0.1")
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	drainEvents() // lines from earlier tests
	// The line waits in events, or is in the log once a Run's logLoop took it.
	var mu sync.Mutex
	var out strings.Builder
	log.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return out.Write(p) }))
	defer log.SetOutput(os.Stderr)
	if r, err := c.Get("http://nowhere.test/private/path?token=s3cret"); err == nil {
		r.Body.Close()
	}
	for range 500 {
		var line string
		select {
		case line = <-events:
		default:
			mu.Lock()
			for _, l := range strings.Split(out.String(), "\n") {
				if strings.Contains(l, "nowhere.test") {
					line = l
				}
			}
			mu.Unlock()
		}
		if strings.Contains(line, "nowhere.test") {
			if strings.Contains(line, "s3cret") || strings.Contains(line, "private") {
				t.Errorf("log line: %q", line)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no log line")
}

// An app retrying a name that does not resolve: the first failure is logged,
// the same ones again (another source port each time) are not.
func TestRemoteProxyLogsRepeatOnce(t *testing.T) {
	rp := &remoteProxy{policy: func() *policy { return nil }, resolve: func(context.Context, string) (netip.Addr, error) {
		return netip.Addr{}, &net.DNSError{Err: "no such host", Name: "repeat.test", IsNotFound: true}
	}}
	var mu sync.Mutex
	var out strings.Builder
	log.SetOutput(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return out.Write(p) }))
	defer log.SetOutput(os.Stderr)
	drainEvents() // lines from earlier tests
	for i := range 5 {
		w := httptest.NewRecorder()
		rp.connect(w, &http.Request{Method: http.MethodConnect, Host: "repeat.test:443"}, netip.AddrPortFrom(netip.MustParseAddr("192.168.0.50"), uint16(50000+i)), Device{})
		if w.Code != http.StatusBadGateway {
			t.Errorf("status %d", w.Code)
		}
	}
	time.Sleep(100 * time.Millisecond) // a Run's logLoop may take the line
	n := 0
	for _, l := range drainEvents() {
		if strings.Contains(l, "CONNECT repeat.test") {
			n++
		}
	}
	mu.Lock()
	n += strings.Count(out.String(), "CONNECT repeat.test")
	mu.Unlock()
	if n != 1 {
		t.Errorf("%d lines for 5 identical failures", n)
	}
}

// The same failure again: not logged within a minute, then with how many were
// not; at most maxFailKinds kinds kept, the one logged longest ago dropped.
func TestFailLog(t *testing.T) {
	var f failLog
	t0 := time.Date(2026, 11, 14, 7, 13, 30, 0, time.Local)
	steps := []struct {
		kind string
		at   time.Duration
		more string
		ok   bool
	}{
		{"a", 0, "", true},
		{"a", 5 * time.Second, "", false},
		{"b", 6 * time.Second, "", true}, // another kind: at once
		{"a", 50 * time.Second, "", false},
		{"a", 61 * time.Second, " (2 more since 07:13:30)", true},
		{"a", 2 * time.Minute, "", false},
		{"a", 3 * time.Minute, " (1 more since 07:14:31)", true},
		{"a", 5 * time.Minute, "", true}, // none skipped since
	}
	for i, s := range steps {
		if more, ok := f.note(s.kind, t0.Add(s.at)); more != s.more || ok != s.ok {
			t.Errorf("%d: %q %v, want %q %v", i, more, ok, s.more, s.ok)
		}
	}
	for i := range maxFailKinds + 10 {
		f.note(fmt.Sprint("k", i), t0.Add(time.Hour+time.Duration(i)*time.Second))
	}
	if len(f.m) != maxFailKinds {
		t.Errorf("%d kinds kept", len(f.m))
	}
	if _, ok := f.m["k0"]; ok {
		t.Error("the oldest kind kept")
	}
	if _, ok := f.m[fmt.Sprint("k", maxFailKinds+9)]; !ok {
		t.Error("the newest kind dropped")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// Peers that are not devices are closed as they are accepted, so they cannot
// hold Remote Proxy connections open; a connection whose device is dropped
// gets a 403 that closes it.
func TestRemoteProxyClosesOutsiders(t *testing.T) {
	var cur atomic.Pointer[policy]
	device := &policy{devices: map[netip.Addr]Device{netip.MustParseAddr("127.0.0.1"): {ID: "nPHONE"}}}
	cur.Store(&policy{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: &remoteProxy{policy: cur.Load}, ReadHeaderTimeout: 30 * time.Second}
	go srv.Serve(onlyDevices{ln, cur.Load})
	t.Cleanup(func() { srv.Close() })

	c, _ := net.Dial("tcp", ln.Addr().String())
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("an outsider's connection stayed open: %v", err)
	}
	c.Close()

	cur.Store(device)
	c, _ = net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	br := bufio.NewReader(c)
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if r, err := http.ReadResponse(br, nil); err != nil || r.StatusCode != 400 {
		t.Fatalf("device's first request: %v %v", r, err)
	} else {
		io.Copy(io.Discard, r.Body)
	}
	cur.Store(&policy{}) // the device is gone from the tailnet
	fmt.Fprint(c, "GET http://a.test/ HTTP/1.1\r\nHost: a.test\r\n\r\n")
	if r, err := http.ReadResponse(br, nil); err != nil || r.StatusCode != 403 || !r.Close {
		t.Errorf("after the device left: %v %v, want a 403 that closes", r, err)
	}
}

// answeringDNS answers every A query with 203.0.113.7, or with NXDOMAIN, and counts queries.
func answeringDNS(t *testing.T, nx bool) (netip.AddrPort, *atomic.Int32) {
	return answeringDNSAfter(t, nx, 0)
}

// answeringDNSAfter answers each query after delay (a slow or lossy path).
func answeringDNSAfter(t *testing.T, nx bool, delay time.Duration) (netip.AddrPort, *atomic.Int32) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	var n atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			m, addr, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:m])
			if err != nil {
				continue
			}
			n.Add(1)
			q, _ := p.Question()
			rh := dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true}
			if nx {
				rh.RCode = dnsmessage.RCodeNameError
			}
			b := dnsmessage.NewBuilder(nil, rh)
			b.StartQuestions()
			b.Question(q)
			if q.Type == dnsmessage.TypeA && !nx {
				b.StartAnswers()
				b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}})
			}
			out, _ := b.Finish()
			time.AfterFunc(delay, func() { c.WriteTo(out, addr) })
		}
	}()
	return netip.MustParseAddrPort(c.LocalAddr().String()), &n
}

// The Remote Proxy's lookups go on to the next --dns when one is dead, for
// every lookup, concurrent ones included, and wait for a slow one in any
// position, lookup after lookup; a name that does not exist is an answer.
func TestResolverTriesEveryUpstream(t *testing.T) {
	good, goodQueries := answeringDNS(t, false)
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0") // open, never answers, like a server that is down
	defer dead.Close()
	deadAddr := netip.MustParseAddrPort(dead.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resolve := resolver([]netip.AddrPort{deadAddr, good})
	start := time.Now()
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ip, err := resolve(ctx, fmt.Sprintf("app%d.example", i)); err != nil || ip != netip.MustParseAddr("203.0.113.7") {
				t.Errorf("lookup %d with a dead first upstream: %v %v", i, ip, err)
			}
		}()
	}
	wg.Wait()
	if d := time.Since(start); d > upstreamStagger+time.Second {
		t.Errorf("20 lookups past a silent first upstream took %v", d)
	}

	// A slow upstream (2.5 s, past Go's first retry would not help) is waited for,
	// first or last, alone or not, on every lookup.
	slow, _ := answeringDNSAfter(t, false, 2500*time.Millisecond)
	for _, ups := range [][]netip.AddrPort{{slow}, {deadAddr, slow}, {slow, deadAddr}} {
		r := resolver(ups)
		for n := range 3 {
			start := time.Now()
			if _, err := r(ctx, fmt.Sprintf("slow%d.example", n)); err != nil {
				t.Errorf("slow upstream in %v, lookup %d: %v", ups, n, err)
			} else if d := time.Since(start); d > 5*time.Second {
				t.Errorf("slow upstream in %v, lookup %d took %v", ups, n, d)
			}
		}
	}

	nx, _ := answeringDNS(t, true)
	before := goodQueries.Load()
	if _, err := resolver([]netip.AddrPort{nx, good})(ctx, "missing.example"); err == nil {
		t.Error("NXDOMAIN from the first upstream: no error")
	}
	if goodQueries.Load() != before {
		t.Error("NXDOMAIN from the first upstream: asked the next one")
	}
	// A dead upstream's error names it, not this computer's resolv.conf server.
	short, cancelShort := context.WithTimeout(ctx, time.Second)
	defer cancelShort()
	if _, err := resolver([]netip.AddrPort{deadAddr})(short, "x.example"); err == nil || !strings.Contains(err.Error(), deadAddr.String()) {
		t.Errorf("dead upstream error: %v", err)
	}
}

// TestSOCKSDialTimeout: mitmproxy answers SOCKS only once connected upstream
// (75 s on macOS for a black-holed address, tried), so a SOCKS dial gives up
// after dialTimeout, as a direct one does, and says which destination did not
// answer, or that the client left, rather than x/net's read timeout on the
// local port.
func TestSOCKSDialTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { // a SOCKS port that never answers
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	defer func(d time.Duration) { dialTimeout = d }(dialTimeout)
	dialTimeout = 200 * time.Millisecond
	dst := netip.MustParseAddrPort("192.0.2.1:443")
	dial := func(ctx context.Context) error {
		done := make(chan error, 1)
		go func() {
			_, err := dialVia(ctx, socks, "dev", ln.Addr().String(), "pw", nil, dst)
			done <- err
		}()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("a SOCKS dial waited past dialTimeout")
			return nil
		}
	}
	if err := dial(context.Background()); err == nil || err.Error() != "192.0.2.1:443 did not answer within 200ms (through mitmproxy)" {
		t.Errorf("timeout: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background()) // the client leaves first (a request's context is canceled)
	defer cancel()
	time.AfterFunc(50*time.Millisecond, cancel)
	if err := dial(ctx); err == nil || err.Error() != "the client left before 192.0.2.1:443 answered (through mitmproxy)" {
		t.Errorf("client left: %v", err)
	}
}

// TestRelayHalfClose: through SOCKS, a client that is done sending (nc -N)
// still gets the answer the server sends after that.
func TestRelayHalfClose(t *testing.T) {
	fs := startFakeSOCKS(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			relay(c, netip.MustParseAddrPort("100.64.0.2:5000"), netip.MustParseAddrPort("203.0.113.5:443"), socks, "dev", fs.addr, "pw", nil, false)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "ping")
	c.(*net.TCPConn).CloseWrite()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if b, _ := io.ReadAll(c); string(b) != "pingbye" {
		t.Errorf("got %q, want the echo and the answer after the half-close", b)
	}
}

// TestDialWaitsForReady: a SOCKS dial goes to the port only once ready says
// mitmproxy is up; while it is not, nothing reaches the port, and the dial
// fails after socksHold. Direct dials do not wait.
func TestDialWaitsForReady(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			c.Close()
		}
	}()
	defer func(d time.Duration) { socksHold = d }(socksHold)
	socksHold = 200 * time.Millisecond
	dst := netip.MustParseAddrPort("192.0.2.1:443")
	notReady := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }

	start := time.Now()
	if _, err := dialVia(context.Background(), socks, "dev", ln.Addr().String(), "pw", notReady, dst); err == nil {
		t.Fatal("dialed while mitmproxy was not ready")
	}
	if d := time.Since(start); d < socksHold || d > 5*time.Second {
		t.Errorf("held %v, want about %v", d, socksHold)
	}
	select {
	case <-accepted:
		t.Fatal("the SOCKS port got a connection while mitmproxy was not ready")
	case <-time.After(50 * time.Millisecond):
	}

	// Ready: the dial reaches the port (the fake closes it, so SOCKS fails after).
	dialVia(context.Background(), socks, "dev", ln.Addr().String(), "pw", func(context.Context) error { return nil }, dst)
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("a ready dial never reached the SOCKS port")
	}

	// Direct: not held.
	start = time.Now()
	dialVia(context.Background(), direct, "dev", "", "", notReady, netip.MustParseAddrPort(ln.Addr().String()))
	if d := time.Since(start); d >= socksHold {
		t.Errorf("a direct dial was held %v", d)
	}
}
