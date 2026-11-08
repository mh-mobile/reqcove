package exitnode

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
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
	for len(events) > 0 { // lines from earlier tests
		<-events
	}
	if r, err := c.Get("http://nowhere.test/private/path?token=s3cret"); err == nil {
		r.Body.Close()
	}
	select {
	case line := <-events:
		if !strings.Contains(line, "nowhere.test") || strings.Contains(line, "s3cret") || strings.Contains(line, "private") {
			t.Errorf("log line: %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no log line")
	}
}

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
