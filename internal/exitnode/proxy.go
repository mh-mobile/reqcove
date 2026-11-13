package exitnode

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// remoteProxy is the Remote Proxy entry: an HTTP proxy on the tailnet that the
// iPhone's Wi-Fi proxy setting points at. It takes CONNECT and plain
// absolute-form requests from the allowed devices only. Each destination is
// decided and dialed like an exit node flow (same devices, same denied
// destinations, same SOCKS hand-off). Requests on one keep-alive connection
// are decided one by one; after CONNECT the connection is a tunnel.
type remoteProxy struct {
	policy  func() *policy
	resolve func(ctx context.Context, host string) (netip.Addr, error)
	dial    func(ctx context.Context, v verdict, device string, dst netip.AddrPort) (net.Conn, error)
	ui      http.Handler // the node's own page (--ui), for requests to the node's port 80
	web     http.Handler // mitmweb's relay (--web), for requests to the node's webAddr port
	webAddr string       // mitmweb on this computer, 127.0.0.1:PORT; the node's WebPort goes there
	local   bool         // the local proxy: this computer's own apps, as the device Local

	// One per device: a pooled connection carries one device's SOCKS user.
	// ponytail: emptied whole past maxPlain clients (their idle connections
	// close on their own timeout); an LRU if that ever matters.
	plain  sync.Map // src IP + StableID -> *httputil.ReverseProxy
	plainN atomic.Int64

	failed failLog // repeated failures, logged once a minute
}

const maxPlain = 256

// logFailure logs a failed request, the first of its kind at once, then the
// same again (client address, method, host:port, error) at most once a
// minute with how many were not logged: an app retrying a name that does not
// resolve would fill the log.
func (rp *remoteProxy) logFailure(src netip.AddrPort, method, host string, err error) {
	msg := err.Error()
	kind := msg[strings.LastIndex(msg, ": ")+1:] // without the addresses before it (a local port differs each time)
	if more, ok := rp.failed.note(src.Addr().String()+" "+method+" "+host+" "+kind, time.Now()); ok {
		logEvent("proxy %v %s %s: %v%s", src, method, host, err, more) // never the path or query: they carry secrets
	}
}

// failLog counts failures by kind, for logFailure. At most maxFailKinds kinds:
// the one logged longest ago goes first.
type failLog struct {
	mu sync.Mutex
	m  map[string]*failKind
}

type failKind struct {
	logged  time.Time // the last line logged
	skipped int       // since
}

const maxFailKinds = 256

// note says whether to log a failure of kind at now, and the words to add
// about the ones not logged since the last line.
func (f *failLog) note(kind string, now time.Time) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.m[kind]
	if k == nil {
		if f.m == nil {
			f.m = map[string]*failKind{}
		}
		if len(f.m) >= maxFailKinds { // ponytail: a scan, on a full map only
			var oldest string
			for s, v := range f.m {
				if oldest == "" || v.logged.Before(f.m[oldest].logged) {
					oldest = s
				}
			}
			delete(f.m, oldest)
		}
		f.m[kind] = &failKind{logged: now}
		return "", true
	}
	if now.Sub(k.logged) < time.Minute {
		k.skipped++
		return "", false
	}
	more := ""
	if k.skipped > 0 {
		more = fmt.Sprintf(" (%d more since %s)", k.skipped, k.logged.Format("15:04:05"))
	}
	k.logged, k.skipped = now, 0
	return more, true
}

var (
	errNotCarried = errors.New("destination not carried (LAN, loopback, tailnet, IPv6 or this Mac)")
	errLANRefused = errors.New("refused in LAN mode")
)

// onlyDevices closes connections from peers that are not devices as soon as
// they are accepted, so they cannot hold the Remote Proxy's connections open
// (waiting for headers, or keep-alive after a 403). ServeHTTP checks each
// request again: the devices can change while a connection lasts.
type onlyDevices struct {
	net.Listener
	policy func() *policy
}

func (l onlyDevices) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if ra := c.RemoteAddr(); ra != nil {
			if _, ok := deviceAt(l.policy(), ra.String()); ok {
				return c, nil
			}
		}
		c.Close()
	}
}

// deviceAt is the device at addr (ip:port), if it is one.
func deviceAt(p *policy, addr string) (Device, bool) {
	src, err := netip.ParseAddrPort(addr)
	if err != nil || p == nil {
		return Device{}, false
	}
	d, ok := p.devices[src.Addr().Unmap()]
	return d, ok
}

// pageWriteTimeout bounds writing the page to a slow reader (a variable for tests).
var pageWriteTimeout = time.Minute

// Local is the device the local proxy's requests are recorded as.
var Local = Device{ID: "local", Name: "local"}

func (rp *remoteProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	src, _ := netip.ParseAddrPort(r.RemoteAddr)
	dev, ok := deviceAt(rp.policy(), r.RemoteAddr)
	if rp.local {
		dev, ok = Local, true // on 127.0.0.1: this computer's own apps, trusted as its user is
	}
	if !ok {
		w.Header().Set("Connection", "close")
		http.Error(w, "reqcove: this device is not one of reqcove's --device", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		rp.connect(w, r, src, dev)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "reqcove is a proxy: send absolute http:// URLs, or CONNECT", http.StatusBadRequest)
		return
	}
	if rp.toWeb(r.URL.Host) {
		rp.web.ServeHTTP(w, r) // mitmweb from a phone on the Remote Proxy, which sends it here too
		return
	}
	if rp.ui != nil && rp.policy().isSelf(r.URL.Host) {
		if _, port, err := net.SplitHostPort(r.URL.Host); err != nil || port == "80" {
			// A phone on the Remote Proxy sends the page's requests here too. As on port 80, a
			// slow reader does not hold a page's memory longer. net/http lifts the deadline
			// once the response is written, before the next request on the connection (read in
			// Go 1.27's conn.serve; TestRemoteProxyPageDeadline checks it).
			http.NewResponseController(w).SetWriteDeadline(time.Now().Add(pageWriteTimeout))
			rp.ui.ServeHTTP(w, r)
			return
		}
	}
	rp.reverseProxy(src, dev).ServeHTTP(w, r)
}

// toWeb: hostport is the node's own mitmweb port.
func (rp *remoteProxy) toWeb(hostport string) bool {
	if rp.web == nil || !rp.policy().isSelf(hostport) {
		return false
	}
	_, port, err := net.SplitHostPort(hostport)
	return err == nil && port == strconv.Itoa(WebPort)
}

func (rp *remoteProxy) connect(w http.ResponseWriter, r *http.Request, src netip.AddrPort, dev Device) {
	var out net.Conn
	var err error
	if rp.toWeb(r.Host) {
		// mitmweb's WebSocket through the proxy (Safari tunnels ws:// with CONNECT):
		// to mitmweb itself, for the user's own devices only, as the relay is.
		if _, all, _ := viewerAt(rp.policy(), r.RemoteAddr); !all {
			http.Error(w, "reqcove: mitmweb is for your own devices only", http.StatusForbidden)
			return
		}
		out, err = (&net.Dialer{Timeout: 5 * time.Second}).DialContext(r.Context(), "tcp", rp.webAddr)
	} else {
		out, err = rp.open(r.Context(), src, dev, r.Host)
	}
	if err != nil {
		rp.logFailure(src, "CONNECT", r.Host, err)
		http.Error(w, "reqcove: "+err.Error(), statusFor(err))
		return
	}
	defer out.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "reqcove: cannot tunnel over this connection", http.StatusInternalServerError)
		return
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer c.Close()
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	if n := brw.Reader.Buffered(); n > 0 { // the client may send its ClientHello right away
		b, _ := brw.Reader.Peek(n)
		if _, err := out.Write(b); err != nil {
			return
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go pipe(&wg, out, c)
	go pipe(&wg, c, out)
	wg.Wait()
}

func (rp *remoteProxy) reverseProxy(src netip.AddrPort, dev Device) *httputil.ReverseProxy {
	key := src.Addr().String() + "|" + dev.ID
	if v, ok := rp.plain.Load(key); ok {
		return v.(*httputil.ReverseProxy)
	}
	if rp.plainN.Add(1) > maxPlain {
		rp.plain.Clear()
		rp.plainN.Store(1)
	}
	v, _ := rp.plain.LoadOrStore(key, &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) { pr.Out.Host = pr.In.Host }, // URL is already absolute
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return rp.open(ctx, src, dev, addr)
			},
			IdleConnTimeout: 90 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			rp.logFailure(src, r.Method, r.Host, err)
			http.Error(w, "reqcove: "+err.Error(), statusFor(err))
		},
	})
	return v.(*httputil.ReverseProxy)
}

// open resolves host:port here (so mitmproxy cannot be pointed elsewhere by a
// second lookup), decides like an exit node flow, and dials.
func (rp *remoteProxy) open(ctx context.Context, src netip.AddrPort, dev Device, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("bad port %q", port)
	}
	p := rp.policy()
	lan := !rp.local && p != nil && p.lan
	if lan && pn != 80 && pn != 443 { // before the lookup: the reason is the port
		return nil, fmt.Errorf("%s: port %d: LAN mode carries ports 80 and 443 only: %w", host, pn, errLANRefused)
	}
	ip, err := rp.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	dst := netip.AddrPortFrom(ip, uint16(pn))
	v := decideTCP(p, src, dst)
	if lan {
		var why string
		if v, why = decideLAN(p, dst, slices.Contains(p.exact, strings.ToLower(strings.TrimSuffix(host, ".")))); v == reject {
			return nil, fmt.Errorf("%s (%v): %s: %w", host, ip, why, errLANRefused)
		}
	}
	if rp.local {
		// An address the app gave, or a name this computer's /etc/hosts gives, is the app's own choice.
		_, literal := netip.ParseAddr(host)
		var self []netip.Addr
		trusted := literal == nil || inHostsFile(host)
		if !trusted {
			self, _ = interfaceAddrs()
		}
		v = decideLocal(dst, self, trusted)
	}
	if v == reject {
		return nil, fmt.Errorf("%s (%v): %w", host, ip, errNotCarried)
	}
	return rp.dial(ctx, v, dev.ID, dst)
}

func statusFor(err error) int {
	if errors.Is(err, errNotCarried) || errors.Is(err, errLANRefused) {
		return http.StatusForbidden
	}
	return http.StatusBadGateway
}

// resolver looks names up like any proxy on this Mac: /etc/hosts first (Go
// reads it even with a custom Dial), then the exit node's DNS upstream, or the
// system's resolver without one. So a name /etc/hosts maps to 127.0.0.1 is
// refused here, while on the exit node the iPhone resolves it itself.
// upstreamStagger is how long each --dns upstream gets alone before the next
// is asked too, as the exit node's own DNS proxy does (200 ms there).
var upstreamStagger = 500 * time.Millisecond

func resolver(dns []netip.AddrPort) func(ctx context.Context, host string) (netip.Addr, error) {
	rs := []*net.Resolver{net.DefaultResolver}
	if len(dns) > 0 {
		rs = nil
		for _, server := range dns {
			rs = append(rs, &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, server.String())
			}})
		}
	}
	return func(ctx context.Context, host string) (netip.Addr, error) {
		if ip, err := netip.ParseAddr(host); err == nil {
			return ip.Unmap(), nil
		}
		if !strings.HasSuffix(host, ".") {
			host += "." // absolute: this computer's search domains are not appended (and sent upstream)
		}
		// Upstream i joins after i staggers; the first answer wins, and a name
		// that does not exist is an answer. Each keeps Go's own retries, so a
		// slow upstream is waited for while a dead one costs one stagger.
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		type result struct {
			ip  netip.Addr
			err error
		}
		out := make(chan result, len(rs))
		for i, r := range rs {
			go func() {
				select {
				case <-time.After(time.Duration(i) * upstreamStagger):
				case <-ctx.Done():
					out <- result{err: ctx.Err()}
					return
				}
				ips, err := r.LookupNetIP(ctx, "ip4", host)
				if err != nil {
					if len(dns) > 0 {
						err = fmt.Errorf("%v: %w", dns[i], err) // Go names resolv.conf's server, not this one
					}
					out <- result{err: err}
					return
				}
				out <- result{ip: ips[0].Unmap()}
			}()
		}
		var first error
		for range rs {
			r := <-out
			var de *net.DNSError
			if r.err == nil || errors.As(r.err, &de) && de.IsNotFound {
				return r.ip, r.err
			}
			if first == nil || errors.Is(first, context.Canceled) {
				first = r.err
			}
		}
		return netip.Addr{}, first
	}
}

// socksHold is how long a SOCKS dial waits for mitmproxy to be ready (a
// restart takes a few seconds); a var for tests.
var socksHold = 15 * time.Second

// dialVia dials dst directly, or through mitmproxy's SOCKS5 listener with the
// device's StableID as the user name, once ready says mitmproxy is up: while
// it is down another local process could hold its port, and would get the
// password and the device's traffic.
func dialVia(ctx context.Context, v verdict, device, socksAddr, socksSecret string, ready func(context.Context) error, dst netip.AddrPort) (net.Conn, error) {
	var d proxy.Dialer = &net.Dialer{Timeout: 10 * time.Second}
	if v == socks {
		if ready != nil {
			hold, cancel := context.WithTimeout(ctx, socksHold)
			err := ready(hold)
			cancel()
			if err != nil {
				return nil, err
			}
		}
		var err error
		if d, err = proxy.SOCKS5("tcp", socksAddr, &proxy.Auth{User: device, Password: socksSecret}, d); err != nil {
			return nil, err
		}
	}
	return d.(proxy.ContextDialer).DialContext(ctx, "tcp", dst.String())
}

// localResolve looks host up as this computer's apps would (search domains,
// /etc/hosts, a VPN's DNS), for the local proxy: IPv4.
func localResolve(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("%s: no IPv4 address", host)
	}
	return ips[0].Unmap(), nil
}

// hostsFile is read for inHostsFile; tests point it elsewhere.
var hostsFile = "/etc/hosts"

// inHostsFile: host is a name in this computer's hosts file (the user's own
// mapping, as for a development domain pointed at 127.0.0.1).
func inHostsFile(host string) bool {
	b, err := os.ReadFile(hostsFile)
	if err != nil {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, line := range strings.Split(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		for _, name := range f[min(1, len(f)):] {
			if strings.EqualFold(name, host) {
				return true
			}
		}
	}
	return false
}
