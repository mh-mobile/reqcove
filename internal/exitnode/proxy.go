package exitnode

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"sync"
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

	// One per device: a pooled connection carries one device's SOCKS user.
	// ponytail: never pruned; bounded by the devices seen in this run.
	plain sync.Map // src IP + StableID -> *httputil.ReverseProxy
}

var errNotCarried = errors.New("destination not carried (LAN, loopback, tailnet, IPv6 or this Mac)")

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

func (rp *remoteProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	src, _ := netip.ParseAddrPort(r.RemoteAddr)
	dev, ok := deviceAt(rp.policy(), r.RemoteAddr)
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
	if rp.ui != nil && rp.policy().isSelf(r.URL.Host) {
		if _, port, err := net.SplitHostPort(r.URL.Host); err != nil || port == "80" {
			rp.ui.ServeHTTP(w, r) // a phone on the Remote Proxy sends the page's requests here too
			return
		}
	}
	rp.reverseProxy(src, dev).ServeHTTP(w, r)
}

func (rp *remoteProxy) connect(w http.ResponseWriter, r *http.Request, src netip.AddrPort, dev Device) {
	out, err := rp.open(r.Context(), src, dev, r.Host)
	if err != nil {
		logEvent("proxy %v CONNECT %s: %v", src, r.Host, err)
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
	v, _ := rp.plain.LoadOrStore(key, &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) { pr.Out.Host = pr.In.Host }, // URL is already absolute
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return rp.open(ctx, src, dev, addr)
			},
			IdleConnTimeout: 90 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logEvent("proxy %v %s %s: %v", src, r.Method, r.Host, err) // never the path or query: they carry secrets
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
	ip, err := rp.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	dst := netip.AddrPortFrom(ip, uint16(pn))
	v := decideTCP(rp.policy(), src, dst)
	if v == reject {
		return nil, fmt.Errorf("%s (%v): %w", host, ip, errNotCarried)
	}
	return rp.dial(ctx, v, dev.ID, dst)
}

func statusFor(err error) int {
	if errors.Is(err, errNotCarried) {
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

// dialVia dials dst directly, or through mitmproxy's SOCKS5 listener with the
// device's StableID as the user name.
func dialVia(ctx context.Context, v verdict, device, socksAddr, socksSecret string, dst netip.AddrPort) (net.Conn, error) {
	var d proxy.Dialer = &net.Dialer{Timeout: 10 * time.Second}
	if v == socks {
		var err error
		if d, err = proxy.SOCKS5("tcp", socksAddr, &proxy.Auth{User: device, Password: socksSecret}, d); err != nil {
			return nil, err
		}
	}
	return d.(proxy.ContextDialer).DialContext(ctx, "tcp", dst.String())
}
