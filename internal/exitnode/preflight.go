package exitnode

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// preflight warns about host settings that break the exit node.
func preflight(dns []netip.AddrPort) {
	if len(dns) == 0 {
		// Without --dns, the exit node's DNS forwards to the first nameserver in /etc/resolv.conf.
		ns, err := firstNameserver("/etc/resolv.conf")
		switch {
		case err != nil:
			log.Printf("WARN: /etc/resolv.conf: %v (exit node DNS will fail)", err)
		case ns == "100.100.100.100" || !netip.MustParseAddr(ns).Is4():
			log.Printf("WARN: first nameserver is %s; exit node DNS needs an IPv4 resolver other than 100.100.100.100", ns)
		default:
			dns = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr(ns), 53)}
		}
	}
	for _, server := range dns {
		go func() { // in the background: it can take seconds, and only warns
			if err := probeDNS(server, 3*time.Second); err != nil {
				log.Printf("WARN: DNS %v: %v. iPhones ask the exit node for these; pick another with --dns 1.1.1.1:53", server, err)
			}
		}()
	}
	// If this host uses an exit node or accepted routes, our outbound goes back into the tailnet.
	if dev := routeDevice("1.1.1.1"); strings.HasPrefix(dev, "utun") || dev == "tailscale0" {
		log.Printf("WARN: 1.1.1.1 routes via %s; this machine seems to use an exit node or accepted routes", dev)
	}
}

// probeDNS asks server for an A and an HTTPS (type 65) record, as iOS does
// for every name. Some home routers never answer type 65, and then iOS
// waits before every connection.
func probeDNS(server netip.AddrPort, timeout time.Duration) error {
	for _, q := range []struct {
		name  string
		qtype dnsmessage.Type
	}{{"A", dnsmessage.TypeA}, {"HTTPS (type 65)", dnsmessage.Type(65)}} {
		err := askDNS(server, q.qtype, timeout)
		if err != nil {
			err = askDNS(server, q.qtype, timeout) // a UDP packet can be lost once; warn only on a pattern
		}
		if err != nil {
			return fmt.Errorf("no answer to an %s query (%v)", q.name, err)
		}
	}
	return nil
}

func askDNS(server netip.AddrPort, qtype dnsmessage.Type, timeout time.Duration) error {
	c, err := net.DialTimeout("udp", server.String(), timeout)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	id := uint16(rand.Uint32())
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("apple.com."), Type: qtype, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	if _, err := c.Write(q); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return err
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil || h.ID != id || !h.Response {
			continue
		}
		if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
			return fmt.Errorf("rcode %v", h.RCode)
		}
		return nil
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
