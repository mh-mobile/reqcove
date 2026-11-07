package exitnode

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
)

// preflight warns about host settings that break the exit node.
func preflight(checkResolvConf bool) {
	if checkResolvConf {
		// Without --dns, the exit node's DNS forwards to the first nameserver in /etc/resolv.conf.
		ns, err := firstNameserver("/etc/resolv.conf")
		switch {
		case err != nil:
			log.Printf("WARN: /etc/resolv.conf: %v (exit node DNS will fail)", err)
		case ns == "100.100.100.100" || !netip.MustParseAddr(ns).Is4():
			log.Printf("WARN: first nameserver is %s; exit node DNS needs an IPv4 resolver other than 100.100.100.100", ns)
		}
	}
	// If this host uses an exit node or accepted routes, our outbound goes back into the tailnet.
	if dev := routeDevice("1.1.1.1"); strings.HasPrefix(dev, "utun") || dev == "tailscale0" {
		log.Printf("WARN: 1.1.1.1 routes via %s; this machine seems to use an exit node or accepted routes", dev)
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
