package exitnode

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS answers A queries; for type 65 it stays silent, answers SERVFAIL,
// or answers, as told.
func fakeDNS(t *testing.T, https string) netip.AddrPort {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, _ := p.Question()
			rcode := dnsmessage.RCodeSuccess
			if q.Type == dnsmessage.Type(65) {
				switch https {
				case "silent":
					continue
				case "servfail":
					rcode = dnsmessage.RCodeServerFailure
				}
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RCode: rcode})
			b.StartQuestions()
			b.Question(q)
			out, _ := b.Finish()
			pc.WriteTo(out, addr)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestProbeDNS(t *testing.T) {
	if err := probeDNS(fakeDNS(t, "answer"), time.Second); err != nil {
		t.Errorf("a good resolver: %v", err)
	}
	for _, mode := range []string{"silent", "servfail"} {
		if err := probeDNS(fakeDNS(t, mode), 300*time.Millisecond); err == nil || !strings.Contains(err.Error(), "HTTPS (type 65)") {
			t.Errorf("%s on type 65: %v", mode, err)
		}
	}
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := netip.MustParseAddrPort(dead.LocalAddr().String())
	dead.Close()
	if err := probeDNS(addr, 300*time.Millisecond); err == nil || !strings.Contains(err.Error(), "an A query") {
		t.Errorf("nothing there: %v", err)
	}
}

func TestFirstNameserver(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ conf, want, err string }{
		{"# a comment\nsearch example.com\nnameserver 192.168.1.1\nnameserver 1.1.1.1\n", "192.168.1.1", ""},
		{"nameserver fe80::1%en0\n", "fe80::1%en0", ""},
		{"search example.com\n", "", "no nameserver"},
		{"nameserver router.local\n", "", "bad nameserver"},
	} {
		p := filepath.Join(dir, "resolv.conf")
		os.WriteFile(p, []byte(c.conf), 0o600)
		got, err := firstNameserver(p)
		if got != c.want || (c.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%q: %q %v", c.conf, got, err)
		}
	}
}
