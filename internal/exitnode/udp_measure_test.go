package exitnode

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

func openFDs() int {
	ents, _ := os.ReadDir("/dev/fd")
	return len(ents)
}

// TestUDPFlowsMeasure (REQCOVE_UDP_MEASURE=1, about 3 minutes): what each UDP
// flow through the exit node holds (netstack forwards each from its own host
// socket, kept until 2 minutes idle), and that it is all released.
func TestUDPFlowsMeasure(t *testing.T) {
	if os.Getenv("REQCOVE_UDP_MEASURE") == "" {
		t.Skip("set REQCOVE_UDP_MEASURE=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	control, wait := runAgainst(t, nil)
	wait("running", func(s Status) bool { return s.Backend == "Running" })
	phone := startPeer(t, ctx, control.HTTPTestServer.URL, "phone")
	var rc *tailcfg.Node
	for _, n := range control.AllNodes() {
		if strings.HasPrefix(n.Name, "reqcove.") {
			rc = n
		}
	}
	control.SetSubnetRoutes(rc.Key, tsaddr.ExitRoutes())
	useExitNode(t, ctx, phone, rc)
	wait("carrying phone", func(s Status) bool { return len(s.Devices) == 1 })
	if c, err := dialExit(t, ctx, phone, "203.0.113.5:443", false); err == nil { // the route is in once TCP reaches the exit node
		c.Close()
	}
	runtime.GC()
	g0, f0 := runtime.NumGoroutine(), openFDs()
	const n = 1000
	for i := range n {
		dst := fmt.Sprintf("203.0.113.%d:%d", 1+i%250, 20000+i) // distinct flows; TEST-NET, nothing answers
		c, err := phone.Dial(ctx, "udp", dst)
		if err != nil {
			t.Fatalf("udp %s: %v", dst, err)
		}
		c.Write([]byte("x"))
		c.Close()
	}
	time.Sleep(3 * time.Second)
	g1, f1 := runtime.NumGoroutine(), openFDs()
	t.Logf("%d UDP flows: goroutines %d -> %d (+%.1f each), open fds %d -> %d (+%.2f each)", n, g0, g1, float64(g1-g0)/n, f0, f1, float64(f1-f0)/n)
	time.Sleep(2*time.Minute + 15*time.Second) // netstack's idle timeout for UDP flows
	runtime.GC()
	g2, f2 := runtime.NumGoroutine(), openFDs()
	t.Logf("after 2m15s idle: goroutines %d, open fds %d", g2, f2)
	if f2 > f0+10 || g2 > g0+20 {
		t.Errorf("not released: goroutines %d (was %d), fds %d (was %d)", g2, g0, f2, f0)
	}
}
