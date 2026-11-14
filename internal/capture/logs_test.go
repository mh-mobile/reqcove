package capture

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// TestLogsHoldNoSecrets (REQCOVE_E2E=1): what mitmdump writes to
// mitmproxy.log, and what reqcove logs about it, carry no secrets, also when
// requests fail: unreachable upstream, a body cut off, a malformed request.
func TestLogsHoldNoSecrets(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var mitmLog, reqcoveLog lockedBuffer
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) {
		c.Log = &mitmLog
		c.Logf = func(f string, a ...any) { fmt.Fprintf(&reqcoveLog, f+"\n", a...) }
		c.RestartDelay = 10 * time.Millisecond
	})
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cut" { // drop the connection mid-request
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "ok SECRET-RESP")
	}))
	defer backend.Close()
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close() // nothing listens here any more

	hc := h.client("dev")
	send := func(method, url, body string) {
		req, _ := http.NewRequest(method, url, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer SECRET-AUTH")
		req.Header.Set("Cookie", "sid=SECRET-COOKIE")
		if r, err := hc.Do(req); err == nil {
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
		}
	}
	send("POST", backend.URL+"/ok?token=SECRET-QUERY", "SECRET-BODY")
	send("POST", "http://"+deadAddr+"/down?token=SECRET-QUERY", "SECRET-BODY")
	send("POST", backend.URL+"/cut?token=SECRET-QUERY", strings.Repeat("SECRET-BODY", 1000))

	// Malformed HTTP straight onto the SOCKS5 tunnel.
	socks, _ := proxy.SOCKS5("tcp", h.c.SocksAddr, &proxy.Auth{User: "dev", Password: h.c.SocksSecret}, proxy.Direct)
	for _, raw := range []string{
		"GET /?token=SECRET-QUERY HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization Bearer SECRET-AUTH\r\n\r\n",
		"POST /?token=SECRET-QUERY HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 999\r\n\r\nSECRET-BODY",
		"SECRET-GARBAGE\r\n\r\n",
	} {
		if c, err := socks.Dial("tcp", backend.Listener.Addr().String()); err == nil {
			io.WriteString(c, raw)
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			bufio.NewReader(c).ReadString('\n')
			c.Close()
		}
	}
	// A restart, logged by reqcove.
	killMitmdump(t, ":"+h.port())
	for deadline := time.Now().Add(time.Minute); h.stats()["state"] != "ready" || h.stat("restarts") != 1; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("mitmdump not back: %v", h.stats())
		}
	}
	time.Sleep(time.Second)

	for name, l := range map[string]string{"mitmproxy.log": mitmLog.String(), "reqcove's log": reqcoveLog.String()} {
		t.Logf("%s: %d bytes", name, len(l))
		if strings.Contains(l, "SECRET") {
			t.Errorf("%s holds a secret:\n%s", name, l)
		}
	}
	if !strings.Contains(reqcoveLog.String(), "restarting") {
		t.Errorf("the restart was not logged: %q", reqcoveLog.String())
	}
}
