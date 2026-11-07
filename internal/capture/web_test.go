package capture

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWeb (REQCOVE_E2E=1): with WebPort, mitmweb runs instead of mitmdump,
// reqcove still records, the UI wants the password, and the password is
// never in argv and gone after Stop.
func TestWeb(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	port, _ := freePort()
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.WebPort = port })
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer backend.Close()
	if r, err := h.client("dev").Get(backend.URL + "/through-web"); err != nil {
		t.Fatal(err)
	} else {
		r.Body.Close()
	}
	if v := h.doneFlow("/through-web", false); v.Status != 200 {
		t.Errorf("reqcove's record under mitmweb: %+v", v)
	}

	base, token, _ := strings.Cut(h.c.WebURL, "?token=")
	get := func(url string) (int, string) {
		r, err := http.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	if code, _ := get(base + "flows"); code != 403 {
		t.Errorf("mitmweb without the password: %d, want 403", code)
	}
	if code, body := get(base + "flows?token=" + token); code != 200 || !strings.Contains(body, "/through-web") {
		t.Errorf("mitmweb with the password: %d %.200s", code, body)
	}
	// Only on loopback: the Mac's other addresses do not answer.
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil && !ip.IP.IsLoopback() {
			if c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.IP.String(), fmt.Sprint(port)), time.Second); err == nil {
				c.Close()
				t.Errorf("mitmweb answers on %v", ip.IP)
			}
		}
	}
	ps, _ := exec.Command("ps", "axww", "-o", "args=").Output()
	if strings.Contains(string(ps), token) {
		t.Error("the mitmweb password is in a process's arguments")
	}
	cfg := filepath.Join(h.confdir, "config.yaml")
	if fi, err := os.Stat(cfg); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("config.yaml: %v %v", fi, err)
	}
	h.c.Stop()
	if exists(cfg) {
		t.Error("the mitmweb password is left in config.yaml after Stop")
	}
}
