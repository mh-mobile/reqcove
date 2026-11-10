package capture

import (
	"context"
	"encoding/json"
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
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.WebPort, c.WebPassword, c.webMaxFlows = port, "KEPTTOKENABCDEFGHIJKLMNOPQ", 2 })
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("b", WebKeep+1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chunked": // no length: streamed in pieces
			io.Copy(io.Discard, r.Body)
			io.WriteString(w, "hello ")
			w.(http.Flusher).Flush()
			io.WriteString(w, "from web")
		case "/big":
			io.WriteString(w, big)
		default:
			io.WriteString(w, "ok")
		}
	}))
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
	if token != "KEPTTOKENABCDEFGHIJKLMNOPQ" { // the password run keeps, not one of its own
		t.Errorf("token %q", token)
	}
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
	// Bodies reach the app once and whole, and mitmweb shows them, up to WebKeep.
	hc := h.client("dev")
	r, err := hc.Post(backend.URL+"/chunked", "text/plain", strings.NewReader("posted body"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(got) != "hello from web" {
		t.Errorf("the app got %q", got)
	}
	r, err = hc.Get(backend.URL + "/big")
	if err != nil {
		t.Fatal(err)
	}
	gotBig, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if len(gotBig) != len(big) {
		t.Errorf("the app got %d bytes of %d", len(gotBig), len(big))
	}
	h.doneFlow("/chunked", false)
	h.doneFlow("/big", false)
	_, list := get(base + "flows?token=" + token)
	var flows []struct {
		ID      string `json:"id"`
		Request struct {
			Path string `json:"path"`
		} `json:"request"`
	}
	json.Unmarshal([]byte(list), &flows)
	ids := map[string]string{}
	for _, f := range flows {
		ids[f.Request.Path] = f.ID
	}
	content := func(path, dir string) string {
		_, b := get(base + "flows/" + ids[path] + "/" + dir + "/content.data?token=" + token)
		return b
	}
	// mitmweb keeps the newest flows only (two in this test): /through-web went.
	if _, ok := ids["/through-web"]; ok || len(flows) != 2 {
		t.Errorf("mitmweb's flows past its bound: %d, /through-web kept %v", len(flows), ok)
	}
	if c := content("/chunked", "response"); c != "hello from web" {
		t.Errorf("mitmweb's response body: %q", c)
	}
	if c := content("/chunked", "request"); c != "posted body" {
		t.Errorf("mitmweb's request body: %q", c)
	}
	if c := content("/big", "response"); len(c) > WebKeep {
		t.Errorf("mitmweb kept a body over WebKeep: %d bytes", len(c))
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

// A config.yml left in the confdir by someone else is removed before mitmdump
// starts: mitmproxy reads it, and options in it could undo reqcove's.
func TestStrayConfigYmlRemoved(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var path string
	if _, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) {
		path = filepath.Join(c.Confdir, "config.yml")
		os.WriteFile(path, []byte("ssl_insecure: true\n"), 0o600)
	}); err != nil {
		t.Fatal(err)
	}
	if exists(path) {
		t.Error("config.yml is still in the confdir")
	}
}

// TestWebMadeResponse (REQCOVE_E2E=1): with --web, a response mitmproxy made
// itself (map_local, a failed rule's 502) leaves nothing kept for mitmweb:
// mitmweb holds it whole, and a copy kept would never be freed. Driven
// through mitmproxy's own test helpers, as no request shows the leak.
func TestWebMadeResponse(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	addon := filepath.Join(t.TempDir(), "addon.py")
	if err := os.WriteFile(addon, addonPy, 0o600); err != nil {
		t.Fatal(err)
	}
	py := `import sys, importlib.util
from mitmproxy.test import taddons, tflow
spec = importlib.util.spec_from_file_location("reqcove_addon", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
a = m.Reqcove()
with taddons.context(a) as tctx:
    tctx.configure(a, reqcove_web_keep=1 << 20)
    f = tflow.tflow(resp=True)
    f.metadata["reqcove_local"] = True
    a.request(f)
    a.response(f)
    print(len(a.kept))
`
	out, err := exec.Command("uvx", "--python", "3.14", "--exclude-newer", UVExcludeNewer, "--from", "mitmproxy==12.3.1", "python", "-I", "-c", py, addon).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "0" {
		t.Errorf("bodies kept for mitmweb after a made response: %s, want 0", got)
	}
}
