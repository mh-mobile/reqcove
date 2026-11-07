package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/proxy"
	"golang.org/x/net/websocket"
)

// harness runs `mcpflow run` on its own port and socket, so it never touches
// a reqcove the user is running (11080).
type harness struct {
	t         *testing.T
	ctx       context.Context
	bin       string
	confdir   string
	socksAddr string
	socksPort string
	mcpSock   string
	run       *exec.Cmd
	session   *mcp.ClientSession
}

func startHarness(t *testing.T, ctx context.Context, port string, extraEnv ...string) *harness {
	t.Helper()
	h := &harness{t: t, ctx: ctx, socksPort: port, socksAddr: "127.0.0.1:" + port}
	h.bin = filepath.Join(t.TempDir(), "mcpflow")
	if out, err := exec.Command("go", "build", "-o", h.bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	h.confdir = t.TempDir()
	sockDir, err := os.MkdirTemp("/tmp", "rcvt-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	h.mcpSock = filepath.Join(sockDir, "mcp.sock")
	h.run = exec.Command(h.bin, "run", "-confdir", h.confdir, "-socks-port", port, "-mcp-sock", h.mcpSock)
	h.run.Stderr = os.Stderr
	h.run.Env = append(os.Environ(), extraEnv...)
	start := time.Now()
	if err := h.run.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.stop)
	for !exists(h.mcpSock) {
		if ctx.Err() != nil {
			t.Fatal("run never served MCP")
		}
		time.Sleep(100 * time.Millisecond)
	}
	for {
		if c, err := net.Dial("tcp", h.socksAddr); err == nil {
			c.Close()
			break
		}
		if ctx.Err() != nil {
			t.Fatal("mitmdump never listened")
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("mitmdump ready after %v", time.Since(start).Round(100*time.Millisecond))
	h.session = h.connect()
	return h
}

func (h *harness) connect() *mcp.ClientSession {
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
	s, err := client.Connect(h.ctx, &mcp.CommandTransport{Command: exec.Command(h.bin, "mcp", "-mcp-sock", h.mcpSock)}, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

func (h *harness) stop() {
	if h.session != nil {
		h.session.Close()
	}
	h.run.Process.Signal(os.Interrupt)
	h.run.Wait()
	time.Sleep(500 * time.Millisecond)
	if pid := pidOn(":" + h.socksPort); pid != 0 {
		h.t.Errorf("mitmdump still listening on %s (pid %d)", h.socksPort, pid)
	}
	if exists(h.mcpSock) {
		h.t.Error("MCP socket left behind")
	}
}

// client returns an HTTP client that goes through mitmdump as the given device.
func (h *harness) client(device string) *http.Client {
	socks, err := proxy.SOCKS5("tcp", h.socksAddr, &proxy.Auth{User: device, Password: "-"}, proxy.Direct)
	if err != nil {
		h.t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(h.confdir, "mitmproxy-ca-cert.pem"))
	if err != nil {
		h.t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	return &http.Client{Transport: &http.Transport{
		DialContext:        socks.(proxy.ContextDialer).DialContext,
		TLSClientConfig:    &tls.Config{RootCAs: roots},
		DisableCompression: true, // let tests see Content-Encoding as sent
	}, Timeout: 2 * time.Minute}
}

func (h *harness) stats() map[string]any {
	var out statsOut
	h.call("capture_stats", nil, &out)
	return out.Stats
}

func (h *harness) stat(name string) int64 {
	v, _ := h.stats()[name].(float64)
	return int64(v)
}

func (h *harness) waitFlows(n int64) {
	for deadline := time.Now().Add(30 * time.Second); h.stat("flows") < n && time.Now().Before(deadline); {
		time.Sleep(200 * time.Millisecond)
	}
}

// flowFor returns the newest flow whose URL contains sub.
func (h *harness) flowFor(sub string, bodies bool) FlowView {
	h.t.Helper()
	var list listOut
	h.call("list_flows", map[string]any{"limit": 10000}, &list)
	for _, f := range list.Flows {
		if strings.Contains(f.URL, sub) {
			var v FlowView
			h.call("get_flow", map[string]any{"id": f.ID, "bodies": bodies}, &v)
			return v
		}
	}
	h.t.Fatalf("no flow for %q", sub)
	return FlowView{}
}

func (h *harness) call(name string, args any, out any) {
	h.t.Helper()
	res, err := h.session.CallTool(h.ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		h.t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		h.t.Fatalf("%s: %+v", name, res.Content)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, out); err != nil {
		h.t.Fatalf("%s: %v", name, err)
	}
}

// TestEndToEnd runs the real pipeline: `mcpflow run` → uvx mitmdump → addon →
// Unix socket → store, read by an agent through `mcpflow mcp` (stdio relay).
// Opt-in: it downloads mitmproxy with uvx and makes one request to github.com.
// REQCOVE_E2E_COLD=1 uses an empty uv cache to time a first install.
func TestEndToEnd(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	const n = 1000
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var env []string
	if os.Getenv("REQCOVE_E2E_COLD") != "" {
		// Also hide installed tools: uvx would reuse `uv tool install mitmproxy`.
		env = []string{"UV_CACHE_DIR=" + t.TempDir(), "UV_TOOL_DIR=" + t.TempDir()}
	}
	h := startHarness(t, ctx, "11180", env...)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		fmt.Fprintf(w, "ok%s", r.URL.Path)
	}))
	defer backend.Close()
	hc := h.client("test-device")
	sendStart := time.Now()
	for i := range n {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/r%d", backend.URL, i), nil)
		req.Header.Set("Authorization", "Bearer s3cret")
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	t.Logf("%d requests through mitmdump in %v", n, time.Since(sendStart).Round(10*time.Millisecond))
	resp, err := hc.Get("https://github.com/robots.txt") // decrypted with the fresh CA
	if err != nil {
		t.Fatalf("github via mitmproxy: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	h.waitFlows(n + 1)
	s := h.stats()
	t.Logf("stats: %v", s)
	if h.stat("flows") != n+1 || h.stat("addon_dropped_bodies") != 0 || h.stat("addon_dropped_events") != 0 || h.stat("orphan_updates") != 0 || h.stat("bad_lines") != 0 {
		t.Errorf("want %d flows and no drops, got %v", n+1, s)
	}
	if s["brotli_decode"] != true {
		t.Errorf("hello: brotli decoding off (%v)", s["brotli"])
	}

	gh := h.flowFor("github.com/robots.txt", false)
	if gh.Status != 200 || gh.Device != "test-device" || gh.State != "done" {
		t.Errorf("github flow = %+v", gh)
	}
	v := h.flowFor(fmt.Sprintf("/r%d", n-1), true)
	if v.RespBodyText != fmt.Sprintf("ok/r%d", n-1) || !v.RespBody.Final {
		t.Errorf("newest body = %q final=%v", v.RespBodyText, v.RespBody.Final)
	}
	cookies := 0
	for _, hd := range append(v.ReqHeaders, v.RespHeaders...) {
		switch strings.ToLower(hd[0]) {
		case "authorization", "set-cookie":
			if hd[1] != "[redacted]" {
				t.Errorf("%s not redacted: %q", hd[0], hd[1])
			}
			if strings.EqualFold(hd[0], "set-cookie") {
				cookies++
			}
		}
	}
	if cookies != 2 {
		t.Errorf("want 2 Set-Cookie headers, got %d", cookies)
	}
	t.Logf("RSS KB: run=%s mitmdump=%s", rss(h.run.Process.Pid), rss(pidOn(":11180")))

	// A new agent session sees the same flows: they live in `run`, not in the session.
	h.session.Close()
	h.session = h.connect()
	if got := h.stat("flows"); got != n+1 {
		t.Errorf("after reconnecting, flows = %d, want %d", got, n+1)
	}
}

func pidOn(port string) int {
	out, _ := exec.Command("lsof", "-t", "-iTCP"+port, "-sTCP:LISTEN").Output()
	var pid int
	fmt.Sscan(string(out), &pid)
	return pid
}

func rss(pid int) string {
	if pid == 0 {
		return "?"
	}
	out, _ := exec.Command("ps", "-o", "rss=", "-p", fmt.Sprint(pid)).Output()
	return strings.TrimSpace(string(out))
}

func rssKB(pid int) int64 {
	var kb int64
	fmt.Sscan(rss(pid), &kb)
	return kb
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// peakRSS samples the RSS of pids every 200ms until stop is called.
type peakRSS struct {
	mu   sync.Mutex
	peak map[int]int64
	done chan struct{}
}

func samplePeak(pids ...int) *peakRSS {
	p := &peakRSS{peak: map[int]int64{}, done: make(chan struct{})}
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			for _, pid := range pids {
				if kb := rssKB(pid); kb > 0 {
					p.mu.Lock()
					p.peak[pid] = max(p.peak[pid], kb)
					p.mu.Unlock()
				}
			}
			select {
			case <-p.done:
				return
			case <-t.C:
			}
		}
	}()
	return p
}

func (p *peakRSS) stop() map[int]int64 {
	close(p.done)
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peak
}

// TestTrial2 is 試し2: bodies stream through mitmproxy without being buffered,
// and both processes stay within a fixed memory budget. Opt-in; local only.
// Thresholds were written down before the first run.
func TestTrial2(t *testing.T) {
	if os.Getenv("REQCOVE_TRIAL2") == "" {
		t.Skip("set REQCOVE_TRIAL2=1")
	}
	const (
		mitmdumpMaxKB = 300 << 10
		runMaxKB      = 150 << 10
		headLimit     = 64 << 10
	)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	h := startHarness(t, ctx, "11181")
	mitmPid := pidOn(":11181")
	peak := samplePeak(mitmPid, h.run.Process.Pid)
	hc := h.client("trial-device")

	fixtures := makeFixtures(t)
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Run("big body streams and only the head is kept", func(t *testing.T) {
		const size = 200 << 20
		mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(size))
			io.Copy(w, io.LimitReader(&pattern{}, size))
		})
		resp, err := hc.Get(srv.URL + "/big")
		if err != nil {
			t.Fatal(err)
		}
		got := sha256.New()
		n, _ := io.Copy(got, resp.Body)
		resp.Body.Close()
		want := sha256.New()
		io.Copy(want, io.LimitReader(&pattern{}, size))
		if n != size || !bytes.Equal(got.Sum(nil), want.Sum(nil)) {
			t.Fatalf("client got %d bytes, checksum match=%v", n, bytes.Equal(got.Sum(nil), want.Sum(nil)))
		}
		h.waitFlows(1)
		time.Sleep(time.Second)
		v := h.flowFor("/big", false)
		if v.RespBody.Size != size || !v.RespBody.Truncated || v.State != "done" {
			t.Errorf("big flow body = %+v state=%s", v.RespBody, v.State)
		}
	})

	t.Run("compressed heads are decoded", func(t *testing.T) {
		for _, fx := range fixtures {
			mux.HandleFunc("/enc/"+fx.name, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", fx.encoding)
				w.Write(fx.data)
			})
			resp, err := hc.Get(srv.URL + "/enc/" + fx.name)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !bytes.Equal(raw, fx.data) {
				t.Errorf("%s: client got altered bytes (%d vs %d)", fx.name, len(raw), len(fx.data))
			}
			time.Sleep(500 * time.Millisecond)
			v := h.flowFor("/enc/"+fx.name, false)
			head := h.flowFor("/enc/"+fx.name, true).RespBodyText
			if !v.RespBody.Decoded || len(head) > headLimit || !strings.HasPrefix(fx.plain, head) || len(head) < min(len(fx.plain), headLimit) {
				t.Errorf("%s: decoded=%v head=%d bytes note=%q", fx.name, v.RespBody.Decoded, len(head), v.RespBody.Note)
			}
		}
	})

	t.Run("decompression bombs stay bounded", func(t *testing.T) {
		for _, fx := range bombs(t) {
			mux.HandleFunc("/bomb/"+fx.name, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", fx.encoding)
				w.Write(fx.data)
			})
			resp, err := hc.Get(srv.URL + "/bomb/" + fx.name)
			if err != nil {
				t.Fatal(err)
			}
			n, _ := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if n != int64(len(fx.data)) {
				t.Errorf("%s: client got %d of %d compressed bytes", fx.name, n, len(fx.data))
			}
			time.Sleep(500 * time.Millisecond)
			v := h.flowFor("/bomb/"+fx.name, false)
			if !v.RespBody.Truncated || !v.RespBody.Decoded {
				t.Errorf("%s: body = %+v", fx.name, v.RespBody)
			}
		}
	})

	t.Run("SSE head is visible while the stream is open", func(t *testing.T) {
		mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			for i := 0; ; i++ {
				if _, err := fmt.Fprintf(w, "data: tick %d\n\n", i); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(200 * time.Millisecond):
				}
			}
		})
		rctx, rcancel := context.WithCancel(ctx)
		defer rcancel()
		req, _ := http.NewRequestWithContext(rctx, "GET", srv.URL+"/sse", nil)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		go io.Copy(io.Discard, resp.Body)
		time.Sleep(2500 * time.Millisecond)
		v := h.flowFor("/sse", true)
		if v.State != "open" || v.Status != 200 || !strings.Contains(v.RespBodyText, "data: tick 0") {
			t.Errorf("SSE while open: state=%s status=%d head=%q", v.State, v.Status, v.RespBodyText)
		}
		rcancel()
		resp.Body.Close()
	})

	t.Run("endless upload flows without stream_large_bodies", func(t *testing.T) {
		received := make(chan int64, 1)
		mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
			n, _ := io.Copy(io.Discard, r.Body)
			received <- n
		})
		pr, pw := io.Pipe()
		go func() {
			for range 30 {
				pw.Write(bytes.Repeat([]byte("u"), 1024))
				time.Sleep(100 * time.Millisecond)
			}
			pw.Close()
		}()
		go func() {
			req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/upload", pr)
			if resp, err := hc.Do(req); err == nil {
				resp.Body.Close()
			}
		}()
		time.Sleep(1500 * time.Millisecond)
		v := h.flowFor("/upload", true)
		if v.State != "open" || !strings.HasPrefix(v.ReqBodyText, "uuu") {
			t.Errorf("upload while open: state=%s head=%d bytes", v.State, len(v.ReqBodyText))
		}
		select {
		case n := <-received:
			if n != 30*1024 {
				t.Errorf("server received %d bytes, want %d", n, 30*1024)
			}
		case <-time.After(30 * time.Second):
			t.Error("upload never reached the server")
		}
	})

	t.Run("long WebSocket does not accumulate in mitmproxy", func(t *testing.T) {
		mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) { io.Copy(ws, ws) }))
		before := rssKB(mitmPid)
		dial := h.client("trial-device").Transport.(*http.Transport).DialContext
		raw, err := dial(ctx, "tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		cfg, _ := websocket.NewConfig("ws://"+srv.Listener.Addr().String()+"/ws", srv.URL)
		ws, err := websocket.NewClient(cfg, raw)
		if err != nil {
			t.Fatal(err)
		}
		msg := bytes.Repeat([]byte("w"), 64<<10)
		buf := make([]byte, len(msg))
		for range 2000 { // 128 MiB each way
			if err := websocket.Message.Send(ws, msg); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(ws, buf); err != nil {
				t.Fatal(err)
			}
		}
		after := rssKB(mitmPid)
		ws.Close()
		t.Logf("mitmdump RSS before/after 256 MiB of WebSocket: %d/%d KB", before, after)
		if after-before > 64<<10 {
			t.Errorf("mitmdump grew by %d KB over the WebSocket", after-before)
		}
	})

	t.Run("a stalled reqcove does not stall the proxy", func(t *testing.T) {
		mux.HandleFunc("/stall", func(w http.ResponseWriter, r *http.Request) {
			w.Write(bytes.Repeat([]byte("s"), 1<<20))
		})
		dropped := h.stat("addon_dropped_bodies")
		syscall.Kill(h.run.Process.Pid, syscall.SIGSTOP) // reqcove stops reading its socket
		start := time.Now()
		for i := range 300 {
			resp, err := hc.Get(fmt.Sprintf("%s/stall?i=%d", srv.URL, i))
			if err != nil {
				syscall.Kill(h.run.Process.Pid, syscall.SIGCONT)
				t.Fatalf("request %d while reqcove was stopped: %v", i, err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		took := time.Since(start)
		syscall.Kill(h.run.Process.Pid, syscall.SIGCONT)
		time.Sleep(3 * time.Second)
		t.Logf("300 x 1 MiB while reqcove was stopped: %v; addon dropped bodies %d -> %d", took.Round(10*time.Millisecond), dropped, h.stat("addon_dropped_bodies"))
		if took > 60*time.Second {
			t.Errorf("proxying slowed to %v while reqcove was stopped", took)
		}
	})

	peaks := peak.stop()
	t.Logf("peak RSS KB: mitmdump=%d run=%d; stats=%v", peaks[mitmPid], peaks[h.run.Process.Pid], h.stats())
	if peaks[mitmPid] > mitmdumpMaxKB || peaks[h.run.Process.Pid] > runMaxKB {
		t.Errorf("peak RSS over budget: mitmdump %d KB (max %d), run %d KB (max %d)",
			peaks[mitmPid], mitmdumpMaxKB, peaks[h.run.Process.Pid], runMaxKB)
	}
}

// pattern is an endless, cheap byte stream; byte n is the same however it is read.
type pattern struct{ off int }

func (r *pattern) Read(p []byte) (int, error) {
	for i := range p {
		n := r.off + i
		p[i] = byte(n*7 + n>>8)
	}
	r.off += len(p)
	return len(p), nil
}

type fixture struct {
	name, encoding, plain string
	data                  []byte
}

// makeFixtures compresses the same text with gzip (Go), br and zstd (Python
// from uv, with the brotli that mitmproxy 12.3.1 pins).
func makeFixtures(t *testing.T) []fixture {
	t.Helper()
	plain := strings.Repeat("reqcove decodes this head. ", 10000) // ~270 KB, over the head limit
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(plain))
	zw.Close()
	fx := []fixture{{"gzip", "gzip", plain, gz.Bytes()}}
	for _, enc := range []string{"br", "zstd"} {
		fx = append(fx, fixture{enc, enc, plain, pyCompress(t, enc, "data = ('reqcove decodes this head. ' * 10000).encode()")})
	}
	return fx
}

// bombs are small bodies that decode to 512 MiB.
func bombs(t *testing.T) []fixture {
	t.Helper()
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	zero := make([]byte, 1<<20)
	for range 512 {
		zw.Write(zero)
	}
	zw.Close()
	fx := []fixture{{"gzip", "gzip", "", gz.Bytes()}}
	for _, enc := range []string{"br", "zstd"} {
		fx = append(fx, fixture{enc, enc, "", pyCompress(t, enc, "data = bytes(512 << 20)")})
	}
	for _, f := range fx {
		t.Logf("%s bomb: %d compressed bytes -> 512 MiB", f.name, len(f.data))
	}
	return fx
}

func pyCompress(t *testing.T, enc, makeData string) []byte {
	t.Helper()
	code := makeData + "\nimport sys\n"
	if enc == "br" {
		code += "import brotli\nsys.stdout.buffer.write(brotli.compress(data, quality=5))\n"
	} else {
		code += "from compression import zstd\nsys.stdout.buffer.write(zstd.compress(data))\n"
	}
	out, err := exec.Command("uv", "run", "--no-project", "--python", "3.14", "--with", "brotli==1.2.1", "python", "-c", code).Output()
	if err != nil {
		t.Fatalf("making %s fixture: %v", enc, err)
	}
	return out
}
