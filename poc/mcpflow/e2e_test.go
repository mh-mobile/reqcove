package main

import (
	"context"
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
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/proxy"
)

// TestEndToEnd runs the real pipeline: `mcpflow run` → uvx mitmdump → addon →
// Unix socket → store, read by an agent through `mcpflow mcp` (stdio relay).
// It reconnects once to check that flows outlive an agent session.
// Opt-in: it downloads mitmproxy with uvx, opens port 11080 and makes one
// request to github.com.
// REQCOVE_E2E_COLD=1 also uses an empty uv cache to time a first install.
func TestEndToEnd(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	const n = 1000
	const socksAddr = "127.0.0.1:11080"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	bin := filepath.Join(t.TempDir(), "mcpflow")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	confdir := t.TempDir()
	sockDir, err := os.MkdirTemp("/tmp", "rcvt-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	mcpSock := filepath.Join(sockDir, "mcp.sock")
	run := exec.Command(bin, "run", "-confdir", confdir, "-socks-port", "11080", "-mcp-sock", mcpSock)
	run.Stderr = os.Stderr
	if os.Getenv("REQCOVE_E2E_COLD") != "" {
		// Also hide installed tools: uvx would reuse `uv tool install mitmproxy`.
		run.Env = append(os.Environ(), "UV_CACHE_DIR="+t.TempDir(), "UV_TOOL_DIR="+t.TempDir())
	}
	start := time.Now()
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		run.Process.Signal(os.Interrupt)
		run.Wait()
		time.Sleep(500 * time.Millisecond)
		if pid := pidOn(":11080"); pid != 0 {
			t.Errorf("mitmdump still listening on 11080 (pid %d)", pid)
		}
		if _, err := os.Stat(mcpSock); err == nil {
			t.Error("MCP socket left behind")
		}
	}()
	for {
		if _, err := os.Stat(mcpSock); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("run never served MCP")
		}
		time.Sleep(100 * time.Millisecond)
	}
	connect := func() *mcp.ClientSession {
		client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
		s, err := client.Connect(ctx, &mcp.CommandTransport{Command: exec.Command(bin, "mcp", "-mcp-sock", mcpSock)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	session := connect()
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tools: %d", len(tools.Tools))

	for {
		if c, err := net.Dial("tcp", socksAddr); err == nil {
			c.Close()
			break
		}
		if ctx.Err() != nil {
			t.Fatal("mitmdump never listened")
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("mitmdump ready after %v", time.Since(start).Round(100*time.Millisecond))

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		fmt.Fprintf(w, "ok%s", r.URL.Path)
	}))
	defer backend.Close()

	socks, err := proxy.SOCKS5("tcp", socksAddr, &proxy.Auth{User: "test-device", Password: "-"}, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(confdir, "mitmproxy-ca-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	hc := &http.Client{Transport: &http.Transport{
		DialContext:     socks.(proxy.ContextDialer).DialContext,
		TLSClientConfig: &tls.Config{RootCAs: roots},
	}, Timeout: 20 * time.Second}

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

	var stats statsOut
	for deadline := time.Now().Add(30 * time.Second); ; {
		call(t, ctx, session, "capture_stats", nil, &stats)
		if stats.Stats["flows"] >= n+1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("stats: %v", stats.Stats)
	if stats.Stats["flows"] != n+1 || stats.Stats["addon_dropped"] != 0 || stats.Stats["bad_lines"] != 0 || stats.Stats["orphan_updates"] != 0 {
		t.Errorf("want %d flows and no drops, got %v", n+1, stats.Stats)
	}

	var list listOut
	call(t, ctx, session, "list_flows", map[string]any{"device": "test-device", "host": "127.0.0.1", "limit": 3}, &list)
	if len(list.Flows) != 3 || list.Flows[0].Status != 200 {
		t.Fatalf("list_flows = %+v", list.Flows)
	}
	var gh listOut
	call(t, ctx, session, "list_flows", map[string]any{"host": "github.com"}, &gh)
	if len(gh.Flows) != 1 || gh.Flows[0].Status != 200 || gh.Flows[0].Device != "test-device" {
		t.Errorf("github flow = %+v", gh.Flows)
	}

	var v FlowView
	call(t, ctx, session, "get_flow", map[string]any{"id": list.Flows[0].ID, "bodies": true}, &v)
	if v.RespBody != fmt.Sprintf("ok/r%d", n-1) {
		t.Errorf("newest body = %q", v.RespBody)
	}
	cookies := 0
	for _, h := range append(v.ReqHeaders, v.RespHeaders...) {
		switch strings.ToLower(h[0]) {
		case "authorization", "set-cookie":
			if h[1] != "[redacted]" {
				t.Errorf("%s not redacted: %q", h[0], h[1])
			}
			if strings.EqualFold(h[0], "set-cookie") {
				cookies++
			}
		}
	}
	if cookies != 2 {
		t.Errorf("want 2 Set-Cookie headers, got %d", cookies)
	}

	t.Logf("RSS KB: run=%s mitmdump=%s", rss(run.Process.Pid), rss(pidOn(":11080")))
	if err := session.Close(); err != nil {
		t.Log(err)
	}

	// A new agent session sees the same flows: they live in `run`, not in the session.
	session = connect()
	defer session.Close()
	var again statsOut
	call(t, ctx, session, "capture_stats", nil, &again)
	if again.Stats["flows"] != n+1 {
		t.Errorf("after reconnecting, flows = %d, want %d", again.Stats["flows"], n+1)
	}
}

func call(t *testing.T, ctx context.Context, s *mcp.ClientSession, name string, args any, out any) {
	t.Helper()
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("%s: %+v", name, res.Content)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// pidOn returns the pid listening on a TCP port (lsof prints pids only, no arguments).
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
