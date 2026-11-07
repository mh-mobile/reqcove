// Command mcpflow is test 1 of the MCP-in-Go design: it starts mitmproxy
// (mitmdump, SOCKS5 mode) through uvx with an embedded addon, receives flows
// over a Unix socket, and serves them to an agent as MCP tools over stdio.
//
// stdout carries MCP; everything else goes to stderr or the child's log file.
package main

import (
	"bufio"
	"context"
	_ "embed"
	"flag"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed addon.py
var addonPy []byte

var (
	confdir   = flag.String("confdir", "", "mitmproxy confdir (CA lives here); required")
	socksPort = flag.String("socks-port", "11080", "mitmproxy SOCKS5 port on 127.0.0.1")
	mitmSpec  = flag.String("mitmproxy", "mitmproxy==12.3.1", "uvx --from spec for mitmproxy")
	maxFlows  = flag.Int("max-flows", 10000, "flows kept in memory")
)

func main() {
	flag.Parse()
	log.SetOutput(os.Stderr)
	if *confdir == "" {
		log.Fatal("-confdir is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// macOS caps Unix socket paths at 104 bytes, so stay short and under /tmp.
	dir, err := os.MkdirTemp("/tmp", "rcv-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	addon := filepath.Join(dir, "addon.py")
	if err := os.WriteFile(addon, addonPy, 0o600); err != nil {
		log.Fatal(err)
	}

	st := newStore(*maxFlows)
	go accept(ln, st)

	child, err := startMitmproxy(dir, sock, addon)
	if err != nil {
		log.Fatal(err)
	}
	defer stopGroup(child)

	server := mcp.NewServer(&mcp.Implementation{Name: "reqcove", Version: "poc"}, nil)
	addTools(server, st)
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		log.Print(err)
	}
}

func startMitmproxy(dir, sock, addon string) (*exec.Cmd, error) {
	logf, err := os.Create(filepath.Join(dir, "mitmdump.log"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("uvx", "--from", *mitmSpec, "mitmdump",
		"--mode", "socks5", "--listen-host", "127.0.0.1", "--listen-port", *socksPort,
		"--set", "confdir="+*confdir,
		"--set", "proxyauth=any",
		"--set", "stream_large_bodies=1", "--set", "store_streamed_bodies=true",
		"-s", addon, "--set", "reqcove_socket="+sock)
	cmd.Stdout, cmd.Stderr = logf, logf // never onto our stdout: that is the MCP stream
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	log.Printf("mitmdump via uvx (pid %d), log %s", cmd.Process.Pid, logf.Name())
	return cmd, nil
}

// stopGroup ends uvx and the mitmdump under it.
func stopGroup(cmd *exec.Cmd) {
	syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	cmd.Wait()
}

func accept(ln net.Listener, st *store) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			r := bufio.NewReaderSize(c, 1<<16)
			for {
				line, err := r.ReadBytes('\n') // no line limit: bodies are inline
				if len(line) > 0 {
					st.apply(line)
				}
				if err != nil {
					return
				}
			}
		}()
	}
}

type listIn struct {
	Device string `json:"device,omitempty" jsonschema:"device name to filter by"`
	Host   string `json:"host,omitempty" jsonschema:"substring of the host to filter by"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max flows to return, newest first (default 50)"`
}
type listOut struct {
	Flows []Summary `json:"flows"`
}
type getIn struct {
	ID     string `json:"id" jsonschema:"flow id from list_flows"`
	Bodies bool   `json:"bodies,omitempty" jsonschema:"include request and response bodies"`
}
type statsOut struct {
	Stats map[string]int64 `json:"stats"`
}

func addTools(s *mcp.Server, st *store) {
	mcp.AddTool(s, &mcp.Tool{Name: "list_flows", Description: "List captured HTTP flows, newest first."},
		func(_ context.Context, _ *mcp.CallToolRequest, in listIn) (*mcp.CallToolResult, listOut, error) {
			if in.Limit <= 0 {
				in.Limit = 50
			}
			return nil, listOut{Flows: st.list(in.Device, in.Host, in.Limit)}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "get_flow", Description: "Get one flow. Authorization and cookie headers are masked."},
		func(_ context.Context, _ *mcp.CallToolRequest, in getIn) (*mcp.CallToolResult, FlowView, error) {
			v, err := st.get(in.ID, in.Bodies)
			return nil, v, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "capture_stats", Description: "Counts of stored flows and of events dropped or rejected."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, statsOut, error) {
			return nil, statsOut{Stats: st.stats()}, nil
		})
}
