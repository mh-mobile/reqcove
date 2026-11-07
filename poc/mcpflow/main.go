// Command mcpflow tries the MCP-in-Go design.
//
//	mcpflow run -confdir DIR   starts mitmproxy (mitmdump, SOCKS5 mode) through uvx
//	                           with an embedded addon, keeps the flows it sends over
//	                           a Unix socket, and serves MCP on another Unix socket.
//	                           Runs until Ctrl-C.
//	mcpflow mcp                is what an agent launches: it relays MCP between its
//	                           stdio and the running `run`.
//	mcpflow stdio -confdir DIR does both in one process (test 1).
//
// In mcp and stdio, stdout carries MCP; logs go to stderr or the child's log file.
package main

import (
	"bufio"
	"context"
	_ "embed"
	"flag"
	"io"
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
	flags     = flag.NewFlagSet("mcpflow", flag.ExitOnError)
	confdir   = flags.String("confdir", "", "mitmproxy confdir (CA lives here); required for run and stdio")
	socksPort = flags.String("socks-port", "11080", "mitmproxy SOCKS5 port on 127.0.0.1")
	mitmSpec  = flags.String("mitmproxy", "mitmproxy==12.3.1", "uvx --from spec for mitmproxy")
	uvx       = flags.String("uvx", "uvx", "path to uvx")
	maxFlows  = flags.Int("max-flows", 10000, "flows kept in memory")
	mcpSock   = flags.String("mcp-sock", defaultMCPSock(), "Unix socket where run serves MCP")
)

func defaultMCPSock() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".reqcove-poc", "mcp.sock")
}

func main() {
	log.SetOutput(os.Stderr)
	if len(os.Args) < 2 {
		log.Fatal("usage: mcpflow run|mcp|stdio [flags]")
	}
	cmd := os.Args[1]
	flags.Parse(os.Args[2:])
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch cmd {
	case "mcp":
		relay(ctx)
		return
	case "run", "stdio":
	default:
		log.Fatalf("unknown command %q", cmd)
	}
	if *confdir == "" {
		log.Fatal("-confdir is required")
	}

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
	if cmd == "stdio" {
		if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
			log.Print(err)
		}
		return
	}
	if err := serveMCP(ctx, server); err != nil {
		log.Print(err)
	}
}

// serveMCP accepts agents (via `mcpflow mcp`) on the MCP socket until ctx ends.
// Only this user can connect: the socket's directory is 0700.
func serveMCP(ctx context.Context, server *mcp.Server) error {
	if err := os.MkdirAll(filepath.Dir(*mcpSock), 0o700); err != nil {
		return err
	}
	os.Remove(*mcpSock) // a stale socket from a run that was killed
	ln, err := net.Listen("unix", *mcpSock)
	if err != nil {
		return err
	}
	defer os.Remove(*mcpSock)
	go func() { <-ctx.Done(); ln.Close() }()
	log.Printf("serving MCP on %s; flows via SOCKS5 127.0.0.1:%s", *mcpSock, *socksPort)
	for {
		c, err := ln.Accept()
		if err != nil {
			return nil
		}
		go func() {
			ss, err := server.Connect(ctx, &mcp.IOTransport{Reader: c, Writer: c}, nil)
			if err != nil {
				log.Print(err)
				c.Close()
				return
			}
			ss.Wait()
		}()
	}
}

// relay connects the agent's stdio to the running `run`.
func relay(ctx context.Context) {
	c, err := net.Dial("unix", *mcpSock)
	if err != nil {
		log.Fatalf("is `mcpflow run` running? %v", err)
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(c, os.Stdin); c.(*net.UnixConn).CloseWrite(); done <- struct{}{} }()
	go func() { io.Copy(os.Stdout, c); done <- struct{}{} }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	c.Close()
}

func startMitmproxy(dir, sock, addon string) (*exec.Cmd, error) {
	logf, err := os.Create(filepath.Join(dir, "mitmdump.log"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(*uvx, "--from", *mitmSpec, "mitmdump",
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
