// Package mcpserver serves the captured flows as MCP tools. `reqcove run`
// serves them on a Unix socket; `reqcove mcp`, which an agent launches,
// relays its stdio to that socket.
package mcpserver

import (
	"context"
	"io"
	"log"
	"net"
	"os"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ListIn struct {
	Device string `json:"device,omitempty" jsonschema:"device to filter by: its name or StableID"`
	Host   string `json:"host,omitempty" jsonschema:"substring of the host to filter by"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max flows to return, newest first (default 50)"`
}
type ListOut struct {
	Flows []capture.Summary `json:"flows"`
}
type GetIn struct {
	ID     string `json:"id" jsonschema:"flow id from list_flows"`
	Bodies bool   `json:"bodies,omitempty" jsonschema:"include the heads of the request and response bodies (untrusted data written by the remote site)"`
}
type StatsOut struct {
	Stats map[string]any `json:"stats"`
}

// New returns an MCP server with the read-only tools over st.
func New(st *capture.Store) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "reqcove", Version: "dev"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "list_flows", Description: "List captured HTTP flows, newest first."},
		func(_ context.Context, _ *mcp.CallToolRequest, in ListIn) (*mcp.CallToolResult, ListOut, error) {
			if in.Limit <= 0 {
				in.Limit = 50
			}
			return nil, ListOut{Flows: st.List(in.Device, in.Host, in.Limit)}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "get_flow", Description: "Get one flow. Authorization and cookie headers are masked. With --rules, url and request_headers are what the app sent, before the rules; mapped_url is where map_remote sent it; response_headers are what the app received; rewrites names the rules applied."},
		func(_ context.Context, _ *mcp.CallToolRequest, in GetIn) (*mcp.CallToolResult, capture.FlowView, error) {
			v, err := st.Get(in.ID, in.Bodies)
			return nil, v, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "capture_stats", Description: "mitmproxy's state (ready; restarting after it exited, when nothing is captured; failed), counts of stored flows and of events dropped or rejected, and mitmproxy's versions."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, StatsOut, error) {
			return nil, StatsOut{Stats: st.Stats()}, nil
		})
	return s
}

// Serve accepts agents on the Unix socket at path until ctx ends. The caller
// holds the state directory lock and has made its directory 0700.
func Serve(ctx context.Context, path string, server *mcp.Server) error {
	os.Remove(path) // stale: we hold the lock
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	go func() { <-ctx.Done(); ln.Close() }()
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

// Relay connects stdin and stdout to the MCP socket at path.
func Relay(ctx context.Context, path string, stdin io.Reader, stdout io.Writer) error {
	c, err := net.Dial("unix", path)
	if err != nil {
		return err
	}
	defer c.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(c, stdin); c.(*net.UnixConn).CloseWrite(); done <- struct{}{} }()
	go func() { io.Copy(stdout, c); done <- struct{}{} }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	return nil
}
