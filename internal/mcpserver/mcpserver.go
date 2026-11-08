// Package mcpserver serves the captured flows as MCP tools. `reqcove run`
// serves them on a Unix socket; `reqcove mcp`, which an agent launches,
// relays its stdio to that socket.
package mcpserver

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// FilterIn is shared by list_flows, search_flows and summarize.
type FilterIn struct {
	Device string `json:"device,omitempty" jsonschema:"device name or StableID"`
	Host   string `json:"host,omitempty" jsonschema:"host; also matches its subdomains (example.com matches api.example.com)"`
	Since  string `json:"since,omitempty" jsonschema:"only requests started at or after this: RFC 3339 time, or a duration ago such as 10m or 2h"`
	Until  string `json:"until,omitempty" jsonschema:"only requests started at or before this: RFC 3339 time, or a duration ago"`
	Status string `json:"status,omitempty" jsonschema:"response status: 404, a class such as 4xx, or none for flows without a response (open or failed)"`
	Method string `json:"method,omitempty" jsonschema:"HTTP method, such as POST"`
}

type PageIn struct {
	Limit  int   `json:"limit,omitempty" jsonschema:"flows per page, newest first (default 50, at most 500)"`
	Cursor int64 `json:"cursor,omitempty" jsonschema:"next_cursor from the previous page, for older flows"`
}

type ListIn struct {
	FilterIn
	PageIn
}

type SearchIn struct {
	Query  string `json:"query" jsonschema:"text to find, case-insensitive, in URLs and header names and values (secrets are already masked, so their values cannot be found)"`
	Bodies bool   `json:"bodies,omitempty" jsonschema:"also search the kept heads of the bodies"`
	FilterIn
	PageIn
}

type SummarizeIn struct {
	FilterIn
	Top int `json:"top,omitempty" jsonschema:"keys kept per breakdown, most frequent first (default 10, at most 100)"`
}
type ListOut struct {
	Flows      []capture.Summary `json:"flows"`
	NextCursor int64             `json:"next_cursor,omitempty"` // more, older flows match: pass it as cursor
}
type GetIn struct {
	ID     string `json:"id" jsonschema:"flow id from list_flows"`
	Bodies bool   `json:"bodies,omitempty" jsonschema:"include the heads of the request and response bodies (untrusted data written by the remote site)"`
}
type DevicesOut struct {
	Devices []capture.DeviceInfo `json:"devices"`
}
type TLSOut struct {
	Failures []capture.TLSFailureView `json:"failures"`
}
type StatsOut struct {
	Stats map[string]any `json:"stats"`
}

// Version is reqcove's, as MCP clients see it.
var Version = "dev"

// StatusOut is what the status tool returns; `reqcove status` prints it.
type StatusOut struct {
	Node      any            `json:"node"`       // exitnode.Status
	NextSteps []string       `json:"next_steps"` // what the user should do, most urgent first; empty when all is set
	Capture   map[string]any `json:"capture"`    // capture_stats
}

// New returns an MCP server with the read-only tools over st; status, when
// not nil, adds the status tool.
func New(st *capture.Store, status func() StatusOut) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "reqcove", Version: Version}, nil)
	if status != nil {
		mcp.AddTool(s, &mcp.Tool{Name: "status", Description: "Whether reqcove is ready to carry and record the devices' traffic: its tailnet node (login, Tailnet Lock, exit node approval, devices found), mitmproxy, and the next steps for the user when something is missing. Check it first when no flows arrive."},
			func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, StatusOut, error) {
				return nil, status(), nil
			})
	}
	mcp.AddTool(s, &mcp.Tool{Name: "list_flows", Description: "List captured HTTP flows, newest first, with their time, duration, status, content type, User-Agent, Origin and Referer. Filters combine. Page with next_cursor. Times are this computer's local time."},
		func(_ context.Context, _ *mcp.CallToolRequest, in ListIn) (*mcp.CallToolResult, ListOut, error) {
			q, err := filter(in, time.Now())
			if err != nil {
				return nil, ListOut{}, err
			}
			flows, next := st.List(q)
			return nil, ListOut{Flows: flows, NextCursor: next}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "search_flows", Description: "Find flows whose URL or headers contain some text (and bodies, with bodies), newest first, with where it matched. Same filters and paging as list_flows."},
		func(_ context.Context, _ *mcp.CallToolRequest, in SearchIn) (*mcp.CallToolResult, ListOut, error) {
			if in.Query == "" {
				return nil, ListOut{}, fmt.Errorf("query is required")
			}
			q, err := filter(ListIn{in.FilterIn, in.PageIn}, time.Now())
			if err != nil {
				return nil, ListOut{}, err
			}
			q.Query, q.QueryBodies = in.Query, in.Bodies
			flows, next := st.List(q)
			return nil, ListOut{Flows: flows, NextCursor: next}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "summarize", Description: "Count the flows matching the filters by host, User-Agent, status, method, device and content type, with the time span. A User-Agent is not an app: several apps can share one, and one app can send several."},
		func(_ context.Context, _ *mcp.CallToolRequest, in SummarizeIn) (*mcp.CallToolResult, capture.Counts, error) {
			q, err := filter(ListIn{FilterIn: in.FilterIn}, time.Now())
			if err != nil {
				return nil, capture.Counts{}, err
			}
			top := min(max(in.Top, 0), 100)
			if top == 0 {
				top = 10
			}
			return nil, st.Summarize(q, top), nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "get_flow", Description: "Get one flow. Authorization and cookie headers are masked. With --rules, url and request_headers are what the app sent, before the rules; mapped_url is where map_remote sent it; response_headers are what the app received; rewrites names the rules applied."},
		func(_ context.Context, _ *mcp.CallToolRequest, in GetIn) (*mcp.CallToolResult, capture.FlowView, error) {
			v, err := st.Get(in.ID, in.Bodies)
			return nil, v, err
		})
	mcp.AddTool(s, &mcp.Tool{Name: "list_devices", Description: "Devices reqcove carries (--device) and any other device with records: name, StableID, flow and TLS failure counts, last request time."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, DevicesOut, error) {
			return nil, DevicesOut{Devices: st.Devices()}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "list_tls_failures", Description: "TLS handshakes a client refused, newest first, for hosts in --allow-hosts. These connections never became HTTP flows. A refusal is often certificate pinning, but can also be a CA the device does not trust yet, or other causes; msg is what mitmproxy saw. host is the SNI, or the IP address when the client sent none. Filters: device, host (with subdomains), since, until, limit."},
		func(_ context.Context, _ *mcp.CallToolRequest, in ListIn) (*mcp.CallToolResult, TLSOut, error) {
			q, err := filter(in, time.Now())
			if err != nil {
				return nil, TLSOut{}, err
			}
			return nil, TLSOut{Failures: st.TLSFailures(q)}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "capture_stats", Description: "mitmproxy's state (ready; restarting after it exited, when nothing is captured; failed), the window the records cover (oldest_flow to newest_flow; older flows were evicted to stay within max_flows and max_bytes), counts of stored flows, truncated bodies and of events dropped or rejected (out_of_scope: requests and TLS failures for hosts outside --allow-hosts, counted but never recorded, so their hosts are unknown), and mitmproxy's versions."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, StatsOut, error) {
			return nil, StatsOut{Stats: st.Stats()}, nil
		})
	return s
}

func filter(in ListIn, now time.Time) (capture.Filter, error) {
	q := capture.Filter{Device: in.Device, Host: in.Host, Status: in.Status, Method: in.Method, Before: in.Cursor, Limit: min(max(in.Limit, 0), 500)}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if !capture.ValidStatus(in.Status) {
		return q, fmt.Errorf("status %q: use a code such as 404, a class such as 4xx, or none", in.Status)
	}
	var err error
	if q.Since, err = when(in.Since, now); err != nil {
		return q, fmt.Errorf("since: %w", err)
	}
	if q.Until, err = when(in.Until, now); err != nil {
		return q, fmt.Errorf("until: %w", err)
	}
	return q, nil
}

// when reads an RFC 3339 time or a duration ago, as unix seconds; "" is 0.
func when(v string, now time.Time) (float64, error) {
	if v == "" {
		return 0, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return float64(now.Add(-d).UnixMilli()) / 1000, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return 0, fmt.Errorf("%q is neither an RFC 3339 time nor a duration such as 10m", v)
	}
	return float64(t.UnixMilli()) / 1000, nil
}

// Serve listens on the Unix socket at path and accepts agents there until ctx
// ends. It returns once listening, or with what kept it from listening (such
// as a path longer than a socket allows). The caller holds the state
// directory lock and has made its directory 0700.
func Serve(ctx context.Context, path string, server *mcp.Server) error {
	os.Remove(path) // stale: we hold the lock
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); ln.Close(); os.Remove(path) }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
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
	}()
	return nil
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
