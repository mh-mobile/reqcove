package mcpserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Proxy serves New's tools on t (the agent's stdio, for `reqcove mcp`) and
// forwards each call to the `run` serving the socket at sock, dialling it when
// needed. The agent stays connected while `run` restarts or is not running:
// a call then answers notRunning, as a tool error.
func Proxy(ctx context.Context, sock, notRunning string, t mcp.Transport) error {
	tools, err := toolList(ctx)
	if err != nil {
		return err
	}
	p := &proxy{sock: sock, notRunning: notRunning, client: mcp.NewClient(&mcp.Implementation{Name: "reqcove-mcp", Version: Version}, nil)}
	defer p.close()
	s := mcp.NewServer(&mcp.Implementation{Name: "reqcove", Version: Version}, nil)
	for _, tool := range tools {
		// This process outlives `run`s of other versions: their answers are not
		// checked against this one's output schemas.
		tool.OutputSchema = nil
		s.AddTool(tool, p.call)
	}
	return s.Run(ctx, t)
}

// toolList is New's tools as an agent sees them, status included.
func toolList(ctx context.Context) ([]*mcp.Tool, error) {
	ct, st := mcp.NewInMemoryTransports()
	ss, err := New(capture.NewStore(1, 1), func() StatusOut { return StatusOut{} }).Connect(ctx, st, nil)
	if err != nil {
		return nil, err
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "reqcove-mcp", Version: Version}, nil).Connect(ctx, ct, nil)
	if err != nil {
		return nil, err
	}
	defer cs.Close()
	var tools []*mcp.Tool
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		tools = append(tools, tool)
	}
	return tools, nil
}

type proxy struct {
	sock, notRunning string
	client           *mcp.Client
	mu               sync.Mutex // held while dialling: concurrent calls share one session
	cs               *mcp.ClientSession
	dials            atomic.Int32 // for the tests
}

// session returns the kept session to `run`, or dials it when there is none or
// the kept one is failed, the one a call just failed on (another call may have
// dialled again already).
func (p *proxy) session(ctx context.Context, failed *mcp.ClientSession) (*mcp.ClientSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cs != nil && p.cs != failed {
		return p.cs, nil
	}
	if p.cs != nil {
		p.cs.Close()
		p.cs = nil
	}
	p.dials.Add(1)
	c, err := net.Dial("unix", p.sock)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second) // a `run` stuck in the handshake does not hold the lock
	defer cancel()
	cs, err := p.client.Connect(ctx, &mcp.IOTransport{Reader: c, Writer: c}, nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	p.cs = cs
	return cs, nil
}

func (p *proxy) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cs != nil {
		p.cs.Close()
	}
}

// call forwards one tool call. A connection that failed (`run` restarted) is
// dialled again and the call sent once more: every tool is read-only. `run`'s
// own answers, errors included, go back as they are.
func (p *proxy) call(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	params := &mcp.CallToolParams{Name: req.Params.Name}
	if len(req.Params.Arguments) > 0 { // not a null for no arguments
		params.Arguments = req.Params.Arguments
	}
	var cs *mcp.ClientSession
	for try := 0; ; try++ {
		var err error
		if cs, err = p.session(ctx, cs); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return p.down(), nil
		}
		res, err := cs.CallTool(ctx, params)
		var rpc *jsonrpc.Error
		switch {
		case err == nil:
			// Only what the tool answered: not the session's own fields.
			return &mcp.CallToolResult{Content: res.Content, StructuredContent: res.StructuredContent, IsError: res.IsError}, nil
		case ctx.Err() != nil, errors.As(err, &rpc):
			return nil, err // cancelled by the agent, or `run`'s own answer (an unknown tool, say)
		case try == 1:
			return p.down(), nil
		}
	}
}

// down is the tool error while `run` is not there.
func (p *proxy) down() *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: p.notRunning}}}
}
