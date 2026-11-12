package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
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
	p := &proxy{sock: sock, notRunning: notRunning, ctx: ctx, client: mcp.NewClient(&mcp.Implementation{Name: "reqcove-mcp", Version: Version}, nil)}
	defer p.close()
	s := mcp.NewServer(&mcp.Implementation{Name: "reqcove", Version: Version}, &mcp.ServerOptions{Instructions: Instructions})
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
	srv := New(capture.NewStore(1, 1), func() StatusOut { return StatusOut{} })
	AddPresetTools(srv, capture.NewStore(1, 1), noPresets{})
	ss, err := srv.Connect(ctx, st, nil)
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
	ctx              context.Context // Proxy's: ending it ends the calls in flight

	mu       sync.Mutex // held while dialling: concurrent calls share one session
	cs       *mcp.ClientSession
	note     string    // said once, with the first answer of a new session: a restart, another version
	failedAt time.Time // the last dial that failed: calls soon after it do not wait again
	dials    atomic.Int32
}

// Dialling `run` again within this of a failure answers at once: a `run`
// stopped with Ctrl-Z, say, would make each call wait for the handshake.
var redialAfter = 2 * time.Second

// handshake bounds a `run` that takes the connection but does not answer.
var handshake = 5 * time.Second

// session returns the kept session to `run`, or dials it when there is none or
// the kept one is failed, the one a call just failed on (another call may have
// dialled again already).
func (p *proxy) session(ctx context.Context, failed *mcp.ClientSession) (*mcp.ClientSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cs != nil && p.cs != failed {
		return p.cs, nil
	}
	if old := p.cs; old != nil {
		p.cs = nil
		go old.Close() // it may wait for calls still on it; not under the lock
	}
	if time.Since(p.failedAt) < redialAfter {
		return nil, errNotRunning
	}
	cs, err := p.dial(ctx)
	if err != nil {
		if p.failedAt.IsZero() || time.Since(p.failedAt) > time.Minute { // stderr, Claude Code's MCP log; not each call
			log.Printf("reqcove mcp: %s: %v", p.sock, err)
		}
		p.failedAt = time.Now()
		return nil, errNotRunning
	}
	p.failedAt = time.Time{}
	if n := p.dials.Add(1); n > 1 {
		p.note = "reqcove run restarted: its records start anew, so flow ids and cursors from before it are gone, and every mock preset is off."
	}
	if v := cs.InitializeResult().ServerInfo.Version; v != Version {
		p.note += fmt.Sprintf(" reqcove run is version %s, this reqcove mcp %s: reconnect the agent's MCP server (/mcp in Claude Code) for the tools of the version running.", v, Version)
	}
	p.cs = cs
	return cs, nil
}

var errNotRunning = errors.New("reqcove run is not running")

func (p *proxy) dial(ctx context.Context) (*mcp.ClientSession, error) {
	c, err := net.Dial("unix", p.sock)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, handshake)
	defer cancel()
	cs, err := p.client.Connect(ctx, &mcp.IOTransport{Reader: c, Writer: c}, nil)
	if err != nil {
		c.Close()
		return nil, err
	}
	return cs, nil
}

func (p *proxy) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cs != nil {
		p.cs.Close()
	}
}

// takeNote returns the note for an answer from cs, once.
func (p *proxy) takeNote(cs *mcp.ClientSession) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cs != cs {
		return ""
	}
	n := p.note
	p.note = ""
	return n
}

// call forwards one tool call. A connection that closed (`run` restarted) is
// dialled again and a read-only call sent once more; a write (activate_mock)
// never is, since it may have landed. `run`'s own answers, errors included,
// go back as they are; a `run` without the tool (an older one) answers that
// it does not have it.
func (p *proxy) call(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(p.ctx, cancel)() // a signal ends a call `run` does not answer
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
		switch {
		case err == nil:
			// Only what the tool answered: not the session's own fields.
			out := &mcp.CallToolResult{Content: res.Content, StructuredContent: res.StructuredContent, IsError: res.IsError}
			if n := p.takeNote(cs); n != "" {
				withNote(out, n)
			}
			return out, nil
		case !closed(err):
			if writeTools[req.Params.Name] && strings.Contains(err.Error(), "unknown tool") {
				return toolError("the running reqcove has no " + req.Params.Name + ": it is an older version; restart `reqcove run` with this one"), nil
			}
			return nil, err // `run`'s own answer (an unknown tool, say), one too big, or the agent's cancel or a signal
		case writeTools[req.Params.Name]:
			return toolError("the connection to reqcove run closed during the call: it may or may not have taken effect; call list_mock_presets to see"), nil
		case try == 1:
			return p.down(), nil
		}
	}
}

// withNote puts the proxy's note in the answer where an agent reads it: in
// the structured answer, which Claude Code shows the model instead of the
// text beside it (seen with Claude Code), and in that text, its JSON.
func withNote(out *mcp.CallToolResult, note string) {
	if m, ok := out.StructuredContent.(map[string]any); ok {
		if own, _ := m["note"].(string); own != "" {
			note += " " + own // the tool's own note (a --pass-hosts host) stays
		}
		m["note"] = note
		if b, err := json.Marshal(m); err == nil {
			out.Content = []mcp.Content{&mcp.TextContent{Text: string(b)}}
			return
		}
	}
	out.Content = append(out.Content, &mcp.TextContent{Text: note})
}

// closed says err is the connection to `run` gone, not an answer of its.
func closed(err error) bool {
	return errors.Is(err, mcp.ErrConnectionClosed) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// down is the tool error while `run` is not there.
func (p *proxy) down() *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: p.notRunning}}}
}

func toolError(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}
