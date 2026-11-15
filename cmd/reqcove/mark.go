package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/mh-mobile/reqcove/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mark puts the user's marker among the running reqcove's records (source
// cli): add_marker over mcp.sock, as reqcove-mark. Only in a terminal, as lan:
// what an agent runs is an agent's (a help, not proof: a script can give it one).
func mark(ctx context.Context, args []string) error {
	words, flags := wordsAndFlags(args)
	fls := flag.NewFlagSet("mark", flag.ExitOnError)
	state := fls.String("state", defaultState(), "state directory")
	if err := parseFlags(fls, flags); err != nil {
		return err
	}
	return markIn(ctx, os.Stdin, os.Stdout, *state, strings.Join(words, " "))
}

func markIn(ctx context.Context, in, out *os.File, state, text string) error {
	if !isTerminal(in) || !isTerminal(out) {
		return errors.New("reqcove mark runs only in a terminal: its markers are the user's (source cli); an agent has add_marker. Run it in your own terminal")
	}
	return sendMark(ctx, out, state, text)
}

func sendMark(ctx context.Context, w io.Writer, state, text string) error {
	cs, err := dialRun(ctx, state, mcpserver.MarkClient)
	if errors.Is(err, errNotRunning) {
		return fmt.Errorf("reqcove is not running (%s): nothing to mark", state)
	} else if err != nil {
		return fmt.Errorf("%w: nothing marked", err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "add_marker", Arguments: map[string]any{"text": text}})
	if err != nil {
		return fmt.Errorf("the running reqcove did not take the marker (%v); an older build? restart `%s` with this one", err, withState("reqcove run", state))
	}
	if res.IsError {
		var msg []string
		for _, c := range res.Content {
			if t, ok := c.(*mcp.TextContent); ok {
				msg = append(msg, t.Text)
			}
		}
		return errors.New(strings.Join(msg, " "))
	}
	var out mcpserver.MarkOut
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		return err
	}
	fmt.Fprintf(w, "marker %d at %s\n", out.ID, out.Time)
	return nil
}

var (
	errNotRunning = errors.New("reqcove is not running")
	errStarting   = errors.New("reqcove is starting, or stopping")
)

// dialRun connects to the running reqcove's MCP socket as client, the
// handshake bounded as reqcove mcp bounds it: a run stopped with Ctrl-Z takes
// the connection but never answers. No socket to connect to: errNotRunning,
// or errStarting while a run holds the state's lock (it serves the socket
// once mitmproxy is up, up to 2 minutes; and stops serving it first).
func dialRun(ctx context.Context, state, client string) (*mcp.ClientSession, error) {
	hctx, cancel := context.WithTimeout(ctx, mcpserver.Handshake)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(hctx, "unix", filepath.Join(state, "mcp.sock"))
	if err != nil {
		if stateHeld(state) {
			return nil, fmt.Errorf("%w (%s): its tools are not up (mitmproxy starts first, and the first start downloads it): try again in a moment", errStarting, state)
		}
		return nil, errNotRunning
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: client, Version: version}, nil).Connect(hctx, &mcp.IOTransport{Reader: conn, Writer: conn}, nil)
	if err != nil {
		conn.Close()
		if hctx.Err() != nil && ctx.Err() == nil {
			return nil, fmt.Errorf("the running reqcove (%s) did not answer in %v (stopped, with Ctrl-Z?)", state, mcpserver.Handshake)
		}
		return nil, err
	}
	return cs, nil
}
