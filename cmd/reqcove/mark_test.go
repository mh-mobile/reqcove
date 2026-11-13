package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

// reqcove mark: refused off a terminal (nothing sent); otherwise its marker
// reaches run as the user's (cli); a run that is not there, or older, says so.
func TestMark(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "rcvm-") // short socket path
	defer os.RemoveAll(dir)
	if err := sendMark(context.Background(), os.Stdout, dir, "x"); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Errorf("not running: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := capture.NewStore(10, 1<<20)
	local, _ := mcpserver.Servers(st, nil, nil, nil)
	if err := mcpserver.Serve(ctx, filepath.Join(dir, "mcp.sock"), local); err != nil {
		t.Fatal(err)
	}
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if err := markIn(ctx, r, w, dir, "tap Pay"); err == nil || !strings.Contains(err.Error(), "only in a terminal") || len(st.Markers(0)) != 0 {
		t.Errorf("off a terminal: %v, %d markers", err, len(st.Markers(0)))
	}
	var out strings.Builder
	if err := sendMark(ctx, &out, dir, "tap Pay"); err != nil || !strings.HasPrefix(out.String(), "marker 1 at ") {
		t.Fatalf("%v %q", err, out.String())
	}
	if ms := st.Markers(0); len(ms) != 1 || ms[0].Source != "cli" || ms[0].Text != "tap Pay" {
		t.Errorf("%+v", ms)
	}
	if err := sendMark(ctx, &out, dir, strings.Repeat("x", 81)); err == nil || !strings.Contains(err.Error(), "at most 80") {
		t.Errorf("too long: %v", err)
	}

	older, _ := os.MkdirTemp("/tmp", "rcvm-")
	defer os.RemoveAll(older)
	if err := mcpserver.Serve(ctx, filepath.Join(older, "mcp.sock"), mcpserver.New(st, nil)); err != nil {
		t.Fatal(err)
	}
	if err := sendMark(ctx, &out, older, "x"); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Errorf("older run: %v", err)
	}
}
