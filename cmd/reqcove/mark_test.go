package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	// A text starting with -, after --.
	if words, flags := wordsAndFlags([]string{"--state", dir, "--", "-5%", "coupon"}); strings.Join(words, " ") != "-5% coupon" || strings.Join(flags, " ") != "--state "+dir {
		t.Errorf("--: words %q, flags %q", words, flags)
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

// A run that takes the connection but never answers (stopped with Ctrl-Z):
// mark, status and har give up after the handshake's time, as reqcove mcp does.
func TestHandshakeTimeout(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "rcvm-")
	defer os.RemoveAll(dir)
	ln, err := net.Listen("unix", filepath.Join(dir, "mcp.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // never answers
		}
	}()
	old := mcpserver.Handshake
	mcpserver.Handshake = 200 * time.Millisecond
	defer func() { mcpserver.Handshake = old }()
	for name, f := range map[string]func() error{
		"mark":   func() error { return sendMark(context.Background(), io.Discard, dir, "x") },
		"status": func() error { return status(context.Background(), []string{"--state", dir}) },
		"har":    func() error { return har(context.Background(), []string{"--state", dir}) },
	} {
		done := make(chan error, 1)
		go func() { done <- f() }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "did not answer") {
				t.Errorf("%s: %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s waits for a run that does not answer", name)
		}
	}
}

// While a run holds the state but serves no socket yet (mitmproxy starting,
// up to 2 minutes) or any more (stopping), status says so, not "not running,
// start it"; har and mark too.
func TestStatusWhileStarting(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() error { return status(context.Background(), []string{"--state", dir}) })
	if !strings.Contains(out, "reqcove is starting, or stopping") || strings.Contains(out, "not running") {
		t.Errorf("status while starting:\n%s", out)
	}
	if err := har(context.Background(), []string{"--state", dir}); err == nil || !strings.Contains(err.Error(), "starting") {
		t.Errorf("har: %v", err)
	}
	if err := sendMark(context.Background(), io.Discard, dir, "x"); err == nil || !strings.Contains(err.Error(), "starting") {
		t.Errorf("mark: %v", err)
	}
	// --json prints the status tool's JSON or nothing: here an error, stdout empty.
	jsonStatus := func() (string, error) {
		var err error
		out := captureStdout(t, func() error { err = status(context.Background(), []string{"--state", dir, "--json"}); return nil })
		return out, err
	}
	if out, err := jsonStatus(); out != "" || err == nil || !strings.Contains(err.Error(), "starting") {
		t.Errorf("status --json while starting: %q, %v", out, err)
	}
	unlock()
	if out, err := jsonStatus(); out != "" || err == nil || !strings.Contains(err.Error(), "not running") {
		t.Errorf("status --json, not running: %q, %v", out, err)
	}
	if out := captureStdout(t, func() error { return status(context.Background(), []string{"--state", dir}) }); !strings.Contains(out, "reqcove is not running") {
		t.Errorf("status once the lock is free:\n%s", out)
	}
	empty := t.TempDir()
	captureStdout(t, func() error { return status(context.Background(), []string{"--state", empty}) })
	if exists(filepath.Join(empty, "lock")) {
		t.Error("status made a lock file")
	}
}
