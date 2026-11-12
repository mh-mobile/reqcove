package capture

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A socket that takes the request but never answers: a write may have taken
// effect, a read changed nothing, and each says so.
func TestPresetsNoAnswer(t *testing.T) {
	dir, err := makeShortDir(t)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, ControlSock))
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
			defer c.Close() // read, never answer
		}
	}()
	c := &Capture{cfg: Config{Dir: dir}}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := c.Presets(ctx); !errors.Is(err, ErrNoAnswer) {
		t.Errorf("list: %v", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	if _, err := c.Activate(ctx2, "p", 60, 0); !errors.Is(err, ErrUncertain) {
		t.Errorf("activate: %v", err)
	}
	ln.Close()
	if _, err := c.Activate(context.Background(), "p", 60, 0); !errors.Is(err, ErrNoControl) {
		t.Errorf("no socket: %v", err)
	}
}

func makeShortDir(t *testing.T) (string, error) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rcp-") // short: macOS caps socket paths at 104 bytes
	if err == nil {
		t.Cleanup(func() { os.RemoveAll(dir) })
	}
	return dir, err
}
