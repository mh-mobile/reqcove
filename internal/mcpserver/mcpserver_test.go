package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func testStore(t *testing.T) *capture.Store {
	st := capture.NewStore(10, 1<<20)
	for _, l := range []string{
		`{"v":2,"ev":"request","id":"a","device":"dev-1","host":"api.example.net","url":"https://api.example.net/x","headers":[["Authorization","Bearer s3cret"]]}`,
		`{"v":2,"ev":"response","id":"a","status":200}`,
		`{"v":2,"ev":"body","id":"a","dir":"response","head":"aGVsbG8=","size":5,"final":true,"decoded":true}`,
		`{"v":2,"ev":"done","id":"a"}`,
	} {
		st.Apply([]byte(l))
	}
	st.SetDeviceNames(map[string]string{"dev-1": "iphone-test"})
	return st
}

func call[T any](t *testing.T, s *mcp.ClientSession, name string, args any) T {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || res.IsError {
		t.Fatalf("%s: %v %+v", name, err, res)
	}
	var out T
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTools(t *testing.T) {
	ct, st := mcp.NewInMemoryTransports()
	server := New(testStore(t))
	if _, err := server.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	list := call[ListOut](t, session, "list_flows", map[string]any{"device": "iphone-test"})
	if len(list.Flows) != 1 || list.Flows[0].DeviceName != "iphone-test" || list.Flows[0].Status != 200 {
		t.Fatalf("list_flows by device name = %+v", list.Flows)
	}
	v := call[capture.FlowView](t, session, "get_flow", map[string]any{"id": "a", "bodies": true})
	if v.RespBodyText != "hello" || v.ReqHeaders[0][1] != "[redacted]" || v.DeviceName != "iphone-test" {
		t.Fatalf("get_flow = %+v", v)
	}
	if s := call[StatsOut](t, session, "capture_stats", nil); s.Stats["flows"] != float64(1) {
		t.Fatalf("capture_stats = %v", s.Stats)
	}
}

// TestServeAndRelay: an agent's stdio, relayed to the socket `run` serves, reaches the tools.
func TestServeAndRelay(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "rcvm-") // short socket path
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "mcp.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, sock, New(testStore(t)))
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := os.Stat(sock); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatal("socket never appeared")
		}
	}

	// The agent side: an in-memory pipe stands in for `reqcove mcp`'s stdio.
	agentIn, relayIn := io.Pipe()   // agent writes -> relay's stdin
	relayOut, agentOut := io.Pipe() // relay's stdout -> agent reads
	go Relay(ctx, sock, agentIn, agentOut)
	transport := &mcp.IOTransport{Reader: relayOut, Writer: relayIn}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := call[ListOut](t, session, "list_flows", nil); len(got.Flows) != 1 {
		t.Fatalf("list_flows through the relay = %+v", got.Flows)
	}
	session.Close()
	cancel()
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(sock); err == nil {
		t.Error("socket left behind after Serve ended")
	}
}

func TestListFilterInput(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	q, err := filter(ListIn{Since: "10m", Until: "2026-11-07T21:00:00+09:00", Limit: 9999, Status: "4xx"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if q.Since != float64(now.Add(-10*time.Minute).Unix()) || q.Until != float64(now.Unix()) || q.Limit != 500 || q.Status != "4xx" {
		t.Errorf("filter = %+v", q)
	}
	if q, _ := filter(ListIn{}, now); q.Limit != 50 || q.Since != 0 {
		t.Errorf("defaults = %+v", q)
	}
	for _, in := range []ListIn{{Since: "yesterday"}, {Until: "12:00"}, {Status: "4XX"}, {Status: "abc"}} {
		if _, err := filter(in, now); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
}
