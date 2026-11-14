package capture

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestWebSocketDeflate (REQCOVE_E2E=1): a WebSocket with permessage-deflate
// (compressed messages) through mitmproxy: each message is recorded inflated,
// its size the inflated one, and masked as any other.
func TestWebSocketDeflate(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionContextTakeover, CompressionThreshold: 1})
		if err != nil {
			return
		}
		defer c.CloseNow()
		for {
			typ, b, err := c.Read(ctx)
			if err != nil {
				return
			}
			c.Write(ctx, typ, b)
		}
	}))
	defer srv.Close()
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hc := h.client("phone")
	c, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws", &websocket.DialOptions{HTTPClient: hc, CompressionMode: websocket.CompressionContextTakeover, CompressionThreshold: 1})
	if err != nil {
		t.Fatal(err)
	}
	if ext := resp.Header.Get("Sec-WebSocket-Extensions"); !strings.Contains(ext, "permessage-deflate") {
		t.Fatalf("not compressed: %q", ext)
	}
	msgs := []string{`{"type":"auth","token":"S3cretTokenAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`, strings.Repeat("hello deflate ", 200), `{"type":"message","text":"hi"}`}
	for _, m := range msgs {
		if err := c.Write(ctx, websocket.MessageText, []byte(m)); err != nil {
			t.Fatal(err)
		}
		if _, b, err := c.Read(ctx); err != nil || string(b) != m {
			t.Fatalf("echo: %v %q", err, b)
		}
	}
	c.Close(websocket.StatusNormalClosure, "")
	time.Sleep(time.Second)
	v := h.doneFlow("/ws", false)
	page, err := h.c.Store.WSList(v.ID, WSQuery{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 6 || len(page.Messages) != 6 {
		t.Fatalf("%d messages, %d kept", page.Total, len(page.Messages))
	}
	for i, m := range page.Messages {
		sent := msgs[i/2]
		if strings.Contains(m.Head, "S3cretToken") || m.Size != int64(len(sent)) || !m.Text {
			t.Errorf("message %d: size %d text %v head %.80q", m.N, m.Size, m.Text, m.Head)
		}
	}
	if h := page.Messages[2].Head; !strings.HasPrefix(h, "hello deflate hello") {
		t.Errorf("not inflated: %.80q", h)
	}
}
