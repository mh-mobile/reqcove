package capture

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// TestSoak (REQCOVE_SOAK=4h, or any duration) keeps real mitmdump busy the
// way a phone would for hours: a steady stream of requests (small, gzip,
// larger than the kept head), one POST that never ends, one long WebSocket
// and one SSE stream. Every minute it logs the RSS of mitmdump and of this
// process; at the end both must stay within the budgets of trial 2 (300 MB
// and 150 MB), the store within its bounds, and nothing must have stalled.
func TestSoak(t *testing.T) {
	d, err := time.ParseDuration(os.Getenv("REQCOVE_SOAK"))
	if err != nil {
		t.Skip("set REQCOVE_SOAK=4h (or another duration)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), d+5*time.Minute)
	defer cancel()
	h := startHarness(t, ctx, []string{"127.0.0.1"})
	mitmPid := pidOn(":" + h.port())

	big := bytes.Repeat([]byte("b"), 200<<10)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(bytes.Repeat([]byte(`{"k":"v"},`), 5000))
	zw.Close()
	var streamed, wsMsgs, sseEvents atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/small", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, `{"ok":true,"path":%q}`, r.URL.Path) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) { w.Write(big) })
	mux.HandleFunc("/gz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(gz.Bytes())
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 32<<10)
		for {
			n, err := r.Body.Read(buf)
			streamed.Add(int64(n))
			if err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; ; i++ {
			if _, err := fmt.Fprintf(w, "data: %d\n\n", i); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
			}
		}
	})
	mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) { io.Copy(ws, ws) }))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	hc := h.client("soak-device")
	dial := hc.Transport.(*http.Transport).DialContext

	// The POST that never ends: 4 KiB every 100 ms for the whole run.
	pr, pw := io.Pipe()
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/upload", pr)
		if r, err := hc.Do(req); err == nil {
			r.Body.Close()
		}
	}()
	go func() {
		chunk := bytes.Repeat([]byte("u"), 4<<10)
		for ctx.Err() == nil {
			if _, err := pw.Write(chunk); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	// The long WebSocket: an 8 KiB echo every 200 ms.
	go func() {
		raw, err := dial(ctx, "tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		cfg, _ := websocket.NewConfig("ws://"+srv.Listener.Addr().String()+"/ws", srv.URL)
		ws, err := websocket.NewClient(cfg, raw)
		if err != nil {
			t.Error(err)
			return
		}
		defer ws.Close()
		msg := bytes.Repeat([]byte("w"), 8<<10)
		buf := make([]byte, len(msg))
		for ctx.Err() == nil {
			if websocket.Message.Send(ws, msg) != nil {
				return
			}
			if _, err := io.ReadFull(ws, buf); err != nil {
				return
			}
			wsMsgs.Add(1)
			time.Sleep(200 * time.Millisecond)
		}
	}()
	// The SSE stream, read line by line.
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/sse", nil)
		r, err := hc.Do(req)
		if err != nil {
			return
		}
		defer r.Body.Close()
		buf := make([]byte, 64)
		for {
			n, err := r.Body.Read(buf)
			sseEvents.Add(int64(strings.Count(string(buf[:n]), "data:")))
			if err != nil {
				return
			}
		}
	}()

	var requests, failures atomic.Int64
	go func() { // about 10 requests a second, as a busy phone
		paths := []string{"/small", "/small", "/small", "/gz", "/big"}
		for i := 0; ctx.Err() == nil; i++ {
			r, err := hc.Get(srv.URL + paths[i%len(paths)] + fmt.Sprintf("?n=%d", i))
			if err != nil {
				failures.Add(1)
			} else {
				io.Copy(io.Discard, r.Body)
				r.Body.Close()
			}
			requests.Add(1)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	var peakMitm, peakGo int64
	end := time.Now().Add(d)
	var lastStreamed, lastWS, lastSSE int64
	for minute := 1; time.Now().Before(end); minute++ {
		time.Sleep(min(time.Minute, time.Until(end)))
		m, g := rssKB(mitmPid), rssKB(os.Getpid())
		peakMitm, peakGo = max(peakMitm, m), max(peakGo, g)
		s := h.stats()
		t.Logf("%3dm rss mitmdump=%dMB go=%dMB | requests=%d failures=%d upload=%dMB ws=%d sse=%d | flows=%v held=%vMB evicted=%v dropped=%v/%v",
			minute, m>>10, g>>10, requests.Load(), failures.Load(), streamed.Load()>>20, wsMsgs.Load(), sseEvents.Load(),
			s["flows"], h.stat("held_bytes")>>20, s["evicted"], s["addon_dropped_bodies"], s["addon_dropped_events"])
		// Nothing may stall: the endless streams keep moving every minute.
		if streamed.Load() == lastStreamed || wsMsgs.Load() == lastWS || sseEvents.Load() == lastSSE {
			t.Errorf("%dm: a long stream stalled (upload %d, ws %d, sse %d)", minute, streamed.Load(), wsMsgs.Load(), sseEvents.Load())
		}
		lastStreamed, lastWS, lastSSE = streamed.Load(), wsMsgs.Load(), sseEvents.Load()
		if s["state"] != "ready" {
			t.Errorf("%dm: mitmdump is %v", minute, s["state"])
		}
	}
	t.Logf("peak RSS: mitmdump %d MB (budget 300), go %d MB (budget 150); %d requests, %d failed", peakMitm>>10, peakGo>>10, requests.Load(), failures.Load())
	if peakMitm > 300<<10 || peakGo > 150<<10 {
		t.Errorf("over budget: mitmdump %d MB, go %d MB", peakMitm>>10, peakGo>>10)
	}
	if f := failures.Load(); f > requests.Load()/1000 {
		t.Errorf("%d of %d requests failed", f, requests.Load())
	}
	if n, _ := h.stats()["flows"].(int); n > 10000 {
		t.Errorf("store over its bound: %d flows", n)
	}
	pw.Close()
}
