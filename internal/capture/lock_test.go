package capture

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// BenchmarkToolsWhileIngesting: how long a tool waits (List, Get) while
// 64 KiB JSON bodies arrive back to back, and how fast they arrive. Masking
// a body under the Store's lock made tools wait for it.
func BenchmarkToolsWhileIngesting(b *testing.B) {
	s := NewStore(DefaultMaxFlows, DefaultMaxBytes)
	body := []byte(`{"items":[` + strings.Repeat(`{"id":12345,"name":"widget","note":"key=AbCdEf0123456789xyz https://x.example/?q=1"},`, 800) + `0]}`)[:64<<10]
	head := base64.StdEncoding.EncodeToString(body)
	stop := make(chan struct{})
	ingested := make(chan int)
	go func() {
		n := 0
		for {
			select {
			case <-stop:
				ingested <- n
				return
			default:
			}
			id := fmt.Sprintf("f%d", n)
			s.Apply([]byte(`{"v":2,"ev":"request","id":"` + id + `","method":"GET","url":"https://a.example/x","host":"a.example","path":"/x","headers":[]}`))
			s.Apply([]byte(`{"v":2,"ev":"response","id":"` + id + `","status":200,"headers":[["Content-Type","application/json"]]}`))
			s.Apply([]byte(`{"v":2,"ev":"body","id":"` + id + `","dir":"response","head":"` + head + `","size":65536,"final":true,"decoded":true}`))
			n++
		}
	}()
	time.Sleep(20 * time.Millisecond)
	var waits []time.Duration
	start := time.Now()
	for b.Loop() {
		t := time.Now()
		s.List(Filter{Limit: 20})
		s.Get("f1", false)
		waits = append(waits, time.Since(t))
		time.Sleep(time.Millisecond)
	}
	elapsed := time.Since(start)
	close(stop)
	n := <-ingested
	sort.Slice(waits, func(i, j int) bool { return waits[i] < waits[j] })
	b.ReportMetric(float64(waits[len(waits)/2].Microseconds()), "p50-µs")
	b.ReportMetric(float64(waits[len(waits)*99/100].Microseconds()), "p99-µs")
	b.ReportMetric(float64(n)/elapsed.Seconds(), "bodies/s")
}

// TestBodyRacingItsRequest: a body event applied while its request event is
// (another connection's lines, a restart) is stored masked, or not at all:
// a flow absent when the body was masked makes it an orphan, even if the
// flow is there by the time it would be stored.
func TestBodyRacingItsRequest(t *testing.T) {
	secret := "S3crQt7VxLu9Kz"
	head := base64.StdEncoding.EncodeToString([]byte(`{"password":"` + secret + `"}`))
	for i := range 300 {
		s := NewStore(100, 1<<20)
		id := fmt.Sprintf("f%d", i)
		done := make(chan struct{})
		go func() {
			s.Apply([]byte(`{"v":2,"ev":"request","id":"` + id + `","method":"POST","url":"https://a.example/x","host":"a.example","path":"/x","headers":[["Content-Type","application/json"]]}`))
			close(done)
		}()
		s.Apply([]byte(`{"v":2,"ev":"body","id":"` + id + `","dir":"request","head":"` + head + `","size":30,"final":true,"decoded":true}`))
		<-done
		s.mu.Lock()
		f := s.flows[id]
		b := f.ReqBody
		s.mu.Unlock()
		if strings.Contains(string(b.Head), secret) || b.Size > 0 && !strings.Contains(string(b.Head), "[redacted]") {
			t.Fatalf("stored %+v (%s)", b, b.Head)
		}
	}
}
