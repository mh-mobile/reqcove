package capture

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestListFiltersAndPages(t *testing.T) {
	st := NewStore(4, 1<<20) // room for 4: the 6 below evict the 2 oldest
	st.SetDeviceNames(map[string]string{"nPHONE": "iphone", "nPAD": "ipad"})
	base := float64(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC).Unix())
	add := func(id, dev, method, host string, status int, start float64) {
		st.Apply(line(t, map[string]any{"ev": "request", "id": id, "device": dev, "method": method, "host": host,
			"url": "https://" + host + "/" + id + "?token=abc", "ts": start,
			"headers": [][2]string{{"User-Agent", "App/1.0"}, {"Origin", "https://app.example"}, {"Referer", "https://app.example/p?key=k1"}}}))
		if status != 0 {
			st.Apply(line(t, map[string]any{"ev": "response", "id": id, "status": status, "headers": [][2]string{{"Content-Type", "application/json"}}}))
			st.Apply(line(t, map[string]any{"ev": "done", "id": id, "ts_end": start + 0.25}))
		}
	}
	add("f1", "nPHONE", "GET", "api.example.com", 200, base)    // evicted
	add("f2", "nPHONE", "GET", "api.example.com", 200, base+10) // evicted
	add("f3", "nPHONE", "POST", "api.example.com", 404, base+20)
	add("f4", "nPAD", "GET", "CDN.Example.com", 500, base+30)
	add("f5", "nPHONE", "post", "badexample.com", 0, base+40) // no response yet
	add("f6", "nPHONE", "GET", "example.com", 201, base+50)

	ids := func(q Filter) string {
		if q.Limit == 0 {
			q.Limit = 50
		}
		fs, _ := st.List(q)
		var out []string
		for _, f := range fs {
			out = append(out, f.ID)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		q    Filter
		want string
	}{
		{Filter{}, "f6,f5,f4,f3"},
		{Filter{Host: "example.com"}, "f6,f4,f3"}, // subdomains yes, badexample.com no
		{Filter{Host: "API.example.com"}, "f3"},
		{Filter{Device: "ipad"}, "f4"},
		{Filter{Device: "nPHONE"}, "f6,f5,f3"},
		{Filter{Method: "post"}, "f5,f3"},
		{Filter{Status: "4xx"}, "f3"},
		{Filter{Status: "5xx"}, "f4"},
		{Filter{Status: "201"}, "f6"},
		{Filter{Status: "none"}, "f5"},
		{Filter{Since: base + 30}, "f6,f5,f4"},
		{Filter{Until: base + 30}, "f4,f3"},
		{Filter{Since: base + 25, Until: base + 45, Device: "iphone"}, "f5"},
	} {
		if got := ids(c.q); got != c.want {
			t.Errorf("%+v: got %s, want %s", c.q, got, c.want)
		}
	}

	// Pages of 2 walk all matches once, and a cursor still works after the
	// flows around it are evicted.
	var pages []string
	q := Filter{Limit: 2}
	for {
		fs, next := st.List(q)
		var p []string
		for _, f := range fs {
			p = append(p, f.ID)
		}
		pages = append(pages, strings.Join(p, ","))
		if next == 0 || len(pages) > 5 {
			break
		}
		q.Before = next
		if len(pages) == 1 {
			add("f7", "nPHONE", "GET", "example.com", 200, base+60) // evicts f3
		}
	}
	if got := fmt.Sprint(pages); got != "[f6,f5 f4]" {
		t.Errorf("pages %s, want [f6,f5 f4]", got)
	}

	fs, _ := st.List(Filter{Host: "cdn.example.com", Limit: 1}) // the record keeps CDN.Example.com
	f := fs[0]
	wantTime := time.Unix(int64(base+30), 0).Format("2006-01-02T15:04:05.000Z07:00")
	if f.Time != wantTime || f.DurationMS != 250 || f.ContentType != "application/json" || f.UserAgent != "App/1.0" ||
		f.Origin != "https://app.example" || f.DeviceName != "ipad" || f.Status != 500 {
		t.Errorf("summary: %+v (time want %s)", f, wantTime)
	}
	if strings.Contains(f.Referer, "k1") || strings.Contains(f.URL, "abc") {
		t.Errorf("secrets in the summary: referer %q, url %q", f.Referer, f.URL)
	}
}

func TestValidStatus(t *testing.T) {
	for s, ok := range map[string]bool{"": true, "none": true, "404": true, "4xx": true, "1xx": true, "6xx": false, "x": false, "99": false, "600": false, "4XX": false} {
		if ValidStatus(s) != ok {
			t.Errorf("ValidStatus(%q) = %v", s, !ok)
		}
	}
}

func TestSummarizeAndSearch(t *testing.T) {
	st := NewStore(100, 1<<20)
	st.SetDeviceNames(map[string]string{"nPHONE": "iphone"})
	base := float64(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC).Unix())
	add := func(id, host, ua, ctype string, status int, start float64) {
		st.Apply(line(t, map[string]any{"ev": "request", "id": id, "device": "nPHONE", "method": "get", "host": host,
			"url": "https://" + host + "/" + id, "ts": start, "headers": [][2]string{{"User-Agent", ua}, {"X-Trace", "trace-" + id}}}))
		if status != 0 {
			st.Apply(line(t, map[string]any{"ev": "response", "id": id, "status": status, "headers": [][2]string{{"Content-Type", ctype}}}))
		}
	}
	add("a", "api.example.com", "App/1", "application/json; charset=utf-8", 200, base)
	add("b", "API.example.com", "App/1", "application/json", 200, base+5)
	add("c", "img.example.com", "Safari", "image/png", 404, base+9)
	add("d", "api.example.com", "App/1", "", 0, base+2)

	c := st.Summarize(Filter{}, 2)
	if c.Flows != 4 || fmt.Sprint(c.ByHost) != "[{api.example.com 3} {img.example.com 1}]" ||
		fmt.Sprint(c.ByUserAgent) != "[{App/1 3} {Safari 1}]" || fmt.Sprint(c.ByStatus) != "[{200 2} {404 1}]" ||
		fmt.Sprint(c.ByType) != "[{application/json 2} { 1}]" || fmt.Sprint(c.ByMethod) != "[{GET 4}]" || fmt.Sprint(c.ByDevice) != "[{iphone 4}]" {
		t.Errorf("summarize = %+v", c)
	}
	if want := time.Unix(int64(base), 0).Format("2006-01-02T15:04:05.000Z07:00"); c.First != want {
		t.Errorf("first = %s, want %s", c.First, want)
	}
	if c := st.Summarize(Filter{Status: "none"}, 10); c.Flows != 1 || c.ByStatus[0].Key != "none" {
		t.Errorf("summarize none = %+v", c)
	}
	// Search: header values, case-insensitive, with where it matched.
	fs, _ := st.List(Filter{Query: "TRACE-C", Limit: 10})
	if len(fs) != 1 || fs[0].ID != "c" || fmt.Sprint(fs[0].MatchedIn) != "[request_headers]" {
		t.Errorf("search = %+v", fs)
	}
	if fs, _ := st.List(Filter{Query: "image/", Limit: 10}); len(fs) != 1 || fmt.Sprint(fs[0].MatchedIn) != "[response_headers]" {
		t.Errorf("search response header = %+v", fs)
	}
}

func TestTLSFailuresAndDevices(t *testing.T) {
	st := NewStore(100, 1<<20)
	allow, _ := ParseAllowHosts([]string{"*.example.com", "10.0.0.5"})
	st.SetScope(allow, true)
	st.SetDeviceNames(map[string]string{"nPHONE": "iphone", "nPAD": "ipad"})
	base := float64(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC).Unix())
	fail := func(dev, sni, host string, ts float64) {
		st.Apply(line(t, map[string]any{"ev": "tls_failed", "conn": "c-" + sni + host, "device": dev, "sni": sni, "host": host, "ts": ts,
			"msg": "Client TLS handshake failed: https://api.example.com/x?token=leak"}))
	}
	fail("nPHONE", "pinned.example.com", "203.0.113.1", base)
	fail("nPHONE", "", "10.0.0.5", base+10) // no SNI: the address dialed
	fail("nPAD", "api.example.com", "203.0.113.2", base+20)
	fail("nPHONE", "elsewhere.net", "203.0.113.3", base+30) // outside --allow-hosts: counted only
	st.Apply(line(t, map[string]any{"ev": "request", "id": "r1", "device": "nPHONE", "host": "api.example.com", "ts": base + 40}))
	st.Apply(line(t, map[string]any{"ev": "request", "id": "r2", "device": "nOLD", "host": "api.example.com", "ts": base + 50}))

	hosts := func(q Filter) string {
		q.Limit = 10
		var out []string
		for _, f := range st.TLSFailures(q) {
			out = append(out, f.Host+"@"+f.DeviceName)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		q    Filter
		want string
	}{
		{Filter{}, "api.example.com@ipad,10.0.0.5@iphone,pinned.example.com@iphone"},
		{Filter{Device: "iphone"}, "10.0.0.5@iphone,pinned.example.com@iphone"},
		{Filter{Host: "example.com"}, "api.example.com@ipad,pinned.example.com@iphone"},
		{Filter{Since: base + 5, Until: base + 15}, "10.0.0.5@iphone"},
	} {
		if got := hosts(c.q); got != c.want {
			t.Errorf("%+v: got %s, want %s", c.q, got, c.want)
		}
	}
	f := st.TLSFailures(Filter{Limit: 1})[0]
	if strings.Contains(f.Msg, "leak") || f.Time == "" || f.Conn == "" {
		t.Errorf("failure view: %+v", f)
	}
	if st.Stats()["out_of_scope"] != int64(1) {
		t.Errorf("out_of_scope = %v, want 1 (elsewhere.net)", st.Stats()["out_of_scope"])
	}

	got := fmt.Sprint(st.Devices())
	at := func(ts float64) string { return unixTime(ts).Format("2006-01-02T15:04:05.000Z07:00") }
	want := fmt.Sprintf("[{nPAD ipad true 0 1 0  } {nPHONE iphone true 1 2 0 %s %s} {nOLD  false 1 0 0 %s %s}]", at(base+40), at(base+40), at(base+50), at(base+50))
	if got != want {
		t.Errorf("devices:\n got %s\nwant %s", got, want)
	}
}

// A LAN mode device (lan:ADDR) is found by the device filter, and its first
// request this run stays its first seen once that record is evicted.
func TestLANDeviceFirstSeen(t *testing.T) {
	st := NewStore(2, 1<<20)
	allow, _ := ParseAllowHosts([]string{"api.example.com"})
	st.SetScope(allow, true)
	st.SetDeviceNames(map[string]string{"lan:192.168.1.23": "lan:192.168.1.23"})
	base := float64(time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC).Unix())
	for i := range 3 {
		st.Apply(line(t, map[string]any{"ev": "request", "id": fmt.Sprint("r", i), "device": "lan:192.168.1.23", "host": "api.example.com", "ts": base + float64(i)}))
	}
	if fs, _ := st.List(Filter{Device: "lan:192.168.1.23", Limit: 10}); len(fs) != 2 {
		t.Errorf("by device: %d flows, want the 2 kept", len(fs))
	}
	d := st.Devices()
	at := func(ts float64) string { return unixTime(ts).Format("2006-01-02T15:04:05.000Z07:00") }
	if len(d) != 1 || d[0].FirstSeen != at(base) || d[0].LastSeen != at(base+2) {
		t.Errorf("devices %+v, want first seen %s", d, at(base))
	}
}
