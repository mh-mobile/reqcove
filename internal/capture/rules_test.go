package capture

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRules runs --rules through real mitmdump (REQCOVE_E2E=1): the mapped
// backend gets POST bodies, never-ending POSTs and SSE as they stream;
// map_local answers GET and POST; modify_headers works both ways; rules never
// touch requests outside --allow-hosts; rule values stay out of the records.
func TestRules(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	var mu sync.Mutex
	seen := map[string]*http.Request{} // path -> request, on either backend
	bodies := map[string]string{}
	note := func(r *http.Request, body string) {
		mu.Lock()
		defer mu.Unlock()
		seen[r.URL.Path], bodies[r.URL.Path] = r, body
	}
	firstChunk, releaseSSE := make(chan string, 1), make(chan struct{})
	mapped := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/landed/stream": // a POST that has not ended yet
			b := make([]byte, 5)
			io.ReadFull(r.Body, b)
			firstChunk <- string(b)
			io.Copy(io.Discard, r.Body)
			note(r, string(b))
		case "/landed/sse":
			note(r, "")
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: 1\n\n")
			w.(http.Flusher).Flush()
			<-releaseSSE
			fmt.Fprint(w, "data: 2\n\n")
		default:
			b, _ := io.ReadAll(r.Body)
			note(r, string(b))
			fmt.Fprintf(w, "mapped %s", r.URL.Path)
		}
	}))
	defer mapped.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		note(r, string(b))
		fmt.Fprintf(w, "origin %s", r.URL.Path)
	}))
	defer origin.Close()
	o, m := origin.Listener.Addr().String(), mapped.Listener.Addr().String()
	_, mport, _ := strings.Cut(m, ":")
	// resolve over TLS: the phone dials the real server; the rule sends the
	// request to target, which records the SNI it was asked for.
	sni := make(chan string, 8)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	target.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni <- h.ServerName
		return nil, nil
	}}
	target.StartTLS()
	defer target.Close()
	real := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer real.Close()
	tport := target.Listener.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "files"), 0o700)
	os.WriteFile(filepath.Join(dir, "files", "hello.json"), []byte(`{"local":true}`), 0o600)
	rules := filepath.Join(dir, "rules.yaml")
	// localhost is outside --allow-hosts (127.0.0.1): the flow must still be recorded.
	os.WriteFile(rules, []byte(fmt.Sprintf(`map_remote:
  - "|//from.test/old/|//resolved.test/new/"
  - "|//%[1]s/remote/|//localhost:%[2]s/landed/"
  - "|//elsewhere.example/|//localhost:%[2]s/landed/"
map_local:
  - "|//%[1]s/local/|files"
modify_headers:
  - "|~q|X-Injected|yes"
  - "|~q|Authorization|Bearer s3cret-injected"
  - "|~s|X-Resp|added"
keep_host_header: true
resolve:
  - "resolved.test=127.0.0.1:%[2]s"
  - "tls.resolved.test=127.0.0.1:%[3]d"
`, o, mport, tport)), 0o600)

	h, err := tryHarness(t, ctx, []string{"127.0.0.1", "resolved.test", "tls.resolved.test", "from.test"}, func(c *Config) { c.Rules = rules })
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(h.stats()["rules"]); got != "map[keep_host_header:1 map_local:1 map_remote:3 modify_headers:3 resolve:2]" {
		t.Errorf("rules loaded: %s", got)
	}
	hc := h.client("dev")
	do := func(method, url, body string) (*http.Response, string) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, url, rd)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, url, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}

	// map_remote with a POST body, to a host outside --allow-hosts.
	resp, body := do("POST", "http://"+o+"/remote/post", "payload")
	if body != "mapped /landed/post" || bodies["/landed/post"] != "payload" {
		t.Errorf("map_remote POST: %q, backend got %q", body, bodies["/landed/post"])
	}
	if resp.Header.Get("X-Resp") != "added" {
		t.Errorf("response header not added: %v", resp.Header)
	}
	mu.Lock()
	got := seen["/landed/post"]
	mu.Unlock()
	if got == nil || got.Header.Get("X-Injected") != "yes" || got.Header.Get("Authorization") != "Bearer s3cret-injected" {
		t.Errorf("request headers at the backend: %v", got)
	} else if got.Host != o {
		t.Errorf("keep_host_header: the mapped backend got Host %q, want the app's %q", got.Host, o)
	}
	v := h.doneFlow("/remote/post", true)
	if v.Host != "127.0.0.1" || !strings.Contains(v.MappedURL, "localhost:"+mport+"/landed/post") || v.ReqBodyText != "payload" {
		t.Errorf("record: host=%q mapped=%q body=%q", v.Host, v.MappedURL, v.ReqBodyText)
	}
	if !slices.Contains(v.Rewrites, "map_remote") || !slices.Contains(v.Rewrites, "modify_headers request: Authorization") || !slices.Contains(v.Rewrites, "modify_headers response: X-Resp") {
		t.Errorf("rewrites: %v", v.Rewrites)
	}
	for _, hd := range v.ReqHeaders {
		if strings.EqualFold(hd[0], "X-Injected") {
			t.Errorf("recorded request headers should be the app's, got %v", v.ReqHeaders)
		}
	}

	// A POST that has not ended reaches the mapped backend as it streams.
	pr, pw := io.Pipe()
	go func() {
		req, _ := http.NewRequest("POST", "http://"+o+"/remote/stream", pr)
		if r, err := hc.Do(req); err == nil {
			r.Body.Close()
		}
	}()
	pw.Write([]byte("first"))
	select {
	case c := <-firstChunk:
		if c != "first" {
			t.Errorf("first chunk %q", c)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the mapped backend never got the start of an unfinished POST")
	}
	pw.Close()

	// SSE through map_remote: the first event arrives before the stream ends.
	sse, err := hc.Get("http://" + o + "/remote/sse")
	if err != nil {
		t.Fatal(err)
	}
	line := make([]byte, len("data: 1\n\n"))
	if _, err := io.ReadFull(sse.Body, line); err != nil || string(line) != "data: 1\n\n" {
		t.Errorf("first SSE event: %q %v", line, err)
	}
	close(releaseSSE)
	sse.Body.Close()

	// map_local answers GET and POST (the POST body is buffered, then recorded).
	if _, body := do("GET", "http://"+o+"/local/hello.json", ""); body != `{"local":true}` {
		t.Errorf("map_local GET: %q", body)
	}
	if _, body := do("POST", "http://"+o+"/local/hello.json?p=1", "up"); body != `{"local":true}` {
		t.Errorf("map_local POST: %q", body)
	}
	lv := h.doneFlow("/local/hello.json?p=1", true)
	if lv.Status != 200 || lv.RespBodyText != `{"local":true}` || lv.ReqBodyText != "up" || !slices.Contains(lv.Rewrites, "map_local: 200") {
		t.Errorf("map_local record: status=%d resp=%q req=%q rewrites=%v", lv.Status, lv.RespBodyText, lv.ReqBodyText, lv.Rewrites)
	}
	mu.Lock()
	_, leaked := seen["/local/hello.json"]
	mu.Unlock()
	if leaked {
		t.Error("map_local still went to the origin")
	}
	// A large request body would be buffered whole for a local answer: such a
	// request goes on to the origin instead, streamed.
	if _, body := do("POST", "http://"+o+"/local/hello.json?big=1", strings.Repeat("u", 2<<20)); body != "origin /local/hello.json" {
		t.Errorf("map_local with a 2 MiB body: %q", body)
	}
	if bv := h.doneFlow("/local/hello.json?big=1", false); !slices.Contains(bv.Rewrites, "map_local: skipped, request body over 1 MiB or of unknown length") {
		t.Errorf("rewrites for the big body: %v", bv.Rewrites)
	}

	// resolve, plain HTTP: the request goes to the rule's address with the
	// app's Host and URL; the record says where it went.
	req, _ := http.NewRequest("GET", "http://"+o+"/resolve/plain", nil)
	req.Host = "resolved.test"
	if r, err := hc.Do(req); err != nil {
		t.Errorf("resolve: %v", err)
	} else {
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		mu.Lock()
		got := seen["/resolve/plain"]
		mu.Unlock()
		if string(b) != "mapped /resolve/plain" || got == nil || got.Host != "resolved.test" {
			t.Errorf("resolve: body %q, backend saw %v", b, got)
		}
	}
	if rv := h.doneFlow("/resolve/plain", false); rv.Host != "resolved.test" || !slices.Contains(rv.Rewrites, "resolve: 127.0.0.1:"+mport) {
		t.Errorf("resolve record: host %q rewrites %v", rv.Host, rv.Rewrites)
	}
	// map_remote sends from.test to resolved.test, whose resolve rule then
	// applies; the app's Host stays (keep_host_header), the record keeps
	// map_remote's URL.
	req, _ = http.NewRequest("GET", "http://"+o+"/old/x", nil)
	req.Host = "from.test"
	if r, err := hc.Do(req); err != nil {
		t.Errorf("map_remote then resolve: %v", err)
	} else {
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		mu.Lock()
		got := seen["/new/x"]
		mu.Unlock()
		if string(b) != "mapped /new/x" || got == nil || got.Host != "from.test" {
			t.Errorf("map_remote then resolve: %q, backend saw %v", b, got)
		}
	}
	if mv := h.doneFlow("/old/x", false); mv.MappedURL != "http://resolved.test/new/x" || !slices.Contains(mv.Rewrites, "resolve: 127.0.0.1:"+mport) {
		t.Errorf("map_remote then resolve, record: mapped %q rewrites %v", mv.MappedURL, mv.Rewrites)
	}
	// resolve, TLS: the target is asked for the app's name (SNI), not its
	// address, and its certificate is checked (it fails here: not trusted).
	tc := h.client("dev")
	tc.Transport.(*http.Transport).TLSClientConfig.ServerName = "tls.resolved.test"
	treq, _ := http.NewRequest("GET", "https://"+real.Listener.Addr().String()+"/resolve/tls", nil)
	treq.Host = "tls.resolved.test"
	if r, err := tc.Do(treq); err != nil {
		t.Errorf("resolve over TLS: %v", err)
	} else {
		r.Body.Close()
		if r.StatusCode != 502 {
			t.Errorf("resolve to a server without the name's certificate: %d, want 502", r.StatusCode)
		}
	}
	select {
	case got := <-sni:
		if got != "tls.resolved.test" {
			t.Errorf("the target was asked for SNI %q, want tls.resolved.test", got)
		}
	case <-time.After(30 * time.Second):
		t.Error("resolve over TLS never reached the target")
	}
	if tv := h.doneFlow("/resolve/tls", false); !slices.Contains(tv.Rewrites, fmt.Sprintf("resolve: 127.0.0.1:%d", tport)) || !strings.Contains(tv.Error, "Certificate verify failed") {
		t.Errorf("resolve over TLS, record: status %d error %q rewrites %v", tv.Status, tv.Error, tv.Rewrites)
	}

	// Outside --allow-hosts (Host elsewhere.example on an allowed connection):
	// no rule applies (the second map_remote would match), nothing is recorded.
	oos := h.stat("out_of_scope")
	req, _ = http.NewRequest("GET", "http://"+o+"/remote/oos", nil)
	req.Host = "elsewhere.example"
	if r, err := hc.Do(req); err == nil {
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if string(b) != "origin /remote/oos" {
			t.Errorf("out-of-scope request was rewritten: %q", b)
		}
	}
	time.Sleep(time.Second)
	if h.stat("out_of_scope") != oos+1 {
		t.Errorf("out_of_scope = %d, want %d", h.stat("out_of_scope"), oos+1)
	}

	// The injected token never reaches the records or the stats.
	all, _ := json.Marshal(h.stats())
	for _, f := range listAll(h.c.Store, 1000) {
		fv, _ := h.c.Store.Get(f.ID, true)
		b, _ := json.Marshal(fv)
		all = append(all, b...)
	}
	if strings.Contains(string(all), "s3cret") {
		t.Error("a rule's value reached the records or the stats")
	}
}

// TestRulesRefused: bad rules files stop Start with the reason, never the rule's text.
func TestRulesRefused(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for name, c := range map[string]struct{ yaml, want string }{
		"other option":                {"scripts: [evil.py]\n", "only map_remote, map_local, modify_headers, resolve, keep_host_header are allowed, not scripts"},
		"misplaced rule as a key":     {"'|~q|Authorization|Bearer sekrit': 1\n", "not (a key that is not a name)"},
		"missing file":                {"modify_headers: [\"|~q|Authorization|@/nonexistent/s3cret\"]\n", "modify_headers[0]: FileNotFoundError"},
		"bad regex":                   {"map_remote: [\"|(|x\"]\n", "map_remote[0]: ValueError"},
		"not a mapping":               {"- a\n", "the file must map"},
		"yaml typo":                   {"map_remote: [\"a\"\n  b: ]\n", " at line "},
		"resolve out of scope":        {"resolve: [\"nope.example=192.0.2.1\"]\n", "resolve[0]: nope.example is not in --allow-hosts"},
		"resolve metadata":            {"resolve: [\"127.0.0.1=169.254.169.254\"]\n", "resolve[0]: 127.0.0.1: 169.254.169.254 cannot be a target"},
		"resolve name target":         {"resolve: [\"127.0.0.1=localhost\"]\n", "resolve[0]: 127.0.0.1: the target must be an IPv4 address"},
		"resolve wildcard":            {"resolve: [\"*.example=192.0.2.1\"]\n", "resolve[0]: write name=IPv4"},
		"map_remote bad group":        {"map_remote: [\"|//a.example/|//b.example/\\\\2\"]\n", "map_remote[0]: "},
		"keep host not bool":          {"keep_host_header: \"yes\"\n", "keep_host_header must be true or false"},
		"resolve shared ip, one port": {"resolve: [\"127.0.0.1=192.0.2.1:8443\", \"a.example=192.0.2.1\"]\n", "resolve[1]: a.example: 192.0.2.1 is 127.0.0.1's target too"},
		"resolve shared target":       {"resolve: [\"127.0.0.1=192.0.2.1\", \"a.example=192.0.2.1\"]\n", "resolve[1]: a.example: 192.0.2.1 is 127.0.0.1's target too"},
		"resolve quad100":             {"resolve: [\"127.0.0.1=100.100.100.100\"]\n", "resolve[0]: 127.0.0.1: 100.100.100.100 cannot be a target"},
	} {
		t.Run(name, func(t *testing.T) {
			rules := filepath.Join(t.TempDir(), "rules.yaml")
			os.WriteFile(rules, []byte(c.yaml), 0o600)
			_, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(cfg *Config) { cfg.Rules = rules })
			if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "s3cret") {
				t.Errorf("Start: %v, want %q", err, c.want)
			}
		})
	}
}

// TestRulesReload: with RulesReload, a changed file takes over for new
// requests; a request under way keeps the rules it started with (its response
// too); a file that does not load leaves the rules before it, and says why;
// without RulesReload nothing is taken again.
func TestRulesReload(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	arrived, release := make(chan struct{}, 1), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) }) // a failed test does not hold the server's Close
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			arrived <- struct{}{}
			<-release
		}
		fmt.Fprint(w, r.Header.Get("X-Rule"))
	}))
	defer srv.Close()
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(rules, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	one := "modify_headers:\n  - \"|~q|X-Rule|one\"\n  - \"|~s|X-Resp|one\"\n"
	two := "modify_headers:\n  - \"|~q|X-Rule|two\"\n  - \"|~s|X-Resp|two\"\n  - \"|~q|X-Two|1\"\n"
	for _, reload := range []bool{true, false} {
		write(one)
		h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.Rules, c.RulesReload = rules, reload })
		if err != nil {
			t.Fatal(err)
		}
		hc := h.client("dev")
		get := func(path string) (string, string) {
			t.Helper()
			resp, err := hc.Get(srv.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return string(b), resp.Header.Get("X-Resp")
		}
		waitRules := func(want, problem string) {
			t.Helper()
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
				got, e := fmt.Sprint(h.stats()["rules"]), fmt.Sprint(h.stats()["rules_error"])
				if strings.Contains(got, want) && strings.Contains(e, problem) && (problem != "" || e == "") {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("rules %s, error %q: want %s, %q", got, e, want, problem)
				}
			}
		}
		if req, resp := get("/r1"); req != "one" || resp != "one" {
			t.Fatalf("first rules: %q %q", req, resp)
		}
		if !reload {
			write(two)
			time.Sleep(3 * time.Second)
			if req, _ := get("/r2"); req != "one" {
				t.Errorf("without RulesReload, taken again: %q", req)
			}
			continue
		}
		slow := make(chan [2]string, 1)
		go func() {
			resp, err := hc.Get(srv.URL + "/slow")
			if err != nil {
				slow <- [2]string{err.Error()}
				return
			}
			resp.Body.Close()
			slow <- [2]string{"", resp.Header.Get("X-Resp")}
		}()
		<-arrived
		write(two)
		waitRules("modify_headers:3", "")
		releaseOnce.Do(func() { close(release) })
		if r := <-slow; r[0] != "" || r[1] != "one" {
			t.Errorf("the request under way got response rules %q (%s), not its own", r[1], r[0])
		}
		if req, resp := get("/r2"); req != "two" || resp != "two" {
			t.Errorf("after the change: %q %q", req, resp)
		}
		write("modify_headers: [\n")
		waitRules("modify_headers:3", "at line")
		if req, _ := get("/r3"); req != "two" {
			t.Errorf("a broken file changed the rules: %q", req)
		}
		write(one)
		waitRules("modify_headers:2", "")
		if req, _ := get("/r4"); req != "one" {
			t.Errorf("fixed: %q", req)
		}
		// Saved by a rename, as editors do.
		tmp := rules + ".tmp"
		if err := os.WriteFile(tmp, []byte(two), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, rules); err != nil {
			t.Fatal(err)
		}
		waitRules("modify_headers:3", "")
		// The checks at start hold on a reload; an error quotes no rule.
		write("resolve: [\"elsewhere.example=192.0.2.1\"]\n")
		waitRules("modify_headers:3", "not in --allow-hosts")
		write("map_remote:\n  - '|~h \"X-Key: sekrit123\" ~zz|//a/|//b/'\n")
		waitRules("modify_headers:3", "map_remote[0]: ")
		if e := fmt.Sprint(h.stats()["rules_error"]); strings.Contains(e, "sekrit123") {
			t.Errorf("the error quotes the rule: %s", e)
		}
		os.Remove(rules)
		waitRules("modify_headers:3", "the file is gone")
		if req, _ := get("/r5"); req != "two" {
			t.Errorf("after the file went: %q", req)
		}
	}
}

// TestRulesReloadSettles: a file still being written (here, changed every
// 50 ms, faster than the 1 s look) is not taken; once it stays, it is, once.
func TestRulesReloadSettles(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rules := filepath.Join(t.TempDir(), "rules.yaml")
	write := func(n int) {
		t.Helper()
		var b strings.Builder
		b.WriteString("modify_headers:\n")
		for i := 0; i <= n%5; i++ {
			fmt.Fprintf(&b, "  - \"|~q|X-R%d|%d\"\n", i, n)
		}
		if err := os.WriteFile(rules, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(0)
	h, err := tryHarness(t, ctx, []string{"127.0.0.1"}, func(c *Config) { c.Rules, c.RulesReload = rules, true })
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	taken := 0
	h.c.Store.SetRulesLog(func(map[string]int, []string, string) { mu.Lock(); taken++; mu.Unlock() })
	count := func() int { mu.Lock(); defer mu.Unlock(); return taken }
	for i := 1; i <= 60; i++ { // 3 s of changes, every 50 ms: settling would need a pause of a whole second
		write(i)
		time.Sleep(50 * time.Millisecond)
	}
	if n := count(); n != 0 {
		t.Errorf("taken %d times while it was changing", n)
	}
	time.Sleep(3 * time.Second)
	if n := count(); n != 1 {
		t.Errorf("taken %d times once it stayed, want 1", n)
	}
}
