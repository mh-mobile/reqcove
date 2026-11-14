package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestRuleTools (REQCOVE_E2E=1): list_rules never shows a filter, a regex, a
// header value, a body or a path; explain_rules answers scope first, then
// what the request path's own code does (a mock, a preset off and on, a
// map_remote then resolve, a ~h filter it cannot tell, a recorded flow), and
// its dry run sends nothing and uses no preset's count. Both work without
// presets, and without a rules file.
func TestRuleTools(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var originHits, stagingHits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		fmt.Fprintf(w, "origin %s", r.URL.Path)
	}))
	defer origin.Close()
	staging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stagingHits.Add(1)
		fmt.Fprintf(w, "staging %s", r.URL.Path)
	}))
	defer staging.Close()
	o, s := origin.Listener.Addr().String(), staging.Listener.Addr().String()
	_, sport, _ := strings.Cut(s, ":")
	dir := t.TempDir()
	local := filepath.Join(dir, "LOCALDIRMARK5")
	os.Mkdir(local, 0o700)
	valueFile := filepath.Join(dir, "FILEMARK5.txt")
	os.WriteFile(valueFile, []byte("v"), 0o600)
	rules := filepath.Join(dir, "rules.yaml")
	os.WriteFile(rules, []byte(fmt.Sprintf(`mock:
  - match: {url: "http://%[1]s/profile"}
    preset: p503
    status: 503
    headers: {X-Mark: MOCKHDRMARK5}
    body: BODYMARK5
  - match: {url: "http://%[1]s/graphql", operation: Feed}
    status: 500
map_remote:
  - '|~u FILTERMARK5|/old/REGEXMARK5/|/new/REGEXMARK7/'
  - '|^http://api\.test(:\d+)?/|http://stage.test/'
  - {rule: '|~d 127.0.0.1|^http://127\.0\.0\.1:\d+/REGEXMARK6/|http://%[2]s/', preset: staging}
map_local:
  - '|~d 127.0.0.1|/local/|%[3]s'
modify_headers:
  - "|~q|X-Token|HDRVALMARK5"
  - "|~h X-Debug|X-Seen|1"
  - "|~q|X-File|@%[4]s"
resolve:
  - "stage.test=127.0.0.1:%[5]s"
`, o, s, local, valueFile, sport)), 0o600)
	h, err := tryHarness(t, ctx, []string{"127.0.0.1", "api.test", "stage.test", "pinned.test"}, func(c *Config) {
		c.Rules = rules
		var err error
		if c.AllowHosts, err = c.AllowHosts.WithPass([]string{"pinned.test"}); err != nil {
			t.Fatal(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	rs, err := h.c.ListRules(ctx)
	b, _ := json.Marshal(rs)
	if err != nil || !rs.Loaded || len(rs.Rules) != 10 {
		t.Fatalf("list_rules: %s %v", b, err)
	}
	for _, m := range []string{"FILTERMARK5", "REGEXMARK5", "REGEXMARK6", "REGEXMARK7", "HDRVALMARK5", "MOCKHDRMARK5", "BODYMARK5", "LOCALDIRMARK5", "FILEMARK5", dir, `\\`} {
		if strings.Contains(string(b), m) {
			t.Errorf("list_rules shows %s: %s", m, b)
		}
	}
	for _, want := range []string{
		`{"kind":"map_remote","index":0,"target":"path only"}`,
		`{"kind":"map_remote","index":1,"target":"http://stage.test"}`,
		`{"kind":"map_remote","index":2,"preset":"staging","active":false,"target":"http://` + s + `"}`,
		`{"kind":"map_local","index":0}`,
		`{"kind":"modify_headers","index":1,"header":"X-Seen","direction":"both"}`,
		`{"kind":"resolve","index":0,"host":"stage.test","address":"127.0.0.1:` + sport + `"}`,
		`{"kind":"mock","index":0,"preset":"p503","active":false,"url":"http://` + o + `/profile","status":503}`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("list_rules lacks %s: %s", want, b)
		}
	}

	explain := func(method, url, op string) Explanation {
		t.Helper()
		e, err := h.c.Explain(ctx, method, url, op)
		if err != nil {
			t.Fatalf("explain %s %s: %v", method, url, err)
		}
		return e
	}
	if e := explain("GET", "http://elsewhere.test/", ""); e.InScope || !strings.Contains(e.Scope, "--allow-hosts") || len(e.Rewrites) != 0 {
		t.Errorf("out of scope: %+v", e)
	}
	if e := explain("GET", "https://pinned.test/", ""); e.InScope || !strings.Contains(e.Scope, "--pass-hosts") {
		t.Errorf("pass-host: %+v", e)
	}
	if _, err := h.c.Explain(ctx, "GET", "ftp://FILTERMARK5/", ""); err == nil || strings.Contains(err.Error(), "FILTERMARK5") {
		t.Errorf("a bad URL: %v", err)
	}

	// A preset off: no mock, but what it would do turned on.
	e := explain("GET", "http://"+o+"/profile", "")
	if e.Mocked || !slices.Contains(e.IfTurnedOn["p503"], "mock[0] preset p503: 503") || len(e.Conditions) == 0 {
		t.Errorf("preset off: %+v", e)
	}
	if ps, _ := h.c.Presets(ctx); slices.ContainsFunc(ps, func(p Preset) bool { return p.Active }) {
		t.Errorf("if_turned_on turned a preset on: %+v", ps)
	}
	if !slices.Contains(e.CannotTell, "modify_headers[1]") || slices.Contains(e.Rewrites, "modify_headers request: X-Seen") {
		t.Errorf("a ~h filter: %+v", e)
	}
	// On, for one request: explained three times, the count stays, nothing sent.
	if _, err := h.c.Activate(ctx, "p503", 60, 1); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if e := explain("GET", "http://"+o+"/profile", ""); !e.Mocked || !slices.Equal(e.Presets, []string{"p503"}) || !slices.Contains(e.Rewrites, "mock[0] preset p503: 503") {
			t.Errorf("preset on: %+v", e)
		}
	}
	ps, _ := h.c.Presets(ctx)
	if i := slices.IndexFunc(ps, func(p Preset) bool { return p.Name == "p503" }); i < 0 || !ps[i].Active || ps[i].Remaining == nil || *ps[i].Remaining != 1 {
		b, _ := json.Marshal(ps)
		t.Errorf("a dry run used the count: %s", b)
	}
	hc := h.client("dev")
	get := func(url string, host ...string) string {
		t.Helper()
		req, _ := http.NewRequest("GET", url, nil)
		if len(host) > 0 {
			req.Host = host[0]
		}
		resp, err := hc.Do(req)
		if err != nil {
			return "error"
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return fmt.Sprintf("%d %s", resp.StatusCode, b)
	}
	if originHits.Load() != 0 || stagingHits.Load() != 0 {
		t.Errorf("explain sent requests: origin %d, staging %d", originHits.Load(), stagingHits.Load())
	}
	if got := get("http://" + o + "/profile"); got != "503 BODYMARK5" {
		t.Errorf("the one request: %q", got)
	}
	if got := get("http://" + o + "/profile?n=2"); got != "200 origin /profile" {
		t.Errorf("after it: %q", got)
	}

	// A GraphQL mock needs the operation; with it, it answers.
	if e := explain("POST", "http://"+o+"/graphql", ""); e.Mocked || !slices.ContainsFunc(e.CannotTell, func(s string) bool { return strings.HasPrefix(s, "mock[1]") }) {
		t.Errorf("no operation: %+v", e)
	}
	if e := explain("POST", "http://"+o+"/graphql", "Feed"); !e.Mocked || !slices.Contains(e.Rewrites, "mock[1]: 500") {
		t.Errorf("operation Feed: %+v", e)
	}

	// map_remote, then resolve by the host it gave; a recorded flow explains to what it got.
	if got := get("http://"+o+"/x?n=chain", "api.test"); got != "200 staging /x" {
		t.Fatalf("chain: %q", got)
	}
	f := h.doneFlow("n=chain", false)
	e = explain(f.Method, f.URL, f.Operation)
	if got := append(e.Rewrites, e.ResponseRewrites...); !slices.Equal(got, f.Rewrites) || e.MappedTo != "http://stage.test" || !slices.Contains(got, "resolve: 127.0.0.1:"+sport) {
		t.Errorf("chain: explained %q (mapped to %q), recorded %q", got, e.MappedTo, f.Rewrites)
	}

	// Without a rules file: in scope, nothing loaded.
	h2, err := tryHarness(t, ctx, []string{"127.0.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rs, err := h2.c.ListRules(ctx); err != nil || rs.Loaded || len(rs.Rules) != 0 {
		t.Errorf("no rules: %+v %v", rs, err)
	}
	if e, err := h2.c.Explain(ctx, "GET", "http://"+o+"/profile", ""); err != nil || !e.InScope || e.Loaded {
		t.Errorf("no rules: %+v %v", e, err)
	}
}

// TestExplainDry (REQCOVE_E2E=1, mitmproxy's Python): a dry run leaves no
// connection state behind (resolve), a plain map_remote's target is shown
// only when it can be read from the rule, and a mock preset that is off and
// wants an operation not given is one it cannot tell.
func TestExplainDry(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	dir := t.TempDir()
	for f, b := range map[string][]byte{"addon.py": addonPy, "mitm.py": mitmPy, "mitm.py.lock": mitmLock} {
		os.WriteFile(filepath.Join(dir, f), b, 0o600)
	}
	bin, args := PyCommand(Config{Uvx: "uvx", Python: "3.14", MitmSpec: "mitmproxy==12.3.1", Dir: dir}, "python")
	out, err := exec.Command(bin, append(args, "-c", explainDryScript, dir)...).CombinedOutput()
	if err != nil || !strings.HasSuffix(strings.TrimSpace(string(out)), "ok") {
		t.Errorf("%v\n%s", err, out)
	}
}

const explainDryScript = `import sys, re, types, tempfile
sys.path.insert(0, sys.argv[1])
import addon
from mitmproxy import ctx
from pathlib import Path
ctx.options = types.SimpleNamespace(ignore_hosts=[])
p = Path(tempfile.mkdtemp()) / "r.yaml"
p.write_text(r'''
map_remote:
  - '|(\w+)\.a\.test|https://\1.b.test/'
  - '|x|https://user:PASSMARK@c.test/'
  - '|x|https://[d.test/'
  - '|x|//e.test/'
resolve:
  - "a.test=127.0.0.1:9"
modify_headers:
  - '|~s & ~d ^a\.test$|X-RespDom|v'
mock:
  - match: {url: "http://a.test/graphql", operation: Feed}
    preset: feed
    status: 500
''')
a = addon.Reqcove()
a.allow = [re.compile(r"^(.+\.)?a\.test$")]
a.rules, why = a._load_checked(p)
assert a.rules, why
assert [r["target"] for r in a._list_rules()["rules"] if r["kind"] == "map_remote"] == ["not shown"] * 4, a._list_rules()
e = a._explain({"method": "GET", "url": "http://a.test/"})
assert e["rewrites"] == ["resolve: 127.0.0.1:9"], e
assert e["response_rewrites"] == ["modify_headers response: X-RespDom"], e  # Host kept after resolve, as a real request's
assert a.resolve_sni == {}, a.resolve_sni
e = a._explain({"method": "POST", "url": "http://a.test/graphql"})  # a mock preset off, for one operation
assert [c[:7] for c in e["cannot_tell"]] == ["mock[0]"] and e["if_turned_on"] == {} and e["conditions"], e
e = a._explain({"method": "GET", "url": "http://evil.test/"})
assert not e["in_scope"] and e["loaded"], e  # out of scope, the rules loaded all the same
p.write_text(r'''
keep_host_header: true
map_remote:
  - '|^http://k\.a\.test/|http://k.b.test/'
resolve:
  - {rule: "k.b.test=127.0.0.1:10", preset: kb}
modify_headers:
  - '|~s & ~d ^k\.a\.test$|X-Kept|v'
mock:
  - match: {url: "http://k.a.test/graphql", operation: Feed}
    status: 500
''')
a = addon.Reqcove()
a.allow = [re.compile(r"^(.+\.)?[ab]\.test$")]
a.rules, why = a._load_checked(p)
assert a.rules, why
e = a._explain({"method": "GET", "url": "http://k.a.test/"})
assert e["rewrites"] == ["map_remote"] and e["response_rewrites"] == ["modify_headers response: X-Kept"], e  # keep_host_header
assert e["if_turned_on"] == {"kb": ["map_remote", "resolve preset kb: 127.0.0.1:10", "modify_headers response: X-Kept"]}, e
e = a._explain({"method": "GET", "url": "http://k.a.test/graphql?operationName=Feed", "operation": "Other"})
assert e["mocked"], e  # the URL's operation first, as a real request is read
e = a._explain({"method": "POST", "url": "http://k.a.test/graphql", "operation": "(anonymous)"})
assert not e["mocked"] and e["cannot_tell"] == [] and "no one GraphQL operation" in e["conditions"][0], e
print("ok")
`
