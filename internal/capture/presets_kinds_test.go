package capture

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestPresetKindsLoad (REQCOVE_E2E=1, mitmproxy's Python): presets of
// map_remote, modify_headers and resolve load from a mapping, share one
// namespace with mocks, are one on per match per kind, take no times, never
// show a value, and the refusals at load hold.
func TestPresetKindsLoad(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	dir := t.TempDir()
	for f, b := range map[string][]byte{"addon.py": addonPy, "mitm.py": mitmPy, "mitm.py.lock": mitmLock} {
		os.WriteFile(filepath.Join(dir, f), b, 0o600)
	}
	bin, args := PyCommand(Config{Uvx: "uvx", Python: "3.14", MitmSpec: "mitmproxy==12.3.1", Dir: dir}, "python")
	out, err := exec.Command(bin, append(args, "-c", presetKindsScript, dir)...).CombinedOutput()
	if err != nil || !strings.HasSuffix(strings.TrimSpace(string(out)), "ok") {
		t.Errorf("%v\n%s", err, out)
	}
}

const presetKindsScript = `import sys, tempfile, os
sys.path.insert(0, sys.argv[1])
import addon
from pathlib import Path
d = tempfile.mkdtemp()
def load(text):
    p = Path(d) / "r.yaml"; p.write_text(text); return addon.load_rules(p)
def refused(text, want):
    try: load(text)
    except ValueError as e:
        assert want in str(e), (want, str(e)); return
    raise AssertionError("accepted: " + want)
r = load('''
map_remote:
  - "|https://api.example.com/|https://plain.example.com/"
  - {rule: "|~d api.example.com|https://api\\\\.example\\\\.com/|https://staging.example.com/", preset: staging, description: to staging}
  - {rule: "|~d api.example.com|https://api\\\\.example\\\\.com/|http://localhost:3000/", preset: dev}
modify_headers:
  - {rule: "/~q/X-Flag/VALUEMARK9", preset: flag}
  - "/~q/X-Lang/ja"
resolve:
  - "staging.example.com=203.0.113.10"
  - {rule: "api.example.com=203.0.113.20", preset: api-a}
  - {rule: "api.example.com=203.0.113.21", preset: api-b}
mock:
  - match: {url: "https://api.example.com/x"}
    preset: mx
    status: 503
''')
b = r["mock"].book
print(sorted(b.names()))
lst = b.control({"op": "list"})["presets"]
for x in lst: print(x["name"], x["kind"], {k: v for k, v in x.items() if k in ("target", "header", "host", "address")})
assert all("X-Flag" not in str(x.get("target")) for x in lst)
assert "VALUEMARK9" not in str(lst)  # no value shown
# one on per match: staging vs dev (same filter + regex)
b.control({"op": "activate", "name": "staging", "seconds": 60})
a = b.control({"op": "activate", "name": "dev", "seconds": 60}); assert a["turned_off"] == ["staging"], a
a = b.control({"op": "activate", "name": "api-a", "seconds": 60}); b.control({"op": "activate", "name": "api-b", "seconds": 60})
assert not b.on("api-a") and b.on("api-b")
assert r["resolve"].target("api.example.com", b) == (("203.0.113.21", None), "api-b")
b.control({"op": "deactivate", "name": "api-b"}); assert r["resolve"].target("api.example.com", b) is None
try: b.control({"op": "activate", "name": "dev", "seconds": 60, "times": 1}); raise SystemExit("times accepted")
except ValueError as e: assert "mocks only" in str(e)
try: b.control({"op": "activate", "name": "dev", "seconds": 60, "kind": "mock"}); raise SystemExit("kind ignored")
except ValueError as e: assert "no mock preset" in str(e), e
assert [x["name"] for x in b.control({"op": "list", "kind": "mock"})["presets"]] == ["mx"]
refused('map_remote:\n  - {rule: "|a|https://u:p@h.example/", preset: x}\n', "no user or password")
refused('map_remote:\n  - {rule: "|(a)|https://\\\\1.example/", preset: x}\n', "written out")
refused('map_remote:\n  - {rule: "|a|http://h.example/", preset: x}\n', "plain http only")
refused('map_remote:\n  - {rule: "|a|/v2/", preset: x}\n', "starts with http")
refused('modify_headers:\n  - {rule: "/~s/X-A/b", preset: x}\n', "requests only")
refused('modify_headers:\n  - {rule: "/~q/X-A/b", preset: x}\n  - "/~q/x-a/c"\n', "same match")
refused('map_remote:\n  - "|a|https://p.example/"\n  - {rule: "|a|https://q.example/", preset: x}\n', "same match")
refused('map_local:\n  - {rule: "|a|/tmp", preset: x}\n', "takes no preset")
refused('resolve:\n  - {rule: "a.example=203.0.113.9", preset: x}\nmock:\n  - match: {url: "https://a.example/"}\n    preset: x\n', "another rule has this preset name")
refused('resolve:\n  - {rule: "a.example=203.0.113.9"}\n', "mapping is for a preset")
refused('resolve:\n  - {rule: "a.example=203.0.113.9", preset: x}\n  - "b.example=203.0.113.9"\n', "target too")
load('map_remote:\n  - {rule: "|a|http://192.168.1.5:3000/", preset: x}\n  - {rule: "|b|http://mac.local/", preset: y}\n')
print("ok")
`

// TestPresetKinds (REQCOVE_E2E=1): a map_remote preset sends requests to its
// target only while on, a resolve preset connects its name only while on, a
// modify_headers preset sets its header only while on; rows list them; a
// reload turns them off.
func TestPresetKinds(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	serve := func(who string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			fmt.Fprintf(w, "%s %s flag=%s", who, r.URL.Path, r.Header.Get("X-Flag"))
		}))
	}
	prod, staging := serve("prod"), serve("staging")
	defer prod.Close()
	defer staging.Close()
	p, s := prod.Listener.Addr().String(), staging.Listener.Addr().String()
	_, sport, _ := strings.Cut(s, ":")
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.yaml")
	write := func(extra string) {
		os.WriteFile(rules, []byte(fmt.Sprintf(`map_remote:
  - {rule: "|http://%[1]s/|http://%[2]s/", preset: staging, description: to staging}
modify_headers:
  - {rule: "|~q|X-Flag|VALUEMARK3", preset: flag}
resolve:
  - {rule: "api.test=127.0.0.1:%[3]s", preset: api-local}
%[4]s`, p, s, sport, extra)), 0o600)
	}
	write("")
	h, err := tryHarness(t, ctx, []string{"127.0.0.1", "api.test"}, func(c *Config) { c.Rules, c.RulesReload = rules, true })
	if err != nil {
		t.Fatal(err)
	}
	hc := h.client("dev")
	get := func(url string, host ...string) string {
		t.Helper()
		req, _ := http.NewRequest("GET", url, nil)
		if len(host) > 0 {
			req.Host = host[0] // as the existing resolve test: dial a real address, name another host
		}
		resp, err := hc.Do(req)
		if err != nil {
			return "error"
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return fmt.Sprintf("%d %s", resp.StatusCode, b)
	}
	ps, err := h.c.Presets(ctx, "")
	if err != nil || len(ps) != 3 {
		t.Fatalf("presets: %+v %v", ps, err)
	}
	for _, x := range ps {
		if strings.Contains(fmt.Sprintf("%+v", x), "VALUEMARK3") {
			t.Errorf("a header value shown: %+v", x)
		}
	}
	if ms, _ := h.c.Presets(ctx, "mock"); len(ms) != 0 {
		t.Errorf("mocks only listed others: %+v", ms)
	}
	if _, err := h.c.Activate(ctx, "staging", "mock", 60, 0); err == nil {
		t.Errorf("activate_mock turned on a map_remote preset")
	}
	if _, err := h.c.Activate(ctx, "staging", "", 60, 1); err == nil || !strings.Contains(err.Error(), "mocks only") {
		t.Errorf("times on map_remote: %v", err)
	}

	if got := get("http://" + p + "/a?n=off"); got != "200 prod /a flag=" {
		t.Errorf("all off: %q", got)
	}
	if got := get("http://"+p+"/r?n=off", "api.test"); !strings.HasPrefix(got, "200 prod /r") {
		t.Errorf("resolve off: %q", got)
	}
	for _, n := range []string{"staging", "flag", "api-local"} {
		if _, err := h.c.Activate(ctx, n, "", 60, 0); err != nil {
			t.Fatalf("activate %s: %v", n, err)
		}
	}
	if got := get("http://" + p + "/a?n=on"); got != "200 staging /a flag=VALUEMARK3" {
		t.Errorf("map_remote and modify_headers on: %q", got)
	}
	f := h.doneFlow("n=on", false)
	if !slices.Contains(f.Presets, "staging") || !slices.Contains(f.Presets, "flag") || f.Preset != "" || f.MappedURL == "" {
		t.Errorf("row: presets %v, preset %q, mapped %q", f.Presets, f.Preset, f.MappedURL)
	}
	if s := strings.Join(f.Rewrites, "; "); !strings.Contains(s, "map_remote preset staging") || !strings.Contains(s, "X-Flag (preset flag)") || strings.Contains(s, "VALUEMARK3") {
		t.Errorf("rewrites: %s", s)
	}
	if got := get("http://"+p+"/r?n=on", "api.test"); !strings.HasPrefix(got, "200 staging /r") {
		t.Errorf("resolve on: %q", got)
	}
	if f := h.doneFlow("/r?n=on", false); !slices.Contains(f.Presets, "api-local") {
		t.Errorf("resolve row: %v %v", f.Presets, f.Rewrites)
	}
	if was, err := h.c.Deactivate(ctx, "staging", ""); !was || err != nil {
		t.Errorf("deactivate: %v %v", was, err)
	}
	if got := get("http://" + p + "/a?n=staging-off"); got != "200 prod /a flag=VALUEMARK3" {
		t.Errorf("map_remote off, flag on: %q", got)
	}
	// A reload turns every preset off.
	write("# changed\n")
	waitFor := func(what, want string) {
		t.Helper()
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(300 * time.Millisecond) {
			if get("http://"+p+"/a?n=reloaded") == want {
				return
			}
		}
		t.Errorf("%s: %q", what, get("http://"+p+"/a?n=reloaded"))
	}
	waitFor("presets still on after a reload", "200 prod /a flag=")
	// So does a change that does not load: the rules before it stay, their presets off.
	h.c.Activate(ctx, "staging", "", 60, 0)
	if got := get("http://" + p + "/a?n=on-again"); !strings.HasPrefix(got, "200 staging") {
		t.Fatalf("on again: %q", got)
	}
	os.WriteFile(rules, []byte("map_remote: [\n"), 0o600)
	waitFor("a preset still on after a file that does not load", "200 prod /a flag=")
}
