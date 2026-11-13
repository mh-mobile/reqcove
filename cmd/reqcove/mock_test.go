package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// printed is what reqcove mock add --print writes (stdin is not a terminal
// under go test: --print works off one).
func printed(t *testing.T, args ...string) string {
	t.Helper()
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	err := mockCmd(context.Background(), append([]string{"add", "--print"}, args...))
	os.Stdout = stdout
	w.Close()
	b, _ := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Values that could end a scalar or a line stay inside their double-quoted
// scalar: each line is one key and a value JSON reads back as given.
var awkward = []string{
	"--url", "https://api.example.com/a\"b: d",
	"--method", "POST",
	"--status", "503",
	"--header", "X-Note: a: b # c \"d\"",
	"--header", "Content-Type: application/json",
	"--body", "{\"k\": \"v\"}\n# not a comment\n- not an item\\ \t\x7f\u0085\u2028\ufeff \u65e5\u672c\u8a9e \U0001F642 'q'",
	"--delay-ms", "10",
	"--preset", "p-1",
	"--description", "says: \"hi\" # there",
}

func TestMockPrint(t *testing.T) {
	out := printed(t, awkward...)
	want := map[string]string{"url": awkward[1], "method": "POST", "X-Note": "a: b # c \"d\"", "Content-Type": "application/json",
		"body": awkward[11], "preset": "p-1", "description": awkward[17]}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 11 || lines[0] != "  - match:" || lines[3] != "    status: 503" || lines[4] != "    headers:" || lines[8] != "    delay_ms: 10" {
		t.Fatalf("%q", out)
	}
	for _, l := range lines {
		k, v, _ := strings.Cut(strings.TrimSpace(l), ": ")
		var key, s string
		if json.Unmarshal([]byte(k), &key) != nil {
			key = k
		}
		if w, ok := want[key]; ok {
			if err := json.Unmarshal([]byte(v), &s); err != nil || s != w {
				t.Errorf("%s: %q read back as %q (%v)", key, v, s, err)
			}
			delete(want, key)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing %v in %q", want, out)
	}
	for _, c := range "\x7f\u0085\u2028\ufeff\t" {
		if strings.ContainsRune(out, c) {
			t.Errorf("%U written as itself", c)
		}
	}
	if err := mockCmd(context.Background(), []string{"add", "--print", "--status", "500"}); err == nil || !strings.Contains(err.Error(), "--url") {
		t.Errorf("no url: %v", err)
	}
	if err := mockCmd(context.Background(), []string{"add", "--print", "--url", "https://a.example/", "--header", "no colon"}); err == nil {
		t.Error("a header without a colon")
	}
	if err := mockCmd(context.Background(), []string{"add", "--print", "--url", "https://a.example/", "--body", "\xff"}); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("not UTF-8: %v", err)
	}
	if err := mockCmd(context.Background(), []string{"remove", "--url", "https://a.example/"}); err == nil {
		t.Error("mock remove")
	}
}

func TestAppendMock(t *testing.T) {
	item := "- match:\n    url: \"https://a.example/\"\n"
	for _, c := range []struct{ name, in, want, err string }{
		{"new file", "", "mock:\n  - match:\n      url: \"https://a.example/\"\n", ""},
		{"no mock key, no newline at the end", "# mine\nmap_remote:\n  - '|a|b'", "# mine\nmap_remote:\n  - '|a|b'\nmock:\n  - match:\n      url: \"https://a.example/\"\n", ""},
		{"mock last, items at 0", "resolve: []\nmock:\n- match: {url: \"https://b.example/\"}\n  status: 1\n# end\n",
			"resolve: []\nmock:\n- match: {url: \"https://b.example/\"}\n  status: 1\n# end\n- match:\n    url: \"https://a.example/\"\n", ""},
		{"mock last, items at 4, comments", "mock:  # mine\n    # first\n    - match: {url: x}\n",
			"mock:  # mine\n    # first\n    - match: {url: x}\n    - match:\n        url: \"https://a.example/\"\n", ""},
		{"mock empty", "mock:\n", "mock:\n  - match:\n      url: \"https://a.example/\"\n", ""},
		{"CRLF", "mock:\r\n  - match: {url: x}\r\n", "mock:\r\n  - match: {url: x}\r\n  - match:\r\n      url: \"https://a.example/\"\r\n", ""},
		{"mock not last", "mock:\n  - match: {url: x}\nresolve: []\n", "", "not the file's last block"},
		{"flow", "mock: []\n", "", "flow style"},
		{"flow with items", "mock: [{match: {url: x}}]  # x\n", "", "flow style"},
		{"flow on the next line", "mock:\n  [{match: {url: x}}]\n", "", "not a block list"},
	} {
		got, err := appendMock(c.in, item)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: %v, %q", c.name, err, got)
			}
		} else if err != nil || got != c.want {
			t.Errorf("%s: %v\n got %q\nwant %q", c.name, err, got, c.want)
		}
	}
}

// fakeRun answers mock.sock's check as a run in state would, after
// checking what it is asked.
func fakeRun(t *testing.T, state string, answer string) chan map[string]any {
	t.Helper()
	os.WriteFile(filepath.Join(state, "socks-secret"), []byte("S3CRET"), 0o600)
	ln, err := net.Listen("unix", filepath.Join(state, capture.ControlSock))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	asked := make(chan map[string]any, 10)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadBytes('\n')
			var req map[string]any
			json.Unmarshal(line, &req)
			if p, _ := req["path"].(string); p != "" {
				b, _ := os.ReadFile(p)
				req["text"] = string(b)
			}
			asked <- req
			c.Write([]byte(answer + "\n"))
			c.Close()
		}
	}()
	return asked
}

func noLeftovers(t *testing.T, dir string, want int) {
	t.Helper()
	if es, _ := os.ReadDir(dir); len(es) != want {
		var names []string
		for _, e := range es {
			names = append(names, e.Name())
		}
		t.Errorf("left in %s: %v", dir, names)
	}
}

func TestMockAdd(t *testing.T) {
	ctx := context.Background()
	state, _ := os.MkdirTemp("/tmp", "rcvk-") // short socket path
	defer os.RemoveAll(state)
	dir, _ := filepath.EvalSymlinks(t.TempDir()) // /var is /private/var on macOS
	path := filepath.Join(dir, "rules.yaml")
	before := "# mine\nmock:\n  - match: {url: \"https://b.example/\"}\n"
	os.WriteFile(path, []byte(before), 0o640)
	item := "- match:\n    url: \"https://a.example/\"\n"

	// Off a terminal: refused, nothing asked or written.
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if err := mockIn(ctx, r, io.Discard, state, "/nonexistent/uvx", path, item); err == nil || !strings.Contains(err.Error(), "only in a terminal") {
		t.Errorf("off a terminal: %v", err)
	}

	// Checked by the running run: refused, the file byte-identical.
	asked := fakeRun(t, state, `{"check": "mock[1]: url must be an http or https URL with a host name", "same": true, "reload": true}`)
	var out strings.Builder
	if err := addMock(ctx, &out, state, "/nonexistent/uvx", path, item); err == nil || !strings.Contains(err.Error(), "mock[1]: url must be") || !strings.Contains(err.Error(), "nothing written") {
		t.Errorf("refused: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != before {
		t.Errorf("refused, yet changed: %q", b)
	}
	noLeftovers(t, dir, 1)
	if len(asked) != 1 {
		t.Fatalf("asked %d times", len(asked))
	}
	req := <-asked
	if req["op"] != "check" || req["secret"] != "S3CRET" || req["target"] != path || filepath.Dir(req["path"].(string)) != dir ||
		req["text"] != before+"  - match:\n      url: \"https://a.example/\"\n" {
		t.Errorf("asked %v", req)
	}
}

func TestMockAddWrites(t *testing.T) {
	ctx := context.Background()
	state, _ := os.MkdirTemp("/tmp", "rcvk-")
	defer os.RemoveAll(state)
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	before := "mock:\n  - match: {url: \"https://b.example/\"}\n"
	os.WriteFile(path, []byte(before), 0o640)
	item := "- match:\n    url: \"https://a.example/\"\n"
	fakeRun(t, state, `{"check": "", "same": true, "reload": true}`)
	var out strings.Builder
	if err := addMock(ctx, &out, state, "/nonexistent/uvx", path, item); err != nil || !strings.Contains(out.String(), "at once") {
		t.Fatalf("%v %q", err, out.String())
	}
	b, _ := os.ReadFile(path)
	st, _ := os.Stat(path)
	if string(b) != before+"  - match:\n      url: \"https://a.example/\"\n" || st.Mode().Perm() != 0o640 {
		t.Errorf("%q %v", b, st.Mode())
	}
	noLeftovers(t, dir, 1)

	// Through a link: the file it names gets the mock; the link stays.
	link := filepath.Join(t.TempDir(), "link.yaml")
	os.Symlink(path, link)
	if err := addMock(ctx, &out, state, "/nonexistent/uvx", link, item); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the link was replaced")
	}
}

// Without a run (or with one too old to check), mitmproxy's Python checks:
// with no uv there, nothing is written, a new file not made.
func TestMockAddNoCheck(t *testing.T) {
	ctx := context.Background()
	for _, older := range []bool{false, true} {
		state, _ := os.MkdirTemp("/tmp", "rcvk-")
		defer os.RemoveAll(state)
		if older {
			fakeRun(t, state, `{"error": "no presets: the --rules file marks no rule with preset:"}`)
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "rules.yaml")
		var out strings.Builder
		err := addMock(ctx, &out, state, "/nonexistent/uvx", path, "- match:\n    url: \"https://a.example/\"\n")
		if err == nil || !strings.Contains(err.Error(), "could not be checked") || !strings.Contains(out.String(), "without --allow-hosts") {
			t.Errorf("older %v: %v %q", older, err, out.String())
		}
		if es, _ := os.ReadDir(dir); len(es) != 0 {
			t.Errorf("older %v: left %v", older, es)
		}

		// Checked by Python instead: written, and when it takes effect said
		// for a run that may take it at once too.
		checkPython = func(context.Context, capture.Config, string) (string, error) { return "", nil }
		out.Reset()
		err = addMock(ctx, &out, state, "/nonexistent/uvx", path, "- match:\n    url: \"https://a.example/\"\n")
		checkPython = capture.CheckRulesPython
		if st, _ := os.Stat(path); err != nil || st == nil || st.Mode().Perm() != 0o600 {
			t.Errorf("older %v: %v %v", older, err, st)
		}
		if at := strings.Contains(out.String(), "it takes it at once, which turns every preset that is on off"); at != older {
			t.Errorf("older %v: %q", older, out.String())
		}
	}
}

// TestMockAddPython (REQCOVE_E2E=1, mitmproxy's Python): the addon's loader
// reads each awkward value back as given, and refuses a bad mock.
func TestMockAddPython(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx := context.Background()
	state := t.TempDir() // no run there
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	body := filepath.Join(dir, "b.json")
	os.WriteFile(body, []byte("{}"), 0o600)
	item := printed(t, awkward...)
	item = strings.ReplaceAll(strings.TrimPrefix(item, "  "), "\n  ", "\n")
	var out strings.Builder
	if err := addMock(ctx, &out, state, "uvx", path, item); err != nil {
		t.Fatalf("%v %q", err, out.String())
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("new file: %v", st.Mode())
	}
	src := t.TempDir()
	for _, f := range []string{"addon.py", "mitm.py", "mitm.py.lock"} {
		b, _ := os.ReadFile("../../internal/capture/" + f)
		os.WriteFile(filepath.Join(src, f), b, 0o600)
	}
	bin, args := capture.PyCommand(capture.Config{Uvx: "uvx", Python: defaultPython, MitmSpec: defaultMitmSpec, Dir: src}, "python")
	script := `import sys, json
sys.path.insert(0, sys.argv[1])
import addon
m = addon.load_rules(sys.argv[2])["mock"]
method, url, op, status, hs, body, preset, description, delay, fault = m.replacements[0]
print(json.dumps({"method": method, "status": status, "headers": {k.decode(): v.decode() for k, v in hs}, "body": body.decode(), "preset": preset, "description": description, "delay": delay}))
`
	cmd := exec.Command(bin, append(args, "-c", script, src, path)...)
	cmd.Dir = src
	b, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Method, Body, Preset, Description string
		Status, Delay                     int
		Headers                           map[string]string
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	json.Unmarshal([]byte(lines[len(lines)-1]), &got)
	if got.Method != "POST" || got.Status != 503 || got.Body != awkward[11] || got.Preset != "p-1" || got.Description != awkward[17] || got.Delay != 10 ||
		got.Headers["X-Note"] != "a: b # c \"d\"" || got.Headers["Content-Type"] != "application/json" {
		t.Errorf("%+v", got)
	}

	// A body_file, relative to where it was typed; then a bad status, refused.
	wd, _ := os.Getwd()
	os.Chdir(dir)
	item = strings.ReplaceAll(strings.TrimPrefix(printed(t, "--url", "https://c.example/", "--body-file", "b.json"), "  "), "\n  ", "\n")
	os.Chdir(wd)
	if err := addMock(ctx, &out, state, "uvx", path, item); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := addMock(ctx, &out, state, "uvx", path, "- match:\n    url: \"https://d.example/\"\n  status: 700\n"); err == nil || !strings.Contains(err.Error(), "mock[2]: status must be") {
		t.Errorf("bad status: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("refused, yet changed")
	}
	noLeftovers(t, dir, 2) // rules.yaml and b.json
}
