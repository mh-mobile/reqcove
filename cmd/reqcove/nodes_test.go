package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// TestMain gives the tests a HOME of their own: run copies the CA of the
// default state (~/.reqcove) into new ones, and must not take the real one.
var testHome string

func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "reqcove-home")
	if err != nil {
		panic(err)
	}
	testHome = home
	os.Setenv("HOME", home)
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

// tempDefaultState is defaultState(), once sure it is under the tests' own
// HOME: the real ~/.reqcove holds the keys the iPhone trusts.
func tempDefaultState(t *testing.T) string {
	t.Helper()
	if testHome == "" || !strings.HasPrefix(defaultState(), testHome+string(filepath.Separator)) {
		t.Fatalf("defaultState() %s is not under the tests' HOME %q", defaultState(), testHome)
	}
	return defaultState()
}

func TestNodeName(t *testing.T) {
	used := filepath.Join(t.TempDir(), ".reqcove-old")
	os.MkdirAll(filepath.Join(used, "tsnet"), 0o700)
	os.WriteFile(filepath.Join(used, "tsnet", "tailscaled.state"), nil, 0o600)
	dot := "."
	c := filepath.Join(t.TempDir(), "reqcove-c")
	os.Mkdir(c, 0o700)
	t.Chdir(c)
	for _, c := range []struct {
		args  []string
		state string
		want  string
	}{
		{nil, defaultState(), "reqcove"},
		{nil, "/x/.reqcove-staging", "reqcove-staging"},
		{nil, "/x/reqcove-B/", "reqcove-b"},
		{nil, "/x/.reqcove", "reqcove"},
		{nil, "/x/staging", "reqcove"},          // not named reqcove-…
		{nil, "/x/.reqcove_staging", "reqcove"}, // not a DNS label
		{nil, "/x/.reqcove-", "reqcove"},        // ends with a dash
		{[]string{"--hostname", "mine"}, "/x/.reqcove-staging", "mine"},
		{[]string{"--hostname", "reqcove"}, "/x/.reqcove-staging", "reqcove"}, // kept as it was
		{nil, used, "reqcove"},                                                // an older reqcove's state: its name then
		{nil, dot, "reqcove-c"},                                               // "." is the directory too
	} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.String("hostname", "reqcove", "")
		fs.Parse(c.args)
		if got := nodeName(fs, c.state); got != c.want {
			t.Errorf("%v %s: %q, want %q", c.args, c.state, got, c.want)
		}
	}
}

func TestPickWebPort(t *testing.T) {
	old := webPorts
	defer func() { webPorts = old }()
	webPorts = nil
	for i := range 3 { // ports of its own, so a reqcove running here does not matter
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		webPorts = append(webPorts, l.Addr().(*net.TCPAddr).Port)
		if i < 2 { // the first two held, as by other runs
			defer l.Close()
		} else {
			l.Close()
		}
	}
	if p, err := pickWebPort(); err != nil || p != webPorts[2] {
		t.Errorf("got %d %v, want %d", p, err, webPorts[2])
	}
}

// A --state without a CA gets the default state's, new or opened before (a
// copy that failed, say); one with its own keeps it; an incomplete default
// CA stops run with why, copying nothing.
func TestRunCopiesCA(t *testing.T) {
	def := filepath.Join(tempDefaultState(t), "mitmproxy")
	os.MkdirAll(def, 0o700)
	defer os.RemoveAll(defaultState())
	for _, name := range capture.CAFiles {
		os.WriteFile(filepath.Join(def, name), []byte(name), 0o600)
	}
	args := func(state string) []string {
		return []string{"--device", "phone", "--state", state, "--uvx", "/usr/bin/false"}
	}
	key := func(state string) string {
		b, _ := os.ReadFile(filepath.Join(state, "mitmproxy", "mitmproxy-ca.pem"))
		return string(b)
	}
	fresh := filepath.Join(t.TempDir(), ".reqcove-b")
	run(context.Background(), args(fresh))
	if key(fresh) != "mitmproxy-ca.pem" {
		t.Errorf("new state: %q", key(fresh))
	}
	if b, _ := os.ReadFile(filepath.Join(defaultState(), caCopies)); !strings.Contains(string(b), filepath.Join(fresh, "mitmproxy")) {
		t.Errorf("%s: %q", caCopies, b)
	}
	opened := t.TempDir()
	if unlock, err := openState(opened); err != nil { // a run before that got no CA
		t.Fatal(err)
	} else {
		unlock()
	}
	run(context.Background(), args(opened))
	if key(opened) != "mitmproxy-ca.pem" {
		t.Errorf("state opened before, without a CA: %q", key(opened))
	}
	own := t.TempDir()
	os.MkdirAll(filepath.Join(own, "mitmproxy"), 0o700)
	os.WriteFile(filepath.Join(own, "mitmproxy", "mitmproxy-ca.pem"), []byte("own"), 0o600)
	os.WriteFile(filepath.Join(own, stateMarker), nil, 0o600)
	run(context.Background(), args(own))
	if key(own) != "own" {
		t.Errorf("state with its own CA: %q", key(own))
	}
	os.Remove(filepath.Join(def, "mitmproxy-ca-cert.cer"))
	broken := t.TempDir()
	if err := run(context.Background(), args(broken)); err == nil || !strings.Contains(err.Error(), "no mitmproxy-ca-cert.cer") {
		t.Errorf("incomplete default CA: %v", err)
	}
	if exists(filepath.Join(broken, "mitmproxy", "mitmproxy-ca-cert.pem")) {
		t.Error("part of an incomplete CA was copied")
	}
}

// --state=~/x leaves the ~ to reqcove (the shell expands it only after a
// space): refused, and nothing made, rather than a ./~/x holding a CA's key.
func TestStateTildeRefused(t *testing.T) {
	t.Chdir(t.TempDir())
	err := run(context.Background(), []string{"--device", "phone", "--state=~/x", "--uvx", "/usr/bin/false"})
	if err == nil || !strings.Contains(err.Error(), "--state ~/x") {
		t.Errorf("got %v", err)
	}
	if exists("~") {
		t.Error("./~ was made")
	}
}

// The name run gave the node is kept, so the next run and cleanup use it.
func TestNodeNameKept(t *testing.T) {
	state := filepath.Join(t.TempDir(), "staging")
	run(context.Background(), []string{"--device", "phone", "--hostname", "foo", "--state", state, "--uvx", "/usr/bin/false"})
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("hostname", "reqcove", "")
	if got := nodeName(fs, state); got != "foo" {
		t.Errorf("kept name: %q", got)
	}
	old := security
	defer func() { security = old }()
	security = func(...string) error { return fmt.Errorf("not trusted") }
	if out := captureStdout(t, func() error { return cleanup([]string{"--state", state}) }); !strings.Contains(out, `remove "foo"`) {
		t.Errorf("cleanup:\n%s", out)
	}
}

// --local-proxy's port taken: run stops before it makes the state directory,
// starts mitmproxy or touches the system proxy or the Simulators.
func TestLocalProxyTakenStopsFirst(t *testing.T) {
	if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localProxyPort)); err == nil {
		defer l.Close()
	} // else a reqcove running here has it: taken all the same
	state := filepath.Join(t.TempDir(), "x")
	err := run(context.Background(), []string{"--local-proxy", "--state", state, "--uvx", "/usr/bin/false"})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("127.0.0.1:%d is taken", localProxyPort)) {
		t.Errorf("got %v", err)
	}
	if _, err := os.Stat(state); err == nil {
		t.Error("the state directory was made")
	}
}

func TestMcpHint(t *testing.T) {
	if got := mcpHint(defaultState(), "reqcove"); got != "claude mcp add reqcove -- reqcove mcp" {
		t.Errorf("default: %q", got)
	}
	if got := mcpHint("/x/.reqcove-b", "reqcove-b"); got != "claude mcp add reqcove-b -- reqcove mcp --state /x/.reqcove-b" {
		t.Errorf("another: %q", got)
	}
	if got := mcpHint("/x/my state's", "my node"); got != `claude mcp add 'my node' -- reqcove mcp --state '/x/my state'\''s'` {
		t.Errorf("quoted: %q", got)
	}
	if got := mcpHint("/x/staging", "reqcove"); got != "claude mcp add reqcove-staging -- reqcove mcp --state /x/staging" { // not the default node's name
		t.Errorf("named reqcove: %q", got)
	}
	cwd, _ := os.Getwd()
	if got := mcpHint("rel", "reqcove-r"); !strings.HasSuffix(got, "--state "+filepath.Join(cwd, "rel")) {
		t.Errorf("relative: %q", got)
	}
}

// cleanup of a state with the default state's CA says the profile serves both.
func TestCleanupSharedCA(t *testing.T) {
	def := filepath.Join(tempDefaultState(t), "mitmproxy")
	os.MkdirAll(def, 0o700)
	defer os.RemoveAll(defaultState())
	pem := testCAPEM(t)
	os.WriteFile(filepath.Join(def, "mitmproxy-ca-cert.pem"), pem, 0o600)
	other := filepath.Join(t.TempDir(), ".reqcove-b")
	os.MkdirAll(filepath.Join(other, "mitmproxy"), 0o700)
	os.WriteFile(filepath.Join(other, "mitmproxy", "mitmproxy-ca-cert.pem"), pem, 0o600)
	old := security
	defer func() { security = old }()
	security = func(...string) error { return fmt.Errorf("not trusted") } // this Mac's keychain left alone
	out := captureStdout(t, func() error { return cleanup([]string{"--state", other}) })
	for _, want := range []string{"It is the CA of " + defaultState(), `remove "reqcove-b"`, "reqcove cleanup --delete-state --state " + other} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if out := captureStdout(t, func() error { return cleanup(nil) }); strings.Contains(out, "It is the CA of") || strings.Contains(out, "--state") {
		t.Errorf("the default state's own cleanup:\n%s", out)
	}
}

// The commands printed for a node of another --state carry it.
func TestCommandsCarryState(t *testing.T) {
	if got := withState("reqcove status", defaultState()); got != "reqcove status" {
		t.Errorf("default: %q", got)
	}
	if got := readyBlock(map[string]string{"n1": "iphone"}, "", "", "/x/.reqcove-b", nil); !strings.Contains(got, "`reqcove status --state /x/.reqcove-b` says") {
		t.Errorf("ready block:\n%s", got)
	}
	other := filepath.Join(t.TempDir(), ".reqcove-b")
	out := captureStdout(t, func() error { return offlineStatus(other, "/nonexistent/uvx") })
	for _, want := range []string{"`reqcove run --state " + other + "` will ask", "reqcove run --device NAME --allow-hosts api.example.com --state " + other} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
}

func TestNodeWebLink(t *testing.T) {
	got := nodeWebLink("http://127.0.0.1:8091/?token=T", "127.0.0.1:8091", "100.1.2.3")
	if got != "http://100.1.2.3:8081/?token=T" { // the node's port, whatever mitmweb's here
		t.Errorf("got %q", got)
	}
}

// The default state's cleanup names the states holding a copy of its CA.
func TestCleanupNamesCACopies(t *testing.T) {
	def := filepath.Join(tempDefaultState(t), "mitmproxy")
	os.MkdirAll(def, 0o700)
	defer os.RemoveAll(defaultState())
	pem := testCAPEM(t)
	os.WriteFile(filepath.Join(def, "mitmproxy-ca-cert.pem"), pem, 0o600)
	copy, gone, other := t.TempDir(), t.TempDir(), t.TempDir()
	for _, d := range []string{copy, other} {
		os.MkdirAll(filepath.Join(d, "mitmproxy"), 0o700)
	}
	os.WriteFile(filepath.Join(copy, "mitmproxy", "mitmproxy-ca-cert.pem"), pem, 0o600)
	os.WriteFile(filepath.Join(other, "mitmproxy", "mitmproxy-ca-cert.pem"), testCAPEM(t), 0o600) // its own CA since
	for _, d := range []string{copy, gone, other, copy} {
		noteCACopy(filepath.Join(d, "mitmproxy"))
	}
	os.RemoveAll(gone)
	old := security
	defer func() { security = old }()
	security = func(...string) error { return fmt.Errorf("not trusted") }
	out := captureStdout(t, func() error { return cleanup(nil) })
	if strings.Count(out, "holds a copy of this CA") != 1 || !strings.Contains(out, copy+" holds a copy") {
		t.Errorf("cleanup:\n%s", out)
	}
}
