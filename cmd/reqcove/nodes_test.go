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
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "reqcove-home")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", home)
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

func TestNodeName(t *testing.T) {
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

// A new --state gets the default state's CA; one that was used before does not.
func TestRunCopiesCAOnlyIntoANewState(t *testing.T) {
	def := filepath.Join(defaultState(), "mitmproxy")
	os.MkdirAll(def, 0o700)
	defer os.RemoveAll(defaultState())
	for _, name := range capture.CAFiles {
		os.WriteFile(filepath.Join(def, name), []byte(name), 0o600)
	}
	args := func(state string) []string {
		return []string{"--device", "phone", "--state", state, "--uvx", "/usr/bin/false"}
	}
	fresh := filepath.Join(t.TempDir(), ".reqcove-b")
	run(context.Background(), args(fresh))
	if _, err := os.Stat(filepath.Join(fresh, "mitmproxy", "mitmproxy-ca.pem")); err != nil {
		t.Errorf("new state: %v", err)
	}
	used := t.TempDir()
	if unlock, err := openState(used); err != nil { // as a run before made it
		t.Fatal(err)
	} else {
		unlock()
	}
	run(context.Background(), args(used))
	if _, err := os.Stat(filepath.Join(used, "mitmproxy")); err == nil {
		t.Error("a state used before got the CA")
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
	if got := mcpHint("/x/my state's", "reqcove"); got != `claude mcp add reqcove -- reqcove mcp --state '/x/my state'\''s'` {
		t.Errorf("quoted: %q", got)
	}
	cwd, _ := os.Getwd()
	if got := mcpHint("rel", "reqcove"); !strings.HasSuffix(got, "--state "+filepath.Join(cwd, "rel")) {
		t.Errorf("relative: %q", got)
	}
}

// cleanup of a state with the default state's CA says the profile serves both.
func TestCleanupSharedCA(t *testing.T) {
	def := filepath.Join(defaultState(), "mitmproxy")
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
