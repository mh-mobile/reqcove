package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMain gives the tests a HOME of their own: run copies the CA of the
// default state (~/.reqcove) into new ones, and must not take the real one.
var testHome string

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

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
	kept := filepath.Join(t.TempDir(), ".reqcove-kept") // made by this version: node-name, and tsnet's state after its first start
	os.MkdirAll(filepath.Join(kept, "tsnet"), 0o700)
	os.WriteFile(filepath.Join(kept, "tsnet", "tailscaled.state"), nil, 0o600)
	os.WriteFile(filepath.Join(kept, nodeNameFile), []byte("reqcove-kept\n"), 0o600)
	edited := t.TempDir()
	os.WriteFile(filepath.Join(edited, nodeNameFile), []byte("  mine \nsecond line\n"), 0o600)
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
		{nil, "/x/reqcovex", "reqcove"},         // not reqcove-…
		{nil, "/x/.reqcove_staging", "reqcove"}, // not a DNS label
		{nil, "/x/.reqcove-", "reqcove"},        // ends with a dash
		{[]string{"--hostname", "mine"}, "/x/.reqcove-staging", "mine"},
		{[]string{"--hostname", "reqcove"}, "/x/.reqcove-staging", "reqcove"}, // kept as it was
		{nil, used, "reqcove"},                                                // an older reqcove's state: its name then
		{nil, kept, "reqcove-kept"},                                           // the kept name before that rule
		{nil, edited, "mine"},                                                 // the first line only
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
	t.Chdir(t.TempDir())
	run(context.Background(), args(".reqcove-b")) // relative: ca-copies must not be
	fresh, _ := filepath.Abs(".reqcove-b")
	if key(fresh) != "mitmproxy-ca.pem" {
		t.Errorf("new state: %q", key(fresh))
	}
	if b, _ := os.ReadFile(filepath.Join(defaultState(), caCopies)); string(b) != filepath.Join(fresh, "mitmproxy")+"\n" {
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
	os.WriteFile(filepath.Join(own, "mitmproxy", "mitmproxy-ca-cert.pem"), []byte("own"), 0o600) // a CA: key and certificate
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
	os.MkdirAll(filepath.Join("~", "x"), 0o700) // a ./~/x that cleanup must not take for the state, nor call gone
	os.WriteFile(filepath.Join("~", "x", stateMarker), nil, 0o600)
	ctx := context.Background()
	for name, cmd := range map[string]func() error{
		"run":     func() error { return run(ctx, []string{"--device", "phone", "--state=~/y", "--uvx", "/usr/bin/false"}) },
		"cleanup": func() error { return cleanup([]string{"--state=~/x", "--delete-state"}) },
		"status":  func() error { return status(ctx, []string{"--state=~/x"}) },
		"har":     func() error { return har(ctx, []string{"--state=~/x"}) },
		"mcp":     func() error { return runMCP(ctx, []string{"--state", "~/x"}, nil) },
	} {
		if err := cmd(); err == nil || !strings.Contains(err.Error(), "the shell did not expand the ~") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if exists(filepath.Join("~", "y")) || !exists(filepath.Join("~", "x")) {
		t.Error("./~/y was made, or ./~/x deleted")
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
	t.Setenv("REQCOVE_CONTAINER", "1")
	host, _ := os.Hostname()
	defer func(p, d string) { podmanEnvFile, dockerEnvFile = p, d }(podmanEnvFile, dockerEnvFile)
	marker := filepath.Join(t.TempDir(), "marker")
	os.WriteFile(marker, nil, 0o600)
	for _, c := range []struct{ podman, docker, engine string }{
		{marker, "/nonexistent", "podman run"},
		{"/nonexistent", marker, "docker run"},
		{marker, marker, "podman run"}, // Podman's own marker first
		{"/nonexistent", "/nonexistent", "docker run"},
	} {
		podmanEnvFile, dockerEnvFile = c.podman, c.docker
		if got := mcpHint(defaultState(), "reqcove"); got != "claude mcp add "+shellWord(host)+" -- "+c.engine+" -i --rm --network none --log-driver none --volumes-from "+shellWord(host)+" reqcove mcp" {
			t.Errorf("in a container (%+v): %q", c, got)
		}
	}
	podmanEnvFile, dockerEnvFile = "/nonexistent", "/nonexistent"
	if got := containerEngineNote(); got != "; under Podman, podman run in place of docker run" {
		t.Errorf("engine unknown: %q", got)
	}
	podmanEnvFile = marker
	if got := containerEngineNote(); got != "" {
		t.Errorf("podman: %q", got)
	}
	os.Unsetenv("REQCOVE_CONTAINER")
	if got := mcpHint(defaultState(), "reqcove"); got != "claude mcp add reqcove -- reqcove mcp" {
		t.Errorf("default: %q", got)
	}
	if got := mcpHint("/x/.reqcove-b", "reqcove-b"); got != "claude mcp add reqcove-b -- reqcove mcp --state /x/.reqcove-b" {
		t.Errorf("another: %q", got)
	}
	// Claude Code takes letters, digits, - and _ in the name; the path is quoted.
	if got := mcpHint("/x/my state's", "my node.v2"); got != `claude mcp add my-node-v2 -- reqcove mcp --state '/x/my state'\''s'` {
		t.Errorf("quoted: %q", got)
	}
	if got := mcpHint("/x/my-stage", "ステージ"); !strings.HasPrefix(got, "claude mcp add reqcove-my-stage -- ") { // nothing of the name left
		t.Errorf("non-ASCII name: %q", got)
	}
	if got := mcpHint("/x/ステージ", "ステージ"); !strings.HasPrefix(got, "claude mcp add reqcove-node -- ") {
		t.Errorf("non-ASCII name and state: %q", got)
	}
	for state, want := range map[string]string{"/x/staging": "reqcove-staging", "/x/.staging": "reqcove-staging", "/x/my stage": "reqcove-my-stage"} { // not the default node's name
		if got := mcpHint(state, "reqcove"); !strings.HasPrefix(got, "claude mcp add "+want+" -- ") {
			t.Errorf("%s named reqcove: %q", state, got)
		}
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
	if got := readyBlock(map[string]string{"n1": "iphone"}, "", "", "", "", "/x/.reqcove-b", nil, true, nil, nil); !strings.Contains(got, "`reqcove status --state /x/.reqcove-b` says") {
		t.Errorf("ready block:\n%s", got)
	}
	other := filepath.Join(t.TempDir(), ".reqcove-b")
	out := captureStdout(t, func() error { return offlineStatus(other, "/nonexistent/uvx") })
	if !strings.Contains(out, "never started here") {
		t.Errorf("no state yet:\n%s", out)
	}
	// tsnet writes its machine key before any login, the profiles after one.
	os.MkdirAll(filepath.Join(other, "tsnet"), 0o700)
	for state, want := range map[string]string{
		`{"_machinekey":"bWtleQ=="}`:                                "not logged in yet",
		`{"_machinekey":"bWtleQ==","_profiles":"e30="}`:             "not logged in yet",    // {}: logged out
		`{"_machinekey":"bWtleQ==","_profiles":"eyJhYmNkIjp7fX0="}`: "has logged in before", // {"abcd":{}}
		`not json`: "not logged in yet",
	} {
		os.WriteFile(filepath.Join(other, "tsnet", "tailscaled.state"), []byte(state), 0o600)
		if out := captureStdout(t, func() error { return offlineStatus(other, "/nonexistent/uvx") }); !strings.Contains(out, "node:  "+want) {
			t.Errorf("%s: no %q in\n%s", state, want, out)
		}
	}
	os.RemoveAll(filepath.Join(other, "tsnet"))
	for _, want := range []string{"`reqcove run --state " + other + "` will ask", "reqcove run --device NAME --allow-hosts api.example.com --state " + other, "the first `reqcove run --state " + other + "` copies"} {
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

// har's error names the node's run, with its --state.
func TestHarCarriesState(t *testing.T) {
	other := t.TempDir()
	if err := har(context.Background(), []string{"--state", other}); err == nil || !strings.Contains(err.Error(), "reqcove run --state "+other) {
		t.Errorf("got %v", err)
	}
}

// A key without its certificate files is a CA all the same (the iPhone may
// trust it): never replaced by the default's.
func TestKeyNeverReplaced(t *testing.T) {
	def := filepath.Join(tempDefaultState(t), "mitmproxy")
	os.MkdirAll(def, 0o700)
	defer os.RemoveAll(defaultState())
	for _, name := range capture.CAFiles {
		os.WriteFile(filepath.Join(def, name), []byte(name), 0o600)
	}
	keyOnly := t.TempDir()
	os.MkdirAll(filepath.Join(keyOnly, "mitmproxy"), 0o700)
	os.WriteFile(filepath.Join(keyOnly, "mitmproxy", "mitmproxy-ca.pem"), []byte("trusted key"), 0o600)
	os.WriteFile(filepath.Join(keyOnly, stateMarker), nil, 0o600)
	run(context.Background(), []string{"--device", "phone", "--state", keyOnly, "--uvx", "/usr/bin/false"})
	if b, _ := os.ReadFile(filepath.Join(keyOnly, "mitmproxy", "mitmproxy-ca.pem")); string(b) != "trusted key" {
		t.Errorf("key replaced: %q", b)
	}
}

// The commands printed carry the --state as a full path (the same in another
// terminal), and the errors of mcp and cleanup name the node's run.
func TestStateCommandsFull(t *testing.T) {
	t.Chdir(t.TempDir())
	os.Mkdir("rel", 0o700)
	full, _ := filepath.Abs("rel")
	if got := withState("reqcove status", "rel"); got != "reqcove status --state "+full {
		t.Errorf("withState: %q", got)
	}
	// reqcove mcp --state rel, with no run there: its tools say which run to start.
	ct, at := mcp.NewInMemoryTransports()
	mctx, mcancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runMCP(mctx, []string{"--state", "rel"}, at) }()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(mctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cs.CallTool(mctx, &mcp.CallToolParams{Name: "status"})
	if err != nil || !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "reqcove run … --state "+full) || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "Do not start it yourself") {
		t.Errorf("mcp's not running: %v %+v", err, res)
	}
	mcancel() // a signal: not an error
	if err := <-done; err != nil {
		t.Errorf("runMCP on a signal: %v", err)
	}
	unlock, err := openState("rel")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := cleanup([]string{"--state", "rel", "--delete-state"}); err == nil || !strings.Contains(err.Error(), "stop `reqcove run --state "+full) {
		t.Errorf("cleanup while running: %v", err)
	}
}

// A HOME starting with ~ is said to be HOME's, not a --state the user gave.
func TestHomeTilde(t *testing.T) {
	t.Setenv("HOME", "~/h")
	if err := status(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "HOME is ~/h") {
		t.Errorf("got %v", err)
	}
}

// Another --state's notes: --hostname only when a tailnet node has a name
// (--lan refuses it).
func TestStateNotes(t *testing.T) {
	if got := strings.Join(stateNotes("/x/b", "reqcove", false), "\n"); !strings.Contains(got, "give --hostname") || !strings.Contains(got, "reqcove status --state /x/b") {
		t.Errorf("tailnet: %s", got)
	}
	if got := strings.Join(stateNotes("/x/b", "reqcove", true), "\n"); strings.Contains(got, "hostname") || !strings.Contains(got, "reqcove status --state /x/b") {
		t.Errorf("--lan: %s", got)
	}
	if got := stateNotes(defaultState(), "reqcove", false); len(got) != 0 {
		t.Errorf("default state: %q", got)
	}
}

// A status, har or mark asking whether a run is starting (stateHeld) holds
// the lock shared for a moment: a run taking it then waits that out instead
// of exiting with "another reqcove is using"; a run holding it still refuses
// another. A cleanup --delete-state that took the lock file away meanwhile
// leaves the waiting run nothing to lock.
func TestLockStateWaitsOutACheck(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(100*time.Millisecond, func() { f.Close() })
	unlock, err := lockState(dir)
	if err != nil {
		t.Fatalf("with a check's shared lock: %v", err)
	}
	if _, err := lockState(dir); err == nil || !strings.Contains(err.Error(), "another reqcove") {
		t.Errorf("with a run's lock: %v", err)
	}
	time.AfterFunc(100*time.Millisecond, func() { os.Remove(filepath.Join(dir, "lock")); unlock() })
	if _, err := lockState(dir); err == nil || !strings.Contains(err.Error(), "deleted") {
		t.Errorf("its lock file deleted meanwhile: %v", err)
	}
}
