package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"golang.org/x/net/proxy"
)

// saveFiles writes a hosts file and a config reading it (with conf more
// lines), and returns their paths.
func saveFiles(t *testing.T, dir, hosts, conf string) (hostsFile, config string) {
	t.Helper()
	hostsFile, config = filepath.Join(dir, "hosts"), filepath.Join(dir, "config")
	if err := os.WriteFile(hostsFile, []byte(hosts), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("--allow-hosts=@"+hostsFile+"\n"+conf), 0o600); err != nil {
		t.Fatal(err)
	}
	return hostsFile, config
}

// run remembers where its hosts came from: the hosts file, the --config
// file's own hosts, the command line's, a host in the file too included.
func TestRunHostsOrigin(t *testing.T) {
	dir := t.TempDir()
	hostsFile, config := saveFiles(t, dir, "# mine\napi.a.com\nboth.c.com\n", "--allow-hosts=conf.d.com\n")
	o, err := parseRunFlags([]string{"--config", config, "--device", "x", "--state", filepath.Join(dir, "s"), "--allow-hosts", "CLI.c.com,both.c.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(o.origin.files, []string{hostsFile}) {
		t.Errorf("files %q", o.origin.files)
	}
	if want := map[string]string{"cli.c.com": "the command line", "both.c.com": "the command line", "conf.d.com": "the --config file"}; !maps.Equal(o.origin.given, want) || !o.origin.inFiles["both.c.com"] || o.origin.inFiles["cli.c.com"] {
		t.Errorf("given %q, want %q; in files %v", o.origin.given, want, o.origin.inFiles)
	}
	if !slices.Equal(o.allow.Hosts, []string{"api.a.com", "both.c.com", "conf.d.com", "cli.c.com", "both.c.com"}) {
		t.Errorf("allow %q", o.allow.Hosts)
	}
	// @~/ and a relative @FILE: the file's absolute path.
	t.Chdir(dir)
	o, err = parseRunFlags([]string{"--device", "x", "--state", filepath.Join(dir, "s"), "--allow-hosts", "@hosts"})
	if err != nil || !slices.Equal(o.origin.files, []string{hostsFile}) || len(o.origin.given) != 0 {
		t.Errorf("relative: %v, %+v", err, o.origin)
	}
}

// saveOf is saveScope for a run of args (config: its --config file, "" for
// none) whose hosts came from o.
func saveOf(base capture.HostRules, o hostsOrigin, config, confirm string, args ...string) (ctlAnswer, bool) {
	return saveScope(base, &ctlState{o: &runOpts{config: config, args: args}, origin: o}, confirm)
}

// capture save writes the base minus the hosts given as they are (but those
// in the file too), keeping the file's comments; a host given on the command
// line and removed now, in the file too or not, is named as coming back; a
// run started from flags alone does not save its hosts passed undecrypted.
// The last host removed: a file without hosts. Refused: "*", a file left
// without hosts that the next start refuses (--rules), a file not plain or
// not this user's, no hosts file (and no config) or several, the --pass-hosts
// file.
func TestSaveHosts(t *testing.T) {
	dir := t.TempDir()
	hostsFile, _ := saveFiles(t, dir, "# mine\napi.a.com # the app\nold.b.com\nboth.c.com\n\n", "")
	args := []string{"--device", "x", "--state", filepath.Join(dir, "s"), "--allow-hosts", "@" + hostsFile}
	origin := hostsOrigin{files: []string{hostsFile}, inFiles: map[string]bool{"api.a.com": true, "old.b.com": true, "both.c.com": true},
		given: map[string]string{"cli.c.com": "the command line", "gone.c.com": "the command line", "both.c.com": "the command line", "conf.d.com": "the --config file"}}
	base, _ := capture.ParseAllowHosts([]string{"api.a.com,cli.c.com,new.c.com,conf.d.com"})
	base, _ = base.WithPass([]string{"api.a.com"})
	a, saved := saveOf(base, origin, "", "", args...)
	if !a.OK || !saved {
		t.Fatal(a.Message)
	}
	for _, want := range []string{
		"saved to " + hostsFile + ": api.a.com, new.c.com",
		"not written, as given on the command line (a start with it records them again): cli.c.com",
		"removed now, but given on the command line, so a start with it records them again: both.c.com, gone.c.com",
		"not written, as given on the --config file (a start with it records them again): conf.d.com",
		"the hosts passed undecrypted are not saved: no --config file",
	} {
		if !strings.Contains(a.Message, want) {
			t.Errorf("%q, want %q in it", a.Message, want)
		}
	}
	b, _ := os.ReadFile(hostsFile)
	if string(b) != "# mine\napi.a.com # the app\n\nnew.c.com\n" {
		t.Errorf("file:\n%s", b)
	}
	if fi, _ := os.Stat(hostsFile); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Errorf("left behind: %v", ents)
	}
	// Given on the command line and in the file, still recorded: it stays in the file.
	kept, _ := capture.ParseAllowHosts([]string{"api.a.com,both.c.com"})
	if a, _ := saveOf(kept, origin, "", "", args...); !strings.HasPrefix(a.Message, "saved to "+hostsFile+": api.a.com, both.c.com;") || strings.Contains(a.Message, "not written, as given on the command line (a start with it records them again): both") {
		t.Errorf("kept: %q", a.Message)
	}

	refused := func(what string, base capture.HostRules, o hostsOrigin, want string, args ...string) {
		t.Helper()
		before, _ := os.ReadFile(hostsFile)
		if a, saved := saveOf(base, o, "", "", args...); a.OK || saved || !strings.Contains(a.Message, want) || !strings.HasSuffix(a.Message, "nothing written") {
			t.Errorf("%s: %q, want %q", what, a.Message, want)
		}
		if after, _ := os.ReadFile(hostsFile); string(after) != string(before) {
			t.Errorf("%s: the file changed:\n%s", what, after)
		}
	}
	all, _ := capture.ParseAllowHosts([]string{"*"})
	refused("*", all, origin, `refused: this run records every host ("*")`)
	allAndMine, _ := capture.ParseAllowHosts([]string{"*,api.a.com"})
	refused("* given on the command line", allAndMine, hostsOrigin{files: origin.files, given: map[string]string{"*": "the command line"}}, `"*"`)
	rules := filepath.Join(dir, "rules.yaml")
	os.WriteFile(rules, []byte("mock: []\n"), 0o600)
	onlyPinned, _ := capture.ParseAllowHosts([]string{"cli.c.com"})
	refused("none left, with --rules", onlyPinned, origin, "the next start of run would refuse it: --rules needs --allow-hosts", append(slices.Clone(args), "--rules", rules)...)
	refused("no hosts file", base, hostsOrigin{}, "nothing to save to: this run's hosts do not come from a hosts file, nor from a --config file")
	refused("two files", base, hostsOrigin{files: []string{hostsFile, "/x"}}, "nothing to save to: this run's hosts come from several files")
	refused("the pass file", base, hostsOrigin{files: origin.files, pass: &hostsOrigin{files: origin.files}}, "--pass-hosts file too")
	link := filepath.Join(dir, "link")
	os.Symlink(hostsFile, link)
	refused("a link", base, hostsOrigin{files: []string{link}}, "is not a plain file")
	if os.Getuid() != 0 {
		refused("not mine", base, hostsOrigin{files: []string{"/etc/hosts"}}, "/etc/hosts is not yours")
	}

	// The last host removed (none pinned left either): the file keeps its
	// comments and no host, and a fresh start takes it.
	if a, saved := saveOf(onlyPinned, origin, "", "", args...); !a.OK || !saved || !strings.Contains(a.Message, "saved to "+hostsFile+": no hosts") {
		t.Errorf("none left: %q", a.Message)
	}
	if b, _ := os.ReadFile(hostsFile); string(b) != "# mine\n\n" {
		t.Errorf("none left, the file:\n%s", b)
	}
	if o, err := parseRunFlags(args); err != nil || len(o.allow.Hosts) != 0 {
		t.Errorf("a fresh start: %v", err)
	}
}

// TestCaptureSaveE2E (REQCOVE_E2E=1, real mitmproxy): run started from a
// config reading a hosts file, and a host on the command line. capture add,
// then remove the command line's host, then save: the file has the host
// added, the answer says the removed one comes back, and the save leaves its
// log line, cli marker and status's trace. A new run from the config records
// the host added. Then (v1.3) a run from a config with its hosts inline:
// capture save shows the change and asks, y creates the hosts file and adds
// its line, a second save writes the file, asking nothing.
func TestCaptureSaveE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "rcvs-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	hostsFile, config := saveFiles(t, dir, "# the app's hosts\nlocalhost\n", "")
	state := filepath.Join(dir, "s")
	start := func(args ...string) (*capture.Capture, *runOpts) {
		t.Helper()
		if !slices.Contains(args, "--config") {
			args = append([]string{"--config", config, "--state", state}, args...)
		}
		o, err := parseRunFlags(append([]string{"--device", "x"}, args...))
		if err != nil {
			t.Fatal(err)
		}
		c, err := capture.Start(ctx, capture.Config{Dir: o.state, Confdir: filepath.Join(dir, "m"),
			Uvx: "uvx", Python: defaultPython, MitmSpec: defaultMitmSpec,
			BodyHead: capture.DefaultBodyHead, MaxFlows: capture.DefaultMaxFlows, MaxBytes: capture.DefaultMaxBytes,
			Log: os.Stderr, ReadyTimeout: 2 * time.Minute, AllowHosts: o.allow})
		if err != nil {
			t.Fatal(err)
		}
		return c, o
	}
	c, o := start("--allow-hosts", "cli.example.com")
	logged := logTo(t)
	sctx, stopCtl := context.WithCancel(ctx)
	if _, err := serveCtl(sctx, state, c, o, nil, nil); err != nil {
		t.Fatal(err)
	}
	change := func(req ctlRequest) string {
		t.Helper()
		var out strings.Builder
		if err := sendCapture(ctx, &out, o.state, req); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	if out := change(ctlRequest{Cmd: "add", Hosts: []string{"127.0.0.1"}}); !strings.Contains(out, "reqcove capture save writes them") {
		t.Errorf("add: %q", out)
	}
	change(ctlRequest{Cmd: "remove", Hosts: []string{"cli.example.com"}})
	out := change(ctlRequest{Cmd: "save"})
	for _, want := range []string{"saved to " + hostsFile + ": localhost, 127.0.0.1", "removed now, but given on the command line, so a start with it records them again: cli.example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("save: %q, want %q in it", out, want)
		}
	}
	if b, _ := os.ReadFile(hostsFile); string(b) != "# the app's hosts\nlocalhost\n127.0.0.1\n" {
		t.Errorf("file:\n%s", b)
	}
	waitLog(t, logged, "capture save (reqcove capture, from a terminal): saved to "+hostsFile, 1)
	if s := liveStatus(exitnode.Status{Backend: "Running"}, c); s.ScopeChange != "capture save" || s.ScopeChangedAt == "" {
		t.Errorf("status: change %q at %q", s.ScopeChange, s.ScopeChangedAt)
	}
	if ms := c.Store.Markers(0); len(ms) == 0 || ms[len(ms)-1].Source != "cli" || ms[len(ms)-1].Text != "capture save" {
		t.Errorf("markers: %+v", ms)
	}
	stopCtl()
	c.Stop()

	// A new run from the config: the host saved is recorded.
	c, o = start()
	defer c.Stop()
	if !slices.Equal(o.allow.Hosts, []string{"localhost", "127.0.0.1"}) {
		t.Errorf("the new run's hosts: %q", o.allow.Hosts)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	socks, _ := proxy.SOCKS5("tcp", c.SocksAddr, &proxy.Auth{User: "dev", Password: c.SocksSecret}, proxy.Direct)
	hc := &http.Client{Transport: &http.Transport{DialContext: socks.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}, Timeout: 30 * time.Second}
	r, err := hc.Get(origin.URL + "/saved")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		flows, _ := c.Store.List(capture.Filter{Limit: 10})
		if len(flows) == 1 && strings.HasSuffix(flows[0].URL, "/saved") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the new run recorded %d flows", len(flows))
		}
	}
	c.Stop()

	inline := filepath.Join(dir, "i")
	os.Mkdir(inline, 0o700)
	iconf, ihosts := filepath.Join(inline, "config"), filepath.Join(inline, "hosts")
	os.WriteFile(iconf, []byte("--allow-hosts=localhost\n"), 0o600)
	c, o = start("--config", iconf, "--state", filepath.Join(dir, "t"))
	defer c.Stop()
	sctx, stopCtl = context.WithCancel(ctx)
	defer stopCtl()
	if _, err := serveCtl(sctx, o.state, c, o, nil, nil); err != nil {
		t.Fatal(err)
	}
	change(ctlRequest{Cmd: "add", Hosts: []string{"127.0.0.1"}})
	var out2 strings.Builder
	if err := saveIn(ctx, strings.NewReader("y\n"), &out2, o.state, ctlRequest{Cmd: "save"}); err != nil {
		t.Fatal(err)
	}
	if s := out2.String(); !strings.Contains(s, "+ --allow-hosts=@"+ihosts+"\nGo on? [y/N] added to "+iconf+": --allow-hosts=@"+ihosts+"; saved to "+ihosts+": 127.0.0.1;") {
		t.Errorf("first save:\n%s", s)
	}
	if b, _ := os.ReadFile(iconf); string(b) != "--allow-hosts=localhost\n--allow-hosts=@"+ihosts+"\n" {
		t.Errorf("config:\n%s", b)
	}
	change(ctlRequest{Cmd: "add", Hosts: []string{"127.0.0.2"}})
	if out := change(ctlRequest{Cmd: "save"}); !strings.HasPrefix(out, "saved to "+ihosts+": 127.0.0.1, 127.0.0.2;") {
		t.Errorf("second save: %q", out)
	}
	if ms := c.Store.Markers(0); len(ms) == 0 || ms[len(ms)-1].Text != "capture save" {
		t.Errorf("markers: %+v", ms)
	}

}

// The first save on a config that names no hosts file (v1.0's setup, or one
// written by hand, its hosts inline): shown first, then with the token,
// hosts and pass-hosts created beside the config (0600, without the inline
// hosts, pinned) and their lines added, nothing else changed; the run takes
// the files at once, so a second save writes them, without asking. A file
// already there is refused, naming it and the choices; a config write that
// fails removes the files created, and a retry works.
func TestFirstSave(t *testing.T) {
	const old = "--device x\n--allow-hosts=inline.a.com # v1.0\n--state=/nonexistent/s" // no newline at the end
	config, args := confFile(t, old)
	dir := filepath.Dir(config)
	hosts, passHosts := filepath.Join(dir, "hosts"), filepath.Join(dir, "pass-hosts")
	o, err := reloadFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	st := newCtlState(o)
	base, _ := capture.ParseAllowHosts([]string{"inline.a.com,new.b.com"})
	base, _ = base.WithPass([]string{"new.b.com"})

	a, saved := saveScope(base, st, "")
	for _, want := range []string{
		"create " + hosts + " (yours only, 0600) with: new.b.com\n",
		"create " + passHosts + " (yours only, 0600) with: new.b.com\n",
		"add to " + config + " (its other lines kept, the old file kept as config.prev):\n    + --allow-hosts=@" + hosts + "\n    + --pass-hosts=@" + passHosts + "\n",
	} {
		if !strings.Contains(a.Message, want) {
			t.Errorf("shown: %q, want %q in it", a.Message, want)
		}
	}
	if a.OK || saved || a.Confirm == "" {
		t.Fatalf("shown: %+v %v", a, saved)
	}
	unchanged := func(what string) {
		t.Helper()
		if b, _ := os.ReadFile(config); string(b) != old {
			t.Errorf("%s: config written:\n%s", what, b)
		}
		for _, f := range []string{hosts, passHosts} {
			if _, err := os.Lstat(f); err == nil {
				t.Errorf("%s: %s created", what, f)
			}
		}
	}
	unchanged("shown")
	if a, _ := saveScope(base, st, "0123"); !strings.Contains(a.Message, "changed since the change was shown") {
		t.Errorf("another token: %q", a.Message)
	}
	unchanged("another token")

	// The config write fails: the files created are removed.
	renameConfig = func(string, string) error { return errors.New("disk full") }
	if a, saved := saveScope(base, st, a.Confirm); a.OK || saved || !strings.Contains(a.Message, "refused: the config: disk full; nothing written") {
		t.Errorf("failed write: %q", a.Message)
	}
	renameConfig = os.Rename
	unchanged("failed write")
	if len(st.origin.files) != 0 {
		t.Errorf("failed write, origin %q", st.origin.files)
	}

	a, saved = saveScope(base, st, a.Confirm)
	if !a.OK || !saved || !strings.Contains(a.Message, "added to "+config+": --allow-hosts=@"+hosts+", --pass-hosts=@"+passHosts+"; saved to "+hosts+": new.b.com; saved to "+passHosts+": new.b.com") ||
		!strings.Contains(a.Message, "not written, as given on the --config file (a start with it records them again): inline.a.com") {
		t.Fatalf("saved: %q", a.Message)
	}
	if b, _ := os.ReadFile(config); string(b) != old+"\n--allow-hosts=@"+hosts+"\n--pass-hosts=@"+passHosts+"\n" {
		t.Errorf("config:\n%s", b)
	}
	if b, _ := os.ReadFile(config + ".prev"); string(b) != old {
		t.Errorf("config.prev:\n%s", b)
	}
	for _, f := range []string{hosts, passHosts} {
		fi, err := os.Lstat(f)
		if b, _ := os.ReadFile(f); err != nil || fi.Mode().Perm() != 0o600 || !strings.HasPrefix(string(b), "# The hosts reqcove") || !strings.HasSuffix(string(b), "\nnew.b.com\n") {
			t.Errorf("%s: %v %v\n%s", f, err, fi, b)
		}
	}
	if !slices.Equal(st.origin.files, []string{hosts}) || !slices.Equal(st.origin.passOrigin().files, []string{passHosts}) || !slices.Equal(st.loaded.Hosts, []string{"inline.a.com", "new.b.com"}) {
		t.Errorf("origin %+v, loaded %q", st.origin, st.loaded.Hosts)
	}

	// A second save in the same run writes the files, nothing asked.
	next, _ := capture.ParseAllowHosts([]string{"inline.a.com,new.b.com,third.c.com"})
	next, _ = next.WithPass([]string{"third.c.com"})
	if a, saved := saveScope(next, st, ""); !a.OK || !saved || a.Confirm != "" || !strings.HasPrefix(a.Message, "saved to "+hosts+": new.b.com, third.c.com; saved to "+passHosts+": third.c.com") {
		t.Errorf("second save: %+v", a)
	}
	if b, _ := os.ReadFile(passHosts); !strings.HasSuffix(string(b), "keeping the comments.\nthird.c.com\n") {
		t.Errorf("pass-hosts:\n%s", b)
	}
	// Removing the last removable host, saved: a fresh start takes it.
	last, _ := capture.ParseAllowHosts([]string{"inline.a.com"})
	if a, _ := saveScope(last, st, ""); !a.OK || !strings.Contains(a.Message, "saved to "+hosts+": no hosts") || !strings.Contains(a.Message, "saved to "+passHosts+": no hosts") {
		t.Errorf("the last: %q", a.Message)
	}
	if n, err := parseRunFlags(args); err != nil || !slices.Equal(n.allow.Hosts, []string{"inline.a.com"}) || len(n.allow.PassHosts) != 0 {
		t.Errorf("a fresh start: %v", err)
	}

	// A file there already, or a link (dangling too), the config naming none:
	// refused, shown nothing.
	for _, link := range []bool{false, true} {
		config, args = confFile(t, "--device x\n--allow-hosts=inline.a.com\n--state=/nonexistent/s\n")
		there := filepath.Join(filepath.Dir(config), "hosts")
		if link {
			os.Symlink(filepath.Join(t.TempDir(), "nowhere"), there)
		} else {
			os.WriteFile(there, []byte("mine.d.com\n"), 0o600)
		}
		o, _ = reloadFlags(args)
		if a, saved := saveScope(base, newCtlState(o), ""); a.Confirm != "" || saved || !strings.Contains(a.Message, "refused: "+there+" is there already, and the config does not name it") ||
			!strings.Contains(a.Message, "add the line --allow-hosts=@"+there+" to "+config+" yourself") || !strings.Contains(a.Message, "or move "+there+" away and save again; nothing written") {
			t.Errorf("there already (link %v): %+v", link, a)
		}
		if b, err := os.ReadFile(there); !link && string(b) != "mine.d.com\n" || link && err == nil {
			t.Errorf("there already (link %v), written:\n%s", link, b)
		}
	}
}

// A save across a created file, the config and a file there: the file
// there not written (its directory read-only), the answer says what was
// written and what not, and the run takes the created file (a retry writes
// it, not creates it again).
func TestSavePartly(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	other := t.TempDir()
	hostsFile := filepath.Join(other, "hosts")
	os.WriteFile(hostsFile, []byte("a.com\n"), 0o600)
	config, args := confFile(t, "--device x\n--allow-hosts=@"+hostsFile+"\n--state=/nonexistent/s\n")
	passHosts := filepath.Join(filepath.Dir(config), "pass-hosts")
	o, err := reloadFlags(args)
	if err != nil {
		t.Fatal(err)
	}
	st := newCtlState(o)
	base, _ := capture.ParseAllowHosts([]string{"a.com,b.com"})
	base, _ = base.WithPass([]string{"a.com"})
	a, _ := saveScope(base, st, "")
	if a.Confirm == "" || !strings.Contains(a.Message, "write "+hostsFile+": a.com, b.com\n") {
		t.Fatalf("shown: %+v", a)
	}
	os.Chmod(other, 0o500)
	t.Cleanup(func() { os.Chmod(other, 0o700) })
	a, saved := saveScope(base, st, a.Confirm)
	if a.OK || !saved || !strings.HasPrefix(a.Message, "partly saved: added to "+config+": --pass-hosts=@"+passHosts+"; saved to "+passHosts+": a.com; but "+hostsFile+" was not written: ") {
		t.Errorf("partly: %+v %v", a, saved)
	}
	if b, _ := os.ReadFile(hostsFile); string(b) != "a.com\n" {
		t.Errorf("the file there:\n%s", b)
	}
	if b, _ := os.ReadFile(passHosts); !strings.HasSuffix(string(b), "\na.com\n") {
		t.Errorf("pass-hosts:\n%s", b)
	}
	if b, _ := os.ReadFile(config); !strings.HasSuffix(string(b), "\n--pass-hosts=@"+passHosts+"\n") {
		t.Errorf("config:\n%s", b)
	}
	if !slices.Equal(st.origin.passOrigin().files, []string{passHosts}) {
		t.Errorf("pass origin: %q", st.origin.passOrigin().files)
	}
	os.Chmod(other, 0o700)
	if a, _ := saveScope(base, st, ""); !a.OK || a.Confirm != "" || !strings.HasPrefix(a.Message, "saved to "+hostsFile+": a.com, b.com; saved to "+passHosts+": a.com") {
		t.Errorf("again: %+v", a)
	}
}

// capture save in a terminal: the change to the config shown, y/N asked; N
// writes nothing, y sends the token back.
func TestSaveAsks(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "rcvs-") // short: macOS caps socket paths at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	config := filepath.Join(dir, "config")
	os.WriteFile(config, []byte("--device x\n--state=/nonexistent/s\n"), 0o600)
	o, err := reloadFlags([]string{"--config", config})
	if err != nil {
		t.Fatal(err)
	}
	st := newCtlState(o)
	base, _ := capture.ParseAllowHosts([]string{"new.b.com"})
	ln, err := net.Listen("unix", filepath.Join(dir, ctlSock))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ctlRequest
			json.NewDecoder(conn).Decode(&req)
			st.mu.Lock()
			a, _ := saveScope(base, st, req.Confirm)
			st.mu.Unlock()
			json.NewEncoder(conn).Encode(a)
			conn.Close()
		}
	}()
	var out strings.Builder
	if err := saveIn(context.Background(), strings.NewReader("n\n"), &out, dir, ctlRequest{Cmd: "save"}); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "+ --allow-hosts=@"+filepath.Join(dir, "hosts")+"\nGo on? [y/N] nothing written\n") {
		t.Errorf("N:\n%s", s)
	}
	if _, err := os.Lstat(filepath.Join(dir, "hosts")); err == nil {
		t.Error("N: the hosts file created")
	}
	out.Reset()
	if err := saveIn(context.Background(), strings.NewReader("y\n"), &out, dir, ctlRequest{Cmd: "save"}); err != nil {
		t.Fatal(err)
	}
	if s := out.String(); !strings.Contains(s, "Go on? [y/N] added to "+config+": --allow-hosts=@"+filepath.Join(dir, "hosts")+"; saved to") {
		t.Errorf("y:\n%s", s)
	}
}

// Save's confirmation is of the files read too, not only of what it writes:
// a host added to the hosts file after the page showed the change (which the
// save would drop: the same text written) refuses it, the file kept; so does
// an edit to the config. Just before the rename, the file must still be the
// one read.
func TestSaveConfirmFilesRead(t *testing.T) {
	dir := t.TempDir()
	hostsFile, config := saveFiles(t, dir, "a.com\n", "")
	args := []string{"--config", config, "--device", "x", "--state", filepath.Join(dir, "s")}
	origin := hostsOrigin{files: []string{hostsFile}, inFiles: map[string]bool{"a.com": true}}
	base, _ := capture.ParseAllowHosts([]string{"a.com"})
	st := &ctlState{o: &runOpts{config: config, args: args}, origin: origin}
	sp, no := planSave(base, st)
	if no != "" {
		t.Fatal(no)
	}
	os.WriteFile(hostsFile, []byte("a.com\nb.com\n"), 0o644)
	if sp2, _ := planSave(base, st); sp2.saves[0].text != sp.saves[0].text {
		t.Fatalf("the edit changes what is written: the test shows nothing (%q)", sp2.saves[0].text)
	}
	if a, saved := saveScope(base, st, sp.token); saved || a.OK || !strings.Contains(a.Message, "changed since the change was shown") {
		t.Errorf("hosts file edited: %+v", a)
	}
	if got := read(t, hostsFile); got != "a.com\nb.com\n" {
		t.Errorf("hosts file: %q", got)
	}
	sp, _ = planSave(base, st)
	os.WriteFile(config, []byte(read(t, config)+"--verbose\n"), 0o600)
	if a, saved := saveScope(base, st, sp.token); saved || a.OK {
		t.Errorf("config edited: %+v", a)
	}

	text, rev, err := hostsText(hostsFile, []string{"a.com"}, "")
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(hostsFile, []byte("a.com\nc.com\n"), 0o644)
	if err := writeHostsText(hostsFile, text, []string{"a.com"}, rev); err == nil || read(t, hostsFile) != "a.com\nc.com\n" {
		t.Errorf("written over an edit: %v", err)
	}
}
