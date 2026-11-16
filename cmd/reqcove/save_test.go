package main

import (
	"context"
	"io"
	"maps"
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

// capture save writes the base minus the hosts given as they are (but those
// in the file too), keeping the file's comments; a host given on the command
// line and removed now, in the file too or not, is named as coming back. Refused: "*", no hosts left, a file not plain or not
// this user's, no hosts file or several, the --pass-hosts file.
func TestSaveHosts(t *testing.T) {
	dir := t.TempDir()
	hostsFile, _ := saveFiles(t, dir, "# mine\napi.a.com # the app\nold.b.com\nboth.c.com\n\n", "")
	origin := hostsOrigin{files: []string{hostsFile}, inFiles: map[string]bool{"api.a.com": true, "old.b.com": true, "both.c.com": true},
		given: map[string]string{"cli.c.com": "the command line", "gone.c.com": "the command line", "both.c.com": "the command line", "conf.d.com": "the --config file"}}
	base, _ := capture.ParseAllowHosts([]string{"api.a.com,cli.c.com,new.c.com,conf.d.com"})
	base, _ = base.WithPass([]string{"api.a.com"})
	msg, err := saveHosts(base, origin)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"saved to " + hostsFile + ": api.a.com, new.c.com",
		"not written, as given on the command line (a start with it records them again): cli.c.com",
		"removed now, but given on the command line, so a start with it records them again: both.c.com, gone.c.com",
		"not written, as given on the --config file (a start with it records them again): conf.d.com",
		"the hosts passed undecrypted are not saved",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q, want %q in it", msg, want)
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
	if msg, err := saveHosts(kept, origin); err != nil || !strings.HasPrefix(msg, "saved to "+hostsFile+": api.a.com, both.c.com;") || strings.Contains(msg, "not written, as given on the command line (a start with it records them again): both") {
		t.Errorf("kept: %q %v", msg, err)
	}

	refused := func(what string, base capture.HostRules, o hostsOrigin, want string) {
		t.Helper()
		before, _ := os.ReadFile(hostsFile)
		if _, err := saveHosts(base, o); err == nil || !strings.Contains(err.Error(), want) || !strings.HasSuffix(err.Error(), "nothing written") {
			t.Errorf("%s: %v, want %q", what, err, want)
		}
		if after, _ := os.ReadFile(hostsFile); string(after) != string(before) {
			t.Errorf("%s: the file changed:\n%s", what, after)
		}
	}
	all, _ := capture.ParseAllowHosts([]string{"*"})
	refused("*", all, origin, `refused: this run records every host ("*")`)
	allAndMine, _ := capture.ParseAllowHosts([]string{"*,api.a.com"})
	refused("* given on the command line", allAndMine, hostsOrigin{files: origin.files, given: map[string]string{"*": "the command line"}}, `"*"`)
	onlyPinned, _ := capture.ParseAllowHosts([]string{"cli.c.com"})
	refused("none left", onlyPinned, origin, "refused: no hosts to write, and run refuses a hosts file without hosts")
	refused("none at all", capture.HostRules{}, origin, "refused: no hosts to write")
	refused("no hosts file", base, hostsOrigin{}, "nothing to save to: this run's hosts do not come from a hosts file; put `--allow-hosts=@FILE` in the config")
	refused("two files", base, hostsOrigin{files: []string{hostsFile, "/x"}}, "nothing to save to: this run's hosts come from several files")
	refused("the pass file", base, hostsOrigin{files: origin.files, passFiles: origin.files}, "--pass-hosts file too")

	link := filepath.Join(dir, "link")
	os.Symlink(hostsFile, link)
	refused("a link", base, hostsOrigin{files: []string{link}}, "is not a plain file")
	if os.Getuid() != 0 {
		refused("not mine", base, hostsOrigin{files: []string{"/etc/hosts"}}, "/etc/hosts is not yours")
	}
}

// TestCaptureSaveE2E (REQCOVE_E2E=1, real mitmproxy): run started from a
// config reading a hosts file, and a host on the command line. capture add,
// then remove the command line's host, then save: the file has the host
// added, the answer says the removed one comes back, and the save leaves its
// log line, cli marker and status's trace. A new run from the config records
// the host added.
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
		o, err := parseRunFlags(append([]string{"--config", config, "--device", "x", "--state", state}, args...))
		if err != nil {
			t.Fatal(err)
		}
		c, err := capture.Start(ctx, capture.Config{Dir: state, Confdir: filepath.Join(dir, "m"),
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
	if err := serveCtl(sctx, state, c, o); err != nil {
		t.Fatal(err)
	}
	change := func(req ctlRequest) string {
		t.Helper()
		var out strings.Builder
		if err := sendCapture(ctx, &out, state, req); err != nil {
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
}
