package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
)

// settingsRun is a run started from a --config file of text (extra on its
// command line; text "" for flags alone), its page open with a session, its
// netmap holding one own device (nOWN) and carrying another user's (nOTHER);
// restarted, the snapshot asked for, once run is asked to restart.
func settingsRun(t *testing.T, text string, extra ...string) (base, token string, st *ctlState, config string, restarted chan string) {
	t.Helper()
	state := t.TempDir()
	args := append([]string{"--state=" + state}, extra...)
	if text != "" {
		var cargs []string
		config, cargs = confFile(t, text+"\n--state="+state+"\n")
		args = append(cargs, extra...)
	}
	o, err := checkFlags(args, nil, nil) // run's options, without its side effects (the mask policy)
	if err != nil {
		t.Fatal(err)
	}
	if config != "" {
		o.configText, _ = os.ReadFile(config)
	}
	dir, _ := os.MkdirTemp("/tmp", "rcvs-") // short socket paths
	t.Cleanup(func() { os.RemoveAll(dir) })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cap := &capture.Capture{Store: capture.NewStore(10, 1<<20)}
	st, err = serveCtl(ctx, dir, cap, o, nil, func() mcpserver.StatusOut {
		return mcpserver.StatusOut{Mode: "tailnet", Node: exitnode.Status{Devices: map[string]string{"nOTHER": "colleague-phone"}, Own: map[string]string{"nOWN": "my-iphone"}}}
	})
	if err != nil {
		t.Fatal(err)
	}
	restarted = make(chan string, 1)
	st.restart = func(s string, _ bool) { // as run's: the page's server closes, before the handler returns
		restarted <- s
		cancel()
		time.Sleep(100 * time.Millisecond)
	}

	startBinary, startBinaryErr, startArgs = os.Args[0], nil, args
	t.Cleanup(func() { startBinary, startArgs = "", nil })
	base, code := openUI(t, dir)
	return base, trade(t, base, code), st, config, restarted
}

func getSettings(t *testing.T, base, token string) pageSettings {
	t.Helper()
	r, b := call(t, base, "GET", "/api/settings", "", map[string]string{sessionHeader: token})
	var s pageSettings
	if r.StatusCode != 200 || json.Unmarshal([]byte(b), &s) != nil {
		t.Fatalf("settings: %d %s", r.StatusCode, b)
	}
	return s
}

func settingOf(t *testing.T, s pageSettings, flag string) pageSetting {
	t.Helper()
	for _, x := range s.Settings {
		if x.Flag == flag {
			return x
		}
	}
	t.Fatalf("no %s in %+v", flag, s.Settings)
	return pageSetting{}
}

// setSetting posts a change (rev: the page's now, unless given); ok and the message.
func postSetting(t *testing.T, base, token string, body map[string]any) (int, bool, string) {
	t.Helper()
	if _, ok := body["rev"]; !ok {
		body["rev"] = getSettings(t, base, token).Rev
	}
	b, _ := json.Marshal(body)
	r, out := call(t, base, "POST", "/api/settings", string(b), map[string]string{sessionHeader: token})
	var d struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	json.Unmarshal([]byte(out), &d)
	return r.StatusCode, d.OK, d.Message + d.Error
}

// Each setting the page writes, written through the writer and read back as
// the page shows it; --upstream-ca cleared; the config's other lines kept.
func TestPageSettingsWrite(t *testing.T) {
	logged := logTo(t)
	ca := filepath.Join(t.TempDir(), "burp.pem")
	base, token, _, config, _ := settingsRun(t, "# mine\n--device=phone\n--allow-hosts=a.example\n--upstream-proxy=http://127.0.0.1:8080\n--upstream-ca="+ca)
	for _, c := range []struct {
		flag   string
		values []string
	}{
		{"device", []string{"phone", "nOWN"}},
		{"keep-awake", []string{"ac"}},
		{"proxy-port", []string{"8443"}},
		{"hostname", []string{"my-node"}},
		{"verbose", []string{"true"}},
		{"ui", []string{"true"}},
		{"mcp-http", []string{"true"}},
		{"local-proxy", []string{"true"}},
		{"dns", []string{"9.9.9.9,1.1.1.1:53"}},
		{"upstream-proxy", []string{"http://127.0.0.1:8081"}},
		{"mask-names", []string{"x-team-key", "session_ref"}},
		{"upstream-ca", nil},
		{"upstream-proxy", nil},
		{"verbose", []string{"false"}},
	} {
		code, ok, msg := postSetting(t, base, token, map[string]any{"flag": c.flag, "values": c.values, "confirmed": true})
		if code != 200 || !ok || !strings.Contains(msg, "run takes it at its next restart") {
			t.Fatalf("%s %v: %d %v %q", c.flag, c.values, code, ok, msg)
		}
		if got := settingOf(t, getSettings(t, base, token), c.flag).Values; !slices.Equal(got, append([]string{}, c.values...)) {
			t.Errorf("%s: read back %q, want %q", c.flag, got, c.values)
		}
	}
	text := read(t, config)
	if !strings.HasPrefix(text, "# mine\n") || !strings.Contains(text, "--allow-hosts=a.example\n") || strings.Contains(text, "upstream-ca") {
		t.Errorf("config:\n%s", text)
	}
	if _, err := checkFlags([]string{"--config", config}, nil, nil); err != nil {
		t.Errorf("the config would not start: %v", err)
	}
	if l := logged.String(); !strings.Contains(l, "--mask-names written to "+config+fromConsole) || strings.Contains(l, "x-team-key") {
		t.Errorf("log: %s", l)
	}
}

// What the page must not write: hostile values (a line break, NUL, a leading
// @, another flag in a value), a terminal-only flag as the field or a field
// added, more values than the flag takes. Nothing written.
func TestPageSettingsRefused(t *testing.T) {
	base, token, _, config, _ := settingsRun(t, "--device=phone\n--allow-hosts=a.example")
	before := read(t, config)
	for _, c := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"flag": "hostname", "values": []string{"node\n--no-redact"}}, "a line break"},
		{map[string]any{"flag": "dns", "values": []string{"1.1.1.1\r--uvx=/tmp/x"}}, "a line break"},
		{map[string]any{"flag": "hostname", "values": []string{"node\x00x"}}, "a control character"},
		{map[string]any{"flag": "mask-names", "values": []string{"@/etc/passwd"}, "confirmed": true}, "a leading @"},
		{map[string]any{"flag": "upstream-proxy", "values": []string{"@/tmp/proxy"}, "confirmed": true}, "a leading @"},
		{map[string]any{"flag": "hostname", "values": []string{"node --uvx=/tmp/x"}}, "--hostname: a name"},
		{map[string]any{"flag": "dns", "values": []string{"1.1.1.1 --no-redact"}, "confirmed": true}, "--dns: IP addresses"},
		{map[string]any{"flag": "mask-names", "values": []string{"a --no-redact"}, "confirmed": true}, "--mask-names: names"},
		{map[string]any{"flag": "keep-awake", "values": []string{"ac", "never"}}, "takes one value"},
		{map[string]any{"flag": "device", "values": []string{"phone", "--no-redact"}, "confirmed": true}, "a device's name"},
		{map[string]any{"flag": "device", "values": []string{"phone", "nOTHER"}, "confirmed": true}, "one of your own devices"},
		{map[string]any{"flag": "upstream-proxy", "values": []string{"http://u:p@127.0.0.1:8081"}, "confirmed": true}, "no user or password"},
		{map[string]any{"flag": "verbose", "values": []string{"true"}, "rev": ""}, "no revision"},
	} {
		code, ok, msg := postSetting(t, base, token, c.body)
		if code != 200 || ok || !strings.Contains(msg, c.want) || !strings.HasSuffix(msg, "; nothing written") || strings.Contains(msg, "/tmp/x") || strings.Contains(msg, "u:p@") {
			t.Errorf("%v: %d %v %q, want %q", c.body, code, ok, msg, c.want)
		}
	}
	for _, body := range []string{
		`{"flag":"no-redact","values":["true"],"rev":"x"}`,
		`{"flag":"uvx","values":["/tmp/x"],"rev":"x"}`,
		`{"flag":"rules","values":["/tmp/x"],"rev":"x"}`,
		`{"flag":"mask-values","values":["x"],"rev":"x"}`,
		`{"flag":"state","values":["/tmp/x"],"rev":"x"}`,
		`{"flag":"upstream-ca","values":["/tmp/x"],"rev":"x"}`,
		`{"flag":"verbose","values":["true"],"rev":"x","uvx":"/tmp/x"}`,
		`{"flag":"verbose","values":["true"],"rev":"x","no-redact":true}`,
		`["verbose"]`,
	} {
		r, b := call(t, base, "POST", "/api/settings", body, map[string]string{sessionHeader: token})
		if r.StatusCode != 400 || !strings.Contains(b, "refused") {
			t.Errorf("%s: %d %s", body, r.StatusCode, b)
		}
	}
	r, _ := call(t, base, "POST", "/api/settings", `{"flag":"verbose","values":["true"],"rev":"x"}`, nil)
	if r.StatusCode != 401 {
		t.Errorf("no session: %d", r.StatusCode)
	}
	if read(t, config) != before {
		t.Errorf("written:\n%s", read(t, config))
	}
}

// A setting given on run's command line is pinned: shown, never written; a
// flags-only run has every setting read-only, with the reason.
func TestPageSettingsPinned(t *testing.T) {
	base, token, _, config, _ := settingsRun(t, "--device=phone", "--keep-awake=never", "--ui")
	s := getSettings(t, base, token)
	if k := settingOf(t, s, "keep-awake"); k.Edit != "" || !slices.Equal(k.Pinned, []string{"never"}) || !strings.Contains(k.Why, "command line") {
		t.Errorf("pinned: %+v", k)
	}
	if v := settingOf(t, s, "verbose"); v.Edit != "restart" || v.Pinned != nil {
		t.Errorf("not pinned: %+v", v)
	}
	before := read(t, config)
	for f, v := range map[string]string{"keep-awake": "ac", "ui": "false"} {
		if _, ok, msg := postSetting(t, base, token, map[string]any{"flag": f, "values": []string{v}, "confirmed": true}); ok || !strings.Contains(msg, "given on run's command line") {
			t.Errorf("%s: %q", f, msg)
		}
	}
	if read(t, config) != before {
		t.Error("written")
	}

	base, token, _, _, _ = settingsRun(t, "", "--device=phone")
	s = getSettings(t, base, token)
	if !strings.Contains(s.ReadOnly, "flags alone") || s.Rev != "" {
		t.Errorf("flags only: %+v", s)
	}
	for _, x := range s.Settings {
		if x.Edit != "" {
			t.Errorf("flags only, %s editable", x.Flag)
		}
	}
	if d := settingOf(t, s, "device"); !slices.Equal(d.Pinned, []string{"phone"}) {
		t.Errorf("flags only, device: %+v", d)
	}
	if _, ok, msg := postSetting(t, base, token, map[string]any{"flag": "verbose", "values": []string{"true"}, "rev": "x"}); ok || !strings.Contains(msg, "flags alone") {
		t.Errorf("flags only: %q", msg)
	}
}

// The settings that ask first show run's own words for the flag (run -h), and
// are refused until confirmed; adding a device asks, keeping one does not.
func TestPageSettingsConfirm(t *testing.T) {
	base, token, _, _, _ := settingsRun(t, "--device=phone\n--allow-hosts=a.example\n--mask-names=x-a,x-b")
	s := getSettings(t, base, token)
	fs := runFlagSet()
	for _, f := range []string{"ui", "mcp-http", "local-proxy", "dns", "upstream-proxy", "mask-names", "device"} {
		if w := settingOf(t, s, f).Warning; w == "" || w != fs.Lookup(f).Usage {
			t.Errorf("%s: warning %q, want run's %q", f, w, fs.Lookup(f).Usage)
		}
	}
	for _, c := range []struct {
		flag   string
		values []string
	}{
		{"ui", []string{"true"}}, {"mcp-http", []string{"true"}}, {"local-proxy", []string{"true"}},
		{"dns", []string{"9.9.9.9"}}, {"upstream-proxy", []string{"http://127.0.0.1:8081"}},
		{"mask-names", []string{"x-a"}}, // a name removed
		{"device", []string{"phone", "nOWN"}},
	} {
		_, ok, msg := postSetting(t, base, token, map[string]any{"flag": c.flag, "values": c.values})
		if ok || !strings.Contains(msg, "confirm first: "+fs.Lookup(c.flag).Usage) {
			t.Errorf("%s unconfirmed: %q", c.flag, msg)
		}
	}
	if _, ok, msg := postSetting(t, base, token, map[string]any{"flag": "keep-awake", "values": []string{"ac"}}); !ok {
		t.Errorf("keep-awake: %q", msg)
	}
	if _, ok, msg := postSetting(t, base, token, map[string]any{"flag": "device", "values": []string{"phone"}}); !ok {
		t.Errorf("device kept: %q", msg)
	}
}

// --mask-values is never in an answer: not the file's, not the command
// line's, not in the restart's list (changed, alone), not in a message. Nor
// an --upstream-proxy run would refuse (a password, edited in by hand).
func TestPageSettingsMaskValues(t *testing.T) {
	logged := logTo(t)
	base, token, _, config, _ := settingsRun(t, "--device=phone\n--allow-hosts=a.example\n--mask-values=k-SECRETFILE1", "--mask-values=k-SECRETCMD2")
	var bodies []string
	get := func(path string) {
		_, b := call(t, base, "GET", path, "", map[string]string{sessionHeader: token})
		bodies = append(bodies, b)
	}
	get("/api/settings")
	if m := settingOf(t, getSettings(t, base, token), "mask-values"); m.Set != "set (2)" || len(m.Values) != 0 || m.Pinned != nil || m.Edit != "" {
		t.Errorf("mask-values: %+v", m)
	}
	_, _, msg := postSetting(t, base, token, map[string]any{"flag": "verbose", "values": []string{"true"}})
	bodies = append(bodies, msg)
	os.WriteFile(config, []byte(strings.Replace(read(t, config), "SECRETFILE1", "SECRETFILE3", 1)), 0o600)
	get("/api/restart")
	restartBody := bodies[len(bodies)-1]
	_, _, msg = postSetting(t, base, token, map[string]any{"flag": "mask-values", "values": []string{"k-SECRETFILE4"}})
	bodies = append(bodies, msg)
	os.WriteFile(config, []byte(read(t, config)+"--upstream-proxy=http://u:SECRETPW@127.0.0.1:1\n"), 0o600)
	if u := settingOf(t, getSettings(t, base, token), "upstream-proxy"); len(u.Values) != 1 || !strings.Contains(u.Values[0], "not shown") {
		t.Errorf("upstream-proxy: %+v", u)
	}
	get("/api/settings")
	_, ok, msg := postSetting(t, base, token, map[string]any{"flag": "upstream-proxy", "values": []string{"http://127.0.0.1:8081"}, "confirmed": true})
	bodies = append(bodies, msg)
	if !ok {
		t.Errorf("upstream-proxy: %q", msg)
	}
	var r pageRestart
	json.Unmarshal([]byte(restartBody), &r)
	if !slices.ContainsFunc(r.Diff, func(d pageDiff) bool { return d.Flag == "mask-values" && d.Changed && d.Was == nil && d.Now == nil }) {
		t.Errorf("restart diff: %+v", r)
	}
	for _, b := range append(bodies, logged.String()) {
		if strings.Contains(b, "SECRET") {
			t.Errorf("shows a pattern: %s", b)
		}
	}
}

// The restart's list: every flag the config on disk has otherwise than run
// started with, an edit by hand of a terminal-only flag among them, that a
// masking file the config reads changed, and the hosts a hosts file gives
// now; a stale page refused, after an edit to the config or to a file it reads.
func TestPageRestartDiff(t *testing.T) {
	names, hosts := filepath.Join(t.TempDir(), "names"), filepath.Join(t.TempDir(), "hosts")
	os.WriteFile(names, []byte("x-a\n"), 0o600)
	os.WriteFile(hosts, []byte("a.com\n"), 0o600)
	base, token, _, config, restarted := settingsRun(t, "--device=phone\n--mask-names=@"+names+"\n--allow-hosts=@"+hosts)
	if _, ok, msg := postSetting(t, base, token, map[string]any{"flag": "keep-awake", "values": []string{"ac"}}); !ok {
		t.Fatal(msg)
	}
	os.WriteFile(config, []byte(read(t, config)+"--uvx=/opt/other/uvx\n--python=3.14\n"), 0o600)
	os.WriteFile(names, []byte("x-a\nx-b\n"), 0o600)
	os.WriteFile(hosts, []byte("b.com\na.com\n"), 0o600)
	_, b := call(t, base, "GET", "/api/restart", "", map[string]string{sessionHeader: token})
	var r pageRestart
	json.Unmarshal([]byte(b), &r)
	want := []pageDiff{{Flag: "keep-awake", Now: []string{"ac"}}, {Flag: "python", Now: []string{"3.14"}}, {Flag: "uvx", Now: []string{"/opt/other/uvx"}}, {Flag: "mask-names", Changed: true},
		{Flag: "allow-hosts=@FILE (its hosts)", Was: []string{"a.com"}, Now: []string{"a.com", "b.com"}}}
	if len(r.Diff) != len(want) || r.Message != "" || r.Rev == "" || !strings.Contains(r.Warning, "start empty") {
		t.Fatalf("restart: %s", b)
	}
	for i, d := range r.Diff {
		if d.Flag != want[i].Flag || !slices.Equal(d.Was, want[i].Was) || !slices.Equal(d.Now, want[i].Now) || d.Changed != want[i].Changed {
			t.Errorf("diff %d: %+v, want %+v", i, d, want[i])
		}
	}
	// Edited again after the page listed it, the config or a file it reads:
	// refused, nothing stopped.
	for _, edit := range []func(){
		func() { os.WriteFile(config, []byte(read(t, config)+"--verbose\n"), 0o600) },
		func() { os.WriteFile(hosts, []byte("b.com\na.com\nc.com\n"), 0o600) },
		func() { os.WriteFile(names, []byte("x-a\nx-c\n"), 0o600) },
	} {
		_, b = call(t, base, "GET", "/api/restart", "", map[string]string{sessionHeader: token})
		json.Unmarshal([]byte(b), &r)
		edit()
		_, b = call(t, base, "POST", "/api/restart", `{"rev":"`+r.Rev+`"}`, map[string]string{sessionHeader: token})
		if !strings.Contains(b, "changed since the page listed") || !strings.Contains(b, "nothing stopped") || len(restarted) != 0 {
			t.Fatalf("stale restart: %s", b) // run asked to restart: the page is gone
		}
	}
	// As listed: run restarts, once the answer is out.
	_, b = call(t, base, "GET", "/api/restart", "", map[string]string{sessionHeader: token})
	json.Unmarshal([]byte(b), &r)
	r2, _ := call(t, base, "POST", "/api/restart", `{"rev":"x","cmd":"set"}`, map[string]string{sessionHeader: token})
	if r2.StatusCode != 400 {
		t.Errorf("a field added: %d", r2.StatusCode)
	}
	// The answer whole (a browser's fetch fails on one cut short), though
	// run closes the page's server right after.
	req, _ := http.NewRequest("POST", base+"/api/restart", strings.NewReader(`{"rev":"`+r.Rev+`"}`))
	req.Header.Set("Origin", base)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(sessionHeader, token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		t.Errorf("the answer cut short: %v", err)
	}
	b = string(body)
	var a struct {
		OK      bool
		Message string
	}
	if json.Unmarshal([]byte(b), &a) != nil || !a.OK || !strings.HasPrefix(a.Message, "restarting: ") {
		t.Errorf("restart: %s", b)
	}
	select {
	case snap := <-restarted:
		if !snapshotName.MatchString(filepath.Base(snap)) {
			t.Errorf("restart asked with %q", snap)
		}
	case <-time.After(5 * time.Second):
		t.Error("run not asked to restart")
	}
}

// A change on a page that read the config before another change (another
// tab, an edit by hand) is refused; the file is left as the other made it.
func TestPageSettingsStale(t *testing.T) {
	base, token, _, config, _ := settingsRun(t, "--device=phone")
	rev := getSettings(t, base, token).Rev
	os.WriteFile(config, []byte(read(t, config)+"--keep-awake=never\n"), 0o600)
	edited := read(t, config)
	if _, ok, msg := postSetting(t, base, token, map[string]any{"flag": "verbose", "values": []string{"true"}, "rev": rev}); ok || !strings.Contains(msg, "changed since this page read it") {
		t.Errorf("stale: %q", msg)
	}
	if read(t, config) != edited {
		t.Error("written")
	}
	if _, ok, msg := postSetting(t, base, token, map[string]any{"flag": "verbose", "values": []string{"true"}}); !ok {
		t.Errorf("again: %q", msg)
	}
}

// The device picker: the user's own devices from run's netmap (Status.Own,
// untagged, this user's: exitnode's TestOwnDevices), never the devices
// carried for another user.
func TestPageSettingsDevices(t *testing.T) {
	base, token, _, _, _ := settingsRun(t, "--device=phone")
	if d := getSettings(t, base, token).Devices; len(d) != 1 || d[0] != (pageDevice{ID: "nOWN", Name: "my-iphone"}) {
		t.Errorf("devices: %+v", d)
	}
}

// run --check-config, as a restart asks the binary it would exec: exit 0 or
// 1 with the reason; it takes no lock, creates no state directory and writes
// no file; it refuses what run would; a bare run reads the file a bare run
// reads.
func TestCheckConfigMode(t *testing.T) {
	home := t.TempDir()
	dir := t.TempDir()
	state := filepath.Join(dir, "state-not-made")
	config := filepath.Join(dir, "config")
	var before []string
	listing := func() []string {
		var out []string
		for _, d := range []string{home, dir} {
			filepath.Walk(d, func(p string, fi os.FileInfo, _ error) error {
				out = append(out, p+" "+fi.ModTime().String())
				return nil
			})
		}
		return out
	}
	// check runs the mode; nothing in HOME or beside the config changes.
	check := func(args ...string) (string, error) {
		t.Helper()
		before = listing()
		defer func() {
			if after := listing(); !slices.Equal(before, after) {
				t.Errorf("%q: files changed:\n%v\n%v", args, before, after)
			}
		}()
		cmd := exec.Command(os.Args[0], append([]string{"run", checkConfigArg}, args...)...) // TestMain takes it as reqcove does
		cmd.Env = append(os.Environ(), "HOME="+home)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	os.WriteFile(config, []byte("--device=phone\n--allow-hosts=a.example\n--state="+state+"\n"), 0o600)
	if out, err := check("--config", config); err != nil {
		t.Errorf("a good config: %v %s", err, out)
	}
	if out, err := check("--config", config, "--keep-awake=sometimes"); err == nil || !strings.Contains(out, "--keep-awake") {
		t.Errorf("a refused command line: %v %s", err, out)
	}
	os.WriteFile(config, []byte("--device=phone\n--state="+state+"\n--web\n"), 0o600)
	out, err := check("--config", config)
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 || !strings.Contains(out, checkPrefix) || !strings.Contains(out, "--web only on the command line") {
		t.Errorf("a refused config: %v %s", err, out)
	}
	if out, err := check(); err == nil || !strings.Contains(out, "--device is required") {
		t.Errorf("bare, no config: %v %s", err, out)
	}
	bare := filepath.Join(home, ".config", "reqcove", "config")
	os.MkdirAll(filepath.Dir(bare), 0o700)
	os.WriteFile(bare, []byte("--device=phone\n--state="+state+"\n"), 0o600)
	if out, err := check(); err != nil {
		t.Errorf("bare: %v %s", err, out)
	}
	if _, err := os.Stat(state); err == nil {
		t.Error("the state directory made")
	}
}

// A restart asks the binary it would exec first: refused there, nothing is
// stopped (no snapshot, run not asked); a binary older than the check mode
// (older than v1.3: it could not take on the state's lock, nor retry) is
// refused too, nothing stopped.
func TestRestartBinaryCheck(t *testing.T) {
	state := t.TempDir()
	st, _, _, _ := restartable(t, "--device phone\n--state="+state+"\n")
	asked := false
	st.restart = func(string, bool) { asked = true }
	script := func(body string) string {
		p := filepath.Join(t.TempDir(), "reqcove")
		os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755)
		return p
	}
	startBinary = script(`echo "12:00:00 check-config: --keep-awake: a newer check refuses" >&2; exit 1`)
	a := restartOp(t.Context(), st, 0, false)
	if a.OK || a.after != nil || !strings.Contains(a.Message, "refuses the settings") || !strings.Contains(a.Message, "--keep-awake: a newer check refuses") || !strings.HasSuffix(a.Message, "; nothing stopped") {
		t.Errorf("refused: %q", a.Message)
	}
	startBinary = script(`echo "boom" >&2; exit 3`)
	if a := restartOp(t.Context(), st, 0, false); a.OK || !strings.Contains(a.Message, "exit status 3: boom") {
		t.Errorf("failed otherwise: %q", a.Message)
	}
	if m, _ := filepath.Glob(filepath.Join(state, "restart-*")); len(m) != 0 || asked {
		t.Errorf("stopped: %v %v", m, asked)
	}
	startBinary = script(`echo "flag provided but not defined: -check-config" >&2; echo "Usage: reqcove run [flags]" >&2; exit 2`)
	a = restartOp(t.Context(), st, 0, false)
	if a.OK || a.after != nil || !strings.Contains(a.Message, "is older than v1.3") || !strings.Contains(a.Message, "stop run and start it again yourself") || !strings.HasSuffix(a.Message, "; nothing stopped") || strings.Contains(a.Message, "Usage") {
		t.Errorf("an older binary: %q", a.Message)
	}
	if m, _ := filepath.Glob(filepath.Join(state, "restart-*")); len(m) != 0 || asked {
		t.Errorf("an older binary: stopped: %v %v", m, asked)
	}
	startBinary = script(`exit 0`)
	if a := restartOp(t.Context(), st, 0, false); !a.OK {
		t.Errorf("checked: %q", a.Message)
	}
}
