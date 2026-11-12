package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
)

// run's log output masks the tokens added and any login URL; "" and short
// values are never added (ReplaceAll("") would mark every byte).
func TestRedactor(t *testing.T) {
	var b bytes.Buffer
	r := &exitnode.Redactor{W: &b}
	r.Add("", "short", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	for _, line := range []string{
		"RegisterReq: got response; nodeKeyExpired=false, machineAuthorized=false; authURL=https://login.tailscale.com/a/1a2b3c4d5e6f\n",
		"AuthURL is https://login.tailscale.com/a/1a2b3c4d5e6f\n",
		"To start this tsnet server, restart with TS_AUTHKEY set, or go to: https://hs.example.com/register/mkey:0123abcd\n",
		`popped "https://login.tailscale.com/a/1a2b3c4d5e6f"` + "\n",
		"--ui http://100.64.0.1/?k=ABCDEFGHIJKLMNOPQRSTUVWXYZ\n",
		"older Headscale: https://hs.example.com/register?key=oldkey123\n",
		"rules: map_remote https://api.example.com/auth/login and /a/b\n",
	} {
		r.Write([]byte(line))
	}
	got := b.String()
	if !strings.Contains(got, "https://api.example.com/auth/login and /a/b") {
		t.Errorf("a URL that is no login URL masked:\n%s", got)
	}
	for _, leak := range []string{"1a2b3c4d5e6f", "mkey:0123abcd", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "oldkey123"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q left in:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, "authURL="+exitnode.RedactedLink+"\n") || !strings.Contains(got, `"`+exitnode.RedactedLink+`"`) || !strings.Contains(got, "TS_AUTHKEY") {
		t.Errorf("lines changed beyond the secrets:\n%s", got)
	}
}

// The files are new and 0600 each time: a wider mode or a link left in their
// place is not kept (os.WriteFile keeps an existing file's mode).
func TestWritePrivate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, linksFile)
	os.WriteFile(p, []byte("old"), 0o644)
	if err := writePrivate(p, []byte("ui=x\n")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	other := filepath.Join(dir, "other")
	os.WriteFile(other, []byte("keep"), 0o644)
	os.Remove(p)
	os.Symlink(other, p)
	if err := writePrivate(p, []byte("ui=y\n")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(other); string(b) != "keep" {
		t.Errorf("followed the link: %q", b)
	}
}

func TestPrintLinks(t *testing.T) {
	dir := t.TempDir()
	out := func() string {
		t.Helper()
		f, _ := os.CreateTemp(t.TempDir(), "out")
		defer f.Close()
		if err := printLinks(f, dir); err != nil {
			return "error: " + err.Error()
		}
		b, _ := os.ReadFile(f.Name())
		return string(b)
	}
	if got := out(); !strings.Contains(got, "error: no links in") {
		t.Errorf("no run: %q", got)
	}
	writePrivate(filepath.Join(dir, loginURLFile), []byte("https://login.tailscale.com/a/abc\n"))
	if got := out(); !strings.Contains(got, "log in:   https://login.tailscale.com/a/abc\n") {
		t.Errorf("login: %q", got)
	}
	os.Remove(filepath.Join(dir, loginURLFile))
	writePrivate(filepath.Join(dir, linksFile), formatLinks([]linkLine{{"ui", "http://100.64.0.1/?k=U"}, {"web", ""}, {"mcp", "http://n.ts.net:8090/mcp"}, {"mcp-token", "TOK"}}))
	got := out()
	for _, want := range []string{"--ui:     http://100.64.0.1/?k=U", "--mcp-http: http://n.ts.net:8090/mcp", "Bearer TOK"} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "--web") {
		t.Errorf("no --web, but:\n%s", got)
	}
	writePrivate(filepath.Join(dir, linksFile), formatLinks(nil))
	if got := out(); !strings.Contains(got, "no links: this run has no") {
		t.Errorf("none: %q", got)
	}
}

// links refuses when its output is not a terminal (an agent's shell, a pipe).
func TestLinksNotATerminal(t *testing.T) {
	dir := t.TempDir()
	writePrivate(filepath.Join(dir, loginURLFile), []byte("https://login.tailscale.com/a/abc\n"))
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	err := linksTo(w, dir)
	if err == nil || !strings.Contains(err.Error(), "only to a terminal") {
		t.Errorf("err %v", err)
	}
}

// run's own wiring: off a terminal the login URL and the links reach neither
// its output nor its log, only the 0600 files, and the login URL is masked
// in later log lines; on a terminal the user sees them.
func TestUserLinks(t *testing.T) {
	const login = "https://ctl.example.com/login/0123abcdef" // a shape the filter does not know
	for _, terminal := range []bool{false, true} {
		dir := t.TempDir()
		var out, logs bytes.Buffer
		red := &exitnode.Redactor{W: &logs}
		log.SetOutput(red)
		u := &userLinks{w: &out, terminal: terminal, red: red, state: dir, cmd: "reqcove links --state " + dir}
		u.status(exitnode.Status{Backend: "NeedsLogin", AuthURL: login})
		if fi, err := os.Stat(filepath.Join(dir, loginURLFile)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("login-url: %v %v", fi, err)
		}
		u.web("http://127.0.0.1:8081/?token=WEBTOKENWEBTOKEN")
		ui, web, tok := u.ready("http://100.64.0.1/?k=UITOKENUITOKEN", "http://100.64.0.1:8081/?token=WEBTOKENWEBTOKEN", "http://127.0.0.1:8081/?token=WEBTOKENWEBTOKEN", "http://n.ts.net:8090/mcp", "MCPTOKENMCPTOKEN", "http://mitm.it")
		log.Printf("again: %s", login) // masked by its value
		shown := out.String() + ui + web + tok
		for _, secret := range []string{"0123abcdef", "WEBTOKENWEBTOKEN", "UITOKENUITOKEN", "MCPTOKENMCPTOKEN"} {
			if strings.Contains(logs.String(), secret) {
				t.Errorf("terminal %v: %s in the log:\n%s", terminal, secret, logs.String())
			}
			if strings.Contains(shown, secret) != terminal {
				t.Errorf("terminal %v: %s shown %v:\n%s", terminal, secret, !terminal, shown)
			}
		}
		if b, _ := os.ReadFile(filepath.Join(dir, linksFile)); !strings.Contains(string(b), "mcp-token=MCPTOKENMCPTOKEN") || !strings.Contains(string(b), "web-local=http://127.0.0.1:8081/") {
			t.Errorf("links file: %q", b)
		}
		u.status(exitnode.Status{Backend: "Running"})
		if _, err := os.Stat(filepath.Join(dir, loginURLFile)); err == nil {
			t.Error("login-url kept after the login")
		}
	}
	log.SetOutput(os.Stderr)
}

// The steps name this node's `reqcove links` (with --state), as run sets it.
func TestStepsNameLinksState(t *testing.T) {
	newUserLinks(os.Stderr, &exitnode.Redactor{W: os.Stderr}, "/s", "reqcove links --state /s")
	defer func() { stepLinksCmd = "reqcove links" }()
	allow, _ := capture.ParseAllowHosts([]string{"api.example.com"})
	out := statusOut(exitnode.Status{Backend: "NeedsLogin"}, map[string]any{"state": "ready"}, allow, capture.CA{}, nil)
	if !strings.Contains(strings.Join(out.NextSteps, "\n"), "`reqcove links --state /s`") {
		t.Errorf("steps %v", out.NextSteps)
	}
}

// run installs the filter first, and leaves it for main's log.Fatal.
func TestRunInstallsRedactor(t *testing.T) {
	defer log.SetOutput(os.Stderr)
	log.SetOutput(os.Stderr)
	run(context.Background(), []string{"--state", t.TempDir()}) // no --device: returns early
	if _, ok := log.Writer().(*exitnode.Redactor); !ok {
		t.Errorf("log output %T", log.Writer())
	}
}

// Off a terminal the ready block names `reqcove links` (main passes the hints)
// and promises no QR codes.
func TestReadyBlockOffTerminal(t *testing.T) {
	hint := "(`reqcove links` prints it)"
	got := readyBlock(map[string]string{"n1": "iphone"}, hint, "", "http://n.ts.net:8090/mcp", hint, "/s", nil, false)
	if strings.Contains(got, "QR code") || !strings.Contains(got, "--ui:     "+hint) || !strings.Contains(got, "Bearer "+hint) {
		t.Errorf("block:\n%s", got)
	}
}
