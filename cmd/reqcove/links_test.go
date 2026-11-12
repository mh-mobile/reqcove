package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	} {
		r.Write([]byte(line))
	}
	got := b.String()
	for _, leak := range []string{"1a2b3c4d5e6f", "mkey:0123abcd", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"} {
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
	err := links(context.Background(), []string{"--state", dir})
	if err == nil || !strings.Contains(err.Error(), "only to a terminal") {
		t.Errorf("err %v", err)
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
