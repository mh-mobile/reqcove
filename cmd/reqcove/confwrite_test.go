package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// confFile writes a --config file (0600) and returns its path and run's
// arguments reading it.
func confFile(t *testing.T, text string) (string, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, []string{"--config", path}
}

// The writer writes its own flags only, each value checked; a value with a
// line break, NUL, another control character or a leading @ is refused, and
// no error quotes a value. Nothing is written.
func TestConfigWriterRefuses(t *testing.T) {
	const old = "--device x\n--mask-values=k-SECRETPATTERN\n--state=/nonexistent/s\n"
	path, args := confFile(t, old)
	for _, c := range []struct {
		e    configEdit
		want string
	}{
		{configEdit{Flag: "device", Values: []string{"MARK\nb"}}, "a line break, a control character or a leading @"},
		{configEdit{Flag: "device", Values: []string{"MARK\rb"}}, "a line break"},
		{configEdit{Flag: "device", Values: []string{"MARK\x00b"}}, "a line break"},
		{configEdit{Flag: "device", Values: []string{"MARK\x1b[31m"}}, "a control character"},
		{configEdit{Flag: "device", Values: []string{"MARK\u0085"}}, "a control character"},
		{configEdit{Flag: "device", Values: []string{"MARK\xff"}}, "a control character"},
		{configEdit{Flag: "mask-names", Values: []string{"@/MARK"}}, "a leading @"},
		{configEdit{Flag: "keep-awake", Values: []string{"MARK"}}, "--keep-awake: always, ac or never"},
		{configEdit{Flag: "dns", Values: []string{"MARK"}}, "--dns: IP addresses"},
		{configEdit{Flag: "proxy-port", Values: []string{"MARK"}}, "--proxy-port: a port"},
		{configEdit{Flag: "upstream-proxy", Values: []string{"http://u:MARK@127.0.0.1:1"}}, "no user or password"},
		{configEdit{Flag: "mask-names", Values: []string{"a,MARK b"}}, "--mask-names: names"},
		{configEdit{Flag: "no-redact", Values: []string{"true"}}, "--no-redact is not written by reqcove"},
		{configEdit{Flag: "uvx", Values: []string{"/tmp/MARK"}}, "--uvx is not written by reqcove"},
		{configEdit{Flag: "rules", Values: []string{"/tmp/MARK"}}, "--rules is not written"},
		{configEdit{Flag: "mask-values", Values: []string{"MARK"}}, "--mask-values is not written"},
		{configEdit{Flag: "upstream-ca", Values: []string{"/tmp/MARK"}}, "--upstream-ca is not written"}, // cleared only
		{configEdit{Flag: "upstream-ca", Values: nil, Add: true}, "--upstream-ca is not written"},
		{configEdit{Flag: "allow-hosts", Values: []string{"MARK.com"}, Add: true}, "--allow-hosts: only the hosts file beside the config"},
		{configEdit{Flag: "allow-hosts", Values: []string{"@/tmp/MARK"}, Add: true}, "only the hosts file beside the config"},
		{configEdit{Flag: "pass-hosts", Values: hostsFileLine(path, true).Values}, "only the hosts file beside the config"}, // not Add: a rewrite
	} {
		_, err := planConfig(path, args, nil, c.e)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "MARK") || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%#v: %v, want %q", c.e, err, c.want)
		}
	}
	if b, _ := os.ReadFile(path); string(b) != old {
		t.Errorf("written:\n%s", b)
	}
}

// The writer replaces a flag's lines (where the first was) or adds lines at
// the end, keeping every other line and comment; the old file is kept as
// config.prev (0600); the read-back is the old flags plus the change; the
// diff names only the lines changed. A flag sharing its line, or with its
// value on the next, an @FILE, a flag given on run's command line, and a
// change the next start would refuse are refused.
func TestConfigWriterDelta(t *testing.T) {
	names := filepath.Join(t.TempDir(), "names")
	os.WriteFile(names, []byte("X-Mine\n"), 0o600)
	old := "# mine\n--device \"Taro's iPhone\"   # first\n--mask-values=k-SECRETPATTERN\n--keep-awake\nac\n--verbose --ui\n--mask-names=@" + names + "\n--state=/nonexistent/s"
	path, args := confFile(t, old)
	p, err := planConfig(path, args, nil, configEdit{Flag: "device", Values: []string{"a", `b "c"`}}, configEdit{Flag: "hostname", Values: []string{"my-node"}})
	if err != nil {
		t.Fatal(err)
	}
	if d := p.diff(); d != "- --device \"Taro's iPhone\"   # first\n+ --device=a\n+ --device=\"b \\\"c\\\"\"\n+ --hostname=my-node\n" {
		t.Errorf("diff:\n%s", d)
	}
	if err := p.commit(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	want := "# mine\n--device=a\n--device=\"b \\\"c\\\"\"\n--mask-values=k-SECRETPATTERN\n--keep-awake\nac\n--verbose --ui\n--mask-names=@" + names + "\n--state=/nonexistent/s\n--hostname=my-node\n"
	if string(b) != want {
		t.Errorf("file:\n%s\nwant:\n%s", b, want)
	}
	words, _, _ := readConfig(path)
	if strings.Join(words, "|") != "--device=a|--device=b \"c\"|--mask-values=k-SECRETPATTERN|--keep-awake|ac|--verbose|--ui|--mask-names=@"+names+"|--state=/nonexistent/s|--hostname=my-node" {
		t.Errorf("read back: %q", words)
	}
	if prev, _ := os.ReadFile(path + ".prev"); string(prev) != old {
		t.Errorf("config.prev:\n%s", prev)
	}
	for _, f := range []string{path, path + ".prev"} {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v", f, fi.Mode())
		}
	}
	if ents, _ := os.ReadDir(filepath.Dir(path)); len(ents) != 2 {
		t.Errorf("left behind: %v", ents)
	}

	for _, c := range []struct {
		e    configEdit
		args []string
		want string
	}{
		{configEdit{Flag: "keep-awake", Values: []string{"never"}}, args, "line 5: --keep-awake shares its lines"},
		{configEdit{Flag: "verbose", Values: []string{"false"}}, args, "line 7: --verbose shares its lines"},
		{configEdit{Flag: "mask-names", Values: []string{"x"}}, args, "line 8: --mask-names reads a file there (@FILE)"},
		{configEdit{Flag: "local-proxy", Values: []string{"true"}}, append([]string{"--local-proxy"}, args...), "--local-proxy is given on run's command line"},
		{configEdit{Flag: "device"}, args, "the next start of run would refuse it: --device is required"},
		{configEdit{Flag: "proxy-port", Values: []string{"80"}}, append([]string{"--ui"}, args...), "--ui uses the node's port 80"},
		{configEdit{Flag: "hostname", Values: []string{"x"}}, []string{"--config", path + ".prev"}, "run was not started from --config"},
	} {
		before, _ := os.ReadFile(path)
		if _, err := planConfig(path, c.args, nil, c.e); err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%#v: %v, want %q", c.e, err, c.want)
		}
		if after, _ := os.ReadFile(path); string(after) != string(before) {
			t.Errorf("%#v: written", c.e)
		}
	}
	// The hosts file line adds up with the command line's hosts: written.
	if _, err := planConfig(path, append([]string{"--allow-hosts", "a.com"}, args...), map[string]string{setupHosts(path): "b.com\n"}, hostsFileLine(path, false)); err != nil {
		t.Errorf("the hosts file line: %v", err)
	}
}

// The read-back check: the other flags as they were, in order, and the
// flag changed as asked; anything else is not the change.
func TestSameDelta(t *testing.T) {
	old := []flagUse{{name: "device", value: "a"}, {name: "state", value: "s"}}
	e := []configEdit{{Flag: "device", Values: []string{"b"}}}
	for _, c := range []struct {
		next []flagUse
		ok   bool
	}{
		{[]flagUse{{name: "device", value: "b"}, {name: "state", value: "s"}}, true},
		{[]flagUse{{name: "state", value: "s"}, {name: "device", value: "b"}}, true},
		{[]flagUse{{name: "device", value: "b"}, {name: "state", value: "t"}}, false},
		{[]flagUse{{name: "device", value: "b"}, {name: "state", value: "s"}, {name: "ui", value: "true"}}, false},
		{[]flagUse{{name: "device", value: "a"}, {name: "device", value: "b"}, {name: "state", value: "s"}}, false},
		{[]flagUse{{name: "state", value: "s"}}, false},
	} {
		if got := sameDelta(old, c.next, e); got != c.ok {
			t.Errorf("%v: %v", c.next, got)
		}
	}
	add := []configEdit{{Flag: "device", Values: []string{"b"}, Add: true}}
	if !sameDelta(old, []flagUse{{name: "device", value: "a"}, {name: "state", value: "s"}, {name: "device", value: "b"}}, add) || sameDelta(old, []flagUse{{name: "device", value: "b"}, {name: "state", value: "s"}}, add) {
		t.Error("add")
	}
}

// A config that is a link, or not this user's, is never written; nor one
// changed since it was read (its revision), and a failed rename leaves the
// file as it was, no temp file behind.
func TestConfigWriterFile(t *testing.T) {
	path, args := confFile(t, "--device x\n--state=/nonexistent/s\n")
	edit := configEdit{Flag: "keep-awake", Values: []string{"ac"}}
	link := filepath.Join(t.TempDir(), "config")
	os.Symlink(path, link)
	if _, err := planConfig(link, []string{"--config", link}, nil, edit); err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Errorf("a link: %v", err)
	}
	if os.Getuid() != 0 {
		if _, err := planConfig("/etc/hosts", []string{"--config", "/etc/hosts"}, nil, edit); err == nil || !strings.Contains(err.Error(), "not yours") {
			t.Errorf("not mine: %v", err)
		}
	}

	p, err := planConfig(path, args, nil, edit)
	if err != nil {
		t.Fatal(err)
	}
	const edited = "--device y\n--state=/nonexistent/s\n"
	os.WriteFile(path, []byte(edited), 0o600)
	if err := p.commit(); err == nil || !strings.Contains(err.Error(), "changed since it was read") {
		t.Errorf("stale: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != edited {
		t.Errorf("stale, written:\n%s", b)
	}

	if p, err = planConfig(path, args, nil, edit); err != nil {
		t.Fatal(err)
	}
	renameConfig = func(string, string) error { return errors.New("disk full") }
	t.Cleanup(func() { renameConfig = os.Rename })
	if err := p.commit(); err == nil {
		t.Error("the rename failed: no error")
	}
	if b, _ := os.ReadFile(path); string(b) != edited {
		t.Errorf("failed rename, written:\n%s", b)
	}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".config.tmp*")); len(m) > 0 {
		t.Errorf("left behind: %v", m)
	}
}
