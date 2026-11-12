package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
)

func TestConfigWords(t *testing.T) {
	for line, want := range map[string][]string{
		`--device "Taro's iPhone"`:            {"--device", "Taro's iPhone"},
		`--device 'Taro iPhone'  # a comment`: {"--device", "Taro iPhone"},
		`# all a comment`:                     nil,
		`--mask-values "a\"b\\c"`:             {"--mask-values", `a"b\c`},
		`--allow-hosts api.example.com,*.cdn`: {"--allow-hosts", "api.example.com,*.cdn"},
		`--hostname ''`:                       {"--hostname", ""},
		"  --ui\t":                            {"--ui"},
	} {
		got, err := configWords(line)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q %v", line, got, err)
		}
	}
	for _, bad := range []string{`--device "open`, `--device 'open`} {
		if _, err := configWords(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func testFlags() (*flag.FlagSet, *[]string, *[]string) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var devices, allow []string
	fs.Func("device", "", func(v string) error { devices = append(devices, v); return nil })
	fs.Func("allow-hosts", "", func(v string) error {
		v, err := hostList(v)
		allow = append(allow, v)
		return err
	})
	fs.String("hostname", "reqcove", "")
	fs.Bool("no-redact", false, "")
	fs.Bool("web", false, "")
	fs.Bool("rules-reload", false, "")
	fs.String("config", "", "")
	return fs, &devices, &allow
}

func writeConfig(t *testing.T, text string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config")
	os.WriteFile(p, []byte(text), mode)
	os.Chmod(p, mode)
	return p
}

func TestParseConfig(t *testing.T) {
	// The file's flags first; the command line's add up (repeatable) or win.
	fs, devices, allow := testFlags()
	p := writeConfig(t, "--device \"Taro's iPhone\"\n--allow-hosts api.example.com\n--hostname from-file\n", 0o600)
	if err := parseConfig(fs, p, allow); err != nil {
		t.Fatal(err)
	}
	if err := fs.Parse([]string{"--config", p, "--device", "ipad", "--hostname", "typed"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*devices, []string{"Taro's iPhone", "ipad"}) || fs.Lookup("hostname").Value.String() != "typed" || len(*allow) != 1 {
		t.Errorf("devices %q, hostname %s, allow %q", *devices, fs.Lookup("hostname").Value, *allow)
	}
	// Refused there: each flag that stays on the command line, '*' however spelled.
	hosts := filepath.Join(t.TempDir(), "hosts")
	os.WriteFile(hosts, []byte("api.example.com\n*\n"), 0o600)
	for text, want := range map[string]string{
		"--no-redact\n":           "--no-redact only on the command line",
		"--web\n":                 "--web only on the command line",
		"--rules-reload\n":        "--rules-reload only on the command line",
		"--config other\n":        "--config only on the command line",
		"--allow-hosts '*'\n":     "--allow-hosts '*' only on the command line",
		"--allow-hosts @" + hosts: "--allow-hosts '*' only on the command line",
		"--device a stray\n":      `"stray" is not a flag`,
	} {
		fs, _, allow := testFlags()
		if err := parseConfig(fs, writeConfig(t, text, 0o600), allow); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", text, err, want)
		}
	}
	// The file must not be writable by others.
	fs, _, allow = testFlags()
	if err := parseConfig(fs, writeConfig(t, "--device a\n", 0o666), allow); err == nil || !strings.Contains(err.Error(), "writable by others") {
		t.Errorf("0666: %v", err)
	}
	fs, _, allow = testFlags()
	if err := parseConfig(fs, writeConfig(t, "--device a\n", 0o644), allow); err != nil {
		t.Errorf("0644: %v", err)
	}
}

// run reads --config before anything else, and refuses what it must.
func TestRunConfigRefused(t *testing.T) {
	// A state and a uvx of its own: were the refusal gone, run would fail fast, not start.
	p := writeConfig(t, "--device phone\n--state "+t.TempDir()+"\n--uvx /nonexistent/uvx\n--no-redact\n", 0o600)
	err := run(context.Background(), []string{"--config", p})
	if err == nil || !strings.Contains(err.Error(), "--no-redact only on the command line") {
		t.Errorf("%v", err)
	}
	if err := run(context.Background(), []string{"--config", filepath.Join(t.TempDir(), "none")}); err == nil || !strings.Contains(err.Error(), "--config") {
		t.Errorf("missing: %v", err)
	}
}

// Under brew services (launchd's label in XPC_SERVICE_NAME) status says so.
func TestStatusService(t *testing.T) {
	allow, _ := capture.ParseAllowHosts([]string{"api.example.com"})
	t.Setenv("XPC_SERVICE_NAME", "homebrew.mxcl.reqcove")
	if s := statusOut(exitnode.Status{}, map[string]any{"state": "ready"}, allow, capture.CA{}, nil).Service; s != "homebrew.mxcl.reqcove" {
		t.Errorf("service %q", s)
	}
	t.Setenv("XPC_SERVICE_NAME", "application.com.apple.Terminal.123") // a terminal's
	if s := statusOut(exitnode.Status{}, map[string]any{"state": "ready"}, allow, capture.CA{}, nil).Service; s != "" {
		t.Errorf("from a terminal: %q", s)
	}
}
