package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// TestMaskPolicyFlags: names and patterns as given or from @FILE (comments
// and blank lines skipped); a wrong file is named by its line only; run
// refuses a bad pattern by its number, never quoting it.
func TestMaskPolicyFlags(t *testing.T) {
	dir := t.TempDir()
	names := filepath.Join(dir, "names")
	os.WriteFile(names, []byte("# ours\nclientRef, x-trace-key\n\nwsTicket2\n"), 0o600)
	values := filepath.Join(dir, "values")
	os.WriteFile(values, []byte("# the UA key\nkey=[A-Za-z0-9]{16,}\n"), 0o600)
	n, v, err := maskPolicy([]string{"a_b", "@" + names}, []string{`sid-[0-9]+`, "@" + values})
	if err != nil || strings.Join(n, " ") != "a_b clientRef x-trace-key wsTicket2" || strings.Join(v, " ") != "sid-[0-9]+ key=[A-Za-z0-9]{16,}" {
		t.Errorf("%q %q %v", n, v, err)
	}
	env := filepath.Join(dir, ".env")
	os.WriteFile(env, []byte("API_KEY=S3CRETVALUE\n"), 0o600)
	if _, _, err := maskPolicy([]string{"@" + env}, nil); err == nil || strings.Contains(err.Error(), "S3CRET") || !strings.Contains(err.Error(), "line 1") {
		t.Errorf("a .env as names: %v", err)
	}

	defer capture.SetMaskPolicy(nil, nil)
	err = run(context.Background(), []string{"--device", "phone", "--allow-hosts", "a.example", "--state", t.TempDir(), "--uvx", "/usr/bin/false",
		"--mask-values", "ok", "--mask-values", "S3CRETVALUE("})
	if err == nil || !strings.Contains(err.Error(), "pattern 2") || strings.Contains(err.Error(), "S3CRET") {
		t.Errorf("run with a bad pattern: %v", err)
	}
}

// TestPythonBelow: the locked mitmproxy needs 3.14; run says so at start.
func TestPythonBelow(t *testing.T) {
	for v, want := range map[string]bool{"3.12": true, "3.13.2": true, "python3.12": true, "3.14": false, "3.15": false, "4.0": false, "/opt/py/bin/python": false, "/tmp/app-2.0/python3.14": false, "cpython3.12": true} {
		if got := pythonBelow(v, 3, 14); got != want {
			t.Errorf("%q: %v", v, got)
		}
	}
	err := run(context.Background(), []string{"--device", "phone", "--allow-hosts", "a.example", "--state", t.TempDir(), "--uvx", "/usr/bin/false", "--python", "3.12"})
	if err == nil || !strings.Contains(err.Error(), "needs Python 3.14") {
		t.Errorf("run --python 3.12: %v", err)
	}
}
