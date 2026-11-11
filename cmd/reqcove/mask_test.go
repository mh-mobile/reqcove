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
