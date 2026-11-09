package capture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyCA(t *testing.T) {
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "mitmproxy")
	if ok, err := CopyCA(src, dst); ok || err != nil { // no CA to copy
		t.Fatalf("empty src: %v %v", ok, err)
	}
	for _, name := range append(CAFiles, "mitmproxy-ca.p12", "mitmproxy-dhparam.pem", "config.yaml") {
		os.WriteFile(filepath.Join(src, name), []byte(name), 0o600)
	}
	if ok, err := CopyCA(src, dst); !ok || err != nil {
		t.Fatalf("copy: %v %v", ok, err)
	}
	ents, _ := os.ReadDir(dst)
	if len(ents) != len(CAFiles) {
		t.Errorf("copied %v, want %v", ents, CAFiles)
	}
	for _, name := range CAFiles {
		fi, err := os.Stat(filepath.Join(dst, name))
		if b, _ := os.ReadFile(filepath.Join(dst, name)); err != nil || string(b) != name || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %q", name, err, b)
		}
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", fi.Mode())
	}
	// A CA already there is never replaced.
	os.WriteFile(filepath.Join(src, "mitmproxy-ca.pem"), []byte("another"), 0o600)
	if ok, err := CopyCA(src, dst); ok || err != nil {
		t.Errorf("second copy: %v %v", ok, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "mitmproxy-ca.pem")); string(b) != "mitmproxy-ca.pem" {
		t.Errorf("replaced: %q", b)
	}
	if CAFiles[len(CAFiles)-1] != "mitmproxy-ca.pem" {
		t.Error("the key must come last: its presence says the copy is whole")
	}
}
