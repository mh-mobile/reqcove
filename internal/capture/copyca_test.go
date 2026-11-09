package capture

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCopyCA(t *testing.T) {
	parent := t.TempDir()
	src, dst := t.TempDir(), filepath.Join(parent, "st[ab]", "mitmproxy") // [ in the path: not a pattern
	sibling := filepath.Join(parent, "sta", "mitmproxy")
	os.MkdirAll(sibling, 0o700)
	os.WriteFile(filepath.Join(sibling, "mitmproxy-ca.pem.tmp9"), nil, 0o600)
	if ok, err := CopyCA(src, dst); ok || err != nil { // no CA to copy
		t.Fatalf("empty src: %v %v", ok, err)
	}
	// Without the .cer: nothing copied, and why.
	for _, name := range []string{"mitmproxy-ca.pem", "mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.p12"} {
		os.WriteFile(filepath.Join(src, name), []byte(name), 0o600)
	}
	if ok, err := CopyCA(src, dst); ok || err == nil || !strings.Contains(err.Error(), "no mitmproxy-ca-cert.cer") {
		t.Fatalf("src without the .cer: %v %v", ok, err)
	}
	if ents, _ := os.ReadDir(dst); len(ents) != 0 {
		t.Fatalf("left behind: %v", ents)
	}
	for _, name := range []string{"mitmproxy-ca-cert.cer", "mitmproxy-ca.p12", "mitmproxy-dhparam.pem", "config.yaml"} {
		os.WriteFile(filepath.Join(src, name), []byte(name), 0o600)
	}
	// One that cannot be read, found once copying began: what was copied goes.
	if os.Getuid() != 0 { // root reads it all the same
		p12 := filepath.Join(src, "mitmproxy-ca-cert.p12")
		os.Chmod(p12, 0)
		if ok, err := CopyCA(src, dst); ok || err == nil {
			t.Fatalf("unreadable .p12: %v %v", ok, err)
		}
		if ents, _ := os.ReadDir(dst); len(ents) != 0 {
			t.Fatalf("a failed copy left %v", ents)
		}
		os.Chmod(p12, 0o600)
	}
	// A temporary file a copy cut short left (it may hold the key) goes too; a
	// backup of the user's, and another directory's files, stay.
	os.MkdirAll(dst, 0o700)
	os.WriteFile(filepath.Join(dst, "mitmproxy-ca.pem.tmp12345"), []byte("key"), 0o600)
	os.WriteFile(filepath.Join(dst, "mitmproxy-ca-cert.pem.bak"), []byte("mine"), 0o600)
	if ok, err := CopyCA(src, dst); !ok || err != nil {
		t.Fatalf("copy: %v %v", ok, err)
	}
	if os.Remove(filepath.Join(dst, "mitmproxy-ca-cert.pem.bak")) != nil {
		t.Error("the user's .bak was removed")
	}
	if _, err := os.Stat(filepath.Join(sibling, "mitmproxy-ca.pem.tmp9")); err != nil {
		t.Error("another directory's file was removed")
	}
	want := []string{"mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.p12", "mitmproxy-ca-cert.pem", "mitmproxy-ca.pem"} // what mitmproxy and mitm.it read; not mitmproxy-ca.p12, the dhparam or config.yaml
	var got []string
	ents, _ := os.ReadDir(dst)
	for _, e := range ents {
		got = append(got, e.Name())
	}
	if !slices.Equal(got, want) {
		t.Errorf("copied %v, want %v", got, want)
	}
	for _, name := range want {
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
	// Nor is a key whose certificate files are missing (ensureCA writes them from it).
	keyOnly := t.TempDir()
	os.WriteFile(filepath.Join(keyOnly, "mitmproxy-ca.pem"), []byte("trusted key"), 0o600)
	if ok, err := CopyCA(src, keyOnly); ok || err != nil {
		t.Errorf("onto a key alone: %v %v", ok, err)
	}
	if b, _ := os.ReadFile(filepath.Join(keyOnly, "mitmproxy-ca.pem")); string(b) != "trusted key" {
		t.Errorf("key replaced: %q", b)
	}
	if CAFiles[len(CAFiles)-1] != "mitmproxy-ca.pem" {
		t.Error("the key must come last: its presence says the copy is whole")
	}
}
