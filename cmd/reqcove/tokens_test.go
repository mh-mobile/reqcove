package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A token is made once (0600) and kept; a file of another form, or not a
// plain file, is replaced by a new one.
func TestKeptToken(t *testing.T) {
	state := t.TempDir()
	first, made, err := keptToken(state, "ui-token")
	if err != nil || !made || !tokenForm.MatchString(first) {
		t.Fatalf("first: %q %v %v", first, made, err)
	}
	if fi, _ := os.Stat(filepath.Join(state, "ui-token")); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	if again, made, _ := keptToken(state, "ui-token"); again != first || made {
		t.Errorf("not kept: %q %v", again, made)
	}
	for _, bad := range []string{"x", "$argon2id$v=19$m", first + "\nscripts: [evil.py]", first + "\n"} {
		os.WriteFile(filepath.Join(state, "web-token"), []byte(bad), 0o600)
		if got, made, _ := keptToken(state, "web-token"); !made || got == bad || !tokenForm.MatchString(got) {
			t.Errorf("%q kept: %q", bad, got)
		}
	}
	os.Remove(filepath.Join(state, "web-token"))
	os.Symlink(filepath.Join(state, "ui-token"), filepath.Join(state, "web-token"))
	if got, made, _ := keptToken(state, "web-token"); !made || got == first {
		t.Errorf("a link followed: %q", got)
	}
}
