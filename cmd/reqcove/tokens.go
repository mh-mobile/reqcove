package main

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
)

// The tokens of the page (--ui) and mitmweb (--web) are kept in the state
// directory, so links and bookmarks keep working across starts. Deleting a
// file and starting again changes that token.

// tokenForm is rand.Text's: a value of any other form is made anew. mitmweb's
// goes into its YAML config, where a newline or a leading $ would mean more.
var tokenForm = regexp.MustCompile(`^[A-Z2-7]{26}$`)

// keptToken returns the token in state/name, made (and written 0600) when the
// file is missing, not a plain file, or not of tokenForm. run holds the state
// lock, so no other run writes it meanwhile.
func keptToken(state, name string) (token string, made bool, err error) {
	path := filepath.Join(state, name)
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() {
		if b, err := os.ReadFile(path); err == nil && tokenForm.Match(b) {
			return string(b), false, nil
		}
	}
	os.Remove(path) // a link or a directory is not followed or kept
	token = rand.Text()
	return token, true, os.WriteFile(path, []byte(token), 0o600)
}
