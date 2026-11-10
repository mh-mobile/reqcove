// Package skills holds the agent skill, embedded so `reqcove init` installs
// the one that matches the binary.
package skills

import _ "embed"

//go:embed reqcove/SKILL.md
var Reqcove []byte
