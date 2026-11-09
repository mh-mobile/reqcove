package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mh-mobile/reqcove/internal/exitnode"
)

// Several exit nodes on one computer: one `reqcove run` per --state, each
// with its own name, mitmweb port and settings, sharing the default state's CA.

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// nodeName is --hostname when given; else a --state named reqcove-SOMETHING
// (a leading dot dropped) names the node after it, so two runs differ in the
// Tailscale app without a flag. Anything else is "reqcove".
func nodeName(fs *flag.FlagSet, state string) string {
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == "hostname" })
	if given {
		return fs.Lookup("hostname").Value.String()
	}
	base := strings.ToLower(strings.TrimPrefix(filepath.Base(state), "."))
	if strings.HasPrefix(base, "reqcove") && dnsLabel.MatchString(base) {
		return base
	}
	return "reqcove"
}

func isDefaultState(state string) bool {
	a, _ := filepath.Abs(state)
	b, _ := filepath.Abs(defaultState())
	return a == b
}

// webPorts are where mitmweb may listen on this computer: 8081, or one of
// 8091-8099 while another run has it. The node's port is exitnode.WebPort on
// every node, so links on the iPhone do not change with the order of starts.
var webPorts = []int{exitnode.WebPort, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099}

// pickWebPort returns the first of webPorts free on 127.0.0.1.
// ponytail: free when asked, not held until mitmweb binds; mitmweb's own error says so if it races.
func pickWebPort() (int, error) {
	for _, p := range webPorts {
		if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
			l.Close()
			return p, nil
		}
	}
	return 0, fmt.Errorf("--web: ports 8081 and 8091-8099 on 127.0.0.1 are all taken")
}

// isNew: dir does not exist yet, or is empty (Finder's .DS_Store aside).
func isNew(dir string) bool {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	return err == nil && (len(ents) == 0 || len(ents) == 1 && ents[0].Name() == ".DS_Store")
}

// mcpHint is the command that registers this node's agent tools in Claude Code.
func mcpHint(state, name string) string {
	if isDefaultState(state) {
		return "claude mcp add reqcove -- reqcove mcp"
	}
	abs, err := filepath.Abs(state)
	if err != nil {
		abs = state
	}
	return fmt.Sprintf("claude mcp add %s -- reqcove mcp --state %s", name, shellWord(abs))
}

// shellWord quotes s for a POSIX shell when it needs it.
func shellWord(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./+:@") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
