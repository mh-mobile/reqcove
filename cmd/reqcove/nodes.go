package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
)

// Several exit nodes on one computer: one `reqcove run` per --state, each
// with its own name, mitmweb port and settings, sharing the default state's CA.

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// nodeNameFile, in the state directory, keeps the name run gave the node, for
// the next run and for cleanup.
const nodeNameFile = "node-name"

// nodeName is --hostname when given; else the name kept in the state; else
// "reqcove" for a state an older reqcove used (its name then); else a --state
// named reqcove-SOMETHING (a leading dot dropped) names the node after it, so
// two runs differ in the Tailscale app without a flag. Anything else is "reqcove".
func nodeName(fs *flag.FlagSet, state string) string {
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == "hostname" })
	if given {
		return fs.Lookup("hostname").Value.String()
	}
	if b, err := os.ReadFile(filepath.Join(state, nodeNameFile)); err == nil {
		if n := strings.TrimSpace(string(b)); n != "" {
			return n
		}
	}
	if _, err := os.Stat(filepath.Join(state, "tsnet", "tailscaled.state")); err == nil {
		return "reqcove"
	}
	abs, err := filepath.Abs(state) // "." and "x/." name the directory too
	if err != nil {
		abs = state
	}
	base := strings.ToLower(strings.TrimPrefix(filepath.Base(abs), "."))
	if strings.HasPrefix(base, "reqcove") && dnsLabel.MatchString(base) {
		return base
	}
	return "reqcove"
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// caCopies, in the default state, lists the confdirs its CA was copied into,
// so its cleanup can name them: each holds the key.
const caCopies = "ca-copies"

func noteCACopy(confdir string) error {
	f, err := os.OpenFile(filepath.Join(defaultState(), caCopies), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(f, confdir)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// caCopiesOf lists the state directories still holding a copy of the default
// state's CA with this SHA-256.
func caCopiesOf(sha256 string) []string {
	b, _ := os.ReadFile(filepath.Join(defaultState(), caCopies))
	var dirs []string
	for _, confdir := range strings.Split(string(b), "\n") {
		if confdir == "" {
			continue
		}
		state := filepath.Dir(confdir)
		if ca, err := capture.ReadCA(confdir); err == nil && ca.SHA256 == sha256 && !slices.Contains(dirs, state) {
			dirs = append(dirs, state)
		}
	}
	return dirs
}

func keepNodeName(state, name string) error {
	return os.WriteFile(filepath.Join(state, nodeNameFile), []byte(name+"\n"), 0o600)
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
// ponytail: free when asked, not held: two runs starting at once, or one
// starting while another's mitmweb restarts, can pick the same port; mitmweb
// then fails to bind and says so. On macOS, a port another app holds on
// 0.0.0.0 or [::] looks free (127.0.0.1 binds besides it); on Linux it does not.
func pickWebPort() (int, error) {
	for _, p := range webPorts {
		if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p)); err == nil {
			l.Close()
			return p, nil
		}
	}
	return 0, fmt.Errorf("--web: ports 8081 and 8091-8099 on 127.0.0.1 are all taken")
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
	if name == "reqcove" { // the default node's, already
		name = "reqcove-" + filepath.Base(abs)
	}
	return fmt.Sprintf("claude mcp add %s -- reqcove mcp --state %s", shellWord(name), shellWord(abs))
}

// nodeWebLink is mitmweb's link, on addr here, as the iPhone opens it: through
// the node at ip, on its WebPort.
func nodeWebLink(webURL, addr, ip string) string {
	return strings.Replace(webURL, "http://"+addr+"/", fmt.Sprintf("http://%s:%d/", ip, exitnode.WebPort), 1)
}

// withState is cmd for the node of state: with --state unless it is the default.
func withState(cmd, state string) string {
	if isDefaultState(state) {
		return cmd
	}
	return cmd + " --state " + shellWord(state)
}

// shellWord quotes s for a POSIX shell when it needs it.
func shellWord(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./+:@") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
