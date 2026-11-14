// Command reqcove lets an AI agent read the HTTP(S) traffic of iPhones in
// your tailnet: the iPhone picks reqcove as its exit node, mitmproxy decrypts
// the traffic, and `reqcove mcp` serves it to the agent.
//
//	reqcove run --device NAME [--device NAME ...]   until Ctrl-C
//	reqcove mcp                                     what the agent launches
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// version is set at release builds: -ldflags "-X main.version=v0.1.0".
var version = "dev"

// buildVersion names a build from source by its commit (dev-77e6706, -dirty
// with changes not committed), so `reqcove mcp` and a `run` of other builds
// tell each other apart; a release keeps the version it was given.
func buildVersion(v string, info *debug.BuildInfo) string {
	if v != "dev" {
		return v
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch {
		case s.Key == "vcs.revision" && len(s.Value) >= 7:
			rev = s.Value[:7]
		case s.Key == "vcs.modified" && s.Value == "true":
			dirty = "-dirty"
		}
	}
	if rev == "" {
		return v
	}
	return v + "-" + rev + dirty
}

const usage = `Reqcove hands an iPhone's HTTP(S) traffic to AI agents over MCP.

Usage:
  reqcove setup      the first run, in your terminal: checks uv, writes the device and
                     the hosts to the service's config file, adds the skill, says how to start
  reqcove run --device NAME --allow-hosts HOSTS [flags]
                     (--local-proxy instead of, or with, --device: the iOS Simulator)
                     carry the device's traffic as a Tailscale exit node and record
                     the allowed hosts; prints what is left to set up
  reqcove status     what reqcove is doing, and the next steps
  reqcove run --lan --allow-hosts HOSTS [flags]
                     LAN mode, without Tailscale: an HTTP proxy on this computer's
                     LAN address for the clients you allow
  reqcove lan allow ADDR | lan deny ADDR | lan list
                     the client addresses LAN mode carries, in your terminal only
  reqcove links      the login URL and the --ui, --web, --mcp-http links, in your
                     terminal only (never for an agent)
  reqcove mark [TEXT]
                     a marker among the records (now I tap Pay), in your terminal only;
                     reqcove mark -- TEXT for a text starting with -
  reqcove mock add --rules FILE --url URL [flags]
                     add a mock to a --rules file, checked first, in your terminal
                     only (-h for its flags; --print shows it without writing)
  reqcove mcp        the MCP server for an agent: claude mcp add reqcove -- reqcove mcp
  reqcove har > flows.har
                     the recorded flows as a HAR file, masked (-h for filters)
  reqcove service install [--config FILE] [--state DIR] | service restart | service uninstall
                     start run now and at login without Homebrew (launchd or
                     systemd), with run's flags in FILE (~/.config/reqcove/config)
  reqcove cleanup    how to undo everything (--delete-state removes ~/.reqcove)
  reqcove init       add the agent skill (how to use reqcove's tools) to the agents in ~
  reqcove version

"reqcove run -h" lists run's flags. More: https://github.com/mh-mobile/reqcove
`

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		version = buildVersion(version, info)
	}
	mcpserver.Version = version
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(capture.GoMemoryLimit)
	}
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) { // under nohup it stays ignored
		sigs = append(sigs, syscall.SIGHUP) // the terminal closed: --local-proxy must still put the system proxy back
	}
	ctx, stop := signal.NotifyContext(context.Background(), sigs...)
	defer stop()
	if os.Args[1] == "run" {
		// A write to a closed stdout or stderr fails instead of killing run (Go
		// kills on EPIPE there unless SIGPIPE is notified: os/signal): with
		// `run … 2>&1 | tee`, Ctrl-C stops tee too, and run must still put the
		// system proxy back.
		signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
	}
	var err error
	if c, ok := commands[os.Args[1]]; ok {
		err = c(ctx, os.Args[2:])
	} else {
		err = other(os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

// commands are reqcove's commands with flags; the docs test parses what the
// docs write with each one's own flags.
var commands = map[string]func(context.Context, []string) error{
	"run":     run,
	"mcp":     func(ctx context.Context, args []string) error { return runMCP(ctx, args, &mcp.StdioTransport{}) },
	"status":  status,
	"har":     har,
	"cleanup": func(_ context.Context, args []string) error { return cleanup(args) },
	"init":    func(_ context.Context, args []string) error { return initSkill(os.Stdout, args) },
	"setup":   setup,
	"links":   links,
	"lan":     lan,
	"mark":    mark,
	"service": service,
	"mock":    mockCmd,
}

// noFlags are the commands that take nothing.
var noFlags = []string{"version", "--version", "-version", "help", "-h", "-help", "--help"}

func other(name string) error {
	switch name {
	case "version", "--version", "-version":
		fmt.Println("reqcove", version)
		return nil
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q", name)
}

// The mitmproxy and Python run uses, unless told otherwise; the Dockerfile
// fetches the same (TestDockerfileInStep).
const (
	defaultMitmSpec = capture.LockedMitmSpec
	defaultPython   = "3.14"
)

func defaultState() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".reqcove")
}

// parseFlags parses args and refuses leftovers: flag stops at the first one,
// so `--device Taro's iPhone --allow-hosts x` would drop the --allow-hosts.
func parseFlags(fs *flag.FlagSet, args []string) error {
	if takeFlags != nil { // the docs test: the command's flags, not run
		takeFlags(fs)
		return errFlagsTaken
	}
	fs.Usage = func() { usageOf(fs) }
	if err := fs.Parse(args); err != nil { // ExitOnError exits first; a test's ContinueOnError returns
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q (quote values with spaces, such as --device \"Taro's iPhone\")", fs.Arg(0))
	}
	// --state=~/x, or a quoted ~: the shell left the ~, which would name ./~/x
	// (for run, a place to copy the CA's key into; for cleanup, one already gone).
	if f := fs.Lookup("state"); f != nil && strings.HasPrefix(f.Value.String(), "~") {
		given := false
		fs.Visit(func(v *flag.Flag) { given = given || v.Name == "state" })
		if !given {
			return fmt.Errorf("HOME is %s, starting with ~: set it to the full path of your home directory", os.Getenv("HOME"))
		}
		return fmt.Errorf("--state %s: the shell did not expand the ~ (it does not after =, nor in quotes): write --state ~/… with a space, or the full path", f.Value.String())
	}
	return nil
}

// takeFlags, set by the docs test, is handed each command's FlagSet in place
// of parsing it. Every command calls parseFlags before doing anything else.
var (
	takeFlags     func(*flag.FlagSet)
	errFlagsTaken = errors.New("flags taken")
)

// usageOf prints a command's flags with two dashes, as the README and run's
// own messages write them (Go's flag package prints one; it takes either).
func usageOf(fs *flag.FlagSet) {
	var b strings.Builder
	fs.SetOutput(&b)
	fs.PrintDefaults()
	fs.SetOutput(os.Stderr)
	fmt.Fprintf(os.Stderr, "Usage: reqcove %s [flags]\n", fs.Name())
	for _, line := range strings.SplitAfter(b.String(), "\n") {
		if strings.HasPrefix(line, "  -") {
			line = "  --" + line[3:]
		}
		fmt.Fprint(os.Stderr, line)
	}
}

func runMCP(ctx context.Context, args []string, agent mcp.Transport) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	state := fs.String("state", defaultState(), "state directory")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	// The agent's connection stays up while run restarts or is not running.
	err := mcpserver.Proxy(ctx, filepath.Join(*state, "mcp.sock"), notRunningMsg(*state), agent)
	if ctx.Err() != nil {
		return nil // a signal: not an error
	}
	return err
}

// notRunningMsg is what the agent's tools answer while run is not running.
func notRunningMsg(state string) string {
	return fmt.Sprintf("reqcove is not running (%s). Do not start it yourself: the user starts `%s` in a terminal, or its service (brew services start reqcove), and leaves it running (if it is restarting or fetching mitmproxy the first time, wait). Then call again; the records start empty after a restart.", state, withState("reqcove run …", state))
}
