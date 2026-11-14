package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mh-mobile/reqcove/internal/capture"
)

// setup is `reqcove setup`, the first run's guide: it checks uv, writes the
// --config file the service reads (the device and the hosts only), adds the
// skill, and says how to start. It never starts run, installs anything but the
// skill, or prints a login URL. Only in a terminal: its questions are the user's.
func setup(ctx context.Context, args []string) error {
	fls := flag.NewFlagSet("setup", flag.ExitOnError)
	if err := parseFlags(fls, args); err != nil {
		return err
	}
	if !terminal(os.Stdin) || !terminal(os.Stdout) {
		return errors.New("reqcove setup runs only in a terminal: it asks you questions. Run it in your own terminal (or follow the steps by hand: README, Use)")
	}
	brew := brewPrefix()
	return setupIn(ctx, os.Stdin, os.Stdout, setupConfig(brew), brew != "")
}

// setupConfig is the file the service reads: the formula's under Homebrew
// (packaging/homebrew), else service install's.
func setupConfig(brew string) string {
	if brew != "" {
		return filepath.Join(brew, "etc", "reqcove", "config")
	}
	return defaultConfig()
}

// brewPrefix is Homebrew's prefix when this binary is its formula's
// (PREFIX/Cellar/reqcove/VERSION/bin/reqcove), else "".
func brewPrefix() string {
	exe, err := selfExe()
	if i := strings.Index(exe, "/Cellar/reqcove/"); err == nil && i > 0 {
		return exe[:i]
	}
	return ""
}

// selfExe is this binary, its symlinks resolved (a seam for tests).
var selfExe = func() (string, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	return exe, err
}

// selfCmd is this binary in the commands setup and service install print:
// reqcove when that is what PATH finds, else its full path (quoted for a shell).
func selfCmd() string {
	exe, err := selfExe()
	if err != nil {
		return "reqcove"
	}
	if p, err := exec.LookPath("reqcove"); err == nil {
		if p, err = filepath.EvalSymlinks(p); err == nil && p == exe {
			return "reqcove"
		}
	}
	return shellWord(exe)
}

var (
	errNoAnswer = errors.New("no answer: setup stopped there (run reqcove setup again to go on)")
	errStopped  = errors.New("setup stopped (Ctrl-C): nothing more done")
)

// setupIn asks through in and answers on out; config is the file to write,
// brew whether reqcove is Homebrew's formula. ctx ending (Ctrl-C) stops it at
// the question it is on.
func setupIn(ctx context.Context, in io.Reader, out io.Writer, config string, brew bool) error {
	lines := make(chan string)
	go func() { // one reader for the whole run: answers typed ahead stay in it
		defer close(lines)
		r := bufio.NewReader(in)
		for {
			line, err := r.ReadString('\n')
			if line != "" {
				select {
				case lines <- line:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	ask := func(q string) (string, error) {
		fmt.Fprint(out, q)
		select {
		case <-ctx.Done():
			fmt.Fprintln(out)
			return "", errStopped
		case line, ok := <-lines:
			if !ok {
				fmt.Fprintln(out)
				return "", errNoAnswer
			}
			return strings.TrimSpace(line), nil
		}
	}
	yes := func(q string) (bool, error) {
		a, err := ask(q + " [y/N] ")
		return strings.EqualFold(a, "y") || strings.EqualFold(a, "yes"), err
	}
	shown := shellWord(config)
	rc := selfCmd()

	fmt.Fprint(out, "Reqcove setup: each step can be skipped; nothing is started or removed.\n\n1. uv (reqcove fetches mitmproxy and Python with it)\n")
	if uvx, err := exec.LookPath("uvx"); err == nil {
		fmt.Fprintf(out, "   found: %s\n", uvx)
	} else {
		fmt.Fprint(out, "   not found: install it (brew install uv, or https://docs.astral.sh/uv/ ), then open a new terminal\n")
	}

	fmt.Fprintf(out, "\n2. The iPhone and the hosts to record, for %s\n", shown)
	_, err := os.Lstat(config)
	have := err == nil
	write := !have
	var old []byte // the file replaced, kept as .old
	if have {
		fi, err := os.Stat(config)
		if err == nil && fi.Mode().IsRegular() {
			old, err = os.ReadFile(config)
		} else if err == nil {
			err = errors.New("not a plain file")
		}
		if err != nil {
			fmt.Fprintf(out, "   %s is there already (%v): kept\n", shown, err)
		} else {
			fmt.Fprintf(out, "   %s is there already:\n", shown)
			fmt.Fprint(out, indent(string(old), "   | ", "\n"))
			if write, err = yes(fmt.Sprintf("   Replace it (the old one is kept as %s)?", shellWord(config+".old"))); err != nil {
				return err
			}
			if !write {
				fmt.Fprintln(out, "   kept")
				if _, err := checkConfig(config); err != nil {
					fmt.Fprintf(out, "   but: %v\n", err)
				}
			}
		}
	}
	var device, hosts string
	for write && device == "" {
		fmt.Fprintf(out, "   The iPhone's name in your tailnet: in the Tailscale app on it, or `tailscale status`\n   (`%s status` lists the devices it sees once run runs). Empty skips this step.\n", rc)
		if device, err = ask("   Device: "); err != nil {
			return err
		}
		if device == "" {
			write = false
			fmt.Fprintln(out, "   skipped: no file written")
		} else if strings.HasPrefix(device, "-") {
			fmt.Fprintln(out, "   a device's name, not a flag")
			device = ""
		}
	}
	for write {
		fmt.Fprintf(out, "   Hosts to record, comma-separated (api.example.com,*.example-cdn.com). Empty: none yet;\n   once run runs, `summarize` (for an agent) or `%s status` lists the hosts the iPhone reached.\n", rc)
		a, err := ask("   Hosts: ")
		if err != nil {
			return err
		}
		var hs []string // as run takes them: a pasted URL's host, not its path
		for h := range strings.SplitSeq(a, ",") {
			hs = append(hs, hostOf(strings.TrimSpace(h)))
		}
		allow, err := capture.ParseAllowHosts([]string{strings.Join(hs, ",")})
		if err == nil && allow.All {
			err = fmt.Errorf("'*' records every site: only on the command line (%s run --config FILE --allow-hosts '*')", rc)
		}
		if err != nil {
			fmt.Fprintf(out, "   %v\n", err)
			continue
		}
		hosts = strings.Join(allow.Hosts, ",")
		break
	}

	if write {
		if old != nil {
			if err := writePrivate(config+".old", old); err != nil {
				return fmt.Errorf("%s.old: %w (nothing replaced)", config, err)
			}
			fmt.Fprintf(out, "   the old one: %s\n", shellWord(config+".old"))
		}
		if err := writeSetupConfig(config, device, hosts); err != nil {
			return err
		}
		have = true
		fmt.Fprintf(out, "   wrote %s (yours only, 0600)\n", shown)
	}

	fmt.Fprintln(out, "\n3. The agent")
	ok, err := yes("   Add the skill (how to use reqcove's tools) to the agents in your home, as reqcove init does?")
	if err != nil {
		return err
	}
	if ok {
		if err := initSkill(out, nil); err != nil {
			fmt.Fprintf(out, "   %v\n", err)
		}
	}
	fmt.Fprintf(out, "   Give the agent the tools (Claude Code; other agents: the command %[1]s mcp in their MCP settings):\n     claude mcp add reqcove -- %[1]s mcp\n", rc)

	fmt.Fprintln(out, "\n4. Start it")
	switch {
	case !have:
		fmt.Fprintf(out, "   in a terminal: %[1]s run --device NAME --allow-hosts HOSTS (or run %[1]s setup again for the file)\n", rc)
	case brew:
		fmt.Fprintf(out, "   now and at each login: brew services start reqcove\n   or in a terminal: %s run --config %s\n", rc, shown)
	default:
		fmt.Fprintf(out, "   now and at each login: %[1]s service install\n   or in a terminal: %[1]s run --config %[2]s\n", rc, shown)
	}
	fmt.Fprintf(out, "   Then `%[1]s links` prints the login URL (the first time, in your terminal), and `%[1]s status` what is left:\n   approving the exit node, choosing it on the iPhone, trusting the CA there (`%[1]s links` shows its QR code).\n", rc)
	fmt.Fprintf(out, "   LAN mode (no Tailscale): --lan is not kept in a config file; in a terminal: %s run --lan --allow-hosts HOSTS\n", rc)
	return nil
}

// writeSetupConfig writes the --config file, whole or not at all, 0600 (its
// directory 0700 when new), read back as run will before it takes the
// file's place.
func writeSetupConfig(path, device, hosts string) error {
	q := func(s string) string { // "…" as configWords reads it
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
	}
	text := "# reqcove run's flags, one a line (written by reqcove setup; edit it as you like).\n" +
		"# --no-redact, --web, --rules-reload, --lan and --allow-hosts '*' are refused here.\n" +
		"--device=" + q(device) + "\n"
	want := []string{"--device=" + device}
	if hosts == "" {
		text += "# --allow-hosts=api.example.com   (none yet: nothing is recorded)\n"
	} else {
		text += "--allow-hosts=" + q(hosts) + "\n"
		want = append(want, "--allow-hosts="+hosts)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config.tmp*") // 0600
	if err != nil {
		return err
	}
	_, err = tmp.WriteString(text)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		var words []string
		if words, _, err = readConfig(tmp.Name()); err == nil && !slices.Equal(words, want) {
			err = fmt.Errorf("%s would not read back as written: nothing replaced", path)
		}
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}
