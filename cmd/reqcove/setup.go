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
// --config file at the default path (the device and the hosts only), adds the
// skill, and says how to start. It never starts run, installs anything but the
// skill, or prints a login URL. Only in a terminal: its questions are the user's.
func setup(_ context.Context, args []string) error {
	fls := flag.NewFlagSet("setup", flag.ExitOnError)
	if err := parseFlags(fls, args); err != nil {
		return err
	}
	if !terminal(os.Stdin) || !terminal(os.Stdout) {
		return errors.New("reqcove setup runs only in a terminal: it asks you questions. Run it in your own terminal (or follow the steps by hand: README, Use)")
	}
	return setupIn(os.Stdin, os.Stdout, defaultConfig(), brewPrefix())
}

// brewPrefix is Homebrew's prefix when this binary is its formula's
// (PREFIX/Cellar/reqcove/VERSION/bin/reqcove), else "".
func brewPrefix() string {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if i := strings.Index(exe, "/Cellar/reqcove/"); err == nil && i > 0 {
		return exe[:i]
	}
	return ""
}

var errNoAnswer = errors.New("no answer: setup stopped there (run reqcove setup again to go on)")

// setupIn asks through in and answers on out; config is the file to write,
// brew Homebrew's prefix when installed with it.
func setupIn(in io.Reader, out io.Writer, config, brew string) error {
	r := bufio.NewReader(in) // one for the whole run: answers typed ahead stay in it
	ask := func(q string) (string, error) {
		fmt.Fprint(out, q)
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintln(out)
			return "", errNoAnswer
		}
		return strings.TrimSpace(line), nil
	}
	yes := func(q string) (bool, error) {
		a, err := ask(q + " [y/N] ")
		return strings.EqualFold(a, "y") || strings.EqualFold(a, "yes"), err
	}
	shown := shellWord(config)

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
	if have {
		fmt.Fprintf(out, "   %s is there already:\n", shown)
		if b, err := os.ReadFile(config); err != nil {
			fmt.Fprintf(out, "   (not readable: %v)\n", err)
		} else {
			fmt.Fprint(out, indent(string(b), "   | ", "\n"))
		}
		if write, err = yes("   Replace it?"); err != nil {
			return err
		}
		if !write {
			fmt.Fprintln(out, "   kept")
			if _, err := checkConfig(config); err != nil {
				fmt.Fprintf(out, "   but: %v\n", err)
			}
		}
	}
	var device, hosts string
	for write && device == "" {
		fmt.Fprint(out, "   The iPhone's name in your tailnet: in the Tailscale app on it, or `tailscale status`\n   (`reqcove status` lists the devices it sees once run runs). Empty skips this step.\n")
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
		fmt.Fprint(out, "   Hosts to record, comma-separated (api.example.com,*.example-cdn.com). Empty: none yet;\n   once run runs, `summarize` (for an agent) or `reqcove status` lists the hosts the iPhone reached.\n")
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
			err = errors.New("'*' records every site: only on the command line (reqcove run --config FILE --allow-hosts '*')")
		}
		if err != nil {
			fmt.Fprintf(out, "   %v\n", err)
			continue
		}
		hosts = strings.Join(allow.Hosts, ",")
		break
	}

	if write {
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
	fmt.Fprint(out, "   Give the agent the tools (Claude Code; other agents: the command reqcove mcp in their MCP settings):\n     claude mcp add reqcove -- reqcove mcp\n")

	fmt.Fprintln(out, "\n4. Start it")
	switch {
	case !have:
		fmt.Fprint(out, "   in a terminal: reqcove run --device NAME --allow-hosts HOSTS (or run reqcove setup again for the file)\n")
	case brew != "":
		etc := filepath.Join(brew, "etc", "reqcove")
		fmt.Fprintf(out, "   brew services reads %s: link the file there, then start it:\n     mkdir -p %s && ln -s %s %s\n     brew services start reqcove\n   or in a terminal: reqcove run --config %s\n",
			shellWord(filepath.Join(etc, "config")), shellWord(etc), shown, shellWord(filepath.Join(etc, "config")), shown)
	default:
		fmt.Fprintf(out, "   now and at each login: reqcove service install\n   or in a terminal: reqcove run --config %s\n", shown)
	}
	fmt.Fprint(out, "   Then `reqcove links` prints the login URL (the first time, in your terminal), and `reqcove status` what is left:\n   approving the exit node, choosing it on the iPhone, trusting the CA there.\n")
	fmt.Fprint(out, "   LAN mode (no Tailscale): --lan is not kept in a config file; in a terminal: reqcove run --lan --allow-hosts HOSTS\n")
	return nil
}

// writeSetupConfig writes the --config file, whole or not at all, 0600 (its
// directory 0700 when new), and reads it back as run will.
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
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return err
	}
	words, _, err := readConfig(path)
	if err != nil {
		return err
	}
	if !slices.Equal(words, want) {
		return fmt.Errorf("%s does not read back as written: check it by hand", path)
	}
	return nil
}
