package main

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
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
	if brew != "" {
		privateLog(brewLog(brew)) // best effort: run makes its output 0600 too, as it starts
	}
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
	own := ownTailnetDevices()
	for write && device == "" {
		if len(own) > 0 {
			fmt.Fprintln(out, "   Your own devices in your tailnet (from Tailscale on this computer):")
			for i, d := range own {
				fmt.Fprintf(out, "     %d. %s\n", i+1, d)
			}
			fmt.Fprintln(out, "   The iPhone: its number, or another device's name. Empty skips this step.")
		} else {
			fmt.Fprintf(out, "   The iPhone's name in your tailnet: in the Tailscale app on it, or `tailscale status`\n   (`%s status` lists the devices it sees once run runs). Empty skips this step.\n", rc)
		}
		if device, err = ask("   Device: "); err != nil {
			return err
		}
		if n, err := strconv.Atoi(device); err == nil && len(own) > 0 {
			if n < 1 || n > len(own) {
				fmt.Fprintf(out, "   a number from 1 to %d, or a name\n", len(own))
				device = ""
				continue
			}
			device = own[n-1].name
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
		// The hosts always in their file beside the config (none answered: a
		// file of comments), which --allow-hosts=@FILE names: Save writes it.
		// Both texts checked whole, as the next start reads them, before
		// anything is written.
		hostsFile := setupHosts(config)
		var hs []string
		if hosts != "" {
			hs = strings.Split(hosts, ",")
		}
		htext, err := hostsText(hostsFile, hs, hostsHead)
		if err != nil {
			return fmt.Errorf("%w (nothing written)", err)
		}
		ctext, want := setupConfigText(device, hostsFile)
		if _, err := setupCheck([]string{"--config", config}, []byte(ctext), map[string]string{hostsFile: htext}); err != nil {
			return fmt.Errorf("the next start would refuse these settings (%v): nothing written", err)
		}
		if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
			return err
		}
		if old != nil {
			if err := writePrivate(config+".old", old); err != nil {
				return fmt.Errorf("%s.old: %w (nothing replaced)", config, err)
			}
			fmt.Fprintf(out, "   the old one: %s\n", shellWord(config+".old"))
		}
		if fi, err := os.Lstat(hostsFile); err == nil && fi.Mode().IsRegular() {
			b, err := os.ReadFile(hostsFile)
			if err == nil {
				err = writePrivate(hostsFile+".old", b)
			}
			if err != nil {
				return fmt.Errorf("%s.old: %w (nothing replaced)", hostsFile, err)
			}
			fmt.Fprintf(out, "   the old hosts: %s\n", shellWord(hostsFile+".old"))
		}
		if err := writeHostsText(hostsFile, htext, hs); err != nil {
			return fmt.Errorf("%w (nothing replaced)", err)
		}
		if err := writeSetupConfig(config, ctext, want); err != nil {
			return err
		}
		have = true
		if hosts != "" {
			fmt.Fprintf(out, "   wrote %s, and the hosts in %s (yours only, 0600)\n", shown, shellWord(hostsFile))
		} else {
			fmt.Fprintf(out, "   wrote %s, and %s with no hosts yet (yours only, 0600): nothing is recorded until\n   you add one (`%s capture add HOST`, then `%s capture save`, or the file by hand)\n", shown, shellWord(hostsFile), rc, rc)
		}
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
	restart := "Ctrl-C and run it again"
	if !have {
		fmt.Fprintf(out, "   in a terminal: %[1]s run --device NAME --allow-hosts HOSTS (or run %[1]s setup again for the file)\n", rc)
	} else {
		cmd := rc + " run --config " + shown
		if first, _ := bareConfig(); first == config { // what a run with no arguments reads
			cmd = rc + " run"
		}
		fmt.Fprintf(out, "   in a terminal: %s (it reads %s; Ctrl-C stops it)\n", cmd, shown)
		if brew {
			fmt.Fprintln(out, "   or to start it at login, in the background: brew services start reqcove")
			restart += ", or brew services restart reqcove"
		} else {
			fmt.Fprintf(out, "   or to start it at login, in the background: %s service install\n", rc)
			restart += ", or " + rc + " service restart"
		}
	}
	fmt.Fprintf(out, "   LAN mode (no Tailscale): --lan is not kept in a config file; in a terminal: %s run --lan --allow-hosts HOSTS\n", rc)
	fmt.Fprintf(out, "   Then `%[1]s links` prints the login URL (the first time, in your terminal), and `%[1]s status` what is left:\n   approving the exit node, choosing it on the iPhone, trusting the CA there (`%[1]s links` shows its QR code).\n", rc)
	if have {
		save, files := "", shown
		if _, err := os.Stat(setupHosts(config)); err == nil {
			hf := shellWord(setupHosts(config))
			save = fmt.Sprintf("; %s capture save keeps them for the next start, in %s", rc, hf)
			files = hf + " or " + shown
		}
		fmt.Fprintf(out, "   While it runs, change the hosts recorded without a restart (the records stay):\n   %s capture add HOST (or remove, set)%s.\n", rc, save)
		fmt.Fprintf(out, "   After editing %s: %s reload takes its hosts and the --rules file without a restart;\n", files, rc)
		fmt.Fprintf(out, "   other changes need a restart (%s): a restart empties the records.\n", restart)
	}
	return nil
}

// tailnetDevice is one of the user's own devices, untagged, as Tailscale on
// this computer lists it.
type tailnetDevice struct {
	name, os string
	online   bool
}

func (d tailnetDevice) String() string {
	s := d.name + " (" + cmp.Or(d.os, "?")
	if d.online {
		s += ", online"
	}
	return s + ")"
}

// ownTailnetDevices are the user's own untagged devices on the tailnet but
// this computer, iOS first, online first: none when the Tailscale CLI is
// not there or does not answer.
func ownTailnetDevices() []tailnetDevice {
	b, err := tailscaleStatus()
	if err != nil {
		return nil
	}
	var st struct {
		Self struct{ UserID int64 }
		Peer map[string]struct {
			DNSName, OS string
			UserID      int64
			Online      bool
			Tags        []string
		}
	}
	if json.Unmarshal(b, &st) != nil {
		return nil
	}
	var out []tailnetDevice
	for _, p := range st.Peer {
		name, _, _ := strings.Cut(p.DNSName, ".")
		if p.UserID != st.Self.UserID || len(p.Tags) > 0 || name == "" || strings.HasPrefix(name, "-") {
			continue
		}
		out = append(out, tailnetDevice{name, p.OS, p.Online})
	}
	slices.SortFunc(out, func(a, b tailnetDevice) int {
		return cmp.Or(cmp.Compare(boolInt(b.os == "iOS"), boolInt(a.os == "iOS")), cmp.Compare(boolInt(b.online), boolInt(a.online)), strings.Compare(a.name, b.name))
	})
	return out
}

// setupCheck is checkFlags (a seam for tests: nothing setup writes today is
// one the next start refuses).
var setupCheck = checkFlags

// setupHosts is the hosts file beside config: ~/.config/reqcove/hosts, or
// Homebrew's etc/reqcove/hosts.
func setupHosts(config string) string { return filepath.Join(filepath.Dir(config), "hosts") }

// hostsHead starts the hosts file setup writes.
const hostsHead = "# The hosts reqcove records, one a line (# starts a comment); the config reads them\n" +
	"# with --allow-hosts=@FILE. Written by reqcove setup; reqcove capture save rewrites\n" +
	"# the hosts, keeping the comments.\n"

// setupConfigText is the --config file setup writes: the device, and the
// hosts file (setupHosts) with @; want, its words as run reads them.
func setupConfigText(device, hosts string) (text string, want []string) {
	q := func(s string) string { // "…" as configWords reads it
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
	}
	text = "# reqcove run's flags, one a line (written by reqcove setup; edit it as you like).\n" +
		"# --no-redact, --web, --rules-reload, --lan and --allow-hosts '*' are refused here.\n" +
		"--device=" + q(device) + "\n" +
		"--allow-hosts=" + q("@"+hosts) + "\n"
	return text, []string{"--device=" + device, "--allow-hosts=@" + hosts}
}

// writeSetupConfig writes the --config file text, whole or not at all, 0600
// (its directory 0700 when new), read back as run will (want) before it
// takes the file's place.
func writeSetupConfig(path, text string, want []string) error {
	dir := filepath.Dir(path)
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
