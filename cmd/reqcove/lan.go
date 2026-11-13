package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// LAN mode's access control (as Charles's): a client address may send through
// this Mac once the user allowed it, here or at run's prompt. The allowed
// addresses are kept in the state directory, 0600, with when each was allowed;
// run reads the file again every few seconds.

const lanAllowedFile = "lan-allowed" // ADDR RFC3339 lines

type lanAllowed struct {
	addr netip.Addr
	when time.Time
}

// readLANAllowed reads the allowed addresses; no file is none.
func readLANAllowed(state string) ([]lanAllowed, error) {
	b, err := os.ReadFile(filepath.Join(state, lanAllowedFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var out []lanAllowed
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil || !a.Is4() {
			continue
		}
		var when time.Time
		if len(f) > 1 {
			when, _ = time.Parse(time.RFC3339, f[1])
		}
		out = append(out, lanAllowed{a, when})
	}
	return out, nil
}

// writeLANAllowed replaces the file at once (a new 0600 file renamed over
// it), so run never reads half of it.
func writeLANAllowed(state string, list []lanAllowed) error {
	var b strings.Builder
	for _, a := range list {
		fmt.Fprintf(&b, "%s %s\n", a.addr, a.when.UTC().Format(time.RFC3339))
	}
	f, err := os.CreateTemp(state, "."+lanAllowedFile+"-*") // 0600
	if err != nil {
		return err
	}
	_, err = f.WriteString(b.String())
	if err = errors.Join(err, f.Close()); err == nil {
		err = os.Rename(f.Name(), filepath.Join(state, lanAllowedFile))
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// allowLAN adds addr (now), if it is not there yet.
// ponytail: read-modify-write without a lock; a `lan allow` and run's prompt
// at the same instant can lose one. A lock file if that ever happens.
func allowLAN(state string, addr netip.Addr) (bool, error) {
	list, err := readLANAllowed(state)
	if err != nil {
		return false, err
	}
	if slices.ContainsFunc(list, func(a lanAllowed) bool { return a.addr == addr }) {
		return false, nil
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		return false, err
	}
	return true, writeLANAllowed(state, append(list, lanAllowed{addr, time.Now()}))
}

// lanAddrs is run's view of the file: on an error, none (refuse all).
func lanAddrs(state string) func() []netip.Addr {
	var warned string
	return func() []netip.Addr {
		list, err := readLANAllowed(state)
		if err != nil {
			if err.Error() != warned {
				warned = err.Error()
				log.Printf("WARN: %s: %v: no LAN client is allowed until it reads", lanAllowedFile, err)
			}
			return nil
		}
		warned = ""
		out := make([]netip.Addr, len(list))
		for i, a := range list {
			out[i] = a.addr
		}
		return out
	}
}

// lanAsker asks on run's terminal, one address at a time, whether to allow a
// client refused for the first time. The proxy never waits: an address not
// answered yet stays refused, and past a few waiting the others are not asked.
func lanAsker(ctx context.Context, in io.Reader, out io.Writer, state string) func(netip.Addr) {
	q := make(chan netip.Addr, 8)
	go func() {
		sc := bufio.NewScanner(in)
		for {
			var a netip.Addr
			select {
			case <-ctx.Done():
				return
			case a = <-q:
			}
			fmt.Fprintf(out, "LAN client %v wants to send through this Mac (its requests to the allowed hosts are recorded). Allow %v? [y/N] ", a, a)
			if !sc.Scan() {
				return // stdin closed: no more questions
			}
			if ans := strings.ToLower(strings.TrimSpace(sc.Text())); ans != "y" && ans != "yes" {
				log.Printf("LAN client %v stays refused (later: %s %v)", a, withState("reqcove lan allow", state), a)
				continue
			}
			if _, err := allowLAN(state, a); err != nil {
				log.Printf("WARN: allowing %v: %v", a, err)
				continue
			}
			log.Printf("LAN client %v allowed (kept in %s; to take it back: %s %v)", a, filepath.Join(state, lanAllowedFile), withState("reqcove lan deny", state), a)
		}
	}()
	return func(a netip.Addr) {
		select {
		case q <- a:
		default:
		}
	}
}

// tailnetOnly are run's flags for the tailnet node, which --lan does not start.
var tailnetOnly = map[string]string{
	"device":   "it names tailnet devices; in LAN mode clients are allowed by address (reqcove lan allow ADDR)",
	"ui":       "the page is served on the tailnet node",
	"mcp-http": "the tools are served on the tailnet node",
	"hostname": "it names the tailnet node",
	"dns":      "it is the exit node's DNS; LAN mode looks names up with this computer's resolver",
}

// lanFlags refuses, with a reason, what does not go with --lan (or without it).
func lanFlags(fs *flag.FlagSet, on bool, proxyPort int) error {
	var refused error
	fs.Visit(func(f *flag.Flag) {
		if refused != nil {
			return
		}
		if why, ok := tailnetOnly[f.Name]; ok && on {
			refused = fmt.Errorf("--%s does not go with --lan, which starts no tailnet node: %s", f.Name, why)
		} else if f.Name == "lan-interface" && !on {
			refused = errors.New("--lan-interface goes with --lan")
		}
	})
	if refused == nil && on && proxyPort == 0 {
		refused = errors.New("--lan needs a --proxy-port: the LAN proxy listens on it")
	}
	return refused
}

// lan allows, denies and lists the LAN mode client addresses. Only in a
// terminal (stdin and stdout): it decides who may send through this Mac, so
// not an agent's to run (a help, not a guarantee, as links).
func lan(_ context.Context, args []string) error {
	const use = "reqcove lan allow ADDR | lan deny ADDR | lan list  [--state DIR]"
	// The words anywhere among the flags: run's hints write `lan allow --state DIR ADDR`.
	var words, flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			words = append(words, a)
			continue
		}
		flags = append(flags, a)
		if name, _, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "="); name == "state" && !hasValue && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	fls := flag.NewFlagSet("lan", flag.ExitOnError)
	state := fls.String("state", defaultState(), "state directory")
	if err := parseFlags(fls, flags); err != nil {
		return err
	}
	words = append(words, "", "")
	if words[2] != "" {
		return fmt.Errorf("unexpected argument %q (usage: %s)", words[2], use)
	}
	return lanIn(os.Stdin, os.Stdout, *state, words[0], words[1], use)
}

func lanIn(in, out *os.File, state, sub, arg, use string) error {
	if !isTerminal(in) || !isTerminal(out) {
		return errors.New("reqcove lan runs only in a terminal: it decides who may send through this Mac. Run it in your own terminal")
	}
	switch sub {
	case "list":
		list, err := readLANAllowed(state)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			fmt.Fprintf(out, "no LAN client allowed (%s ADDR allows one)\n", withState("reqcove lan allow", state))
		}
		for _, a := range list {
			fmt.Fprintf(out, "%-15s allowed %s\n", a.addr, a.when.Local().Format("2006-01-02 15:04"))
		}
		return nil
	case "allow", "deny":
	default:
		return errors.New("usage: " + use)
	}
	addr, err := netip.ParseAddr(arg)
	if err != nil || !addr.Is4() {
		return fmt.Errorf("%q: give the client's IPv4 address, as run logs it (usage: %s)", arg, use)
	}
	if sub == "allow" {
		added, err := allowLAN(state, addr)
		if err != nil {
			return err
		}
		if added {
			fmt.Fprintf(out, "%v allowed: it may send through this Mac in LAN mode, and its requests to the allowed hosts are recorded (a running run takes it within seconds)\n", addr)
		} else {
			fmt.Fprintf(out, "%v was allowed already\n", addr)
		}
		return nil
	}
	list, err := readLANAllowed(state)
	if err != nil {
		return err
	}
	n := len(list)
	list = slices.DeleteFunc(list, func(a lanAllowed) bool { return a.addr == addr })
	if len(list) == n {
		fmt.Fprintf(out, "%v was not allowed\n", addr)
		return nil
	}
	if err := writeLANAllowed(state, list); err != nil {
		return err
	}
	fmt.Fprintf(out, "%v denied: a running run refuses its new connections within seconds (those open go on until they close)\n", addr)
	return nil
}
