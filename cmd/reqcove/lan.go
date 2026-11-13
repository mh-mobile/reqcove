package main

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"golang.org/x/sys/unix"
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
func lanAddrs(state string) func() map[netip.Addr]time.Time {
	var warned string
	return func() map[netip.Addr]time.Time {
		list, err := readLANAllowed(state)
		if err != nil {
			if err.Error() != warned {
				warned = err.Error()
				log.Printf("WARN: %s: %v: no LAN client is allowed until it reads", lanAllowedFile, err)
			}
			return nil
		}
		warned = ""
		out := make(map[netip.Addr]time.Time, len(list))
		for _, a := range list {
			out[a.addr] = a.when
		}
		return out
	}
}

// lanAsker asks on run's terminal, one address at a time, whether to allow a
// client refused for the first time. The proxy never waits: an address not
// answered yet stays refused, and past a few waiting the others are not asked.
// It reads stdin only while run is the terminal's foreground job (a
// background read would stop run), and drops what was typed before each
// question, so an earlier Enter or y does not answer it.
func lanAsker(ctx context.Context, in io.Reader, out io.Writer, state string, tty lanTTY) func(netip.Addr) {
	q := make(chan netip.Addr, 8)
	go func() {
		for {
			var a netip.Addr
			select {
			case <-ctx.Done():
				return
			case a = <-q:
			}
			if !tty.foreground() {
				log.Printf("LAN client %v not asked: run is not the terminal's foreground job (to allow it: %s %v)", a, withState("reqcove lan allow", state), a)
				continue
			}
			tty.flush()
			fmt.Fprintf(out, "LAN client %v wants to send through this Mac (its requests to the allowed hosts are recorded). Allow %v? [y/N] ", a, a)
			// A new reader each time: nothing read ahead outlives the question.
			ans, err := bufio.NewReader(in).ReadString('\n')
			if errors.Is(err, io.EOF) && ans == "" {
				return // stdin closed: no more questions
			}
			if ans = strings.ToLower(strings.TrimSpace(ans)); ans != "y" && ans != "yes" {
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

// lanReady is the ready block's part in LAN mode.
type lanReady struct {
	listen   string // ADDR:PORT, what the iPhone's Wi-Fi proxy is set to
	allowed  []exitnode.LANAllowed
	state    string
	prompt   bool // run asks on its terminal
	caSHA256 string
	caFile   string
}

func (l *lanReady) lines(qr string) string {
	var b strings.Builder
	server, port, _ := net.SplitHostPort(l.listen)
	fmt.Fprintf(&b, "Wi-Fi proxy: on the iPhone, Settings, Wi-Fi, (i) by this network, Configure Proxy, Manual: Server %s, Port %s, Authentication off\n", server, port)
	var allowed []string
	for _, a := range l.allowed {
		if t, err := time.Parse(time.RFC3339, a.When); err == nil {
			a.Addr += " (since " + t.Local().Format("2006-01-02 15:04") + ")"
		}
		allowed = append(allowed, a.Addr)
	}
	fmt.Fprintf(&b, "allowed:  %s\n", cmp.Or(strings.Join(allowed, ", "), "none yet"))
	how := "`" + withState("reqcove lan allow", l.state) + " ADDR`"
	if l.prompt {
		how = "answer run's question here, or " + how
	}
	fmt.Fprintf(&b, "allow:    a new address is refused until you allow it: %s, with the address run logs. An address, not a device: whoever has it later is allowed too (`%s ADDR` takes it back)\n", how, withState("reqcove lan deny", l.state))
	fmt.Fprintf(&b, "CA:       http://mitm.it  (with the Wi-Fi proxy set%s; once per device). Plain HTTP on a LAN can be swapped by others on it: AirDrop %s instead, or check that the CA's SHA-256 is %s\n", strings.Replace(qr, ";", ":", 1), shellWord(l.caFile), l.caSHA256)
	return b.String()
}

// printLANStatus is `reqcove status`'s part for LAN mode.
func printLANStatus(w io.Writer, l *exitnode.LANStatus) {
	fmt.Fprintln(w, "  mode:        lan (a Wi-Fi proxy on this computer's LAN address; no tailnet node)")
	if l == nil {
		fmt.Fprintln(w, "  LAN proxy:   starting")
		return
	}
	where := l.Listen
	if where == "" {
		where = "not listening (" + l.Stopped + ")"
	}
	fmt.Fprintf(w, "  LAN proxy:   %s on %s, for clients on %s\n", where, l.Interface, l.Network)
	var allowed []string
	for _, a := range l.Allowed {
		if t, err := time.Parse(time.RFC3339, a.When); err == nil {
			a.Addr += " (since " + t.Local().Format("2006-01-02 15:04") + ")"
		}
		allowed = append(allowed, a.Addr)
	}
	fmt.Fprintf(w, "  allowed:     %s\n", cmp.Or(strings.Join(allowed, ", "), "-"))
	if len(l.Refused) > 0 {
		fmt.Fprintf(w, "  refused:     %s (not allowed, this run)\n", strings.Join(l.Refused, ", "))
	}
}

// lanSteps are LAN mode's next steps: why it does not listen, the addresses
// refused, how to set the iPhone and allow it, and allowed ones with no traffic.
func lanSteps(n exitnode.Status, devices []capture.DeviceInfo) []string {
	if n.Mode != "lan" {
		return nil
	}
	l := n.LAN
	if l == nil {
		return []string{"the LAN proxy is starting"}
	}
	allowCmd := strings.Replace(stepLinksCmd, "reqcove links", "reqcove lan allow", 1)
	server, port, _ := net.SplitHostPort(l.Listen)
	proxy := fmt.Sprintf("Settings, Wi-Fi, (i) by the network, Configure Proxy, Manual: Server %s, Port %s", server, port)
	var steps []string
	if l.Stopped != "" {
		steps = append(steps, "the LAN proxy is not listening: "+l.Stopped)
	}
	if len(l.Refused) > 0 {
		steps = append(steps, fmt.Sprintf("refused by the LAN proxy, not allowed: %s. If one is your device, allow it in your own terminal: %s ADDR (an address, not a device: whoever has it later is allowed too)", strings.Join(l.Refused, ", "), allowCmd))
	}
	var idle []string
	busy := false
	for _, d := range devices {
		if strings.HasPrefix(d.ID, "lan:") && d.Carried {
			if d.Flows+d.TLSFailures+d.Passthroughs > 0 {
				busy = true
			} else {
				idle = append(idle, d.ID)
			}
		}
	}
	switch {
	case l.Listen == "" || busy:
	case len(idle) > 0:
		steps = append(steps, fmt.Sprintf("no traffic from %s yet: set the iPhone's Wi-Fi proxy (%s)", strings.Join(idle, ", "), proxy))
	case len(l.Refused) == 0:
		steps = append(steps, fmt.Sprintf("set the iPhone's Wi-Fi proxy (%s), then allow it on this computer: answer run's question if it asks, or %s ADDR with the address run logs", proxy, allowCmd))
	}
	return steps
}

// lanTTY is what lanAsker needs of run's terminal (a seam for tests).
type lanTTY struct {
	foreground func() bool // run is the terminal's foreground process group
	flush      func()      // drop the input typed and not read yet
}

// ttyForeground: run's process group is the terminal's foreground one.
func ttyForeground(fd int) bool {
	pg, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	return err == nil && pg == unix.Getpgrp()
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
