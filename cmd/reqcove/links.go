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
	"os"
	"path/filepath"
	"strings"

	"github.com/mh-mobile/reqcove/internal/capture"
	"github.com/mh-mobile/reqcove/internal/exitnode"
	"golang.org/x/term"
)

// The login URL and the links with tokens (--ui, --web, --mcp-http) are for
// the user's eyes: run prints them on its terminal, keeps them in two files
// (0600) of the state directory, and `reqcove links` prints them again. Off a
// terminal (a service, docker logs, an agent's shell) run's output names
// `reqcove links` instead, and its log lines never carry them.

const (
	loginURLFile = "login-url" // while the node waits for a login
	linksFile    = "links"     // once run is ready: name=value lines
)

// userLinks shows the user what is for their eyes only: on run's terminal,
// and in the two files for `reqcove links`; never in a log line.
type userLinks struct {
	w        io.Writer // run's terminal, when terminal
	terminal bool
	red      *exitnode.Redactor
	state    string
	cmd      string // `reqcove links` for this state
	login    string // the login URL shown last
	lan      bool   // LAN mode: the CA comes through the Wi-Fi proxy
}

// newUserLinks is run's: the steps (status, the tools) name its links command too.
func newUserLinks(w *os.File, red *exitnode.Redactor, state, cmd string) *userLinks {
	stepLinksCmd = cmd
	return &userLinks{w: w, terminal: isTerminal(w), red: red, state: state, cmd: cmd}
}

// status keeps login-url while the node waits for a login, and shows a new
// login URL on the terminal.
func (u *userLinks) status(s exitnode.Status) {
	p := filepath.Join(u.state, loginURLFile)
	switch {
	case s.Backend == "NeedsLogin" && s.AuthURL != "" && s.AuthURL != u.login:
		u.login = s.AuthURL
		u.red.Add(u.login)
		if err := writePrivate(p, []byte(u.login+"\n")); err != nil {
			log.Printf("WARN: %s: %v", loginURLFile, err)
		}
		if u.terminal {
			fmt.Fprintf(u.w, "login URL: %s\n  (whoever opens it first puts this node in their tailnet; `%s` prints it again)\n", u.login, u.cmd)
		}
	case u.login != "" && s.Backend != "NeedsLogin":
		u.login = ""
		os.Remove(p)
	}
}

// web shows mitmweb's link on this computer (with its token).
func (u *userLinks) web(local string) {
	if u.terminal {
		fmt.Fprintf(u.w, "mitmweb on %s\n", local)
		return
	}
	addr, _, _ := strings.Cut(local, "?")
	log.Printf("mitmweb on %s (its link: `%s`)", addr, u.cmd)
}

// ready writes the links file and returns what the ready block shows for the
// links and the token: themselves on a terminal, else a hint.
func (u *userLinks) ready(ui, web, webLocal, mcp, mcpToken, ca string) (shownUI, shownWeb, shownToken string) {
	caKey := "ca"
	if u.lan {
		caKey = "ca-lan"
	}
	if err := writePrivate(filepath.Join(u.state, linksFile), formatLinks([]linkLine{{"ui", ui}, {"web", web}, {"web-local", webLocal}, {"mcp", mcp}, {"mcp-token", mcpToken}, {caKey, ca}})); err != nil {
		log.Printf("WARN: %s: %v", linksFile, err)
	}
	if u.terminal {
		return ui, web, mcpToken
	}
	hint := func(v string) string {
		if v == "" {
			return ""
		}
		return "(`" + u.cmd + "` prints it)"
	}
	return hint(ui), hint(web), hint(mcpToken)
}

// isTerminal: run's stderr is someone's terminal (also `docker run -t`).
func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// writePrivate writes data to path, 0600, as a new file: an existing one is
// removed first, so a wider mode or a link left there is not kept.
func writePrivate(path string, data []byte) error {
	os.Remove(path)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return errors.Join(err, f.Close())
}

// linkLines are the links file's lines, in the order links prints them.
type linkLine struct{ key, value string }

func formatLinks(lines []linkLine) []byte {
	var b strings.Builder
	for _, l := range lines {
		if l.value != "" {
			fmt.Fprintf(&b, "%s=%s\n", l.key, l.value)
		}
	}
	return []byte(b.String())
}

// links prints the login URL and the links run keeps, with QR codes. It
// refuses when stdout is not a terminal: what an agent runs is read by its
// model provider (a help, not a guarantee: a script can give it a terminal).
func links(_ context.Context, args []string) error {
	fls := flag.NewFlagSet("links", flag.ExitOnError)
	state := fls.String("state", defaultState(), "state directory")
	if err := parseFlags(fls, args); err != nil {
		return err
	}
	return linksTo(os.Stdout, *state)
}

func linksTo(out *os.File, state string) error {
	if !isTerminal(out) {
		return errors.New("reqcove links prints only to a terminal: its links carry tokens, and the login URL puts this node in whoever's tailnet opens it first. Run it in your own terminal")
	}
	return printLinks(out, state)
}

func printLinks(w *os.File, state string) error {
	found := false
	if b, err := os.ReadFile(filepath.Join(state, loginURLFile)); err == nil {
		found = true
		u := strings.TrimSpace(string(b))
		fmt.Fprintf(w, "log in:   %s\n", u)
		printQRs(w, qrItem{u, "the login URL"})
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.Open(filepath.Join(state, linksFile))
	if errors.Is(err, fs.ErrNotExist) {
		if !found {
			return fmt.Errorf("no links in %s: `%s` keeps them while it runs (the login URL while it waits for one, the others once it is ready)", state, withState("reqcove run", state))
		}
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	var codes []qrItem
	hasMCP := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "ui":
			fmt.Fprintf(w, "--ui:     %s  (the flows, read only)\n", v)
			codes = append(codes, qrItem{v, "--ui (the flows)"})
		case "web":
			fmt.Fprintf(w, "--web:    %s  (mitmweb: unmasked, can edit and replay)\n", v)
			codes = append(codes, qrItem{v, "--web (mitmweb, unmasked)"})
		case "web-local":
			fmt.Fprintf(w, "          %s  (the same, on this computer)\n", v)
		case "ca":
			fmt.Fprintf(w, "CA:       %s  (on an iPhone, with the exit node on; once per device)\n", v)
			codes = append(codes, qrItem{v, "CA (with the exit node on)"})
		case "ca-lan":
			advice := ""
			if ca, err := capture.ReadCA(filepath.Join(state, "mitmproxy")); err == nil {
				advice = ". " + lanCAAdvice(caPEM(state), ca.SHA256)
			}
			fmt.Fprintf(w, "CA:       %s  (on an iPhone, with the Wi-Fi proxy set; once per device%s)\n", v, advice)
			codes = append(codes, qrItem{v, "CA (with the Wi-Fi proxy set)"})
		case "mcp":
			hasMCP = true
			fmt.Fprintf(w, "--mcp-http: %s\n", v)
		case "mcp-token":
			fmt.Fprintf(w, "            with the header  Authorization: Bearer %s\n", v)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if !found && len(codes) == 0 && !hasMCP {
		fmt.Fprintln(w, "no links: this run has no --ui, --web or --mcp-http")
	}
	printQRs(w, codes...)
	return nil
}
