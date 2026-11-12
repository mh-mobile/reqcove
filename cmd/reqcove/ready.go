package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/mh-mobile/reqcove/internal/exitnode"
	"github.com/skip2/go-qrcode"
	"golang.org/x/term"
)

// printQR draws url as a QR code, with what it is for, when w is a terminal:
// typing http://mitm.it by hand is easy to get wrong (Safari tries https).
func printQR(w *os.File, url, what string) { printQRs(w, qrItem{url, what}) }

type qrItem struct{ url, caption string }

// printQRs prints QR codes for the terminal, side by side when it is wide
// enough. Low error correction keeps them small: they are scanned off a screen.
func printQRs(w *os.File, items ...qrItem) {
	if !isTerminal(w) {
		return // a log file or pipe: no QR codes (and no tokens in them)
	}
	cols, _, err := term.GetSize(int(w.Fd()))
	if err != nil {
		cols = 80
	}
	fmt.Fprint(w, sideBySide(items, cols))
}

func sideBySide(items []qrItem, cols int) string {
	var blocks [][]string
	width := 0
	for _, it := range items {
		q, err := qrcode.New(it.url, qrcode.Low)
		if err != nil {
			continue
		}
		lines := strings.Split(strings.TrimRight(q.ToSmallString(false), "\n"), "\n")
		blocks = append(blocks, append([]string{it.caption + ":"}, lines...))
		width = max(width, utf8.RuneCountInString(lines[0]))
	}
	const gap = "   "
	perRow := max(1, (cols+len(gap))/(width+len(gap))) // as many as fit, the rest on the next rows
	var b strings.Builder
	for start := 0; start < len(blocks); start += perRow {
		row := blocks[start:min(start+perRow, len(blocks))]
		lines := 0
		for _, bl := range row {
			lines = max(lines, len(bl))
		}
		for r := 0; r < lines; r++ {
			var cells []string
			for _, bl := range row {
				cell := ""
				if r < len(bl) {
					cell = bl[r]
				}
				if n := utf8.RuneCountInString(cell); n > width {
					cell = string([]rune(cell)[:width]) // a caption wider than its code
				} else {
					cell += strings.Repeat(" ", width-n)
				}
				cells = append(cells, cell)
			}
			b.WriteString(strings.TrimRight(strings.Join(cells, gap), " ") + "\n")
		}
	}
	return b.String()
}

func firstIPv4(ips []string) string {
	for _, s := range ips {
		if ip, err := netip.ParseAddr(s); err == nil && ip.Is4() {
			return s
		}
	}
	return ""
}

// readyBlock is what run prints once the node is up: the devices, the links
// and the next steps, numbered, in one place.
// Off a terminal (terminal false) the callers pass hints in place of the
// links and the token, and there are no QR codes.
func readyBlock(devices map[string]string, uiLink, webLink, mcpURL, mcpToken, state string, steps []string, terminal bool, presets []string) string {
	var b strings.Builder
	qr := "; QR code below"
	if !terminal {
		qr = ""
	}
	fmt.Fprintf(&b, "\n──────── reqcove is ready ────────\n")
	var names []string
	for _, n := range devices {
		if n == exitnode.Local.Name {
			n += fmt.Sprintf(" (this computer's apps, through 127.0.0.1:%d)", localProxyPort)
		}
		names = append(names, n)
	}
	slices.Sort(names)
	fmt.Fprintf(&b, "devices:  %s\n", strings.Join(names, ", "))
	if uiLink != "" {
		fmt.Fprintf(&b, "--ui:     %s  (the flows, read only%s; the same at each start, rm %s to change it)\n", uiLink, qr, "-- "+shellWord(filepath.Join(state, "ui-token")))
	}
	if webLink != "" {
		fmt.Fprintf(&b, "--web:    %s  (mitmweb: unmasked, can edit and replay%s; rm %s to change it)\n", webLink, qr, "-- "+shellWord(filepath.Join(state, "web-token")))
	}
	if mcpURL != "" {
		fmt.Fprintf(&b, "--mcp-http: %s  with the header  Authorization: Bearer %s\n            (for agents on your own devices; the same at each start, rm %s to change it)\n", mcpURL, mcpToken, "-- "+shellWord(filepath.Join(state, "mcp-token")))
	}
	if slices.ContainsFunc(names, func(n string) bool { return !strings.HasPrefix(n, exitnode.Local.Name+" ") }) { // a phone, not only this computer's apps
		fmt.Fprintf(&b, "CA:       http://mitm.it  (on an iPhone, with the exit node on%s; once per device)\n", strings.Replace(qr, ";", ":", 1))
	}
	if len(presets) > 0 {
		fmt.Fprintf(&b, "presets:  %s  (mocks an agent may turn on, at most 5 minutes each time; `%s` shows which are on)\n", strings.Join(presets, ", "), withState("reqcove status", state))
	}
	if len(steps) > 0 {
		fmt.Fprintf(&b, "\nnext:\n")
		for i, st := range steps {
			fmt.Fprintf(&b, "  %d. %s\n", i+1, strings.ReplaceAll(st, "\n", "\n     ")) // a command on a line of its own
		}
	} else {
		fmt.Fprintf(&b, "\nnothing left to set up (`%s` says the same later)\n", withState("reqcove status", state))
	}
	fmt.Fprintf(&b, "──────────────────────────────────\n")
	return b.String()
}

func presetNames(stats map[string]any) []string {
	names, _ := stats["mock_presets"].([]string)
	return names
}

// readyGate says when the node is ready to report: Running at two polls in a
// row that agree on the first step left (as the log's steps wait), since just
// after start an approved node looks unapproved for a moment.
type readyGate struct {
	seen  bool
	first string
}

func (g *readyGate) ready(s exitnode.Status) bool {
	if s.Backend != "Running" {
		g.seen = false
		return false
	}
	first := exitnode.FirstStep(s)
	agreed := g.seen && first == g.first
	g.seen, g.first = true, first
	return agreed
}
