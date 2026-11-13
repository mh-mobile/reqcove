package capture

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Presets: rules in the --rules file marked preset: NAME (a mock, map_remote,
// modify_headers or resolve) apply only while an agent has turned them on
// (activate_preset), for at most PresetMaxSeconds and, for a mock, if it says,
// PresetMaxTimes requests. Their state
// lives in the addon alone (a reload or a restart turns them off); reqcove
// asks it over ControlSock, one JSON line each way.

// ControlSock is the addon's socket in the state directory.
const ControlSock = "mock.sock"

const (
	PresetMaxSeconds = 300
	PresetMaxTimes   = 20
)

// Preset kinds.
var PresetKinds = []string{"mock", "map_remote", "modify_headers", "resolve"}

// Preset is one preset as list_presets shows it: never a body, a header's
// value, a filter or a regex.
type Preset struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Description string   `json:"description,omitempty"`
	Target      string   `json:"target,omitempty"`  // map_remote: scheme and host it sends requests to
	Header      string   `json:"header,omitempty"`  // modify_headers: the request header's name
	Host        string   `json:"host,omitempty"`    // resolve: the name
	Address     string   `json:"address,omitempty"` // resolve: where that name connects
	Method      *string  `json:"method"`
	URL         string   `json:"url,omitempty"`
	Operation   *string  `json:"operation"`
	Status      *int     `json:"status"`             // none for fault: close
	DelayMS     int      `json:"delay_ms,omitempty"` // before the answer or the close
	Fault       *string  `json:"fault"`
	Active      bool     `json:"active"`
	Remaining   *int     `json:"remaining"`  // requests left while active; none: no count
	ExpiresAt   *float64 `json:"expires_at"` // while active (Unix seconds)
}

// Activation is activate_mock's answer from the addon.
type Activation struct {
	Name      string   `json:"name"`
	ExpiresAt float64  `json:"expires_at"`
	Times     *int     `json:"times"`
	TurnedOff []string `json:"turned_off"` // presets for the same match it turned off
}

// ErrNoControl: the addon could not be reached (mitmproxy restarting):
// nothing was asked.
var ErrNoControl = errors.New("mitmproxy did not answer about presets (restarting?)")

// ErrUncertain: the request went to the addon but no answer came back: it may
// have taken effect.
var ErrUncertain = errors.New("mitmproxy did not answer in time: it may or may not have taken effect; call list_presets to see")

// ErrNoAnswer: a read (the list) went unanswered: nothing changed.
var ErrNoAnswer = errors.New("mitmproxy did not answer about presets in time (busy?)")

// PresetName is a preset name's form, as the addon checks it: never sent (nor
// logged) when it is not one.
var PresetName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (c *Capture) control(ctx context.Context, req map[string]any, out any) error {
	return control(ctx, c.cfg.Dir, c.SocksSecret, req, out)
}

func control(ctx context.Context, dir, secret string, req map[string]any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", filepath.Join(dir, ControlSock))
	if err != nil {
		return ErrNoControl
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	req["secret"] = secret
	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return ErrUncertain // part of it may have gone
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return ErrUncertain
	}
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(line, &e) == nil && e.Error != "" {
		return errors.New(e.Error)
	}
	return json.Unmarshal(line, out)
}

// Presets lists the --rules file's presets of kind ("": every kind) and which are on.
func (c *Capture) Presets(ctx context.Context, kind string) ([]Preset, error) {
	var out struct {
		Presets []Preset `json:"presets"`
	}
	err := c.control(ctx, withKind(map[string]any{"op": "list"}, kind), &out)
	return out.Presets, readControl(err)
}

// readControl: a read that went unanswered changed nothing.
func readControl(err error) error {
	if errors.Is(err, ErrUncertain) {
		return ErrNoAnswer
	}
	return err
}

// Rule is one --rules rule as list_rules shows it: its kind, its index among
// that kind's rules in the file, its preset, and derived parts only, never a
// filter, a regex, a header value, a body or a path.
type Rule struct {
	Kind      string  `json:"kind"`
	Index     int     `json:"index"`
	Preset    string  `json:"preset,omitempty"`
	Active    *bool   `json:"active,omitempty"`    // a preset: on now
	Method    *string `json:"method,omitempty"`    // mock
	URL       string  `json:"url,omitempty"`       // mock
	Operation *string `json:"operation,omitempty"` // mock
	Status    *int    `json:"status,omitempty"`    // mock; none for fault: close
	DelayMS   int     `json:"delay_ms,omitempty"`  // mock
	Fault     *string `json:"fault,omitempty"`     // mock
	Target    string  `json:"target,omitempty"`    // map_remote: scheme and host, "path only" or "not shown"
	Header    string  `json:"header,omitempty"`    // modify_headers: the header's name
	Direction string  `json:"direction,omitempty"` // modify_headers: request, response or both
	Host      string  `json:"host,omitempty"`      // resolve: the name
	Address   string  `json:"address,omitempty"`   // resolve: where it connects
}

// Rules is list_rules' answer from the addon.
type Rules struct {
	Loaded         bool   `json:"loaded"`                // a --rules file is in effect
	RulesError     string `json:"rules_error,omitempty"` // why the file (or its last change) did not load
	KeepHostHeader bool   `json:"keep_host_header,omitempty"`
	Rules          []Rule `json:"rules"`
}

// Explanation is explain_rules' answer from the addon: what the rules do now
// to a request of a method and URL, by the request path's own code, on a
// request never sent.
type Explanation struct {
	InScope          bool                `json:"in_scope"`
	Scope            string              `json:"scope,omitempty"` // out of scope: why
	Loaded           bool                `json:"loaded"`
	RulesError       string              `json:"rules_error,omitempty"`
	Rewrites         []string            `json:"rewrites"`                    // as a record's rewrites would say
	ResponseRewrites []string            `json:"response_rewrites,omitempty"` // modify_headers on the answer
	Mocked           bool                `json:"mocked"`
	MappedTo         string              `json:"mapped_to,omitempty"` // map_remote's scheme and host
	Presets          []string            `json:"presets"`             // presets on now that change or answer it
	IfTurnedOn       map[string][]string `json:"if_turned_on"`        // a preset off now: its rewrites were it on
	CannotTell       []string            `json:"cannot_tell"`         // rules whose filter reads more than a method and URL tell
	Conditions       []string            `json:"conditions,omitempty"`
}

// ListRules is every --rules rule, by kind and index, and which presets are on.
func (c *Capture) ListRules(ctx context.Context) (Rules, error) {
	var out Rules
	return out, readControl(c.control(ctx, map[string]any{"op": "rules"}, &out))
}

// Explain says what the rules do now to a request of method, url and
// (GraphQL) operation, without sending it or changing a preset.
func (c *Capture) Explain(ctx context.Context, method, url, operation string) (Explanation, error) {
	var out Explanation
	req := map[string]any{"op": "explain", "method": method, "url": url}
	if operation != "" {
		req["operation"] = operation
	}
	return out, readControl(c.control(ctx, req, &out))
}

// withKind limits req to presets of kind (activate_mock: mocks only).
func withKind(req map[string]any, kind string) map[string]any {
	if kind != "" {
		req["kind"] = kind
	}
	return req
}

// Activate turns preset name (of kind, or "" for any) on for seconds and, for
// a mock when times > 0, that many requests; it replaces the limits of a
// preset already on.
func (c *Capture) Activate(ctx context.Context, name, kind string, seconds, times int) (Activation, error) {
	var a Activation
	if !PresetName.MatchString(name) {
		return a, errors.New("no preset by that name")
	}
	if seconds < 1 || seconds > PresetMaxSeconds {
		return a, errors.New("at most 5 minutes")
	}
	req := withKind(map[string]any{"op": "activate", "name": name, "seconds": seconds}, kind)
	if times != 0 {
		if times < 1 || times > PresetMaxTimes {
			return a, errors.New("times must be from 1 to 20")
		}
		req["times"] = times
	}
	err := c.control(ctx, req, &a)
	return a, err
}

// Deactivate turns preset name (of kind, or "" for any) off; wasActive says it was on.
func (c *Capture) Deactivate(ctx context.Context, name, kind string) (wasActive bool, err error) {
	var out struct {
		WasActive bool `json:"was_active"`
	}
	if !PresetName.MatchString(name) {
		return false, errors.New("no preset by that name")
	}
	err = c.control(ctx, withKind(map[string]any{"op": "deactivate", "name": name}, kind), &out)
	return out.WasActive, err
}

// RulesCheck is the addon's word on a --rules file as it would be (reqcove
// mock add): Why it would not load ("" when it would), never a rule's text.
type RulesCheck struct {
	Why    *string `json:"check"`  // none: an older run, without the op
	Same   bool    `json:"same"`   // the running run reads the file at target
	Reload bool    `json:"reload"` // and takes it again when it changes (--rules-reload)
}

// CheckRules asks the run whose state directory is dir to check the rules
// file at path (beside target, so a relative body_file reads the same) as it
// checks its own at start, with its --allow-hosts and --pass-hosts. It sends
// the path, not the text: a control line is at most 64 KiB.
// ErrNoControl: no run there.
func CheckRules(ctx context.Context, dir, path, target string) (RulesCheck, error) {
	var out RulesCheck
	secret, err := os.ReadFile(filepath.Join(dir, "socks-secret"))
	if err != nil {
		return out, ErrNoControl
	}
	if err := control(ctx, dir, string(secret), map[string]any{"op": "check", "path": path, "target": target}, &out); err != nil {
		return out, err
	}
	if out.Why == nil {
		return out, errors.New("the running reqcove has no check (an older build)")
	}
	return out, nil
}

// CheckRulesPython checks the rules file at path with the addon's loader in
// mitmproxy's Python (cfg's, Dir aside), without a run: no host is out of
// scope. It says why the file would not load, "" when it would.
func CheckRulesPython(ctx context.Context, cfg Config, path string) (string, error) {
	dir, err := os.MkdirTemp("", "reqcove-check-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	for f, b := range map[string][]byte{"addon.py": addonPy, "mitm.py": mitmPy, "mitm.py.lock": mitmLock} {
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			return "", err
		}
	}
	cfg.Dir = dir
	bin, args := PyCommand(cfg, "python")
	cmd := exec.CommandContext(ctx, bin, append(args, "-c", checkScript, dir, path)...)
	cmd.Dir = dir               // python -c imports from the current directory first
	cmd.WaitDelay = time.Second // on Ctrl-C, not held by a child of uv that keeps the pipes
	var stderr strings.Builder
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s: %v %s", bin, err, strings.TrimSpace(stderr.String()))
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var out RulesCheck
	if json.Unmarshal([]byte(lines[len(lines)-1]), &out) != nil || out.Why == nil {
		return "", fmt.Errorf("mitmproxy's Python gave no answer: %q", b)
	}
	return *out.Why, nil
}

// checkScript: _load_checked as run's, every host in scope.
const checkScript = `import sys, json
sys.path.insert(0, sys.argv[1])
import addon
r = addon.addons[0]
r.allow_all = True
print(json.dumps({"check": r._load_checked(sys.argv[2])[1]}))
`
