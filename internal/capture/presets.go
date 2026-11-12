package capture

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"time"
)

// Mock presets: mocks in the --rules file marked preset: NAME answer only
// while an agent has turned them on (activate_mock), for at most
// PresetMaxSeconds and, if it says, PresetMaxTimes requests. Their state
// lives in the addon alone (a reload or a restart turns them off); reqcove
// asks it over ControlSock, one JSON line each way.

// ControlSock is the addon's socket in the state directory.
const ControlSock = "mock.sock"

const (
	PresetMaxSeconds = 300
	PresetMaxTimes   = 20
)

// Preset is one preset as list_mock_presets shows it: never its body or its
// headers' values.
type Preset struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Method      *string  `json:"method"`
	URL         string   `json:"url"`
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

// ErrNoControl: the addon did not answer (mitmproxy restarting, or a build
// without presets).
var ErrNoControl = errors.New("mitmproxy did not answer about presets (restarting?)")

func (c *Capture) control(ctx context.Context, req map[string]any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", filepath.Join(c.cfg.Dir, ControlSock))
	if err != nil {
		return ErrNoControl
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	req["secret"] = c.SocksSecret
	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return ErrNoControl
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return ErrNoControl
	}
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(line, &e) == nil && e.Error != "" {
		return errors.New(e.Error)
	}
	return json.Unmarshal(line, out)
}

// Presets lists the --rules file's presets and which are on.
func (c *Capture) Presets(ctx context.Context) ([]Preset, error) {
	var out struct {
		Presets []Preset `json:"presets"`
	}
	err := c.control(ctx, map[string]any{"op": "list"}, &out)
	return out.Presets, err
}

// Activate turns preset name on for seconds and, when times > 0, that many
// requests; it replaces the limits of a preset already on.
func (c *Capture) Activate(ctx context.Context, name string, seconds, times int) (Activation, error) {
	var a Activation
	if seconds < 1 || seconds > PresetMaxSeconds {
		return a, errors.New("at most 5 minutes")
	}
	req := map[string]any{"op": "activate", "name": name, "seconds": seconds}
	if times != 0 {
		if times < 1 || times > PresetMaxTimes {
			return a, errors.New("times must be from 1 to 20")
		}
		req["times"] = times
	}
	err := c.control(ctx, req, &a)
	return a, err
}

// Deactivate turns preset name off; wasActive says it was on.
func (c *Capture) Deactivate(ctx context.Context, name string) (wasActive bool, err error) {
	var out struct {
		WasActive bool `json:"was_active"`
	}
	err = c.control(ctx, map[string]any{"op": "deactivate", "name": name}, &out)
	return out.WasActive, err
}
