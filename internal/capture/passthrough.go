package capture

import (
	"slices"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// maxPasses bounds the --pass-hosts and raw TCP connections kept, as TLS
// failures are.
const maxPasses = 1000

type passthrough struct {
	conn, device, host, server, note string
	alpn                             []string
	alpnNeg                          string // raw: the protocol the client got
	start, end                       float64
	up, down                         int64
	unknown                          bool // the bytes went with mitmdump
	raw                              bool // decrypted, then carried as raw TCP: not a --pass-hosts host's
}

// PassthroughView is a connection with no flow as list_passthrough returns it:
// a --pass-hosts host's (reason pass_hosts: what is outside TLS, nothing
// inside), or an allowed host's that mitmproxy carried as raw TCP, not read as
// HTTP (reason raw_tcp: its sizes, never its bytes).
type PassthroughView struct {
	Time        string   `json:"time"`          // the connection's start
	End         string   `json:"end,omitempty"` // empty while open
	Open        bool     `json:"open"`          // still connected; bytes come when it ends
	DurationMS  int64    `json:"duration_ms,omitempty"`
	Reason      string   `json:"reason"` // pass_hosts or raw_tcp
	Host        string   `json:"host"`   // the SNI the client sent (the address without one)
	Device      string   `json:"device,omitempty"`
	DeviceName  string   `json:"device_name,omitempty"`
	Server      string   `json:"server,omitempty"` // IP:port connected to
	ALPNOffered []string `json:"alpn_offered,omitempty"`
	ALPN        string   `json:"alpn_negotiated,omitempty"` // raw_tcp: the protocol the client got
	// pass_hosts: from the client, TLS included, the whole connection; raw_tcp:
	// what mitmproxy relayed, inside TLS.
	BytesUp      int64  `json:"bytes_up"`
	BytesDown    int64  `json:"bytes_down"`
	BytesUnknown bool   `json:"bytes_unknown,omitempty"` // mitmproxy restarted mid-connection: the bytes above are not its
	Note         string `json:"note,omitempty"`          // why it ended early (mitmproxy restarted)
	Conn         string `json:"conn"`
}

// Passthroughs returns the newest --pass-hosts and raw TCP connections first.
// Of q, it uses Device, Host, Since, Until and Limit.
func (s *Store) Passthroughs(q Filter) []PassthroughView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []PassthroughView{}
	for i := len(s.passes) - 1; i >= 0 && len(out) < q.Limit; i-- {
		p := s.passes[i]
		// A connection open at since counts: a long one (an app's push channel)
		// started before it.
		t := p.start
		if q.Since > 0 && t < q.Since && (p.end == 0 || p.end >= q.Since) {
			t = q.Since
		}
		if !q.match(&Flow{Device: p.device, Host: p.host, Start: t}, s.names[p.device]) {
			continue
		}
		v := PassthroughView{Reason: "pass_hosts", Host: p.host, Device: p.device, DeviceName: s.names[p.device], Server: p.server,
			ALPNOffered: p.alpn, BytesUp: p.up, BytesDown: p.down, BytesUnknown: p.unknown, Note: p.note, Conn: p.conn, Open: p.end == 0}
		if p.raw {
			v.Reason, v.ALPN = "raw_tcp", p.alpnNeg
		}
		if p.start > 0 {
			v.Time = unixTime(p.start).Format("2006-01-02T15:04:05.000Z07:00")
		}
		if p.end > 0 {
			v.End = unixTime(p.end).Format("2006-01-02T15:04:05.000Z07:00")
			v.DurationMS = int64((p.end - p.start) * 1000)
		}
		out = append(out, v)
	}
	return out
}

// RawHost is an allowed host whose connections from a device mitmproxy carried
// as raw TCP, not read as HTTP: decrypted, but no flow is recorded.
type RawHost struct {
	Device      string   `json:"device"`
	DeviceName  string   `json:"device_name,omitempty"`
	Host        string   `json:"host"`
	Connections int      `json:"connections"`               // of those kept
	ALPN        []string `json:"alpn_negotiated,omitempty"` // the protocols the client got, when TLS said
}

// rawHostsLocked lists the raw TCP connections kept by device and host, the
// most first, at most 30.
func (s *Store) rawHostsLocked() []RawHost {
	type key struct{ device, host string }
	by := map[key]*RawHost{}
	for _, p := range s.passes {
		if !p.raw {
			continue
		}
		k := key{p.device, p.host}
		if by[k] == nil {
			by[k] = &RawHost{Device: p.device, DeviceName: s.names[p.device], Host: p.host}
		}
		r := by[k]
		r.Connections++
		if p.alpnNeg != "" && !slices.Contains(r.ALPN, p.alpnNeg) {
			r.ALPN = append(r.ALPN, p.alpnNeg)
		}
	}
	out := []RawHost{}
	for _, r := range by {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Connections > out[j].Connections || out[i].Connections == out[j].Connections && out[i].Device+out[i].Host < out[j].Device+out[j].Host
	})
	return out[:min(len(out), 30)]
}

// RefusedHost is a host a device refused Reqcove's certificate for, again and
// again, while it accepted it elsewhere: what certificate pinning (or a client
// with its own list of CAs) looks like. --pass-hosts lets it through.
type RefusedHost struct {
	Device     string `json:"device"`
	DeviceName string `json:"device_name,omitempty"`
	Host       string `json:"host"`
	Refusals   int    `json:"refusals"`
	// SiblingsRecorded: the device has decrypted flows to another host of the
	// same domain, so a *.domain in --pass-hosts would stop recording those.
	SiblingsRecorded bool `json:"siblings_recorded,omitempty"`
}

// refusedAfter is how many refusals, alerts or hang-ups during the handshake,
// make a host one: single ones happen (a cancelled request, a network blip).
const refusedAfter = 3

// refusedLocked lists the hosts refused at least refusedAfter times by a
// device that has decrypted HTTPS flows, for none of which it is the host,
// and that are not passed through already; the most refused first, at most 30.
// registrable is host's registrable domain (example.co.uk for api.example.co.uk),
// or host itself when it has none (an address, a bare name).
func registrable(host string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(host, ".")); err == nil {
		return d
	}
	return host
}

func (s *Store) refusedLocked() []RefusedHost {
	type key struct{ device, host string }
	counts := map[key]int{}
	for _, f := range s.tlsFailures {
		if strings.Contains(f.Msg, "does not trust the proxy's certificate") || strings.Contains(f.Msg, "disconnected during the handshake") {
			counts[key{f.Device, f.Host}]++
		}
	}
	if len(counts) == 0 {
		return []RefusedHost{}
	}
	trusting := map[string]bool{} // devices with a decrypted request
	seen := map[key]bool{}
	domains := map[key]bool{} // (device, registrable domain) with decrypted flows
	for _, f := range s.flows {
		if strings.HasPrefix(f.URL, "https://") {
			trusting[f.Device] = true
			h := strings.ToLower(f.Host)
			seen[key{f.Device, h}] = true
			domains[key{f.Device, registrable(h)}] = true
		}
	}
	out := []RefusedHost{}
	for k, n := range counts {
		// A host as a host name: an SNI is the phone's app's to choose, and these
		// go into a command run suggests (--pass-hosts …).
		if n >= refusedAfter && trusting[k.device] && !seen[k] && !s.allow.Passed(k.host) && validHost(k.host) && k.host != "mitm.it" {
			out = append(out, RefusedHost{k.device, s.names[k.device], k.host, n, domains[key{k.device, registrable(k.host)}]})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Refusals > out[j].Refusals || out[i].Refusals == out[j].Refusals && out[i].Host < out[j].Host
	})
	return out[:min(len(out), 30)] // run groups them by domain
}

// PassHost reports whether host is one of --pass-hosts: carried undecrypted,
// so no flow of it is ever recorded.
func (s *Store) PassHost(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if host == "" {
		return false
	}
	host = normHost(host)
	if s.allow.Passed(host) {
		return true
	}
	for _, p := range s.allow.PassHosts { // a host filter matches subdomains: so does this
		if p = strings.TrimPrefix(p, "*."); strings.HasSuffix(p, "."+host) {
			return true
		}
	}
	return false
}
