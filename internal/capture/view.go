package capture

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// TLSFailureView is what list_tls_failures returns.
type TLSFailureView struct {
	Time       string `json:"time"`
	Host       string `json:"host,omitempty"` // the SNI, or the IP address dialed
	Device     string `json:"device,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
	Msg        string `json:"msg,omitempty"`
	Conn       string `json:"conn"`
}

// TLSFailures returns the newest matching failures first. Of q, it uses
// Device, Host (the SNI), Since, Until and Limit.
func (s *Store) TLSFailures(q Filter) []TLSFailureView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []TLSFailureView{}
	for i := len(s.tlsFailures) - 1; i >= 0 && len(out) < q.Limit; i-- {
		f := s.tlsFailures[i]
		if !q.match(&Flow{Device: f.Device, Host: f.Host, Start: f.TS}, s.names[f.Device]) {
			continue
		}
		v := TLSFailureView{Host: f.Host, Device: f.Device, DeviceName: s.names[f.Device], Msg: f.Msg, Conn: f.Conn}
		if f.TS > 0 {
			v.Time = unixTime(f.TS).Format("2006-01-02T15:04:05.000Z07:00")
		}
		out = append(out, v)
	}
	return out
}

// DeviceInfo is what list_devices returns.
type DeviceInfo struct {
	ID           string `json:"id"` // StableID
	Name         string `json:"name,omitempty"`
	Carried      bool   `json:"carried"` // one of --device now
	Flows        int    `json:"flows"`
	TLSFailures  int    `json:"tls_failures"`
	Passthroughs int    `json:"passthroughs"`        // --pass-hosts connections kept
	LastSeen     string `json:"last_seen,omitempty"` // newest request start
}

// Devices lists the --device devices and any other device with records.
func (s *Store) Devices() []DeviceInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	byID := map[string]*DeviceInfo{}
	get := func(id string) *DeviceInfo {
		if byID[id] == nil {
			_, carried := s.names[id]
			byID[id] = &DeviceInfo{ID: id, Name: s.names[id], Carried: carried}
		}
		return byID[id]
	}
	for id := range s.names {
		get(id)
	}
	last := map[string]float64{}
	for _, f := range s.flows {
		if f.Device == "" {
			continue
		}
		get(f.Device).Flows++
		last[f.Device] = max(last[f.Device], f.Start)
	}
	for _, f := range s.tlsFailures {
		if f.Device != "" {
			get(f.Device).TLSFailures++
		}
	}
	for _, p := range s.passes {
		if p.device != "" {
			get(p.device).Passthroughs++
			last[p.device] = max(last[p.device], p.start)
		}
	}
	out := []DeviceInfo{}
	for id, d := range byID {
		if last[id] > 0 {
			d.LastSeen = unixTime(last[id]).Format("2006-01-02T15:04:05.000Z07:00")
		}
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name+out[i].ID < out[j].Name+out[j].ID })
	return out
}

// FlowView is what get_flow returns: secrets masked, body heads as text when possible.
type FlowView struct {
	Flow
	DeviceName   string `json:"device_name,omitempty"`
	ReqBodyText  string `json:"request_body_head,omitempty"`
	ReqBodyEnc   string `json:"request_body_head_encoding,omitempty"` // "base64" when that head is not text
	RespBodyText string `json:"response_body_head,omitempty"`
	RespBodyEnc  string `json:"response_body_head_encoding,omitempty"`
}

func (s *Store) Get(id string, bodies bool) (FlowView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flows[id]
	if f == nil {
		return FlowView{}, fmt.Errorf("no flow %q (evicted, or from before reqcove run restarted)", id)
	}
	v := FlowView{Flow: *f, DeviceName: s.names[f.Device]} // already masked as it arrived
	if bodies {
		v.ReqBodyText, v.ReqBodyEnc = s.bodyOut(f.ReqBody, f.ReqHeaders)
		v.RespBodyText, v.RespBodyEnc = s.bodyOut(f.RespBody, f.RespHeaders)
	}
	return v, nil
}

// omittedBody is what a head that is not text says instead: nothing in it can
// be checked for secrets, so it is not handed out while masking is on.
const omittedBody = "omitted: not text, so it cannot be checked for secrets (reqcove run --no-redact returns it)"

// bodyOut: the caller holds s.mu (s.redact).
func (s *Store) bodyOut(b Body, headers [][2]string) (string, string) {
	if s.redact && !checkable(b, headers) {
		return "", omittedBody
	}
	return bodyText(b.Head, b.Truncated)
}

// checkable: masking can only have looked at a head that was decoded (not
// wire bytes of an encoding it could not undo) and is text by its content
// type (or, with none, by its bytes alone). A protobuf can be valid UTF-8.
func checkable(b Body, headers [][2]string) bool {
	if len(b.Head) == 0 {
		return true
	}
	if !b.Decoded {
		return false
	}
	head := trimCutRune(b.Head)
	ct, _, _ := strings.Cut(strings.ToLower(header(headers, "content-type")), ";")
	ct = strings.TrimSpace(ct)
	switch {
	case ct == "":
		return strictText(head)
	case strings.HasPrefix(ct, "text/"), strings.HasSuffix(ct, "+json"), strings.HasSuffix(ct, "+xml"),
		ct == "application/json", ct == "application/xml", ct == "application/javascript",
		ct == "application/x-www-form-urlencoded", ct == "application/graphql", ct == "application/x-ndjson":
		return isText(head)
	}
	return false
}

// strictText: UTF-8 with no control characters but tab, newline and return.
func strictText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' || c == 0x7f {
			return false
		}
	}
	return true
}

func (s *Store) Stats() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The window the records cover: older flows were evicted to stay within the limits.
	var oldest, newest string
	if len(s.order) > 0 {
		if t := s.flows[s.order[0]].Start; t > 0 {
			oldest = unixTime(t).Format("2006-01-02T15:04:05.000Z07:00")
		}
		if t := s.flows[s.order[len(s.order)-1]].Start; t > 0 {
			newest = unixTime(t).Format("2006-01-02T15:04:05.000Z07:00")
		}
	}
	truncated := 0
	for _, f := range s.flows {
		if f.ReqBody.Truncated || f.RespBody.Truncated {
			truncated++
		}
	}
	return map[string]any{
		"flows": len(s.order), "held_bytes": s.heldBytes, "evicted": s.evicted, "checkpoint": s.seq,
		"oldest_flow": oldest, "newest_flow": newest, "max_flows": s.maxFlows, "max_bytes": s.maxBytes,
		"flows_with_truncated_bodies": truncated,
		"state":                       s.state, "state_detail": s.stateDetail, "restarts": s.restarts,
		"started":              s.started.Format("2006-01-02T15:04:05.000Z07:00"),
		"addon_dropped_bodies": s.earlier[0] + s.addonDropped[0], "addon_dropped_events": s.earlier[1] + s.addonDropped[1],
		"bad_lines": s.badLines, "unknown_version": s.unknownVer, "orphan_updates": s.orphanUpdates,
		"out_of_scope": s.outOfScope + s.earlier[2] + s.addonOOS, "all_hosts": s.allow.All, "redacting": s.redact,
		"tls_failures":   len(s.tlsFailures),
		"passed_through": s.passCount, "passed_through_open": len(s.passByConn),
		"pass_hosts": orNone(s.allow.PassHosts), "refused_hosts": s.refusedLocked(),
		"mitmproxy": s.hello.Mitmproxy, "python": s.hello.Python, "brotli": s.hello.Brotli,
		"brotli_decode": s.hello.BrotliDecode, "zstd_decode": s.hello.ZstdDecode,
		"rules": s.hello.Rules, "rules_error": s.hello.RulesError, "resolve": s.hello.Resolve, "upstream": s.hello.Upstream,
	}
}

// bodyText returns a head as text, or as base64 when it is not text. Each
// body on its own: a binary request must not turn a JSON response into base64.
// A head cut at the limit may end inside a UTF-8 character; that tail is dropped.
func bodyText(b []byte, truncated bool) (string, string) {
	if truncated && !utf8.Valid(b) {
		for cut := 1; cut < utf8.UTFMax && cut < len(b); cut++ {
			if utf8.Valid(b[:len(b)-cut]) {
				b = b[:len(b)-cut]
				break
			}
		}
	}
	if isText(b) {
		return string(b), ""
	}
	return base64.StdEncoding.EncodeToString(b), "base64"
}

func isText(b []byte) bool {
	return utf8.Valid(b) && !bytes.Contains(b, []byte{0})
}

func orNone(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
