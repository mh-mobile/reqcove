package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"
)

// event is one line from the addon (addon.py). v is the wire version.
type event struct {
	V           int         `json:"v"`
	Ev          string      `json:"ev"`
	ID          string      `json:"id"`
	Device      string      `json:"device"`
	Client      string      `json:"client"`
	TS          float64     `json:"ts"`
	TSEnd       float64     `json:"ts_end"`
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	Host        string      `json:"host"`
	Path        string      `json:"path"`
	HTTPVersion string      `json:"http_version"`
	Headers     [][2]string `json:"headers"`
	Status      int         `json:"status"`
	Reason      string      `json:"reason"`
	ReqBody     string      `json:"req_body"`
	ReqSize     int         `json:"req_body_size"`
	ReqTrunc    bool        `json:"req_body_truncated"`
	Body        string      `json:"body"`
	BodySize    int         `json:"body_size"`
	BodyTrunc   bool        `json:"body_truncated"`
	Msg         string      `json:"msg"`
	Dropped     int64       `json:"dropped"`
}

const wireVersion = 1

type Flow struct {
	ID          string      `json:"id"`
	Device      string      `json:"device,omitempty"`
	Client      string      `json:"client,omitempty"`
	Start       float64     `json:"start"`
	End         float64     `json:"end,omitempty"`
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	Host        string      `json:"host"`
	Path        string      `json:"path"`
	HTTPVersion string      `json:"http_version"`
	ReqHeaders  [][2]string `json:"request_headers"`
	ReqBody     []byte      `json:"-"`
	ReqSize     int         `json:"request_body_size"`
	ReqTrunc    bool        `json:"request_body_truncated,omitempty"`
	Status      int         `json:"status,omitempty"`
	Reason      string      `json:"reason,omitempty"`
	RespHeaders [][2]string `json:"response_headers,omitempty"`
	RespBody    []byte      `json:"-"`
	RespSize    int         `json:"response_body_size"`
	RespTrunc   bool        `json:"response_body_truncated,omitempty"`
	Error       string      `json:"error,omitempty"`
}

// store keeps the most recent flows in memory.
// ponytail: fixed cap and FIFO eviction; size by bytes if bodies get large.
type store struct {
	mu            sync.Mutex
	cap           int
	flows         map[string]*Flow
	order         []string
	addonDropped  int64
	badLines      int64
	unknownVer    int64
	orphanUpdates int64
}

func newStore(cap int) *store {
	return &store{cap: cap, flows: map[string]*Flow{}}
}

func (s *store) apply(line []byte) {
	var e event
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := json.Unmarshal(line, &e); err != nil || e.ID == "" {
		s.badLines++
		return
	}
	if e.V != wireVersion {
		s.unknownVer++
		return
	}
	if e.Dropped > s.addonDropped {
		s.addonDropped = e.Dropped
	}
	f := s.flows[e.ID]
	if f == nil {
		if e.Ev != "request" {
			s.orphanUpdates++ // the request event was dropped or evicted
			return
		}
		f = &Flow{ID: e.ID}
		s.flows[e.ID] = f
		s.order = append(s.order, e.ID)
		if len(s.order) > s.cap {
			delete(s.flows, s.order[0])
			s.order = s.order[1:]
		}
	}
	switch e.Ev {
	case "request":
		f.Device, f.Client, f.Start = e.Device, e.Client, e.TS
		f.Method, f.URL, f.Host, f.Path, f.HTTPVersion = e.Method, e.URL, e.Host, e.Path, e.HTTPVersion
		f.ReqHeaders = e.Headers
	case "response":
		f.End, f.Status, f.Reason, f.RespHeaders = e.TSEnd, e.Status, e.Reason, e.Headers
		f.ReqBody, _ = base64.StdEncoding.DecodeString(e.ReqBody)
		f.RespBody, _ = base64.StdEncoding.DecodeString(e.Body)
		f.ReqSize, f.ReqTrunc, f.RespSize, f.RespTrunc = e.ReqSize, e.ReqTrunc, e.BodySize, e.BodyTrunc
	case "error":
		f.Error = e.Msg
	}
}

type Summary struct {
	ID       string `json:"id"`
	Device   string `json:"device,omitempty"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Status   int    `json:"status,omitempty"`
	RespSize int    `json:"response_body_size"`
	Error    string `json:"error,omitempty"`
}

// list returns the newest flows first, filtered by device and host substring.
func (s *store) list(device, host string, limit int) []Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Summary
	for i := len(s.order) - 1; i >= 0 && len(out) < limit; i-- {
		f := s.flows[s.order[i]]
		if device != "" && f.Device != device || host != "" && !strings.Contains(f.Host, host) {
			continue
		}
		out = append(out, Summary{f.ID, f.Device, f.Method, f.URL, f.Status, f.RespSize, f.Error})
	}
	return out
}

// FlowView is what get_flow returns: secrets masked, bodies as text when possible.
type FlowView struct {
	Flow
	ReqBody  string `json:"request_body,omitempty"`
	RespBody string `json:"response_body,omitempty"`
	Encoding string `json:"body_encoding,omitempty"` // "base64" when a body is not UTF-8
}

func (s *store) get(id string, bodies bool) (FlowView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flows[id]
	if f == nil {
		return FlowView{}, fmt.Errorf("no flow %q", id)
	}
	v := FlowView{Flow: *f}
	v.ReqHeaders, v.RespHeaders = redact(f.ReqHeaders), redact(f.RespHeaders)
	if bodies {
		v.ReqBody, v.RespBody, v.Encoding = bodyText(f.ReqBody, f.RespBody)
	}
	return v, nil
}

func (s *store) stats() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]int64{
		"flows": int64(len(s.order)), "addon_dropped": s.addonDropped,
		"bad_lines": s.badLines, "unknown_version": s.unknownVer, "orphan_updates": s.orphanUpdates,
	}
}

// secretHeaders are masked in every header list reqcove returns.
var secretHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
}

func redact(h [][2]string) [][2]string {
	out := make([][2]string, len(h))
	for i, kv := range h {
		out[i] = kv
		if secretHeaders[strings.ToLower(kv[0])] {
			out[i][1] = "[redacted]"
		}
	}
	return out
}

func bodyText(req, resp []byte) (string, string, string) {
	if isText(req) && isText(resp) {
		return string(req), string(resp), ""
	}
	return base64.StdEncoding.EncodeToString(req), base64.StdEncoding.EncodeToString(resp), "base64"
}

func isText(b []byte) bool {
	return utf8.Valid(b) && !bytes.Contains(b, []byte{0})
}
