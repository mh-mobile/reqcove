package capture

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"
)

// event is one line from the addon (addon.py). V is the wire version.
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
	Dir         string      `json:"dir"`
	Head        string      `json:"head"`
	Size        int64       `json:"size"`
	Final       bool        `json:"final"`
	Truncated   bool        `json:"truncated"`
	Decoded     bool        `json:"decoded"`
	Encoding    string      `json:"encoding"`
	Note        string      `json:"note"`
	Msg         string      `json:"msg"`
	FromClient  bool        `json:"from_client"`
	Conn        string      `json:"conn"`
	SNI         string      `json:"sni"`
	// hello
	Mitmproxy    string `json:"mitmproxy"`
	Python       string `json:"python"`
	Brotli       string `json:"brotli"`
	BrotliDecode bool   `json:"brotli_decode"`
	ZstdDecode   bool   `json:"zstd_decode"`
	// counters the addon attaches to every line
	DroppedBodies int64 `json:"dropped_bodies"`
	DroppedEvents int64 `json:"dropped_events"`
}

const wireVersion = 2

// Body is the head of one request or response body as reqcove keeps it.
type Body struct {
	Head      []byte `json:"-"`
	Size      int64  `json:"size"`                // bytes on the wire so far
	Final     bool   `json:"final"`               // the body ended
	Truncated bool   `json:"truncated,omitempty"` // head is cut at the limit
	Decoded   bool   `json:"decoded"`             // head is decoded (false: wire bytes)
	Encoding  string `json:"encoding,omitempty"`
	Note      string `json:"note,omitempty"`
}

type Flow struct {
	ID          string      `json:"id"`
	Device      string      `json:"device,omitempty"`
	Client      string      `json:"client,omitempty"`
	Start       float64     `json:"start"`
	End         float64     `json:"end,omitempty"`
	State       string      `json:"state"` // open, done, error
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	Host        string      `json:"host"`
	Path        string      `json:"path"`
	HTTPVersion string      `json:"http_version"`
	ReqHeaders  [][2]string `json:"request_headers"`
	ReqBody     Body        `json:"request_body"`
	Status      int         `json:"status,omitempty"`
	Reason      string      `json:"reason,omitempty"`
	RespHeaders [][2]string `json:"response_headers,omitempty"`
	RespBody    Body        `json:"response_body"`
	WSMessages  int         `json:"websocket_messages,omitempty"`
	WSBytes     int64       `json:"websocket_bytes,omitempty"`
	Error       string      `json:"error,omitempty"`
}

func (f *Flow) bytes() int { return len(f.ReqBody.Head) + len(f.RespBody.Head) }

type TLSFailure struct {
	Conn   string `json:"conn"`
	Client string `json:"client,omitempty"`
	SNI    string `json:"sni,omitempty"`
	Msg    string `json:"msg,omitempty"`
}

// Store keeps the most recent flows in memory, bounded by count and by the
// bytes of the body heads it holds (FIFO eviction).
type Store struct {
	mu            sync.Mutex
	maxFlows      int
	maxBytes      int
	flows         map[string]*Flow
	order         []string
	heldBytes     int
	hello         event
	tlsFailures   []TLSFailure
	addonDropped  [2]int64 // bodies, events
	badLines      int64
	unknownVer    int64
	orphanUpdates int64
	evicted       int64
	names         map[string]string // device StableID -> display name
}

// SetDeviceNames tells the store the display name of each device it may see.
func (s *Store) SetDeviceNames(names map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.names = names
}

func NewStore(maxFlows, maxBytes int) *Store {
	return &Store{maxFlows: maxFlows, maxBytes: maxBytes, flows: map[string]*Flow{}}
}

func (s *Store) Apply(line []byte) {
	var e event
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := json.Unmarshal(line, &e); err != nil {
		s.badLines++
		return
	}
	if e.V != wireVersion {
		s.unknownVer++
		return
	}
	s.addonDropped = [2]int64{max(s.addonDropped[0], e.DroppedBodies), max(s.addonDropped[1], e.DroppedEvents)}
	switch e.Ev {
	case "hello":
		s.hello = e
		return
	case "tls_failed":
		s.tlsFailures = append(s.tlsFailures, TLSFailure{e.Conn, e.Client, e.SNI, e.Msg})
		if len(s.tlsFailures) > 1000 {
			s.tlsFailures = s.tlsFailures[1:]
		}
		return
	}
	if e.ID == "" {
		s.badLines++
		return
	}
	f := s.flows[e.ID]
	if f == nil {
		if e.Ev != "request" {
			s.orphanUpdates++ // the request event was dropped or evicted
			return
		}
		f = &Flow{ID: e.ID, State: "open"}
		s.flows[e.ID] = f
		s.order = append(s.order, e.ID)
	}
	before := f.bytes()
	switch e.Ev {
	case "request":
		f.Device, f.Client, f.Start = e.Device, e.Client, e.TS
		f.Method, f.URL, f.Host, f.Path, f.HTTPVersion = e.Method, e.URL, e.Host, e.Path, e.HTTPVersion
		f.ReqHeaders = e.Headers
	case "response":
		f.Status, f.Reason, f.RespHeaders = e.Status, e.Reason, e.Headers
	case "body":
		head, _ := base64.StdEncoding.DecodeString(e.Head)
		b := Body{head, e.Size, e.Final, e.Truncated, e.Decoded, e.Encoding, e.Note}
		if e.Dir == "request" {
			f.ReqBody = b
		} else {
			f.RespBody = b
		}
	case "done":
		f.End, f.State = e.TSEnd, "done"
	case "error":
		f.Error, f.State = e.Msg, "error"
	case "ws":
		f.WSMessages++
		f.WSBytes += e.Size
	}
	s.heldBytes += f.bytes() - before
	s.evictLocked()
}

func (s *Store) evictLocked() {
	for len(s.order) > 0 && (len(s.order) > s.maxFlows || s.heldBytes > s.maxBytes) {
		id := s.order[0]
		s.order = s.order[1:]
		s.heldBytes -= s.flows[id].bytes()
		delete(s.flows, id)
		s.evicted++
	}
}

type Summary struct {
	ID         string `json:"id"`
	Device     string `json:"device,omitempty"` // StableID
	DeviceName string `json:"device_name,omitempty"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	State      string `json:"state"`
	Status     int    `json:"status,omitempty"`
	RespSize   int64  `json:"response_body_size"`
	Error      string `json:"error,omitempty"`
}

// List returns the newest flows first, filtered by device (StableID or
// display name) and host substring.
func (s *Store) List(device, host string, limit int) []Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Summary
	for i := len(s.order) - 1; i >= 0 && len(out) < limit; i-- {
		f := s.flows[s.order[i]]
		if device != "" && f.Device != device && s.names[f.Device] != device || host != "" && !strings.Contains(f.Host, host) {
			continue
		}
		out = append(out, Summary{f.ID, f.Device, s.names[f.Device], f.Method, f.URL, f.State, f.Status, f.RespBody.Size, f.Error})
	}
	return out
}

// FlowView is what get_flow returns: secrets masked, body heads as text when possible.
type FlowView struct {
	Flow
	DeviceName   string `json:"device_name,omitempty"`
	ReqBodyText  string `json:"request_body_head,omitempty"`
	RespBodyText string `json:"response_body_head,omitempty"`
	BodyEncoding string `json:"body_head_encoding,omitempty"` // "base64" when a head is not UTF-8
}

func (s *Store) Get(id string, bodies bool) (FlowView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flows[id]
	if f == nil {
		return FlowView{}, fmt.Errorf("no flow %q", id)
	}
	v := FlowView{Flow: *f, DeviceName: s.names[f.Device]}
	v.ReqHeaders, v.RespHeaders = redact(f.ReqHeaders), redact(f.RespHeaders)
	if bodies {
		v.ReqBodyText, v.RespBodyText, v.BodyEncoding = bodyText(f.ReqBody.Head, f.RespBody.Head)
	}
	return v, nil
}

func (s *Store) Stats() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{
		"flows": len(s.order), "held_bytes": s.heldBytes, "evicted": s.evicted,
		"addon_dropped_bodies": s.addonDropped[0], "addon_dropped_events": s.addonDropped[1],
		"bad_lines": s.badLines, "unknown_version": s.unknownVer, "orphan_updates": s.orphanUpdates,
		"tls_failures": len(s.tlsFailures),
		"mitmproxy":    s.hello.Mitmproxy, "python": s.hello.Python, "brotli": s.hello.Brotli,
		"brotli_decode": s.hello.BrotliDecode, "zstd_decode": s.hello.ZstdDecode,
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
