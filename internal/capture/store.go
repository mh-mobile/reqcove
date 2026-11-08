package capture

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
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
	MappedURL   string      `json:"mapped_url"` // request: where map_remote sent it
	Rewrites    []string    `json:"rewrites"`   // request, response: --rules applied (rule kinds and header names, never values)
	// hello
	Mitmproxy    string         `json:"mitmproxy"`
	Python       string         `json:"python"`
	Brotli       string         `json:"brotli"`
	BrotliDecode bool           `json:"brotli_decode"`
	ZstdDecode   bool           `json:"zstd_decode"`
	Rules        map[string]int `json:"rules"`       // --rules loaded, by kind
	RulesError   string         `json:"rules_error"` // why --rules could not be loaded
	Resolve      []string       `json:"resolve"`     // resolve rules, "name -> ip:port"
	Upstream     string         `json:"upstream"`    // host:port decrypted requests go on to
	// counters the addon attaches to every line
	DroppedBodies int64 `json:"dropped_bodies"`
	DroppedEvents int64 `json:"dropped_events"`
	OutOfScope    int64 `json:"out_of_scope"`
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
	seq         int64       // arrival order; the list cursor
	ID          string      `json:"id"`
	Conn        string      `json:"conn,omitempty"` // the client connection; list_tls_failures uses the same IDs
	Device      string      `json:"device,omitempty"`
	Client      string      `json:"client,omitempty"`
	Start       float64     `json:"start"`
	End         float64     `json:"end,omitempty"`
	State       string      `json:"state"` // open, done, error
	Method      string      `json:"method"`
	URL         string      `json:"url"` // as the app sent it, before --rules
	MappedURL   string      `json:"mapped_url,omitempty"`
	Rewrites    []string    `json:"rewrites,omitempty"`
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
	Notes       []string    `json:"notes,omitempty"` // reqcove's, about what it left out
}

// bytes is what a flow holds that a site or an app controls the size of: the
// body heads, and the headers, URLs and error text.
func (f *Flow) bytes() int {
	n := len(f.URL) + len(f.MappedURL) + len(f.Path) + len(f.Error) + len(f.Reason) + len(f.HTTPVersion)
	for _, b := range []Body{f.ReqBody, f.RespBody} {
		n += len(b.Head) + len(b.Encoding) + len(b.Note)
	}
	for _, note := range f.Notes {
		n += len(note) + 16
	}
	for _, h := range [][][2]string{f.ReqHeaders, f.RespHeaders} {
		for _, kv := range h {
			n += len(kv[0]) + len(kv[1]) + 64 // and the strings' and slot's own overhead
		}
	}
	return n
}

// TLSFailure is a client that refused the certificate mitmproxy showed it:
// often certificate pinning, but also a CA not trusted yet, among others.
type TLSFailure struct {
	Conn   string  `json:"conn"`
	Device string  `json:"device,omitempty"`
	Client string  `json:"client,omitempty"`
	Host   string  `json:"host,omitempty"` // the SNI, or the IP address dialed when there was none
	Msg    string  `json:"msg,omitempty"`
	TS     float64 `json:"-"`
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
	allow         HostRules         // hosts recorded (--allow-hosts)
	redact        bool              // mask secrets as they arrive (off: --no-redact)
	outOfScope    int64             // requests to hosts outside allow, seen here
	addonOOS      int64             // the same, seen by the addon
	earlier       [3]int64          // addon counters of mitmdump processes that exited: dropped bodies, events, out of scope
	hellos        int64
	seq           int64  // last Flow.seq handed out
	state         string // starting, ready, restarting, failed
	stateDetail   string
	restarts      int64
}

func (s *Store) setState(state, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state == "restarting" && s.state != "restarting" {
		s.restarts++
	}
	s.state, s.stateDetail = state, detail
}

func (s *Store) helloCount() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hellos
}

// mitmdumpExited closes the flows the dead process left open and keeps its
// counters, since the next process counts from zero.
// ponytail: lines still buffered from the dead process can land after this; they only reopen nothing (orphans count).
func (s *Store) mitmdumpExited(why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.flows {
		if f.State == "open" {
			before := f.bytes()
			f.State, f.Error = "error", why
			s.heldBytes += f.bytes() - before
		}
	}
	s.earlier[0] += s.addonDropped[0]
	s.earlier[1] += s.addonDropped[1]
	s.earlier[2] += s.addonOOS
	s.addonDropped, s.addonOOS = [2]int64{}, 0
}

// SetScope sets which hosts are recorded and whether secrets are masked.
// Call it before flows arrive.
func (s *Store) SetScope(allow HostRules, redact bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allow, s.redact = allow, redact
}

// SetDeviceNames tells the store the display name of each device it may see.
func (s *Store) SetDeviceNames(names map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.names = names
}

// The store's default bounds, what `reqcove run` uses. MaxBytes counts the
// kept body heads (up to BodyHead each). The soak test (4 hours of a busy
// phone) found 256 MiB of heads would take the Go process far past its
// 150 MB budget; 64 MiB keeps it inside.
const (
	DefaultBodyHead = 64 << 10
	DefaultMaxFlows = 10000
	DefaultMaxBytes = 64 << 20
	// GoMemoryLimit is the soft limit `run` gives Go's GC (unless GOMEMLIMIT
	// is set): with GOGC alone the heap grows to about twice the live store,
	// which the soak test measured at 175 MB with full heads.
	GoMemoryLimit = 120 << 20
)

func NewStore(maxFlows, maxBytes int) *Store {
	// Permissive until SetScope: capture.Start always sets the real scope.
	return &Store{maxFlows: maxFlows, maxBytes: maxBytes, flows: map[string]*Flow{}, allow: HostRules{All: true}, redact: true, state: "starting"}
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
	s.addonOOS = max(s.addonOOS, e.OutOfScope)
	switch e.Ev {
	case "hello":
		s.hello = e
		s.hellos++
		return
	case "skip": // a request outside --allow-hosts; only its count matters
		return
	case "tls_failed":
		host := e.SNI
		if host == "" {
			host = e.Host
		}
		if !s.allow.Match(host) {
			s.outOfScope++ // only hosts in --allow-hosts are recorded, failures included
			return
		}
		s.tlsFailures = append(s.tlsFailures, TLSFailure{e.Conn, e.Device, e.Client, host, s.maskError(e.Msg), e.TS})
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
			s.orphanUpdates++ // the request event was dropped, evicted or out of scope
			return
		}
		if !s.allow.Match(e.Host) {
			s.outOfScope++ // the addon should have skipped it; this is the second check
			return
		}
		s.seq++
		f = &Flow{ID: e.ID, State: "open", seq: s.seq}
		s.flows[e.ID] = f
		s.order = append(s.order, e.ID)
	}
	before := f.bytes()
	switch e.Ev {
	case "request":
		f.Device, f.Client, f.Start, f.Conn = e.Device, e.Client, e.TS, e.Conn
		f.Method, f.URL, f.Host, f.Path, f.HTTPVersion = e.Method, s.mask(e.URL), e.Host, s.mask(e.Path), e.HTTPVersion
		f.ReqHeaders = s.maskHeaders(e.Headers)
		if e.Note != "" {
			f.Notes = append(f.Notes, "request headers: "+e.Note)
		}
		f.MappedURL, f.Rewrites = s.mask(e.MappedURL), e.Rewrites
	case "response":
		f.Status, f.Reason, f.RespHeaders = e.Status, s.mask(e.Reason), s.maskHeaders(e.Headers) // a reason is free text from the site
		f.Rewrites = append(f.Rewrites, e.Rewrites...)
		if e.Note != "" {
			f.Notes = append(f.Notes, "response headers: "+e.Note)
		}
	case "body":
		head, _ := base64.StdEncoding.DecodeString(e.Head)
		if s.redact {
			h := f.RespHeaders
			if e.Dir == "request" {
				h = f.ReqHeaders
			}
			head = maskBody(head, header(h, "content-type"), e.Dir == "request")
		}
		b := Body{head, e.Size, e.Final, e.Truncated, e.Decoded, e.Encoding, e.Note}
		if e.Dir == "request" {
			f.ReqBody = b
		} else {
			f.RespBody = b
		}
	case "done":
		f.End, f.State = e.TSEnd, "done"
	case "error":
		f.Error, f.State = s.maskError(e.Msg), "error"
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
	ID          string   `json:"id"`
	Time        string   `json:"time"`                  // request start, local time
	DurationMS  int64    `json:"duration_ms,omitempty"` // request start to response end
	Device      string   `json:"device,omitempty"`      // StableID
	DeviceName  string   `json:"device_name,omitempty"`
	Method      string   `json:"method"`
	Host        string   `json:"host"`
	URL         string   `json:"url"`
	State       string   `json:"state"`
	Status      int      `json:"status,omitempty"`
	ContentType string   `json:"content_type,omitempty"` // of the response
	RespSize    int64    `json:"response_body_size"`
	UserAgent   string   `json:"user_agent,omitempty"`
	Origin      string   `json:"origin,omitempty"`
	Referer     string   `json:"referer,omitempty"`
	Error       string   `json:"error,omitempty"`
	MatchedIn   []string `json:"matched_in,omitempty"` // with Filter.Query: url, request_headers, response_headers, request_body, response_body
}

// Filter selects flows for List; zero fields match everything.
type Filter struct {
	Device       string  // StableID or display name
	Host         string  // this host or any subdomain of it
	Since, Until float64 // unix seconds; the request's start
	Status       string  // "404", "4xx", or "none" (no response: open or failed)
	Method       string
	Query        string // case-insensitive text in the URL or header names and values (as stored, masked)
	QueryBodies  bool   // Query also looks in the kept body heads
	Before       int64  // cursor from a previous page: only older flows
	textOnly     bool   // set by the store while masking: bodies that are not text are not searched
	Limit        int
}

// ValidStatus reports whether s is a Status filter List understands.
func ValidStatus(s string) bool {
	if s == "" || s == "none" {
		return true
	}
	if len(s) == 3 && strings.HasSuffix(s, "xx") {
		return s[0] >= '1' && s[0] <= '5'
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 100 && n <= 599
}

// matchedIn says where Query occurs in f.
func (q Filter) matchedIn(f *Flow) []string {
	needle := strings.ToLower(q.Query)
	has := func(s string) bool { return strings.Contains(strings.ToLower(s), needle) }
	inHeaders := func(h [][2]string) bool {
		for _, kv := range h {
			if has(kv[0]) || has(kv[1]) {
				return true
			}
		}
		return false
	}
	var where []string
	if has(f.URL) || has(f.MappedURL) {
		where = append(where, "url")
	}
	if inHeaders(f.ReqHeaders) {
		where = append(where, "request_headers")
	}
	if inHeaders(f.RespHeaders) {
		where = append(where, "response_headers")
	}
	if q.QueryBodies {
		// Bodies fold ASCII case only (containsFold), so the needle may lower ASCII only.
		needle := strings.Map(func(r rune) rune {
			if 'A' <= r && r <= 'Z' {
				return r + 'a' - 'A'
			}
			return r
		}, q.Query)
		// While masking, a head that is not text is never handed out, so it is
		// not searched either: a match would tell what is in it.
		if (!q.textOnly || checkable(f.ReqBody, f.ReqHeaders)) && containsFold(f.ReqBody.Head, needle) {
			where = append(where, "request_body")
		}
		if (!q.textOnly || checkable(f.RespBody, f.RespHeaders)) && containsFold(f.RespBody.Head, needle) {
			where = append(where, "response_body")
		}
	}
	return where
}

func (q Filter) match(f *Flow, name string) bool {
	host, fhost := strings.ToLower(q.Host), strings.ToLower(f.Host)
	switch {
	case q.Before != 0 && f.seq >= q.Before,
		q.Device != "" && f.Device != q.Device && name != q.Device,
		host != "" && fhost != host && !strings.HasSuffix(fhost, "."+host),
		q.Since != 0 && f.Start < q.Since,
		q.Until != 0 && f.Start > q.Until,
		q.Method != "" && !strings.EqualFold(f.Method, q.Method):
		return false
	}
	switch {
	case q.Status == "":
	case q.Status == "none":
		return f.Status == 0
	case strings.HasSuffix(q.Status, "xx"):
		return f.Status/100 == int(q.Status[0]-'0')
	default:
		return strconv.Itoa(f.Status) == q.Status
	}
	return true
}

// List returns the newest matching flows first, and a cursor for the next
// (older) page, 0 when there is none.
func (s *Store) List(q Filter) ([]Summary, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q.textOnly = s.redact
	var out []Summary
	var last int64
	for i := len(s.order) - 1; i >= 0; i-- {
		f := s.flows[s.order[i]]
		if !q.match(f, s.names[f.Device]) {
			continue
		}
		var where []string
		if q.Query != "" {
			if where = q.matchedIn(f); len(where) == 0 {
				continue
			}
		}
		if len(out) == q.Limit {
			return out, last
		}
		v := s.summary(f)
		v.MatchedIn = where
		out = append(out, v)
		last = f.seq
	}
	return out, 0
}

func (s *Store) summary(f *Flow) Summary {
	v := Summary{ID: f.ID, Device: f.Device, DeviceName: s.names[f.Device], Method: f.Method, Host: f.Host, URL: f.URL,
		State: f.State, Status: f.Status, RespSize: f.RespBody.Size, Error: f.Error,
		ContentType: header(f.RespHeaders, "content-type"), UserAgent: header(f.ReqHeaders, "user-agent"),
		Origin: header(f.ReqHeaders, "origin"), Referer: header(f.ReqHeaders, "referer")}
	if f.Start > 0 {
		v.Time = unixTime(f.Start).Format("2006-01-02T15:04:05.000Z07:00")
	}
	if f.End > f.Start && f.Start > 0 {
		v.DurationMS = int64((f.End - f.Start) * 1000)
	}
	return v
}

// Counts is what summarize returns: how the matching flows split up.
type Counts struct {
	Flows       int     `json:"flows"`
	First       string  `json:"first,omitempty"` // earliest request start
	Last        string  `json:"last,omitempty"`
	ByHost      []Count `json:"by_host"`
	ByUserAgent []Count `json:"by_user_agent"`
	ByStatus    []Count `json:"by_status"` // "none": no response (open or failed)
	ByMethod    []Count `json:"by_method"`
	ByDevice    []Count `json:"by_device"`
	ByType      []Count `json:"by_content_type"`
}

type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Summarize counts the flows q matches (Limit and Before are ignored),
// keeping the top n keys of each kind.
func (s *Store) Summarize(q Filter, n int) Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	q.Before = 0
	tally := map[string]map[string]int{}
	add := func(kind, key string) {
		if tally[kind] == nil {
			tally[kind] = map[string]int{}
		}
		tally[kind][key]++
	}
	var c Counts
	var first, last float64
	for _, id := range s.order {
		f := s.flows[id]
		if !q.match(f, s.names[f.Device]) {
			continue
		}
		c.Flows++
		if f.Start > 0 && (first == 0 || f.Start < first) {
			first = f.Start
		}
		last = max(last, f.Start)
		status := "none"
		if f.Status != 0 {
			status = strconv.Itoa(f.Status)
		}
		ct, _, _ := strings.Cut(header(f.RespHeaders, "content-type"), ";")
		device := s.names[f.Device]
		if device == "" {
			device = f.Device
		}
		add("host", strings.ToLower(f.Host))
		add("ua", header(f.ReqHeaders, "user-agent"))
		add("status", status)
		add("method", strings.ToUpper(f.Method))
		add("device", device)
		add("type", strings.TrimSpace(ct))
	}
	top := func(kind string) []Count {
		out := []Count{}
		for k, v := range tally[kind] {
			out = append(out, Count{k, v})
		}
		sort.Slice(out, func(i, j int) bool {
			return out[i].Count > out[j].Count || out[i].Count == out[j].Count && out[i].Key < out[j].Key
		})
		return out[:min(len(out), n)]
	}
	c.ByHost, c.ByUserAgent, c.ByStatus, c.ByMethod, c.ByDevice, c.ByType = top("host"), top("ua"), top("status"), top("method"), top("device"), top("type")
	if first > 0 {
		c.First = unixTime(first).Format("2006-01-02T15:04:05.000Z07:00")
		c.Last = unixTime(last).Format("2006-01-02T15:04:05.000Z07:00")
	}
	return c
}

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
	ID          string `json:"id"` // StableID
	Name        string `json:"name,omitempty"`
	Carried     bool   `json:"carried"` // one of --device now
	Flows       int    `json:"flows"`
	TLSFailures int    `json:"tls_failures"`
	LastSeen    string `json:"last_seen,omitempty"` // newest request start
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

func unixTime(sec float64) time.Time { return time.UnixMilli(int64(sec * 1000)) }

func header(h [][2]string, name string) string {
	for _, kv := range h {
		if strings.EqualFold(kv[0], name) {
			return kv[1]
		}
	}
	return ""
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
		return FlowView{}, fmt.Errorf("no flow %q", id)
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
		"flows": len(s.order), "held_bytes": s.heldBytes, "evicted": s.evicted,
		"oldest_flow": oldest, "newest_flow": newest, "max_flows": s.maxFlows, "max_bytes": s.maxBytes,
		"flows_with_truncated_bodies": truncated,
		"state":                       s.state, "state_detail": s.stateDetail, "restarts": s.restarts,
		"addon_dropped_bodies": s.earlier[0] + s.addonDropped[0], "addon_dropped_events": s.earlier[1] + s.addonDropped[1],
		"bad_lines": s.badLines, "unknown_version": s.unknownVer, "orphan_updates": s.orphanUpdates,
		"out_of_scope": s.outOfScope + s.earlier[2] + s.addonOOS, "all_hosts": s.allow.All, "redacting": s.redact,
		"tls_failures": len(s.tlsFailures),
		"mitmproxy":    s.hello.Mitmproxy, "python": s.hello.Python, "brotli": s.hello.Brotli,
		"brotli_decode": s.hello.BrotliDecode, "zstd_decode": s.hello.ZstdDecode,
		"rules": s.hello.Rules, "rules_error": s.hello.RulesError, "resolve": s.hello.Resolve, "upstream": s.hello.Upstream,
	}
}

func (s *Store) mask(v string) string {
	if !s.redact {
		return v
	}
	return maskTokens(maskURLs(v))
}

// maskError is mask for error messages, which can also quote raw bytes from
// the wire (mitmproxy: "Invalid header line: b'Set-Cookie sid=…'").
func (s *Store) maskError(v string) string {
	if !s.redact {
		return v
	}
	return quotedBytesRE.ReplaceAllString(maskTokens(maskURLs(v)), "${1}b'[redacted]'")
}

// Python's repr of bytes, b'…' or b"…", not the b' of a word such as "job's".
// One cut before its closing quote (the addon cuts messages at 1 KiB) runs to the end.
var quotedBytesRE = regexp.MustCompile(`(^|[^A-Za-z0-9_])b(?:'(?:[^'\\]|\\.)*(?:'|\\?$)|"(?:[^"\\]|\\.)*(?:"|\\?$))`)

func (s *Store) maskHeaders(h [][2]string) [][2]string {
	if !s.redact {
		return h
	}
	out := make([][2]string, len(h))
	for i, kv := range h {
		out[i] = kv
		switch name := strings.ToLower(kv[0]); {
		case name == "cookie":
			out[i][1] = maskCookies(kv[1], "; ", false)
		case name == "set-cookie":
			out[i][1] = maskCookies(kv[1], ";", true)
		case strings.HasSuffix(name, "-authenticate"):
			// WWW-Authenticate, Proxy-Authenticate: a challenge (scheme, realm, error),
			// not a credential, and what says why a 401 came; a token it quotes still goes
			out[i][1] = maskShapes(maskURLs(kv[1]))
		case secretName(kv[0]): // the name as sent: X-ClientKey splits into client and key
			out[i][1] = "[redacted]"
		default:
			// a credential by its shape, or a URL's (Referer, Location, Link, Refresh, …), under any name
			out[i][1] = maskTokens(maskURLs(kv[1]))
		}
	}
	return out
}

// secretName reports whether a header or parameter name says it carries a
// secret (secretKind with a lone "code" counted: in URLs and forms it is an
// OAuth authorization code). Masking a harmless value by mistake costs
// little; missing a key does not.
func secretName(name string) bool { return secretKind(name, true) }

// secretKind decides by two kinds of words. Strong ones are secret wherever
// they appear, even run together (accesstoken, x-authtoken, sessiontoken,
// passcode). Short ones only as a whole word, so author, keyword and monkey
// are not; code and key next to an everyday word (country_code, error_code,
// sort_key) are everyday values; a lone code counts only if loneCode.
func secretKind(name string, loneCode bool) bool {
	lower := strings.ToLower(name)
	flat := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return -1
	}, lower)
	if notSecretNames[flat] {
		return false
	}
	for _, part := range strongSecretParts {
		if strings.Contains(flat, part) {
			return true
		}
	}
	words := nameWords(name)
	everyday := false
	for _, w := range words {
		everyday = everyday || everydayWords[w]
	}
	for _, w := range words {
		if !shortSecretWords[w] {
			continue
		}
		switch {
		case (w == "code" || w == "key") && everyday:
		case w == "code" && len(words) == 1 && !loneCode:
		default:
			return true
		}
	}
	return false
}

var strongSecretParts = []string{
	"token", "secret", "password", "passwd", "passphrase", "passcode", "credential",
	"signature", "session", "sessid", "jwt", "apikey", "privatekey", "authorization",
	"authentication", "csrf", "xsrf",
}

var shortSecretWords = map[string]bool{
	"auth": true, "key": true, "sid": true, "sig": true, "pwd": true, "otp": true, "totp": true,
	"pin": true, "code": true, "pass": true, "pw": true,
}

// everydayWords next to code or key make them ordinary values.
var everydayWords = map[string]bool{
	"error": true, "status": true, "reason": true, "response": true, "http": true, "result": true,
	"country": true, "currency": true, "lang": true, "language": true, "locale": true, "region": true,
	"zip": true, "postal": true, "area": true, "state": true, "iso": true, "sort": true, "order": true,
	"primary": true, "foreign": true,
}

// notSecretNames look secret but carry what debugging needs (letters and digits only).
var notSecretNames = map[string]bool{
	"tokentype": true, "authenticationtype": true, "authenticationmethod": true,
}

// nameWords splits a name at non-alphanumerics and case changes, in lower
// case: "X-Amz-Signature" -> x amz signature, "accessToken" -> access token,
// "APIToken" -> api token.
func nameWords(name string) []string {
	rs := []rune(name)
	var words []string
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			words = append(words, strings.ToLower(string(rs[start:end])))
		}
		start = -1
	}
	for i, r := range rs {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush(i)
			continue
		}
		if start >= 0 && unicode.IsUpper(r) {
			prev := rs[i-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush(i)
			}
		}
		if start < 0 {
			start = i
		}
	}
	flush(len(rs))
	return words
}

// maskCookies keeps each cookie's name, so it shows which cookies went, and
// masks its value. In Set-Cookie (oneCookie), only the first pair is a
// cookie; the attributes after it (Path, HttpOnly, ...) stay.
func maskCookies(v, sep string, oneCookie bool) string {
	parts := strings.Split(v, sep)
	for i, p := range parts {
		if oneCookie && i > 0 {
			break
		}
		if name, _, ok := strings.Cut(p, "="); ok {
			parts[i] = name + "=[redacted]"
		} else if i == 0 {
			parts[i] = "[redacted]" // a value without a name
		}
	}
	return strings.Join(parts, sep)
}

// A name=value after ?, &, ; or # (OAuth's implicit flow puts the token in the
// fragment, sometimes after a route: #/callback?access_token=). Names stop at
// / and ?. A value runs to & or #: a secret's is masked whole, ';' included
// (some servers keep it in the value); another's is split at ';', so
// "?view=1;token=" is seen too.
// In bodies, a value also stops at a quote, < or > and a backslash (HTML
// attributes, JSON strings), and JSON may write & as \u0026.
var queryRE = regexp.MustCompile(`([?&;#]|\\u0026)([^=&#;?/\s"<>\\]+)=([^&#\s"<>\\]*)`)

// A URL's password (https://user:pass@host), also with JSON's escaped slashes
// (https:\/\/user:pass@host, as PHP writes it).
var userinfoRE = regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*:\\?/\\?/[^/?#@\s:"'<>\\]*:)[^/?#@\s"'<>]+@`)

func maskUserinfo(v string) string {
	if strings.Contains(v, ":/") || strings.Contains(v, `:\/`) {
		return userinfoRE.ReplaceAllString(v, "${1}REDACTED@")
	}
	return v
}

func maskURLs(v string) string {
	if strings.IndexByte(v, '=') < 0 && !strings.Contains(v, "@") {
		return v // no parameter, no password: skip the regexps (most of a 64 KiB JSON head)
	}
	return maskURLsAt(maskUserinfo(v), 0)
}

// maskURLsAt is maskURLs for a URL found depth levels inside another's value.
func maskURLsAt(v string, depth int) string {
	return queryRE.ReplaceAllStringFunc(v, func(m string) string {
		sub := queryRE.FindStringSubmatch(m)
		name, err := url.QueryUnescape(sub[2])
		if err != nil {
			name = sub[2]
		}
		if secretName(name) {
			if sub[3] == "[redacted]" {
				return m // masked already (a form field)
			}
			return sub[1] + sub[2] + "=REDACTED"
		}
		// The value up to ';' is this name's; each ';name=value' after it is
		// looked at once, in one pass (recursing on the rest was quadratic).
		pieces := strings.Split(sub[3], ";")
		if nestedSecret(pieces[0], depth) {
			pieces[0] = "REDACTED"
		}
		for i := 1; i < len(pieces); i++ {
			n, v, ok := strings.Cut(pieces[i], "=")
			if !ok {
				continue
			}
			if secretName(unescapeCut(n)) {
				pieces[i] = n + "=REDACTED"
				pieces = pieces[:i+1] // a secret's value is masked whole, ';' included
				break
			}
			if nestedSecret(v, depth) {
				pieces[i] = n + "=REDACTED"
			}
		}
		return sub[1] + sub[2] + "=" + strings.Join(pieces, ";")
	})
}

// unescapeCut is url.QueryUnescape for text that may be cut inside a %XX
// escape (a head ends anywhere): the cut escape is dropped.
func unescapeCut(v string) string {
	for cut := 0; cut <= 2 && cut <= len(v); cut++ {
		if u, err := url.QueryUnescape(v[:len(v)-cut]); err == nil {
			return u
		}
	}
	return v
}

// nestedSecret: does a value hold a URL or parameters (?redirect=https://x/cb?token=…,
// also percent-encoded, a URL's password included) with a secret in them? Two
// levels are looked into, and a deeper one that could hold parameters counts
// as secret; each level scans its own part of the text once, so the cost stays
// linear in the text whatever its length.
func nestedSecret(v string, depth int) bool {
	if !strings.ContainsAny(v, "?=%@") {
		return false
	}
	inner := unescapeCut(v)
	if !strings.ContainsAny(inner, "?=@") {
		return false
	}
	if depth >= 2 {
		return true
	}
	return maskTokens(maskURLsAt(maskUserinfo(inner), depth+1)) != inner
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

// containsFold reports whether lowerNeedle (already lower case) occurs in b,
// ignoring ASCII case. A short needle (masking's words) is compared in place;
// a long one (an agent's query) searches a folded copy in linear time, so it
// cannot hold the store for minutes.
func containsFold[T string | []byte](b T, lowerNeedle string) bool {
	n := len(lowerNeedle)
	if n > 16 {
		low := make([]byte, len(b))
		for i := 0; i < len(b); i++ {
			low[i] = lowerASCII(b[i])
		}
		return bytes.Contains(low, []byte(lowerNeedle))
	}
	for i := 0; i+n <= len(b); i++ {
		j := 0
		for j < n && lowerASCII(b[i+j]) == lowerNeedle[j] {
			j++
		}
		if j == n {
			return true
		}
	}
	return false
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
