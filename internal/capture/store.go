package capture

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	Server      string      `json:"server"` // pass_open: where the connection went
	ALPN        []string    `json:"alpn"`   // pass_open: what the client offered
	Up, Down    int64       // pass_close: bytes from and to the client
	MappedURL   string      `json:"mapped_url"` // request: where map_remote sent it
	Rewrites    []string    `json:"rewrites"`   // request, response: --rules applied (rule kinds and header names, never values)
	Mocked      bool        `json:"mocked"`     // request: a mock rule answered it, not the server
	Trailers    [][2]string `json:"trailers"`   // done: the response's trailers (HTTP/2's: gRPC's status)
	Text        bool        `json:"text"`       // ws: a text message
	Capped      bool        `json:"capped"`     // ws: no head (the socket's rate cap, or the queue was full)
	Code        int         `json:"code"`       // ws_end: the close code
	ByClient    bool        `json:"by_client"`  // ws_end: the client closed it
	// hello
	Mitmproxy    string         `json:"mitmproxy"`
	Python       string         `json:"python"`
	Brotli       string         `json:"brotli"`
	BrotliDecode bool           `json:"brotli_decode"`
	ZstdDecode   bool           `json:"zstd_decode"`
	Rules        map[string]int `json:"rules"`       // --rules loaded, by kind
	RulesError   string         `json:"rules_error"` // why --rules could not be loaded (at start), or reloaded
	Resolve      []string       `json:"resolve"`     // resolve rules, "name -> ip:port"
	Upstream     string         `json:"upstream"`    // host:port decrypted requests go on to
	// counters the addon attaches to every line
	DroppedBodies int64       `json:"dropped_bodies"`
	DroppedEvents int64       `json:"dropped_events"`
	OutOfScope    int64       `json:"out_of_scope"`
	op            string      // the GraphQL operation, worked out before the lock (gqlURLOperation, gqlBodyOperation)
	grpcTrailers  [][2]string // body: gRPC-Web's trailer frame, masked
	view          string      // body: what the head was rendered as (Body.View)
	wsHead        string      // ws: the message's head, masked before the lock
	wsNote        string      // ws: why it has none
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
	View      string `json:"view,omitempty"` // the head is reqcove's rendering, not the bytes: protobuf's structure, or the message type --proto read it as
}

type Flow struct {
	seq          int64       // arrival order; the list cursor
	answered     int64       // from the same counter, when it got its response or error first; 0 until then (wait_for_flows)
	ws           *wsLog      // a WebSocket's kept messages
	opNamed      bool        // the URL or a header named Operation: the body does not change it
	ID           string      `json:"id"`
	Conn         string      `json:"conn,omitempty"` // the client connection; list_tls_failures uses the same IDs
	Device       string      `json:"device,omitempty"`
	Client       string      `json:"client,omitempty"`
	Start        float64     `json:"start"`
	End          float64     `json:"end,omitempty"`
	State        string      `json:"state"` // open, done, error
	Method       string      `json:"method"`
	URL          string      `json:"url"` // as the app sent it, before --rules
	MappedURL    string      `json:"mapped_url,omitempty"`
	Rewrites     []string    `json:"rewrites,omitempty"`
	Operation    string      `json:"operation,omitempty"` // GraphQL's: operationName, or the document's first; (anonymous), (batched)
	Mocked       bool        `json:"mocked,omitempty"`    // a mock rule answered it: the request was not sent to the server
	Host         string      `json:"host"`
	Path         string      `json:"path"`
	HTTPVersion  string      `json:"http_version"`
	ReqHeaders   [][2]string `json:"request_headers"`
	ReqBody      Body        `json:"request_body"`
	Status       int         `json:"status,omitempty"`
	Reason       string      `json:"reason,omitempty"`
	RespHeaders  [][2]string `json:"response_headers,omitempty"`
	RespTrailers [][2]string `json:"response_trailers,omitempty"` // HTTP/2's, or gRPC-Web's last frame: gRPC's status
	RespBody     Body        `json:"response_body"`
	WSMessages   int         `json:"websocket_messages,omitempty"`
	WSBytes      int64       `json:"websocket_bytes,omitempty"`
	WSClose      *WSClose    `json:"websocket_close,omitempty"` // how the socket ended; none while it is open
	Error        string      `json:"error,omitempty"`
	Notes        []string    `json:"notes,omitempty"` // reqcove's, about what it left out
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
	if f.ws != nil {
		n += f.ws.bytes + 64*(len(f.ws.first)+len(f.ws.last))
	}
	if f.WSClose != nil {
		n += len(f.WSClose.Reason)
	}
	for _, h := range [][][2]string{f.ReqHeaders, f.RespHeaders, f.RespTrailers} {
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
	rulesLog      func(rules map[string]int, resolve []string, problem string) // SetRulesLog
	maxFlows      int
	maxBytes      int
	flows         map[string]*Flow
	order         []string
	heldBytes     int
	hello         event
	tlsFailures   []TLSFailure
	passes        []*passthrough          // --pass-hosts connections, oldest first, at most maxPasses
	passByConn    map[string]*passthrough // the open ones
	passCount     int                     // all seen, evicted included
	addonDropped  [2]int64                // bodies, events
	badLines      int64
	maskFailed    int64 // lines masking panicked on (counted in badLines too)
	unknownVer    int64
	orphanUpdates int64
	evicted       int64
	names         map[string]string // device StableID -> display name
	allow         HostRules         // hosts recorded (--allow-hosts)
	redact        atomic.Bool       // mask secrets as they arrive (off: --no-redact); set before events, read outside mu by Apply
	outOfScope    int64             // requests to hosts outside allow, seen here
	addonOOS      int64             // the same, seen by the addon
	earlier       [3]int64          // addon counters of mitmdump processes that exited: dropped bodies, events, out of scope
	hellos        int64
	seq           int64         // last Flow.seq (or Flow.answered) handed out
	evictedMark   int64         // the highest seq or answered of the flows evicted: a wait from below it may have missed one
	wake          chan struct{} // closed when a flow is answered, for Wait; nil until a waiter asks
	started       time.Time
	base          int64  // the first seq is base+1: base is started in unix µs, so a cursor of an earlier run is below it
	state         string // starting, ready, restarting, failed
	stateDetail   string
	restarts      int64
	rulesLoaded   time.Time // when the --rules file was last taken (at start, or a reload)
}

func (s *Store) setState(state, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state == "restarting" && s.state != "restarting" {
		s.restarts++
	}
	s.state, s.stateDetail = state, detail
}

// badLine counts a line from the addon that could not be taken.
func (s *Store) badLine() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.badLines++
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
			s.answerLocked(f)
		}
	}
	// mitmdump took them down with it; their bytes went with it. A pass_open of
	// the dead process read after this would stay open: lines are read in order,
	// so only one cut off mid-write could.
	for _, p := range s.passByConn {
		p.end, p.note, p.unknown = float64(time.Now().UnixNano())/1e9, why+" (bytes unknown)", true
	}
	clear(s.passByConn)
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
	s.allow = allow
	s.redact.Store(redact)
}

// SetRulesLog has f told of each --rules-reload: the rules now in force (counts
// by kind, and resolve's targets), and why the file did not load when it did not
// (the rules before it then stay).
func (s *Store) SetRulesLog(f func(rules map[string]int, resolve []string, problem string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rulesLog = f
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
	now := time.Now()
	// ponytail: a run handing out over a million seqs a second for its whole
	// life (two a flow, its arrival and its answer, and one a WebSocket message)
	// could pass the next run's base, and then its cursors look current.
	s := &Store{maxFlows: maxFlows, maxBytes: maxBytes, flows: map[string]*Flow{}, passByConn: map[string]*passthrough{}, allow: HostRules{All: true}, state: "starting",
		started: now, base: now.UnixMicro(), seq: now.UnixMicro()}
	s.redact.Store(true)
	return s
}

// Apply takes one line from the addon. What the event brings is masked
// before the lock is taken, a body too, so tools do not wait while one is
// masked (6.9 ms for 64 KiB). Lines of one connection are applied in order,
// by the one goroutine reading it.
func (s *Store) Apply(line []byte) {
	// A line a bug in masking cannot read must not take reqcove (the exit
	// node with it) down: it is counted as a bad line.
	defer func() {
		if r := recover(); r != nil {
			s.mu.Lock()
			s.badLines++
			s.maskFailed++ // apart: a bug in masking, not a line the addon garbled
			s.mu.Unlock()
		}
	}()
	var e event
	err := json.Unmarshal(line, &e)
	var head []byte
	headOK := true // false: the flow was not there when its body was masked
	if err == nil && e.V == wireVersion {
		s.maskEvent(&e)
		switch e.Ev {
		case "body":
			head, headOK = s.maskHead(&e)
			if e.Dir == "request" && headOK {
				e.op = gqlBodyOperation(head) // a POST's body names it, a GET's URL
			}
		case "ws":
			e.wsHead, e.wsNote = s.wsHead(&e)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
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
		if e.Rules != nil { // at start, and when a restarted mitmproxy takes the file again
			s.rulesLoaded = time.Now()
		}
		return
	case "skip": // a request outside --allow-hosts; only its count matters
		return
	case "rules": // --rules-reload took the file again, or could not
		s.hello.Rules, s.hello.Resolve, s.hello.RulesError = e.Rules, e.Resolve, e.RulesError
		if e.RulesError == "" {
			s.rulesLoaded = time.Now()
		}
		if s.rulesLog != nil {
			s.rulesLog(e.Rules, e.Resolve, e.RulesError)
		}
		return
	case "pass_open":
		if !s.allow.Allowed(e.SNI) || !s.allow.Passed(e.SNI) { // passed through for an allowed --pass-hosts host only: checked here too
			s.outOfScope++
			return
		}
		p := &passthrough{conn: e.Conn, device: e.Device, host: e.SNI, server: e.Server, alpn: e.ALPN, start: e.TS}
		s.passes = append(s.passes, p)
		s.passByConn[e.Conn] = p
		s.passCount++
		if len(s.passes) > maxPasses {
			delete(s.passByConn, s.passes[0].conn)
			s.passes = s.passes[1:]
		}
		return
	case "pass_close":
		if p := s.passByConn[e.Conn]; p != nil {
			p.end, p.up, p.down, p.note = e.TSEnd, e.Up, e.Down, e.Msg
			delete(s.passByConn, e.Conn)
		}
		return
	case "tls_failed":
		host := e.SNI
		if host == "" {
			host = e.Host
		}
		if !s.allow.Allowed(host) {
			s.outOfScope++ // only hosts in --allow-hosts are recorded, failures included
			return
		}
		msg := e.Msg
		if s.allow.Passed(host) { // a --pass-hosts host was decrypted after all: say so, it is why it failed
			msg = "not passed through (--pass-hosts did not apply to this connection): " + msg
		}
		s.tlsFailures = append(s.tlsFailures, TLSFailure{e.Conn, e.Device, e.Client, host, msg, e.TS})
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
	if f == nil || !headOK {
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
		f.Method, f.URL, f.Host, f.Path, f.HTTPVersion = e.Method, e.URL, e.Host, e.Path, e.HTTPVersion
		f.ReqHeaders = e.Headers
		if e.Note != "" {
			f.Notes = append(f.Notes, "request headers: "+e.Note)
		}
		f.MappedURL, f.Rewrites, f.Operation, f.Mocked, f.opNamed = e.MappedURL, e.Rewrites, e.op, e.Mocked, e.op != ""
	case "response":
		s.answerLocked(f)
		f.Status, f.Reason, f.RespHeaders = e.Status, e.Reason, e.Headers
		f.Rewrites = append(f.Rewrites, e.Rewrites...)
		if e.Note != "" {
			f.Notes = append(f.Notes, "response headers: "+e.Note)
		}
	case "body":
		// The URL's or the header's name comes first, and a GET's body names
		// nothing, as for mocks; a later head corrects a partial one's.
		if e.Dir == "request" && !f.opNamed && f.Method != "GET" && (e.op != "" || e.Final) {
			f.Operation = e.op
		}
		if e.Dir == "response" && e.grpcTrailers != nil && f.RespTrailers == nil {
			f.RespTrailers = e.grpcTrailers
		}
		b := Body{head, e.Size, e.Final, e.Truncated, e.Decoded, e.Encoding, e.Note, e.view}
		if e.Dir == "request" {
			f.ReqBody = b
		} else {
			f.RespBody = b
		}
	case "done":
		if len(e.Trailers) > 0 {
			f.RespTrailers = e.Trailers
		}
		if e.Note != "" {
			f.Notes = append(f.Notes, "response trailers: "+e.Note)
		}
		if f.Status != 101 || !strings.EqualFold(header(f.RespHeaders, "upgrade"), "websocket") { // a WebSocket is open until ws_end (an h2c or other 101 is not one)
			f.End, f.State = e.TSEnd, "done"
		}
		s.answerLocked(f) // a response event dropped by the addon: done answers it too
	case "error":
		f.Error, f.State = e.Msg, "error"
		s.answerLocked(f)
	case "ws":
		f.WSMessages++
		f.WSBytes += e.Size
		if f.ws == nil {
			f.ws = &wsLog{}
		}
		s.seq++ // messages share the flows' counter, so a checkpoint is a cursor for them too; they wake no wait
		f.ws.add(WSMessage{Seq: s.seq, N: f.WSMessages, Time: e.TS, FromClient: e.FromClient, Size: e.Size, Text: e.Text,
			Head: e.wsHead, Truncated: e.Truncated && e.wsHead != "", Note: e.wsNote})
	case "ws_end":
		f.WSClose = &WSClose{Time: e.TSEnd, Code: e.Code, ByClient: e.ByClient, Reason: e.Reason}
		if f.State == "open" {
			f.End, f.State = e.TSEnd, "done"
		}
	}
	s.heldBytes += f.bytes() - before
	s.evictLocked()
}

// maskEvent masks, in place, what an event brings that a site or an app
// wrote: URLs, headers, a reason (free text from the site), an error.
func (s *Store) maskEvent(e *event) {
	switch e.Ev {
	case "request":
		e.URL, e.Path, e.MappedURL, e.Headers = s.mask(e.URL), s.mask(e.Path), s.mask(e.MappedURL), s.maskHeaders(e.Headers)
		if e.op = gqlURLOperation(e.URL); e.op == "" {
			e.op = gqlName(header(e.Headers, "x-apollo-operation-name")) // Apollo's, as mocks read it
		}
	case "response":
		e.Reason, e.Headers = s.mask(e.Reason), s.maskHeaders(e.Headers)
	case "error", "tls_failed":
		e.Msg = s.maskError(e.Msg)
	case "done":
		e.Trailers = s.maskHeaders(e.Trailers)
	case "ws_end":
		e.Reason = s.mask(e.Reason)
	}
}

// maskHead decodes and masks a body event's head. The lock is held only to
// read the content type its direction's headers give; the flow is looked up
// again when the head is stored. ok is false if the flow was not there: the
// event is then an orphan, even if the flow comes meanwhile, so a head is
// stored only as masked.
func (s *Store) maskHead(e *event) (head []byte, ok bool) {
	head, _ = base64.StdEncoding.DecodeString(e.Head)
	redact := s.redact.Load()
	s.mu.Lock()
	f := s.flows[e.ID]
	var ct, path string
	if f != nil {
		h := f.RespHeaders
		if e.Dir == "request" {
			h = f.ReqHeaders
		}
		ct, path = header(h, "content-type"), f.Path
	}
	s.mu.Unlock() // f is not used past here
	if f == nil {
		return nil, false
	}
	if isGRPC(ct) && e.Decoded { // framed: masked message by message, and described
		var note string
		head, note, e.grpcTrailers, e.view = s.grpcBody(head, ct, path, e.Dir == "request", redact, e.Truncated || !e.Final)
		if e.Note == "" {
			e.Note = note
		}
		return head, true
	}
	if !redact {
		return head, true
	}
	if isProtobuf(ct) && e.Decoded { // not text: rendered, its strings by length unless --proto names them
		head, e.view = renderProto(head, ct, path, e.Dir == "request", e.Truncated || !e.Final) // a partial head is cut too
		return head, true
	}
	return maskBody(head, ct, e.Dir == "request"), true
}

func (s *Store) evictLocked() {
	for len(s.order) > 0 && (len(s.order) > s.maxFlows || s.heldBytes > s.maxBytes) {
		// An open socket that is talking is passed over for the next flow (among
		// the oldest few), so s.order stays in seq order (List pages by it).
		i := 0
		for k := 0; k < min(len(s.order)-1, 16); k++ {
			if f := s.flows[s.order[k]]; f.ws == nil || f.WSClose != nil || f.State != "open" {
				i = k
				break
			}
		}
		id := s.order[i]
		copy(s.order[1:i+1], s.order[:i])
		s.order = s.order[1:]
		f := s.flows[id]
		mark := f.answered
		if mark == 0 { // still open: its answer, had it come, would be after any cursor taken so far
			s.seq++ // its own: a body event hands out none, so s.seq may be a cursor already given
			mark = s.seq
			if s.wake != nil { // and a waiter for it should hear of the gap now, not at its timeout
				close(s.wake)
				s.wake = nil
			}
		}
		s.evictedMark = max(s.evictedMark, f.seq, mark)
		s.heldBytes -= f.bytes()
		delete(s.flows, id)
		s.evicted++
	}
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
