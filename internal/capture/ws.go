package capture

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// WebSocket messages: the addon sends a text message's first wsHeadLimit
// bytes (at most about 20 a second per socket, bursts of 100: past that, and
// for binary messages, only the size), masked here as it arrives with the
// direction's rules. A flow keeps its socket's first wsKeepFirst messages
// (the auth message is usually one) and its newest wsKeepLast.
const (
	wsHeadLimit   = 4 << 10
	wsKeepFirst   = 5
	wsKeepLast    = 100
	wsListLimit   = 100
	wsListDefault = 20
)

// WSMessage is one message as list_ws_messages returns it.
type WSMessage struct {
	Seq        int64   `json:"seq"` // from the store's counter, as checkpoints: pass the last one as after
	N          int     `json:"n"`   // its number on the socket, from 1
	Time       float64 `json:"time"`
	FromClient bool    `json:"from_client"`
	Size       int64   `json:"size"` // the whole message's
	Text       bool    `json:"text"` // a text message (not binary)
	Head       string  `json:"head,omitempty"`
	Truncated  bool    `json:"truncated,omitempty"` // head is the message's first bytes only
	Note       string  `json:"note,omitempty"`      // why there is no head
}

// WSClose is how a socket ended.
type WSClose struct {
	Time     float64 `json:"time"`
	Code     int     `json:"code,omitempty"`
	ByClient bool    `json:"by_client"`
	Reason   string  `json:"reason,omitempty"`
}

// wsLog is a flow's kept messages; Store.mu guards it.
type wsLog struct {
	first, last []WSMessage
	bytes       int // heads and notes kept
	lastSeq     int64
	bumped      bool // moved to the back of the eviction order once
}

func (w *wsLog) add(m WSMessage) {
	w.lastSeq = m.Seq
	w.bytes += len(m.Head) + len(m.Note)
	if m.N <= wsKeepFirst {
		w.first = append(w.first, m)
		return
	}
	w.last = append(w.last, m)
	if len(w.last) > wsKeepLast {
		w.bytes -= len(w.last[0].Head) + len(w.last[0].Note)
		w.last = append(w.last[:0:0], w.last[1:]...) // a copy: one handed out keeps its own
	}
}

// kept returns the kept messages oldest first (copies the caller may keep).
func (w *wsLog) kept() []WSMessage {
	if w == nil {
		return nil
	}
	return append(append([]WSMessage(nil), w.first...), w.last...)
}

// wsHead decodes and masks a message's head before the lock. Binary
// messages, and text that masking cannot read (control characters but a
// STOMP frame's closing NUL), keep no head while masking.
func (s *Store) wsHead(e *event) (head, note string) {
	if e.Capped {
		return "", "not kept: more than about 20 messages a second on this socket, or the queue was full"
	}
	if !e.Text {
		return "", "binary: size only"
	}
	b, _ := base64.StdEncoding.DecodeString(e.Head)
	if !s.redact.Load() {
		return string(trimCutRune(b)), ""
	}
	t := trimCutRune(b)
	if !strictText([]byte(strings.TrimSuffix(string(t), "\x00"))) {
		return "", "omitted: not text, so it cannot be checked for secrets (reqcove run --no-redact returns it)"
	}
	return maskWSMessage(string(t), e.FromClient), ""
}

// maskWSMessage masks a message as a body, then two shapes only messages
// have, in what a client sends: a bare token as the whole message, and the
// values after an auth event's name in an event array (socket.io's
// 42["authenticate","…"]).
func maskWSMessage(m string, fromClient bool) string {
	m = string(maskBody([]byte(m), "", fromClient))
	if !fromClient {
		return m
	}
	t := strings.TrimSpace(strings.TrimSuffix(m, "\x00"))
	if len(t) >= 16 && !strings.ContainsAny(t, " \t\r\n\"'{}[]:,<>") && credentialLike(t) && strings.ContainsAny(t, "0123456789") && strings.IndexFunc(t, func(r rune) bool { return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' }) >= 0 {
		return strings.Replace(m, t, "[redacted]", 1)
	}
	return maskAuthEvent(m)
}

// wsAuthEvents name events that send a credential as their arguments.
var wsAuthEvents = map[string]bool{"authenticate": true, "authorize": true, "auth": true, "login": true, "signin": true, "identify": true}

// maskAuthEvent: an event array (after socket.io's digits and namespace)
// whose first element names an auth event or a secret: its string elements
// after it are masked (objects in it are masked by name already).
func maskAuthEvent(m string) string {
	i := 0
	for i < len(m) && m[i] >= '0' && m[i] <= '9' {
		i++
	}
	if i < len(m) && m[i] == '/' { // a namespace: /chat,
		if k := strings.IndexByte(m[i:], ','); k > 0 {
			i += k + 1
		}
	}
	if i >= len(m) || m[i] != '[' {
		return m
	}
	j := skipSpace(m, i+1)
	if j >= len(m) || m[j] != '"' {
		return m
	}
	end, ok := jsonStringEnd(m, j)
	name := strings.ToLower(strings.NewReplacer("_", "", "-", "", ":", "", ".", "").Replace(m[j+1 : end]))
	if !ok || !wsAuthEvents[name] && !secretName(m[j+1:end]) {
		return m
	}
	var b strings.Builder
	last := 0
	for k := end + 1; k < len(m); {
		k = skipSpace(m, k)
		if k >= len(m) || m[k] != ',' {
			break
		}
		k = skipSpace(m, k+1)
		if k >= len(m) {
			break
		}
		switch m[k] {
		case '"':
			e, closed := jsonStringEnd(m, k)
			b.WriteString(m[last : k+1])
			b.WriteString("[redacted]")
			if closed {
				b.WriteByte('"')
			}
			last = e + 1
			k = e + 1
		case '{', '[':
			e, _ := containerEnd(m, k)
			k = e + 1
		default:
			for k < len(m) && m[k] != ',' && m[k] != ']' {
				k++
			}
		}
	}
	if last == 0 {
		return m
	}
	b.WriteString(m[min(last, len(m)):])
	return b.String()
}

// WSPage is what list_ws_messages returns.
type WSPage struct {
	FlowID   string      `json:"flow_id"`
	Messages []WSMessage `json:"messages"` // oldest first; [] when none, not null
	After    int64       `json:"after"`    // pass it back for the next page: the last message's seq, or the after given
	More     bool        `json:"more,omitempty"`
	// Missed counts messages after `after` that are no longer kept (between
	// the socket's first messages and its newest), never their contents.
	Missed int      `json:"missed,omitempty"`
	Total  int      `json:"total"` // messages on the socket so far, kept or not
	Open   bool     `json:"open"`
	Close  *WSClose `json:"close,omitempty"`
}

// WSQuery selects messages for WSList.
type WSQuery struct {
	After      int64
	Limit      int
	FromClient *bool  // nil: both directions
	Text       string // case-insensitive text in the head
	MaxBytes   int    // a head cut to this, 0: as kept
}

// WSList returns a flow's kept messages after q.After, oldest first.
func (s *Store) WSList(id string, q WSQuery) (WSPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flows[id]
	if f == nil {
		return WSPage{}, fmt.Errorf("no flow %q (evicted, or from before reqcove run restarted)", id)
	}
	if q.Limit <= 0 {
		q.Limit = wsListDefault
	}
	q.Limit = min(q.Limit, wsListLimit)
	p := WSPage{FlowID: id, Messages: []WSMessage{}, After: q.After, Total: f.WSMessages, Close: f.WSClose, Open: f.Status == 101 && f.WSClose == nil && f.State == "open"}
	needle := strings.ToLower(q.Text)
	prevN := 0
	for _, m := range f.ws.kept() {
		if m.Seq <= q.After {
			prevN = m.N
			continue
		}
		if len(p.Messages) == q.Limit {
			if q.FromClient == nil || *q.FromClient == m.FromClient {
				if needle == "" || strings.Contains(strings.ToLower(m.Head), needle) {
					p.More = true
					break
				}
			}
			continue
		}
		if m.N > prevN+1 {
			p.Missed += m.N - prevN - 1
		}
		prevN = m.N
		p.After = m.Seq
		if q.FromClient != nil && *q.FromClient != m.FromClient || needle != "" && !strings.Contains(strings.ToLower(m.Head), needle) {
			continue
		}
		if q.MaxBytes > 0 && len(m.Head) > q.MaxBytes {
			m.Head, m.Truncated = string(trimCutRune([]byte(m.Head[:q.MaxBytes]))), true
		}
		p.Messages = append(p.Messages, m)
	}
	return p, nil
}
