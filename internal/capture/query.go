package capture

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
)

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
	UserAgent    string // text in the request's User-Agent, lowercase: matched case-insensitively
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
		q.Method != "" && !strings.EqualFold(f.Method, q.Method),
		q.UserAgent != "" && !containsFold(header(f.ReqHeaders, "user-agent"), q.UserAgent):
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

// OldCursor says whether cursor came from an earlier run of reqcove, whose
// flows are gone. base itself is this run's: an empty store's Checkpoint.
func (s *Store) OldCursor(cursor int64) bool {
	return cursor != 0 && cursor < s.base // base never changes
}

// List returns the newest matching flows first, and a cursor for the next
// (older) page, 0 when there is none.
// ponytail: the search (bodies included) holds s.mu, so a search over many
// large heads holds up ingest meanwhile; copy the flows out first if it shows.
func (s *Store) List(q Filter) ([]Summary, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q.textOnly = s.redact.Load()
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

// maxUAText is how much of a User-Agent lists and summaries show (get_flow
// has it whole): an app can send a long one, and an agent reads each.
const maxUAText = 256

// summary: the caller holds s.mu (s.names).
func (s *Store) summary(f *Flow) Summary {
	v := Summary{ID: f.ID, Device: f.Device, DeviceName: s.names[f.Device], Method: f.Method, Host: f.Host, URL: f.URL,
		State: f.State, Status: f.Status, RespSize: f.RespBody.Size, Error: f.Error,
		ContentType: header(f.RespHeaders, "content-type"), UserAgent: cutTo(header(f.ReqHeaders, "user-agent"), maxUAText),
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
		add("ua", cutTo(header(f.ReqHeaders, "user-agent"), maxUAText))
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

// SimilarHosts returns up to n recorded hosts that look like host (compared
// lowercased with all but letters and digits left out, one containing the
// other: acmeshop.com and api.acme-shop.com), for an agent whose
// host filter matched nothing; nil when host or a subdomain of it is recorded.
func (s *Store) SimilarHosts(host string, n int) []string {
	key := func(h string) string {
		return strings.Map(func(r rune) rune {
			if 'a' <= r && r <= 'z' || '0' <= r && r <= '9' {
				return r
			}
			return -1
		}, strings.ToLower(h))
	}
	// Keys this short (x.com, news) are in too many others to tell alike from not.
	const shortest = 6
	want := key(host)
	if len(want) < shortest {
		return nil
	}
	q := Filter{Host: host}
	seen := map[string]bool{}
	s.mu.Lock()
	for _, f := range s.flows {
		if q.match(f, "") {
			s.mu.Unlock()
			return nil
		}
		seen[strings.ToLower(f.Host)] = true
	}
	s.mu.Unlock()
	var out []string
	for h := range seen {
		if k := key(h); len(k) >= shortest && (strings.Contains(k, want) || strings.Contains(want, k)) {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out[:min(len(out), n)]
}
