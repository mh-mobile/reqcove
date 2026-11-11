package capture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Diff is one field that differs between two flows.
type Diff struct {
	Field string `json:"field"`       // status, method, url, mapped_url, error, request_header:NAME, response_header:NAME, request_body:PATH, response_body:PATH
	A     any    `json:"a,omitempty"` // absent on that side when left out
	B     any    `json:"b,omitempty"`
}

// BodyDiff compares two body heads as they were kept.
type BodyDiff struct {
	// Result: same; differs; heads_same (equal as far as kept, but cut, so the
	// whole bodies may differ); masked (equal as shown, but with masked parts,
	// whose values may differ); not_compared (Note says why); none (neither
	// flow has one).
	Result string `json:"result"`
	Note   string `json:"note,omitempty"`
	ASize  int64  `json:"a_size"`
	BSize  int64  `json:"b_size"`
}

// FlowDiff is DiffFlows' answer.
type FlowDiff struct {
	A           Summary `json:"a"`
	B           Summary `json:"b"`
	Differences []Diff  `json:"differences"`
	// Masked lists the fields that read the same but hold masked values: the
	// values themselves may differ.
	Masked       []string `json:"masked,omitempty"`
	RequestBody  BodyDiff `json:"request_body"`
	ResponseBody BodyDiff `json:"response_body"`
	Truncated    bool     `json:"truncated,omitempty"` // more differences than maxDiffs: the rest left out
}

const (
	maxDiffs    = 100
	maxDiffText = 300 // a value's text in a Diff, at most; longer ones are cut, with "…"
)

// DiffFlows compares flows a and b as they are kept (masked as they arrived),
// both read under one lock.
func (s *Store) DiffFlows(a, b string) (FlowDiff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fa, fb := s.flows[a], s.flows[b]
	for id, f := range map[string]*Flow{a: fa, b: fb} {
		if f == nil {
			return FlowDiff{}, fmt.Errorf("no flow %q (evicted, or from before reqcove run restarted)", id)
		}
	}
	d := &differ{redact: s.redact, out: FlowDiff{A: s.summary(fa), B: s.summary(fb), Differences: []Diff{}}}
	d.value("method", fa.Method, fb.Method)
	d.value("url", fa.URL, fb.URL)
	d.value("mapped_url", fa.MappedURL, fb.MappedURL)
	if fa.Status != fb.Status {
		d.add(Diff{"status", fa.Status, fb.Status})
	}
	d.value("error", fa.Error, fb.Error)
	d.headers("request_header:", fa.ReqHeaders, fb.ReqHeaders)
	d.headers("response_header:", fa.RespHeaders, fb.RespHeaders)
	d.out.RequestBody = d.body("request_body:", fa.ReqBody, fb.ReqBody, fa.ReqHeaders, fb.ReqHeaders)
	d.out.ResponseBody = d.body("response_body:", fa.RespBody, fb.RespBody, fa.RespHeaders, fb.RespHeaders)
	return d.out, nil
}

type differ struct {
	redact bool
	out    FlowDiff
}

func (d *differ) add(x Diff) {
	if len(d.out.Differences) == maxDiffs {
		d.out.Truncated = true
		return
	}
	d.out.Differences = append(d.out.Differences, x)
}

// masked: v shows a masked value (only while masking is on: with
// --no-redact, a "[redacted]" in a value is the site's own text).
func (d *differ) masked(v string) bool {
	return d.redact && (strings.Contains(v, "[redacted]") || strings.Contains(v, "REDACTED"))
}

// value compares two texts: equal and masked goes under Masked, never as
// equal; one side empty is left out of that side.
func (d *differ) value(field, a, b string) {
	if a == b {
		if d.masked(a) {
			d.out.Masked = append(d.out.Masked, field)
		}
		return
	}
	x := Diff{Field: field}
	if a != "" {
		x.A = cut(a)
	}
	if b != "" {
		x.B = cut(b)
	}
	d.add(x)
}

func cut(v string) string {
	if len(v) <= maxDiffText {
		return v
	}
	i := maxDiffText
	for i > 0 && v[i]&0xc0 == 0x80 { // not inside a UTF-8 sequence
		i--
	}
	return v[:i] + "…"
}

// headers compares by name (case-insensitive); a repeated header's values
// are compared as one list, in order.
func (d *differ) headers(prefix string, a, b [][2]string) {
	byName := func(h [][2]string) map[string][]string {
		m := map[string][]string{}
		for _, kv := range h {
			n := strings.ToLower(kv[0])
			m[n] = append(m[n], kv[1])
		}
		return m
	}
	ma, mb := byName(a), byName(b)
	var names []string
	for n := range ma {
		names = append(names, n)
	}
	for n := range mb {
		if _, ok := ma[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		d.value(prefix+n, strings.Join(ma[n], "\n"), strings.Join(mb[n], "\n"))
	}
}

func (d *differ) body(prefix string, a, b Body, ha, hb [][2]string) BodyDiff {
	r := BodyDiff{ASize: a.Size, BSize: b.Size}
	switch {
	case len(a.Head) == 0 && len(b.Head) == 0 && a.Size == 0 && b.Size == 0:
		r.Result = "none"
		return r
	case len(a.Head) == 0 && a.Size > 0 || len(b.Head) == 0 && b.Size > 0:
		r.Result, r.Note = "not_compared", "a body was not kept (dropped on the way to reqcove)"
		return r
	case d.redact && (!checkable(a, ha) || !checkable(b, hb)):
		r.Result, r.Note = "not_compared", "not text, so not checked for secrets: not compared (reqcove run --no-redact compares it)"
		return r
	}
	cutHead := a.Truncated || b.Truncated || !a.Final || !b.Final
	// JSON on both sides, whole: compared by path.
	if !cutHead {
		var ja, jb any
		if json.Unmarshal(a.Head, &ja) == nil && json.Unmarshal(b.Head, &jb) == nil {
			pa, pb := map[string]string{}, map[string]string{}
			flatten("$", ja, pa)
			flatten("$", jb, pb)
			paths := make([]string, 0, len(pa))
			for p := range pa {
				paths = append(paths, p)
			}
			for p := range pb {
				if _, ok := pa[p]; !ok {
					paths = append(paths, p)
				}
			}
			sort.Strings(paths)
			n := len(d.out.Differences)
			masked := len(d.out.Masked)
			for _, p := range paths {
				d.value(prefix+p, pa[p], pb[p])
			}
			switch {
			case len(d.out.Differences) > n || d.out.Truncated:
				r.Result = "differs"
			case len(d.out.Masked) > masked:
				r.Result = "masked"
			default:
				r.Result = "same"
			}
			return r
		}
	}
	switch {
	case !bytes.Equal(a.Head, b.Head):
		r.Result = "differs"
		if cutHead {
			r.Note = "the kept heads differ (the bodies were cut or still streaming)"
		}
	case d.masked(string(a.Head)):
		r.Result = "masked"
	case cutHead || a.Size != b.Size:
		r.Result, r.Note = "heads_same", "equal as far as kept: the bodies were cut or still streaming, so the rest may differ"
	default:
		r.Result = "same"
	}
	return r
}

// flatten puts each leaf of v under its path ($.a.b[0]) as compact JSON.
func flatten(path string, v any, out map[string]string) {
	switch v := v.(type) {
	case map[string]any:
		if len(v) == 0 {
			out[path] = "{}"
		}
		for k, x := range v {
			flatten(path+"."+k, x, out)
		}
	case []any:
		if len(v) == 0 {
			out[path] = "[]"
		}
		for i, x := range v {
			flatten(path+"["+strconv.Itoa(i)+"]", x, out)
		}
	default:
		b, _ := json.Marshal(v)
		out[path] = string(b)
	}
}
