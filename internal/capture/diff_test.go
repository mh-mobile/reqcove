package capture

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func flowWith(s *Store, id, extra, respBody string) {
	s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"request","id":%q,"device":"d","method":"POST","host":"api.example.com","url":"https://api.example.com/v1/me?token=abc%s","headers":[["Authorization","Bearer t-%s"],["Accept","application/json"]%s]}`, id, id, id, extra)))
	s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"response","id":%q,"status":%d,"headers":[["Content-Type","application/json"],["Set-Cookie","sid=%s"],["Set-Cookie","theme=dark"]]}`, id, map[bool]int{true: 200, false: 401}[id == "a"], id)))
	s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"body","id":%q,"dir":"response","head":%q,"size":%d,"final":true,"decoded":true}`, id, base64.StdEncoding.EncodeToString([]byte(respBody)), len(respBody))))
	s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"done","id":%q}`, id)))
}

func fields(d FlowDiff) string {
	var f []string
	for _, x := range d.Differences {
		f = append(f, fmt.Sprintf("%s=%v|%v", x.Field, x.A, x.B))
	}
	return strings.Join(f, " ")
}

// TestDiffFlows: what differs is listed; masked values that read the same
// are listed as masked, never as equal; JSON bodies by path.
func TestDiffFlows(t *testing.T) {
	s := NewStore(100, 1<<20)
	flowWith(s, "a", "", `{"user":{"id":1,"name":"x"},"session":"s-a","items":[1,2]}`)
	flowWith(s, "b", `,["X-Debug","1"]`, `{"user":{"id":2,"name":"x"},"session":"s-b","items":[1]}`)
	d, err := s.DiffFlows("a", "b")
	if err != nil {
		t.Fatal(err)
	}
	got := fields(d)
	for _, want := range []string{"status=200|401", "request_header:x-debug=<nil>|1", "response_body:$.user.id=1|2", "response_body:$.items[1]=2|<nil>"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s not in %s", want, got)
		}
	}
	for _, same := range []string{"request_header:accept", "$.user.name", "url="} {
		if strings.Contains(got, same) {
			t.Errorf("%s listed as different: %s", same, got)
		}
	}
	// Masked on both sides, so they read the same: masked, not equal, not different.
	masked := strings.Join(d.Masked, " ")
	for _, want := range []string{"url", "request_header:authorization", "response_header:set-cookie", "response_body:$.session"} {
		if !strings.Contains(masked, want) {
			t.Errorf("%s not in masked: %s", want, masked)
		}
	}
	if d.ResponseBody.Result != "differs" || d.RequestBody.Result != "none" {
		t.Errorf("bodies: %+v %+v", d.RequestBody, d.ResponseBody)
	}
	if strings.Contains(fmt.Sprint(d), "t-a") || strings.Contains(fmt.Sprint(d), "s-a") {
		t.Errorf("a secret in the diff: %+v", d)
	}
	if _, err := s.DiffFlows("a", "gone"); err == nil {
		t.Error("a missing flow")
	}
}

// TestDiffNoRedact: with --no-redact every value is compared, "[redacted]"
// in a value included (it is then the site's own text).
func TestDiffNoRedact(t *testing.T) {
	s := NewStore(100, 1<<20)
	s.SetScope(HostRules{All: true}, false)
	flowWith(s, "a", "", `{"note":"[redacted]"}`)
	flowWith(s, "b", "", `{"note":"[redacted]"}`)
	d, _ := s.DiffFlows("a", "b")
	if got := fields(d); !strings.Contains(got, "request_header:authorization=Bearer t-a|Bearer t-b") {
		t.Errorf("values not compared: %s", got)
	}
	if len(d.Masked) != 0 || d.ResponseBody.Result != "same" {
		t.Errorf("masked %v, body %+v", d.Masked, d.ResponseBody)
	}
}

// TestDiffBodies: heads cut, not text, or not kept are not called the same.
func TestDiffBodies(t *testing.T) {
	s := NewStore(100, 1<<20)
	body := func(id, head string, size int, final, truncated bool, ct string) {
		s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"request","id":%q,"device":"d","host":"h.example","url":"https://h.example/"}`, id)))
		s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"response","id":%q,"status":200,"headers":[["Content-Type",%q]]}`, id, ct)))
		s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"body","id":%q,"dir":"response","head":%q,"size":%d,"final":%v,"truncated":%v,"decoded":true}`, id, base64.StdEncoding.EncodeToString([]byte(head)), size, final, truncated)))
	}
	body("c1", "same start", 100000, true, true, "text/plain")
	body("c2", "same start", 200000, true, true, "text/plain")
	body("p1", "\x08\x96\x01", 3, true, false, "application/x-protobuf")
	body("p2", "\x08\x96\x01", 3, true, false, "application/x-protobuf")
	body("t1", "hello", 5, true, false, "text/plain")
	body("t2", "hello", 5, true, false, "text/plain")
	for _, c := range []struct{ a, b, want string }{{"c1", "c2", "heads_same"}, {"p1", "p2", "not_compared"}, {"t1", "t2", "same"}, {"t1", "c1", "differs"}} {
		d, _ := s.DiffFlows(c.a, c.b)
		if d.ResponseBody.Result != c.want {
			t.Errorf("%s vs %s: %+v, want %s", c.a, c.b, d.ResponseBody, c.want)
		}
	}
}
