package capture

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// TestOperationAndEndpoints: a GraphQL request's operation (operationName
// first, then the document's; anonymous, batched, GET, persisted, cut), on
// rows, filtered by, and in summarize's by_endpoint with ids collapsed.
func TestOperationAndEndpoints(t *testing.T) {
	s := NewStore(100, 1<<20)
	n := 0
	flow := func(method, url, body string) string {
		n++
		id := fmt.Sprintf("f%d", n)
		host, path, _ := strings.Cut(strings.TrimPrefix(url, "https://"), "/")
		s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"request","id":%q,"method":%q,"url":%q,"host":%q,"path":%q,"headers":[["Content-Type","application/json"]]}`, id, method, url, host, "/"+path)))
		if body != "" {
			s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"body","id":%q,"dir":"request","head":%q,"size":%d,"final":true,"decoded":true}`, id, base64.StdEncoding.EncodeToString([]byte(body)), len(body))))
		}
		return id
	}
	for _, c := range []struct{ method, url, body, op string }{
		{"POST", "https://api.example.com/graphql", `{"operationName":"Login","query":"mutation Other($p: String) { login(password: $p) }"}`, "Login"},
		{"POST", "https://api.example.com/graphql", `{"query":"query Feed { feed { id } }"}`, "Feed"},
		{"POST", "https://api.example.com/graphql", `{"query":"{ me(token: \"x\") { id } }"}`, gqlAnonymous},
		{"POST", "https://api.example.com/graphql", `[{"query":"query A { a }"},{"query":"query B { b }"}]`, gqlBatched},
		{"POST", "https://api.example.com/graphql", `{"operationName":"Persisted","extensions":{"persistedQuery":{"sha256Hash":"ab"}}}`, "Persisted"},
		{"POST", "https://api.example.com/graphql", `{"operationName":"Cut","query":"mutation { login(password: \"`, "Cut"},
		{"GET", "https://api.example.com/graphql?query=query+Search+%7B+s+%7D", "", "Search"},
		{"GET", "https://api.example.com/graphql?operationName=ByName&query=%7B+a+%7D", "", "ByName"},
		{"POST", "https://api.example.com/graphql", `{"operationName":"not a name <b>","query":"query Q { a }"}`, "Q"}, // a name GraphQL does not allow is not shown
		{"POST", "https://shop.example.com/search", `{"query":"shoes"}`, ""},
		{"POST", "https://api.example.com/graphql", `{"query":"fragment F on U { a } query Feed { ...F }"}`, "Feed"},           // past a fragment
		{"POST", "https://api.example.com/graphql", `{"query":"\"\"\"Described\"\"\" mutation Described { a }"}`, "Described"}, // past a description
		{"POST", "https://api.example.com/graphql", `{"query":"fragment F on U { a } { ...F }"}`, gqlAnonymous},
	} {
		id := flow(c.method, c.url, c.body)
		if v, _ := s.Get(id, false); v.Operation != c.op {
			t.Errorf("%s %s: operation %q, want %q", c.method, c.url, v.Operation, c.op)
		}
	}
	if rows, _ := s.List(Filter{Operation: "login", Limit: 10}); len(rows) != 1 || rows[0].Operation != "Login" {
		t.Errorf("filter: %+v", rows)
	}
	flow("GET", "https://shop.example.com/v1/users/42?x=1", "")
	flow("GET", "https://shop.example.com/v1/users/7", "")
	flow("GET", "https://shop.example.com/v1/orders/123e4567-e89b-12d3-a456-426614174000/items", "")
	got := map[string]int{}
	for _, c := range s.Summarize(Filter{}, 20).ByEndpoint {
		got[c.Key] = c.Count
	}
	for k, want := range map[string]int{
		"GET shop.example.com/v1/users/{id}":         2,
		"GET shop.example.com/v1/orders/{id}/items":  1,
		"POST api.example.com/graphql Login":         1,
		"POST api.example.com/graphql " + gqlBatched: 1,
		"POST shop.example.com/search":               1,
		"GET api.example.com/graphql Search":         1,
	} {
		if got[k] != want {
			t.Errorf("by_endpoint %q: %d, want %d (%v)", k, got[k], want, got)
		}
	}
}
