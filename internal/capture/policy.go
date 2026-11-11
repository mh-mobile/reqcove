package capture

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync/atomic"
	"unicode"
)

// The user's mask policy (--mask-names, --mask-values): set once at start,
// before flows arrive; package-wide, as the maskers are.
// ponytail: one policy per process; a Store field if a process ever holds several runs.
var (
	maskNames  atomic.Pointer[map[string]*atomic.Int64] // flattened name -> times it matched
	maskValues atomic.Pointer[[]userValue]
)

type userValue struct {
	re   *regexp.Regexp
	hits atomic.Int64
}

const (
	maxMaskValues  = 32
	maxMaskPattern = 512
)

// flatName is a name as secretKind compares it: lowercase letters and digits.
func flatName(name string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, name)
}

// SetMaskPolicy sets the names treated as secret, as the built-in ones are
// (headers, URL and form parameters, JSON fields), and the patterns (RE2)
// whose matches are masked wherever they appear. Errors never quote a
// pattern: it may be a secret itself.
func SetMaskPolicy(names, values []string) error {
	m := map[string]*atomic.Int64{}
	for _, n := range names {
		f := flatName(n)
		if f == "" {
			return fmt.Errorf("--mask-names: %q has no letters or digits", n)
		}
		m[f] = new(atomic.Int64)
	}
	if len(values) > maxMaskValues {
		return fmt.Errorf("--mask-values: %d patterns, at most %d", len(values), maxMaskValues)
	}
	var vs []userValue
	for i, v := range values {
		if len(v) > maxMaskPattern {
			return fmt.Errorf("--mask-values: pattern %d is longer than %d bytes", i+1, maxMaskPattern)
		}
		re, err := regexp.Compile(v)
		if err != nil {
			why := "not a valid pattern"
			var se *syntax.Error
			if errors.As(err, &se) {
				why = string(se.Code) // the kind of error, without the pattern's text
			}
			return fmt.Errorf("--mask-values: pattern %d: %s (RE2 syntax)", i+1, why)
		}
		if re.MatchString("") {
			return fmt.Errorf("--mask-values: pattern %d matches empty text", i+1)
		}
		vs = append(vs, userValue{re: re})
	}
	if len(m) == 0 {
		maskNames.Store(nil)
	} else {
		maskNames.Store(&m)
	}
	if len(vs) == 0 {
		maskValues.Store(nil)
	} else {
		maskValues.Store(&vs)
	}
	return nil
}

// userName: flat is one of --mask-names (and counts it).
func userName(flat string) bool {
	m := maskNames.Load()
	if m == nil {
		return false
	}
	c, ok := (*m)[flat]
	if ok {
		c.Add(1)
	}
	return ok
}

// hasUserName: name is one of --mask-names (not counted: a check, not a mask).
func hasUserName(name string) bool {
	m := maskNames.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[flatName(name)]
	return ok
}

// maskUserValues masks the matches of --mask-values.
func maskUserValues(s string) string {
	vs := maskValues.Load()
	if vs == nil {
		return s
	}
	for i := range *vs {
		v := &(*vs)[i]
		if loc := v.re.FindStringIndex(s); loc != nil {
			v.hits.Add(1)
			s = v.re.ReplaceAllString(s, "[redacted]")
		}
	}
	return s
}

// policyStats is the policy as capture_stats shows it: the names (the
// user's own words, not secrets) and how often each matched; the patterns by
// number only.
func policyStats() map[string]any {
	out := map[string]any{}
	if m := maskNames.Load(); m != nil {
		hits := map[string]int64{}
		for n, c := range *m {
			hits[n] = c.Load()
		}
		out["mask_names"] = hits
	}
	if vs := maskValues.Load(); vs != nil {
		var hits []int64
		for i := range *vs {
			hits = append(hits, (*vs)[i].hits.Load())
		}
		out["mask_values"] = hits
	}
	return out
}

// gqlArgRE: a GraphQL argument with a string value, as in
// login(password: "x"), raw or inside a JSON string (\"x\", where the
// query's own escaped quote is \\\" and its backslash \\\\), a block
// string ("""x""", or \"\"\"x\"\"\" inside JSON) too; a value cut by the head's end (even right after a
// backslash) runs to it. Between the name, the colon and the value: spaces,
// line breaks (also written \n in JSON) and # comments.
var gqlArgRE = regexp.MustCompile(`((?:^|[(,{\s])(?:\s|\\[nrt]|#[^\n]*?(?:\\n|\n))*)([_A-Za-z][_0-9A-Za-z]*)(\s*:(?:\s|\\[nrt]|#[^\n]*?(?:\\n|\n))*)("""(?s:.*?)(?:"""|$)|\\"\\"\\"(?s:.*?)(?:\\"\\"\\"|$)|\\"(?:\\\\\\\\|\\\\\\"|\\[^"]|[^"\\])*(?:\\"|\\?$)|"(?:[^"\\]|\\.)*(?:"|\\?$))`)

// maskGraphQL masks the string values of GraphQL arguments with secret names
// (login(password: "x")), which are not JSON fields: the query is one string.
func maskGraphQL(s string, loneCode bool) string {
	if !strings.Contains(s, "(") || !strings.Contains(s, ":") {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range gqlArgRE.FindAllStringSubmatchIndex(s, -1) { // one pass: no second match per hit
		name := s[m[4]:m[5]]
		if !secretKind(name, loneCode) {
			continue
		}
		v := s[m[8]:m[9]]
		q := `"`
		switch {
		case strings.HasPrefix(v, `"""`):
			q = `"""`
		case strings.HasPrefix(v, `\"\"\"`):
			q = `\"\"\"`
		case strings.HasPrefix(v, `\"`):
			q = `\"`
		}
		b.WriteString(s[last:m[8]])
		b.WriteString(q + "[redacted]")
		if len(v) >= 2*len(q) && strings.HasSuffix(v, q) {
			b.WriteString(q)
		}
		last = m[9]
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}
