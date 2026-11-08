package capture

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// maskBody masks the secrets it can recognise in a kept body head, as it
// arrives: in JSON, the string values of fields whose names are secret
// (accessToken, password, ...); in a form (application/x-www-form-urlencoded),
// the values of such fields; anywhere in text, values whose shape gives them
// away (maskTokens). The head may be cut anywhere, so this works on text, not
// on parsed JSON: a value cut before its closing quote is masked too. Heads
// that are not text are left alone here and never handed out while masking
// (Store.bodyOut). Other secrets in a body, under names that do not say so,
// are not found.
func maskBody(head []byte, contentType string) []byte {
	if len(head) == 0 || !utf8.Valid(trimCutRune(head)) {
		return head
	}
	s := string(head)
	if strings.Contains(strings.ToLower(contentType), "application/x-www-form-urlencoded") {
		s = maskForm(s)
	} else {
		s = jsonSecretRE.ReplaceAllStringFunc(s, func(m string) string {
			sub := jsonSecretRE.FindStringSubmatch(m)
			if !secretBodyName(sub[1]) {
				return m
			}
			return sub[0][:len(sub[0])-len(sub[2])-len(sub[3])] + "[redacted]" + sub[3]
		})
	}
	return []byte(maskTokens(s))
}

// trimCutRune drops a UTF-8 character cut at the end of a head, for the check.
func trimCutRune(b []byte) []byte {
	for cut := 0; cut < utf8.UTFMax && cut < len(b); cut++ {
		if utf8.Valid(b[:len(b)-cut]) {
			return b[:len(b)-cut]
		}
	}
	return b
}

// "name": "value" in JSON; the value may run to the end of a cut head.
var jsonSecretRE = regexp.MustCompile(`"((?:[^"\\]|\\.){1,128})"\s*:\s*"((?:[^"\\]|\\.)*)("|$)`)

// secretBodyName is secretName for JSON fields, except code alone: in a
// body it is usually an error code ({"code": "invalid_token"}), which
// debugging needs. auth_code and the like still count (auth).
func secretBodyName(name string) bool {
	for _, w := range nameWords(name) {
		if secretWords[w] && w != "code" {
			return true
		}
	}
	return false
}

// maskForm masks the values of secret fields in a form body (a=1&password=x).
// code counts here: a form is how an OAuth authorization code is sent.
func maskForm(s string) string {
	parts := strings.Split(s, "&")
	for i, p := range parts {
		name, _, ok := strings.Cut(p, "=")
		if ok && secretName(formName(name)) {
			parts[i] = name + "=[redacted]"
		}
	}
	return strings.Join(parts, "&")
}

func formName(n string) string {
	if u, err := url.QueryUnescape(n); err == nil {
		return u
	}
	return n
}

// Values whose shape gives them away, wherever they appear (headers of any
// name, URLs, bodies, error messages): HTTP credentials, JWTs, and API keys
// with well-known prefixes.
var tokenREs = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`), // JWT
	regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})`),     // GitHub
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`),                                         // OpenAI, Anthropic, Stripe and others
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),                                  // Slack
	regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`),                                     // AWS access key ID
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),                                       // Google API key
}

func maskTokens(s string) string {
	for i, re := range tokenREs {
		if i == 0 {
			s = re.ReplaceAllString(s, "$1 [redacted]")
			continue
		}
		s = re.ReplaceAllString(s, "[redacted]")
	}
	return s
}
