package capture

import (
	"net/url"
	"strings"
	"testing"
)

// secretIn puts a secret under a secret name in one of the shapes masking
// knows, with filler (letters, digits, spaces, commas only: other text can
// change what the shape is) before it.
func secretIn(shape uint8, filler, secret string) (body, contentType string) {
	filler = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == ' ' || r == ',' {
			return r
		}
		return -1
	}, filler)
	switch shape % 8 {
	case 0:
		return `{"note":"` + filler + `","password":"` + secret + `"}`, "application/json"
	case 1:
		return `{"data":"{\"a\":\"` + filler + `\",\"access_token\":\"` + secret + `\"}"}`, "application/json"
	case 2:
		return "a=" + url.QueryEscape(filler) + "&client_secret=" + secret, "application/x-www-form-urlencoded"
	case 3:
		return `{"url":"https://x.example/cb?` + "q=" + url.QueryEscape(filler) + `&token=` + secret + `"}`, "application/json"
	case 4:
		inner := "https://x.example/cb?code=" + secret
		return `{"next":"https://y.example/?r=` + url.QueryEscape(url.QueryEscape(inner)) + `"}`, "application/json"
	case 5:
		return `{"query":"mutation { ` + filler + ` login(password: \"` + secret + `\") { ok } }"}`, "application/json"
	case 6:
		return "mutation { login(" + filler + " secret: \"" + secret + "\") { ok } }", "application/graphql"
	default:
		return `{"items":[1,2],"session":` + `"` + secret + `"}`, "application/json"
	}
}

// FuzzMaskBody: a secret in a known shape never survives masking, whatever
// comes before it and wherever the head is cut (a cut inside the value masks
// to the end). Seeds run with go test; go test -fuzz=FuzzMaskBody explores.
func FuzzMaskBody(f *testing.F) {
	for shape := range uint8(8) {
		f.Add(shape, "", 0)
		f.Add(shape, "some words, 42", 7)
		f.Add(shape, strings.Repeat("x", 65530), 65536) // the 64 KiB boundary
	}
	const secret = "S3cr3tV4lue9xQ"
	f.Fuzz(func(t *testing.T, shape uint8, filler string, cut int) {
		body, ct := secretIn(shape, filler, secret)
		head := []byte(body)
		if cut > 0 && cut < len(head) {
			head = head[:cut]
		}
		got := string(maskBody(head, ct, true))
		if strings.Contains(got, secret) {
			t.Errorf("shape %d: the secret survived:\n%s", shape%8, got[max(0, strings.Index(got, secret)-80):])
		}
	})
}
