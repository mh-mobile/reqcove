package capture

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMaskXML: elements and attributes by their local names, as JSON's keys.
func TestMaskXML(t *testing.T) {
	const soap = `<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="urn:wsse"><soap:Header><wsse:Security><wsse:Password Type="urn:x#PasswordText">S3CRET-4</wsse:Password></wsse:Security></soap:Header><soap:Body><m:GetPrice xmlns:m="urn:m"><m:Item>Apples</m:Item></m:GetPrice></soap:Body></soap:Envelope>`
	for _, c := range []struct {
		name, ctype, in string
		request         bool
		gone, keep      []string
	}{
		{"element text", "text/xml", `<Login><User>alice</User><Password>S3CRET-1</Password></Login>`, false,
			[]string{"S3CRET-1"}, []string{"<User>alice</User>", "<Password>[redacted]</Password>"}},
		{"attributes", "application/xml", `<Login user="alice" password="S3CRET-2" apiKey='S3CRET-3' empty=""/>`, false,
			[]string{"S3CRET-2", "S3CRET-3"}, []string{`user="alice"`, `password="[redacted]"`, `apiKey='[redacted]'`, `empty=""/>`}},
		{"namespaced (SOAP)", "application/soap+xml; charset=utf-8", soap, true,
			[]string{"S3CRET-4"}, []string{`<wsse:Password Type="urn:x#PasswordText">[redacted]</wsse:Password>`, "<m:Item>Apples</m:Item>", `xmlns:wsse="urn:wsse"`}},
		{"CDATA", "text/xml", `<a><Token><![CDATA[S3CRET-5]]></Token><b><![CDATA[kept]]></b></a>`, false,
			[]string{"S3CRET-5"}, []string{"<Token>[redacted]</Token>", "<b><![CDATA[kept]]></b>"}},
		{"a secret element masked whole", "text/xml", `<a><Credentials><Inner>S3CRET-6</Inner><Password>S3CRET-7</Password></Credentials><b>x</b></a>`, false,
			[]string{"S3CRET-6", "S3CRET-7"}, []string{"<Credentials>[redacted]</Credentials><b>x</b>"}},
		{"comments and processing instructions", "text/xml", `<a><!-- <Password> --><User>u</User><Password><!-- </Password> -->S3CRET-8<?pi x?></Password><b>x</b></a>`, false,
			[]string{"S3CRET-8"}, []string{"<!-- <Password> --><User>u</User><Password>[redacted]</Password><b>x</b>"}},
		{"JSON's case rule", "text/xml", `<r><PASSWORD>S3CRET-9</PASSWORD><accessToken>S3CRET-10</accessToken><Token_Type>Bearer</Token_Type><error_code>E1</error_code><code>E2</code></r>`, false,
			[]string{"S3CRET-9", "S3CRET-10"}, []string{"<Token_Type>Bearer</Token_Type>", "<error_code>E1</error_code>", "<code>E2</code>"}},
		{"a lone code in a request", "text/xml", `<r><code>S3CRET-11</code></r>`, true, []string{"S3CRET-11"}, nil},
		{"an undeclared entity does not stop it", "text/xml", `<a>&nbsp;&custom;</a><Password>S3CRET-17</Password>`, false,
			[]string{"S3CRET-17"}, []string{"<a>&nbsp;&custom;</a>"}},
		{"another encoding declared, ASCII sent", "text/xml", `<?xml version="1.0" encoding="ISO-8859-1"?><Password>S3CRET-16</Password>`, false,
			[]string{"S3CRET-16"}, nil},
		{"cut inside a secret element", "text/xml", `<a><b>x</b><Password>S3CRET-18abc`, false, []string{"S3CRET-18"}, []string{"<b>x</b><Password>[redacted]"}},
		{"cut inside its CDATA", "text/xml", `<a><Password><![CDATA[S3CRET-25`, false, []string{"S3CRET-25"}, nil},
		{"cut inside an attribute", "text/xml", `<a><b>x</b><c id="1" password="S3CRET-19`, false, []string{"S3CRET-19"}, []string{`<c id="1" password="[redacted]`}},
		{"broken inside a secret element", "text/xml", `<Password>S3CRET-13 < oops</Password><User>u</User>`, false, []string{"S3CRET-13"}, nil},
		{"broken: the text masking still applies", "text/xml", `<a><b>1 < 2</b>Bearer S3CRET12abcdefgh</a>`, false, []string{"S3CRET12"}, []string{"<b>1 < 2</b>"}},
		{"broken in a tag: only that tag's values", "text/xml", `<a><b c="1" <d>a key="x</d><e>kept</e></a>`, false, nil, []string{"<e>kept</e>"}},
		{"SAML Assertion", "text/xml", `<samlp:Response><saml:Assertion ID="a1"><saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion><saml2:EncryptedAssertion><x>S3CRET-26</x></saml2:EncryptedAssertion><samlp:Status>ok</samlp:Status></samlp:Response>`, false,
			[]string{"alice", "S3CRET-26"}, []string{`<saml:Assertion ID="a1">[redacted]</saml:Assertion>`, "<samlp:Status>ok</samlp:Status>"}},
		{"plist: the value after a secret key", "application/xml", `<plist><dict><key>access_token</key><string>S3CRET-14</string><key>name</key><string>Bob</string></dict></plist>`, false,
			[]string{"S3CRET-14"}, []string{"<key>access_token</key><string>[redacted]</string>", "<key>name</key><string>Bob</string>"}},
		{"S3's Key is a key, as in JSON", "application/xml", `<Contents><Key>photos/a.jpg</Key><Size>3</Size></Contents>`, false,
			[]string{"photos/a.jpg"}, []string{"<Size>3</Size>"}},
		{"namespace declarations stay", "text/xml", `<a xmlns:token="urn:x:token"><token:b>x</token:b></a>`, false,
			nil, []string{`<a xmlns:token="urn:x:token"><token:b>x</token:b></a>`}},
		{"a body with an XML declaration, whatever its type", "text/plain", `<?xml version="1.0"?><Password>S3CRET-15</Password>`, false, []string{"S3CRET-15"}, nil},
	} {
		got := string(maskBody([]byte(c.in), c.ctype, c.request))
		for _, g := range c.gone {
			if strings.Contains(got, g) {
				t.Errorf("%s: %q survived: %s", c.name, g, got)
			}
		}
		for _, k := range c.keep {
			if !strings.Contains(got, k) {
				t.Errorf("%s: %q was lost: %s", c.name, k, got)
			}
		}
	}
	// Left as they came, byte for byte: a self-closing secret element, and XML
	// with no secret (prefixes, entities, quotes, spacing).
	for _, in := range []string{
		`<a><Password/><b>x</b></a>`,
		`<?xml version="1.0"?><s:E xmlns:s="urn:s" a = 'q"' ><s:B>&amp;&#65;<![CDATA[<x>]]></s:B><!-- c --></s:E>`,
	} {
		if got := string(maskBody([]byte(in), "text/xml", true)); got != in {
			t.Errorf("changed:\n%s\n%s", in, got)
		}
	}
	// What masked XML before still does, by the text masking.
	for _, in := range []string{
		`<Header>Bearer S3CRET20abcdefgh</Header>`,
		`<Url>https://x.example/cb?access_token=S3CRET-21</Url>`,
		`<Data>eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.S3CRET22sig</Data>`,
		"<Note>\npassword: S3CRET-23\n</Note>",
		`<a href="https://x.example/?token=S3CRET-24">x</a>`,
		`<a>{"password":"S3CRET-27"}</a>`,
	} {
		for _, ct := range []string{"text/xml", "text/plain"} {
			if got := string(maskBody([]byte(in), ct, false)); strings.Contains(got, "S3CRET") {
				t.Errorf("%s: %s", ct, got)
			}
		}
	}
	// Not read as XML (SECURITY says so): XML as an element's text, escaped or
	// in CDATA; a WebSocket message (no content type) without a declaration.
	for in, ct := range map[string]string{
		`<req>&lt;Password&gt;Sx1&lt;/Password&gt;</req>`:           "text/xml",
		`<req><![CDATA[<Password>Sx1</Password>]]></req>`:           "text/xml",
		`<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>Sx1</auth>`: "",
	} {
		if got := string(maskBody([]byte(in), ct, true)); got != in {
			t.Errorf("SECURITY says this passes: %s", got)
		}
	}
	// Not decoded: SAML's POST binding, a base64 form field (SECURITY says so).
	saml := "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("<saml:Assertion>x</saml:Assertion>")))
	if got := string(maskBody([]byte(saml), "application/x-www-form-urlencoded", true)); got != saml {
		t.Errorf("SAMLResponse: SECURITY says it passes: %s", got)
	}
	for ct, want := range map[string]bool{"text/xml; charset=utf-8": true, "application/soap+xml": true, "application/atom+xml": true, "Application/XML": true, "text/html": false, "application/json": false} {
		if isXML(ct, "<a/>") != want {
			t.Errorf("isXML(%q) = %v", ct, !want)
		}
	}
}

// TestMaskXMLCut: a SOAP head cut anywhere shows no 5 characters of the
// secret, in an element or an attribute.
func TestMaskXMLCut(t *testing.T) {
	S := fuzzSecret
	body := `<soap:Envelope xmlns:soap="urn:s"><soap:Body><m:Login m:pin="` + S + `" user="u"><m:Password><![CDATA[` + S + `]]></m:Password></m:Login></soap:Body></soap:Envelope>`
	for cut := 0; cut <= len(body); cut++ {
		if got := string(maskBody([]byte(body[:cut]), "application/soap+xml", true)); leak(got, S) != "" {
			t.Fatalf("cut at %d: %s", cut, got)
		}
	}
}

// TestMaskXMLEntities: a DTD is not read: no entity expanded (billion laughs),
// none fetched; time and memory stay bounded.
func TestMaskXMLEntities(t *testing.T) {
	var dtd strings.Builder
	dtd.WriteString(`<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY xxe SYSTEM "file:///etc/passwd">`)
	for i := 1; i <= 9; i++ {
		dtd.WriteString(fmt.Sprintf(`<!ENTITY lol%d "%s">`, i, strings.Repeat(fmt.Sprintf("&lol%d;", i-1), 10)))
	}
	in := strings.Replace(dtd.String(), "&lol0;", "&lol;", -1) + `]><lolz><Password>&lol9;</Password><v>&lol9;&xxe;</v></lolz>`
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	got := string(maskBody([]byte(in), "text/xml", false))
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	if strings.Contains(got, "lollol") || strings.Contains(got, "root:") || !strings.Contains(got, "<Password>[redacted]</Password><v>&lol9;&xxe;</v>") {
		t.Errorf("expanded or not masked: %s", got)
	}
	// About 0.1 ms and 15 KB on an M-series Mac (3 ms under -race).
	if alloc := after.TotalAlloc - before.TotalAlloc; elapsed > time.Second || alloc > 8<<20 {
		t.Errorf("%v, %d bytes", elapsed, alloc)
	}
}

// TestXMLStore: handed out, searched and compared masked; a head not in
// UTF-8 is not handed out at all.
func TestXMLStore(t *testing.T) {
	s := NewStore(10, 1<<20)
	add := func(id, ct, body string) {
		s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"request","id":%q,"method":"POST","url":"https://soap.example/s","host":"soap.example","path":"/s","headers":[["Content-Type",%q]]}`, id, ct)))
		s.Apply([]byte(fmt.Sprintf(`{"v":2,"ev":"body","id":%q,"dir":"request","decoded":true,"final":true,"size":%d,"head":%q}`, id, len(body), base64.StdEncoding.EncodeToString([]byte(body)))))
	}
	add("a", "application/soap+xml", `<Envelope><Body><Password>S3CRET-A1</Password></Body></Envelope>`)
	add("b", "application/soap+xml", `<Envelope><Body><Password>S3CRET-B2</Password></Body></Envelope>`)
	add("c", "text/xml; charset=ISO-8859-1", "<Envelope><Name>Jos\xe9</Name><Password>S3CRET-C3</Password></Envelope>")
	utf16 := []byte{0xff, 0xfe}
	for _, r := range "<Password>S3CRET-D4</Password>" {
		utf16 = append(utf16, byte(r), 0)
	}
	add("d", "text/xml; charset=UTF-16", string(utf16))
	if v, _ := s.Get("a", true); strings.Contains(v.ReqBodyText, "S3CRET") || !strings.Contains(v.ReqBodyText, "<Password>[redacted]</Password>") {
		t.Errorf("a: %q", v.ReqBodyText)
	}
	for _, id := range []string{"c", "d"} { // Latin-1, UTF-16
		if v, _ := s.Get(id, true); v.ReqBodyText != "" || v.ReqBodyEnc != omittedBody {
			t.Errorf("%s: %q %q", id, v.ReqBodyText, v.ReqBodyEnc)
		}
	}
	if rows, _ := s.List(Filter{Query: "S3CRET", QueryBodies: true, Limit: 5}); len(rows) != 0 {
		t.Errorf("a secret found by search: %d", len(rows))
	}
	if d, _ := s.DiffFlows("a", "b"); d.RequestBody.Result != "masked" {
		t.Errorf("diff: %+v", d.RequestBody)
	}
}

// TestXMLE2E (REQCOVE_E2E=1): a SOAP request through mitmproxy: its
// password never reaches the record.
func TestXMLE2E(t *testing.T) {
	if os.Getenv("REQCOVE_E2E") == "" {
		t.Skip("set REQCOVE_E2E=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body) }))
	defer srv.Close()
	h := startHarness(t, ctx, []string{"127.0.0.1"})
	body := `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><soap:Header><wsse:Security><wsse:Password>XMLe2eSecret01</wsse:Password></wsse:Security></soap:Header><soap:Body><GetPrice><Item>Apples</Item></GetPrice></soap:Body></soap:Envelope>`
	resp, err := h.client("xml-device").Post(srv.URL+"/soap", "application/soap+xml; charset=utf-8", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var v FlowView
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if f, ok := h.findFlow("/soap", true); ok && f.ReqBody.Final {
			v = f
			break
		}
	}
	if strings.Contains(v.ReqBodyText, "XMLe2eSecret01") || !strings.Contains(v.ReqBodyText, "<wsse:Password>[redacted]</wsse:Password>") || !strings.Contains(v.ReqBodyText, "<Item>Apples</Item>") {
		t.Errorf("SOAP: %s", v.ReqBodyText)
	}
}
