package capture

import (
	"bytes"
	"cmp"
	"fmt"
	"math"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMaskingLinear: masking runs on Store.Apply's serial path, so an input
// that makes it superlinear stalls all recording (html.go's unbounded script
// comments took 7 s on 64 KiB; multipart's header unfolding allocated 412 MB
// for 80 KB). Each entry point gets inputs that repeat a short unit aimed at
// one of its regexps or loops, measured at two sizes 4x apart: linear grows
// about 4x, quadratic 16x, and more than 9x fails, in time (the least of three
// runs: noise only adds) or in bytes allocated (where copying is the risk:
// timing does not see it well). A ratio over 9 is measured once more
// before it fails. Each input must reach what it aims at: at the small size,
// its output holds what masking writes there (want), so an early return (no
// ':' for maskLines, no '=' for maskURLs, ...) does not pass for linear.
func TestMaskingLinear(t *testing.T) {
	path, _ := protoTestSchema(t)
	defer protoSchema.Store(nil)
	if _, err := LoadProtoSchema(path); err != nil {
		t.Fatal(err)
	}
	st := NewStore(100, 64<<20)
	body := func(ct string, request bool) func(string) string {
		return func(s string) string { return string(maskBody([]byte(s), ct, request)) }
	}
	json, form, text, none := body("application/json", true), body("application/x-www-form-urlencoded", true), body("text/plain", true), body("", true)
	html, js, xml, gql := body("text/html", false), body("application/javascript", false), body("text/xml", true), body("application/graphql", true)
	header := func(name string) func(string) string {
		return func(s string) string { return st.maskHeaders([][2]string{{name, s}})[0][1] }
	}
	mp := func(s string) string { return string(renderMultipart([]byte(s), "XyZ", true, false)) }
	proto := func(ct, path string) func(string) string {
		return func(s string) string { b, _ := renderProto([]byte(s), ct, path, true, false); return string(b) }
	}
	grpc := func(ct string) func(string) string {
		return func(s string) string {
			b, _, _, _ := st.grpcBody([]byte(s), ct, "/x", true, true, false)
			return string(b)
		}
	}
	ws := func(s string) string {
		h, note := st.wsHead(&event{Text: true, FromClient: true, Head: b64(s)})
		return h + note
	}
	n := 0
	apply := func(ct string) func(string) string {
		return func(s string) string {
			n++
			id := fmt.Sprint(n)
			st.Apply(line(t, map[string]any{"ev": "request", "id": id, "method": "POST", "host": "h", "url": "https://h/x?a=1", "path": "/x",
				"headers": [][2]string{{"Content-Type", ct}}}))
			st.Apply(line(t, map[string]any{"ev": "body", "id": id, "dir": "request", "head": b64(s), "size": len(s), "decoded": true, "final": true}))
			return string(st.flows[id].ReqBody.Head)
		}
	}
	// rep: pre, then unit repeated, then post, about n bytes in all.
	rep := func(pre, unit, post string) func(int) string {
		return func(n int) string { return pre + strings.Repeat(unit, max(1, (n-len(pre)-len(post))/len(unit))) + post }
	}
	// numbered: unit with %d, numbered from 0 (names that must differ).
	numbered := func(pre, unit, post string) func(int) string {
		return func(n int) string {
			var b strings.Builder
			b.WriteString(pre)
			for i := 0; b.Len() < n-len(post); i++ {
				fmt.Fprintf(&b, unit, i)
			}
			b.WriteString(post)
			return b.String()
		}
	}
	// pbFail: sub-messages nested depth deep that each read for a while, then
	// do not (a wire type protobuf does not have): each is tried, and fails.
	pbFail := func(depth int) []byte {
		b := append(bytes.Repeat(pbVarint(1, 1), 4), 0x07)
		for range depth {
			b = append(pbBytes(1, b), 0x07)
		}
		return b
	}
	pbNest := func(depth int, leaf []byte) []byte {
		for range depth {
			leaf = pbBytes(1, leaf)
		}
		return leaf
	}
	const (
		pw  = `"password":"S3cret1"`
		red = "redacted" // [redacted] or REDACTED, compared in lower case
		kb  = 1 << 10
	)
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlMTIz"
	mpPart := func(name, content string) string {
		return "--XyZ\r\nContent-Disposition: form-data; name=\"" + name + "\"\r\n\r\n" + content + "\r\n"
	}
	cases := []struct {
		name  string
		run   func(string) string
		build func(int) string
		want  string // in the small output, lower-cased
		size  int    // the small size; 16 KiB if 0 (see below)
	}{
		// JSON: maskJSON's scan, and what each string may be looked into for.
		{"json fields", json, rep(`{`, `"a":"b",`, pw+`}`), red, 0},
		{"json array strings", json, rep(`[`, `"a",`, `"Bearer abcdefgh123"]`), red, 0},
		{"json escaped keys and values", json, rep(`{`, `"\u0061":"\u0062\"",`, pw+`}`), red, 0},
		{"json backslashes", json, rep(`{"a":"`, `\\`, `",`+pw+`}`), red, 0},
		{"json in strings", json, rep(`{`, `"a":"{\"b\":\"\u0063\"}",`, pw+`}`), red, 0},
		{"json in a string, nested", json, rep(`{"a":"`, `{\"b\":`, `{\"password\":\"S3cret1\"}"}`), red, 0},
		{"json nested objects", json, rep(``, `{"a":`, `{`+pw+`}`), red, 0},
		{"json nested arrays", json, rep(``, `[`, `"Bearer abcdefgh123"`), red, 0},
		{"json secret containers", json, rep(`{`, `"password":[1],`, `"a":1}`), red, 0},
		{"json secret container cut", json, rep(`{"password":`, `[`, `1`), red, 0},
		{"json attribute keys", json, rep(`{`, `"key":"a.b","value":1,`, pw+`}`), red, 0},
		{"json attribute keys, spaces", json, rep(`{`, `"key":"a.b"            ,`, pw+`}`), red, 0},
		{"json graphql strings", json, rep(`{`, `"q":"{a(b:1)}",`, `"q":"{a(password:\"x\")}"}`), red, 0},
		{"json graphql by an escape", json, rep(`{`, `"q":"\u0071uery{a}",`, `"q":"\u0071uery{a(password:1)}"}`), red, 0},
		{"json secret numbers", json, rep(`{`, `"otp":123,`, `"a":1}`), red, 0},
		{"json urls", json, rep(`{`, `"u":"https://h/?a=1&b=2",`, `"u":"https://h/?token=x"}`), red, 0},
		{"json cut string, escapes", json, rep(`{"a":"`, `\u0061\"`, ` Bearer abcdefgh123`), red, 0},
		{"json cut string, raw newlines", json, rep(`{"a":"`, "\\u0061\n", ` Bearer abcdefgh123`), red, 0},
		{"json cut key", json, rep(`{"a":1,"`, `\"`, ``), "", 0},
		{"json unclosed quotes", json, rep(``, `"`, ``), "", 0},
		{"json colons", json, rep(`{`, `"a":`, pw), red, 0},
		// Forms: each field, and what it may hold.
		{"form fields", form, rep(``, `a=1&`, `password=x`), red, 0},
		{"form json fields", form, rep(``, `a=%7B%22b%22%3A1%7D&`, `password=x`), red, 0},
		{"form base64 json", form, rep(``, `a=eyJhIjoxfQ&`, `password=x`), red, 0},
		{"form graphql", form, rep(``, `a={b(c:1)}&`, `q={a(password:1)}`), red, 0},
		{"form nested url, first field", form, rep(`next=`, `https%3A%2F%2Fh%2F%3Fa%3D1%26`, `token%3Dx`), red, 0},
		{"form encoded twice", form, rep(`next=`, `%253Fa%253D1`, `%2526token%253Dx`), red, 32 * kb},
		{"form semicolons", form, rep(`a=1`, `;a=1`, `;token=x`), red, 0},
		{"form tokens", form, rep(``, `a=Bearer+abcdefgh&`, `b=Bearer+abcdefgh123`), red, 0},
		{"form, no type", none, rep(``, `a=1&`, `password=x`), red, 0},
		// Text: lines, shapes, URLs.
		{"lines", text, rep(``, "a: b\n", "password: x\n"), red, 0},
		{"lines, CR only", text, rep(``, "a: b\r", "\npassword: x"), red, 0},
		{"lines, long names", text, rep(``, strings.Repeat("a", 72)+":b\n", "password: x"), red, 0},
		{"lines, export", text, rep(``, "export a=b\n", "export API_KEY=x"), red, 0},
		{"lines, blanks", text, rep(``, " \t \t \t \t:\n", "password: x"), red, 0},
		{"lines, no type", none, rep(``, "a:1\n", "password: x"), red, 0},
		{"schemes", text, rep(``, "Bearer ", "Bearer abcdefgh123"), red, 0},
		{"schemes, words", text, rep(``, "bearer abcdefgh ", "Bearer abcdefgh123"), red, 0},
		{"schemes, spaces", text, rep(`token`, " ", "abcdefgh123"), red, 0},
		{"jwt near misses", text, rep(``, "eyJ-", " "+jwt), red, 0},
		{"jwt runs", text, rep(``, "eyJaaaaaa.", " "+jwt), red, 0},
		{"key near misses", text, rep(``, "sk-a ", " sk-"+strings.Repeat("A1", 12)), red, 0},
		{"key runs", text, rep(``, "sk-", ""), red, 0},
		{"github near misses", text, rep(``, "ghp_"+strings.Repeat("a", 29)+" ", "ghp_"+strings.Repeat("a", 36)), red, 0},
		{"query near misses", text, rep(``, "?a", "&token=x"), red, 0},
		{"query empty values", text, rep(``, "?a=", "&token=x"), red, 0},
		{"query gson escapes", text, rep(``, `\u0026a\u003d1`, `\u0026token\u003dx`), red, 0},
		{"query fragments", text, rep(``, "#a=1", "#token=x"), red, 0},
		{"query semicolons", text, rep(`x?q=1`, ";a=1", ";token=x"), red, 0},
		{"query nested", text, rep(`?r=`, `https%3A%2F%2Fh%2F%3Fa%3D`, `1%26token%3Dx`), red, 0},
		{"userinfo near misses", text, rep(``, "a://b:", " https://u:pw@h/"), red, 0},
		{"userinfo escaped", text, rep(``, `http:\/\/a:b`, ` https://u:pw@h/`), red, 0},
		{"userinfo many", text, rep(``, "a://b:c@ ", ""), red, 0},
		// GraphQL documents: the lexer, and the values it masks.
		{"graphql nested", gql, rep(`query { `, `a(b: 1) { `, `login(password: "x")`), red, 0},
		{"graphql many arguments", gql, rep(`mutation { `, `a(password: "x") `, `}`), red, 0},
		{"graphql nested lists", gql, rep(`mutation { a(password: `, `[`, `1`), red, 0},
		{"graphql comments", gql, rep(`query { a `, "# c\n", `login(password: "x") }`), red, 0},
		{"graphql block strings", gql, rep(`query { `, `a(b: """x""") `, `login(password: "x") }`), red, 0},
		{"graphql block string cut", gql, rep(`mutation { a(password: """`, `\"""`, ``), red, 0},
		{"graphql defaults", gql, rep(`query Q(`, `$password: String = "x" `, `) { a }`), red, 0},
		{"graphql in json, nested", json, rep(`{"query":"query { `, `a(b: 1) { `, `login(password: \"x\")"}`), red, 0},
		{"graphql in json, many", json, rep(`[`, `{"query":"{a(password:\"x\")}"},`, `{}]`), red, 0},
		{"graphql in json, raw newlines", json, rep(`{"query":"query { `, "a(b: 1)\n", `login(password: \"x\") }"}`), red, 0},
		{"graphql in json, cut", json, rep(`{"query":"query { a(b: \"`, `\\\"`, ``), "", 0},
		// HTML: tags, comments and raw text.
		{"html comment cut", html, rep(``, `<!--`, `<input name="csrf" value="x">`), red, 0},
		{"html comment dashes", html, rep(`<!-- `, `-- `, `--><input name="csrf" value="x">`), red, 0},
		{"html comments", html, rep(``, `<!---->`, `<input name="csrf" value="x">`), red, 0},
		{"html scripts cut", html, rep(``, `<script>`, `<input name="csrf" value="x">`), red, 0},
		{"html script end near misses", html, rep(`<script>`, `</scrip`, `</script><input name="csrf" value="x">`), red, 0},
		{"html scripts", html, rep(``, `<script>a</script>`, `<input name="csrf" value="x">`), red, 0},
		{"html titles cut", html, rep(``, `<title>`, `<input name="csrf" value="x">`), red, 0},
		{"html quotes cut", html, rep(``, `<a b="`, ``), "", 0},
		{"html attributes", html, rep(`<input `, `a=1 `, `name="csrf" value="x">`), red, 0},
		{"html bare attributes", html, rep(`<input `, `hidden `, `name="csrf" value="x">`), red, 0},
		{"html equals", html, rep(`<a `, `= `, `><input name="csrf" value="x">`), red, 0},
		{"html fields", html, rep(``, `<input type="hidden" name="code" value="x">`, ``), red, 0},
		{"html textareas", html, rep(``, `<textarea name="password">`, ``), red, 0},
		{"html text", html, rep(``, `a < b `, `<input name="csrf" value="x">`), red, 0},
		{"html tags cut", html, rep(``, `<a`, ``), "", 0},
		{"html script fields", html, rep(`<script>`, `{a:"x",`, `accessToken:"y"}</script>`), red, 0},
		// Scripts' objects; the comment units are #84's review's (7 s on 64 KiB before jsGap's bound).
		{"js fields", js, rep(``, `{a:"x",`, `accessToken:"y"}`), red, 0},
		{"js template literal cut", js, rep(``, "{token:`", ""), red, 0},
		{"js strings to the line's end", js, rep(``, "{a:\",b:1\n", ",pin:1234"), red, 0},
		{"js escapes", js, rep(`{token:"`, `\"`, `"}`), red, 0},
		{"js numbers", js, rep(``, `{pin:1,`, ``), red, 0},
		{"js long names", js, rep(`{`, `a`, `:1,token:"x"}`), red, 0},
		{"js block comment cut", js, rep(``, "{/*x,a:1", ",pin:1234"), red, 0},
		{"js line comment cut", js, rep(``, "{//x,a:1", "\n,pin:1234"), red, 0},
		{"js comment as value", js, rep(``, "{a:/*,b:1", ",pin:1234"), red, 0},
		{"js comments open", js, rep(``, "/*,/*,a:1*/", ",pin:1234"), red, 0},
		{"js comments in html", html, rep(`<script>`, "{/*x,a:1", ",pin:1234"), red, 0},
		{"js comments in html, line", html, rep(`<script>`, "{//x,a:1", "\n,pin:1234"), red, 0},
		// XML: the decoder, its restarts, and what the masking keeps.
		{"xml nested", xml, rep(``, `<a>`, `<Password>x</Password>`), red, 0},
		{"xml secret nested", xml, rep(``, `<Password>`, ``), red, 0},
		{"xml attributes", xml, rep(`<a `, `b="1" `, `password="x"/>`), red, 0},
		{"xml elements", xml, rep(``, `<a password="x"/>`, ``), red, 0},
		{"xml refused tags", xml, rep(``, `<a b=c!d>`, `<Password>x</Password>`), red, 0},
		{"xml restarts", xml, rep(``, `<1`, `<Password>x</Password>`), red, 0},
		{"xml refused tags, quoted", xml, rep(``, `<a b="<x>" c=d!e>`, `<Password>x</Password>`), red, 0},
		{"xml bad comments", xml, rep(``, `<!-- -- -->`, `<Password>x</Password>`), red, 0},
		{"xml plist key text", xml, rep(`<plist><dict><key>`, `    <b/>`, `token</key><string>x</string></dict></plist>`), red, 0},
		{"xml plist key comments", xml, rep(`<plist><dict><key>`, ` <!---->`, `token</key><string>x</string></dict></plist>`), red, 0},
		{"xml cdata cut", xml, rep(`<Password>`, `<![CDATA[`, ``), red, 0},
		{"xml entities", xml, rep(`<a>`, `&amp;&x;`, `</a><Password>x</Password>`), red, 0},
		{"xml namespaces", xml, rep(``, `<a xmlns:b="c">`, `<b:Password>x</b:Password>`), red, 0},
		{"xml instructions", xml, rep(``, `<?a ?>`, `<Password>x</Password>`), red, 0},
		// Multipart: parts, delimiters, headers.
		{"multipart parts", mp, rep(``, mpPart("a"+strings.Repeat("b", 240), "x"), mpPart("password", "x")+"--XyZ--"), red, 0},
		{"multipart delimiter near misses", mp, rep(`--XyZ`+"\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n", "\r\n--XyZa", "\r\n--XyZ--"), red, 0},
		{"multipart delimiter spaces", mp, rep(`--XyZ`+"\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n\r\n--XyZ", " ", "x\r\n--XyZ--"), red, 0},
		{"multipart folds", mp, rep("--XyZ\r\nContent-Disposition: form-data; name=\"x\"", "\r\n a", "\r\nX-Api-Key: x\r\n\r\nplain\r\n--XyZ--"), red, 0},
		{"multipart header lines", mp, rep("--XyZ\r\nContent-Disposition: form-data; name=\"x\"\r\n", "X-A: b\r\n", "X-Api-Key: x\r\n\r\nplain\r\n--XyZ--"), red, 0},
		{"multipart disposition parameters", mp, numbered("--XyZ\r\nContent-Disposition: form-data; name=\"x\"", "; p%d=1", "\r\nX-Api-Key: x\r\n\r\nplain\r\n--XyZ--"), red, 0},
		{"multipart continuations", mp, numbered("--XyZ\r\nContent-Disposition: form-data; name=\"x\"", "; f*%d=a", "\r\nX-Api-Key: x\r\n\r\nplain\r\n--XyZ--"), red, 0},
		{"multipart text part", mp, rep("--XyZ\r\nContent-Disposition: form-data; name=\"x\"\r\nContent-Type: application/json\r\n\r\n{", `"a":"b",`, pw+"}\r\n--XyZ--"), red, 0},
		// Protobuf: the structure walk and its trials; --proto's JSON, masked.
		{"protobuf varints", proto("application/x-protobuf", "/x"), rep(``, string(pbVarint(1, 1)), ``), "1: 1", kb},
		{"protobuf nested", proto("application/x-protobuf", "/x"), rep(``, string(pbNest(3, pbVarint(1, 300))), ``), "1 {", kb},
		{"protobuf failing trials", proto("application/x-protobuf", "/x"), rep(``, string(pbBytes(1, pbFail(8))), ``), "bytes(", kb},
		{"protobuf schema strings", proto("application/x-protobuf", "/t.S/Do"), rep(``, string(pbBytes(6, []byte{0x80})), string(pbBytes(2, []byte("S3cret1")))), "[redacted]", 2 * kb},
		{"protobuf schema map", proto("application/x-protobuf", "/t.S/Do"), rep(``, string(pbBytes(7, append(pbBytes(1, []byte("authorization")), pbBytes(2, []byte("x"))...))), ``), "[redacted]", 2 * kb},
		{"protobuf schema nested", proto("application/x-protobuf", "/t.S/Do"), rep(``, string(pbBytes(5, append(pbBytes(1, []byte("x")), 0x10, 0x01))), string(pbBytes(2, []byte("S3cret1")))), "[redacted]", 2 * kb},
		{"protobuf schema unknown", proto("application/x-protobuf", "/t.S/Do"), rep(``, string(pbNest(3, pbVarint(1, 300))), string(pbBytes(2, []byte("S3cret1")))), "[redacted]", 2 * kb},
		{"grpc frames", grpc("application/grpc"), rep(``, "\x00\x00\x00\x00\x04\x08\x01\x10\x02", ``), "1: 1", 4 * kb},
		{"grpc json frames", grpc("application/grpc+json"), rep(``, "\x00\x00\x00\x00\x09{\"a\":\"b\"}", "\x00\x00\x00\x00\x14{\"password\":\"x1234\"}"), red, 0},
		// The GraphQL operation's name, worked out in Apply too.
		{"graphql operation, batched", func(s string) string { return gqlBodyOperation([]byte(s)) }, rep(`[`, `{"query":"{a}"},`, `{"query":"{a}"}]`), "(batched)", 0},
		{"graphql operation, cut", func(s string) string { return gqlBodyOperation([]byte(s)) }, rep(`{"variables":`, `{"a":`, ``), "", 0},
		{"graphql operation, url", func(s string) string { return gqlURLOperation(s) }, rep(`https://h/g?query=`, url.QueryEscape(`{ a(b: 1) `), ``), "(anonymous)", 64 * kb},
		// Headers (up to 256 KiB a message): each kind of value.
		{"cookies", header("Cookie"), rep(``, `a=1; `, `sid=x`), red, 64 * kb},
		{"set-cookie joins", header("Set-Cookie"), rep(``, `,a=`, ``), red, 64 * kb},
		{"set-cookie dates", header("Set-Cookie"), rep(``, `a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/, `, ``), red, 64 * kb},
		{"websocket protocols", header("Sec-WebSocket-Protocol"), rep(``, `access_token, x, `, ``), red, 64 * kb},
		{"websocket protocols, base64", header("Sec-WebSocket-Protocol"), rep(``, `header-eyJhIjoxfQ, `, `header-`+b64(`{"token":"x"}`)), red, 64 * kb},
		{"header urls", header("Referer"), rep(`https://h/`, `?a`, `&token=x`), red, 64 * kb},
		{"header schemes", header("X-A"), rep(``, `Bearer `, `Bearer abcdefgh123`), red, 64 * kb},
		{"header challenge", header("WWW-Authenticate"), rep(``, `Bearer realm="x", `, jwt), red, 64 * kb},
		{"grpc-message", header("grpc-message"), rep(``, `%41`, `%20Bearer%20abcdefgh123`), "", 64 * kb},
		{"many headers", func(s string) string {
			var h [][2]string
			for _, l := range strings.Split(s, "\n") {
				k, v, _ := strings.Cut(l, ":")
				h = append(h, [2]string{k, v})
			}
			return fmt.Sprint(st.maskHeaders(h))
		}, rep(``, "Cookie:a=1\nX-Api-Key:x\nX-A:b\n", ""), red, 64 * kb},
		// URLs.
		{"url parameters", st.mask, rep(`https://h/?`, `a=1&`, `token=x`), red, 64 * kb},
		{"url nested", st.mask, rep(`https://h/?r=`, `https%3A%2F%2Fh%2F%3Fa%3D1%26`, `token%3Dx`), red, 64 * kb},
		{"url semicolons", st.mask, rep(`https://h/?q=1`, `;a=1`, `;token=x`), red, 64 * kb},
		{"url userinfo", st.mask, rep(``, `a://b:c@`, ``), red, 64 * kb},
		// WebSocket messages (a head is 4 KiB: larger ones measure growth only).
		{"websocket signalr records", ws, rep(``, "{\"a\":\"b\"}\x1e", "{"+pw+"}\x1e"), red, 0},
		{"websocket auth event", ws, rep(`42["authenticate",`, `"a",`, `"b"]`), red, 0},
		{"websocket signalr auth", ws, rep(`{"type":1,"target":"auth","arguments":[`, `"a",`, `"b"]}`), red, 0},
		{"websocket stomp", ws, rep("CONNECT\n", "a:b\n", "passcode:x\n\n\x00"), red, 0},
		// Error text (the addon cuts it at 1 KiB: larger ones measure growth only).
		{"error bytes cut", st.maskError, rep(`Invalid header: b'`, `x`, ``), red, 0},
		{"error bytes", st.maskError, rep(``, ` b'x'`, ``), red, 0},
		{"error bytes, a quote open", st.maskError, rep(` b"`, ` b'x'`, "\\\n"), red, 0},
		{"error urls", st.maskError, rep(`https://h/?`, `a=1&`, `token=x`), red, 0},
		// The whole of Apply: maskEvent and maskHead around the masking.
		{"apply json", apply("application/json"), rep(`{`, `"a":"b",`, pw+`}`), red, 0},
		{"apply html", apply("text/html"), rep(``, `<input type="hidden" name="code" value="x">`, ``), red, 0},
		{"apply multipart", apply("multipart/form-data; boundary=XyZ"), rep(``, mpPart("a"+strings.Repeat("b", 240), "x"), mpPart("password", "x")+"--XyZ--"), red, 0},
		{"apply graphql", apply("application/json"), rep(`[`, `{"query":"{a(password:\"x\")}"},`, `{}]`), red, 0},
	}
	// The race detector makes both measures wrong (sync.Pool drops what it is
	// given back, so a regexp's state is made again at the input's size, and
	// all of it runs 20 to 30 times slower): there, only the inputs that caught
	// a regression run, once each and at half the size. Without it (CI's E2E
	// job), all of them.
	underRace := map[string]bool{"js block comment cut": true, "js line comment cut": true, "js comment as value": true, "js comments open": true,
		"js comments in html": true, "js comments in html, line": true, "multipart folds": true, "xml plist key text": true}
	runs := 3
	if slow > 1 {
		runs = 1
	}
	measure := func(run func(string) string, s string, loops int) (time.Duration, uint64) {
		d, a := time.Duration(math.MaxInt64), uint64(math.MaxUint64)
		for range runs {
			var m0, m1 runtime.MemStats
			runtime.ReadMemStats(&m0)
			start := time.Now()
			for range loops {
				run(s)
			}
			took := time.Since(start)
			runtime.ReadMemStats(&m1)
			d, a = min(d, took), min(a, m1.TotalAlloc-m0.TotalAlloc)
		}
		return d, a
	}
	// Sizes: below 256 KiB / its program's length, a regexp runs on Go's
	// quicker backtracker, so an input (or the text it decodes to) that crosses
	// that line between the sizes grows by more than its size: 16 KiB clears it
	// for every regexp here, 32 KiB for text decoded to a third.
	for _, c := range cases {
		if slow > 1 && !underRace[c.name] {
			continue
		}
		size := cmp.Or(c.size, 16*kb)
		if slow > 1 {
			size /= 2
		}
		small, large := c.build(size), c.build(4*size)
		start := time.Now()
		if got := strings.ToLower(c.run(small)); c.want != "" && !strings.Contains(got, c.want) { // and a warm-up
			t.Errorf("%s: does not reach what it aims at (%q not in the output): %.300q", c.name, c.want, got)
			continue
		}
		loops := min(1000, max(1, int(time.Millisecond/max(time.Since(start), 1)))) // what is quicker than 1 ms runs until it takes that
		for try := 1; ; try++ {
			ts, as := measure(c.run, small, loops)
			tl, al := measure(c.run, large, loops)
			slowTime, copies := tl > 9*ts+50*time.Microsecond, al > 9*as+64*kb // the slack: what is too small to count
			t.Logf("%-40s time x%.1f (%v), allocated x%.1f (%d KiB)", c.name, float64(tl)/float64(ts), tl/time.Duration(loops), float64(al)/float64(max(as, 1)), al/uint64(loops)/kb)
			if !slowTime && !copies {
				break
			}
			if try == 2 {
				t.Errorf("%s: %d KiB took %v and allocated %d KiB, %d KiB %v and %d KiB: grows faster than the size",
					c.name, len(small)/kb, ts/time.Duration(loops), as/uint64(loops)/kb, len(large)/kb, tl/time.Duration(loops), al/uint64(loops)/kb)
				break
			}
		}
	}
}
