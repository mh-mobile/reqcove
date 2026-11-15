# What Reqcove masks, and what it does not

[日本語](masking.ja.md)

[SECURITY.md](SECURITY.md#masking) says what masking is for. This page is the
detail, for checking whether what your app sends is covered: the names and
shapes that count as secrets, how each kind of body is read, what a record
keeps, and which connections leave no record. It describes v1.0.

Secrets are masked as they arrive, so no tool can return them. `--no-redact`
turns masking off.

A point that was not tried, or that comes from reading code, says so where it
stands. What tests and trials covered is in the "Checked:" line that ends a
section. Tried with mitmproxy 12.3.1 and an iPhone on iOS 27.3, unless a line
names something else.

## Names that count as secret

A header, a query parameter or a body field is secret by its name. A name is
split into words at punctuation and case changes, so `apiKey`, `XAuth` and
`X-Amz-Signature` count, while `author` and `keyword` do not.

| A name is secret when it | Words |
|---|---|
| contains one of these, even run together (`accesstoken`, `X-AuthToken`) | token, secret, password, passwd, passphrase, passcode, credential, signature, session, jwt, apikey, privatekey, authorization, authentication, csrf, xsrf, ticket (a WebSocket's `wsTicket`), dpop, hmac, verifier (OAuth's `oauth_verifier`), privkey, mnemonic (a wallet's recovery phrase) |
| has one of these as a whole word, a number after it included (`key1`, `pin2`) | auth, key, sid, sig, sign (an app's request-signing header `sign`), pwd, pw, pass, otp, totp, pin, code |

| Not secret | Note |
|---|---|
| `auth0`, as in `Auth0-Client` | The Auth0 service's name |
| `code` and `key` next to an everyday word: `country_code`, `error_code`, `sort_key`, `foreign_key` | `primaryKey` is a secret |
| `token_type`, `ticket_id`, `ticketNumber` | |
| `Access-Control-Allow-Credentials` | CORS's; only ever `true` |
| A body's `"key"` whose value is a dotted lowercase name: `{"key": "service.name", …}` | As OpenTelemetry writes attributes. A key in it is mixed case or has no dots. `key=` in a URL stays a secret |
| A lone `code` in a response | Usually an error code. `verification_code` and `device_code` are masked. In a request a lone `code` is masked: it carries one-time and OAuth codes |

JWTs and the other [shapes](#shapes-masked-whatever-the-field) are masked
whatever the field is called.

## Where names and shapes are looked for

| Place | Masked | Kept, or not caught |
|---|---|---|
| Headers | The value of a header with a secret name; a credential's shape anywhere in a value | |
| Cookies | Every cookie's value, one without a name too | Names, and a cookie's attributes |
| A `Set-Cookie` line joining several cookies with commas (a server can send one; it is recorded as sent) | Each cookie | Cookies joined with no attributes between them are masked as one value: a comma before a cookie's first `;` may be its value's, as in `v1,QUJD…==` |
| URLs, wherever one appears: any header (`Referer`, `Location`, `Link`), fragments (`#/callback?access_token=`), a URL inside another parameter (also encoded two or three times), bodies, error messages | Query parameters with secret names; a URL's password (`https://user:…@host`) | |
| The response's reason text | Masked too | |
| `WWW-Authenticate` | Credential shapes only | Its challenge: scheme, realm, error |
| `Sec-WebSocket-Protocol` | A credential carried in it: after a name such as `access_token`, as AppSync's `header-` base64 JSON, after Kubernetes' bearer prefix, or a long value shaped like one that is not a dotted name | |
| A host (a flow's `host`, an SNI), a method, the ALPN names a connection in `list_passthrough` offered or got, a body's `Content-Encoding` and the notes that quote it | A credential's shape | The scope is checked with the host as sent |
| Error messages | Shapes and URLs; raw bytes that mitmproxy quotes (`b'…'`) are masked whole | |
| gRPC response trailers | As headers are | Metadata ending in `-bin` (binary) keeps its size only |
| gRPC's `grpc-message` | Decoded, then masked as other header values are (by shapes and URLs), cut to 1 KiB | A free-text `password=…` in it is not caught |
| A WebSocket close's reason; a marker's text | As error text is | |

Checked: tests; an E2E test for the joined `Set-Cookie` line.

## Shapes masked whatever the field

Credentials recognisable by their shape are masked anywhere in a header
value, a URL, a body or an error message.

| Shape | Note |
|---|---|
| `Bearer`, `Basic` and `Token` values that look like credentials | Not the next word of a sentence |
| JWTs | |
| Keys with well-known prefixes | GitHub, `sk-…`, Slack, AWS access key IDs, Google API keys |
| Any of these behind percent-encoding | JSON encoded in a form field or a URL parameter; `Bearer+…` |
| Any of these behind JSON's escapes | `Basic\t…`, `\/` or `\u…` inside a token. A string with any escape is read decoded, at the top level and in JSON inside a string, a cut one too |
| base64 of a JSON object with a secret in it, in a URL parameter or a form field | AppSync's `?header=`. Masked whole |

Checked: tests.

## Bodies, format by format

A body is kept up to 64 KiB, in memory only, and masking works on that head,
which may be cut: a value cut before its closing quote is masked too. The
shapes above are masked in every body, whatever its format.

Checked: a fuzz test, over the shapes of this section, cut anywhere.

### JSON

Read as JSON whatever the content type says.

| In JSON | Result |
|---|---|
| A field with a secret name, its value a string or a number | Masked |
| A field with a secret name, its value a list or an object | Masked whole: `{"password": "[redacted]"}` |
| JSON sent as a string inside JSON, or as a form field | Masked the same way, one level deep |
| A lone `code` | Masked in a request, kept in a response |
| A secret under a name that does not say so: `{"data": "…"}` | **Not masked.** `--mask-names` or `--mask-values` can add it |

### Forms

| In a form | Result |
|---|---|
| A field with a secret name, a lone `code` included | Masked. A body that looks like a form counts as one: one line, which a newline may end |
| SAML's POST binding: the assertion as a base64 `SAMLResponse` field | **Not masked**: the field is not decoded |

Checked: a test (the `SAMLResponse` field passes).

### Text: `name: value` and `name=value` lines

| In a text body that is not a GraphQL document, or in a JSON string | Result |
|---|---|
| A line whose name is secret: a STOMP frame's `passcode:` (also inside SockJS's JSON), a YAML mapping, headers written into a body, a `.env` file's `API_KEY=…` (after `export` too) | The rest of the line is masked, all of it. A `Bearer`, `Basic` or `Token` scheme stays only when the value is that credential alone |
| A YAML list item (`- password: …`); a quoted name | **Not masked**: not looked at |

Checked: tests.

### GraphQL

A document is read by a lexer. It is found where it starts like one: in a
JSON string at the top level or in JSON inside a string (under any key, in
requests and in responses that echo it), in the body, or in a URL parameter
(GET `?query=`, masked and escaped again).

| In a GraphQL document | Result |
|---|---|
| An argument, an input object's field or a variable's default with a secret name | Its whole value is masked, as a JSON field's is: a string, a number, a list, an object. `login(password: "[redacted]", pin: "[redacted]")` |
| Enum and boolean values, `$variables`, aliases | Kept |
| Values sent as GraphQL variables | They are JSON fields: masked by name |
| A document that starts like one and cannot be read | Masked whole |
| One that starts like a script's object (`{a: b, …}`, a comma after the first value) | Left as it is |
| A secret under an innocent name | **Not masked**, so ids stay readable and `diff_flows` can compare them. (Tools that parse GraphQL, such as OpenTelemetry and Apollo, drop every value written into the query instead.) |
| A document quoted mid-message, with prose before it | **Not found** |

Checked: tests and the fuzz test.

### XML

Read as XML when the content type is `text/xml`, `application/xml` or
`application/*+xml` (SOAP's `application/soap+xml`), or when the body starts
with `<?xml`. It is read token by token, by names only. The rest stays as it
came, byte for byte (prefixes, entities, spacing), and the text masking
applies on top.

| In XML | Result |
|---|---|
| An element whose local name is secret (`wsse:Password` is `Password`) | Its whole content is masked (text, CDATA, child elements, comments), up to an end tag of the same local name: a stray `</i>` inside does not end it. `<wsse:Password>[redacted]</wsse:Password>` |
| An attribute whose local name is secret | Its value is masked. Namespace declarations stay |
| A SAML `Assertion` or `EncryptedAssertion` | Masked whole. It is a bearer credential (whoever holds it can present it until it expires), so its subject and attributes do not show either |
| In an Apple plist, the value after a `<key>` in a `<dict>` whose text is secret | Masked: `<key>access_token</key><string>[redacted]</string>` |
| An element named `Key` | Masked, as JSON's `key` is: S3's object names among them |
| A head cut, or that does not tokenize, inside a secret element or attribute value | Masked to its end |
| A head that does not tokenize elsewhere (XML 1.1's declaration, `1 < 2`, a bad comment or name) | Reading goes on past it (after a bad comment's `-->`), in bounded time. That part gets the text masking only |
| A start tag the decoder refuses (`a=b!c`, an unquoted value) | Still read as one, by its name and attributes |
| A DTD | Not read: no entity is expanded or fetched. **Nothing in it is masked by names** (`<!ENTITY p "…">`) |
| A secret in an element or attribute named otherwise | **Not masked** |
| A comment outside a secret element | **Not masked** by names |
| XML carried as text in an element, escaped (`&lt;Password&gt;`) or in CDATA, outside a secret element | **Not read as XML** |
| A WebSocket message | It has no content type, so it is read as XML only if it starts with `<?xml`. XMPP's `<auth mechanism='PLAIN'>…</auth>` passes |
| A JSON body labelled XML (`application/xml`) | XML's masking reads a body before JSON's. A tag inside a string, its masked value running over the string's end, takes the quote JSON's reading needs, and **a secret field after it passes**: `{"xml": "<b data-token=x\"", "password": "…"}`. Labelled HTML, JSON's reading comes first and it is masked |
| A declared encoding | Not used. A head that is not valid UTF-8 (Latin-1 or Shift_JIS with text beyond ASCII, UTF-16) is not masked, as no such body is, and so is neither handed out nor searched |

The XML masking can take away what the text masking keys on (a quote inside a
masked element), so it is not checked to mask everything the text masking
alone would.

Checked: tests (among them: escaped XML and CDATA, XMPP's `<auth>`, the JSON
body labelled XML, a head that is not UTF-8, bounded time, a billion-laughs
document); a fuzz test of markup (it never fails, and a secret element and
attribute before any markup stay masked); an E2E test over mitmproxy with a
SOAP request.

### HTML and JavaScript

Read as HTML when the content type names `html`, or when the head starts with
`<!doctype html` or `<html`. It is read tag by tag, not as a browser parses
it. JSON's masking reads the head before this, so a masked tag takes no quote
from it (a JSON body labelled `text/html`); the rest of the text masking
applies on top.

| In HTML | Result |
|---|---|
| A tag whose `name`, `id` or `property` is secret, a lone `code` included as in forms | Its `value` and `content` are masked: an OAuth `form_post`'s hidden `code` and `id_token`, Rails' `authenticity_token`, ASP.NET's `__RequestVerificationToken`, `<meta name="csrf-token">` |
| A `<textarea>` so named | Its text is masked |
| An attribute secret by its own name (`data-auth-token`) | Its value is masked, as XML's |
| A tag cut by the head's end | Its `value` and `content` are masked whatever its name, which may come after them. A secret `<textarea>` cut: its text to the end |
| A comment; the text of `<script>`, `<style>`, `<textarea>`, `<title>` and the other elements whose text is no markup | Read up to its end only: a quote or a `<` in it (a script's `"<a x='"`) does not make the tags after it read as an attribute's value. Tags inside are still read (a commented-out field, HTML in a script's string) |
| A secret in a tag's text other than a `<textarea>`'s, or under an innocent name | **Not masked** |
| A name written with character references (`&#99;ode`) | **Not masked** |
| A script's text that a browser reads past its first `</script>` (`<script><!--<script>`) | It ends at the first one here |
| SAML's `SAMLResponse` field | **Not masked**, as in a form |

| In HTML, and in JavaScript by its content type | Result |
|---|---|
| An object's field with an unquoted secret name: `{accessToken: "…"}`, `{pin: 1234}`; a lone `code` as in JSON | Its string, template literal or number value is masked, also with comments around its name and colon (two at most, of 80 bytes or less each) and for a string going on past a line's end after a backslash |
| A longer comment, or more than two, between a name and its value | **Not masked** |
| A quoted name: `{'accessToken': '…'}` | **Not masked** |
| An assignment: `x.accessToken = "…"` | **Not masked** |
| A template literal holding another | Masked up to the inner one only |

Checked: tests and the fuzz test, cut anywhere.

### `multipart/form-data`

Handed out as Reqcove's rendering (`view`), part by part. At most 256 parts
are read.

| In an upload | Result |
|---|---|
| A part whose name is secret (a lone `code` in a request) | Masked whole |
| A part header with a secret name | Masked |
| A text part (no filename, a text or JSON type) | Masked as a body is |
| A file part; a part that is not text or is encoded (`Content-Transfer-Encoding: base64`); a part whose `Content-Disposition` does not read, comes twice, or names neither a field nor a file | Its headers and its size only, never its bytes |
| Folded part headers (a line starting with a space or a tab) | Read and masked unfolded, as one line |
| A body with LF-only lines | No part is shown |
| A preamble and an epilogue | Not shown |
| `multipart/mixed` | A secret in it is **not caught** |

Checked: tests, and an E2E test with Go's multipart writer.

### Protobuf and gRPC

Protobuf, by its content type or in gRPC's frames, is handed out as Reqcove's
rendering instead of the bytes (`view` says so).

| Protobuf | Result |
|---|---|
| A body that does not read as protobuf to its end | Shows nothing |
| Printable text | Shows nothing, unless it reads whole as strings and sub-messages alone (one string field of printable length is printable) |
| A head cut before its end | Shows what it read only when that held a string or a whole sub-message |
| Without a schema | The structure only: field numbers, wire types, lengths; a string's length, never its text |
| Numbers, without a schema | Shown in responses. In requests only 1-byte numbers (0 to 127: enums, booleans, but also a PIN or CVV that small); larger ones show as their byte count, as a lone `code` is masked in requests |
| A span of printable text | Always a string, never read as a message: its bytes would then show as numbers |
| Random bytes (`bytes` fields) | Can still read as a message. In a response usually all of their bytes then show as numbers (about 1 in 100 16-byte values whole, 1 in 1,000 32-byte ones); in a request parts of them (field numbers and 1-byte numbers) |
| Lengths | **Shown**: a password's length |
| With `--proto FILE` (your compiled schema), a message whose type is known: a gRPC, Connect or Twirp method by its path, or `messageType` in the content type | Read with its field names (the proto names, never `json_name`) as JSON, and masked by name as JSON is. `bytes` show their length, and fields the schema does not have their structure |
| A schema that is stale or wrong | It can give a token an innocent name, which then **passes** |
| Values under names the built-in list does not count as secret (a `cookie` entry of a headers map, a `cvv`) | **Not masked**, as in JSON |

| gRPC | Result |
|---|---|
| Framed JSON messages | Masked as JSON |
| Framed protobuf messages | Rendered as above |
| A body under a gRPC type that is not framed | Masked as a body |
| Response trailers, `-bin` metadata, `grpc-message` | [Above](#where-names-and-shapes-are-looked-for) |

Checked: tests; the fuzz test is of the reading without a schema; an E2E test
over HTTP/2 for gRPC. The guide's `protoc` command was run once, with protoc
33.0.

### WebSocket messages

A text message's first 4 KiB is masked as it arrives, as a body is: a
client's with a request's rules, a lone `code` included.

| WebSocket | Result |
|---|---|
| A text message masking could read: text with no control characters but a STOMP frame's closing NUL and SignalR's 0x1e between JSON objects | Kept, masked |
| From a client, a message that is one token-shaped word, bare or as one JSON string | Masked |
| From a client, the strings after an auth event's name in an event array: socket.io's `42["authenticate","…"]`, with a namespace and an ack id too | Masked |
| From a client, a SignalR invocation's arguments when its target is such a name | Masked. SignalR's records are read one by one; only the first `target` is read |
| Strings nested deeper in the arguments, in SignalR's and in socket.io's | **Not masked** |
| A credential sent positionally in other ways: an array without such an event name, a custom binary framing | **Not caught**, as in bodies |
| Binary messages, and those past about 20 a second on one socket | Their size only |
| A close's reason | Masked as error text is |

A socket keeps its first 5 messages and its newest 100. They are handed out
only by `list_ws_messages` (and `reqcove har`).

Checked: tests, and the E2E test with a real socket.

## Bodies that are not handed out

- A body is handed out and searched only if masking could look at it. It
  must be decoded (not wire bytes of an encoding it could not undo) and text.
- Text is told by the content type: JSON, XML, forms, text, …; another type
  naming `json`, such as `application/x-amz-json-1.1`, and Sentry envelopes,
  only with no control characters. With no content type, it is told by the
  bytes.
- Other bodies, a protobuf that happens to be valid UTF-8 included, are
  neither handed out nor searched while masking is on. `--no-redact` returns
  them. Protobuf by its content type is the exception:
  [its rendering](#protobuf-and-grpc) is handed out.
- Bodies are returned only when a tool is asked for them (`bodies` in
  `get_flow` and `search_flows`), and by `diff_flows`, which compares them:
  the values and keys that differ, cut to 300 bytes, and bodies that are not
  text not at all while masking.
- Personal data, such as e-mail addresses and names, is not masked: debugging
  needs it.

## Your own rules (`--mask-names`, `--mask-values`)

Both are fixed at start, and do nothing with `--no-redact` (`run` warns).

| Flag | What it adds | Limits |
|---|---|---|
| `--mask-names` | Names treated as secret wherever names count, before the built-in exceptions (an OpenTelemetry `key`, `WWW-Authenticate` kept as a challenge, a cookie's attributes) | The whole name only, in any spelling: `clientRef` covers `client_ref` and `Client-Ref`, not `X-Client-Ref` |
| `--mask-values` | RE2 patterns whose matches are masked wherever they appear: a header of any name (a User-Agent's `key=…` among them), URLs, bodies, error text | At most 32 patterns of 512 bytes each, none that matches empty text. Errors name a pattern by its number, never its text |

- `capture_stats` counts the matches per name and per pattern number (a value
  can count more than once).
- A pattern on the command line shows in `ps`. A literal secret belongs in an
  `@FILE`, written as `\Q…\E` so its `+`, `/` and `.` match themselves.

Checked: tests.

## What a record keeps

| What | Bound |
|---|---|
| Flows | At most 10,000, in memory, gone when `reqcove run` stops. Reqcove writes no flow to disk itself |
| Text in all records together: body heads, headers, URLs and other text | At most 64 MiB |
| A body | Its first 64 KiB |
| A WebSocket text message | Its first 4 KiB; per socket, the first 5 messages and the newest 100 |
| A site's reason text; `Content-Encoding`; an error message | Cut to 1 KiB; 64 bytes; 1 KiB |
| User-Agents in lists and summaries; ALPN names; JSON keys in `diff_flows` that are not plain names | Cut to 256 bytes; cut to printable ASCII; quoted (`$["a.b"]`) |
| A marker (`reqcove mark`, `add_marker`) | In memory with the records, at most 80 characters on one line (else refused), masked as error text is, at most 100 per source, not logged (from reading the code) |
| A request whose Host is no host name or address | Carried, not recorded |

Checked: a test (the request with such a Host; the marker's masking and
refusals).

## Connections recorded without their content

Two kinds of connection leave a record of the connection, never of what it
carried.

### `--pass-hosts` hosts

Allowed hosts whose apps refuse Reqcove's certificate pass through
undecrypted, and only their connections are recorded.

| `--pass-hosts` | Result |
|---|---|
| What is recorded | The host the client named (its SNI), the server's address, start and end, bytes each way, the protocols offered. Nothing inside TLS is kept or seen |
| The scope | The record is checked against `--allow-hosts` again, so a host outside it leaves nothing |
| Bytes | The whole connection's: another host's requests riding it count in them, unseen (from reading the code) |
| A pass host's TLS connections | Go to its server directly, past `--rules` and `--upstream-proxy` |
| Its plain HTTP, and its requests riding another host's decrypted connection (HTTP/2) | Decrypted all the same: counted as out of scope, not recorded, and sent on through `--upstream-proxy` when one is set, checked as all HTTPS through it is (against `--upstream-ca` only, or the public CAs without one). They skip `--rules` (from reading the code) |
| A pass host on Apple's list | Passed by mitmproxy itself: no record. `run` warns |
| The hosts `reqcove status` suggests for `--pass-hosts` | They come from the phone's TLS (its SNI, the app's to choose). Only host names and IPv4 addresses are suggested (a client that names no host is passed by its destination), never mitm.it, and the command is quoted for a shell |
| `@FILE` lists | Read as hosts, never run. A line that is not a host stops `run`, named by its line number only, so a wrong file (a .env, say) is not printed back |

Checked: tests (a pass host's decrypted requests go through
`--upstream-proxy`; a pass host on Apple's list; the suggestion; the `@FILE`
line).

### Raw TCP

A connection to an allowed host that mitmproxy carries as raw TCP, not read
as HTTP, has no flow for what it carries. Only the connection is recorded, in
`list_passthrough` with `reason: raw_tcp`.

| Raw TCP | Result |
|---|---|
| An ALPN name mitmproxy does not know (once decrypted, for TLS) | Raw TCP only when the server speaks first or the client's bytes do not look like HTTP. Otherwise it is read as HTTP/1, which fails for a client speaking another protocol |
| Bytes that do not look like HTTP | Raw TCP |
| What a request upgrades to with a `101` other than a WebSocket | Raw TCP. The request itself is a flow |
| What is recorded | The host the client named (its SNI; after a plain HTTP `101`, the request's host; else the address), the server's address, start and end, the protocols the client offered and the one it got, and the bytes relayed each way (inside TLS, for TLS); never the bytes themselves |
| The scope | The record is checked against `--allow-hosts` and `--pass-hosts` again, so a host outside the first or in the second leaves nothing |

Checked: an E2E test over plain HTTP (the `101`, and what is recorded); a
test (the scope check). Tried 2026-11-15: the unknown ALPN name, and the
`101` over TLS.

## Connections that leave no record

Nothing of these is recorded or counted. Connections mitmproxy passes through
itself fire none of its hooks (from reading mitmproxy 12.3.1's code).

| Connection | What happens | How it was checked |
|---|---|---|
| Apple's hosts; hosts outside `--allow-hosts` | Passed through by mitmproxy | From reading the code |
| A connection mitmproxy knows by its address only | Passed through, unless `--allow-hosts` names the address | From reading the code |
| TLS without SNI | Known by its address only. That holds on the Remote Proxy, LAN mode and the local proxy too: the name in `CONNECT` does not reach mitmproxy | From reading the code |
| Plain TCP (ports 80 and 443 go to mitmproxy) whose first bytes do not name an allowed host as mitmproxy reads them: not HTTP, a server that speaks first, HTTP/2 without TLS (h2c with prior knowledge, which mitmproxy 12.3.1 does not take), HTTP/1.0 without `Host`, `Host:` with no space after the colon | Known by its address only | Tried 2026-11-15 |
| An allowed host's HTTP/2 requests riding a connection the client opened for a name outside the list, which shares its certificate and address | They go with that connection, undecrypted. URLSession reuses connections so (HTTP/2 connection coalescing, from Apple's WWDC 2020 session "Boost performance and security with modern networking"), and CDNs give sibling hosts one certificate: an allowed host's requests can be missing when the app reached a sibling first. Allow the names that share the certificate (`*.example.com`) | Tried 2026-11-15 with Go's HTTP/2 client; not on an iPhone |
| TLS with Encrypted Client Hello | mitmproxy sees only the provider's public name, so unless that name is allowed the connection passes through. iOS does not use ECH by default, by public sources, but an app can turn it on for its own connections | Tried 2026-11-15 with Go's ECH client and server; not tried on an iPhone |
| An HTTP/1 connection to an allowed host (by SNI) whose first request names one of Apple's hosts in `Host` | Carried whole, decrypted, its later requests too: mitmproxy checks the name again after TLS | Tried 2026-11-15 |
| An address in `--allow-hosts` and a name in SNI | The connection is decrypted by its address. Its HTTP requests count as out of scope, and one mitmproxy then carries as raw TCP is checked by its name and leaves nothing | Tried 2026-11-15 |
| A client that finishes the TLS handshake and only then refuses mitmproxy's certificate and closes | No TLS failure, no flow, no count: for mitmproxy the handshake succeeded | Tried 2026-11-15 with curl on OpenSSL 4.1, TLS 1.2 and 1.3 |
| A client that finishes the handshake and closes without a request | The same | An E2E test |
| A client that refuses during the handshake: Python's and Go's | Listed as a TLS failure | Tried with TLS 1.2 and 1.3; Go's, an E2E test |
| An iPhone app that pins by refusing in URLSession's delegate or in Network.framework's verify block | It refuses during the handshake, and is listed | Tried on an iPhone, 2026-11-15 |
| An iPhone app that lets the handshake finish, checks the certificate itself and closes | Leaves nothing, as above | Tried on an iPhone, 2026-11-15 |
