# Reqcove's security model

Reqcove decrypts a phone's HTTPS and hands what it reads to an AI agent. This page
says what it protects, what it trusts, and what it does not try to do. Points that
come from reading code rather than from a test say so. It describes v0.4.

## Trust

- **Your OS user is trusted.** The state directory (`~/.reqcove`, mode 0700) and
  the MCP socket in it are open to that user only. Any process running as that user
  can read the records, and the CA's private key. Reqcove promises nothing stronger.
- **The devices you name are trusted to use the exit node**, nothing else. Traffic
  from other tailnet devices is refused, on the exit node and on the Remote Proxy.
  A device name is what each device calls itself, so `--device` takes one only from
  your own user's devices, and only while neither it nor Reqcove's node is tagged
  (a tagged node keeps the user ID of whoever tagged it); name other devices by
  machine name, IP or StableID.

## In a container

(docs/container.md) mitmproxy, which opens what sites send, runs
in the container: a flaw there reaches the container (the records, the CA's key
in its volume), not the rest of the user's files. The image has no shell or
package manager and runs as a user of its own, not root. In exchange, whoever
can use the Docker daemon's socket can read the volume, the CA's key included,
and `docker logs` keeps the login URL, the `--ui`/`--web` links and the
`--mcp-http` token until the container is removed. `reqcove mcp` runs with
`--log-driver none`, so the tools' answers are not logged. Checked by
`scripts/container-smoke.sh` (the state directory's owner and mode, no
network needed), not by an attack.

## The CA's private key

`~/.reqcove/mitmproxy/mitmproxy-ca.pem`, and `mitmproxy-ca.p12` next to it (a
PKCS#12 file without a passphrase), hold the private key of a CA your iPhone
trusts. Whoever has it can impersonate any HTTPS site to that iPhone. Keep the
directory to yourself; when you stop using Reqcove, remove the profile from the
iPhone first, then delete the directory (`reqcove cleanup` lists the steps).
Copying the directory to another computer copies the key.

A `--state` directory without a CA gets a copy of `~/.reqcove`'s
at start (several exit nodes on one computer, one profile on the iPhone):
`mitmproxy-ca.pem` with the key, and the certificate files; not
`mitmproxy-ca.p12`, nor mitmweb's password. `run` logs where it copied it, and
every command refuses a `--state` starting with `~` (`--state=~/x`, which the
shell leaves as it is, would put the key in `./~/x`, and `cleanup` would call
the real one gone). The key is then in each such
directory, each 0700 with the files 0600 (a test): deleting one leaves it in
the others, and removing the profile from the iPhone is what stops them all.
`~/.reqcove/ca-copies` lists the copies, and `cleanup` of `~/.reqcove` names
those still holding the CA; `cleanup` of a copy says the profile serves both.
So "delete the directory" above means each of them.

## What is recorded

- Only requests to hosts in `--allow-hosts` (and not in `--pass-hosts`) are
  recorded. Two checks enforce it: mitmproxy passes other connections through
  undecrypted, and each request's Host is checked again. A connection to an
  allowed host can carry requests to others (HTTP/2 connection reuse): those are
  decrypted with it, not recorded, but shown by `--web` and possibly sent on to
  `--upstream-proxy`. Requests and TLS failures outside the list are counted,
  never recorded.
- Connections to Apple's hosts always pass through undecrypted.
- `--pass-hosts` hosts (allowed hosts whose apps refuse
  Reqcove's certificate) pass through undecrypted too, and only their
  connections are recorded: the host the client named (its SNI), the server's
  address, start and end, bytes each way, the protocols offered. Nothing inside
  TLS is kept or seen. The record is checked against --allow-hosts again, so
  a host outside it leaves nothing, and requests to a pass host riding another
  host's decrypted connection (HTTP/2) are not recorded either. Bytes are the
  whole connection's: another host's requests riding it count in them, unseen
  (from reading code). The hosts `reqcove status` suggests for `--pass-hosts`
  come from the phone's TLS (its SNI, the app's to choose): only host names
  and IPv4 addresses (a client that names no host is passed by its
  destination) are suggested, never mitm.it, and the command is quoted for a
  shell (a test). `@FILE` lists are read as hosts, never run: a line that is
  not a host stops `run`, named by its line number only, so a wrong file (a
  .env, say) is not printed back (a test). A pass host's TLS connections go to
  its server directly, past `--rules` and `--upstream-proxy`. Its plain HTTP,
  and its requests riding another host's decrypted connection, are decrypted all
  the same: counted as out of scope, not recorded, and sent on through
  `--upstream-proxy` when one is set (a test), checked as all HTTPS through it
  is: against `--upstream-ca` only, or the public CAs without one. They skip
  `--rules` (from reading code). A pass
  host on Apple's list is passed by mitmproxy itself and leaves no record (a
  test); `run` warns.
- The secrets Reqcove recognises are masked as they arrive, so no tool can
  return them. A header, query
  parameter or body field is secret by its name: a name containing token,
  secret, password, passwd, passphrase, passcode, credential, signature, session,
  jwt, apikey, privatekey, authorization, authentication, csrf, xsrf, ticket
  (a WebSocket's `wsTicket` was seen unmasked) or dpop, even run
  together (`accesstoken`, `X-AuthToken`), or having auth, key, sid, sig, sign
  (an app's request-signing header `sign` was seen unmasked), pwd,
  pw, pass, otp, totp, pin or code as a whole word (names split at punctuation
  and case changes, so `apiKey`, `XAuth` and `X-Amz-Signature` count, while
  `author` and `keyword` do not). `code` and `key` next to an everyday word
  (`country_code`, `error_code`, `sort_key`), `token_type`, `ticket_id`,
  `ticketNumber` and CORS's `Access-Control-Allow-Credentials` (only ever
  `true`; seen masked in use) are not secrets, nor a body's `"key"` whose
  value is a dotted lowercase name, as OpenTelemetry writes attributes
  (`{"key": "service.name", …}`; seen masked in use). A key in it is mixed case
  or has no dots; JWTs and the other shapes below are masked whatever the field;
  `key=` in a URL stays a secret.
  Cookie values are masked (names stay), and query parameters wherever a URL
  appears (any header, such as `Referer`, `Location` or `Link`; fragments such
  as `#/callback?access_token=`; a URL inside another parameter; bodies; error
  messages), as is a URL's password (`https://user:…@host`) and the response's
  reason text. Raw bytes that mitmproxy quotes in an error message (`b'…'`) are
  masked whole. `--no-redact` turns this off.
- Bodies are masked as they arrive too, as far as they can be recognised: in JSON
  (whatever the content type says), the string and number values of fields
  whose names are secret by the same rule, also in JSON sent as a string inside
  JSON or as a form field (one level deep). In a response a lone `code` is
  kept, as it is usually an error code (`verification_code` and `device_code`
  are masked); in a request it is masked, as it carries one-time and OAuth
  codes. In forms (or bodies that look like one), such fields' values, a lone
  `code` included. Anywhere in a header value, URL, body or error message,
  credentials recognisable by their shape are masked: `Bearer`/`Basic`/`Token`
  values that look like credentials (not the next word of a sentence), JWTs,
  and keys with well-known prefixes (GitHub, `sk-…`, Slack, AWS access key IDs,
  Google API keys), also behind percent-encoding (JSON encoded in a form
  field or a URL parameter, `Bearer+…`). `WWW-Authenticate` keeps its
  challenge (scheme, realm, error), with only such shapes masked.
  A line `name: value` in a text body that is not a GraphQL document, or in a
  JSON string, whose name is secret (a STOMP frame's `passcode:`, also inside
  SockJS's JSON; a YAML mapping; headers written into a body) has the rest of
  the line masked; YAML list items (`- password: …`) and quoted names are not
  looked at. A URL parameter or form field holding base64 of a JSON object with
  a secret in it (AppSync's `?header=`) is masked whole, and so is a credential
  carried in `Sec-WebSocket-Protocol` (after a name such as `access_token`, as
  AppSync's `header-` base64 JSON, after Kubernetes' bearer prefix, or a long
  value shaped like one that is not a dotted name). (Tests.)
  A field with a secret name whose value is a list or an object is masked
  whole (`{"password": "[redacted]"}`).
  In a GraphQL document, read by a lexer, an argument, an input object's
  field or a variable's default whose name is such has its whole value masked
  (`login(password: "[redacted]", pin: "[redacted]")`: a string, a number, a
  list, an object), as a JSON field's is; enum and boolean values, `$variables`
  and aliases stay. A document is found where it starts like one: a JSON
  string at the top level or in JSON inside a string (under any key, in
  requests and in responses that echo it), the body, or a URL parameter (GET
  `?query=`, masked and escaped again). One that starts like a document and
  cannot be read is masked whole, unless it starts like a script's object
  (`{a: b, …}`, a comma after the first value), which is left as it is. (Tests and the fuzz test.)
  A URL inside a parameter is looked into also when encoded two or three times.
  A body is kept up to 64 KiB, in memory only, and works on a head that may be cut:
  a value cut before its closing quote is masked too (a fuzz test, over these
  shapes and cut anywhere: it found the twice-encoded URL and a GraphQL value
  cut after a backslash, both fixed).
- Your own rules, fixed at start: `--mask-names` adds names treated as secret
  wherever names count, the whole name only (any spelling: `clientRef` covers
  `client_ref` and `Client-Ref`, not `X-Client-Ref`), before the built-in
  exceptions (an OpenTelemetry `key`, `WWW-Authenticate` kept as a challenge,
  a cookie's attributes: a test). `--mask-values` adds RE2 patterns whose matches are masked
  wherever they appear (a header of any name, a User-Agent's `key=…` among
  them, URLs, bodies, error text); at most 32 patterns of 512 bytes each, none
  that matches empty text. Errors name a pattern by its number, never its text.
  `capture_stats` counts the matches per name and per pattern number (a value
  can count more than once). (Tests.) A pattern on the command line shows in
  `ps`, so a literal secret belongs in an `@FILE`, written as `\Q…\E` so its
  `+`, `/` and `.` match themselves. Both do nothing with `--no-redact` (`run`
  warns).
- **What this does not catch:** a secret under a name that does not say so
  (`{"data": "…"}`; `--mask-names` or `--mask-values` can add it),
  or in formats other than JSON, forms and text
  (`multipart/mixed`, XML elements and attributes; protobuf and
  `multipart/form-data` are read as below). In GraphQL the same
  holds: a secret under an innocent name passes, so ids stay readable and
  `diff_flows` can compare them (tools that parse GraphQL, such as
  OpenTelemetry and Apollo, drop every value written into the query instead);
  and a document quoted mid-message, with prose before it, is not found.
  Values sent as GraphQL variables are JSON fields, masked by name.
  Personal data, such as e-mail addresses
  and names, is not masked: debugging needs it. A body is handed out and searched
  only if masking could look at it: decoded (not wire bytes of an encoding it
  could not undo) and text, by its content type (JSON, XML, forms, text, …;
  another type naming `json`, such as `application/x-amz-json-1.1`, and Sentry
  envelopes only with no control characters) or, with none, by its bytes. Others, a protobuf that happens to be valid UTF-8
  included, are neither handed out nor searched while masking is on;
  `--no-redact` returns them. Protobuf (by its content type, or in gRPC's
  frames) is the exception: reqcove hands out its own rendering instead of
  the bytes (`view` says so); a body that does not read as protobuf to its
  end (or is text) shows nothing, and a head cut before its end shows what
  it read only when that held a string or a whole sub-message. Without a schema, it is the structure only:
  field numbers, wire types, lengths, a string's length but never its text,
  and numbers in responses; in requests only 1-byte numbers (0 to 127:
  enums, booleans, but also a PIN or CVV that small), larger ones as their
  byte count, as a lone `code` is masked in requests. A span of printable
  text is always a string, never read as a message, as its bytes would then
  show as numbers; random bytes (`bytes` fields) can still read as one: in a
  response usually all of their bytes then show as numbers (about 1 in 100
  16-byte values whole, 1 in 1,000 32-byte ones), in a request parts of
  them (field numbers and 1-byte numbers). Lengths show (a password's
  length). With `--proto FILE` (your
  compiled schema), a message whose type is known (a gRPC, Connect or Twirp
  method by its path, or `messageType` in the content type) is read with
  its field names (the proto names, never `json_name`) as JSON and masked
  by name as JSON is; `bytes` show their length, and fields the schema does
  not have their structure. A schema that is stale or wrong can give a
  token an innocent name, which then passes; so do values under names the
  built-in list does not count as secret, as in JSON (a `cookie` entry of a
  headers map, a `cvv`). (Tests; the fuzz test is of the reading without a
  schema. The `protoc` command above was run once, with protoc 33.0.)
- `multipart/form-data` (uploads): handed out as reqcove's rendering
  (`view`), part by part. A part whose name is secret (a lone `code` in a
  request) is masked whole, as are part headers with secret names; a text
  part (no filename, a text or JSON type) is masked as a body is; a file
  part, a part that is not text or is encoded (`Content-Transfer-Encoding:
  base64`), and a part whose `Content-Disposition` does not read (or comes
  twice) keep their headers and their size only, never their bytes. A body
  with LF-only lines shows no part. A preamble and an epilogue are not
  shown. At most 256 parts are read.
  (Tests, and an E2E test with Go's multipart writer.)
- gRPC: response trailers are masked as headers are; metadata ending in `-bin`
  (binary) keeps its size only; `grpc-message` is decoded, then masked, cut to
  1 KiB, as other header values are (by shapes and URLs: a free-text
  `password=…` in it is not caught). Framed JSON messages are masked as JSON;
  protobuf ones are rendered as above; a body under a gRPC type that is not
  framed is masked as a body. (Tests, and an E2E test over
  HTTP/2.)
- WebSocket messages: a text message's first 4 KiB is masked as it arrives,
  as a body is (a client's with a request's rules, a lone `code` included),
  and kept only if masking could read it (text with no control characters but
  a STOMP frame's closing NUL, and SignalR's 0x1e between JSON objects). From
  a client, shapes only messages have are masked too: a message that is one token-shaped word (bare or as one
  JSON string), the strings after an auth event's name in an event array
  (socket.io's `42["authenticate","…"]`, with a namespace and an ack id too),
  and a SignalR invocation's arguments when its target is such a name
  (SignalR's records are read one by one; only the first `target` is read,
  and strings nested deeper in the arguments, as in socket.io's, are not). Binary messages, and those past about 20 a
  second on one socket, keep their size only. A socket keeps its first 5
  messages and its newest 100; they are handed out only by
  `list_ws_messages` (and `reqcove har`). A close's reason is masked as error
  text is. (Tests, and the E2E test with a real socket.) Not caught: a
  credential sent positionally in other ways (an array without such an event
  name, a custom binary framing), as in bodies.
- Bodies are returned only when a tool is asked for them (`bodies` in
  `get_flow` and `search_flows`), and by `diff_flows`, which compares them: the
  values and keys that differ, cut to 300 bytes, and bodies that are not text
  not at all while masking.
- Records live in memory (at most 10,000 flows and 64 MiB of body heads, headers,
  URLs and other text together; a site's reason text, `Content-Encoding` and
  error messages are cut to 1 KiB, 64 bytes and 1 KiB) and are gone
  when `reqcove run` stops; reqcove writes no flow to disk itself. `reqcove har >
  FILE` writes them where you send it, masked as the tools return
  them, with your shell's file mode (often readable by other users; the state
  directory is 0700). `mitmproxy.log` in the
  state directory holds mitmproxy's error lines only (a test checks that secrets
  sent in failing and malformed requests do not reach it).

## What the agent sees goes further

Whatever a tool returns is sent to the agent's model provider. Choose
`--allow-hosts` with that in mind; `--allow-hosts '*'` sends other apps' and sites'
traffic too, and Reqcove warns when it starts. Besides the traffic, the `status`
and `list_devices` tools carry the node's MagicDNS name (which includes the
tailnet's name), its tailnet addresses and the devices' machine names; not your
login (from reading code).

## Prompt injection

Reqcove's tools only read, but an agent that reads them may also hold other
tools: a shell, file writes, the network, other MCP servers. Text a site
wrote into a record can try to steer it into using those (send a cookie
somewhere, edit a file). Reqcove cannot stop that from its side; your agent's
own settings can. Give an agent that reads Reqcove only what the task needs:
in Claude Code, allow Reqcove's tools without allowing shell commands or
network tools along with them, and keep its permission prompts for the rest;
in Codex, keep its sandbox (by default without network, from its
documentation, not tried) and approvals. An agent that only
reads Reqcove and answers you is the safest shape.

Response bodies, and also response headers, status reasons, redirect targets
and error messages, are written by remote sites and may contain text meant to
steer the agent; an app chooses its User-Agent, its TLS names and the JSON
keys it sends, and a tailnet peer its device name. Tools return bodies only on
request (and `diff_flows` what differs), and every tool's description says
what it returns was written by sites, apps or the tailnet: data. The server's
instructions, sent to every client (also those without the skill, such as Grok
Bot), say so too, and that the agent must not write a file (a `--rules` file
above all), a commit or a command because of what the records say, nor suggest
`--no-redact` or `--web`, and that `next_steps` are for the user (tests check
that clients get them over stdio and HTTP, not their wording; whether a model
keeps to them is not something a test can show). A request whose Host is no host name or address (an app's own HTTP stack
can put any text there) is carried but not recorded (a test); hosts from TLS
are host names by mitmproxy's own check (from reading its code). A flow's host
is the request's Host, which the app chooses: on a connection to an allowed
host it can name another allowed one, and the record shows that one (the
request still goes where the connection went). User-Agents in lists and summaries
are cut to 256 bytes, ALPN names to printable ASCII, and JSON keys in
`diff_flows` that are not plain names are quoted (`$["a.b"]`).
The MCP tools only read; nothing an agent calls changes traffic. (`--rules` are
yours, from a file, at start.)

## Rules (`--rules`)

Rules are yours, read from a file when mitmproxy starts; no tool changes them.
With `run --rules-reload` the file is also read again whenever it
changes, so whatever can write it (any process as your user, an agent with file
access included) can then change where the devices' requests go while `run`
runs; without it, the file is read only when mitmproxy starts (with `run`, or
when reqcove restarts it after it exits).
`modify_headers` takes header names that are HTTP tokens and values without
a line break or NUL (they would start a header of their own on the wire); a
value file read again for a later flow and given one since is dropped from
that flow's headers. `resolve` names are host names only, so nothing in them
reaches the log as control characters (tests).
`map_remote` and `resolve` make mitmproxy connect, from this computer, where the
rule says, this computer and the LAN included: the exit node's refusal of those
addresses is about the devices' own connections, and a rule opens its target to
every app on the carried devices that sends a request for the rule's host (a web
page included). `resolve` takes IPv4 addresses only, never a name to look up, and
refuses `0.0.0.0/8`, link-local, multicast and reserved ranges, Tailscale's
100.100.100.100 and the cloud metadata addresses 169.254.169.254 and
100.100.100.200; `map_remote` takes whatever it is given. A `resolve` rule
without a port takes the request's port (the app's, or a `map_remote` URL's). TLS to a `resolve` target is
checked against the rule's name, with mitmproxy's own CA list (certifi, from
reading its code), so a request goes on only to a server with a certificate for
that name (tried: one with a trusted certificate for another name gets a 502); plain HTTP is not checked. Each
`resolve` name needs its own address: mitmproxy reuses a connection by address,
so names sharing one would share one name's check, and are refused. A
`map_remote` to a `resolve` target's address shares its connections, both ways:
a request of one can ride on a connection made, and checked, for the other, and a
failed connection fails both for as long as the app's connection lasts.
A request a rule fails on (say, a `map_remote` making a bad port) is answered with
a 502 rather than sent on as it was (a test), and a `map_remote` whose replacement
cannot work at all stops `run` at start.
A rules file from someone else is code: it can send your apps' requests, cookies
and tokens included, anywhere.
A `mock` answers in the site's name: the app, and a web view's page, take it
as the site's own answer (a script in it runs in that origin, a redirect is
followed). It is for hosts in `--allow-hosts` only (refused otherwise), and its
header values are checked as `modify_headers`'s are. The records say a flow was
mocked, with the rule's number and status, never its text. A request a mock may
answer is held whole until its body is in (the operation is in it): at most
1 MiB when it says its length; a GET without one can carry more over HTTP/2,
kept whole, as for `map_local`. No MCP tool writes a rule: a mock comes from the file the user wrote, and
over `--mcp-http` an agent has no way to the file at all.

## An upstream proxy (`--upstream-proxy`)

Decrypted HTTP(S) requests then go on through that proxy, and Reqcove's mitmproxy
does not connect to their servers itself (connection strategy lazy; a test counts
the server's connections). Other protocols over TLS to an allowed host still go
straight to their servers (from reading code; a review saw it). What changes:

- The proxy sees the requests and responses unmasked, and Burp, for one, keeps them
  in its project, on disk. Its own MCP server or extensions give agents what
  Reqcove's tools hold back, and the ability to send requests.
- Checking the real server's certificate is the proxy's job: with the proxy's CA
  (`--upstream-ca`, or Burp's fetched at start), Reqcove trusts only that CA, so it
  checks the proxy, not the server. Burp's is fetched over plain HTTP from the
  proxy's own listener (`http://127.0.0.1:PORT/cert`, no name looked up, so no
  other server can answer), only when the proxy is on this computer, and only a
  CA named "PortSwigger CA" is taken (a test; Burp answered there, checked with
  curl). Burp, by
  default, did not check (tried, a review).
- Where the proxy connects is the proxy's choice. Reqcove hands it the address the
  exit node allowed, but Burp connects by the name in the SNI, looked up again on
  this computer (tried, a review): a name that resolves into this computer's LAN
  reaches it, past the exit node's refusal. A site the iPhone visits can make
  its own name do that only for the proxy's lookup (DNS rebinding: from reading
  code, not tried), so keep `--allow-hosts` narrow; `run` warns when it is `'*'`.
  `resolve` rules are refused with `--upstream-proxy` for this reason.
- The CONNECT lines (an IP address and port) and plain HTTP reach the proxy
  unencrypted: keep it on this computer, or on the tailnet.
- The flag is read at start; no tool changes it.

## The page (`--ui`)

`--ui` serves a read-only page of the records on the node's port 80, with what the
MCP tools return, masked the same way. Who can read it (each a test):

- Only your own devices on the tailnet (logged in as the same user as reqcove's
  node, and untagged) and the `--device` devices, checked when a connection opens
  and on every request; others get nothing.
- Your own devices see every device's flows, with the device's name. A `--device`
  device of another user sees only its own flows, in the list and by ID, and its
  own counts and next steps (not the other devices', nor their names).
- Only a browser holding the token: the link `run` prints sets it as an HttpOnly,
  SameSite=Strict cookie kept 400 days. Another app on the same iPhone can reach
  the port, but not read the page without the token. The token is kept in
  `ui-token` in the state directory (0600) and is the same at each start, so a
  link, a bookmark or a cookie keeps working until you delete that file and start
  again; then they get 403. Your own devices and the `--device` devices reach the
  page; a link that leaks works only from those.
- Only requests that name the node (its MagicDNS name or tailnet address) in
  `Host`: a site the iPhone visits cannot point its own name at the node and read
  the page as its own (DNS rebinding).
- GET and HEAD only, also when the request comes through the Remote Proxy; the
  search form goes to the page itself (CSP `form-action 'self'`), and Clear only
  hides flows from the list (a `since` in its URL), deleting nothing. The
  page's only script is its own `/app.js` (the Content-Security-Policy allows no
  other, and nothing inline), which asks `/flows.json` for the list once a second
  and puts it in with DOM calls and `textContent` only, so what sites wrote into
  headers and bodies stays text (a test runs it over a stand-in DOM in node); it is not cached
  (`no-store`). Pages still go through Safari: its history may keep the URLs of
  the flow pages viewed, and the first link with the token (useless without the
  device; it lasts until `ui-token` is deleted), and the URLs of searches, with
  what was searched (with `--no-redact`, a search for a secret's value keeps it
  there). A JSON body nested deeper than 32 levels is
  shown as it is, not indented (indenting deep nesting takes memory that grows
  with the square of the depth).

The token appears only in `run`'s terminal, as the login URL does: never in the
MCP tools.

## mitmweb (`--web`)

mitmweb listens on 127.0.0.1, with a password kept in `web-token` in the state
directory (0600; the same at each start until you delete that file and start
again) and passed through a 0600 file, never the command line. A link with it
(`?token=`) opened by a browser through the node is answered, once mitmweb
accepts it, with a redirect to the same URL without it (a test, with a stand-in
for mitmweb), so the password does not stay in the address bar; whether
Safari's history keeps the first URL is not checked. `run` prints the links with
the tokens on its standard error: in the terminal's scrollback, and in a file if
you send it there, they stay valid until the token files are deleted. mitmweb's
cookie does not outlast its restart (it signs it with a key made at each start,
from reading its code), so after one the link is needed again. The node also relays
its port 8081 to it for your own devices on the tailnet (the same user, untagged:
not a `--device` device of another user, nor anyone else; checked when a
connection opens and on every request, by the node's name or address in `Host`).
The password still guards it, and it gives what it gives on this computer: with
it, mitmweb's options can be changed (scripts included), which runs code on this
computer. The link with the password is printed in `run`'s terminal only. A phone on the
Remote Proxy reaches it the same way (its requests and WebSocket tunnels to the
node's port 8081 go to mitmweb, for your own devices only). A WebSocket already
open stays open if the device stops counting as yours. Tried from an iPhone on
the exit node. It shows traffic **unmasked**, and
from its page anyone with the password can edit and replay requests and change
options. It shows bodies up to 2 MB each (Reqcove gives it them,
as mitmproxy keeps no body it streams), whole and unmasked, and keeps the newest
10,000 flows and 256 MB of bodies. It shows every flow mitmproxy decrypted, including requests to hosts
outside `--allow-hosts` that rode on an allowed connection (HTTP/2 connection
reuse): the per-request check keeps those out of Reqcove's records only.

What its options change (from reading code, not tried): mitmproxy's behaviour
only, until reqcove starts it again. Reqcove's records stay scoped to
`--allow-hosts` and masked, since Reqcove checks both again as they arrive.
Turning off the SOCKS proxy in its Capture tab stops the devices' HTTP(S)
(that is how Reqcove hands them to mitmproxy). Another mode turned on there
listens on 127.0.0.1 (the listen host reqcove sets) and bypasses Reqcove's
device names and its refusals of this computer and the LAN.

## MCP over HTTP (`--mcp-http`)

The node serves the MCP tools on its port 8090, at `/mcp`, to your
own devices on the tailnet only (the same user as reqcove's node, neither
tagged: checked when a connection opens and on every request), asked by the node's name or address in
`Host`, and with `Authorization: Bearer` and the token kept in `mcp-token` in the
state directory (0600; compared in constant time). Requests from a browser page
of another origin are refused. The token is printed in `run`'s terminal only (in
a container, `docker logs` keeps it), never by `reqcove status` or the tools:
agents may run those. On a personal tailnet an agent's device joined through
Tailscale's OAuth apps (Grok Bot) counts as one of your own devices, as do your
other computers: the token is what tells them apart. Whatever the tools answer
then reaches that device and its model provider (for Grok Bot, xAI's cloud),
and the agent keeps the token until you delete `mcp-token` and restart `run`.
The tools are the same as over `reqcove mcp`, and give the same masked records.
`run` logs each tool call over HTTP with the calling device and the tool's
name (not its arguments), and each request with no token or a wrong one.
Each device may call about 10 times a second (30 at once); past that it gets
`429 Too Many Requests` for the moment, logged once a minute (a test): a
runaway agent on one device does not keep `run` busy for the others. A call
ends when its caller disconnects (a test).
Checked with tests (another user's device refused over a real tailnet; the
token, `Host` and origin checks), from this Mac over the tailnet, and with
Grok Bot.

## The local proxy (`--local-proxy`)

An HTTP proxy on 127.0.0.1:8082 for this computer's own apps (the
iOS Simulator), with no password: any process on this computer, of any user, can
use it, and what it sends to `--allow-hosts` hosts is recorded as the device
`local`. Its apps reach the LAN, VPNs and the tailnet as they would without it,
by this computer's own lookups. It refuses IPv6, and a name that leads to this
computer itself (loopback, its own addresses) or to a link-local address unless
this computer's `/etc/hosts` gives it (a test): a page in a browser here could
otherwise reach this computer's services through it by pointing its own name
there (DNS rebinding). A page could still point its name at a LAN, VPN or
tailnet address, and the proxy lets it on (so that names inside a VPN keep
working). A browser going direct faces the same, but through the proxy it does
not see the address, so its own protection for private networks (Chrome's
Private Network Access) does not apply: keep `--local-proxy` on only while you
need it. This computer, the LAN and the tailnet are
in the system proxy's exceptions, so apps reach them directly, as without
reqcove. Apple's hosts are not decrypted. On macOS, `run` points the system's web
proxies at it while it runs, keeping what they were in the state directory
(0600) to put back when it stops (also on SIGHUP), at the next start, or with
`reqcove cleanup`; it never saves over settings not put back yet, and cleanup
will not delete the state while it holds them. If reqcove is killed outright,
apps here that use the system proxy cannot connect until they are put back.
Reqcove never makes this computer trust its CA; `run` prints the command (TLS
only, for this user). Once trusted, the CA's private key in `<state>/mitmproxy/`
can impersonate any HTTPS site to this computer too, not only to the devices:
keep the state directory, and its copies and backups, private, and remove the
trust when done (`reqcove status` and `cleanup` print how, by its fingerprint).
Tried with the real `networksetup` (set, and put back at Ctrl-C) and an iOS 27
Simulator.

## Other processes on this computer

mitmproxy's SOCKS5 port is on 127.0.0.1, protected by a password made at each
start (kept in a 0600 file, never in process arguments). Only reqcove knows it, so
another local process can neither use the proxy nor pose as a device. When
mitmdump dies, reqcove starts it again on the same port (visible in `ps`), and
meanwhile another user's process on this computer could take the port. The
devices' connections then wait (15 seconds at most, then fail) until the new
mitmdump's addon says hello, which mitmproxy (12.3.1) does only once it
listens: one that cannot bind the port exits first, and is started again.
Tests: while another process holds the port, the restarted mitmdump never
becomes ready, and comes back once the port is free; while it is not ready, no
connection is sent to the port. One gap remains, from reading code: between
mitmdump's death and reqcove noticing it (milliseconds), a connection can
still be sent to the free port; whoever took it in that moment would get the
SOCKS password and that connection: plain HTTP readable, HTTPS not. On a
computer shared with users you do not trust, keep that in mind.

The state directory is checked itself, not the directories above it. Keep it
(and `--state`) under directories only you can write: someone who can rename
entries in a parent can swap the state directory for their own.

## mitmproxy's own code

mitmproxy and its dependencies (44 packages) come from a lock file built into
reqcove (`internal/capture/mitm.py.lock`): `run` writes it and a small
launcher into the state directory and starts mitmproxy with
`uv run --locked --script`, which installs exactly the files the lock names
and checks each one's hash (tried: a lock with one package's hashes changed was
refused, with an empty cache and with a full one). Plain `uvx`, which checks no
hash even when given them (tried), is used for another `--mitmproxy-spec`,
and for a `--uvx` whose file is not named `uvx` (a wrapper, whose `uv` is not
known), from releases before a fixed date (`--exclude-newer`). CI
checks that the lock matches the launcher and audits it for known
vulnerabilities (pip-audit); the first audit found three in tornado 6.5.10,
mitmweb's server, which mitmproxy 12.3.1 caps at that version: the lock
overrides it to 6.6, which fixes them (Reqcove's `--web` test passes with it;
mitmproxy's own tests were not run).

## The exit node's DNS

The exit node answers DNS over HTTPS (Tailscale's PeerAPI) for devices that use it.
It also answered this computer, which was not one of `--device`, when tried: other
devices of the tailnet that may use the exit node can resolve names through it.
They ask the same upstream as your devices: `1.1.1.1` by default. With `--dns system`,
or a LAN resolver in `--dns`, that is your router's or your company's resolver, and
they can look up names only it knows. (From reading Tailscale's code: it answers any
peer the tailnet policy lets use an exit node.) Reqcove does not record DNS.

From this computer to the upstream, DNS is plain, unencrypted DNS, for the exit
node and for the Remote Proxy alike, and answers are not checked with DNSSEC
(from reading code). So the network this computer is on (its Wi-Fi, the ISP) sees
the names the devices look up, and someone on that path can answer falsely.
Off the path that is hard: each query has a random ID and its own random port,
and answers from any other address are dropped. A false answer gets little
(from reading code, not tried): HTTPS still has to show a certificate for the
name (mitmproxy checks it for decrypted hosts, the phone itself for the others),
and an answer pointing at this computer, its LAN or loopback is refused like any
connection there (tested). Plain HTTP can be sent elsewhere, as it can on any
network. To hide the names, a local DNS-over-HTTPS relay could serve as
`--dns 127.0.0.1:PORT`; that has not been tried.

## What the devices can reach

Public IPv4 addresses. Reqcove refuses this computer's own addresses (those of every
interface) and the networks those interfaces are on (so a LAN with public addresses,
or a cloud server's subnet with its neighbours, is refused too), loopback, private
and link-local ranges, the tailnet's range, multicast and the other special-purpose
ranges, and all of IPv6, on the exit node and on the Remote Proxy. Public networks
reached only through a route (behind a router, not on an interface's subnet) are
not refused (from reading code). Pings (ICMP echo) follow the same rules: one
from a device not in `--device`, or to a refused address, is dropped (tests send
pings to 127.0.0.1 from both); a listed device's ping to a public address is
answered by pinging from this computer (from reading code).

While a device's UDP flow lasts (2 minutes after its last packet, 30 seconds for
DNS), only the address and port it was sent to can answer through it; datagrams
from anyone else that reach its port on this computer are dropped (a test sends
one from this computer).

What it does not catch:

- **Your network's public address.** It is not an address of this computer's
  interfaces. A device that connects to it may reach what the router forwards
  (port forwarding), or, on a cloud server, this computer. Not tested.

## The login URL

While the node is not logged in, `reqcove run` prints a login URL. Whoever opens it
first puts this node in their own tailnet, so it is printed in `run`'s terminal
only: the `status` tool, and with it the agent and its model provider, says where
to find it but does not carry it.

## Logs to Tailscale

Reqcove's node does not send logs to Tailscale. A tailnet that requires data plane
audit logs is not supported (`reqcove status` says so); Reqcove never turns logs on.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository rather than
a public issue.
