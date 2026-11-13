# Changelog

## Unreleased

### For people

- `--local-proxy` also keeps the tailnet's IPv6 range (`fd7a:115c:a1e0::/48`)
  out of the proxy, as its IPv4 range already was.
- The guide shows which Reqcove tools to allow by name in Claude Code's
  settings, with the preset tools under `ask`; says that Claude Code's `!`
  gets nothing from `reqcove links` (tried), and that `status` over
  `--mcp-http` has no `active_mock_presets`.
- `run --lan`: LAN mode without Tailscale, an HTTP proxy on this computer's
  LAN address for the client addresses you allow (`reqcove lan allow ADDR`,
  or run's question), recorded as `lan:ADDR`; ports 80 and 443 only, private
  hosts only for exact `--allow-hosts` names, never this computer or its own
  network. Refused in `--config`. The ready block says what to enter on the
  iPhone, who is allowed, and the CA's file and SHA-256 (plain HTTP on a LAN
  can be swapped); `reqcove status` shows the allowed and refused addresses.
  README, the guide and SECURITY have a section. Not tried yet with an iPhone
  on a real network.
- Presets of `map_remote`, `modify_headers` (requests only) and `resolve`: a
  rule written as `{rule: "…", preset: NAME}` applies only while an agent turns
  it on, for at most 5 minutes each time, as mock presets. A `map_remote`
  preset sends the app's requests, cookies and tokens to its target: SECURITY
  has a section on what that allows. Targets are shown in the ready block, the
  log, `list_presets` and (the ones on) `reqcove status`; a request a preset
  would send outside its target gets a 502; refused at load: a target that cannot be shown,
  with a user or password, or plain `http://` beyond this computer and the LAN.
  Not tried yet with an iPhone.
- `reqcove mark [TEXT]` puts a marker among the records (a time and a
  checkpoint to read from), in your terminal only; agents put theirs with
  `add_marker`. At most 80 characters on one line, masked; at most 100 per
  source (`cli`, `mcp`: the channel, not proof); in memory only. The guide has
  a section. Not tried yet with an iPhone.
- `reqcove mock add --rules FILE --url URL …` adds a mock to a rules file,
  keeping the file's text, comments and order; refused when `mock:` is not the
  last block or is in flow style. The whole file is checked first by the
  addon's loader (by the running `run`, with its hosts, else by mitmproxy's
  Python, hosts unchecked) and written at once, its mode kept. In your
  terminal only (a help, not a guarantee); `--print` shows the mock without
  writing. The guide has a section. Tried with the tests, not by hand.

### For agents

- The skill: never run `reqcove mock add`; with `--print`, only when the user
  asks.

- The skill's rules example has a mock preset (`preset:`, `description:`,
  `delay_ms`).
- `status` has `mode` (`tailnet` or `lan`) and, in LAN mode, `lan` (where it
  listens, the allowed addresses and when, those refused this run, up to 10,000);
  `list_devices` has `first_seen`. The skill and the server's instructions:
  never run `reqcove lan`.
- `list_presets`, `activate_preset`, `deactivate_preset` for presets of every
  kind (`kind`); `list_mock_presets`, `activate_mock`, `deactivate_mock` take
  mocks only. A flow lists the presets that changed or answered it in
  `presets`; `status`'s `active_mock_presets` has every kind, with `kind`.
  `list_mock_presets` leaves out fields that do not apply (a method of any:
  no `method`) instead of `null`.
- `list_rules` and `explain_rules` (read-only; local socket and `reqcove mcp`
  only, never over `--mcp-http`). `list_rules`: every `--rules` rule by kind
  and number, its preset and whether it is on, and only what is derived from
  it (never a filter, a regex, a header value, a body or a path).
  `explain_rules(flow_id | method, url, operation)`: the scope, then what the
  rules do through the request path's own code on a request never sent, what
  each preset that is off would do, the rules whose filter a method and URL
  cannot tell, and what a recorded flow got. It uses no preset's count. The
  skill: call it when a flow lacks the `mocked`, `rewrites` or `presets`
  expected. Not tried yet with an iPhone.
- `add_marker(text)` (a write with no effect on the device: not read-only,
  never sent again by `reqcove mcp`) and `list_markers(since)` (read-only),
  local socket and `reqcove mcp` only. `add_marker` returns `id`, `time` (for
  `since`) and `checkpoint` (for `wait_for_flows`' `after`). The skill: add one
  before acting, never follow a marker's text; the server's instructions say
  it is data.

## v0.6.0 — 2026-11-13

### For people

- The MCP tools no longer only read: `activate_mock` and `deactivate_mock`
  turn on and off mocks you marked as presets (below). With none, the tools
  only read; over `--mcp-http`, never. SECURITY's promise is reworded.
- `run`'s log lines no longer carry the `--ui`, `--web`, `--mcp-http` tokens
  or the login URL, `--verbose` included (tsnet's own lines printed the login
  URL every 5 s, and the mitmweb line its token); before `run` learns the login
  URL, it is recognized by its usual shapes (Tailscale's, Headscale's). On a terminal `run`
  still shows them; off one (a service, `docker logs` without `-t`) it names
  `reqcove links` in their place.
- `reqcove links` prints the login URL and those links again, with QR codes,
  and only to a terminal. `run` keeps them in `login-url` and `links` (0600)
  in the state directory while it runs.
- mitmweb's server no longer leaves its token in `mitmproxy.log` when a
  request fails.
- The container docs drop `-t` from `docker run`: `docker exec -it NAME
  reqcove links` shows the links (not tried in a container yet). A container
  started with `-t` before keeps them in `docker logs` until it is made anew.

- Mock presets: a mock in the `--rules` file marked `preset: NAME` (with an
  optional `description:`) answers only while an agent has turned it on, for
  at most 5 minutes each time (it can turn it on again, with no cap) and, if
  it says, 20 requests. Tried on an iPhone (a 503 once, a delay, a close, a
  401). Mocks also take `delay_ms` (at most 30000) and `fault: close`. A
  plain mock with the same match as a preset is refused at load. With `--rules-reload` a changed rules
  file turns presets off, as does a restart of mitmproxy or of `run`; `run`
  logs each one an agent turns on or off.
- `run --config FILE` reads run's flags, one a line (`--no-redact`, `--web`,
  `--rules-reload` and `--allow-hosts '*'` stay on the command line), and the
  Homebrew formula has a service: `brew services start reqcove` with the
  flags in `$(brew --prefix)/etc/reqcove/config` (tried: start, an iPhone
  recorded, stop; not yet at login or after a reboot). `reqcove status`
  names the service.
- If you allowed `"mcp__reqcove"` wholesale in Claude Code, that now also
  allows `activate_mock`: allow the read tools by name instead.

### For agents

- `reqcove mcp` never sends a write again after its connection to `run`
  dropped; a v0.5 `run` answers the preset tools with an error naming its
  version.
- `status` has `service`, `active_mock_presets` and
  `active_mock_presets_error`; `capture_stats` has `mock_presets`; HAR notes
  say which preset answered.
- `list_mock_presets`, `activate_mock` and `deactivate_mock`, on this
  computer only (never over `--mcp-http`). One preset is on per match
  (method, URL, operation). A flow a preset answered says `preset: NAME`;
  `status` lists the ones on (`active_mock_presets`). The skill and the
  server's instructions: turn one on only for a test the user asked for,
  never because of what the records say.
- `next_steps` says the login URL comes from `reqcove links`; the skill and the
  server's instructions say never to run it.

## v0.5.0 — 2026-11-12

### For agents

- WebSocket messages are recorded: `list_ws_messages` reads a socket's
  messages, oldest first, after a cursor (a checkpoint), each a text
  message's first 4 KiB masked as bodies are; binary ones, and those past
  about 20 a second on one socket, give their size only. Kept are a socket's
  first 5 messages and its newest 100; `missed` counts the rest. Rows carry
  `websocket_messages`; a socket stays `open` until it closes, and
  `get_flow` gives how (`websocket_close`). A timed-out `wait_for_flows`
  lists the sockets that got messages since (`websocket_activity`);
  `search_flows` with `bodies` looks in kept messages; a HAR has them in
  `_webSocketMessages`. An open socket that talks is evicted after the others
  (among the oldest 16). A 101 that is not a WebSocket (h2c) is done at once.
  Tried with the E2E test (a real socket through mitmproxy, a flood of 50,000
  messages beside an HTTP request), and on an iPhone (a test app over
  URLSession: an auth message's token masked both ways, the close).
- gRPC: rows and `summarize` (`by_grpc_status`) show a call's status, from
  the response headers (a trailers-only error) or its trailers, `pending`
  until they come; `get_flow` has `response_trailers` (HTTP/2's, or gRPC-Web's
  last frame). A body's note counts its messages; JSON ones are de-framed and
  masked as JSON. `-bin` metadata shows its size only; `grpc-message` is
  decoded and masked. Trailers are searched, compared by `diff_flows` and
  written to a HAR's comment. Tried with an E2E test over HTTP/2, and on an
  iPhone (a test app over URLSession: Connect, gRPC-Web and gRPC to
  Connect's demo server, with `--proto`; gRPC's answer showed nothing there:
  fixed after, by a test). A Connect stream's last frame (flag 2: its error,
  as JSON) is shown as `[end of stream]`, masked (by a test only).
- Protobuf bodies (gRPC's messages, `application/x-protobuf` and the like) are
  handed out as reqcove's rendering (`view`): without a schema, their
  structure (field numbers, types, lengths, a string's length, numbers in
  responses, only small ones in requests); with `--proto FILE` (a compiled
  schema), as JSON with their field names, masked by name. The type comes
  from the method in the path (gRPC, gRPC-Web, Connect, Twirp) or
  `messageType` in the content type. A body that does not read as protobuf
  to its end shows nothing. `diff_flows` never calls two structures, nor
  lengths-only values, the same. Tried with tests and a fuzz test (of the
  reading without a schema).
- `multipart/form-data` bodies (uploads) are handed out, part by part: a
  secret-named part masked whole, text parts masked as bodies, files and
  parts that are not text by their size only. Before, they were left out as
  "not text". Tried with tests and an E2E test (Go's multipart writer).

### Masking

- Token shapes (JWTs, keys with known prefixes, `Bearer …`) are found behind
  percent-encoding too: JSON encoded in a form field or a URL parameter,
  `Bearer+…` (before, the shapes needed a word boundary that `%22` and `+` do
  not give).
- A `name: value` line with a secret name, in a text body that is not a
  GraphQL document or in a JSON string (a STOMP frame's `passcode:`, also in
  SockJS's JSON; a YAML mapping), has the rest of the line masked.
- Base64 of a JSON object with a secret in it, as a URL parameter or form field
  (AppSync realtime's `?header=`), is masked whole; so is a credential carried
  in `Sec-WebSocket-Protocol` (`access_token, …`, AppSync's `header-…`,
  Kubernetes' bearer prefix).
- Bodies of JSON under other content types (`application/x-amz-json-1.1`, as
  Cognito and Amplify send, any type naming `json`) and Sentry envelopes are
  handed out when they hold no control characters; before, they were masked
  but left out as "not text".

### Inside

- Cursors (checkpoints, `next_cursor`, `after`) count in microseconds, so a
  run handing out many (WebSocket messages take one each) cannot reach the
  next run's, which would make old cursors look current. A line from the
  addon that masking fails on is counted as a bad line instead of stopping
  `reqcove run`.
- A GraphQL request's operation is read by its keys' exact case, as mocks
  read it (`OperationName` is not it); in a head cut before its end, only a
  top-level `operationName` counts, not one nested in variables. Mocks no
  longer take a no-break space for GraphQL's space, as the row does not.

## v0.4.0 — 2026-11-12

### For agents

- Response mocks: a `mock:` rule in the `--rules` file answers a request
  (method, URL exact or by prefix, GraphQL operation) with a status, headers
  and a body (inline or a file, at most 1 MiB), before `map_remote` and
  `map_local` (request `modify_headers` rules apply first); the
  request is not sent to the server (for HTTPS, mitmproxy may have connected
  to it already, to read its certificate). One it would have to hold but
  cannot (a length over 1 MiB, a POST of unknown length) goes on, its
  `rewrites` saying `mock: skipped, …`. Its row says `mocked: true`, `rewrites` gives
  `mock[i]: status` (never the rule's text), a HAR notes it, `summarize`
  counts them. `Cache-Control: no-store` unless the rule sets one. Hosts in
  `--allow-hosts` only. `capture_stats.rules_loaded` says when the file was
  last taken. Tried with the E2E tests, and on an iPhone (Safari; one GraphQL
  operation of the GitHub app).
- `summarize` counts by endpoint (`by_endpoint`): method, host and path
  without the query, with segments of digits only or a UUID as `{id}`, then
  a GraphQL operation (`POST api.example.com/graphql Login`).
- Rows (`list_flows`, `search_flows`, `wait_for_flows`) and `get_flow` carry
  a GraphQL request's `operation`, as mocks read it: the URL's
  (`?operationName=`, else the `?query=` document's), else Apollo's
  `X-APOLLO-OPERATION-NAME` header, else the body's (`operationName`, else
  its document's first operation); `(anonymous)` or `(batched)`; a name GraphQL does not allow is not shown. A filter
  `operation` selects them. Worked out from the masked request as it arrives.

### Masking

- GraphQL documents are read by a lexer instead of a pattern. An argument, an
  input object's field or a variable's default whose name is secret has its
  whole value masked: a string, a number, a list or an object
  (`pin: "[redacted]"`), as a JSON field's is; enums, booleans, `$variables`
  and aliases stay. Documents are found where a JSON string at depth 0 or 1
  (any key, requests and responses), the body or a URL parameter starts like
  one; a GET `?query=` is masked and escaped again rather than replaced. One
  that cannot be read is masked whole. Before, variable defaults, lists,
  numbers, quotes written `\u0022` and responses without a trigger word passed.
  A second fuzz test writes documents from a small grammar.
  A `name: "value"` outside a document (prose, a script's object, an error
  message quoting part of a query) is no longer masked: the pattern caught it
  in requests, and in responses with a trigger word.
- A field with a secret name whose value is a list or an object is masked
  whole (`{"password": "[redacted]"}`; cut by the head's end, to the end).
- A URL in a form's first field is looked into, as the other fields are.
- A URL parameter's value goes on after `\/` and Gson's `\u0027` and
  `\u003d` (before, what followed was left).
- A string cut by the head's end is read with its escapes undone (`\u`
  escapes, a cut one dropped), as a whole one is.
- The fuzz test checks every 5 characters of the secret, as written and
  decoded, at every cut, in 21 shapes (it checked the whole secret at one cut).

### Inside

- Masking happens before the Store's lock is taken: an event's URLs,
  headers and error text, and a body's head (the lock is held only to read
  its content type). Tools no longer wait while a body is masked: with 64 KiB
  JSON bodies arriving back to back, a `list_flows` and a `get_flow` waited
  12 ms at the median (17 ms at the 99th percentile) before, 6 µs (95 µs)
  after (`BenchmarkToolsWhileIngesting`, this Mac). A body whose flow was not
  there when it was masked is dropped as an orphan, as before.

## v0.3.0 — 2026-11-11

### For agents

- `wait_for_flows`: read what an action on the device sent. Take `checkpoint`
  from `list_flows` (or `capture_stats`) before acting (a tap through RoamRun,
  or the user), then wait with `after: checkpoint`: the flows answered since
  come oldest answer first, as soon as there is one, each once across calls
  (pass the answer's `after` on), even when they finish out of order; one that
  never ends (SSE, a long poll) holds nothing up. Up to 30 seconds a call, 16
  waits at once (4 for one `--mcp-http` device); an `after` no checkpoint gave
  is refused; flows evicted unread are said at once (`evicted`). Tried with one iPhone (Safari, httpbin.org) acted on through
  RoamRun, on the Mac's Wi-Fi and from another network (tethering).
- `diff_flows`: two flows compared (one that worked, one that failed): method,
  URL, status, error, headers by name, bodies (JSON by path). Values masked on
  both sides are listed as masked, never as equal; bodies that are not text
  are not compared while masking is on; with `--no-redact` everything is. JSON
  numbers are compared as written (IDs past 2^53 too).
- `get_flow` takes `max_body`, at most that many bytes of each body head.
- Every tool is marked read-only and not destructive (`readOnlyHint`,
  `destructiveHint`). `run` prints Codex's command to add the tools beside
  Claude Code's; the guide says how to allow the tools in each, and not to
  allow a shell or network tools along with them.
- The skill covers `wait_for_flows` and `diff_flows`: run `reqcove init`
  again to update it.

### Masking

- `--mask-names a,b`: your own names treated as secret (headers, parameters,
  JSON fields, GraphQL arguments; any spelling). `--mask-values RE`: a
  pattern's matches masked wherever they are (the `key=…` seen in a bank app's
  User-Agent; a literal secret in a file goes as `\Q…\E`). Both `@FILE` too;
  errors never quote a pattern; `capture_stats` counts the matches.
  `--mask-names` matches the whole name (`clientRef` is not `X-Client-Ref`).
  `--mask-names` tried on an iPhone's flow (URL, JSON body, Referer);
  `--mask-values` by tests only.
- String arguments with secret names in GraphQL documents
  (`login(password: "…")`, in JSON, raw, or a GET `?query=`), and URLs encoded
  twice or three times inside a parameter. A fuzz test found the latter, and a
  GraphQL value cut after a backslash; a review found the query's own escaped
  quotes and block strings written inside JSON. GraphQL's GET variables
  (`?variables={"password":…}`), JSON in a URL parameter, are looked into too
  (they were not in 0.2 either, also after a space), as are arguments after a
  line break or a `#` comment (before the colon too), escaped `"""` in block
  strings, queries echoed back in responses, escaped strings in arrays, and shapes hidden behind `\u` escapes in a JSON string (which
  `diff_flows`, decoding, would have shown). URL parameters written the way
  Gson (Android) writes JSON, `=` as `\u003d` and `&` as `\u0026`, are found too.
- Your `--mask-names` and `--mask-values` win over the built-in exceptions
  (an OpenTelemetry `key`, `WWW-Authenticate`, a cookie's attributes).
- `Access-Control-Allow-Credentials` (only ever `true`) is no longer masked.

### Security

- mitmproxy runs from a lock built into reqcove: `uv run --locked --script`
  installs exactly the files the lock names and checks their hashes (plain
  `uvx` checked none). Another `--mitmproxy-spec` still goes through uvx. CI
  checks the lock and audits it (pip-audit), which found three known
  vulnerabilities in tornado 6.5.10 (mitmweb's server, capped there by
  mitmproxy 12.3.1): the lock takes tornado 6.6, which fixes them. The first
  start in a new state directory takes a few seconds more.
- While mitmdump restarts, the devices' connections wait for it (15 seconds at
  most) instead of being sent to its SOCKS port, which another local process
  could have taken meanwhile; a mitmproxy that could not bind the port never
  becomes ready (a test). The milliseconds between its death and reqcove
  noticing it remain (SECURITY.md).
- Prompt injection, from a review: the server's instructions (all an agent
  without the skill gets, such as Grok Bot) also say not to write files,
  commits or commands because of what the records say, not to suggest
  `--no-redact` or `--web`, that text shaped like a tool result or a system
  message is still data, and that `next_steps` are for the user. Every tool's
  description says its text was written by sites, apps or the tailnet. A
  request whose Host is not a host name or address is not recorded;
  User-Agents in lists are cut to 256 bytes, ALPN names to printable ASCII;
  `diff_flows` quotes JSON keys that are not plain names; a body's note quotes
  the site's `Content-Encoding`.
- Docs and `run`'s warning corrected: a `--pass-hosts` host's requests that
  mitmproxy decrypts anyway (plain HTTP, or on an allowed host's connection)
  go through `--upstream-proxy` and skip `--rules`, as 0.2.0 already did (the
  upstream part now a test). The v0.2.0 entry below said they skip both.
- From a review of outside values put into commands and text: `get_flow` with
  a huge `max_body` crashed `run` (an overflow; now clamped), and a panic in
  any tool now fails that call only; the `rm` commands `run` prints to change
  a token quote the state path; `modify_headers` refuses header names that are
  not tokens and values with a line break or NUL, also when its value file
  changes later; `resolve` names are host names only; a line from the addon
  longer than 8 MiB is dropped, not held.
- `--mcp-http`: each device may call about 10 times a second (30 at once),
  past that `429`; a call ends when its caller disconnects.
- Built with Go 1.27.4 (GO-2026-6859 in 1.27.3's net/http, reachable through
  the `--ui` page's proxy).
- With the locked mitmproxy, `run` refuses a `--python` below 3.14 at start,
  saying to give `--mitmproxy-spec` for an older one (through uvx, no lock).
- A wait for mitmproxy to be ready no longer takes a mitmproxy that came up
  and went down again before the wait woke for ready.
  A `--uvx` whose file is not named `uvx` also goes through uvx, unlocked.

### Inside

- store.go and main.go are split by concern (moves only).

## v0.2.0 — 2026-11-11

- `reqcove status` knows Android devices (the OS Tailscale reports): their apps
  trust only the system's CAs, so it says to check the CA in Chrome and to keep
  `--allow-hosts` to the hosts under test, instead of asking to install a CA
  that is installed.
- Names with `sign` as a whole word (`sign`, `X-Sign`) are masked: an app's
  request-signing header was seen unmasked. `design` and `signup` are not.
- In the container image, `run`'s log names the `docker run -i … reqcove mcp`
  command for Claude Code, not `reqcove mcp` inside the container.
- `run --mcp-http`: the MCP tools over HTTP on the node's port 8090, for agents
  on your own devices on the tailnet (Grok Bot, through Tailscale's OAuth apps),
  with a token `run` prints. Stateless: agents go on across restarts of `run`.
  `run` logs each call over HTTP: the device and the tool.
- The MCP server gives clients short instructions (the skill's rules), for
  agents without the skill. `capture_stats` has `started`, and a cursor from
  before a restart of `run` is refused instead of paging the new records.
- The README is shorter: what Reqcove does and how to start. Every option and
  the details (rules, `--ui`, the Simulator, HAR, an upstream proxy, pinning,
  the skill, more limits) moved to `docs/guide.md` (and `guide.ja.md`).
- `run --ui`: a read-only page of the flows on the tailnet node, opened from a QR
  code: your own devices on the tailnet see every device's flows, a `--device`
  device of another user its own. It follows new flows without reloading.
- `run --web`: mitmweb also opens from your own devices on the tailnet, on the
  node's port 8081, with the link `run` prints. It now shows bodies (up to 2 MB
  each; before, none: they stream past mitmproxy), and keeps the newest 10,000
  flows and 256 MB of bodies instead of every flow.
- The `--ui` and `--web` links stay the same across starts (their tokens are
  kept in the state directory; delete `ui-token` or `web-token` to change one).
- `run --upstream-proxy http://HOST:PORT` (and `--upstream-ca FILE`): decrypted
  requests go on through Burp Suite or another HTTP proxy, which sees the same
  traffic while Reqcove keeps its records. See "An upstream proxy" in docs/guide.md.
- Burp's CA is fetched from the proxy's own `/cert` at start when the proxy is on this
  computer, so `--upstream-ca` is needed only for other proxies that decrypt.
- `run --local-proxy`: an HTTP proxy on `127.0.0.1:8082` for this computer's own
  apps, such as the iOS Simulator, recorded as the device `local`. On macOS the
  system's web proxies point at it while `run` runs and go back when it stops,
  and the CA goes into the booted Simulators; on Linux, point apps at it.
  `run` prints how to have this computer trust the CA too (its own browsers'
  requests to allowed hosts are then recorded), and `status` and `cleanup` how
  to stop.
- `reqcove har > flows.har`: the recorded flows as a HAR 1.2 file, masked, with
  the same filters as `list_flows`.
- `run --rules-reload`: the `--rules` file is read again when it changes; a
  file that does not load leaves the rules before it, and says why.
- `reqcove help` (also `-h`, `--help`) shows the commands.
- A build from source is versioned by its commit (`dev-77e6706`, `-dirty` with
  uncommitted changes) instead of `dev`, so `reqcove mcp` can tell a `run` of
  another build and say to reconnect.
- `run --pass-hosts HOSTS` (and `@FILE` for it and `--allow-hosts`, one host
  a line): allowed hosts carried undecrypted, for apps that refuse Reqcove's
  certificate there (certificate pinning). Only their connections are recorded (host, server,
  times, bytes; the new tool `list_passthrough`), no URL or contents; a host
  filter naming one says so in a `note`. `reqcove status` names hosts a
  device refused again and again while accepting the CA elsewhere, with the
  `--pass-hosts` to add. They skip `--rules` and `--upstream-proxy` (`run`
  warns).
- `reqcove init`: the agent skill (`skills/reqcove/SKILL.md`, carried in the
  binary) into `~/.claude/skills` and `~/.agents/skills` for the agents found
  in `~` (or `--client`); it updates only its own unchanged file, and leaves
  others' skills, edited ones and links alone. `reqcove status` and `run` say
  when an installed one is from another version. The `status` tool now lists
  `allow_hosts`.
- A container image (`Dockerfile`, distroless, not root), built from the
  repository: one container and volume per environment, the agent through
  `docker run -i … reqcove mcp` ([docs/container.md](docs/container.md)).
  `scripts/container-smoke.sh` checks it without a tailnet login; CI runs it.
- `reqcove mcp` serves the tools itself and forwards each call to `run`,
  dialling it again when needed: the agent stays connected while `run`
  restarts (before, the relay ended with it, and Claude Code needed `/mcp`;
  tried in a Claude Code session).
  While `run` is not running, the tools say so; the first answer after a
  restart says flow ids and cursors from before it are gone, and one from a
  `run` of another version says to reconnect the agent. When `run` stops,
  the agents' connections to it close at once.
- Names containing `ticket` (a WebSocket's `wsTicket`, seen unmasked) or
  `dpop` are secrets too; `ticket_id` and `ticketNumber` are not.
- A body's `"key"` holding a dotted lowercase name (OpenTelemetry's
  `{"key": "service.name", …}`) is no longer masked: the attributes' names
  were lost (seen by Claude Code reading an app's traces). Mixed case, no
  dots, JWTs, and `key=` in URLs are still masked.
- `list_flows`, `search_flows`, `summarize` (and `reqcove har --user-agent`)
  filter by text in the User-Agent, case-insensitive: one app's traffic, as
  summarize lists the User-Agents. A host filter that matches no flow answers
  with `similar_hosts`, recorded hosts that look alike (`acme-shop.com`
  for `acmeshop.com`). The host filter takes a URL, a port or a final
  dot too, and Unicode names (as punycode). `list_tls_failures` takes only
  device, host, since, until and limit (before, status and method were
  accepted and matched nothing: a failed handshake has no response).
- Several exit nodes on one computer, one `run` per `--state`
  ([docs/several-exit-nodes.md](docs/several-exit-nodes.md)): a `--state`
  directory named `reqcove-NAME` names the node so, and the name is kept in it
  (`node-name`; a directory an older reqcove used keeps `reqcove`), one without
  a CA gets a copy of `~/.reqcove`'s (listed in `~/.reqcove/ca-copies`, named
  by its `cleanup`), mitmweb takes 8091-8099 on this computer while 8081 is
  taken (the node's port stays 8081), the `--ui` page shows the node's name,
  and the commands reqcove prints for the node carry `--state`. A second
  `--local-proxy` stops at once, before anything changes.
- `--hostname` is kept in the state directory: the next runs, and `cleanup`,
  use it without the flag.
- Every command refuses a `--state` starting with `~` (`--state=~/x`, left
  unexpanded by the shell).
- A `~/.reqcove` holding only a `mitmproxy/` folder with a CA copied from
  another computer is taken as a state directory (README, Tips); before,
  `run` refused it.
- A CA's key (`mitmproxy-ca.pem`) is never replaced: certificate files
  missing beside it are written again from it at start.
- `--dns 1.1.1.1` works without the port (53).
- `--allow-hosts` takes pasted URLs and host:port, using the host (and says so);
  `.example.com` is refused with the right spelling, `*.example.com`.
- Without `--device`, `run` suggests your iPhones and iPads on the tailnet (from the
  Tailscale CLI, when there is one), and it prints the `claude mcp add` command.
- The exit node approval step says how to skip it next time (`autoApprovers` in
  the tailnet policy).
- A request a `--rules` rule fails on (such as a `map_remote` making a bad port)
  is answered with a 502 instead of going on unrewritten.
- `resolve` and `--upstream-proxy` are refused together: Burp connects by the
  name, so a `resolve` rule would not apply. A `map_remote` whose replacement
  cannot work (a missing group) stops `run` at start.
- Dependencies: klauspost/compress v1.20.2 (GO-2026-6865), golang.org/x/net
  v0.62.0.
- CI runs every end-to-end test, `staticcheck` and `govulncheck`.

## v0.1.0 — 2026-11-08

First release.

- An iPhone's HTTP(S), through a Tailscale exit node (or the Remote Proxy), is
  decrypted by mitmproxy for the hosts in `--allow-hosts` and handed to AI agents
  over MCP. Secrets are masked as they arrive; records stay in memory.
- `reqcove status` and the `status` tool say what is left to do (login, Tailnet
  Lock, approval, the CA); `run` shows a QR code for `http://mitm.it`.
- Rules: `map_remote`, `map_local`, `modify_headers` (mitmproxy's syntax),
  `resolve` and `keep_host_header` (Reqcove's).
- macOS (Apple silicon, signed and notarized) and Linux (amd64, arm64) binaries;
  Homebrew: `brew install mh-mobile/tap/reqcove`.
