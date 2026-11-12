# Reqcove guide

[日本語](guide.ja.md) · [README](../README.md)

What comes after the README's four steps. Each section ends with what was
tried and what was not.

1. [Set up](#set-up)
2. [Read the traffic with an agent](#read-the-traffic-with-an-agent)
3. [Look at the flows yourself](#look-at-the-flows-yourself)
4. [Record clients other than iPhone apps](#record-clients-other-than-iphone-apps)
5. [Change where requests go](#change-where-requests-go)
6. Reference: [Options](#options) · [MCP tools](#mcp-tools) · [Limits](#limits) · [Security](#security)

## Set up

The four steps are in the [README](../README.md#use).

### First start

`run` prints what is left to do, and `reqcove status` repeats it: log in with
the URL, sign the node if the tailnet uses Tailnet Lock, approve the exit node.

- Only `run`'s terminal shows the login URL: whoever opens it first puts the
  node in their own tailnet ([SECURITY](SECURITY.md#the-login-url)).
- To skip the approval for new nodes, add an auto-approver to the tailnet
  policy: `"autoApprovers": {"exitNode": ["you@example.com"]}`.

### Use one CA on two computers

The CA lasts as long as the state directory. Copy `~/.reqcove/mitmproxy/` whole
(it holds the private key) into `~/.reqcove/` on the other computer, with
reqcove stopped there, or before its first run.

### Stop, restart, update

- **Stop** with Ctrl-C. The records are in memory and go with it. If the
  iPhone's DNS then stays stuck
  ([tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)),
  turn its exit node off and on again.
- **Restart**: while `run` is down, `reqcove mcp` stays up and the tools answer
  that it is not running; then they work again without reconnecting the agent
  (`/mcp` in Claude Code). The records start empty, and the first answer's
  `note` says so.
- **Update** (a newer version: `brew upgrade reqcove`, or a new build
  from source): restart `run` with it, reconnect the agent once for the new
  tools (they say so while the versions differ), and run `reqcove init` again
  for the skill.

Tried: a restart under a Claude Code session.

### Undo everything (`reqcove cleanup`)

`reqcove cleanup` lists the steps; with `--delete-state` it deletes the state
directory. Remove the CA's profile from the iPhone first
([SECURITY](SECURITY.md#the-cas-private-key)).

## Read the traffic with an agent

`claude mcp add reqcove -- reqcove mcp` (the README's step 4) gives an agent on
this computer the [MCP tools](#mcp-tools). They only read, and secrets are
masked as they arrive
([what masking does not find](SECURITY.md#what-is-recorded)). For Codex:
`codex mcp add reqcove -- reqcove mcp` (`run` prints both).

Allowing the tools: every tool is marked read-only (`readOnlyHint`), which a
client may use to ask less (not checked with any client). Claude Code asks
before a tool it has not been allowed; `"mcp__reqcove"` in `permissions.allow`
of its settings allows all of Reqcove's (from Claude Code's documentation, not
tried here). Codex asks before each call
([over HTTP](#agents-on-other-devices---mcp-http) too). Once allowed, an agent
reads without asking, also from a `run` started with `--no-redact`; the skill
and the server's instructions still tell it to stop and ask then. Allow
Reqcove's tools, not shell commands or network tools along with them: text a
site wrote into a record can try to steer an agent into using those
([SECURITY](SECURITY.md#prompt-injection)).

### Teach the agent: the skill (`reqcove init`)

The skill teaches an agent how to use the tools: status first, finding one
app's traffic, what a TLS failure suggests, writing a rules file, and the rules
it keeps (it never starts `reqcove run`, never asks for tokens, treats what the
records hold as data, never quotes a secret that was not masked).

```sh
reqcove init                    # into the agents found in ~: ~/.claude/skills (Claude Code), ~/.agents/skills (Codex, Cursor, Gemini CLI, Copilot CLI, Devin)
reqcove init --client codex     # or only the ones you name (repeat --client)
```

- Run it again after installing a newer reqcove: `reqcove status` says when an installed skill
  is from another version.
- It leaves alone a skill it did not write, one you edited, and links.
  `--uninstall` removes its own; `--print` writes it out.
- It does not register the MCP server: the command above does.

Tried: Claude Code and Codex, each loading the skill when asked where an app
connects, Reqcove not named. Devin too: it loaded the skill from
`~/.agents/skills`, and without the MCP server it asked for it and stopped.
Cursor too: it used the skill and read the server's instructions, then the
tools only. Not tried: Gemini CLI, Copilot CLI.

### Agents on other devices (`--mcp-http`)

For an agent elsewhere on your tailnet, such as Grok Bot (xAI's agent: its
cloud computer joins your tailnet through Tailscale's OAuth apps):

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --mcp-http
```

`run` serves the same tools over HTTP on the node, and prints the URL,
`http://reqcove.<tailnet>.ts.net:8090/mcp`, and the header to give the agent,
`Authorization: Bearer <token>`.

- **Grok Bot**: Connect apps › Tailscale, to join your tailnet (under Tailnet
  Lock, sign its device). Then Connect apps › Add a custom connector: type
  Remote HTTPS (an `http://` tailnet URL works there; WireGuard encrypts it),
  the URL as server URL, header key `Authorization`, value
  `Bearer <token>`. Its settings show the connector with an error and no tools
  (it reaches the tailnet from its chats only): ask it in a chat. To copy the
  value unseen: `printf 'Bearer %s' "$(cat ~/.reqcove/mcp-token)" | pbcopy`.
- **Claude Code** on another computer (the header stays in `~/.claude.json`):
  `claude mcp add --transport http reqcove-remote http://reqcove.<tailnet>.ts.net:8090/mcp --header "Authorization: Bearer <token>"`
- **Codex** on another computer, the token in that variable:
  `codex mcp add reqcove-remote --url http://reqcove.<tailnet>.ts.net:8090/mcp --bearer-token-env-var REQCOVE_TOKEN`.
  Codex asks before each MCP tool call; for `codex exec`, which cannot ask, set
  `default_tools_approval_mode = "approve"` for this server.

What to know:

- Only your own untagged devices on the tailnet can call it, with the token
  ([SECURITY](SECURITY.md#mcp-over-http---mcp-http)). A tagged device is
  refused (`run` logs it once): do not tag an agent's device to restrict it.
- What the agent reads goes to its computer and model provider (for Grok Bot,
  xAI's cloud). To cut it off, delete `mcp-token` in the state directory and
  restart `run` (otherwise the token stays the same), or remove its device
  from the tailnet.
- Restarting `run` needs no reconnecting (calls fail meanwhile); the records
  start empty, and an earlier cursor is refused.
- `run` logs each call's device and tool, not its arguments (`--mcp-http:
  grokbot-user-1 (100.104.0.1) called "list_flows"`), and requests with no token
  or a wrong one. An agent that only says it is checking leaves no line.
- Each device may call about 10 times a second; past that it gets `429` for a
  moment (`run` logs it once a minute).
- Plain HTTP, inside the tailnet's encryption (WireGuard). In a container: the
  same flag, no port to publish, the token in `docker logs`
  ([container](container.md#3-the-agent)).

Tried: Grok Bot (status, flows, bodies; the same chat after a restart of
`run`; `run` in a container); Claude Code (`claude -p`) and Codex
(`codex exec`) on this Mac over the tailnet (each read the status); and a call
from another computer, a macOS VM on the tailnet, by the node's name and by its
address.

## Look at the flows yourself

### On the iPhone (`--ui`)

To watch the flows beside the app that sends them:

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --ui
```

`run` serves a read-only page on the node's port 80 and prints its link with a
QR code. Scan it with the iPhone's camera: Safari opens the list, which follows
new flows every second (split view puts it beside the app). Tap a flow for its
headers and bodies, masked as the MCP tools return them.

- Search matches URLs and headers as you type; "bodies too" adds the kept
  heads of bodies and stops the list following (it walks every record). Filter
  by status (2xx to 5xx, no answer) or, from a flow's page, by host.
- Clear hides the flows so far; "Show all" brings them back. Nothing is
  deleted: the agent still sees them.
- Live/Paused stops and starts following. Scrolled down, the list stays put
  and counts the new flows; tap the count to see them.
- Your own devices on the tailnet see every device's flows; another user's
  `--device` device sees only its own
  ([who else, and the token](SECURITY.md#the-page---ui)).
- The link is the same at each start, so a bookmark should work after a
  restart. To change it, delete `ui-token` in the state directory and start
  again.
- Tailscale must be on; the exit node and the
  [Remote Proxy](#without-the-exit-node-the-wi-fi-proxy) need not be. The
  page's own requests are not recorded.

Tried on an iPhone: opened from the camera, new flows following, search, Clear
and Show all, and reopening the page in Safari after a restart of `run`.

### As a HAR file (`reqcove har`)

While `reqcove run` is running:

```sh
reqcove har > flows.har
```

It writes a HAR 1.2 file, oldest first: the newest 1000 flows by default
(`--limit 0` for all), filtered with `--host`, `--device`, `--since 10m`,
`--until`, `--status 4xx`, `--method` and `--user-agent`.

- It holds what the MCP tools return: masked as it arrived, the heads of bodies
  only (cut ones say so in a comment), no body that masking could not check.
  With `run --no-redact` nothing is masked, and the file's comment says so.
- The file gets your shell's file mode, often readable by other users
  ([SECURITY](SECURITY.md#what-is-recorded)).

Tried: imported into Chrome's developer tools (Network), with the requests,
their headers (masked) and responses. Not tried: Charles, Proxyman. From
reading the spec, no validator run: HAR 1.2's required fields are there.

### In mitmweb (`--web`)

For mitmproxy's own page, which can edit and replay requests:

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --web
```

mitmweb runs instead of mitmdump, on `http://127.0.0.1:8081` (8091-8099 while
another run has 8081: [two addresses](several-exit-nodes.md#ports)) and, for
your own devices on the tailnet, on the node's port 8081, with the link and QR
code `run` prints.

- Nothing is masked ([SECURITY](SECURITY.md#mitmweb---web)). It shows bodies
  up to 2 MB each, and keeps the newest 10,000 flows and 256 MB of bodies.
- The link is the same at each start (`web-token` in the state directory).
  After a restart, open it again: a bookmark without the token asks for it.
- In its Capture tab, leave "Run SOCKS Proxy" on, or the devices' HTTP(S)
  stops. The other modes there are not Reqcove's. Changes last until reqcove
  starts again.

Tried: from an iPhone on the exit node. From reading code, not tried: with
options changed there, Reqcove's records stay scoped and masked.

## Record clients other than iPhone apps

Reqcove decrypts what a client sends through it, once the client trusts
Reqcove's CA. Who trusts it differs:

| Client | What is decrypted | Tried on |
|---|---|---|
| iPhone apps, Safari and apps' web views (Flutter's `dart:io` and React Native too; a web view inside an app that pins its own API) | everything to `--allow-hosts` | an iPhone |
| apps that pin their certificates | nothing: with `--pass-hosts` they work, and only their connections are recorded ([how](#apps-that-pin-certificates---pass-hosts)) | an iPhone |
| Android: Chrome | as on the iPhone | an Android 14 device |
| Android: other apps | nothing: they trust only the system's CAs; your own app can opt in ([how](#android)) | the same, and a sample app |
| a web app in production | what the device and the server exchange (pages, the API its front end calls), not what the server sends on | an iPhone |
| a web app's backend you run | its calls to other APIs, through the Remote Proxy ([how](#a-web-apps-backend)) | a Rails app (Net::HTTP, Faraday) |
| this computer's apps, the iOS Simulator | with `--local-proxy` ([how](#the-ios-simulator---local-proxy)) | Chrome on this Mac; Safari on the iOS 27 Simulator |
| another Mac | as a `--device` on the exit node, with the Tailscale app ([how](#another-mac)) | a macOS 27 VM |
| gRPC apps | their calls and status; the messages' contents not yet ([how](#grpc)) | the E2E test only |

### Apps that pin certificates (`--pass-hosts`)

Apps that pin their certificates refuse Reqcove's, so their requests to those
hosts fail. `reqcove status` names such hosts, with the `--pass-hosts` to start
`run` with; those hosts are then carried undecrypted and the apps work.

```sh
reqcove run --device iphone --allow-hosts '*' --pass-hosts '*.example-cdn.com,api.example.com'
reqcove run --device iphone --allow-hosts '*' --pass-hosts @pass-hosts.txt   # one host a line
```

- For those hosts only the connections are recorded (host, server, times,
  bytes: `list_passthrough`), no URLs or contents.
- Their connections skip `--rules` and `--upstream-proxy`. Requests to them
  that mitmproxy decrypts all the same (plain HTTP, or riding an allowed
  host's connection) are not recorded and skip `--rules`, but go through
  `--upstream-proxy`.
- Pinning checked after the TLS handshake shows nowhere.
- For your own app, use a build without pinning. Android apps refuse the CA
  for another reason ([Android](#android)).

Tried: on an iPhone. That a pass host's decrypted requests go through
`--upstream-proxy`: a test; that they skip `--rules`: from reading code.

### gRPC

A gRPC call is a flow: its path names the method (`/pkg.Service/Method`), and
rows and `summarize` show its status (`grpc_status`: `0` is OK, `16`
UNAUTHENTICATED, …; `pending` until its trailers come), read from the response
headers when there is no message (a trailers-only answer, the usual error),
else from the trailers (HTTP/2's, or gRPC-Web's last frame). `grpc_message` is
decoded and masked. A body's note counts its messages and their sizes;
protobuf messages are not handed out while masking (they are not text), JSON
ones (`application/grpc+json`, `connect+json`) are, one a line, masked as JSON.
Metadata ending in `-bin` (binary) shows its size only.

Apps built on gRPC-core (Google's SDKs among them) trust their own list of
CAs, not the ones the iPhone trusts, so their calls show as TLS failures (from
gRPC's mailing list, not tried). Tried so far: the E2E test, gRPC's shape over
HTTP/2 through mitmproxy (a body over 64 KiB with its status in the trailers,
and a trailers-only error), not an app on an iPhone.

### Android

Apps built for Android 7 and later trust only the system's CAs by default,
not one you install (as a CA certificate, in Settings), unless the app allows
user CAs in its `network_security_config`. On the device tried, Chrome was
decrypted and every other app refused the CA.
`reqcove status` says so for Android devices (from the OS Tailscale reports).

- Keep `--allow-hosts` to the hosts you test: the others pass undecrypted and
  their apps work.
- For your own app, let a debug build trust user CAs in its
  `network_security_config`:

```xml
<network-security-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user" />
    </trust-anchors>
  </debug-overrides>
</network-security-config>
```

Tried: an Android 14 device (Chrome decrypted; every other app refused the
CA), and a sample app, decrypted for the host it named this way in a
`domain-config` and refusing the CA for another; and a debuggable build of it
with the `debug-overrides` above, which got answers from both hosts.

### The iOS Simulator (`--local-proxy`)

The Simulator's apps use this computer's network, which the exit node does not
carry. `--local-proxy` opens an HTTP proxy on `127.0.0.1:8082` instead, and its
requests are recorded as the device `local`:

```sh
reqcove run --allow-hosts api.example.com --local-proxy   # --device too, for an iPhone as well
```

- macOS: `run` points the system's web proxies (HTTP and HTTPS, every enabled
  network service) at it, as Charles and Proxyman do, and puts back what was
  there when it stops (Ctrl-C, `kill`, closing the terminal). It adds Reqcove's
  CA to the booted Simulators (`xcrun simctl keychain … add-root-cert`); one
  booted later needs the command it prints.
- Linux: nothing is changed for you. Point apps at it
  (`HTTPS_PROXY=http://127.0.0.1:8082`) and have them trust the CA.
- Every app on this computer then goes through it. Only `--allow-hosts` hosts
  are decrypted and recorded, but those break in apps here that do not trust
  Reqcove's CA (Safari on the Mac, say).
- After `kill -9` or a crash, apps that use the system proxy cannot connect
  until the next `run` or `reqcove cleanup` puts it back (or you do, in System
  Settings).
- This computer, the LAN, the tailnet (`*.ts.net` too) and `*.local` stay
  direct, as the proxy's exceptions. Names are looked up as this computer does
  (VPNs, split DNS, search domains), not with `--dns`; one that leads to this
  computer itself or a link-local address is refused unless `/etc/hosts` gives
  it ([SECURITY](SECURITY.md#the-local-proxy---local-proxy)).
- Automatic proxy configuration (PAC) and authenticated proxies are left as
  they are.

To record this computer's own browsers too (as `local`, mixed with the
Simulator's) rather than have them warn, trust Reqcove's CA here once: `run`
prints the command, and `reqcove status` and `reqcove cleanup` how to stop.
The CA's key can then impersonate any HTTPS site to this computer too
([SECURITY](SECURITY.md#the-local-proxy---local-proxy)).

- macOS (TLS only; it asks for your password):
  `security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`.
  Firefox may keep its own store. To stop, run the command `reqcove status`
  prints, or delete the CA in Keychain Access (its trust goes with it).
- Debian and Ubuntu: `sudo cp ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/reqcove.crt && sudo update-ca-certificates`.
  Fedora: into `/etc/pki/ca-trust/source/anchors/` and `sudo update-ca-trust`.
- Chrome and Chromium on Linux: `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n Reqcove -i ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`.
  Node: `NODE_EXTRA_CA_CERTS=` that file. Python: the system's bundle once
  updated, not that file alone (it would replace every other CA).

Tried on macOS 27: the trust command and Reqcove's check of it, the hint to
stop, deleting the CA in Keychain Access, Chrome on the Mac opening an allowed
host without a warning, recorded; the system's web proxies pointed at
127.0.0.1:8082 by the real `networksetup` and put back at Ctrl-C, the CA added to the booted
Simulators, and Safari on the iOS 27 Simulator decrypted and recorded as
`local`. Not tried: the address forms in the exceptions, PAC and authenticated
proxies, Linux.

### A web app's backend

A web app's own calls to other APIs (a Rails server calling a payment API)
leave from the server, not the phone: Reqcove sees them only when the server
sends them through it and trusts its CA. For a server on one of your machines
on the tailnet, name that machine with `--device` and point the server at the
node's [Remote Proxy](#without-the-exit-node-the-wi-fi-proxy):

```sh
reqcove run --device dev-server --allow-hosts api.example.com
# on dev-server: both variables (Ruby's Net::HTTP reads http_proxy even for HTTPS),
# and a CA bundle with Reqcove's CA added (cat the system's bundle and mitmproxy-ca-cert.pem)
http_proxy=http://100.x.y.z:8080 https_proxy=http://100.x.y.z:8080 SSL_CERT_FILE=bundle.pem bin/rails server
```

- Its calls are recorded under that machine's name. Nothing on it changes
  but the server's environment.
- Connections to the database or Redis are not HTTP(S) on 80/443: not seen.
- The browser's requests to the app are a different path: from the iPhone,
  `map_remote` sends an allowed host's requests to a development server
  ([Rules](#rules---rules)).

Tried: a Rails 8 app on this Mac as the device, calling an API with Net::HTTP
and with Faraday (without the CA, Ruby refused the certificate and a TLS
failure was recorded; with it, both calls were). Not tried: other clients, a
server on another machine.

### Without the exit node: the Wi-Fi proxy

The node also serves the **Remote Proxy**: an HTTP proxy on its tailnet
address, port 8080 (`--proxy-port`), for the `--device` devices. Instead of
choosing the exit node, the iPhone can set its Wi-Fi proxy (Manual) to it.
Cellular has no proxy setting, so this works on Wi-Fi only.

| | Exit node | Wi-Fi proxy |
|---|---|---|
| through this computer | everything the phone sends (DNS, HTTP(S), other ports) | HTTP(S) of the apps that use the proxy setting |
| the rest | nothing else | straight to the internet from the phone's Wi-Fi, unrecorded |
| cellular | yes | no |
| in the Tailscale app | choose the exit node | stay connected only |

What goes through it leaves for the internet from this computer, as with the
exit node, and names are looked up here.

Tried on an iPhone: Safari's requests were recorded, and sites outside
`--allow-hosts` opened as before.

### Another Mac

A Mac named with `--device` that chooses the exit node in the Tailscale app is
recorded as an iPhone is ([the steps](another-mac.md)). With Homebrew's
open-source `tailscaled` the exit node shows as on, but that Mac's traffic does
not go through it. Tried with a macOS 27 VM. Not tried: that Mac's iOS
Simulator (it should go through with the Mac's own traffic, once it trusts
Reqcove's CA).

## Change where requests go

### Rules (`--rules`)

A YAML file of rules, applied to `--allow-hosts` hosts only. To send an app's
requests to a development server on this computer:

```yaml
map_remote:                     # mitmproxy's syntax, as are map_local and modify_headers
  - "|https://api.example.com/|http://localhost:3000/"
keep_host_header: true          # reqcove's: map_remote keeps the app's Host
```

```sh
reqcove run --device iphone --allow-hosts api.example.com --rules rules.yaml
```

- `map_remote`, `map_local` and `modify_headers` are mitmproxy's, run by its own
  code. Relative paths count from the rules file.
- `map_remote` changes the URL, and with it `Host` unless `keep_host_header` is
  true. Write the schemes, as above: apps send `https`, and a plain server
  cannot answer TLS.
- `map_local` answers only requests whose body is at most 1 MiB and of known
  length; others go on to the real destination (the record says so). An HTTP/2
  GET without a length is answered too, and a body sent with it anyway is held
  whole in memory. Apps and web pages on a `--device` device (or, with
  `--local-proxy`, on this computer) can be the senders, to a host a rule matches: a
  very large body can run mitmproxy out of memory (reqcove restarts it), and the
  devices' traffic stalls meanwhile.
- Read someone else's rules file before using it: rules can send your apps'
  requests, cookies and tokens included, wherever they say.

`mock` answers a request here, with what you write, and the request is not sent
to the server (for HTTPS, mitmproxy may have connected to it already, to read
its certificate): to see how the app takes an expired session or an empty list.

```yaml
mock:                           # Reqcove's own; the first that matches answers, before map_remote and map_local
  - match: {method: POST, url: "https://api.example.com/v1/login"}
    status: 401
    headers: {Content-Type: application/json}
    body: '{"error":"expired"}'
  - match: {url: "https://api.example.com/graphql", operation: Feed}
    body_file: feed.json        # relative to the rules file
```

- `url` matches the URL the app sent without its query, exactly (the host in
  any case), or, ending in `*` after a path (`https://api.example.com/v1/*`),
  any URL that starts with the rest. It takes no query, fragment, user or
  default port (refused: it would never match). `method` and `operation` (a GraphQL
  operation: `operationName`, Apollo's `X-APOLLO-OPERATION-NAME` header, or the
  document's first named operation) are optional. The host must be in
  `--allow-hosts` and not in `--pass-hosts`.
- `status` is 100 to 599 (200 if left out); a body is at most 1 MiB, inline or
  in a file, and none goes with `HEAD`, 204 or 304. `Cache-Control: no-store`
  is added unless you set one. Request `modify_headers` rules apply before
  the match, response ones still apply.
- A request a mock may answer (its method and URL match) is held whole until
  its body is in: one whose length is over 1 MiB, or a POST of unknown length,
  goes on unanswered, its `rewrites` saying `mock: skipped, …`. As with `map_local`, a GET (HEAD, OPTIONS, DELETE)
  without a length is held too, and over HTTP/2 a body sent with it is kept
  whole in memory.
- The record says so: `mocked: true` on its row, `rewrites` with the rule's
  number and status (`mock[0]: 401`), a note in a HAR. `capture_stats` has
  `rules_loaded`, when the file was last taken.

Tried with the E2E tests (real mitmproxy): a 401 with headers for a POST, a
GraphQL operation from the body, a prefix, HEAD, the server never reached, and
rules refused (a bad status, a line break in a header, a missing file, a host
outside `--allow-hosts`). On an iPhone: a 401 for Safari (httpbin.org), and one
GraphQL operation of the GitHub app mocked while its others, on the same
connection, reached GitHub.

`resolve` connects elsewhere and leaves the request as it is, for a staging
server or a new load balancer:

```yaml
resolve:                        # reqcove's: connect elsewhere, Host and SNI unchanged
  - "shop.example.com=203.0.113.10"
  - "auth.example.com=192.168.1.20:8443"
```

- Requests for the name go to that IPv4 address, this computer and the LAN
  included. `Host`, SNI and the recorded URL stay the same, and TLS is still
  checked against the name: the server needs a certificate for it (a local
  HTTPS server without one gets a 502). Plain HTTP is not checked.
- Without a port, the request's is used (the app's, 80 or 443, or the
  `map_remote` URL's). After a `map_remote`, the name is its new URL's host,
  which is then the SNI too.
- The name is still looked up (by the phone, or by this computer for the Remote
  Proxy) and the real server connected first: a name that does not resolve
  publicly, or a server that refuses connections, cannot be redirected.
- Each name must be in `--allow-hosts` and have its own address or port:
  mitmproxy reuses a connection by address.
- Refused: `0.0.0.0/8`, link-local (cloud metadata), multicast, Tailscale's
  100.100.100.100 ([SECURITY](SECURITY.md#rules---rules)), and `resolve`
  together with `--upstream-proxy`.

The file is read when mitmproxy starts: with `run`, and when reqcove restarts
it. `--rules-reload` reads it again once a change has settled, for requests
that start after it; one under way keeps the rules it started with.

- A file that does not load leaves the earlier rules in place, and `run` and
  `reqcove status` say why; but if mitmproxy restarts meanwhile, `run` stops on
  it, as at start.
- Whatever can write the file (an agent included) can then change where the
  devices' requests go, without you restarting anything.

From reading code: a change is read within about two seconds.

### An upstream proxy (`--upstream-proxy`)

To see the same requests in Burp Suite (or ZAP, Charles, …) while Reqcove keeps
its records:

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' \
  --upstream-proxy http://127.0.0.1:8080
```

Decrypted requests go to the proxy (HTTPS in a CONNECT tunnel, plain HTTP as
proxy requests), never straight to the server. The proxy sees everything
unmasked, and Burp keeps it in its project. Turn Burp's Intercept off, or
requests wait in it.

- Hosts outside `--allow-hosts` pass directly, as always; but a request to one
  that rides a decrypted connection to an allowed host (HTTP/2 connection
  reuse) goes through the proxy too, unrecorded. Other protocols to an allowed
  host (MQTT, say) go straight to their servers; over TLS they fail while the
  proxy's CA is in use (the server's certificate is checked against it).
- Burp connects to HTTPS hosts by the SNI's name, looked up again on this
  computer, so the exit node's refusal of this computer and its LAN does not
  cover it ([SECURITY](SECURITY.md#an-upstream-proxy---upstream-proxy)): keep
  `--allow-hosts` to the hosts you test (`run` warns about `'*'`). `resolve`
  rules are refused for the same reason; use the proxy's own overrides (Burp's
  Hostname resolution overrides).
- HTTPS through the proxy is checked against the proxy's CA only: Burp's, on
  this computer, is fetched at start (from its listener's `/cert`); another proxy
  that decrypts (ZAP, Charles) needs `--upstream-ca FILE` (PEM or DER);
  otherwise the public CAs are used (for a proxy that does not decrypt).
- Reqcove connects to the proxy itself and ignores the system's proxy
  settings. But a proxy that points them at itself (Charles, unless its Proxy
  menu's macOS Proxy is off) and `--local-proxy` both claim them, each putting
  back what the other set: with `--local-proxy`, turn that off in the proxy.
- With Burp: plain HTTP shows under the IP address, the name in its `Host`
  header; a request body is held until all of it has come; server-sent events
  to an HTTP/1.1 client fail (to HTTP/2 clients, as iOS apps mostly are, they
  stream); HTTPS to a bare IP address, without SNI, fails (Burp names its
  certificate after the address in a way mitmproxy does not accept). With
  `--web`, a plain HTTP request replayed from mitmweb goes to the proxy itself.

Tried: Burp Suite Community 2026.10, its lookup by the SNI's name included;
Charles 5.0b12 decrypting, with `--upstream-ca` (without it, the record says the
certificate was not trusted). With a proxy other than Burp on this computer,
`run` still asks its listener for `/cert` at start, which fails there and
changes nothing. Not tried: other proxies. From reading code:
other protocols going straight to their servers.

## Options

`reqcove run`:

| | |
|---|---|
| `--device NAME` | a device to carry: machine name, device name (your own untagged devices only), tailnet IP or StableID; repeat for more |
| `--allow-hosts HOSTS` | hosts to decrypt and record: `api.example.com`, `*.example.com` (the domain itself and every subdomain), `'*'` for all, or `@FILE`, one a line (`#` for comments). Without it, traffic is carried but nothing is recorded |
| `--pass-hosts HOSTS` | allowed hosts carried undecrypted, written the same way (not `'*'`): [pinning](#apps-that-pin-certificates---pass-hosts) |
| `--rules FILE` | [rules](#rules---rules) for allowed hosts |
| `--rules-reload` | read that file again whenever it changes |
| `--upstream-proxy URL` | send decrypted requests on through [an HTTP proxy](#an-upstream-proxy---upstream-proxy) |
| `--upstream-ca FILE` | that proxy's CA (PEM or DER) |
| `--local-proxy` | a proxy on `127.0.0.1:8082` for this computer's apps: [the iOS Simulator](#the-ios-simulator---local-proxy) |
| `--proxy-port N` | the [Remote Proxy](#without-the-exit-node-the-wi-fi-proxy)'s port, 8080 by default; 0 turns it off |
| `--ui` | [a read-only page of the flows](#on-the-iphone---ui), on the node's port 80 |
| `--web` | [mitmweb](#in-mitmweb---web) instead of mitmdump: no masking |
| `--mcp-http` | [the MCP tools over HTTP](#agents-on-other-devices---mcp-http), on the node's port 8090 |
| `--dns SERVERS` | the exit node's DNS upstreams, comma-separated, `1.1.1.1:53` by default (the port may be left out); `system` for the first nameserver in `/etc/resolv.conf` |
| `--no-redact` | keep secrets in the records |
| `--mask-names a,b` | mask whatever has exactly this name too (any spelling: `clientRef` is also `client_ref` and `Client-Ref`, not `X-Client-Ref`): headers, parameters, JSON fields, GraphQL arguments; `@FILE` too |
| `--mask-values RE` | mask what this pattern (RE2) matches, wherever it is; repeat it, or `@FILE` (one a line: keeps a literal secret out of `ps`; write one as `\Q…\E`) |
| `--state DIR` | `~/.reqcove` by default: the node key, the CA and its private key. A new or empty directory, or one reqcove used before; write `--state ~/x` with a space (`--state=~/x` is refused). One without a CA gets a copy of `~/.reqcove`'s, and a new one named `reqcove-NAME` names the node so: [several exit nodes](several-exit-nodes.md) |
| `--hostname NAME` | the node's name, `reqcove` by default; kept in the state directory |
| `--verbose` | log tsnet's backend and every flow decision |
| `--uvx PATH` | the uvx to run; the `uv` beside it runs the default mitmproxy from Reqcove's lock (hashes checked). A path not named `uvx` is run as uvx: no lock, no hashes |
| `--python VERSION` | the Python to run mitmproxy with, 3.14 by default |
| `--mitmproxy-spec SPEC` | another mitmproxy than the locked `mitmproxy==12.3.1`, fetched through uvx (no lock, no hashes) |

The other commands (all but `init` and `version` take `--state DIR` too):

| | |
|---|---|
| `reqcove status` | what reqcove is doing, and the next steps; `--json` for the `status` tool's JSON; `--uvx PATH` |
| `reqcove mcp` | the MCP server for an agent on this computer |
| `reqcove har` | [the flows as a HAR file](#as-a-har-file-reqcove-har): `--host`, `--device`, `--since`, `--until`, `--status`, `--method`, `--user-agent`, `--limit N` |
| `reqcove init` | [the agent skill](#teach-the-agent-the-skill-reqcove-init): `--client NAME`, `--print`, `--uninstall` |
| `reqcove cleanup` | how to undo everything; `--delete-state`; `--hostname NAME` |
| `reqcove version` | the version |

Tried on an iPhone: `--mask-names`; `wait_for_flows` after acting through
RoamRun. By tests only: `--mask-values`, `diff_flows`, `max_body`, the
`--mcp-http` rate limit.

From reading code (the flags' help), not tried for this guide: `--proxy-port 0`,
`--hostname`, `--verbose`, `--uvx`, `--python`, `--mitmproxy-spec`,
`status --json`.

## MCP tools

| Tool | |
|---|---|
| `list_flows` | flows, newest first; filter by device, host (and subdomains), time (`since: "10m"`), status (`404`, `4xx`, `none`), method, User-Agent (text in it, such as an app's name; the app's bundle id is not in its traffic), GraphQL operation (`operation: "Login"`: its `operationName`, or the document's first operation; rows show it); paged. A host that matches nothing brings `similar_hosts`, recorded hosts that look alike (`acme-shop.com` for `acmeshop.com`) |
| `search_flows` | text in URLs and headers (and body heads with `bodies`); the same filters and `similar_hosts` |
| `wait_for_flows` | what an action on the device sent: take `checkpoint` from `list_flows` (or `capture_stats`) before acting, then call with `after: checkpoint`. Returns the flows answered since (a response or an error), oldest answer first, waiting up to `timeout` seconds (default 20, at most 30) for the first. Pass its `after` to the next call: each flow comes once. The same filters. A WebSocket is answered once, when it opens (`101`), and stays `open` until it closes |
| `get_flow` | one flow; bodies only with `bodies`, cut to `max_body` bytes each if given; `response_trailers` (HTTP/2's, or gRPC-Web's last frame) |
| `list_ws_messages` | a WebSocket's messages (a row with `websocket_messages`), oldest first, after a cursor (`after`: a checkpoint, or the last page's `after`); filters `direction` (`client`, `server`) and `text`. A text message's first 4 KiB, masked as it arrived as bodies are; a binary one, one past about 20 a second on its socket, or text masking cannot read gives its size only. Kept are the socket's first 5 messages (an auth message is usually one) and its newest 100; `missed` counts the others after the cursor (`missed_at_most` when the cursor itself falls among them: then some may be from before it). `open` and `close` (code, who closed) say how the socket stands. Messages wake no `wait_for_flows`, but a timed-out wait lists the sockets that got messages since (`websocket_activity`); `search_flows` with `bodies` looks in the kept ones |
| `diff_flows` | two flows compared (one that worked and one that failed): method, URL, status, error, headers by name, bodies (JSON by path). While masking is on, values masked on both sides are listed under `masked`, never as equal (they may differ), and bodies that are not text are not compared; with `--no-redact` everything is compared |
| `summarize` | counts by host, User-Agent, status, method, device, content type, gRPC status (`by_grpc_status`), and endpoint (`by_endpoint`: method, host and path without the query, ids as `{id}`, then the GraphQL operation: `GET api.example.com/v1/users/{id}`, `POST api.example.com/graphql Login`); the same filters and `similar_hosts` |
| `list_devices` | carried devices, their counts and last activity |
| `list_tls_failures` | handshakes a device refused: often certificate pinning, or a CA not trusted yet |
| `list_passthrough` | connections to `--pass-hosts` hosts: host, server, times, bytes; no URLs or contents |
| `capture_stats` | mitmproxy's state, the window the records cover, drops |
| `status` | whether everything is set up, and the next steps if not |

## Limits

The main ones are in the [README](../README.md#limits). The rest:

- IPv6 is refused; apps fall back to IPv4 at once.
- QUIC is dropped except to Apple, so apps fall back to TCP. This is by
  address, not by host: QUIC to hosts outside `--allow-hosts` falls back too
  (and without `--allow-hosts` as well). QUIC on a port other than 443 goes on,
  unrecorded.
- mitmproxy holds each WebSocket message until it is complete, and inflates a
  compressed one (permessage-deflate) whole, so one huge message can use a lot
  of memory: Reqcove's 4 KiB bound is on what it keeps, not on mitmproxy. If
  mitmproxy runs out, reqcove restarts it; when it is down again within a
  minute after 5 restarts in a row, `run` stops.
- Phone calls through the exit node have not been tried.
- Limits of one feature are in its section: [`--ui`](#on-the-iphone---ui),
  [`--web`](#in-mitmweb---web), [`--local-proxy`](#the-ios-simulator---local-proxy),
  [rules](#rules---rules), [an upstream proxy](#an-upstream-proxy---upstream-proxy).

## Security

In full: [SECURITY.md](SECURITY.md). Each option's own points are linked from
its section above; the rest:

- [What is recorded](SECURITY.md#what-is-recorded): only `--allow-hosts`
  hosts, never Apple's; what masking finds, and what it does not.
- [What the agent sees goes further](SECURITY.md#what-the-agent-sees-goes-further),
  to its model provider, and bodies may try to instruct it
  ([prompt injection](SECURITY.md#prompt-injection)).
- [What the devices can reach](SECURITY.md#what-the-devices-can-reach): not
  this computer, its LAN or the tailnet.
- [The CA's private key](SECURITY.md#the-cas-private-key), in the state
  directory.
- [The exit node's DNS](SECURITY.md#the-exit-nodes-dns) (`--dns`), and
  [a container](SECURITY.md#in-a-container).
