# Reqcove guide

[日本語](guide.ja.md) · [README](../README.md)

The details the README leaves out: the MCP tools and every option in full, the agent skill, rules, the
other ways in (the iOS Simulator, an upstream proxy), certificate pinning, and
more limits. Where something has not been tried, it says so.

## Restarts and upgrades

After v0.1.0, `reqcove mcp` stays up while `reqcove run` restarts or is not
running: the tools then answer that it is not running, and work again once
it is back, without reconnecting the agent (`/mcp` in Claude Code). Checked
with tests (a stand-in `run` stopped and started again), and in a Claude
Code session: with `run` stopped the tools said so, and after it started
again they worked without `/mcp`. A restart starts the records empty (the
first answer after it says so, in its `note`; seen in Claude Code too). After upgrading reqcove, reconnect the
agent once for the new tools; the tools say so while the versions differ.

## MCP tools

| Tool | |
|---|---|
| `list_flows` | flows, newest first; filter by device, host (and subdomains), time (`since: "10m"`), status (`404`, `4xx`, `none`), method, User-Agent (after v0.1.0: text in it, such as an app's name; the app's bundle id is not in its traffic); paged. After v0.1.0, a host that matches nothing brings `similar_hosts`, recorded hosts that look alike (`acme-shop.com` for `acmeshop.com`) |
| `search_flows` | text in URLs and headers (and body heads with `bodies`); the same filters and `similar_hosts` |
| `get_flow` | one flow; bodies only with `bodies` |
| `summarize` | counts by host, User-Agent, status, method, device, content type; the same filters and `similar_hosts` |
| `list_devices` | carried devices, their counts and last activity |
| `list_tls_failures` | handshakes a device refused: often certificate pinning, or a CA not trusted yet |
| `list_passthrough` | after v0.1.0: connections to `--pass-hosts` hosts: host, server, times, bytes; no URLs or contents |
| `capture_stats` | mitmproxy's state, the window the records cover, drops |
| `status` | whether everything is set up, and the next steps if not |

## Without the exit node: a Wi-Fi proxy

Instead of the exit node, the iPhone can also set its Wi-Fi proxy (Manual) to the
reqcove node's tailnet address, port 8080 (`--proxy-port`). Cellular has no proxy
setting, so this works on Wi-Fi only.

## Agents on other devices (`--mcp-http`)

> Not in v0.1.0: until the next release, build from source to use it.

`reqcove mcp` serves the tools to an agent on the computer running `run`. For
an agent elsewhere on your tailnet, such as Grok Bot (xAI's agent: its cloud
computer joins your tailnet through Tailscale's OAuth apps), `run --mcp-http`
serves the same tools over HTTP on the node:

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --mcp-http
```

`run` prints the URL, `http://reqcove.<tailnet>.ts.net:8090/mcp`, and the header
to give the agent, `Authorization: Bearer <token>`. The token is kept in
`mcp-token` in the state directory, the same at each start; delete it and start
again to change it.

- Grok Bot: in Connect apps › Tailscale, let it join your tailnet (under
  Tailnet Lock, sign its device). Then Connect apps › Add a custom connector:
  type Remote HTTPS, the URL as server URL, and the header (key
  `Authorization`, value `Bearer <token>`). Its settings show the connector
  with an error and no tools: Grok Bot reaches the tailnet from its chats only.
  Ask it in a chat. To copy the header's value without showing it:
  `printf 'Bearer %s' "$(cat ~/.reqcove/mcp-token)" | pbcopy`.
- Claude Code on another computer:
  `claude mcp add --transport http reqcove-remote http://reqcove.<tailnet>.ts.net:8090/mcp --header "Authorization: Bearer <token>"`
  (it keeps the header in `~/.claude.json`).
- Codex on another computer: `codex mcp add reqcove-remote --url http://reqcove.<tailnet>.ts.net:8090/mcp --bearer-token-env-var REQCOVE_TOKEN`,
  with the token in that variable. Codex asks before each MCP tool call; in
  `codex exec`, which cannot ask, set `default_tools_approval_mode = "approve"`
  for this server.
- Who can call it: your own devices on the tailnet (the same user as reqcove's
  node, neither tagged), with the token. A tagged device is refused (`run` logs
  it once), so do not tag Grok Bot's device to restrict it.
- What the agent reads goes to that agent's computer and its model provider:
  for Grok Bot, xAI's cloud. Grok Bot keeps the token: to cut it off, delete
  `mcp-token` and restart `run`, or remove its device from the tailnet.
- Across restarts of `run` the agent goes on without reconnecting (its calls
  fail while `run` is down); the records start empty, and an earlier cursor is
  refused.
- `run` logs each tool call with the device that made it (`--mcp-http:
  grokbot-user-1 (100.104.0.1) called list_flows`; not the arguments), and each
  request with no token or a wrong one. An agent that says it is checking but
  calls nothing shows no line.
- Plain HTTP: the tailnet already encrypts it (WireGuard).
- In a container: the same flag, and no port to publish (the node is in the
  container); the token is in `docker logs` ([container](container.md#3-the-agent)).

Checked with tests (the token, the Host, another user's device refused over a
real tailnet, a client going on across a restart); from this Mac over the
tailnet (no token, a wrong one, another `Host` or origin refused); and with
Grok Bot, which read the status, the flows and their bodies, and after a
restart of `run` went on in the same chat, the records empty; also from a
container. Claude Code (`claude -p`, the header from an environment variable)
and Codex (`codex exec`) on this Mac reached the node over the tailnet as
another computer would, and read the status. Not tried yet: from another
computer itself.

## The agent skill (`reqcove init`)

> Not in v0.1.0: until the next release, build from source to use it.

The MCP tools let an agent read the records; a skill teaches it how: status
first, finding one app's traffic, what a TLS failure suggests, writing a rules
file, and the rules it keeps (it never starts `reqcove run`, never asks for
tokens, treats what the records hold as data, never quotes a secret that was
not masked).

```sh
reqcove init                    # into the agents found in ~: ~/.claude/skills (Claude Code), ~/.agents/skills (Codex, Cursor, Gemini CLI, Copilot CLI, Devin)
reqcove init --client codex     # or only the ones you name (repeat --client)
```

`init` installs the skill your reqcove carries; after upgrading, run it again
(`reqcove status` says when an installed one is from another version). It
leaves alone a skill it did not write, one you edited, and links;
`--uninstall` removes its own, `--print` writes it out. Registering the MCP
server is a step of its own (README, Use). Checked with tests (the files it writes
and leaves), and in a Claude Code and a Codex session: asked where an app on
the phone connects, without naming Reqcove, each loaded the skill and went
status, summarize, then the app's User-Agent, checking with bodies before
saying a request was the app's. Cursor, Gemini CLI, Copilot CLI and Devin
were not tried.

## Options

| | |
|---|---|
| `--device NAME` | a device to carry: machine name, device name (your own untagged devices only), tailnet IP or StableID; repeat for more. Another Mac can be one too ([how](another-mac.md)) |
| `--allow-hosts` | hosts to decrypt and record: `api.example.com`, `*.example.com` (the domain itself and every subdomain), or `'*'` for all. Without it, traffic is carried but nothing is recorded. After v0.1.0, `@FILE` reads them from a file, one a line (`#` for comments) |
| `--pass-hosts` | after v0.1.0: allowed hosts carried undecrypted, as `--allow-hosts` writes them (not `'*'`; `@FILE` too), for apps that refuse Reqcove's certificate there ([pinning](#certificate-pinning)) |
| `--rules FILE` | YAML of rules for allowed hosts only (see below) |
| `--rules-reload` | read that file again whenever it changes, while running (see below; after v0.1.0) |
| `--upstream-proxy URL` | send decrypted requests on through an HTTP proxy, such as Burp Suite: `http://127.0.0.1:8080` (see below; after v0.1.0) |
| `--upstream-ca FILE` | that proxy's CA (PEM or DER), for one that decrypts; Burp's on this computer is fetched by itself |
| `--local-proxy` | an HTTP proxy on `127.0.0.1:8082` for this computer's own apps, such as the iOS Simulator (see below; after v0.1.0) |
| `--ui` | a read-only page of the flows on the iPhone itself, on the node's port 80 (see below; after v0.1.0) |
| `--web` | run mitmweb instead, on `http://127.0.0.1:8081` (after v0.1.0, 8091-8099 while another run has 8081; [two addresses](several-exit-nodes.md#ports); no masking, can edit and replay; it shows bodies up to 2 MB each, after v0.1.0, and keeps the newest 10,000 flows and 256 MB of bodies); after v0.1.0 also on the node's port 8081 for your own devices on the tailnet, with the link and QR code `run` prints, the same at each start (`web-token` in the state directory); after a restart, open the link again (a bookmark without the token asks for it); tried from an iPhone on the exit node |
| `--mcp-http` | the MCP tools over HTTP on the node's port 8090, for agents on your own devices on the tailnet, with a token ([how](#agents-on-other-devices---mcp-http); after v0.1.0) |
| `--dns` | the exit node's DNS upstreams, comma-separated, `1.1.1.1:53` by default (the port may be left out, after v0.1.0); `system` for the first nameserver in `/etc/resolv.conf` |
| `--no-redact` | keep secrets in the records |
| `--state DIR` | `~/.reqcove` by default: the node key, the CA and its private key. A new or empty directory, or one reqcove used before. After v0.1.0, one without a CA gets a copy of `~/.reqcove`'s, and a new one named `reqcove-NAME` names the node so ([several exit nodes](several-exit-nodes.md)). Write `--state ~/x` with a space (`--state=~/x` is refused) |

## Rules

```yaml
map_remote:                     # mitmproxy's syntax, as are map_local and modify_headers
  - "|https://api.example.com/|http://localhost:3000/"
keep_host_header: true          # reqcove's: map_remote keeps the app's Host
resolve:                        # reqcove's: connect elsewhere, Host and SNI unchanged
  - "shop.example.com=203.0.113.10"
  - "auth.example.com=192.168.1.20:8443"
```

- `map_remote`, `map_local` and `modify_headers` are mitmproxy's, run by its own
  code. Relative paths count from the rules file.
- `map_remote` changes the URL, and with it the `Host` header, unless
  `keep_host_header` is true. For a development server on this computer
  (`http://localhost:3000`), this is the one to use; write the schemes, as above,
  since apps send `https` and a plain server cannot answer TLS.
- `resolve` sends requests for the name to that IPv4 address, on this computer or
  the LAN too; `Host`, SNI and the recorded URL stay the same, and TLS is still
  checked against the name. So the server there needs a certificate for that name
  (a staging server or a new load balancer; a local HTTPS server without one gets
  a 502). After a `map_remote`, the name is the host of its new URL, which is then
  also the SNI. Without a port, the request's port is used (the app's, 80 or 443,
  or the `map_remote` URL's), and plain HTTP is not checked by any certificate.
  The name is still looked up (by the phone, or by this computer for the Remote
  Proxy) and the real server connected first: a name that does not resolve
  publicly, or a real server that refuses connections, cannot be redirected. Names must be
  in `--allow-hosts`, and each needs its own address (or port): mitmproxy reuses a
  connection by address. `0.0.0.0/8`, link-local (cloud metadata), multicast and
  Tailscale's 100.100.100.100 are refused.
- Read a rules file from someone else before using it: rules can send your apps'
  requests, cookies and tokens included, wherever they say.
- The file is read when mitmproxy starts: with `run`, and when reqcove restarts
  it after it exits. With `--rules-reload` (after v0.1.0) it is also read again
  once a change has settled, within about two seconds (from the code), for the
  requests that start after it; a request under way keeps the rules it started
  with. A file that does not
  load leaves the rules before it in place, and `run` and `reqcove status` say
  why; but if mitmproxy restarts meanwhile, `run` stops on it, as at start. With
  it, whatever can write the file (an agent included) can change where the
  devices' requests go, without you restarting anything.

## The flows on the iPhone (`--ui`)

> Not in v0.1.0: until the next release, build from source to use it.

`reqcove run --ui` serves a read-only page of the flows on its tailnet node and
prints a link to it with a QR code. Scan it with the iPhone's camera: Safari opens
the list, which follows new flows every second, beside the app in split view if
you like. Tap a flow for its headers and bodies, masked as the MCP tools return
them.

- Search URLs and headers as you type (with "bodies too", the kept heads of the
  bodies; the list then stops following, as that search walks every record);
  filter by status (2xx to 5xx, no answer) or by host (on a flow's page).
- Clear hides the flows so far from the list, to see only what comes next;
  "Show all" brings them back. Nothing is deleted: the agent still sees them.
- Live/Paused stops and starts following. Scrolled down, the list stays put and
  says how many flows are new; tap that to see them.
- Tried: opened on an iPhone from the camera. Not tried yet: this layout,
  search and Clear on an iPhone (the tests run the page's script in node).

- Your own devices on the tailnet (logged in as you: the iPhone, a second
  MacBook, an iPad) can open it and see every device's flows; a `--device` device
  of another user sees only its own; no one else reaches it. Only the browser that
  opened the link can read it. The link is the same at each start (its token is
  kept in `ui-token` in the state directory; delete that and start again to change
  it), and a device that opened it keeps a cookie for 400 days, so a bookmark
  should work after a restart (the cookie is tested; a restart with Safari on
  the iPhone is not tried yet).
- Tailscale must be on; it works with the exit node or the Remote Proxy, or
  neither. The page's own requests are not recorded.

## The iOS Simulator (`--local-proxy`)

> Not in v0.1.0: until the next release, build from source to use it.

```sh
reqcove run --allow-hosts api.example.com --local-proxy   # --device too, for an iPhone as well
```

The Simulator's apps use this computer's network, which the exit node does not
carry. `--local-proxy` opens an HTTP proxy on `127.0.0.1:8082` instead, and its
requests are recorded as the device `local`. On macOS, as Charles and Proxyman
do, `run` points the system's web proxies (HTTP and HTTPS, every enabled network
service) at it and puts back what was there when it stops; if it dies, the next
start or `reqcove cleanup` puts them back. It also adds Reqcove's CA to the booted
Simulators (`xcrun simctl keychain … add-root-cert`); one booted later needs the
command it prints. On Linux nothing is changed for you: point apps at it
(`HTTPS_PROXY=http://127.0.0.1:8082`) and have them trust the CA.

- Every app on this computer then goes through it, not only the Simulator. Only
  `--allow-hosts` hosts are decrypted and recorded, but those break in apps on
  this computer that do not trust Reqcove's CA (Safari on the Mac, say).
- This computer, the LAN, the tailnet (`*.ts.net` too) and `*.local` are added to
  the proxy's exceptions, so they are reached directly, as before (the address
  forms there are not tried yet). Names are looked up as this computer does (VPNs,
  split DNS, search domains), not with `--dns`, and names that lead to the LAN, a
  VPN or the tailnet go on. A name that leads to this computer itself, or to a
  link-local address, is refused unless this computer's `/etc/hosts` gives it: a
  site pointing its own name at 127.0.0.1 (DNS rebinding) cannot reach this
  computer's services through it.
- While `run` runs, the system proxy is reqcove's. Ctrl-C, `kill` and closing the
  terminal put it back; if reqcove is killed outright (`kill -9`) or crashes,
  apps that use the system proxy cannot connect until the next `run` or
  `reqcove cleanup` puts it back (or you do, in System Settings).
- This computer's own browsers: to have their requests to the allowed hosts
  decrypted and recorded too (as `local`, mixed with the Simulator's) rather than
  warned about, trust Reqcove's CA on this computer once. `run` prints the
  command when it is not trusted yet; `reqcove status` and `reqcove cleanup` say
  how to stop. Tried on macOS 27 (the command, Reqcove's check of it, the hint
  to stop, and Chrome on the Mac opening an allowed host without a warning, its
  requests recorded); not tried on Linux.
  - macOS (TLS only; it asks for your password):
    `security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`.
    Firefox may keep its own store. To stop, run the command `reqcove status`
    prints, or delete the CA in Keychain Access (its trust goes with it; tried).
  - Linux, Debian and Ubuntu: `sudo cp ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/reqcove.crt && sudo update-ca-certificates`;
    Fedora: into `/etc/pki/ca-trust/source/anchors/` and `sudo update-ca-trust`;
    Chrome and Chromium: `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n Reqcove -i ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`;
    Node: `NODE_EXTRA_CA_CERTS=` that file; Python: the system's bundle once
    updated, not that file alone (it would replace every other CA).
- Automatic proxy configuration (PAC) and authenticated proxies are left as they
  are; not tried with them. Not tried yet with the real `networksetup` and
  Simulator either: the tests use stand-ins.

## A HAR file

> Not in v0.1.0: until the next release, build from source to use it.

While `reqcove run` is running, `reqcove har > flows.har` writes its flows as a
HAR 1.2 file, oldest first: the newest 1000 by default (`--limit 0` for all),
filtered with `--host`, `--device`, `--since 10m`, `--until`, `--status 4xx`,
`--method` (and `--user-agent`, after v0.1.0). It
holds what the MCP tools return: masked as it arrived, the heads of bodies only
(cut ones say so in a comment), and no body that masking could not check. With
`run --no-redact` nothing is masked, and the file says so in its comment. It is
written to the HAR 1.2 spec's required fields (from reading the spec; no
validator was run), but not opened in other tools yet (browsers' developer tools,
Charles, Proxyman).

## An upstream proxy (Burp Suite and others)

> Not in v0.1.0: until the next release, build from source to use it.

To see the same requests in Burp Suite (or ZAP, Charles, …) while Reqcove keeps its
records, send them on through it:

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' \
  --upstream-proxy http://127.0.0.1:8080
```

- Decrypted requests go to the proxy (HTTPS in a CONNECT tunnel, plain HTTP as
  proxy requests), never straight to the server. Connections to hosts outside
  `--allow-hosts` pass through directly, as always; but a request to another host
  that rides on a decrypted connection to an allowed one (HTTP/2 connection
  reuse) goes through the proxy too, unrecorded. Turn Burp's Intercept off, or requests wait
  in it.
- Reqcove hands the proxy the address the iPhone connected to, but Burp connects to
  HTTPS hosts by the name in the SNI, looked up again on this computer (tried). So
  the exit node's refusal of this computer and its LAN does not cover where Burp
  connects, and a site the iPhone visits can answer that lookup with this
  computer's or the LAN's address (DNS rebinding; from reading code, not tried):
  keep `--allow-hosts` to the hosts you test (`run` warns about `'*'`). For the same reason,
  `resolve` rules are refused with `--upstream-proxy`; use the proxy's own
  overrides (Burp's Hostname resolution overrides). Plain HTTP shows up in Burp
  under the IP address, with the name in its `Host` header.
- HTTPS through the proxy is checked against the proxy's CA only. A proxy on this
  computer that serves `http://burp/cert`, as Burp does, has it fetched from there
  at start; for another proxy that decrypts (ZAP, Charles), pass its CA with
  `--upstream-ca FILE` (PEM or DER). Otherwise the public CAs are used (for a
  proxy that does not decrypt).
- Reqcove connects to the proxy itself and ignores the system's proxy settings.
  But a proxy that points them at itself when it starts (Charles does, unless its
  Proxy menu's macOS Proxy is off) and `--local-proxy` (after v0.1.0) both claim
  them, and each puts back what the other set. With `--local-proxy`, turn that
  off in the proxy. Not tried with Charles.
- Only HTTP(S) goes through the proxy. Other protocols to an allowed host (MQTT,
  say) go straight to their servers (from reading code); over TLS with the
  proxy's CA in use they fail: the server's certificate is checked against that CA. HTTPS without a server name
  (SNI), to a bare IP address, fails through Burp, which names its certificate
  after the address the way mitmproxy does not accept.
- The proxy sees everything unmasked, and Burp keeps it in its project. Tried with
  Burp Suite Community 2026.10; other proxies have not been tried. Seen with Burp:
  it holds a request body until the whole of it has come, and server-sent events
  to an HTTP/1.1 client fail (to HTTP/2 clients, as iOS apps mostly are, they
  stream). With `--web`, replaying a plain HTTP request from mitmweb sends it to
  the proxy itself.

## Certificate pinning

> Not in v0.1.0: until the next release, build from source to use it.

Apps that pin their certificates refuse Reqcove's, so their requests to those
hosts fail. `reqcove status` names such hosts, with the `--pass-hosts` to start
`run` with; those hosts are then carried undecrypted and the apps work (tried on
an iPhone).

```sh
reqcove run --device iphone --allow-hosts '*' --pass-hosts '*.example-cdn.com,api.example.com'
reqcove run --device iphone --allow-hosts '*' --pass-hosts @pass-hosts.txt   # one host a line
```

- For those hosts only the connections are recorded (host, server, times,
  bytes: `list_passthrough`), no URLs or contents.
- They skip `--rules` and `--upstream-proxy`.
- Pinning checked after the TLS handshake shows nowhere.
- For your own app, use a build without pinning.

## More limits

- IPv6 is refused (apps fall back to IPv4 at once). QUIC is dropped except to Apple,
  so apps fall back to TCP. This is by address, not by host: QUIC to hosts outside
  `--allow-hosts` falls back too (and without `--allow-hosts` as well). QUIC on a
  port other than 443 is not dropped; it goes on, and is not recorded.
- Phone calls through the exit node have not been tried.
- mitmweb (`--web`) can change mitmproxy's options. In its Capture tab, leave
  "Run SOCKS Proxy" on: it is how Reqcove hands the devices' traffic to
  mitmproxy, and without it their HTTP(S) stops. The other modes there are not
  Reqcove's. Whatever is changed goes back when reqcove starts again, and
  Reqcove's records stay scoped and masked (from reading code, not tried).
- The iOS Simulator on the computer running Reqcove needs `--local-proxy` (see
  above; after v0.1.0). On another Mac that is a `--device` and uses Reqcove's
  exit node ([how](another-mac.md)), the Simulator's traffic should go
  through with the Mac's own, once
  the Simulator trusts Reqcove's CA (not tried).
- mitmproxy holds each WebSocket message until it is complete, so one huge message
  can use a lot of memory (if mitmproxy runs out, reqcove restarts it; when it is down again within a minute
  after 5 restarts in a row, `run` stops).
- `map_local` answers only requests whose body is at most 1 MiB and of known length;
  others go on to the real destination (the record says so). An HTTP/2 GET without
  a length is answered too, and a body the device sends with it anyway is held
  whole; only your own devices send these requests.

## Tips

- To skip approving the exit node for every new node, add an auto-approver to the
  tailnet policy: `"autoApprovers": {"exitNode": ["you@example.com"]}`.
- The CA stays the same as long as the state directory does. To use one CA on two
  computers, copy `~/.reqcove/mitmproxy/` whole (it holds the private key) into
  `~/.reqcove/` on the other, with reqcove stopped there (after v0.1.0, also
  before its first run).
