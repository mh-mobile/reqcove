# Changelog

## Unreleased

- In the container image, `run`'s log names the `docker run -i … reqcove mcp`
  command for Claude Code, not `reqcove mcp` inside the container.
- `run --mcp-http`: the MCP tools over HTTP on the node's port 8090, for agents
  on your own devices on the tailnet (Grok Bot, through Tailscale's OAuth apps),
  with a token `run` prints. Stateless: agents go on across restarts of `run`.
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
- Burp's CA is fetched from `http://burp/cert` at start when the proxy is on this
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
