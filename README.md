# Reqcove

[![test](https://github.com/mh-mobile/reqcove/actions/workflows/test.yml/badge.svg)](https://github.com/mh-mobile/reqcove/actions/workflows/test.yml)
[![release](https://img.shields.io/github/v/release/mh-mobile/reqcove)](https://github.com/mh-mobile/reqcove/releases)
[![license](https://img.shields.io/github/license/mh-mobile/reqcove)](LICENSE)

Hand the HTTP(S) traffic of an iPhone, on your desk or far away, to an AI agent.

The name Reqcove (REK-kohv) combines request and cove: a sheltered place where
requests gather.

[日本語](README.ja.md)

The iPhone picks your computer as its Tailscale **exit node**. Reqcove, a single
binary on that computer, carries the traffic, has [mitmproxy](https://mitmproxy.org)
decrypt the hosts you allow, and serves the flows to your agent over
[MCP](https://modelcontextprotocol.io). Nothing to configure on the phone beyond
choosing the exit node and trusting a CA once, and it works over 5G as well as Wi-Fi.

```text
iPhone ──(tailnet, exit node)──▶ reqcove run ──SOCKS5──▶ mitmproxy ──▶ internet
                                     │                       │
                                     │                 addon: flows
                                     ▼                       ▼
                              agent ◀── MCP ── reqcove mcp ◀─ records (masked)
```

Reqcove is a separate tool from RoamRun, which brings a remote device to Xcode
and does not read its traffic.

> **Status: early** (v0.1). Tried on macOS (Apple silicon) and Ubuntu 24.04
> (arm64) with an iPhone; where something has not been tried, the docs say so.
> Some of what follows is newer than v0.1.0 ([CHANGELOG](CHANGELOG.md)): until
> the next release, build from source for it.

## What you need

- macOS on Apple silicon, or Linux (amd64 or arm64)
- [uv](https://docs.astral.sh/uv/). Reqcove fetches mitmproxy (12.3.1) and Python with it
  on the first run; nothing else to install
- A Tailscale tailnet, and the Tailscale app on the iPhone

## Install

With Homebrew (macOS or Linux; it builds from source and installs uv too):

```sh
brew install mh-mobile/tap/reqcove
```

Or download a binary from [Releases](https://github.com/mh-mobile/reqcove/releases)
(macOS on Apple silicon, Linux amd64 and arm64), and install uv yourself. The macOS
binary is signed with a Developer ID and notarized by Apple, so it runs when
downloaded with a browser too.

Or build from source (Go 1.27):

```sh
git clone https://github.com/mh-mobile/reqcove && cd reqcove
go build -o reqcove ./cmd/reqcove
```

`go install …@version` does not work: Reqcove uses a fork of Tailscale's tsnet
through a `replace` directive.

## Use

1. Start it on the computer, naming the iPhone (as in `tailscale status`) and the
   hosts to record:

   ```sh
   reqcove run --device iphone --allow-hosts 'api.example.com,*.example-cdn.com'
   ```

   The first time, it prints a login URL, then what else is needed (approving
   the exit node, Tailnet Lock). `reqcove status` always says what is still
   missing.
2. On the iPhone, in the Tailscale app, choose the exit node `reqcove`.
3. Still on the iPhone, trust Reqcove's CA: scan the QR code `reqcove run`
   prints with the Camera (or open `http://mitm.it` in Safari, typing the
   `http://`), install the profile (Settings › Profile Downloaded), and trust
   it in Settings › General › About › Certificate Trust Settings (it is named
   `Reqcove CA (<computer>, <date>)`).
4. Give your agent the tools, and the skill that teaches it how to use them.
   For Claude Code:

   ```sh
   claude mcp add reqcove -- reqcove mcp
   reqcove init   # not in v0.1.0 yet
   ```

   Then ask it things like "which requests to api.example.com failed in the last
   ten minutes?"

After v0.1.0, `reqcove run` can restart without reconnecting the agent; the
records start empty. `reqcove cleanup` lists how to undo everything.

### MCP tools

| Tool | |
|---|---|
| `summarize` | counts by host, User-Agent, status, device: what is there |
| `list_flows` | flows, newest first; filter by device, host, time (`since: "10m"`), status, method, User-Agent |
| `search_flows` | text in URLs and headers (and bodies) |
| `get_flow` | one flow, with its bodies if asked |
| `list_devices` | the devices carried |
| `list_tls_failures` | handshakes a device refused: often certificate pinning, or a CA not trusted yet |
| `list_passthrough` | connections to `--pass-hosts` hosts: host, server, times, bytes |
| `capture_stats` | mitmproxy's state, the window the records cover |
| `status` | whether everything is set up, and the next steps if not |

In full: [the guide](docs/guide.md#mcp-tools).

### Options

| | |
|---|---|
| `--device NAME` | a device to carry (as in `tailscale status`); repeat for more |
| `--allow-hosts` | hosts to decrypt and record: `api.example.com`, `*.example.com`, `'*'` for all, `@FILE` |
| `--pass-hosts` | allowed hosts to carry undecrypted, for apps that pin certificates |
| `--rules FILE` | rewrite where allowed hosts' requests go (`map_remote`, `map_local`, …) |
| `--upstream-proxy URL` | send decrypted requests on through Burp Suite or another proxy |
| `--local-proxy` | record this computer's own apps too, such as the iOS Simulator; on macOS it points the system's web proxies at Reqcove while `run` runs |
| `--ui` | a page of the flows on the iPhone itself |
| `--web` | mitmweb instead (no masking) |
| `--state DIR` | where the node key and the CA live, `~/.reqcove` by default |

All of them, and what each does in full: [the guide](docs/guide.md#options).

### More

- [Rules](docs/guide.md#rules): send an app's requests to a development server, or answer them from a file
- [The flows on the iPhone](docs/guide.md#the-flows-on-the-iphone---ui) (`--ui`)
- [The iOS Simulator](docs/guide.md#the-ios-simulator---local-proxy) (`--local-proxy`)
- [A HAR file](docs/guide.md#a-har-file) (`reqcove har`)
- [An upstream proxy](docs/guide.md#an-upstream-proxy-burp-suite-and-others) (Burp Suite and others)
- [Certificate pinning](docs/guide.md#certificate-pinning) (`--pass-hosts`)
- [The agent skill](docs/guide.md#the-agent-skill-reqcove-init) (`reqcove init`)
- [Several exit nodes on one computer](docs/several-exit-nodes.md), [in a container](docs/container.md), [another Mac as a device](docs/another-mac.md)

## What it keeps safe, and what it does not

- Only the hosts in `--allow-hosts` are decrypted and recorded. Apple's hosts
  always pass undecrypted.
- Secrets (tokens, keys, cookies, passwords) are masked as they arrive. **Other
  secrets in a body, under names that do not say so, are not found**, and
  personal data such as e-mail addresses is not masked.
- What the agent reads goes to its model provider. Bodies are written by remote
  sites and may try to instruct the agent.
- The exit node refuses this computer, its LAN and the tailnet as destinations.

More in [docs/SECURITY.md](docs/SECURITY.md).

## Limits

- Apps that pin certificates refuse Reqcove's; see [Certificate pinning](docs/guide.md#certificate-pinning).
- Only TCP ports 80 and 443 go through mitmproxy; other ports are carried as they are.
- IPv6 is refused and QUIC dropped (except to Apple); apps fall back to IPv4 and TCP.
- The phone cannot reach this computer or its LAN directly; a rule can send an
  allowed host's requests there.
- If reqcove stops while the iPhone uses it, the iPhone's DNS can stay stuck
  ([tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)):
  turn the exit node off and on again.
- The computer must stay awake: `reqcove run` keeps macOS from idle sleep, not
  from a closed lid.

More in [the guide](docs/guide.md#more-limits).

## License

MIT. Reqcove uses a fork of Tailscale (BSD-3-Clause) and other open source
modules; release archives include their licenses.
