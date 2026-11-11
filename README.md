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

> **Status: early** (v0.3). Tried on macOS (Apple silicon) and Ubuntu 24.04
> (arm64) with an iPhone; where something has not been tried, the docs say so.

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

Then put `reqcove` on your `PATH` (or call it as `./reqcove`).

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
   reqcove init
   ```

   Then ask it things like "which requests to api.example.com failed in the last
   ten minutes?"

The agent reads the records through MCP tools such as `summarize`, `list_flows`,
`search_flows` and `get_flow` ([all of them](docs/guide.md#mcp-tools)). After
it acts on the phone (through RoamRun, say), `wait_for_flows` returns the
requests that action sent.
`reqcove cleanup` lists how to undo everything; stopping, restarting and
updating are in [the guide](docs/guide.md#stop-restart-update).

### Options

| | |
|---|---|
| `--device NAME` | a device to carry (as in `tailscale status`); repeat for more |
| `--allow-hosts` | hosts whose requests are recorded (their connections decrypted): `api.example.com`, `*.example.com`, `'*'` for all, `@FILE` |
| `--pass-hosts` | allowed hosts to carry undecrypted, for apps that pin certificates |
| `--rules FILE` | rewrite where allowed hosts' requests go (`map_remote`, `map_local`, …) |
| `--state DIR` | where the node key and the CA live, `~/.reqcove` by default |

All of them: [the guide](docs/guide.md#options).

### More

- [Read the traffic with an agent](docs/guide.md#read-the-traffic-with-an-agent): the skill, agents on your other devices
- [Look at the flows yourself](docs/guide.md#look-at-the-flows-yourself): on the iPhone, as a HAR file, in mitmweb
- [Record clients other than iPhone apps](docs/guide.md#record-clients-other-than-iphone-apps): apps that pin certificates, Android, the iOS Simulator, a web app's backend
- [Change where requests go](docs/guide.md#change-where-requests-go): to a development server, or on through another proxy
- [Several exit nodes on one computer](docs/several-exit-nodes.md), [in a container](docs/container.md), [another Mac as a device](docs/another-mac.md)

## What it keeps safe, and what it does not

- Only requests to the hosts in `--allow-hosts` are recorded. A request to
  another host that rides on an allowed host's connection (HTTP/2 connection
  reuse) is decrypted too, and is not recorded, but `--web` shows it and
  `--upstream-proxy` may receive it. Connections to Apple's hosts always pass
  undecrypted.
- The secrets Reqcove recognises (tokens, keys, cookies, passwords) are masked
  as they arrive. **Other
  secrets in a body, under names that do not say so, are not found** (add
  yours with `--mask-names` or `--mask-values`), and personal data such as
  e-mail addresses is not masked.
- What the agent reads goes to its model provider. Bodies are written by remote
  sites and may try to instruct the agent.
- The exit node refuses this computer, its LAN and the tailnet as destinations.

More in [docs/SECURITY.md](docs/SECURITY.md).

## Limits

- Apps that pin certificates refuse Reqcove's; see [`--pass-hosts`](docs/guide.md#apps-that-pin-certificates---pass-hosts).
- Only TCP ports 80 and 443 go through mitmproxy; other ports are carried as they are.
- IPv6 is refused and QUIC dropped (except to Apple); apps fall back to IPv4 and TCP.
- The phone cannot reach this computer or its LAN directly; a rule can send an
  allowed host's requests there.
- If reqcove stops while the iPhone uses it, the iPhone's DNS can stay stuck
  ([tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)):
  turn the exit node off and on again.
- The computer must stay awake: `reqcove run` keeps macOS from idle sleep, not
  from a closed lid.

More in [the guide](docs/guide.md#limits).

## License

MIT. Reqcove uses a fork of Tailscale (BSD-3-Clause) and other open source
modules; release archives include their licenses.
