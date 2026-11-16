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

> **Status: v1.0.** The MCP tools, the CLI and the rules file stay compatible
> until a v2 ([COMPATIBILITY](docs/COMPATIBILITY.md)).

## What you need

- macOS on Apple silicon, or Linux (amd64 or arm64)
- [uv](https://docs.astral.sh/uv/). Reqcove fetches mitmproxy (12.3.1) and Python with it
  on the first run; nothing else to install
- A Tailscale tailnet, and the Tailscale app on the iPhone

## Install

With Homebrew (macOS or Linux; it builds from source and installs uv too):

```sh
brew trust --formula mh-mobile/tap/reqcove   # Homebrew 7 loads a formula from another tap only once trusted
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

A first run has four steps: one on the computer, two on the iPhone, one for
the agent.

1. **On the computer: set it up and start it.** In a terminal:

   ```sh
   reqcove setup
   ```

   It checks uv, asks for the iPhone's name in your tailnet (as in
   `tailscale status`) and the hosts to record, and writes them to a config
   file: `~/.config/reqcove/config`, or Homebrew's `etc/reqcove/config` for a
   brew install (the hosts in `hosts` beside it). It adds the agent skill if you answer `y`, and prints the
   line that gives Claude Code the tools. It starts nothing itself
   ([what it asks and writes](docs/guide.md#first-start)).

   Then start it in a terminal (Ctrl-C stops it):

   ```sh
   reqcove run
   ```

   With no arguments, `run` reads that file (since v1.1). To have it start
   at login in the background instead: `reqcove service install`, or
   `brew services start reqcove` for a brew install
   ([background](docs/guide.md#run-it-in-the-background)). While it runs,
   `reqcove capture add HOST` records one more host without a restart
   ([more](docs/guide.md#change-what-is-recorded-while-it-runs)).

   The first time, log in: `reqcove links` prints the login URL.
   `reqcove status` says what is left, such as approving the exit node.
2. **On the iPhone: choose the exit node.** In the Tailscale app, choose the
   exit node `reqcove`.
3. **On the iPhone: trust Reqcove's CA.** Once trusted, the CA lets this
   computer read the iPhone's HTTPS to any site, not only the hosts you
   allow, for as long as its profile stays on the iPhone
   ([SECURITY](docs/SECURITY.md#the-cas-private-key)).

   Scan the CA's QR code with the Camera: `reqcove links` prints it, and so
   does `reqcove run` started in a terminal. (Or open `http://mitm.it` in
   Safari, typing the `http://`.) Install the profile (Settings › Profile
   Downloaded), and trust it in Settings › General › About › Certificate
   Trust Settings. It is named `Reqcove CA (<computer>, <date>)`, the
   computer's name cut to 39 characters.
4. **Give your agent the tools**, and the skill that teaches it how to use
   them. For Claude Code:

   ```sh
   claude mcp add reqcove -- reqcove mcp
   reqcove init
   ```

   The first line is the one setup printed. `reqcove init` adds the skill:
   setup has done it already if you answered `y`.

Then check that it works. On the iPhone, open the app and do one thing that
sends a request to a host you allowed. Ask the agent "what did the iPhone
just send to api.example.com?" It works when the agent answers with that
request: its method, its URL and its status. If the agent finds nothing,
`reqcove status` says what is missing
([troubleshooting](docs/guide.md#troubleshooting)).

After that, ask it things like "which requests to api.example.com failed in
the last ten minutes?"

Without `setup`, step 1 by hand is one command in a terminal, naming the
iPhone (as in `tailscale status`) and the hosts to record:

```sh
reqcove run --device iphone --allow-hosts 'api.example.com,*.example-cdn.com'
```

The first time, it prints a login URL on its terminal (`reqcove links` prints
it again), then what else is needed (approving the exit node, Tailnet Lock).
`reqcove status` always says what is still missing. Steps 2 to 4 are the same.

### What the agent can do

- It reads the records through MCP tools such as `summarize`, `list_flows`,
  `search_flows` and `get_flow` ([all of them](docs/guide.md#mcp-tools)).
- After it acts on the phone (through RoamRun, say), `wait_for_flows` returns
  the requests that action sent.
- With a rule you marked as a preset in the `--rules` file, it can also turn
  that rule on, a few minutes at a time (`activate_preset`,
  [presets](docs/guide.md#presets-an-agent-can-turn-on)): a mock to see how
  the app takes an error, or a `map_remote` or `resolve` rule to send the app
  to your staging server.
- The tools cannot write or change a rule (an agent with file access writes
  one only when you ask).

`reqcove cleanup` lists how to undo everything; stopping, restarting and
updating are in [the guide](docs/guide.md#stop-restart-update).

### Options

The main ones. All of them are in [the guide](docs/guide.md#options).

| | |
|---|---|
| `--device NAME` | a device to carry (as in `tailscale status`); repeat for more |
| `--allow-hosts` | hosts whose requests are recorded (their connections decrypted): `api.example.com`, `*.example.com`, `'*'` for all, `@FILE` |
| `--pass-hosts` | allowed hosts to carry undecrypted, for apps that pin certificates |
| `--rules FILE` | rewrite where allowed hosts' requests go (`map_remote`, `map_local`, …), or answer them here (`mock`) |
| `--state DIR` | where the node key and the CA live, `~/.reqcove` by default |

### More

- [Read the traffic with an agent](docs/guide.md#read-the-traffic-with-an-agent): the skill, agents on your other devices
- [Look at the flows yourself](docs/guide.md#look-at-the-flows-yourself): on the iPhone, as a HAR file, in mitmweb
- [Record clients other than iPhone apps](docs/guide.md#record-clients-other-than-iphone-apps): apps that pin certificates, Android, the iOS Simulator, a web app's backend
- [Change where requests go](docs/guide.md#change-where-requests-go): to a development server, or on through another proxy
- [Run it in the background](docs/guide.md#run-it-in-the-background), [troubleshooting](docs/guide.md#troubleshooting)
- [Several exit nodes on one computer](docs/several-exit-nodes.md), [in a container](docs/container.md), [another Mac as a device](docs/another-mac.md)
- [Compatibility](docs/COMPATIBILITY.md): what stays stable from v1.0.0, and how it changes

### Without Tailscale (LAN mode)

On the same network, the iPhone can also use this computer as its Wi-Fi
proxy, with no Tailscale:

```sh
reqcove run --lan --allow-hosts api.example.com
```

Wi-Fi only, ports 80 and 443 only, and no password: an address you allow on
this computer can send through it. The steps (the iPhone's proxy setting,
allowing its address, trusting the CA), what it reaches and what blocks it are
in [the guide](docs/guide.md#without-tailscale-lan-mode---lan). Tried with an
iPhone on a home Wi-Fi (iOS 27.3).

## What it keeps safe, and what it does not

- Only requests to the hosts in `--allow-hosts` are recorded. Connections to
  Apple's hosts always pass undecrypted.
- A request to another host that rides on an allowed host's connection (HTTP/2
  connection reuse) is decrypted too. It is not recorded, but `--web` shows it
  and `--upstream-proxy` may receive it.
- The secrets Reqcove recognises (tokens, keys, cookies, passwords) are masked
  as they arrive. **Other secrets in a body, under names that do not say so,
  are not found** (add yours with `--mask-names` or `--mask-values`), and
  personal data such as e-mail addresses is not masked.
- What the agent reads goes to its model provider. Bodies are written by remote
  sites and may try to instruct the agent.
- The exit node refuses this computer, its LAN and the tailnet as destinations.
- LAN mode (`--lan`) has no password: an address you allow on this computer
  can reach the internet through it from your address (ports 80 and 443), and
  the private hosts named exactly in `--allow-hosts`.

More in [docs/SECURITY.md](docs/SECURITY.md).

## Limits

- Apps that pin certificates refuse Reqcove's; see [`--pass-hosts`](docs/guide.md#apps-that-pin-certificates---pass-hosts).
- Only TCP ports 80 and 443 go through mitmproxy; other ports are carried as they are.
- A connection to an allowed host that mitmproxy does not read as HTTP is
  recorded as a connection only: what it carries has no flows. That is
  another protocol, an ALPN mitmproxy does not know when the server speaks
  first or the client's bytes do not look like HTTP, and what a `101`
  upgrades to. See [raw TCP](docs/guide.md#connections-not-read-as-http-raw-tcp).
- IPv6 is refused and QUIC dropped (except to Apple); apps fall back to IPv4 and TCP.
- The phone cannot reach this computer or its LAN directly; a rule can send an
  allowed host's requests there.
- If reqcove stops while the iPhone uses it, the iPhone's DNS can stay stuck
  ([tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)):
  turn the exit node off and on again.
- The computer must stay awake: `reqcove run` keeps macOS from idle sleep, not
  from a closed lid (`--keep-awake=ac` holds it on AC power only, since v1.2).

More in [the guide](docs/guide.md#limits).

## License

MIT. Reqcove uses a fork of Tailscale (BSD-3-Clause) and other open source
modules; release archives include their licenses.
