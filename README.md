# Reqcove

Hand the HTTP(S) traffic of an iPhone, on your desk or far away, to an AI agent.

[日本語](README.ja.md)

The iPhone picks your computer as its Tailscale **exit node**. Reqcove, a single
binary on that computer, carries the traffic, has [mitmproxy](https://mitmproxy.org)
decrypt the hosts you allow, and serves the flows to your agent over
[MCP](https://modelcontextprotocol.io). Nothing to configure on the phone beyond
choosing the exit node and trusting a CA once, and it works over 5G as well as Wi-Fi.

```
iPhone ──(tailnet, exit node)──▶ reqcove run ──SOCKS5──▶ mitmproxy ──▶ internet
                                     │                       │
                                     │                 addon: flows
                                     ▼                       ▼
                              agent ◀── MCP ── reqcove mcp ◀─ records (masked)
```

Reqcove is a separate tool from RoamRun, which brings a remote device to Xcode
and does not read its traffic.

> **Status: early.** v0.1 is not released yet. Everything below was tried on
> macOS (Apple silicon) and Ubuntu 24.04 (arm64) with an iPhone; where something
> has not been tried, this README says so.

## What you need

- macOS on Apple silicon, or Linux (amd64 or arm64)
- [uv](https://docs.astral.sh/uv/). Reqcove fetches mitmproxy (12.3.1) and Python with it
  on the first run; nothing else to install
- A Tailscale tailnet, and the Tailscale app on the iPhone

## Install

Until there is a release, build from source (Go 1.27):

```sh
git clone https://github.com/mh-mobile/reqcove && cd reqcove
go build -o reqcove ./cmd/reqcove
```

`go install …@version` does not work: Reqcove uses a fork of Tailscale's tsnet
through a `replace` directive.

The macOS binaries in releases are not signed with a Developer ID or notarized.
Downloaded with `curl` they run; downloaded with a browser, macOS kills them
on start (exit status 137) until you remove the download mark:

```sh
xattr -dr com.apple.quarantine reqcove_*_darwin_arm64
```

## Use

1. Start it on the computer, naming the iPhone (as in `tailscale status`) and the
   hosts to record:

   ```sh
   reqcove run --device iphone --allow-hosts 'api.example.com,*.example.com'
   ```

   The first time, it prints a login URL. Under Tailnet Lock it then prints the
   `tailscale lock sign nodekey:…` to run on a signing device, and asks you to
   approve the exit node in the admin console. `reqcove status` always says
   what is still missing.
2. On the iPhone, in the Tailscale app, choose the exit node `reqcove`.
3. Still on the iPhone, with the exit node on, scan the QR code `reqcove run`
   prints with the Camera, or open `http://mitm.it` in Safari (type the `http://`
   yourself; Safari may try HTTPS otherwise and warn); install the iOS profile,
   and trust it in Settings › General › About › Certificate Trust Settings. The
   CA is named `Reqcove CA (<computer>, <date>)`.
4. Give your agent the tools. For Claude Code:

   ```sh
   claude mcp add reqcove -- reqcove mcp
   ```

   Then ask it things like "which requests to api.example.com failed in the last
   ten minutes?"

Instead of the exit node, the iPhone can also set its Wi-Fi proxy (Manual) to the
reqcove node's tailnet address, port 8080 (`--proxy-port`). Cellular has no proxy
setting, so this works on Wi-Fi only.

### MCP tools

| Tool | |
|---|---|
| `list_flows` | flows, newest first; filter by device, host (and subdomains), time (`since: "10m"`), status (`404`, `4xx`, `none`), method; paged |
| `search_flows` | text in URLs and headers (and body heads with `bodies`) |
| `get_flow` | one flow; bodies only with `bodies` |
| `summarize` | counts by host, User-Agent, status, method, device, content type |
| `list_devices` | carried devices, their counts and last activity |
| `list_tls_failures` | handshakes a device refused: often certificate pinning, or a CA not trusted yet |
| `capture_stats` | mitmproxy's state, the window the records cover, drops |
| `status` | whether everything is set up, and the next steps if not |

### Options

| | |
|---|---|
| `--device NAME` | a device to carry: machine name, device name (your own untagged devices only), tailnet IP or StableID; repeat for more |
| `--allow-hosts` | hosts to decrypt and record: `api.example.com`, `*.example.com`, or `'*'` for all. Without it, traffic is carried but nothing is recorded |
| `--rules FILE` | YAML of rules for allowed hosts only (see below) |
| `--web` | run mitmweb on `http://127.0.0.1:8081` instead (no masking, can edit and replay, keeps every flow) |
| `--dns` | the exit node's DNS upstream, `1.1.1.1:53` by default; `system` for `/etc/resolv.conf` |
| `--no-redact` | keep secrets in the records |
| `--state DIR` | `~/.reqcove` by default: the node key, the CA and its private key. A new or empty directory, or one reqcove used before |

### Rules

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

## What it keeps safe, and what it does not

- Only the hosts in `--allow-hosts` are decrypted and recorded; requests to other
  hosts on the same connection are counted, not recorded. Apple's hosts always pass
  through undecrypted.
- Secrets are masked as they arrive: headers and query parameters whose names
  contain words such as authorization, token, secret, key or signature
  (`accessToken` and `X-Amz-Signature` too), cookie values, and the same
  parameters wherever a URL appears (fragments, `Referer`, `Location`, other
  headers, bodies, error messages), along with a URL's password. In bodies,
  the values of such JSON and form fields are masked, and so are credentials
  recognisable by their shape (`Bearer …`, JWTs, keys such as `ghp_…`, `sk-…`,
  `AKIA…`) anywhere. **Other secrets in a body, under names that do not say so,
  are not found**, and personal data such as e-mail addresses is not masked.
  Bodies that are not text cannot be checked, so they are not handed out.
- What the agent reads goes to its model provider. Bodies are written by remote
  sites and may try to instruct the agent; the tools say so.
- Only reqcove may use mitmproxy's SOCKS5 port (a password made each run). The MCP
  socket and the state directory are open to your OS user only.
- The exit node refuses this computer, its LAN and the tailnet as destinations.
- Logs are not sent to Tailscale. A tailnet that requires data plane audit logs is
  not supported, and `reqcove status` says so.

More in [docs/SECURITY.md](docs/SECURITY.md).

## Limits

- Apps that pin certificates cannot be decrypted (`list_tls_failures` shows them).
- Only TCP ports 80 and 443 go through mitmproxy; other ports are carried as they are.
- The exit node refuses this computer and its LAN as destinations, so the phone
  cannot reach a development server there directly; a rule can send an allowed
  host's requests to it (`map_remote` with `keep_host_header`, see Rules).
- IPv6 is refused (apps fall back to IPv4 at once). QUIC is dropped except to Apple,
  so apps fall back to TCP.
- Phone calls through the exit node have not been tried.
- mitmproxy holds each WebSocket message until it is complete, so one huge message
  can use a lot of memory (if mitmproxy runs out, reqcove restarts it).
- `map_local` answers only requests whose body is at most 1 MiB and of known length;
  others go on to the real destination (the record says so). An HTTP/2 GET without
  a length is answered too, and a body the device sends with it anyway is held
  whole; only your own devices send these requests.
- If reqcove stops while the iPhone uses it, the iPhone's DNS can stay stuck after
  reqcove is back ([tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)):
  turn the exit node off and on again.
- The computer must stay awake; `reqcove run` keeps macOS from idle sleep, but not
  from a closed lid.

## Tips

- To skip approving the exit node for every new node, add an auto-approver to the
  tailnet policy: `"autoApprovers": {"exitNode": ["you@example.com"]}`.
- The CA stays the same as long as the state directory does. To use one CA on two
  computers, copy `~/.reqcove/mitmproxy/` whole (it holds the private key).
- `reqcove cleanup` lists how to undo everything; `--delete-state` deletes the state
  directory (only one reqcove made).

## License

MIT. Reqcove uses a fork of Tailscale (BSD-3-Clause) and other open source
modules; release archives include their licenses.
