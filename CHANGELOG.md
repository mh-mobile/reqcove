# Changelog

## Unreleased

- `run --upstream-proxy http://HOST:PORT` (and `--upstream-ca FILE`): decrypted
  requests go on through Burp Suite or another HTTP proxy, which sees the same
  traffic while Reqcove keeps its records. See "An upstream proxy" in the README.
- Burp's CA is fetched from `http://burp/cert` at start when the proxy is on this
  computer, so `--upstream-ca` is needed only for other proxies that decrypt.
- `reqcove help` (also `-h`, `--help`) shows the commands.
- `--dns 1.1.1.1` works without the port (53).
- Without `--device`, `run` suggests your iPhones and iPads on the tailnet (from the
  Tailscale CLI, when there is one), and it prints the `claude mcp add` command.
- A request a `--rules` rule fails on (such as a `map_remote` making a bad port)
  is answered with a 502 instead of going on unrewritten.
- `resolve` sets the SNI in `tls_start_server`, so it also holds through a proxy;
  `resolve` and `--upstream-proxy` are refused together (Burp connects by name).
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
