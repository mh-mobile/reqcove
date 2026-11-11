# Reqcove

Hands an iPhone's HTTP(S) traffic to AI agents over MCP: a Tailscale exit node
(tsnet) carries it, mitmproxy decrypts the allowed hosts, records are masked and
kept in memory. How to use it: `README.md`, in full `docs/guide.md`. What it protects: `docs/SECURITY.md`.
How to contribute: `CONTRIBUTING.md`.

## Layout

- `cmd/reqcove`: `run`, `status`, `cleanup`, `mcp`, `version`.
- `internal/exitnode`: the tsnet exit node (a fork of Tailscale through the
  `replace` in `go.mod`), the destination policy, the Remote Proxy, status and
  next steps.
- `internal/capture`: runs mitmdump from its lock (uv) as a child, with the embedded
  addon (`addon.py`), and records what it reports (masking, scope, bounds).
- `internal/mcpserver`: the MCP tools and the Unix socket bridge.

## Tests

- `go test -race ./...`: the usual tests (CI on macOS and Linux).
- `REQCOVE_E2E=1 go test ./internal/capture/`: real mitmproxy, from the lock (uv; CI too).
- `REQCOVE_TRIAL2=1` (memory), `REQCOVE_SOAK=4h` (soak), `REQCOVE_UDP_MEASURE=1`
  (UDP): by hand only.
- After a fix, check that its test fails with the fix taken out.

## Rules

- Docs say only what was checked; what was not tried, or comes from reading code,
  says so. Keep the English and Japanese READMEs (and guides) in step.
- Secrets must not reach the records, the MCP tools or the logs unmasked.
- Ask the maintainer before anything that leaves this computer (pushing a tag, a
  release, issues or pull requests upstream).
