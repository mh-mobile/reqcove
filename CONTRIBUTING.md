# Contributing to Reqcove

Thanks for helping. Issues and pull requests are welcome, in English or Japanese.

## Security problems

Please do not open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/mh-mobile/reqcove/security/advisories/new)
instead. [docs/SECURITY.md](docs/SECURITY.md) says what Reqcove protects and what
it does not.

## Building and testing

You need Go (the version in `go.mod`) and, for the end-to-end tests,
[uv](https://docs.astral.sh/uv/).

```sh
go build -o reqcove ./cmd/reqcove
go vet ./... && go test -race ./...
REQCOVE_E2E=1 go test -count=1 ./internal/capture/ ./internal/exitnode/ ./cmd/reqcove/   # real mitmproxy, from the lock
```

CI runs these on macOS and Linux, with `gofmt`, `staticcheck` and `govulncheck`,
and checks mitmproxy's lock (`internal/capture/mitm.py.lock`) against its
launcher and for known vulnerabilities (pip-audit). To move to another
mitmproxy: change the version and the date in `internal/capture/mitm.py`,
`capture.LockedMitmSpec` and `UVExcludeNewer`, then
`uv lock --script internal/capture/mitm.py --upgrade`.
A push or pull request that changes only docs (`*.md`, `docs/`, `poc/`) runs
only the checks and, on Linux, `go test ./cmd/reqcove/` (the tests that read the
docs and SKILL.md); anything else, or a change it cannot tell (a new branch, a
force-push), runs everything (`scripts/ci-docs-only.sh`). A tag is released only
when test.yml passed on its commit or, for a merge with the same tree as its
second parent (dev merged into main), on that parent (`scripts/release-gate.sh`).
The end-to-end tests use local servers, except `TestEndToEnd`, which also checks
that github.com and www.apple.com pass through undecrypted: it needs the internet.
Tests that need a real tailnet, an iPhone or hours (`REQCOVE_TRIAL2`,
`REQCOVE_SOAK`, `REQCOVE_UDP_MEASURE`) run only by hand.

Reqcove uses a fork of Tailscale's tsnet
([mh-mobile/tailscale](https://github.com/mh-mobile/tailscale), branch
`reqcove/v1.104.5`) through a `replace` directive in `go.mod`.

## What a change needs

- **A test that fails without it.** For a fix, check that the test fails when the
  fix is taken out. Prefer local servers to the internet in tests.
- **Docs that say only what was checked.** README, docs/guide.md and docs/SECURITY.md describe
  what was tried; when something comes from reading code or has not been tried,
  they say so. Update both READMEs and guides (English and Japanese) when behaviour changes.
- **Secrets stay out.** Records are masked as they arrive; a change that adds a
  field reaching the MCP tools needs to say how secrets in it are handled.
- Small, focused pull requests are easier to review. Open them against `dev`:
  `main` holds the released version only.

## Keeping the docs from growing back

docs/SECURITY.md is for someone deciding whether to trust Reqcove;
docs/masking.md is for someone checking whether their app's format is masked.
Neither is a log of what was fixed.

- **A fix goes to the CHANGELOG, with its test.** docs/SECURITY.md changes only
  when a property a reader relies on changes. History ("up to v0.8", "a review
  found") stays in the CHANGELOG.
- **A masking gap that is not fixed becomes one row in docs/masking.md**, never
  a new clause in SECURITY.
- **An option's detail goes in docs/guide.md**, under "Security details" in the
  option's section (「セキュリティの詳細」 in Japanese). SECURITY keeps a few
  lines per option: what it exposes, to whom, the main limit, what to do. The
  guide's block adds to those lines and does not repeat them, and the section
  keeps its main warning beside the instruction.
- **One point per bullet.** Mark only the exceptions where they stand ("not
  tried", "from reading the code"); what a test or a trial covered goes in the
  section's one "Checked:" line (「確認状況：」 in Japanese).
- **English and Japanese change together**: the same headings, facts, tables
  and warnings, each written as its own language.

## Reporting a bug

Please include the output of `reqcove version` and `reqcove status`, your OS,
and what you expected. Mask tokens, cookies and tailnet names before pasting.
