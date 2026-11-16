# Compatibility

[日本語](COMPATIBILITY.ja.md) · [README](../README.md)

**This applies from v1.0.0.** Before it (v0.x), a minor release could change
anything here, and some did.

What stays as it is within a major version, what may change in any release, and
how changes are announced. The lists come from the code (the tools as the MCP
server registers them, each command's flags, the rules file's loader), not from
memory. Where tests check a point, the last line of its section says so; the
rest comes from reading code.

1. [Versions](#versions)
2. [Stable within a major version](#stable-within-a-major-version)
3. [Not stable](#not-stable)
4. [`reqcove mcp` and a `run` of another version](#reqcove-mcp-and-a-run-of-another-version)

## Versions

From v1.0.0, versions are `major.minor.patch` ([semantic versioning](https://semver.org)):

- A patch release (1.0.1) fixes. What this page lists as stable works as before,
  except for a security fix (below).
- A minor release (1.1.0) adds: tools, optional inputs, output fields, commands,
  flags, rule keys. It may deprecate something, never remove it.
- A major release (2.0.0) may remove or change what is stable, deprecated first.

### Deprecation

- Announced in a minor release: the CHANGELOG lists it under "Deprecated", with
  what to use instead, and a deprecated tool's description starts with
  "Deprecated".
- It keeps working as before until it is removed, no earlier than the next major
  release.

### Security fixes

A security fix may change behaviour in any release, a patch release included,
when keeping the old behaviour would leave users exposed. It may refuse what was
accepted (a flag's value, a rule, a `--config` line), mask more, show less in a
tool's answer, or turn something off, even something this page lists as stable.
It is not held back for a major release. The CHANGELOG says so under "Security",
with what changed and what to do.

## Stable within a major version

Within a major version, what is listed here is not removed and does not change
meaning; minor releases may add to it.

### MCP tools

On this computer (`reqcove mcp`, and `run`'s socket), 19 tools:

`status`, `list_flows`, `wait_for_flows`, `search_flows`, `summarize`,
`get_flow`, `list_ws_messages`, `diff_flows`, `list_devices`,
`list_tls_failures`, `list_passthrough`, `capture_stats`, `list_presets`,
`activate_preset`, `deactivate_preset`, `list_rules`, `explain_rules`,
`add_marker`, `list_markers`.

Since v1.2, `reqcove mcp` alone also has `request_capture_add` (`hosts`: 1
to 5 host names) and `get_capture_request` (`id`), 21 tools there: never on
`run`'s socket's own list, never over `--mcp-http`. Both answer a request:
`id`, `hosts`, `state` (`pending`, `approved`, `applied`, `failed`,
`denied`, `expired`; more values may come), `created_at` and `expires_at`
(RFC 3339), `approved_in` (`terminal` or `dialog`; `console` from `reqcove console`), `result` (text for
people), `approve` (while pending, the command the user runs), `unmasked`
(true while `run` masks nothing, `--no-redact`) and `note`.

Over `--mcp-http`, the first twelve (`status` to `capture_stats`), never the
preset, rule and marker tools; its `status` has no `active_presets` or
`active_presets_error`. Its server answers at `/mcp`, on the node's port
8090, with `Authorization: Bearer` and the token in `mcp-token` (the state
directory, below).

Removed in v1.0.0, deprecated since v0.8.0 (v0.6's names):

| Removed | Use |
|---|---|
| `list_mock_presets`, `activate_mock`, `deactivate_mock` | `list_presets`, `activate_preset`, `deactivate_preset` |
| `status`' `active_mock_presets`, `active_mock_presets_error` | `active_presets`, `active_presets_error` |
| `capture_stats`' `mock_presets` | `presets` |

Each tool's fields:

- Inputs: the fields of its input schema, as `run` lists the tools. A new input
  comes only as an optional one, in a minor release. An input is never removed,
  made required, or changed in meaning within a major version.
- Outputs: the fields of its output schema, as `run` lists the tools, and, for
  `status` and `capture_stats` (whose schemas leave their contents open), the
  fields listed below. New fields may come in a minor release: an agent ignores
  those it does not know. A field is never removed or changes meaning within a
  major version.
- These values keep their meaning: `status`' `mode` (`tailnet`, `lan`),
  `capture_stats`' `state` (`starting`, `ready`, `restarting`, `failed`), a
  preset's `kind` (`mock`, `map_remote`, `modify_headers`, `resolve`), a marker's
  `source` (`cli`, `mcp`), a `list_passthrough` connection's `reason`
  (`pass_hosts`, `raw_tcp`). A minor release may add a value (a new mode, say).
- A field that holds text written for people (`next_steps`, `note`, `msg`,
  error fields such as `list_rules`' and `explain_rules`' `rules_error`, and
  `active_presets_error`) stays; its wording is not stable.

#### `status` and `reqcove status --json`

`reqcove status --json` prints the `status` tool's JSON. When no run answers
(none runs, or one is starting or stopping), it prints nothing on stdout and
exits 1, saying why on stderr. Its fields:

- `mode`, `next_steps`, `allow_hosts`, `pass_hosts`, `service`, `capture`
  (`capture_stats`' fields, below), `active_presets` and `active_presets_error`.
  Each of `active_presets` has `name`, `kind`, `description`, `target`,
  `header`, `host`, `address`, `method`, `url`, `operation`, `status`,
  `delay_ms`, `fault`, `active`, `remaining`, `expires_at` (as `list_presets`'
  presets).
- Since v1.1, while the hosts are changed live (`reqcove capture`, `reqcove reload`):
  `scope_pending` (a change mitmproxy has not acknowledged yet, text for
  people; absent when none), `scope_changed_at` (RFC 3339) and `scope_change`
  (the command, such as `capture add api.example.com` or `reload`), absent before the
  first change. `allow_hosts` and `pass_hosts` are the hosts mitmproxy has
  acknowledged.
- Since v1.1, `recording`: `on`, or `stopped` (`reqcove capture stop`, until
  `capture start`; more values may come). While stopped, `allow_hosts` is `[]`
  and `pass_hosts` absent (nothing is recorded); `base_allow_hosts` and
  `base_pass_hosts` are the hosts recorded when it is on (absent when none),
  while stopped the ones `start` records. Absent from a run older than v1.1.
- Since v1.1, `recording` is also `allow-all` (`reqcove capture allow-all
  --for D`, until it ends): `allow_hosts` is `["*"]`, `pass_hosts` the hosts
  still passed undecrypted, `base_allow_hosts` the hosts recorded after it;
  `allow_all_until` (RFC 3339) and `allow_all_left` (a Go duration, such as
  `29m10s`) say when it ends, absent when off. `records_outside_scope`: the
  records kept whose host `base_allow_hosts` does not record (allow-all's,
  kept after it ends, or those of hosts removed since); absent when none.
- Since v1.1, about the run itself: `version` (as `reqcove version` prints
  it, as `serverInfo`'s), `manager` (what started it: `terminal`,
  `reqcove service` for `reqcove service install`'s LaunchAgent or unit,
  `brew services`; more values may come; absent when it cannot be told),
  `restart_command` (the command that restarts it under its service, such as
  `brew services restart reqcove`, or `reqcove service install` when that
  service runs another binary than `run`, or one gone; absent from a
  terminal), and, on this
  computer only (not over `--mcp-http`), `config_file` (the `--config` file
  it read, in full; absent for flags only), `config_unused` (the other config
  file a `run` with no arguments found there and did not read) and
  `hosts_files` (the files `--allow-hosts=@FILE` and `--pass-hosts=@FILE`
  read). Absent from a run older than v1.1: `reqcove status` takes the
  version from `serverInfo` then.
- Since v1.2, on this computer only (not over `--mcp-http`): `executable`
  (`run`'s binary, its symlinks resolved) and, on macOS, `keep_awake`
  (`always`, `ac` or `never`). Absent from a run older than v1.2.
- Since v1.2, on this computer only (not over `--mcp-http`):
  `capture_requests`, the agents' requests waiting for the user (each as
  `get_capture_request` answers it, without `note`); absent when none.
- Since v1.1, on this computer only (not over `--mcp-http`), host discovery
  (`reqcove capture discover`): `discover_until` (RFC 3339) and
  `discover_left` while it is on; `out_of_scope_hosts` (each with `host`,
  `count`, and `add`, the command that records it, absent for a name that is
  not a plain host name; at most 30, most seen first) and
  `out_of_scope_hosts_kept` (how many names are kept), absent when none.
  `summarize` gets `out_of_scope_hosts` too, the same, not narrowed by its
  filters.
- `node`: `backend`, `node`, `ips`, `exit_node_approved`,
  `tailnet_lock`, `tailnet_lock_signed`, `node_key`, `devices`, `device_os`,
  `device_problems`, `health`. `backend`'s values and `health`'s texts are
  Tailscale's, not Reqcove's: not promised.
- `lan`, in LAN mode only: `interface`, `network`, `listen`, `stopped`,
  `allowed` (each with `addr` and `allowed_at`), `refused`, `refused_more`.

Checked by a unit test: when no run answers, nothing on stdout, exit status 1
and the reason on stderr. By unit tests too: v1.1's fields, and a new
`reqcove status` reading a v1.0.0 `run`'s answer.

#### `capture_stats`

Its documented fields: `flows`, `flows_with_truncated_bodies`, `evicted`,
`checkpoint`, `oldest_flow`, `newest_flow`, `max_flows`, `max_bytes`, `state`,
`started`, `redacting`, `out_of_scope`, `passed_through`, `raw_tcp`,
`raw_tcp_hosts`, `refused_hosts`,
`pass_hosts`, `mitmproxy`, `python` (their versions), `presets`, `retries` (since
v1.1: attempts in a row to start mitmproxy again), `last_failure` (since v1.1:
why it last failed, text for people; "" when it has not), `next_attempt` (since
v1.1: while it waits to try again), `rules_loaded`
(once a rules file was taken), `recording` (since v1.1: `on`, `stopped` or
`allow-all`, as `status`'s; while stopped, `pass_hosts` is none), and, while masking is on, `mask_names` and
`mask_values` (the matches per name and per pattern number). The others are
[not stable](#not-stable).

### The rules file (`--rules`)

Its top-level keys: `mock`, `map_remote`, `map_local`, `modify_headers`,
`resolve` (each a list) and `keep_host_header` (`true` or `false`). Any other key
is refused.

- `map_remote`, `map_local` and `modify_headers`: one string per rule, in
  mitmproxy's own syntax, read by mitmproxy's code. Reqcove keeps the mitmproxy
  it locks up to date ([below](#not-stable)); an update that would change how
  such a rule reads waits for a major release, unless it is a security fix.
- `mock` (Reqcove's): a list of mappings with `match` (`url`, and optionally
  `method` and `operation`), `status`, `headers`, `body` or `body_file`,
  `delay_ms`, `fault` (`close`, with no `status`, `headers`, `body` or
  `body_file`), `preset`, and `description` (with `preset`).
- `resolve` (Reqcove's): one string per rule, `HOST=IPV4` or `HOST=IPV4:PORT`.
- `keep_host_header` (Reqcove's): `map_remote` keeps the app's `Host`.
- A `map_remote`, `modify_headers` or `resolve` preset: a mapping `{rule,
  preset, description}`, with `rule` the rule's string as above, `preset` its
  name (needed in a mapping), `description` optional. `map_local` takes no
  preset; a `modify_headers` preset changes requests only (no `~s`).
- A preset's name: letters, digits, `.`, `_` and `-`, at most 64; a
  description: one line, at most 200 characters.

A file that loads in v1.0.0 keeps loading, and does the same, in every v1
release (security fixes aside). A minor release may add a key or a kind; a file
that uses it does not load in an older version.

### The CLI

The commands and their flags, from each command's flag set:

| Command | Flags |
|---|---|
| `reqcove run` | `--device`, `--allow-hosts`, `--pass-hosts`, `--rules`, `--rules-reload`, `--proto`, `--upstream-proxy`, `--upstream-ca`, `--local-proxy`, `--proxy-port`, `--lan`, `--lan-interface`, `--ui`, `--web`, `--mcp-http`, `--dns`, `--no-redact`, `--mask-names`, `--mask-values`, `--state`, `--hostname`, `--verbose`, `--config`, `--keep-awake` (v1.2) |
| `reqcove status` | `--json`, `--state` |
| `reqcove har` | `--host`, `--device`, `--since`, `--until`, `--status`, `--method`, `--user-agent`, `--limit`, `--state` (a HAR 1.2 file on standard output) |
| `reqcove links` | `--state` |
| `reqcove lan allow ADDR`, `lan deny ADDR`, `lan list` | `--state` |
| `reqcove mark [TEXT]` (`-- TEXT` for one starting with `-`) | `--state` |
| `reqcove capture add HOST…`, `capture remove HOST…` (since v1.1) | `--pass`, `--state` |
| `reqcove capture set` (since v1.1) | `--allow-hosts`, `--pass-hosts`, `--state` |
| `reqcove capture stop`, `capture start` (since v1.1) | `--state` |
| `reqcove capture save` (since v1.1) | `--state` |
| `reqcove capture allow-all` (since v1.1) | `--for D` (at most `24h`) or `--end`, `--state` |
| `reqcove capture discover` (since v1.1) | `--for D` (at most `24h`) or `--end`, `--state` |
| `reqcove capture requests`, `capture approve ID`, `capture deny ID` (since v1.2) | `--state` |
| `reqcove console` (since v1.2) | `--end` (since v1.3), `--state` |
| `reqcove reload` (since v1.1) | `--state` |
| `reqcove mock add` | `--rules`, `--url`, `--method`, `--operation`, `--status`, `--header`, `--body`, `--body-file`, `--delay-ms`, `--fault`, `--preset`, `--description`, `--print`, `--state` |
| `reqcove setup` | none |
| `reqcove service install` | `--config`, `--state` |
| `reqcove service restart`, `service uninstall` | none |
| `reqcove init` | `--client NAME` (`claude`, `agents`, `codex`, `cursor`, `gemini`, `copilot`, `devin`), `--print`, `--uninstall` |
| `reqcove cleanup` | `--delete-state`, `--hostname`, `--state` |
| `reqcove mcp` | `--state` |
| `reqcove version` | none |

`--uvx`, `--python` and `--mitmproxy-spec` are not in this list: they are not
stable ([below](#not-stable)).

`reqcove console` (since v1.2) asks `run` over `ctl.sock` with a new op, `console`: a
`run` older than v1.2 answers it with its usage, and `reqcove console` then says
to restart `run` with v1.2 or later (a unit test with a v1.1 answer). The
page's link (`http://127.0.0.1:PORT/#c=CODE`) and what it shows are not
stable, nor its requests to `run` ([below](#not-stable)). Since v1.3 `run`'s
answer to `console` also names a file in the state directory that opens the
page (`file`; a v1.2 `reqcove console` ignores it and opens the link, in its
arguments, as before; a v1.3 one against a v1.2 `run` opens nothing and
prints the link), and `reqcove console --end` asks with another new op,
`console-end`: a v1.2 `run` answers it with its usage (in LAN mode, with its
LAN refusal), and `reqcove console --end` then says to restart `run` with
v1.3 or later (unit tests with both answers).

### The `--config` file

- `run`'s flags, one a line, read before the command line's: a flag
  given once is the command line's, a repeatable one (`--device`,
  `--allow-hosts`) adds up. Blank lines and lines starting with `#` are skipped.
  Words split at spaces, kept together in `'…'` or `"…"` (`\"` and `\\` inside)
  as a shell would; a word starting with `~/` starts at the home directory.
- Refused in it: `--no-redact`, `--web`, `--rules-reload`, `--lan`, `--config`,
  and `--allow-hosts '*'`, however it is written (`@FILE` included).
- The file must be a plain file, yours, with no permission for group or others
  (`chmod 600`).
- Its places: `~/.config/reqcove/config` for `reqcove service install` (its
  `--config` by default) and `reqcove setup` without Homebrew; with Homebrew,
  `reqcove setup` writes `$(brew --prefix)/etc/reqcove/config`, which
  `brew services` reads.
- Since v1.1, a `reqcove run` with no arguments at all (refused before)
  reads `~/.config/reqcove/config`, else Homebrew's (when that `reqcove` is
  Homebrew's), as `--config FILE` does; with neither, it asks for `--device`
  as before. A `run` with any argument reads a file only when `--config`
  names it, as in v1.0. `reqcove service install` without `--config` takes
  the same file (installed already: the installed service's `--config`).
- Since v1.1, `reqcove setup` writes the hosts to their own file beside it,
  `hosts` (`~/.config/reqcove/hosts`, or `$(brew --prefix)/etc/reqcove/hosts`),
  one host a line, `#` starting a comment, and the config line
  `--allow-hosts=@FILE` for it; `reqcove capture save` rewrites that file.
  A config written before (hosts on the `--allow-hosts` line) is read as
  before.

### The state directory

`~/.reqcove` by default (`--state DIR`). The files a user touches:

- `mitmproxy/mitmproxy-ca-cert.pem`: the CA's certificate, to trust it on this
  computer or in a browser ([guide](guide.md#the-ios-simulator---local-proxy)).
- `mitmproxy/`, whole, with `mitmproxy/mitmproxy-ca.pem` (the CA's private key
  and certificate): copied to share one CA with another computer
  ([guide](guide.md#use-one-ca-on-two-computers)).
- `lan-allowed`: the addresses LAN mode carries; change it with `reqcove lan`.
- `mcp-token` and `ui-token`: the tokens of `--mcp-http` and `--ui`, read to
  give them to an agent or a browser, deleted to make new ones
  ([guide](guide.md)).
- `ca-copies`, in `~/.reqcove` only: the state directories its CA was copied
  into, which `reqcove cleanup` names.

The other files there (`mcp.sock`, `tsnet/`, the logs, the pid and
proxy files) are Reqcove's own and may change in any release.

### The skill

`reqcove init` writes the skill to `~/.claude/skills/reqcove` (Claude Code) and
`~/.agents/skills/reqcove` (Codex, Cursor, Gemini CLI, Copilot CLI, Devin), or
only those `--client` names. These places and `init`'s flags are stable. The
skill's text changes with each version: run `reqcove init` again after an update
(`reqcove status` says when an installed skill is from another version).

## Not stable

These may change in any release, a patch release included:

- Log lines: `run`'s, the service's, mitmproxy's.
- The ready block `run` prints: its wording and layout.
- Error texts and refusals, of the commands and of the tools; the tools'
  descriptions and the server's instructions (only the "Deprecated" at the
  start of a deprecated tool's description is kept).
- `reqcove status`' text (its `--json` is stable).
- The mitmproxy Reqcove runs and its Python lock (`internal/capture/mitm.py.lock`):
  updated for security fixes, in any release. Which mitmproxy version a release
  runs is not promised.
- `--uvx`, `--python` and `--mitmproxy-spec` (of `run`; `--uvx` of `status` and
  `mock add` too), and their defaults: they choose how mitmproxy is run (uv, a
  Python, a mitmproxy version), and follow mitmproxy and uv.
- `capture_stats`' fields not listed above: `held_bytes`, `restarts`,
  `state_detail`, `tls_failures`, `passed_through_open`, `addon_dropped_bodies`,
  `addon_dropped_events`, `bad_lines`, `masking_failed`, `unknown_version`,
  `orphan_updates`, `all_hosts`, `brotli`, `brotli_decode`, `zstd_decode`,
  `rules`, `rules_error`, `resolve`, `upstream`. They may change or go in a
  minor release.
- `reqcove console`'s page: its port, its layout, its `/api/` requests and their
  answers.
- The `poc/` folder: the maintainer's notes, not in the repository.
- Anything else this page does not list as stable.

## `reqcove mcp` and a `run` of another version

- The MCP server says its version when an agent connects (`serverInfo`: name
  `reqcove`, version as `reqcove version` prints it): over the socket, through
  `reqcove mcp`, and over `--mcp-http`.
- `reqcove mcp` lists its own version's tools, not those of the `run` it
  connects to, and without their output schemas, so that a `run` of another
  version is not refused for its answers.
- When `run`'s version is not `reqcove mcp`'s, the first answer after it
  connects carries a note: run both at one version, restart `reqcove run` with
  the newer one, then reconnect the agent's MCP server.
- A tool this `reqcove mcp` has and the `run` lacks: a preset, rule or marker
  tool answers that the running reqcove (its version) has no such tool; any
  other gets `run`'s own error, an unknown tool. `request_capture_add` and
  `get_capture_request` against a `run` older than v1.2 answer that it has
  no requests: restart it with v1.2 or later (a unit test).
- Mixed versions are not supported beyond these notes: run `reqcove run` and
  `reqcove mcp` at one version. A v1.0.0 `reqcove mcp` has no
  `list_mock_presets`, `activate_mock` or `deactivate_mock`, even against an
  older `run`; a call to one of them, to `run` or to `reqcove mcp`, gets a tool
  error naming what replaced it. A v1.0.0 `reqcove status` still reads an
  older `run`'s `active_mock_presets` and `mock_presets`; a v0.6 or v0.7
  `reqcove status` against a v1.0.0 `run` shows no preset on, since those
  versions read only the old names (from reading their code); their
  `reqcove mcp` passes `run`'s answer on as it is.

Checked by tests: the tools listed without output schemas, the note when the
versions differ, both answers for a tool the `run` lacks, the error for a
removed tool, and a v1.0.0 `reqcove status` reading an older `run`'s fields.
