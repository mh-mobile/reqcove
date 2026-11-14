# Reqcove guide

[日本語](guide.ja.md) · [README](../README.md)

What comes after the README's four steps. Each section ends with what was
tried and what was not.

1. [Set up](#set-up)
2. [Read the traffic with an agent](#read-the-traffic-with-an-agent)
3. [Look at the flows yourself](#look-at-the-flows-yourself)
4. [Record clients other than iPhone apps](#record-clients-other-than-iphone-apps)
5. [Change where requests go](#change-where-requests-go)
6. Reference: [Options](#options) · [MCP tools](#mcp-tools) · [Limits](#limits) · [Security](#security)

## Set up

The four steps are in the [README](../README.md#use).

### First start

`reqcove setup` walks through the first run, in a terminal only (it refuses
when its input or output is not one, as from an agent). Each step can be
skipped (an empty answer); it starts nothing and removes nothing:

- uv: says where `uvx` is, or how to install it (it installs nothing).
- The device and the hosts: writes `--device` and `--allow-hosts`, quoted, to
  the file the service reads: `~/.config/reqcove/config` (`reqcove service
  install`'s), or for a brew install (this binary under `Cellar/reqcove/`)
  Homebrew's `$(brew --prefix)/etc/reqcove/config` (`brew services`'). 0600,
  its directory 0700 when new; checked as `run` reads it before it takes the
  file's place. `*` and a name starting with `-` are asked again; a pasted URL
  keeps its host only. No hosts yet: once `run` runs, `reqcove status` (or an
  agent's `summarize`) lists the hosts the iPhone reached. An existing file is
  shown and kept unless you answer `y`; then it is replaced whole, and the old
  one kept as `config.old` (0600; its other flags, such as `--rules`, are
  there to copy back). A path that is not a plain file is left alone.
- The agent: adds the skill as `reqcove init` does, if you answer `y`, and
  prints `claude mcp add reqcove -- reqcove mcp` (it runs no agent command).
  When `reqcove` on `PATH` is not this binary (none, or another one), the
  commands it prints name this binary by its full path instead (as `service
  install`'s do).
- How to start: `brew services start reqcove` for a brew install, else
  `reqcove service install`; or `reqcove run --config FILE` in a terminal.
  `--lan` is not kept in a file: `reqcove run --lan --allow-hosts HOSTS` in a
  terminal. It prints no login URL: `reqcove links` does.
- Ctrl-C stops it at the question it is on; what was written stays.

Tried: unit tests (answers fed in, a temporary home and Homebrew prefix), and
Ctrl-C at the first question in a terminal (it ended at once, nothing written);
on macOS (2026-11-14): found uvx, wrote the file (0600, its directory 0700),
installed the skill, printed the commands, and `service install` ran with that
file. Not tried: `brew services` with the file setup wrote; Linux.

`run` prints what is left to do, and `reqcove status` repeats it: log in with
the URL, sign the node if the tailnet uses Tailnet Lock, approve the exit node.

- The login URL, and the `--ui`, `--web` and `--mcp-http` links with their
  tokens, are shown on `run`'s terminal only, not in its log lines (`--verbose`
  too; the login URL by its usual shapes until `run` learns it,
  [SECURITY](SECURITY.md#the-login-url)) or the MCP tools. Whoever opens the login URL first puts the
  node in their own tailnet ([SECURITY](SECURITY.md#the-login-url)).
- `reqcove links` prints them again (and mitmweb's link on this computer, the
  CA's), with QR codes, in your terminal (it refuses
  when its output is not a terminal: Claude Code's `!` gets nothing either, tried). Off a terminal (a service, `docker logs`),
  `run` prints "`reqcove links` prints it" in their place. While `run` runs they
  are kept in `login-url` and `links` (0600) in the state directory.
- To skip the approval for new nodes, add an auto-approver to the tailnet
  policy: `"autoApprovers": {"exitNode": ["you@example.com"]}`.

### Use one CA on two computers

The CA lasts as long as the state directory. Copy `~/.reqcove/mitmproxy/` whole
(it holds the private key) into `~/.reqcove/` on the other computer, with
reqcove stopped there, or before its first run.

### Stop, restart, update

- **Stop** with Ctrl-C. The records are in memory and go with it. If the
  iPhone's DNS then stays stuck
  ([tailscale#20870](https://github.com/tailscale/tailscale/issues/20870)),
  turn its exit node off and on again.
- **Restart**: while `run` is down, `reqcove mcp` stays up and the tools answer
  that it is not running; then they work again without reconnecting the agent
  (`/mcp` in Claude Code). The records start empty, and the first answer's
  `note` says so.
- **Update** (a newer version: `brew upgrade reqcove`, or a new build
  from source): restart `run` with it, reconnect the agent once for the new
  tools (they say so while the versions differ), and run `reqcove init` again
  for the skill.

Tried: a restart under a Claude Code session.

### Keep it running (`brew services`)

To have `run` start at login, put its flags, one a line, in a file and let
`brew services` start it. First: while the Mac sleeps, an iPhone on its exit
node has no internet; turn the exit node off before it sleeps.

```sh
mkdir -p "$(brew --prefix)/etc/reqcove"
printf -- '--device iphone\n--allow-hosts api.example.com\n' > "$(brew --prefix)/etc/reqcove/config"
chmod 600 "$(brew --prefix)/etc/reqcove/config"
brew services start reqcove
reqcove links        # the login URL, the first time (after a minute: the first start fetches mitmproxy; tail -f "$(brew --prefix)/var/log/reqcove.log")
reqcove status       # "service: sh.brew.reqcove" (homebrew.mxcl.reqcove with an older Homebrew)
```

- `--config FILE` takes `run`'s flags, one a line (`#` starts a comment;
  quote as a shell would: `--device "Taro's iPhone"`; `~/` is your home; give
  paths in full or from `~/`, as a service starts in `/`). The
  command line's come after them: a flag given once is the command line's, a
  repeatable one adds up. `--no-redact`, `--web`, `--rules-reload`, `--lan` and
  `--allow-hosts '*'` (also from an `@FILE`) are refused there: they stay on
  the command line. The file must be yours and readable by you only (`chmod
  600`): it may hold `--mask-values` patterns. One `--config` only.
- A missing or refused file ends the service once (`brew services` shows an
  error); it is not started again in a loop. Nor is it after any other end:
  `brew services restart reqcove` (also after `brew upgrade reqcove`).
  Nothing is read unless named.
- The log is `$(brew --prefix)/var/log/reqcove.log`, and `mitmproxy.log` in the
  state directory grows too; neither is rotated (by launchd or by reqcove):
  truncate them now and then. Neither carries a login URL or a token: `reqcove
  links` prints them, in your terminal.
- A `run` in your terminal on the same state finds it in use: `brew services
  stop reqcove` first.
- `run` keeps the Mac from idle sleep while it runs
  (`caffeinate -i`, as from a terminal, also on battery: it drains it), not
  from closing the lid or choosing Sleep.

Linux: Homebrew's `brew services` makes a systemd unit from the same formula
(from Homebrew's documentation, not tried; `status` names no service there).
Without Homebrew, see the next section.

Tried: the config file's parsing and refusals (unit tests); `brew services
start` and `stop` on macOS 27 with the formula (uv found on its PATH; the
config read; an iPhone's requests recorded; no token or login URL in the log;
`reqcove links` refused off a terminal; `links` and `login-url` gone after
stop). Not tried yet: a start at login or after a reboot, sleep, whether
macOS's Local Network privacy asks about a `run` not started from a terminal,
and whether launchd's default background priority slows it (with `brew
services`; a sleep, a start at login and the Local Network prompt were tried
with `reqcove service install`, below).

### Keep it running without Homebrew (`reqcove service install`)

With the release's binary or one built from source (with Homebrew, use
`brew services` above), `reqcove service install` does the same: a
LaunchAgent on macOS (`~/Library/LaunchAgents/io.github.mh-mobile.reqcove.plist`),
a systemd user unit on Linux (`~/.config/systemd/user/reqcove.service`). It
runs this binary (its full path) with `run --config FILE`, starts it now and
at each login, and is not started again when it ends (as `brew services`).

```sh
mkdir -p ~/.config/reqcove
printf -- '--device iphone\n--allow-hosts api.example.com\n' > ~/.config/reqcove/config
chmod 600 ~/.config/reqcove/config
reqcove service install       # --config FILE for another file, --state DIR for another state
reqcove links                 # the login URL, the first time (after a minute)
reqcove status                # "service: io.github.mh-mobile.reqcove" (Linux: reqcove.service)
reqcove service restart       # after it ended, or after a change to the file
reqcove service uninstall     # stops it and removes the file
```

- The file is `~/.config/reqcove/config` unless `--config` names another,
  read as for `brew services` (above). Install refuses a missing file (saying
  how to write one), one that is not yours or that others can read, and
  `--no-redact`, `--web`, `--rules-reload` or `--lan` in it; `--allow-hosts
  '*'` there is refused when `run` starts (the service then ends once). A
  `--state` in the file is the state directory (in full or from `~/`). The
  state directory must be empty, new or reqcove's (as for `run`).
- Once `run` ends (an error, a refused file, `kill`), it stays down until the
  next login: `reqcove service restart` starts it again (`launchctl kickstart
  -k gui/$(id -u)/io.github.mh-mobile.reqcove`, or `systemctl --user restart
  reqcove`; not tried).
- Refused while Homebrew's service is there (its file or loaded:
  `sh.brew.reqcove`, `homebrew.mxcl.reqcove`; on Linux
  `sh.brew.reqcove.service`, `homebrew.reqcove.service`, names from reading
  Homebrew's code, not tried): two services would fight over the state
  directory. Refused too for Homebrew's own binary, whose path (in its
  Cellar) `brew upgrade` removes: run `reqcove setup`, which writes the
  file Homebrew's service reads, then `brew services start reqcove` (a unit
  test). Installed already: `reqcove service restart` to start it again;
  `reqcove service uninstall`, then install again, to change its flags on
  the command line or after moving the binary.
- The log: `service.log` in the state directory on macOS (not rotated:
  truncate it now and then, as `mitmproxy.log`; `service install` makes it
  0600 before launchd opens it, which would make it 0644: unit test only, not
  tried with launchd), `journalctl --user -u
  reqcove` on Linux. It prints no login URL or token, nor does
  `service install`: `reqcove links` does, in your terminal.
- `PATH` is uvx's directory where you installed it, then `~/.local/bin`,
  `/opt/homebrew/bin`, `/usr/local/bin` and the system's; elsewhere, give
  `--uvx /full/path/uvx` in the file.
- To stop it until the next login: `launchctl bootout gui/$(id -u)/io.github.mh-mobile.reqcove`,
  or `systemctl --user stop reqcove`; `reqcove status` says which.
- Linux: a user unit starts at login; at boot, before any login, only after
  `loginctl enable-linger $USER` (from systemd's documentation, not tried).

Tried: the files written (paths with spaces, `&`, `<`, `%`, `$`, quotes),
the refusals and the launchctl and systemctl commands it would run (unit
tests, which never run them). On macOS (2026-11-14): `service install` wrote
the LaunchAgent and started `run` with the file's flags (an iPhone on the exit
node recorded; no login URL or token in `service.log`), `reqcove status` named
the service, `service uninstall` stopped it and removed the file; after a
sleep it kept running, and after a reboot it started at login by itself (an
iPhone recorded, no alert at login). macOS asked for Local Network access,
before and after the sleep (allowed both times; its list shows each build at
another path as its own entry). Not tried yet:
`service restart`; Linux.

### Undo everything (`reqcove cleanup`)

`reqcove cleanup` lists the steps; with `--delete-state` it deletes the state
directory. Remove the CA's profile from the iPhone first
([SECURITY](SECURITY.md#the-cas-private-key)). A service starts `run` again
at the next login, which makes the state directory anew: stop it first
(`brew services stop reqcove`, or `reqcove service uninstall`).

## Read the traffic with an agent

`claude mcp add reqcove -- reqcove mcp` (the README's step 4) gives an agent on
this computer the [MCP tools](#mcp-tools). They read, and secrets are
masked as they arrive; the one change they can make is to turn on, for at most
5 minutes each time (no cap on turning it on again), a rule you marked as a
[preset](#presets-an-agent-can-turn-on): a mock, or since v0.7 a `map_remote`,
`modify_headers` or `resolve` rule, which changes what requests carry or where they go
(with none, they only read; over `--mcp-http`, never), and they can put a
[marker](#mark-a-moment-reqcove-mark), which changes nothing on the device
([what masking does not find](SECURITY.md#what-is-recorded)). For Codex:
`codex mcp add reqcove -- reqcove mcp` (`run` prints both).

Allowing the tools: the tools that read are marked read-only (`readOnlyHint`),
which a client may use to ask less (not checked with any client);
the ones that turn presets on and off (`activate_preset`, `deactivate_preset`,
and v0.6's `activate_mock`, `deactivate_mock`: deprecated, removed in v1.0) are not, nor is `add_marker` (a write to
Reqcove's memory only). Claude Code asks before a tool
it has not been allowed. Allow the read tools by name
(`"mcp__reqcove__list_flows"` and so on) rather than `"mcp__reqcove"`, which
also allows those (`activate_mock` since v0.6, `activate_preset`, which can
send requests to a server you wrote in a preset, since v0.7; from Claude
Code's documentation, not tried here). For example, in `.claude/settings.json` (the form is from
Claude Code's documentation; not tried here):

```json
{
  "permissions": {
    "allow": ["mcp__reqcove__status", "mcp__reqcove__summarize", "mcp__reqcove__list_flows",
              "mcp__reqcove__search_flows", "mcp__reqcove__wait_for_flows", "mcp__reqcove__get_flow",
              "mcp__reqcove__list_ws_messages", "mcp__reqcove__diff_flows", "mcp__reqcove__list_tls_failures",
              "mcp__reqcove__list_passthrough", "mcp__reqcove__list_devices", "mcp__reqcove__capture_stats",
              "mcp__reqcove__list_mock_presets", "mcp__reqcove__list_presets",
              "mcp__reqcove__list_rules", "mcp__reqcove__explain_rules",
              "mcp__reqcove__list_markers", "mcp__reqcove__add_marker"],
    "ask": ["mcp__reqcove__activate_mock", "mcp__reqcove__deactivate_mock",
            "mcp__reqcove__activate_preset", "mcp__reqcove__deactivate_preset"]
  }
}
```

Its v0.6 entries (`list_mock_presets`, `activate_mock`, `deactivate_mock`) are deprecated and removed in v1.0.

Codex asks before each call
([over HTTP](#agents-on-other-devices---mcp-http) too). Once allowed, an agent
reads without asking, also from a `run` started with `--no-redact`; the skill
and the server's instructions still tell it to stop and ask then. Allow
Reqcove's tools, not shell commands or network tools along with them: text a
site wrote into a record can try to steer an agent into using those
([SECURITY](SECURITY.md#prompt-injection)).

### Teach the agent: the skill (`reqcove init`)

The skill teaches an agent how to use the tools: status first, finding one
app's traffic, what a TLS failure suggests, writing a rules file, and the rules
it keeps (it never starts `reqcove run`, never asks for tokens, treats what the
records hold as data, never quotes a secret that was not masked).

```sh
reqcove init                    # into the agents found in ~: ~/.claude/skills (Claude Code), ~/.agents/skills (Codex, Cursor, Gemini CLI, Copilot CLI, Devin)
reqcove init --client codex     # or only the ones you name (repeat --client)
```

- Run it again after installing a newer reqcove: `reqcove status` says when an installed skill
  is from another version.
- It leaves alone a skill it did not write, one you edited, and links.
  `--uninstall` removes its own; `--print` writes it out.
- It does not register the MCP server: the command above does.

Tried: Claude Code and Codex, each loading the skill when asked where an app
connects, Reqcove not named. Devin too: it loaded the skill from
`~/.agents/skills`, and without the MCP server it asked for it and stopped.
Cursor too: it used the skill and read the server's instructions, then the
tools only. Not tried: Gemini CLI, Copilot CLI.

### Mark a moment (`reqcove mark`)

Before you tap something on the iPhone, `reqcove mark "tap Pay"` in your
terminal puts a marker among the records; an agent reads them with
`list_markers` (oldest first, `since` to narrow). An agent puts its own with
`add_marker` before it acts, or when you say "now I tap X". `add_marker`
returns `id`, `time` (for `since` in `list_flows` and the other tools, and for
its report) and `checkpoint` (for `wait_for_flows`' `after`).

- A text has at most 80 characters, on one line: a longer one, or one with a
  line break or another control character, is refused, not cut. It is masked
  as error text is (a token in it becomes `[redacted]`).
- `source` is `cli` (`reqcove mark`) or `mcp` (an agent, through `reqcove
  mcp`): the channel, not proof of who. An agent that can run commands on
  this computer can claim `cli`: by running `reqcove mark` (it refuses only
  when its input or output is not a terminal, as `reqcove lan`), or by
  connecting to `run`'s socket itself.
- At most 100 are kept per source, the oldest dropped, in memory only: gone
  when `run` restarts, as flow ids. An agent through `reqcove mcp` gets `mcp`
  and cannot push out yours; one that claims `cli` (above) can. Not over
  `--mcp-http`.
- `add_marker` is a write (not marked read-only) but changes nothing on the
  device; `reqcove mcp` never sends it again after a dropped connection.

Tried: `add_marker` from Claude Code during an iPhone sitting (iOS 27.3,
2026-11-14): it worked. The rest by tests only (`reqcove mark` not tried by
hand).

### Agents on other devices (`--mcp-http`)

For an agent elsewhere on your tailnet, such as Grok Bot (xAI's agent: its
cloud computer joins your tailnet through Tailscale's OAuth apps):

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --mcp-http
```

`run` serves the same tools over HTTP on the node, but the preset ones
(`list_presets`, `activate_preset`, `deactivate_preset`, and the deprecated
`list_mock_presets`, `activate_mock`, `deactivate_mock`), the rule ones (`list_rules`,
`explain_rules`) and the marker ones (`add_marker`, `list_markers`), and prints the URL,
`http://reqcove.<tailnet>.ts.net:8090/mcp`, and the header to give the agent,
`Authorization: Bearer <token>` (`reqcove links` prints them again; off a
terminal, only it).

- **Grok Bot**: Connect apps › Tailscale, to join your tailnet (under Tailnet
  Lock, sign its device). Then Connect apps › Add a custom connector: type
  Remote HTTPS (an `http://` tailnet URL works there; WireGuard encrypts it),
  the URL as server URL, header key `Authorization`, value
  `Bearer <token>`. Its settings show the connector with an error and no tools
  (it reaches the tailnet from its chats only): ask it in a chat. To copy the
  value unseen: `printf 'Bearer %s' "$(cat ~/.reqcove/mcp-token)" | pbcopy`.
- **Claude Code** on another computer (the header stays in `~/.claude.json`):
  `claude mcp add --transport http reqcove-remote http://reqcove.<tailnet>.ts.net:8090/mcp --header "Authorization: Bearer <token>"`
- **Codex** on another computer, the token in that variable:
  `codex mcp add reqcove-remote --url http://reqcove.<tailnet>.ts.net:8090/mcp --bearer-token-env-var REQCOVE_TOKEN`.
  Codex asks before each MCP tool call; for `codex exec`, which cannot ask, set
  `default_tools_approval_mode = "approve"` for this server.

What to know:

- Only your own untagged devices on the tailnet can call it, with the token
  ([SECURITY](SECURITY.md#mcp-over-http---mcp-http)). A tagged device is
  refused (`run` logs it once): do not tag an agent's device to restrict it.
- What the agent reads goes to its computer and model provider (for Grok Bot,
  xAI's cloud). To cut it off, delete `mcp-token` in the state directory and
  restart `run` (otherwise the token stays the same), or remove its device
  from the tailnet.
- Restarting `run` needs no reconnecting (calls fail meanwhile); the records
  start empty, and an earlier cursor is refused.
- `run` logs each call's device and tool, not its arguments (`--mcp-http:
  grokbot-user-1 (100.104.0.1) called "list_flows"`), and requests with no token
  or a wrong one. An agent that only says it is checking leaves no line.
- Each device may call about 10 times a second; past that it gets `429` for a
  moment (`run` logs it once a minute).
- Plain HTTP, inside the tailnet's encryption (WireGuard). In a container: the
  same flag, no port to publish, the token from `docker exec -it NAME reqcove
  links` ([container](container.md#3-the-agent)).

Tried: Grok Bot (status, flows, bodies; the same chat after a restart of
`run`; `run` in a container); Claude Code (`claude -p`) and Codex
(`codex exec`) on this Mac over the tailnet (each read the status); and a call
from another computer, a macOS VM on the tailnet, by the node's name and by its
address.

## Look at the flows yourself

### On the iPhone (`--ui`)

To watch the flows beside the app that sends them:

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --ui
```

`run` serves a read-only page on the node's port 80 and prints its link with a
QR code (`reqcove links` prints them again; off a terminal, only it). Scan it with the iPhone's camera: Safari opens the list, which follows
new flows every second (split view puts it beside the app). Tap a flow for its
headers and bodies, masked as the MCP tools return them.

- Search matches URLs and headers as you type; "bodies too" adds the kept
  heads of bodies and stops the list following (it walks every record). Filter
  by status (2xx to 5xx, no answer) or, from a flow's page, by host.
- Clear hides the flows so far; "Show all" brings them back. Nothing is
  deleted: the agent still sees them.
- Live/Paused stops and starts following. Scrolled down, the list stays put
  and counts the new flows; tap the count to see them.
- Your own devices on the tailnet see every device's flows; another user's
  `--device` device sees only its own
  ([who else, and the token](SECURITY.md#the-page---ui)).
- The link is the same at each start, so a bookmark should work after a
  restart. To change it, delete `ui-token` in the state directory and start
  again.
- Tailscale must be on; the exit node and the
  [Remote Proxy](#without-the-exit-node-the-wi-fi-proxy) need not be. The
  page's own requests are not recorded.

Tried on an iPhone: opened from the camera, new flows following, search, Clear
and Show all, and reopening the page in Safari after a restart of `run`.

### As a HAR file (`reqcove har`)

While `reqcove run` is running:

```sh
reqcove har > flows.har
```

It writes a HAR 1.2 file, oldest first: the newest 1000 flows by default
(`--limit 0` for all), filtered with `--host`, `--device`, `--since 10m`,
`--until`, `--status 4xx`, `--method` and `--user-agent`.

- It holds what the MCP tools return: masked as it arrived, the heads of bodies
  only (cut ones say so in a comment), no body that masking could not check.
  With `run --no-redact` nothing is masked, and the file's comment says so.
- The file gets your shell's file mode, often readable by other users
  ([SECURITY](SECURITY.md#what-is-recorded)).

Tried: imported into Chrome's developer tools (Network), with the requests,
their headers (masked) and responses. Not tried: Charles, Proxyman. From
reading the spec, no validator run: HAR 1.2's required fields are there.

### In mitmweb (`--web`)

For mitmproxy's own page, which can edit and replay requests:

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --web
```

mitmweb runs instead of mitmdump, on `http://127.0.0.1:8081` (8091-8099 while
another run has 8081: [two addresses](several-exit-nodes.md#ports)) and, for
your own devices on the tailnet, on the node's port 8081, with the link and QR
code `run` (or `reqcove links`) prints.

- Nothing is masked ([SECURITY](SECURITY.md#mitmweb---web)). It shows bodies
  up to 2 MB each, and keeps the newest 10,000 flows and 256 MB of bodies.
- The link is the same at each start (`web-token` in the state directory).
  After a restart, open it again: a bookmark without the token asks for it.
- In its Capture tab, leave "Run SOCKS Proxy" on, or the devices' HTTP(S)
  stops. The other modes there are not Reqcove's. Changes last until reqcove
  starts again.

Tried: from an iPhone on the exit node. From reading code, not tried: with
options changed there, Reqcove's records stay scoped and masked.

## Record clients other than iPhone apps

Reqcove decrypts what a client sends through it, once the client trusts
Reqcove's CA. Who trusts it differs:

| Client | What is decrypted | Tried on |
|---|---|---|
| iPhone apps, Safari and apps' web views (Flutter's `dart:io` and React Native too; a web view inside an app that pins its own API) | everything to `--allow-hosts` | an iPhone |
| apps that pin their certificates | nothing: with `--pass-hosts` they work, and only their connections are recorded ([how](#apps-that-pin-certificates---pass-hosts)) | an iPhone |
| Android: Chrome | as on the iPhone | an Android 14 device |
| Android: other apps | nothing: they trust only the system's CAs; your own app can opt in ([how](#android)) | the same, and a sample app |
| a web app in production | what the device and the server exchange (pages, the API its front end calls), not what the server sends on | an iPhone |
| a web app's backend you run | its calls to other APIs, through the Remote Proxy ([how](#a-web-apps-backend)) | a Rails app (Net::HTTP, Faraday) |
| this computer's apps, the iOS Simulator | with `--local-proxy` ([how](#the-ios-simulator---local-proxy)) | Chrome on this Mac; Safari on the iOS 27 Simulator |
| another Mac | as a `--device` on the exit node, with the Tailscale app ([how](#another-mac)) | a macOS 27 VM |
| gRPC apps | their calls and status; protobuf messages by structure, or by name with `--proto` ([how](#grpc)) | an iPhone test app over URLSession (Connect, gRPC-Web, gRPC); the E2E test |

### Apps that pin certificates (`--pass-hosts`)

Apps that pin their certificates refuse Reqcove's, so their requests to those
hosts fail. `reqcove status` names such hosts, with the `--pass-hosts` to start
`run` with; those hosts are then carried undecrypted and the apps work.

```sh
reqcove run --device iphone --allow-hosts '*' --pass-hosts '*.example-cdn.com,api.example.com'
reqcove run --device iphone --allow-hosts '*' --pass-hosts @pass-hosts.txt   # one host a line
```

- For those hosts only the connections are recorded (host, server, times,
  bytes: `list_passthrough`), no URLs or contents.
- Their connections skip `--rules` and `--upstream-proxy`. Requests to them
  that mitmproxy decrypts all the same (plain HTTP, or riding an allowed
  host's connection) are not recorded and skip `--rules`, but go through
  `--upstream-proxy`.
- Pinning checked after the TLS handshake shows nowhere.
- For your own app, use a build without pinning. Android apps refuse the CA
  for another reason ([Android](#android)).

Tried: on an iPhone. That a pass host's decrypted requests go through
`--upstream-proxy`: a test; that they skip `--rules`: from reading code.

### gRPC

A gRPC call is a flow: its path names the method (`/pkg.Service/Method`), and
rows and `summarize` show its status (`grpc_status`: `0` is OK, `16`
UNAUTHENTICATED, …; `pending` until its trailers come), read from the response
headers when there is no message (a trailers-only answer, the usual error),
else from the trailers (HTTP/2's, or gRPC-Web's last frame when the kept head
holds it: a body over 64 KiB loses it). `grpc_message` is decoded and masked
(with `--no-redact`, as sent). Trailers are searched, compared by `diff_flows`
and written to a HAR's comment. A body's note counts its messages and their sizes;
JSON ones (`application/grpc+json`, `connect+json`) are handed out one a line,
masked as JSON, protobuf ones as below; a Connect stream's last frame (its
error, its trailers: JSON) as `[end of stream]`, masked as JSON. A Connect
stream's outcome is in that frame, not in `grpc_status` (by a test only). Metadata ending in
`-bin` (binary) shows its size only.

Protobuf bodies (gRPC's messages, and `application/x-protobuf` and the like)
are not text, so reqcove hands out its own rendering of them, marked by the
body's `view`. Without a schema it is the structure only: field numbers,
types and lengths, `string(12)` for a string (never its text), and numbers in
responses (in requests only those under 128, such as enums and booleans; a
larger one, such as a code sent as a number, shows its byte count; a PIN under
128 shows too):

```
1: 150
2: string(12)
3 {
  1: string(3)
}
```

With `--proto FILE`, your compiled schema (`protoc --descriptor_set_out=FILE
--include_imports`), a message whose type is known is shown as JSON with its
field names and masked by name, as JSON is: the type comes from the method
its path names (gRPC, gRPC-Web, Connect, Twirp: `/pkg.Service/Method`, the
input in a request, the output in a response) or from `messageType` in the
content type. `bytes` fields show their length; fields the schema does not
have, their structure. With `--no-redact`, protobuf bodies are kept as they
came.

Apps built on gRPC-core (Google's SDKs among them) trust their own list of
CAs, not the ones the iPhone trusts, so their calls show as TLS failures (from
gRPC's mailing list, not tried); so do apps whose gRPC library is told whose
certificates to trust, unless a debug build trusts Reqcove's CA (not tried).
Tried: on an iPhone, a test app calling Connect's demo server through
URLSession (the system's trust, the CA installed) over Connect, gRPC-Web and
gRPC, with `--proto` (statuses from the trailers and from gRPC-Web's last
frame, the messages by their names, except gRPC's answer, which showed nothing
on the build tried: fixed since, by a test, not tried again on the iPhone; the
reading without a schema by tests only); and the E2E test, gRPC's shape over
HTTP/2 through mitmproxy (a body over 64 KiB with its status in the trailers,
and a trailers-only error).

### Android

Apps built for Android 7 and later trust only the system's CAs by default,
not one you install (as a CA certificate, in Settings), unless the app allows
user CAs in its `network_security_config`. On the device tried, Chrome was
decrypted and every other app refused the CA.
`reqcove status` says so for Android devices (from the OS Tailscale reports).

- Keep `--allow-hosts` to the hosts you test: the others pass undecrypted and
  their apps work.
- For your own app, let a debug build trust user CAs in its
  `network_security_config`:

```xml
<network-security-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user" />
    </trust-anchors>
  </debug-overrides>
</network-security-config>
```

Tried: an Android 14 device (Chrome decrypted; every other app refused the
CA), and a sample app, decrypted for the host it named this way in a
`domain-config` and refusing the CA for another; and a debuggable build of it
with the `debug-overrides` above, which got answers from both hosts.

### The iOS Simulator (`--local-proxy`)

The Simulator's apps use this computer's network, which the exit node does not
carry. `--local-proxy` opens an HTTP proxy on `127.0.0.1:8082` instead, and its
requests are recorded as the device `local`:

```sh
reqcove run --allow-hosts api.example.com --local-proxy   # --device too, for an iPhone as well
```

- macOS: `run` points the system's web proxies (HTTP and HTTPS, every enabled
  network service) at it, as Charles and Proxyman do, and puts back what was
  there when it stops (Ctrl-C, `kill`, closing the terminal). It adds Reqcove's
  CA to the booted Simulators (`xcrun simctl keychain … add-root-cert`); one
  booted later needs the command it prints.
- Linux: nothing is changed for you. Point apps at it
  (`HTTPS_PROXY=http://127.0.0.1:8082`) and have them trust the CA.
- Every app on this computer then goes through it. Only `--allow-hosts` hosts
  are decrypted and recorded, but those break in apps here that do not trust
  Reqcove's CA (Safari on the Mac, say).
- After `kill -9` or a crash, apps that use the system proxy cannot connect
  until the next `run` or `reqcove cleanup` puts it back (or you do, in System
  Settings).
- This computer, the LAN, the tailnet (IPv4 and IPv6, `*.ts.net` too) and `*.local` stay
  direct, as the proxy's exceptions. Names are looked up as this computer does
  (VPNs, split DNS, search domains), not with `--dns`; one that leads to this
  computer itself or a link-local address is refused unless `/etc/hosts` gives
  it ([SECURITY](SECURITY.md#the-local-proxy---local-proxy)).
- Automatic proxy configuration (PAC) and authenticated proxies are left as
  they are.

To record this computer's own browsers too (as `local`, mixed with the
Simulator's) rather than have them warn, trust Reqcove's CA here once: `run`
prints the command, and `reqcove status` and `reqcove cleanup` how to stop.
The CA's key can then impersonate any HTTPS site to this computer too
([SECURITY](SECURITY.md#the-local-proxy---local-proxy)).

- macOS (TLS only; it asks for your password):
  `security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`.
  Firefox may keep its own store. To stop, run the command `reqcove status`
  prints, or delete the CA in Keychain Access (its trust goes with it).
- Debian and Ubuntu: `sudo cp ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/reqcove.crt && sudo update-ca-certificates`.
  Fedora: into `/etc/pki/ca-trust/source/anchors/` and `sudo update-ca-trust`.
- Chrome and Chromium on Linux: `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n Reqcove -i ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`.
  Node: `NODE_EXTRA_CA_CERTS=` that file. Python: the system's bundle once
  updated, not that file alone (it would replace every other CA).

Tried on macOS 27: the trust command and Reqcove's check of it, the hint to
stop, deleting the CA in Keychain Access, Chrome on the Mac opening an allowed
host without a warning, recorded; the system's web proxies pointed at
127.0.0.1:8082 by the real `networksetup` and put back at Ctrl-C, the CA added to the booted
Simulators, and Safari on the iOS 27 Simulator decrypted and recorded as
`local`. `networksetup` takes the tailnet's IPv6 range (`fd7a:115c:a1e0::/48`) as an
exception and the system lists it (tried 2026-11-13). RoamRun alongside (tried
2026-11-14, RoamRun 0.12.0 and its PR #253): with `--local-proxy` on, `roamrun
doctor` passed and `roamrun up` bridged an iPhone on another Wi-Fi over the
tailnet to Ready, as without it. Not tried: whether apps skip the proxy for the address forms in the exceptions, PAC and authenticated
proxies, Linux.

### A web app's backend

A web app's own calls to other APIs (a Rails server calling a payment API)
leave from the server, not the phone: Reqcove sees them only when the server
sends them through it and trusts its CA. For a server on one of your machines
on the tailnet, name that machine with `--device` and point the server at the
node's [Remote Proxy](#without-the-exit-node-the-wi-fi-proxy):

```sh
reqcove run --device dev-server --allow-hosts api.example.com
# on dev-server: both variables (Ruby's Net::HTTP reads http_proxy even for HTTPS),
# and a CA bundle with Reqcove's CA added (cat the system's bundle and mitmproxy-ca-cert.pem)
http_proxy=http://100.x.y.z:8080 https_proxy=http://100.x.y.z:8080 SSL_CERT_FILE=bundle.pem bin/rails server
```

- Its calls are recorded under that machine's name. Nothing on it changes
  but the server's environment.
- Connections to the database or Redis are not HTTP(S) on 80/443: not seen.
- The browser's requests to the app are a different path: from the iPhone,
  `map_remote` sends an allowed host's requests to a development server
  ([Rules](#rules---rules)).

Tried: a Rails 8 app on this Mac as the device, calling an API with Net::HTTP
and with Faraday (without the CA, Ruby refused the certificate and a TLS
failure was recorded; with it, both calls were). Not tried: other clients, a
server on another machine.

### Without the exit node: the Wi-Fi proxy

The node also serves the **Remote Proxy**: an HTTP proxy on its tailnet
address, port 8080 (`--proxy-port`), for the `--device` devices. Instead of
choosing the exit node, the iPhone can set its Wi-Fi proxy (Manual) to it.
Cellular has no proxy setting, so this works on Wi-Fi only.

| | Exit node | Wi-Fi proxy |
|---|---|---|
| through this computer | everything the phone sends (DNS, HTTP(S), other ports) | HTTP(S) of the apps that use the proxy setting |
| the rest | nothing else | straight to the internet from the phone's Wi-Fi, unrecorded |
| cellular | yes | no |
| in the Tailscale app | choose the exit node | stay connected only |

What goes through it leaves for the internet from this computer, as with the
exit node, and names are looked up here.

Tried on an iPhone: Safari's requests were recorded, and sites outside
`--allow-hosts` opened as before.

### Without Tailscale: LAN mode (`--lan`)

`reqcove run --lan` starts no tailnet node: Reqcove listens as an HTTP proxy
on this computer's address on the LAN, and an iPhone on the same network sets
its Wi-Fi proxy to it. The exit node stays the main way: it carries everything
the phone sends, over cellular too, and needs nothing from the network it is
on. LAN mode is for when Tailscale is not an option.

```sh
reqcove run --lan --allow-hosts api.example.com
```

1. run prints where it listens: the address of the default route's interface
   (`--lan-interface en0` picks another; a VPN's tunnel is refused) and
   `--proxy-port`, 8080 by default.
2. On the iPhone: Settings, Wi-Fi, (i) by the network, Configure Proxy,
   Manual: that server and port, Authentication off.
3. Its first connection is refused, and run logs its address. Allow it on this
   computer: answer run's question (`Allow ADDR? [y/N]`, asked while run is the
   terminal's foreground job), or run `reqcove lan allow ADDR` in a terminal.
   `reqcove lan list` shows the allowed addresses and when each was allowed;
   `reqcove lan deny ADDR` takes one back. These commands refuse to run off a
   terminal: they are not for an agent.
4. The CA: open `http://mitm.it` with the proxy set, once per device, as with
   the exit node. Anyone else on the LAN can swap plain HTTP, so run's ready
   block also names the CA file, to send by AirDrop instead, and prints the
   CA's SHA-256 to compare as iOS shows it (lowercase pairs, `ab 90 7e …`):
   on the iPhone, Settings, General, VPN & Device Management, the profile,
   More Details (checked on iOS 27.3, 2026-11-14: it matched). Not checked:
   AirDrop of that file.

The records name the device `lan:ADDR`; the tools' `device` filter and
`reqcove har --device lan:ADDR` take that name, and `list_devices` gives its first and
last request this run. `reqcove status` (and the `status` tool, as
`mode: "lan"`) shows where it listens, the allowed addresses and the ones
refused this run: the 50 last seen, and how many more (`refused_more`), as
anyone on the network can add to them (the list behind them holds up to
10,000 and is emptied when it fills).

There is no password. Who may use the proxy is decided on this computer, by
address, as in Charles Proxy (its documentation describes an access control
list, and a dialog for a new address). What that means:

- An allowed entry is an address, not a device: whoever has that address later
  is allowed too. The list is kept in the state directory (`lan-allowed`), so
  an address stays allowed on another network with the same prefix (a café's
  192.168.1.0/24 as your home's). Use `reqcove lan list` and `lan deny` when
  done. Not checked: whether an iPhone keeps the same private Wi-Fi address
  on a network over time.
- Through this computer, an allowed address reaches the internet from your
  address, on ports 80 and 443 only, and private hosts named exactly in
  `--allow-hosts` (no `*`), those behind this computer's VPN included. Never
  this computer, link-local addresses, or the network the proxy is on, even by
  an exact name. Its requests to the allowed hosts are recorded.
- `map_remote` and `resolve` targets in `--rules` are dialled by mitmproxy,
  outside these checks: a rule sending an allowed host to a server on this
  computer serves the LAN clients' requests there too.
- `lan deny` refuses new connections within two seconds, but HTTPS tunnels
  already open go on until they close.
- Use it on a network you trust, and stop it when done.

Other differences from the exit node:

- Ports 80 and 443 only: a development server on this computer or on the same
  Wi-Fi (Metro on 8081, say) is refused while the proxy is set. Not checked:
  whether iOS skips the proxy for local addresses.
- Names are looked up with this computer's resolver, `/etc/hosts` first: a
  name it maps to 127.0.0.1 is refused.
- Apps that ignore the Wi-Fi proxy go straight out, and are not recorded.
- What blocks it: client isolation on the Wi-Fi (guest networks often have
  it), VLANs between the iPhone and this computer, an MDM profile, a managed
  firewall. Not checked: whether the macOS firewall asks to accept connections
  for `reqcove`.
- `--lan` is refused in `--config`, so it never runs as a service.
  `--device`, `--ui`, `--mcp-http`, `--hostname` and `--dns` do not go with it
  (they are the tailnet node's); `--local-proxy` and `--web` (on this computer
  only) do.
- If this computer's address changes on the same network, run listens on the
  new one. If it moves to another network, run stops listening and says so in
  its log and `reqcove status`; a restart listens on the new network.

Tried by tests: the proxy on the loopback interface with real mitmproxy
(HTTP and HTTPS recorded as `lan:127.0.0.1`, `http://mitm.it` serving the CA),
and the refusals above. Tried with an iPhone on a home Wi-Fi (iOS 27.3,
2026-11-14): its first request refused, allowed at run's question, then
Safari's HTTPS to an allowed host decrypted and recorded as `lan:ADDR`;
`reqcove lan deny` stopped it, `lan allow` again let it through. Not tried: a
change of network.

### Another Mac

A Mac named with `--device` that chooses the exit node in the Tailscale app is
recorded as an iPhone is ([the steps](another-mac.md)). With Homebrew's
open-source `tailscaled` the exit node shows as on, but that Mac's traffic does
not go through it. Tried with a macOS 27 VM. Not tried: that Mac's iOS
Simulator (it should go through with the Mac's own traffic, once it trusts
Reqcove's CA).

## Change where requests go

### Rules (`--rules`)

A YAML file of rules, applied to `--allow-hosts` hosts only. To send an app's
requests to a development server on this computer:

```yaml
map_remote:                     # mitmproxy's syntax, as are map_local and modify_headers
  - "|https://api.example.com/|http://localhost:3000/"
keep_host_header: true          # reqcove's: map_remote keeps the app's Host
```

```sh
reqcove run --device iphone --allow-hosts api.example.com --rules rules.yaml
```

- `map_remote`, `map_local` and `modify_headers` are mitmproxy's, run by its own
  code. Relative paths count from the rules file.
- `map_remote` changes the URL, and with it `Host` unless `keep_host_header` is
  true. Write the schemes, as above: apps send `https`, and a plain server
  cannot answer TLS.
- `map_local` answers only requests whose body is at most 1 MiB and of known
  length; others go on to the real destination (the record says so). An HTTP/2
  GET without a length is answered too, and a body sent with it anyway is held
  whole in memory. Apps and web pages on a `--device` device (or, with
  `--local-proxy`, on this computer) can be the senders, to a host a rule matches: a
  very large body can run mitmproxy out of memory (reqcove restarts it), and the
  devices' traffic stalls meanwhile.
- Read someone else's rules file before using it: rules can send your apps'
  requests, cookies and tokens included, wherever they say.

`mock` answers a request here, with what you write, and the request is not sent
to the server (for HTTPS, mitmproxy may have connected to it already, to read
its certificate): to see how the app takes an expired session or an empty list.

```yaml
mock:                           # Reqcove's own; the first that matches answers, before map_remote and map_local
  - match: {method: POST, url: "https://api.example.com/v1/login"}
    status: 401
    headers: {Content-Type: application/json}
    body: '{"error":"expired"}'
  - match: {url: "https://api.example.com/graphql", operation: Feed}
    body_file: feed.json        # relative to the rules file
```

- `url` matches the URL the app sent without its query, exactly (the host in
  any case), or, ending in `*` after a path (`https://api.example.com/v1/*`),
  any URL that starts with the rest. It takes no query, fragment, user or
  default port (refused: it would never match). `method` and `operation` (a GraphQL
  operation: `operationName`, Apollo's `X-APOLLO-OPERATION-NAME` header, or the
  document's first named operation) are optional. The host must be in
  `--allow-hosts` and not in `--pass-hosts`.
- `status` is 100 to 599 (200 if left out); a body is at most 1 MiB, inline or
  in a file, and none goes with `HEAD`, 204 or 304. `Cache-Control: no-store`
  is added unless you set one. Request `modify_headers` rules apply before
  the match, response ones still apply.
- A request a mock may answer (its method and URL match) is held whole until
  its body is in: one whose length is over 1 MiB, or a POST of unknown length,
  goes on unanswered, its `rewrites` saying `mock: skipped, …`. As with `map_local`, a GET (HEAD, OPTIONS, DELETE)
  without a length is held too, and over HTTP/2 a body sent with it is kept
  whole in memory.
- The record says so: `mocked: true` on its row, `rewrites` with the rule's
  number and status (`mock[0]: 401`), a note in a HAR. `capture_stats` has
  `rules_loaded`, when the file was last taken.

Tried with the E2E tests (real mitmproxy): a 401 with headers for a POST, a
GraphQL operation from the body, a prefix, HEAD, the server never reached, and
rules refused (a bad status, a line break in a header, a missing file, a host
outside `--allow-hosts`). On an iPhone: a 401 for Safari (httpbin.org), and one
GraphQL operation of the GitHub app mocked while its others, on the same
connection, reached GitHub.

#### Add a mock from your terminal (`reqcove mock add`)

`reqcove mock add` writes a mock into the file for you, checked first:

```sh
reqcove mock add --rules rules.yaml --url https://api.example.com/v1/login \
  --method POST --status 401 --header 'Content-Type: application/json' \
  --body '{"error":"expired"}'
```

- The other flags: `--operation NAME`, `--body-file PATH` (from where you type
  it; written as a full path), `--delay-ms N`, `--fault close`, `--preset NAME`
  and `--description TEXT`.
- It adds the mock as the last of `mock:`'s items and keeps the rest of the
  file as it was (comments and order too); a file without `mock:` gets one at
  its end. It refuses a file whose `mock:` is not its last block, or is in flow
  style (`mock: []`), and says how to fix it. A new file is made `0600`; an
  existing one keeps its mode, replaced at once (a temp file beside it, renamed).
  If the file changes while it is checked (your editor saved it), nothing is
  written: run it again. A header name given twice is refused.
- Before writing, the whole file as it would be is checked by the addon's own
  loader: by the running `reqcove run` (the same `--state`), with its
  `--allow-hosts` and `--pass-hosts`, or, when none is running, by mitmproxy's
  Python from the lock (`--uvx PATH`), which leaves the hosts unchecked.
  Refused, it says why (never a rule's text) and writes nothing.
- Then it says when the mock takes effect: at once when run has
  `--rules-reload` (which also turns every preset that is on off), else when
  you restart run.
- It runs only in a terminal (stdin and stdout, as `reqcove mark`): a help
  against an agent running it unasked, not a guarantee (an agent with a shell
  can give it one, and can edit the file anyway). `--print` shows the mock as YAML without writing or
  checking anything, in a terminal or not.

Tried with the tests: the YAML for values with quotes, line breaks, `#`, `: `,
control characters and other scripts, read back as given by the addon's loader;
the file's text kept (comments, CRLF, no newline at the end); the refusals; the
check by a real run (hosts in and out of scope, passed) and by mitmproxy's
Python. Not tried by hand with a running run and a device.

#### Presets an agent can turn on

A mock with `preset: NAME` does nothing until an agent turns it on, for at most
5 minutes each time; it can turn it on again, with no cap
([SECURITY](SECURITY.md#mock-presets)). So an agent can check how the app takes
a 503, a slow answer or a dropped connection, and turn it off again, without
editing the file. A plain mock with the same match (method, URL, operation) as
a preset is refused at load: it would answer in its place.

```yaml
mock:
  - match: {url: "https://api.example.com/v1/profile"}
    preset: profile-503             # letters, digits, . _ -; at most 64
    description: the profile API is down   # optional, one line, at most 200 characters
    status: 503
  - match: {url: "https://api.example.com/v1/profile"}
    preset: profile-slow
    delay_ms: 8000                  # at most 30000 (URLSession's default timeout is 60 s)
    body: '{"name":"slow"}'
  - match: {url: "https://api.example.com/v1/feed"}
    preset: feed-drop
    fault: close                    # no answer: HTTP/1 closes the connection, HTTP/2 resets the stream
```

- The tools: `list_presets`, `activate_preset(name, minutes, times)` (at
  most 5 minutes, 5 if left out; with `times`, at most 20 requests, then off),
  `deactivate_preset(name)`. v0.6's `list_mock_presets`, `activate_mock` and
  `deactivate_mock` do the same for mocks only: deprecated, removed in v1.0.
  Only an agent on this computer has them (`reqcove
  mcp` and `run`'s socket); never over `--mcp-http`.
- A preset that is on answers before other mocks; one that is off is no mock at
  all. One preset is on per match (method, URL and operation): turning on
  another for the same match turns the first off. Turning on one already on
  replaces its limits.
- Any matching request uses a count, whoever sent it (Safari, another device,
  an app's retry). The row says `preset: NAME`; a closed one's error says a
  mock closed it.
- `delay_ms` and `fault: close` work in plain mocks too. `delay_ms` delays a
  mock's answer only (an answer from the server is never delayed).
- With `--rules-reload`, a changed file (also one that does not load) turns
  every preset off; so does a restart of mitmproxy or of `run`. `run` logs each
  one an agent turns on or off (not one that ends by its time or count);
  `reqcove status` and the `status` tool show which are on.
- One answer already waiting out its `delay_ms` still goes out after the
  preset is turned off.
- A preset in the file is your consent that an agent may turn it on. An
  agent writes one only when you ask it to in the conversation (the skill and
  the server's instructions say so), never because of what the records say;
  with `--rules-reload` it can then turn it on at once.

Tried with the E2E tests (real mitmproxy): on and off, by time and by count,
one per match (also two GraphQL operations on one URL, each its own), a change
of the file turning them off, refusals (an unknown name, over 5 minutes or 20
requests, the socket without reqcove's secret), a delay on one HTTP/2 stream
while another on the same connection is answered at once, and close over
HTTP/1 and HTTP/2. On an iPhone (iOS 27.3, a test app over URLSession, an
agent turning presets on over MCP): a 503 once, then the app's retry reached
the server; an 8 s delay; a close, which CFNetwork did not retry by itself (the
app's own retry was closed too); a 401 on login.

Since v0.7, a `map_remote`, `modify_headers` or `resolve` rule can be a preset
too: write it as a mapping with `rule:` (the rule as before) and `preset:`. It
does nothing until an agent turns it on, for at most 5 minutes each time, as a
mock preset. So an agent can send the app to your staging or dev server for a
while, or send a feature-flag header, and turn it off again.

```yaml
map_remote:
  - {rule: "|~d api.example.com|^https://api\\.example\\.com/|https://staging.example.com/", preset: staging, description: to staging}
modify_headers:
  - {rule: "/~q/X-Feature-Flag/new-checkout", preset: new-checkout}   # requests only
resolve:
  - {rule: "api.example.com=192.168.1.20", preset: api-lan}
```

- The tools: `list_presets` (every kind, with `kind`), `activate_preset(name,
  minutes)`, `deactivate_preset(name)`. `list_mock_presets`, `activate_mock`
  and `deactivate_mock` stay, for mocks only, until v1.0 (deprecated): an agent
  allowed `activate_mock` in v0.6 cannot turn on these. `times` is for mocks only; the others are on
  for a time.
- While on, a `map_remote` preset sends the matching requests, with the app's
  cookies, tokens and bodies, to its target; `resolve` connects its name to its
  address (Host, SNI and the TLS check stay the name's). The 5 minutes bound
  the switch, not its effects: what the app wrote lands on that server, and the
  app may keep the tokens and caches it got from there
  ([SECURITY](SECURITY.md#map_remote-modify_headers-and-resolve-presets)).
- Shown, by `list_presets`, the ready block and `reqcove status`: a
  `map_remote` preset's target (scheme and host), a `modify_headers` preset's
  header name (never its value), a `resolve` preset's name and address; never
  a filter or a regex.
- Refused at load: a `map_remote` preset whose replacement does not start with
  `http://` or `https://`, a host and `/` (its target could not be shown), has
  a user or password, takes its host from the request (`\1`), goes to a
  link-local address, or is plain `http://` to anything but this computer or a
  LAN address (`localhost`, `*.local`, a private address); a request whose
  rewritten URL would be outside the target shown (a regex that matched inside
  the URL) gets a 502 instead; a `modify_headers` preset on responses (`~s`);
  a preset in `map_local`; a plain rule with the same match as a preset
  (`map_remote`: the same filter and regex; `modify_headers`: the same filter
  and header).
- One on per match, per kind: the same filter and regex (`map_remote`), the
  same filter and header (`modify_headers`), the same name (`resolve`). A
  `resolve` preset that is on comes before a plain `resolve` rule for its name;
  a `map_remote` preset that is on applies before the plain rules; a
  `modify_headers` preset after them, so its header wins.
- Names are shared across kinds: a mock and a `resolve` preset cannot both be
  `staging`. The row lists every preset that changed or answered it in
  `presets` (`preset` stays the mock's that answered).
- `reqcove status` and the `status` tool's `active_presets` list every kind
  that is on (with `kind`; `active_presets_error` when mitmproxy did not say);
  `capture_stats`' `presets` names every preset. v0.6's names, the same until
  then (`active_mock_presets`, `active_mock_presets_error`, `mock_presets`), are
  deprecated and removed in v1.0.

Tried with the E2E tests (real mitmproxy, plain HTTP): a `map_remote`, a
`modify_headers` and a `resolve` preset each change requests only while on, the
row lists them, the header's value is never shown, `activate_mock` and
`list_mock_presets` leave them alone, `times` refused, a changed file turns
them off; the refusals at load (mitmproxy's Python). Not tried: HTTPS through a
`map_remote` or `resolve` preset turned on while the app's connections are open
(pooled HTTP/1, HTTP/2): the app may keep using a connection opened before.
Tried on an iPhone in LAN mode (iOS 27.3, 2026-11-14): a `map_remote` preset
to a dev server on this Mac, turned on over MCP (Safari got the dev server's
answer, the row listed it; off: the server's own), and a mock preset with
`times: 1` (a 503 once, then the server's answer). Not tried on an iPhone: a
`resolve` or a `modify_headers` preset. From reading code: rules apply when a request starts, so a
WebSocket, a stream or a long upload begun while a `map_remote` or `resolve`
preset was on stays with its target after the preset is off.

`resolve` connects elsewhere and leaves the request as it is, for a staging
server or a new load balancer:

```yaml
resolve:                        # reqcove's: connect elsewhere, Host and SNI unchanged
  - "shop.example.com=203.0.113.10"
  - "auth.example.com=192.168.1.20:8443"
```

- Requests for the name go to that IPv4 address, this computer and the LAN
  included. `Host`, SNI and the recorded URL stay the same, and TLS is still
  checked against the name: the server needs a certificate for it (a local
  HTTPS server without one gets a 502). Plain HTTP is not checked.
- Without a port, the request's is used (the app's, 80 or 443, or the
  `map_remote` URL's). After a `map_remote`, the name is its new URL's host,
  which is then the SNI too.
- The name is still looked up (by the phone, or by this computer for the Remote
  Proxy) and the real server connected first: a name that does not resolve
  publicly, or a server that refuses connections, cannot be redirected.
- Each name must be in `--allow-hosts` and have its own address or port:
  mitmproxy reuses a connection by address.
- Refused: `0.0.0.0/8`, link-local (cloud metadata), multicast, Tailscale's
  100.100.100.100 ([SECURITY](SECURITY.md#rules---rules)), and `resolve`
  together with `--upstream-proxy`.

The file is read when mitmproxy starts: with `run`, and when reqcove restarts
it. `--rules-reload` reads it again once a change has settled, for requests
that start after it; one under way keeps the rules it started with.

- A file that does not load leaves the earlier rules in place, and `run` and
  `reqcove status` say why; but if mitmproxy restarts meanwhile, `run` stops on
  it, as at start.
- Whatever can write the file (an agent included) can then change where the
  devices' requests go, without you restarting anything.

From reading code: a change is read within about two seconds.

#### Why a rule did or did not apply (`list_rules`, `explain_rules`)

An agent on this computer can read the rules without the file: `list_rules`
gives each rule by kind and number (`mock[0]`, as `rewrites` names them), its
preset and whether it is on, and only what is derived from it: a mock's match
and answer, a `map_remote` target's scheme and host (`path only` when the
replacement is a path, `not shown` when it does not write the host out), a
`modify_headers` header name and direction (`request` for `~q`, `response` for
`~s`, else `both`), a `resolve` name and address; a `map_local` rule's number
only. Never a filter, a regex, a header value, a body or a file's path.

`explain_rules` says why a request got, or would get, which rules: give it a
flow's id, or a method and URL (and a GraphQL operation). It answers the scope
first (a host not in `--allow-hosts`, or in `--pass-hosts`, gets no rule), then
runs the request path's own code on a request it makes up and never sends:
`rewrites` as the record would say them, `mocked`, `mapped_to`, the presets on
now that apply, and `if_turned_on`, what each preset that is off would do. A
filter that reads headers, a body or the response (`~h`, `~b`, `~t`, `~c`…)
cannot be told from a method and URL: that rule is counted as not matching and
listed in `cannot_tell`. With a flow's id, `recorded` is what the flow got; the
rules, or a preset's state, may have changed since. It uses no preset's count
and turns none on or off.

Tried with the E2E tests (real mitmproxy, plain HTTP): no filter, regex,
header value, body or path in `list_rules` (marker strings); an out-of-scope
host, a `--pass-hosts` host, a mock preset off and then on (its count unused,
the server never reached), a GraphQL mock with and without the operation, a
`~h` filter in `cannot_tell`, a `map_remote` then `resolve` explained as the
recorded flow got them; without a rules file. Tried: `list_rules` and
`explain_rules` from Claude Code during an iPhone sitting (iOS 27.3,
2026-11-14): they worked. A
recorded URL is masked: a value masked in its path or query (`[redacted]`) can change what a filter or regex
sees, and a GraphQL operation in the URL comes before the one given, as for a real request.

### An upstream proxy (`--upstream-proxy`)

To see the same requests in Burp Suite (or ZAP, Charles, …) while Reqcove keeps
its records:

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' \
  --upstream-proxy http://127.0.0.1:8080
```

Decrypted requests go to the proxy (HTTPS in a CONNECT tunnel, plain HTTP as
proxy requests), never straight to the server. The proxy sees everything
unmasked, and Burp keeps it in its project. Turn Burp's Intercept off, or
requests wait in it.

- Hosts outside `--allow-hosts` pass directly, as always; but a request to one
  that rides a decrypted connection to an allowed host (HTTP/2 connection
  reuse) goes through the proxy too, unrecorded. Other protocols to an allowed
  host (MQTT, say) go straight to their servers; over TLS they fail while the
  proxy's CA is in use (the server's certificate is checked against it).
- Burp connects to HTTPS hosts by the SNI's name, looked up again on this
  computer, so the exit node's refusal of this computer and its LAN does not
  cover it ([SECURITY](SECURITY.md#an-upstream-proxy---upstream-proxy)): keep
  `--allow-hosts` to the hosts you test (`run` warns about `'*'`). `resolve`
  rules are refused for the same reason; use the proxy's own overrides (Burp's
  Hostname resolution overrides).
- HTTPS through the proxy is checked against the proxy's CA only: Burp's, on
  this computer, is fetched at start (from its listener's `/cert`); another proxy
  that decrypts (ZAP, Charles) needs `--upstream-ca FILE` (PEM or DER);
  otherwise the public CAs are used (for a proxy that does not decrypt).
- Reqcove connects to the proxy itself and ignores the system's proxy
  settings. But a proxy that points them at itself (Charles, unless its Proxy
  menu's macOS Proxy is off) and `--local-proxy` both claim them, each putting
  back what the other set: with `--local-proxy`, turn that off in the proxy.
- With Burp: plain HTTP shows under the IP address, the name in its `Host`
  header; a request body is held until all of it has come; server-sent events
  to an HTTP/1.1 client fail (to HTTP/2 clients, as iOS apps mostly are, they
  stream); HTTPS to a bare IP address, without SNI, fails (Burp names its
  certificate after the address in a way mitmproxy does not accept). With
  `--web`, a plain HTTP request replayed from mitmweb goes to the proxy itself.

Tried: Burp Suite Community 2026.10, its lookup by the SNI's name included;
Charles 5.0b12 decrypting, with `--upstream-ca` (without it, the record says the
certificate was not trusted). With a proxy other than Burp on this computer,
`run` still asks its listener for `/cert` at start, which fails there and
changes nothing. Not tried: other proxies. From reading code:
other protocols going straight to their servers.

## Options

`reqcove run`:

| | |
|---|---|
| `--device NAME` | a device to carry: machine name, device name (your own untagged devices only), tailnet IP or StableID; repeat for more |
| `--allow-hosts HOSTS` | hosts to decrypt and record: `api.example.com`, `*.example.com` (the domain itself and every subdomain), `'*'` for all, or `@FILE`, one a line (`#` for comments). Without it, traffic is carried but nothing is recorded |
| `--pass-hosts HOSTS` | allowed hosts carried undecrypted, written the same way (not `'*'`): [pinning](#apps-that-pin-certificates---pass-hosts) |
| `--rules FILE` | [rules](#rules---rules) for allowed hosts |
| `--rules-reload` | read that file again whenever it changes |
| `--proto FILE` | a compiled protobuf schema: [read messages by their names](#grpc) |
| `--upstream-proxy URL` | send decrypted requests on through [an HTTP proxy](#an-upstream-proxy---upstream-proxy) |
| `--upstream-ca FILE` | that proxy's CA (PEM or DER) |
| `--local-proxy` | a proxy on `127.0.0.1:8082` for this computer's apps: [the iOS Simulator](#the-ios-simulator---local-proxy) |
| `--proxy-port N` | the proxy port: the [Remote Proxy](#without-the-exit-node-the-wi-fi-proxy)'s, or with `--lan` the LAN proxy's; 8080 by default; 0 turns the Remote Proxy off |
| `--lan` | [LAN mode](#without-tailscale-lan-mode---lan): no tailnet node; a Wi-Fi proxy on this computer's LAN address for the addresses you allow |
| `--lan-interface NAME` | with `--lan`, the interface to listen on; the default route's by default |
| `--ui` | [a read-only page of the flows](#on-the-iphone---ui), on the node's port 80 |
| `--web` | [mitmweb](#in-mitmweb---web) instead of mitmdump: no masking |
| `--mcp-http` | [the MCP tools over HTTP](#agents-on-other-devices---mcp-http), on the node's port 8090 |
| `--dns SERVERS` | the exit node's DNS upstreams, comma-separated, `1.1.1.1:53` by default (the port may be left out); `system` for the first nameserver in `/etc/resolv.conf` |
| `--no-redact` | keep secrets in the records |
| `--mask-names a,b` | mask whatever has exactly this name too (any spelling: `clientRef` is also `client_ref` and `Client-Ref`, not `X-Client-Ref`): headers, parameters, JSON fields, GraphQL arguments, XML elements and attributes; `@FILE` too |
| `--mask-values RE` | mask what this pattern (RE2) matches, wherever it is; repeat it, or `@FILE` (one a line: keeps a literal secret out of `ps`; write one as `\Q…\E`) |
| `--state DIR` | `~/.reqcove` by default: the node key, the CA and its private key. A new or empty directory, or one reqcove used before; write `--state ~/x` with a space (`--state=~/x` is refused). One without a CA gets a copy of `~/.reqcove`'s (listed in `~/.reqcove/ca-copies`, so that `cleanup` of `~/.reqcove` names it), and a new one named `reqcove-NAME` names the node so: [several exit nodes](several-exit-nodes.md) |
| `--hostname NAME` | the node's name, `reqcove` by default; kept in the state directory |
| `--verbose` | log tsnet's backend and every flow decision |
| `--config FILE` | [run's flags from a file](#keep-it-running-brew-services), one a line, before the command line's (not `--no-redact`, `--web`, `--rules-reload`, `--lan`, `--allow-hosts '*'`); the file `chmod 600` |
| `--uvx PATH` | the uvx to run; the `uv` beside it runs the default mitmproxy from Reqcove's lock (hashes checked). A path not named `uvx` is run as uvx: no lock, no hashes |
| `--python VERSION` | the Python to run mitmproxy with, 3.14 by default |
| `--mitmproxy-spec SPEC` | another mitmproxy than the locked `mitmproxy==12.3.1`, fetched through uvx (no lock, no hashes) |

The other commands (all but `init` and `version` take `--state DIR` too):

| | |
|---|---|
| `reqcove status` | what reqcove is doing, and the next steps; `--json` for the `status` tool's JSON; `--uvx PATH` |
| `reqcove links` | the login URL and the `--ui`, `--web`, `--mcp-http` links again, with QR codes; only to a terminal ([first start](#first-start)) |
| `reqcove mark` | `[TEXT]` (`-- TEXT` for one starting with `-`): a [marker](#mark-a-moment-reqcove-mark) among the records, as yours (`cli`); only in a terminal |
| `reqcove mock add` | `--rules FILE --url URL` and the mock's flags: [a mock added to the file](#add-a-mock-from-your-terminal-reqcove-mock-add), checked first; only in a terminal (`--print` shows it, anywhere); `--uvx PATH` |
| `reqcove mcp` | the MCP server for an agent on this computer |
| `reqcove lan` | `allow ADDR`, `deny ADDR`, `list`: the addresses [LAN mode](#without-tailscale-lan-mode---lan) carries; only in a terminal |
| `reqcove har` | [the flows as a HAR file](#as-a-har-file-reqcove-har): `--host`, `--device`, `--since`, `--until`, `--status`, `--method`, `--user-agent`, `--limit N` |
| `reqcove init` | [the agent skill](#teach-the-agent-the-skill-reqcove-init): `--client NAME`, `--print`, `--uninstall` |
| `reqcove cleanup` | how to undo everything; `--delete-state`; `--hostname NAME` |
| `reqcove version` | the version |

Tried on an iPhone: `--mask-names`; `wait_for_flows` after acting through
RoamRun; with a test app, `diff_flows` (a request sent twice),
`list_ws_messages` and `--proto`. By tests only: `--mask-values`, `max_body`,
the `--mcp-http` rate limit, `multipart/form-data`, XML bodies (and an E2E test
with a SOAP request through mitmproxy).

From reading code (the flags' help), not tried for this guide: `--proxy-port 0`,
`--hostname`, `--verbose`, `--uvx`, `--python`, `--mitmproxy-spec`,
`status --json`.

## MCP tools

| Tool | |
|---|---|
| `list_flows` | flows, newest first; filter by device, host (and subdomains), time (`since: "10m"`), status (`404`, `4xx`, `none`), method, User-Agent (text in it, such as an app's name; the app's bundle id is not in its traffic), GraphQL operation (`operation: "Login"`: its `operationName`, or the document's first operation; rows show it); paged. A host that matches nothing brings `similar_hosts`, recorded hosts that look alike (`acme-shop.com` for `acmeshop.com`) |
| `search_flows` | text in URLs and headers (and body heads with `bodies`); the same filters and `similar_hosts` |
| `wait_for_flows` | what an action on the device sent: take `checkpoint` from `list_flows` (or `capture_stats`) before acting, then call with `after: checkpoint`. Returns the flows answered since (a response or an error), oldest answer first, waiting up to `timeout` seconds (default 20, at most 30) for the first. Pass its `after` to the next call: each flow comes once. The same filters. A WebSocket is answered once, when it opens (`101`), and stays `open` until it closes |
| `get_flow` | one flow; bodies only with `bodies`, cut to `max_body` bytes each if given; `response_trailers` (HTTP/2's, or gRPC-Web's last frame); a body with `view` is reqcove's rendering, not its bytes: protobuf ([gRPC](#grpc)), or `multipart/form-data` with each part masked and files by their size |
| `list_ws_messages` | a WebSocket's messages (a row with `websocket_messages`), oldest first, after a cursor (`after`: a checkpoint, or the last page's `after`); filters `direction` (`client`, `server`) and `text`. A text message's first 4 KiB, masked as it arrived as bodies are; a binary one, one past about 20 a second on its socket, or text masking cannot read gives its size only. Kept are the socket's first 5 messages (an auth message is usually one) and its newest 100; `missed` counts the others after the cursor (`missed_at_most` when the cursor itself falls among them: then some may be from before it). `open` and `close` (code, who closed) say how the socket stands. Messages wake no `wait_for_flows`, but a timed-out wait lists the sockets that got messages since (`websocket_activity`); `search_flows` with `bodies` looks in the kept ones |
| `diff_flows` | two flows compared (one that worked and one that failed): method, URL, status, error, headers by name, bodies (JSON by path). While masking is on, values masked on both sides are listed under `masked`, never as equal (they may differ), and bodies that are not text are not compared; with `--no-redact` everything is compared |
| `summarize` | counts by host, User-Agent, status, method, device, content type, gRPC status (`by_grpc_status`), and endpoint (`by_endpoint`: method, host and path without the query, ids as `{id}`, then the GraphQL operation: `GET api.example.com/v1/users/{id}`, `POST api.example.com/graphql Login`); the same filters and `similar_hosts` |
| `list_devices` | carried devices (`lan:ADDR` in LAN mode), their counts, and first and last activity this run |
| `list_tls_failures` | handshakes a device refused: often certificate pinning, or a CA not trusted yet |
| `list_passthrough` | connections to `--pass-hosts` hosts: host, server, times, bytes; no URLs or contents |
| `capture_stats` | mitmproxy's state, the window the records cover, drops |
| `status` | the mode (`tailnet` or `lan`, with the LAN addresses allowed and refused), whether everything is set up, and the next steps if not; the presets turned on, of every kind (`active_presets`, with `kind`; v0.6's `active_mock_presets`, the same, is deprecated, removed in v1.0; not over `--mcp-http`, which has no preset tools) |
| `list_presets` | the [presets](#presets-an-agent-can-turn-on) in the `--rules` file, of every kind (`kind`): a mock's match and answer, a `map_remote` preset's target, a `modify_headers` preset's header name, a `resolve` preset's name and address; whether it is on, when it turns off. Never bodies, header values, filters or regexes. Not over `--mcp-http` |
| `activate_preset` | turn a preset of any kind on, for at most 5 minutes (`minutes`; `times`, at most 20 requests, for a mock); returns `checkpoint` for `wait_for_flows` and the preset it turned off for the same match. Not over `--mcp-http` |
| `deactivate_preset` | turn a preset off. Not over `--mcp-http` |
| `list_mock_presets` | deprecated, removed in v1.0: as `list_presets`, mocks only (v0.6). Not over `--mcp-http` |
| `activate_mock` | deprecated, removed in v1.0: as `activate_preset`, mocks only (v0.6): it never turns on a `map_remote`, `modify_headers` or `resolve` preset. Not over `--mcp-http` |
| `deactivate_mock` | deprecated, removed in v1.0: turn a mock preset off (v0.6). Not over `--mcp-http` |
| `list_rules` | the `--rules` file's [rules](#why-a-rule-did-or-did-not-apply-list_rules-explain_rules) by kind and number, with their presets and what is derived from them (a mock's match and answer, a `map_remote` target, a `modify_headers` header name and direction, a `resolve` name and address); never filters, regexes, header values, bodies or paths. Not over `--mcp-http` |
| `explain_rules` | why a flow (`flow_id`), or a method and URL, got or would get which rules: the scope, then the rewrites, a mock, the presets on and what one off would do; rules whose filter reads more than a method and URL in `cannot_tell`. Sends nothing, uses no preset's count. Not over `--mcp-http` |
| `add_marker` | a [marker](#mark-a-moment-reqcove-mark) (`text`, at most 80 characters, one line, masked); returns `id`, `time` (for `since`) and `checkpoint` (for `wait_for_flows`' `after`). Changes nothing on the device. Not over `--mcp-http` |
| `list_markers` | the markers, oldest first (`since`), with `source`: `cli` (`reqcove mark`) or `mcp` (an agent). Not over `--mcp-http` |

## Limits

The main ones are in the [README](../README.md#limits). The rest:

- IPv6 is refused; apps fall back to IPv4 at once.
- QUIC is dropped except to Apple, so apps fall back to TCP. This is by
  address, not by host: QUIC to hosts outside `--allow-hosts` falls back too
  (and without `--allow-hosts` as well). QUIC on a port other than 443 goes on,
  unrecorded.
- mitmproxy holds each WebSocket message until it is complete, and inflates a
  compressed one (permessage-deflate) whole (from reading mitmproxy's code; no
  compressed message has been tried), so one huge message can use a lot of
  memory: Reqcove's 4 KiB bound is on what it keeps, not on mitmproxy. If
  mitmproxy runs out, reqcove restarts it; when it is down again within a
  minute after 5 restarts in a row, `run` stops.
- A connection reqcove gives to mitmproxy waits for mitmproxy to connect to
  the server, as a direct one waits for the server: 10 seconds at most. The
  log then says `<address>:<port> did not answer within 10s (through
  mitmproxy)`, or, when the app gave up first, `the client left before
  <address>:<port> answered (through mitmproxy)`: the server was slow or not
  reachable from this computer at that moment (tried with an address that
  never answers; why the two such lines seen with real apps were slow is not
  known).
- Phone calls through the exit node have not been tried.
- Limits of one feature are in its section: [`--ui`](#on-the-iphone---ui),
  [`--web`](#in-mitmweb---web), [`--local-proxy`](#the-ios-simulator---local-proxy),
  [LAN mode](#without-tailscale-lan-mode---lan), [rules](#rules---rules), [an upstream proxy](#an-upstream-proxy---upstream-proxy).

## Security

In full: [SECURITY.md](SECURITY.md). Each option's own points are linked from
its section above; the rest:

- [What is recorded](SECURITY.md#what-is-recorded): only `--allow-hosts`
  hosts, never Apple's; what masking finds, and what it does not.
- [What the agent sees goes further](SECURITY.md#what-the-agent-sees-goes-further),
  to its model provider, and bodies may try to instruct it
  ([prompt injection](SECURITY.md#prompt-injection)).
- [What the devices can reach](SECURITY.md#what-the-devices-can-reach): not
  this computer, its LAN or the tailnet.
- [The CA's private key](SECURITY.md#the-cas-private-key), in the state
  directory.
- [The exit node's DNS](SECURITY.md#the-exit-nodes-dns) (`--dns`), and
  [a container](SECURITY.md#in-a-container).
