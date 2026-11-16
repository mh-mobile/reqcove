# Reqcove guide

[日本語](guide.ja.md) · [README](../README.md)

What comes after the README's four steps. Each section ends with a short
"Tried:" line: what was tried, on what, and what was not. In those lines,
mitmproxy is 12.3.1 (the version Reqcove locks), Linux is Ubuntu 24.04
(arm64), and an E2E test is a test that runs real mitmproxy.

Each section keeps its main warning beside the instruction. The rest of an
option's security points is folded under "Security details" in its section
(click to open it), with a "Checked:" line for what tests and trials covered.
[SECURITY.md](SECURITY.md) has the short version, and says what "state
directory" and "your own devices" mean; those blocks add to it and do not
repeat it.

1. [Set up](#set-up): [first start](#first-start) · [stop, restart, update](#stop-restart-update) · [restart in place](#restart-in-place-reqcove-restart) · [one CA on two computers](#use-one-ca-on-two-computers) · [undo everything](#undo-everything-reqcove-cleanup)
2. [Read the traffic with an agent](#read-the-traffic-with-an-agent): [allow the tools](#allow-the-tools) · [the skill](#teach-the-agent-the-skill-reqcove-init) · [markers](#mark-a-moment-reqcove-mark) · [agents on other devices](#agents-on-other-devices---mcp-http)
3. [Look at the flows yourself](#look-at-the-flows-yourself): [on the iPhone](#on-the-iphone---ui) · [as a HAR file](#as-a-har-file-reqcove-har) · [in mitmweb](#in-mitmweb---web)
4. [Record clients other than iPhone apps](#record-clients-other-than-iphone-apps): [apps that pin certificates](#apps-that-pin-certificates---pass-hosts) · [connections not read as HTTP](#connections-not-read-as-http-raw-tcp) · [gRPC](#grpc) · [Android](#android) · [the iOS Simulator](#the-ios-simulator---local-proxy) · [a web app's backend](#a-web-apps-backend) · [the Wi-Fi proxy](#without-the-exit-node-the-wi-fi-proxy) · [another Mac](#another-mac)
5. [Change where requests go](#change-where-requests-go): [rules](#rules---rules) · [mocks](#answer-a-request-here-mock) · [presets](#presets-an-agent-can-turn-on) · [why a rule applied](#why-a-rule-did-or-did-not-apply-list_rules-explain_rules) · [an upstream proxy](#an-upstream-proxy---upstream-proxy)
6. [Without Tailscale: LAN mode](#without-tailscale-lan-mode---lan)
7. [Run it in the background](#run-it-in-the-background): [start, update, stop](#start-update-stop) · [the config file](#the-config-file---config) · [`brew services`](#with-homebrew-brew-services) · [`reqcove service install`](#without-homebrew-reqcove-service-install)
8. [Containers](#containers)
9. [Troubleshooting](#troubleshooting)
10. Reference: [Options](#options) · [MCP tools](#mcp-tools) · [Limits](#limits) · [Security](#security) · [Compatibility](COMPATIBILITY.md)

## Set up

Installing is in the [README](../README.md#install), and so are the four
steps of a first run ([Use](../README.md#use)).

### First start

Run `reqcove setup` in a terminal: it walks through the first run. It refuses
when its input or output is not a terminal, as from an agent. Skip any step
with an empty answer. It starts nothing and removes nothing.

- **uv**: it says where `uvx` is, or how to install it. It installs nothing.
- **The device and the hosts**: it writes `--device`, quoted, to the file
  the service reads, and the hosts to their own file beside it, which that
  file reads with `--allow-hosts=@FILE` (since v1.1; `reqcove capture save`
  writes it).
  - The file is `~/.config/reqcove/config` (`reqcove service install`'s). For
    a brew install (this binary under `Cellar/reqcove/`), it is Homebrew's
    `$(brew --prefix)/etc/reqcove/config` (`brew services`').
  - The hosts file is `hosts` beside it: `~/.config/reqcove/hosts`, or
    `$(brew --prefix)/etc/reqcove/hosts`. One host a line; `#` starts a
    comment. No hosts answered: no hosts file, and the `--allow-hosts` line
    stays a comment.
  - Both are 0600, and their directory 0700 when new. Before they take the
    files' place, they are checked as `run` reads them.
  - `*` and a name starting with `-` are asked again. A pasted URL keeps its
    host only.
  - No hosts yet: once `run` runs, `reqcove status` (or an agent's
    `summarize`) lists the hosts the iPhone reached.
  - An existing file is shown, and kept unless you answer `y`. Then it is
    replaced whole, and the old one is kept as `config.old` (0600): its other
    flags, such as `--rules`, are there to copy back. An existing hosts file
    is kept as `hosts.old`; the new one keeps its comments.
  - A path that is not a plain file is left alone.
- **The agent**: if you answer `y`, it adds the skill as `reqcove init` does
  (with no agent found in your home, it says so). It prints
  `claude mcp add reqcove -- reqcove mcp`, and runs no agent command. When
  `reqcove` on `PATH` is not this binary (none, or another one), the commands
  it prints name this binary by its full path instead, as those of
  `service install` do.
- **How to start** (since v1.1, its last lines): in a terminal first,
  `reqcove run`, which reads the file with no arguments (or
  `reqcove run --config FILE` when another file comes first,
  [the config file](#the-config-file---config)); then, to start it at login in
  the background, `reqcove service install`, or `brew services start reqcove`
  for a brew install. `--lan` is not kept in a file: in a terminal,
  `reqcove run --lan --allow-hosts HOSTS`. Then how to change things while it
  runs: `reqcove capture add HOST` and `reqcove capture save` for the hosts,
  else edit the file and restart. It prints no login URL: `reqcove links`
  does.
- **Ctrl-C** stops it at the question it is on. What was written stays.

`run` prints what is left to do, and `reqcove status` repeats it:

1. Log in with the URL.
2. Sign the node, if the tailnet uses Tailnet Lock.
3. Approve the exit node.

About the login URL and the links:

- **Whoever opens the login URL first puts the node in their own tailnet.**
  The same care goes to the `--ui`, `--web` and `--mcp-http` links, which
  carry their tokens. `run` shows them on its terminal only
  ([SECURITY](SECURITY.md#the-login-url)).
- **To see them again**, run `reqcove links` in your terminal. It prints them
  with QR codes, and mitmweb's link on this computer and the CA's too. It
  refuses when its output is not a terminal (Claude Code's `!` gets nothing
  either).
- **Off a terminal** (a service, `docker logs`), `run` prints
  "`reqcove links` prints it" in their place.
- **To skip the approval** for new nodes, add an auto-approver to the tailnet
  policy: `"autoApprovers": {"exitNode": ["you@example.com"]}`.

Tried, for `reqcove setup`: unit tests (answers fed in); by hand on macOS and
on Linux (a VM, over ssh), 2026-11-14; Ctrl-C at the first question (it ended
at once, nothing written). Tried too: `reqcove links` from Claude Code's `!`.
Tried by hand with a v1.1 build from a local formula (macOS, 2026-11-16):
setup wrote Homebrew's config and its hosts file and pointed to `brew services
start reqcove`, whose run read them and recorded the iPhone. The hosts file
otherwise: unit tests (the file, its `@` line, an old one kept).

<a id="security-login-url"></a>

<details>
<summary>Security details: how the login URL and the links are kept out of logs and files</summary>

Where they are shown, and who can read the files:
[SECURITY](SECURITY.md#the-login-url). Beyond that:

- **Off a terminal** (a service, `docker logs` without `-t`, an agent's
  shell), `run` prints neither the URL nor the links, only that
  `reqcove links` prints them.
- **Agents are told never to run `reqcove links`**, by the skill and the
  server's instructions.
- **One filter for every log line.** Every line `run` logs, and the error it
  exits with, goes through a filter that replaces the tokens, the login URL
  itself once `run` has seen it, and any URL shaped as a control server's
  login URL (Tailscale's `/a/<hex>`, Headscale's `/register/…` and
  `/register?key=…`). Under `--verbose` that covers tsnet's own lines, which
  print the URL before `run` learns it.
- **The filter knows those shapes only.** A control server whose login URL
  has another shape is masked from `run`'s first poll on (within 3 s).
- **`login-url` and `links`** are kept in the state directory, 0600, and
  removed when `run` starts and when it stops. After a crash they stay until
  the next start: `reqcove links` does not check that `run` is up.
- **tsnet keeps its own lines**, the login URL among them, in a buffer file
  there (`tsnet/tailscaled.log*.txt`, 0600), also without `--verbose` (from
  reading the code).
- **mitmweb's server logs a failed request's URL**, `?token=` included, into
  `mitmproxy.log`: the addon masks the token there first.

Checked: tests (tsnet's lines, read from a test control server; the mitmweb
E2E test for `mitmproxy.log`). Tried 2026-11-13: Claude Code's `!` gets
nothing from `reqcove links`.

</details>

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
  for the skill. A running `run` keeps the old version until it is restarted:
  `reqcove status` says when its version is not its own, and gives the one
  command that restarts it under what started it (a terminal, `reqcove
  service install`'s service, `brew services`;
  [the table](#start-update-stop)). `reqcove har > flows.har` first: a restart
  empties the records.

Tried: a restart under a Claude Code session. What `reqcove status` says
after an update: unit tests (a v1.0.0 `run` faked), and by hand (2026-11-16)
after `brew upgrade` from v1.1.0 to a v1.2 build under `brew services`: it
named the version difference, then `brew services restart reqcove`.

### Restart in place (`reqcove restart`)

```sh
reqcove restart    # in your terminal; --state DIR for another node
```

Since v1.3, `reqcove restart` asks the running `run` to stop and start again
in the same process, as it was started: the same binary path and arguments,
the config on disk as it is now. Under `reqcove service install`'s service or
`brew services` it stays the service's process, so you need not know which
started it.

- **Checked first, nothing stopped when refused:** the config on disk and
  `run`'s command line as the next start reads them (a flag or file it would
  refuse, with the reason, as `reqcove reload` checks them), and the binary
  `run` was started from still being there. That path is the one `run` was
  started with (absolute, as services start it, or found on PATH then), links
  kept: Homebrew's `opt/reqcove` is kept, so after `brew upgrade` a restart
  starts the new version (read from the code; not tried).
- **Then it stops as Ctrl-C stops it:** the system's web proxies put back
  (`--local-proxy`), mitmproxy, the node and caffeinate stopped. Devices lose
  the internet until it is up again.
- **What a restart empties:** the records (flow ids and cursors too), the
  markers, the agents' requests, the hosts changed by `reqcove capture` and
  not saved, allow-all and discovery, the presets turned on, the
  `reqcove console` links not opened yet. **What it keeps:** the state
  directory and its tokens, the CA, the node; the `reqcove console` page's
  port, and its sessions (a page open stays open); no other `run` can take
  the state meanwhile.
- **When the new start fails** (a file it reads is gone, say `--uvx`'s),
  `run` puts back the config it had started from (a copy it kept from its
  start, with the hosts file line `capture save` added; not `config.prev`),
  keeps the one that failed as `config.failed` beside it, and starts once
  more. If that fails too, it stays down, as a failed start always does (no
  service restarts it). `reqcove status` says what happened (a `restart:`
  line), until `run` is next started by hand or by its service. A run
  started from flags alone (no `--config`) has no config to put back: a
  failed start stays down.
- **The config names another `--state`:** the new start uses it, and
  `reqcove status --state DIR` for it says how it went.
- In a terminal only, as `reqcove capture`. A `run` older than v1.3 says to
  stop it and start it again.

Tried: unit tests (the checks; the copy of the start config, after two writes
and after a write then an edit by hand, after a `capture save` that added the
hosts file line, with a leftover copy and with `--state` changed; a copy that
is a link, another user's, not 0600, wrongly named, outside a state directory
or missing is neither read nor removed, and no retry; the retry made once;
the exec of a test binary keeping the page's port, its session and the
state's lock, the variables and the fds not reaching a child), and E2E with
real mitmproxy (`run` in LAN mode on the loopback, started through a link:
two restarts, the second after an edit its start refuses; the pid, the
page's port and session kept, the state never free, mitmdump and caffeinate
stopped before each exec, the config put back and kept as `config.failed`,
`reqcove status` saying so; on macOS with `--local-proxy`, the system proxy
put back at each stop, through a stand-in `networksetup`). Not tried: a
tailnet node, under launchd, `brew services` or systemd, after `brew upgrade`
and `brew cleanup`, on Linux.

### Change what is recorded while it runs

Since v1.1, the hosts recorded change without a restart, so the records stay.
The commands change the `run` that is running, whether a terminal or a
service started it (`--state DIR` for another one). Type them in a terminal:

```sh
reqcove capture add api.example.com          # record it too
reqcove capture remove api.example.com       # stop recording it
reqcove capture add --pass pinned.example.com     # carry it undecrypted (as --pass-hosts)
reqcove capture remove --pass pinned.example.com  # decrypt it again
reqcove capture set --allow-hosts 'api.example.com,*.example.net'  # all of them at once
```

Hosts are written as `--allow-hosts` takes them; `--state DIR` for a node
other than the default one. Each answer says what happened: applied, or
pending (mitmproxy took the change but did not acknowledge it: reqcove tells
it again every few seconds, and when mitmproxy starts again), how many
records are kept, and the limits below. While mitmproxy restarts, `add`,
`remove` and `set` are refused, nothing changed ("mitmproxy is restarting:
try again in a moment"): each is checked first against the rules mitmproxy
holds.

- **New connections only.** An added host is decrypted on new connections:
  an app keeps its connection open for a while, so reopen it to see the host
  now. A removed host is no longer recorded from the next event on, and a
  body under way is copied no more, but its open connections stay decrypted
  (unrecorded) until they close. With `--web`, mitmweb still lists the
  requests on them (URLs and headers, unmasked), without their bodies (from
  reading the code).
- **Not saved** until `reqcove capture save` (below): a restart of `run`
  goes back to the hosts it was started with (its flags or `--config`).
- **Refused:** `"*"`, removing a host a wildcard takes in (the answer names
  the wildcard: remove that, or use `set`), a change that takes out a host a
  `mock` rule names (the answer names the rules), and any change in LAN mode
  (not in this version: restart `run` there). A `run` older than v1.1 says so.
- **Only in a terminal**, as `reqcove mark`: agents never run it. A tool's
  note, or a step in `next_steps`, gives `reqcove capture add HOST` for you to
  run. That is a guard against mistakes, not a boundary
  ([SECURITY](SECURITY.md#other-processes-on-this-computer)).
- **A trace:** each change is a line in `run`'s log, a marker with source
  `cli` (`list_markers`), and in `reqcove status` "last changed at … (capture
  add api.example.com)" (`scope_change`, `scope_changed_at` in `--json`).

Tried by tests (unit, and E2E with real mitmproxy: add, then a new
connection is recorded; remove, then one is not; the marker and status), and
by hand on an iPhone (Safari over the exit node, a `run` under `brew services`, 2026-11-16): add, remove and `set`, each answered and marked, a host recorded
after `add` and `set` and not after `remove`. The pending answer and a `mock` rule's refusal, as `reqcove
capture` gives them, are from reading the code (the change underneath, its
pending state and the refusal, has tests of its own); the refusal while
mitmproxy restarts, telling a pending change again, and a body under way
copied no more (with mitmproxy's Python) have unit tests.

#### Keep the hosts for the next start (`reqcove capture save`)

```sh
reqcove capture save     # write the hosts recorded now to the hosts file
```

It writes the hosts recorded (those `capture start` records, while stopped)
into the hosts file `run` read them from: the `--allow-hosts=@FILE` that
`reqcove setup` puts in the config. Since v1.3 the hosts passed undecrypted
(`--pass`) go the same way into the `--pass-hosts=@FILE`. The next start from
that config records them. The file is replaced whole (0600). Its comments
stay, and so do its lines whose hosts are all kept; new hosts go at the end.

- **A config with its hosts inline** (since v1.3: `reqcove setup` of v1.0
  wrote `--allow-hosts=HOSTS`, or one written by hand): the first save shows
  what it would do and asks y/N. It creates the hosts file beside the config
  (`hosts`, and `pass-hosts` for hosts passed undecrypted; 0600, never over a
  file or link already there) and adds one line to the config,
  `--allow-hosts=@FILE` (or `--pass-hosts=@FILE`), at its end. The config's
  other lines are not changed; the file before is kept as `config.prev`
  (0600). If writing the config fails, the file created is removed. From then
  on `run` saves to that file (a second save asks nothing). Refused when a
  file of that name is there already and the config does not name it: add the
  line yourself (then `reqcove reload`), or move the file away.

- **Hosts given as they are** (on `run`'s command line, or as
  `--allow-hosts HOST` in the config) are not written: a start with them
  records them again whatever the file says (one in the hosts file too stays
  there). The answer names them, and says which of them you removed now
  that come back that way, in the hosts file too or not.
- **Nothing to save to** when `run`'s hosts come from several files, or,
  started from flags alone, from no hosts file: the answer says to put one
  `--allow-hosts=@FILE` on the command line, or to start `run` from a config.
  Nothing is written. (Started from flags alone, the hosts passed
  undecrypted are not saved, unless `--pass-hosts=@FILE` names a file.)
- **No hosts left** (since v1.3): the file keeps its comments and no host,
  when the next start would still take it. Before writing, the save checks the
  whole set of `run`'s flags it would leave, as the next start reads them:
  `--rules`, `--upstream-proxy` and hosts passed undecrypted need hosts
  recorded (hosts given as they are count), so a save leaving none with
  `--rules` is refused.
- **Refused**, nothing written: `"*"` (never in the file); what the next
  start would refuse; a file that is not a plain file (a link, say) or not
  yours; the file `--pass-hosts` reads too. In LAN mode, as the others.
- **A trace**, as a change: `run`'s log, a `cli` marker, and `reqcove status`
  "last changed at … (capture save)".

Tried by tests only (unit: what is written and kept, each refusal; E2E with
real mitmproxy: `run` started from a config with a hosts file and a host on
the command line, add, remove that host, save, then a new `run` from the
config records the host added), and by hand on an iPhone (Safari over the exit node, a `run` under `brew services`, 2026-11-16): Homebrew's hosts file
rewritten with the hosts added live, its comments kept. The v1.3 changes
(the first save on an inline config with its y/N, a file without hosts, pass
hosts saved, the check of the flags left) have unit tests only, not tried by
hand.

#### Edit the files, then `reqcove reload`

```sh
reqcove reload     # read the config, its hosts files and the --rules file again
```

Since v1.1, after you edit the config, the hosts file it names
(`--allow-hosts=@FILE`) or the `--rules` file, `reqcove reload` puts their
hosts and rules in force without a restart, so the records stay. `--state
DIR` for a node other than the default one.

- **All or nothing.** It reads the files first and checks them together: the
  config's flags, the hosts files, and the rules against the new hosts (a
  host and the `mock` naming it can go in, or out, in one edit). If anything
  does not load, nothing changes, and the answer says why (a line number, never
  a line's text).
- **The hosts** replace those recorded now (the base, while stopped or during
  allow-all: what is recorded once it ends). Hosts given on `run`'s command
  line stay. Changes made with `reqcove capture` and not saved are replaced by
  the files': the answer names them.
- **The rules** are read again and loaded with the hosts at once; the answer
  says how many of each kind are loaded. Presets go off (new rules turn them
  off; an agent turns one on again). `--rules-reload` works as before.
- **Other settings** (`--device`, `--mcp-http`, `--proto`, `--mask-values`,
  …) take a restart: the answer names, in one line, those that changed
  (never their values), and applies none of them. So does a `--rules` file
  added, removed or moved to another path.
- **Nothing to reload** for a `run` started from flags alone (no `--config`,
  no `--allow-hosts=@FILE`, no `--rules`).
- **Refused**, nothing changed: a hosts file that now gives `"*"` (every
  host) while the hosts recorded are not `"*"`, as `capture set` refuses it
  (`reqcove capture allow-all --for D` records every host for a while); and
  while mitmproxy restarts, as `capture add` ("try again in a moment"). New
  hosts and rules that mitmproxy then does not acknowledge restart it with
  both, never one without the other.
- **New connections only**, as `capture add` and `remove`.
- As the `capture` commands: in a terminal only, refused in LAN mode, an
  older `run` named, and a trace (`run`'s log, a `cli` marker, `scope_change`
  `reload`).

Tried by tests only (unit: the parse of `run`'s arguments again, which never
exits nor logs, the settings named, `"*"` refused, mitmproxy restarted when it
does not acknowledge new rules; E2E with real mitmproxy: a host and a
mock for it added together, then answered by the mock; a broken rules file
changing nothing, the hosts file's edit neither; the host and its mock taken
out together; an unsaved `capture add` named as replaced; a preset off after;
`--mcp-http` added named), and by hand on an iPhone (Safari over the exit node, a `run` under `brew services`, 2026-11-16): the hosts file edited by hand,
then `reload`: the host added recorded, the one taken out not, the records
kept.

#### Stop recording for a while

```sh
reqcove capture stop     # record nothing new; the records stay readable
reqcove capture start    # record the same hosts again
```

While stopped, mitmproxy decrypts nothing new (mitm.it only, for the CA),
nothing new is recorded, and **no rule of the `--rules` file applies**: mock,
map_local, map_remote, modify_headers and resolve, presets included (the
ones on are turned off, and `activate_preset` is refused). So the app's
requests go to the real servers as it sends them, a mocked API's too: the
answer of `stop` warns of it and says how many records are kept.

- Connections already decrypted stay decrypted until they close, but nothing
  on them is recorded, and no rule applies to their new requests (a request
  already under way when you stop ends as it began, from reading the code;
  its body is copied no more, a unit test). An open WebSocket's flow
  is closed with "recording stopped: its host left the scope". With `--web`,
  mitmweb still lists the requests on those connections (URLs and headers,
  unmasked), without their bodies (from reading the code).
- `start` says the hosts it records again. It records new connections and
  WebSockets only (reopen the app): one open before the stop is not recorded
  again. Presets stay off until an agent turns one on.
- `capture add`, `remove` and `set` while stopped change the hosts `start`
  records (the answer says so); nothing is recorded until then.
- A restart of mitmproxy keeps it stopped; a restart of `run` records again
  (not saved).
- `reqcove status` says "recorded: nothing: stopped" and the hosts kept;
  `--json` and the MCP `status` say `"recording": "stopped"`, `allow_hosts: []`
  and the hosts kept in `base_allow_hosts` (`base_pass_hosts`); `next_steps`
  gives `reqcove capture start`. Refused in LAN mode, as the others.

Tried by tests only (E2E with real mitmproxy: an open WebSocket records
nothing more and does not resume after the start, a new one records; a mocked
URL reaches the server, on a new connection and on one decrypted before the
stop; a preset is turned off and cannot be turned on; mitmproxy killed while
stopped comes back stopped; the CLI's answers, status, markers), and
by hand on an iPhone (Safari over the exit node, a `run` under `brew services`, 2026-11-16): nothing recorded while stopped, recorded again after `start`.

#### See what every app sends, for a while

```sh
reqcove capture allow-all --for 30m   # record every host for 30 minutes (at most 24h)
reqcove capture allow-all --end       # end it sooner
```

For a while every host is decrypted and recorded, as `--allow-hosts '*'`
does, not only the ones you allowed: to see what the other apps send. Apple's
hosts still pass through undecrypted, and so do the `--pass-hosts` ones. The
answer repeats what `'*'` warns of: every app's and site's traffic is
recorded and readable by agents and their model providers; apps that pin
their certificates (banks, say) fail meanwhile; and, when they apply,
`--upstream-proxy` (every request goes on to it), `--mcp-http`, `--web`,
`--local-proxy`.

- **Time-limited.** It ends at the time the answer gives, by this computer's
  clock or by `run`'s own running time, whichever comes first (a sleeping Mac
  does not keep it on longer), within a second or so. `--for` again moves the
  end to now plus the new time.
- **The records made meanwhile stay** after it ends, until evicted or `run`
  restarts. Other apps' traffic fills `max_flows` and `max_bytes` too, so your
  app's older records are evicted sooner (from reading the code).
- **The rules** (`--rules`) apply to the hosts you allowed alone, never to
  the other hosts recorded meanwhile: a `modify_headers` rule naming no host
  does not send its header to them.
- **New connections only**, both ways: reopen an app to see it; once it
  ends, connections decrypted meanwhile stay decrypted (unrecorded) until
  they close.
- `capture add`, `remove` and `set` meanwhile change the hosts recorded after
  it (the answer says so). `capture stop` ends it; `allow-all` while stopped
  is refused (`capture start` first). A run started with `--allow-hosts '*'`
  has nothing to add ("nothing changed").
- **Never kept past its end:** a restart of mitmproxy meanwhile keeps it
  until its end, not longer; when its end comes and mitmproxy does not
  answer, reqcove stops recording the other hosts first, then restarts
  mitmproxy without it. So does a `capture stop` meanwhile that mitmproxy
  does not acknowledge: restarted stopped (a unit test). A restart of `run`
  ends it (not saved).
- `reqcove status` says "every host: allow-all until …" with the time left
  and the hosts recorded after it; `--json` and the MCP `status` say
  `"recording": "allow-all"`, `allow_hosts: ["*"]`, `allow_all_until`,
  `allow_all_left` and `base_allow_hosts`; `next_steps` gives the time left
  and `reqcove capture allow-all --end`. After it, `records_outside_scope`
  counts the records of hosts outside the ones recorded. The trace, the LAN
  refusal and "in a terminal only" as the others; the end by time is in
  `run`'s log and `scope_change` ("allow-all ended: its time is up"), with no
  marker.

Tried by tests only (unit: the arguments, the order, a stop ending it, the
end by either clock with mitmproxy silent; E2E with real mitmproxy: a host
outside the ones allowed recorded, with no rule applied, and not after the
end, its records kept; a `--pass-hosts` host still undecrypted; mitmproxy
killed just before the end comes back without it; the CLI's answers, status,
markers), and by hand on an iPhone (Safari over the exit node, a `run` under `brew services`, 2026-11-16) for a minute: another site and another app's
requests recorded, none after the end, the records kept. Not across a real
sleep of the Mac.

#### Find the hosts an app reaches (`reqcove capture discover`)

```sh
reqcove capture discover --for 30m   # keep the names of the other hosts for 30 minutes (at most 24h)
reqcove capture discover --end       # end it sooner
```

Since v1.1, for a while, Reqcove keeps the **names** of the hosts outside the
ones recorded that the devices reach, and how often: the name a TLS
connection asks for (its SNI), and the Host of a request on a connection that
is decrypted but not recorded. Nothing they send is kept: no content, no URL
path, no time. So you can see which hosts your app talks to, then add the
ones you want.

- **Where it shows:** `reqcove status` ("outside:", each with the `reqcove
  capture add HOST` command that records it), and for this computer's agents
  `status` and `summarize` (`out_of_scope_hosts`, `out_of_scope_hosts_kept`,
  `discover_until`, `discover_left`). Never over `--mcp-http` nor on the
  `--ui` page. It shows on once mitmproxy has acknowledged it: until then
  (mitmproxy restarting, say) `next_steps` says it is asked, not on yet, and
  reqcove tells mitmproxy again every few seconds and when it starts again
  (unit tests).
- **Counts:** TLS connections and requests together. The 30 most seen are
  shown, of at most 1,000 kept (past that, a new name takes the place of the
  least seen). A host you add drops off the list.
- **Left out:** Apple's hosts, mitm.it, names that are not plain host names
  (shown masked, without a command, if masking changed them).
- **Not every host:** a connection without a name (an address dialed), one
  with ECH (only its outer, public name is seen) and connections that are not
  TLS on a host outside the scope are missed (from reading the code, not
  tried).
- **Time-limited**, as allow-all: it ends by this computer's clock or by
  `run`'s running time, whichever comes first; `--for` again moves the end.
  A run with `--allow-hosts '*'` has nothing outside ("nothing changed").
  At the end no name is taken from then on, whether mitmproxy was told or
  not. The names seen **stay** until `run` restarts or discovery starts
  again (a new `--for` after the end begins a new list). A restart of `run`
  ends it (not saved).
- The cost: each TLS connection's ClientHello is read once more (mitmproxy
  reads it anyway to decide what to decrypt): about 22 µs for a 1.5 KB one,
  from a micro-benchmark on an M1 Max Mac (mitmproxy 12.3.1, Python 3.14);
  nothing when off (from reading the code).
- As the other `capture` commands: in a terminal only (agents never run
  it), refused in LAN mode, an older `run` named, and a trace (`run`'s log,
  a `cli` marker, `scope_change`).

Tried by tests only (unit: the names taken only while on, Apple's, mitm.it and
bad names left out, masking, the bound, the end by either clock with
mitmproxy silent; E2E with real mitmproxy: a TLS connection's SNI and a
request's Host counted, once a connection, none of Apple's, nothing recorded
of them, not in what `--mcp-http` and `--ui` read, none taken before or after,
a host added dropping off; the summarize and status tools: on the local
server alone), and by hand on an iPhone (Safari over the exit node, a `run` under `brew services`, 2026-11-16): a site's names listed in `reqcove status`
and `summarize` with their `capture add` command, one added and then recorded.

#### Let an agent ask for a host (`reqcove capture approve`)

```sh
reqcove capture requests            # what agents asked, and what came of it
reqcove capture approve 0a1b2c3d    # shows the hosts, asks y/N, then adds them
reqcove capture deny 0a1b2c3d       # refuses it
```

Since v1.2, an agent connected through `reqcove mcp` can ask for hosts to be
recorded (the `request_capture_add` tool): 1 to 5 host names. It records
nothing by itself. `run` keeps the request, with an id and its hosts fixed,
and the agent's answer gives you the command to run, such as
`reqcove capture approve 0a1b2c3d`. The agent is told never to run it.

- **Approve** shows the hosts and asks `Approve? [y/N]`; only `y` or `yes`
  approves. It adds exactly those hosts, as `reqcove capture add` does:
  new connections only, not saved, the hosts passed undecrypted kept, and a
  stopped recording stays stopped (the hosts are the ones `capture start`
  records). The id is bound to its hosts: an approval for other hosts is
  refused.
- **The client's dialog:** when the agent's client says it can show a form
  (MCP elicitation), `reqcove mcp` also shows one for a new request. Its text
  is Reqcove's: the hosts (run's, checked as host names), that agents will
  read their traffic, masked (unmasked, it says, under `--no-redact`; so does
  `approve`, and every view of the request, `unmasked`), and that it is not saved; never the agent's words. It has one box, "Record these hosts", off at
  first: accept with the box ticked approves it as `approve` does (Enter on
  Accept alone, where Claude Code's cursor starts, approves nothing). Decline,
  close it, accept without the box, an error or no answer within 2 minutes
  leaves it pending, for the terminal or `reqcove console`. Tried in Claude
  Code's terminal CLI (2026-11-16): the dialog shows, with the box; Esc
  leaves the request pending, and so does Accept with the box unticked;
  ticked, Accept approves it ("approved in the dialog"). It is not
  shown again when the agent asks again for the same hosts. A client that
  declares URL elicitation alone (no form) gets no dialog. Over MCP's newest
  protocol the client shows the dialog between two calls: its answer counts
  only for a dialog `reqcove mcp` showed on that connection, once, within 2
  minutes by either clock; any other answer leaves the request pending. If
  the client fails there, the agent's call ends in an error and the request
  stays pending: asking again for the same hosts gives its id and command.
- **What is asked:** host names only (letters, digits, `-` and `.`; no
  wildcard, no IP address), lowercased, each once, sorted. Refused: hosts all
  recorded already, a host passed undecrypted (`--pass-hosts`), any host
  you denied in the last 10 minutes (alone or with other hosts), a 4th pending request, an 11th made in
  10 minutes, and any in LAN mode. Asking again for the same hosts while
  pending gives the same request.
- **Time-limited:** a request expires 10 minutes after it was made, by this
  computer's clock or by `run`'s running time, whichever comes first. One
  that ended (applied, failed, denied, expired) is kept 10 minutes more for
  `capture requests` and `get_capture_request`. A restart of `run` drops
  them all.
- **Where it shows:** `reqcove status` ("asked:", with the command), this
  computer's `status` (`capture_requests`), and the agent's
  `get_capture_request` (`pending`, `approved`, `applied`, `failed`,
  `denied`, `expired`). Never over `--mcp-http`, which has neither tool.
- **A trace:** each state is a line in `run`'s log; an approval is also a
  marker with source `mcp` and `scope_change`, both "capture add HOST (asked
  by an agent, approved in the terminal)" (or "in the dialog").
- As the other `capture` commands: in a terminal only, and a `run` older than
  v1.2 says to restart it with v1.2.

Tried: unit tests (the hosts taken and refused, the limits, expiry
by either clock, the denial kept, a restart, an approval for other hosts, the
y/N prompt, a v1.1 and a v1.0 `run`, LAN mode, the terminal check, a denied
host asked with another, `unmasked` in every view under `--no-redact`; the
dialog with an in-memory client accepting, declining, cancelling, failing,
not answering in time, or without the capability, over MCP's newest
protocol and older ones; a client declaring URL elicitation alone; an answer
made up, replayed, from another connection, or late by either clock; a raw
client asking 2026-07-28 in `initialize` (answered 2025-11-25, and given the
dialog between two calls, as the SDK treats it); neither tool over `--mcp-http`), and E2E with real
mitmproxy (asked through `reqcove mcp`, shown in this computer's status and
not in `--mcp-http`'s, approved, then a new connection recorded; the `mcp`
marker and `scope_change`; approved while stopped); by hand in Claude Code's
terminal CLI (2026-11-16): its dialog as above, a request left pending
approved in `reqcove console`, and one that expired by itself. Not tried:
Codex's dialog.

#### See the state and approve in a page (`reqcove console`)

```sh
reqcove console    # prints a link to a page on 127.0.0.1 and opens it in the browser
reqcove console --end    # ends every page open and every link not opened yet
```

Since v1.2, `reqcove console` asks the running `run` for a page of its state and
of the agents' requests, and prints its link. Since v1.3 it opens a file
`run` wrote in the state directory with `open` (macOS) or `xdg-open`
(Linux), never the link itself, which other users of this computer would see
in `ps`: the file sends the browser on to the link, and `run` removes it
after 60 seconds. When that fails, when the file opens in an app other than
the browser (`open` picks the app for `.html` files, which may not be your
web browser), or when the browser cannot read the state directory (a
sandboxed one may not read `~/.reqcove`), open the printed link yourself;
against a v1.2 `run`, which writes no file, it opens nothing and prints the
link alone. The page shows
what `reqcove status` shows, refreshed every 5 seconds: the version, `run`'s
binary, the service, the config and hosts files, keep awake, the node and its
devices, what is recorded (on, stopped, or allow-all and until when, with the
hosts) and a change pending, and the next steps; and the requests waiting,
each with its hosts, until when, and **Approve** and **Deny**. Approve adds
the hosts the page showed, as `reqcove capture approve` does (`run` refuses
other hosts), traced "capture add HOST (asked by an agent, approved in the
console)"; Deny is `reqcove capture deny`. Nothing else changes from the page:
the hosts, stop and start, save, allow-all and discovery stay commands.

- **This computer only:** `run` listens on 127.0.0.1, on a port the system
  picks, from the first `reqcove console` until `run` ends (`reqcove restart`
  keeps it); never on the tailnet
  node, the LAN, or `--ui`'s page. In LAN mode it shows the state too (the
  requests are refused there, as ever).
- **The link works once, for 60 seconds:** it carries a one-use code after
  `#`, which the page trades for a session kept in that tab alone (the
  browser forgets it when the tab closes; `run` keeps it until the limits
  below) and then takes out of the address bar. `reqcove console` again
  gives a new link. A link opened a second time closes every page of
  `reqcove console` and says so: someone else may have had it. At most 4 pages
  at once (a 5th closes the one used least recently); one unused for 12
  hours closes; a restart of `run` closes them all, but `reqcove restart`
  (since v1.3), which keeps them, each as long unused as it was.
- **`reqcove console --end`** (since v1.3) closes every page and ends every
  link not opened yet; the pages say so. `reqcove console` again opens a new
  one. A `run` older than v1.3 says to restart it with v1.3.
- **Never shown:** the flows' contents, any token, link or login URL, and any
  text from an agent or an MCP client (the hosts it asked for are checked as
  host names first).
- In a terminal only, as the `capture` commands; a `run` older than v1.2 says
  to restart it with v1.2.

Tried: unit tests (the listener on 127.0.0.1 only; a wrong Host, a
cross-site or missing Origin, a body other than JSON, a GET or PUT where a
change is a POST, no session, a wrong one, a cookie alone, the code once,
60 seconds by either clock, a code used twice closing every session, 4
sessions, 12 hours idle by either clock; an approval for other hosts refused,
approve and deny traced as the page's; no CORS header, the CSP, `no-store`,
`no-referrer` on every answer; no code or token in the answers or `run`'s
log; LAN mode; the terminal check, the link printed and the code file
handed to a stand-in for `open`, the code never in its arguments, a v1.1
`run`; the code file 0600, never through a symlink nor over a file, removed
after its time, at `--end` and when `run` starts and ends; `--end` ending
sessions and codes, in LAN mode too, and a v1.2 `run`'s answers), and E2E with real mitmproxy (approved in the console through its
listener, the `mcp` marker "approved in the console"); by hand in a
Chromium-based browser on macOS (2026-11-16): the page showed the state and
the agents' requests, and Approve applied the hosts (traced "approved in the
console"). The file's link, its `#c=` kept, reached a page on 127.0.0.1 in
headless Chromium and Firefox on macOS (2026-11-16). Not tried: the file in
Safari, Linux's `xdg-open`, the page in another browser, another user of this
computer.

### Use one CA on two computers

The CA lasts as long as the state directory. Copy `~/.reqcove/mitmproxy/` whole
(it holds the private key) into `~/.reqcove/` on the other computer. Do it
with reqcove stopped there, or before its first run.

The copy holds the key too: whoever has either directory can impersonate any
HTTPS site to the iPhone. Keep both to yourself
([SECURITY](SECURITY.md#the-cas-private-key)).

<a id="security-ca-copies"></a>

<details>
<summary>Security details: the copies Reqcove makes of the CA, and backups</summary>

What the key can do, and what to do about copies and backups:
[SECURITY](SECURITY.md#the-cas-private-key). Beyond that:

Copies in other state directories:

- A `--state` directory without a CA gets a copy of `~/.reqcove`'s at start
  (several exit nodes on one computer, one profile on the iPhone):
  `mitmproxy-ca.pem` with the key, and the certificate files; not
  `mitmproxy-ca.p12`, nor mitmweb's password. `run` logs where it copied it.
- The key is then in each such directory, each 0700 with the files 0600.
  Deleting one leaves it in the others, so "delete the directory" in
  [SECURITY](SECURITY.md#the-cas-private-key) means each of them. Removing
  the profile from the iPhone is what stops them all.
- `~/.reqcove/ca-copies` lists the copies. `cleanup` of `~/.reqcove` names
  those still holding the CA; `cleanup` of a copy says the profile serves
  both.
- Every command refuses a `--state` starting with `~`: `--state=~/x`, which
  the shell leaves as it is, would put the key in `./~/x`, and `cleanup`
  would call the real one gone.

Backups:

- Backups hold the key too. The state directory is an ordinary directory in
  your home, and Reqcove marks nothing in it as not to be backed up (from
  reading the code; no backup was looked at). Time Machine, or another backup
  or sync tool that takes your home, copies the CA's key, the node's key
  (`tsnet/`) and the tokens, and keeps them after `cleanup --delete-state`.
- A restore can widen the modes, so that other users of this computer can
  read the files. `run` makes the directory 0700 and the token files 0600
  again at start, not the other files (from reading the code).

Checked: tests (a copy's directory is 0700 and its files 0600).

</details>

### Undo everything (`reqcove cleanup`)

`reqcove cleanup` lists the steps; with `--delete-state` it deletes the state
directory. First:

- Remove the CA's profile from the iPhone
  ([SECURITY](SECURITY.md#the-cas-private-key)).
- Stop a service (`brew services stop reqcove`, or
  `reqcove service uninstall`). Otherwise it starts `run` again at the next
  login, which makes the state directory anew.

What cleanup does not remove (the node in the tailnet, the service's files,
the skill, HAR files, backups, the agent's transcripts) is listed
[below](#security-cleanup).

<a id="security-cleanup"></a>

<details>
<summary>Security details: what stays after cleanup, and how to remove each</summary>

What cleanup does itself, and when it refuses to delete the state directory:
[SECURITY](SECURITY.md#what-reqcove-cleanup-leaves).

What stays until you remove it:

- **The CA's profile on each device**, and its trust on this computer or in
  a Simulator. cleanup prints how for iPhones, the Simulator and a Mac's
  keychain, and does none of it. A trust added elsewhere (Linux's store, a
  browser's own, Android) it does not know of.
- **The node in the tailnet** (the admin console's Machines), and the exit
  node or Wi-Fi proxy chosen on the phone.
- **Other state directories** (`--state`). Each is cleaned up on its own,
  and cleanup of `~/.reqcove` names only those holding a copy of its CA.
- **A service**, which cleanup does not mention. `reqcove service uninstall`
  stops it and removes its file, not its config file
  (`~/.config/reqcove/config`). `brew services stop reqcove` stops
  Homebrew's, whose config and log (`$(brew --prefix)/var/log/reqcove.log`)
  stay. A service left in place starts `run` at the next login, which makes
  the state directory, and a new CA, again.
- **The skill** (`reqcove init --uninstall` removes it) and the agent's MCP
  server entry.
- **What left Reqcove**: HAR files, the agent's transcripts
  ([SECURITY](SECURITY.md#what-the-agent-sees-goes-further)), backups, and
  uv's cache of mitmproxy and Python.

Checked: tests (the refusals to delete, the proxies put back, the CA copies
it names).

</details>

## Read the traffic with an agent

Run `claude mcp add reqcove -- reqcove mcp` (the README's step 4): it gives an
agent on this computer the [MCP tools](#mcp-tools). For Codex:
`codex mcp add reqcove -- reqcove mcp`. `run` prints both.

What the tools can do:

- **Read.** Secrets are masked as they arrive
  ([what masking does not find](SECURITY.md#masking)).
- **Turn on a preset**: the one change they can make. A
  [preset](#presets-an-agent-can-turn-on) is a rule you marked as one: a mock,
  or a `map_remote`, `modify_headers` or `resolve` rule, which changes what
  requests carry or where they go. It is on for at most 5 minutes each time,
  with no cap on turning it on again. With no preset, the tools only read.
  Over `--mcp-http`, they never turn one on.
- **Put a [marker](#mark-a-moment-reqcove-mark)**, which changes nothing on
  the device.

### Allow the tools

- The tools that read are marked read-only (`readOnlyHint`). A client may use
  that to ask less (not checked with any client).
- Not marked read-only: the tools that turn presets on and off
  (`activate_preset`, `deactivate_preset`), `add_marker` (a write to
  Reqcove's memory only), and `request_capture_add` (it asks you; it records
  nothing until you approve).
- Claude Code asks before a tool it has not been allowed. Allow the read tools
  by name (`"mcp__reqcove__list_flows"` and so on), not `"mcp__reqcove"`:
  that also allows the ones not marked read-only (`activate_preset`, which can
  send requests to a server you wrote in a preset). From Claude Code's
  documentation, not tried here.

For example, in `.claude/settings.json` (the form is from Claude Code's
documentation; not tried here):

```json
{
  "permissions": {
    "allow": ["mcp__reqcove__status", "mcp__reqcove__summarize", "mcp__reqcove__list_flows",
              "mcp__reqcove__search_flows", "mcp__reqcove__wait_for_flows", "mcp__reqcove__get_flow",
              "mcp__reqcove__list_ws_messages", "mcp__reqcove__diff_flows", "mcp__reqcove__list_tls_failures",
              "mcp__reqcove__list_passthrough", "mcp__reqcove__list_devices", "mcp__reqcove__capture_stats",
              "mcp__reqcove__list_presets", "mcp__reqcove__list_rules", "mcp__reqcove__explain_rules",
              "mcp__reqcove__list_markers", "mcp__reqcove__add_marker",
              "mcp__reqcove__request_capture_add", "mcp__reqcove__get_capture_request"],
    "ask": ["mcp__reqcove__activate_preset", "mcp__reqcove__deactivate_preset"]
  }
}
```

A list written before v1.0 may name `mcp__reqcove__list_mock_presets`,
`mcp__reqcove__activate_mock` and `mcp__reqcove__deactivate_mock`. Those tools
are gone: replace them with `mcp__reqcove__list_presets`,
`mcp__reqcove__activate_preset` and `mcp__reqcove__deactivate_preset`.
`activate_preset` turns on the other kinds too, not only mocks: the example
keeps it and `deactivate_preset` under `ask`. The fields renamed with them,
for scripts, and what a call to a removed tool gets:
[COMPATIBILITY](COMPATIBILITY.md#mcp-tools).

What to know:

- Codex asks before each call
  ([over HTTP](#agents-on-other-devices---mcp-http) too).
- Once allowed, an agent reads without asking, also from a `run` started with
  `--no-redact`. The skill and the server's instructions still tell it to stop
  and ask then.
- Allow Reqcove's tools, not shell commands or network tools along with them:
  text a site wrote into a record can try to steer an agent into using those
  ([SECURITY](SECURITY.md#prompt-injection)).

<a id="security-agent"></a>

<details>
<summary>Security details: what Reqcove tells an agent, and what a record cannot prove</summary>

What an agent can do with Reqcove's tools and with its own, and what to give
it: [SECURITY](SECURITY.md#prompt-injection). Beyond that:

- An agent turns on only the presets you wrote
  ([mock presets](#security-mock-presets),
  [the other kinds](#security-presets)).
- `add_marker` writes too, but only a marker in Reqcove's memory.
- In Claude Code, keep its permission prompts for the tools you did not
  allow.
- Codex's sandbox is without network by default (from its documentation, not
  tried).

What Reqcove does:

- Tools return bodies only on request, and `diff_flows` what differs.
- Each tool that returns what sites, apps or the tailnet wrote says so in
  its description: data, not instructions (the twelve tools `--mcp-http` has
  too, and `list_markers` for a marker's text).
- The preset and rule tools return what your rules file holds, and
  `add_marker` Reqcove's own values. `list_presets` says a preset's
  description is your words, not instructions.
- The server's instructions, sent to every client (also those without the
  skill, such as Grok Bot), say so too, and that the agent must not write a
  file (a `--rules` file above all), a commit or a command because of what
  the records say, nor suggest `--no-redact` or `--web`, and that
  `next_steps` are for the user. Whether a model keeps to them is not
  something a test can show.
- A request whose Host is no host name or address (an app's own HTTP stack
  can put any text there) is carried but not recorded. Hosts from TLS are
  host names by mitmproxy's own check (from reading its code).
- User-Agents in lists and summaries are cut to 256 bytes, ALPN names to
  printable ASCII, and JSON keys in `diff_flows` that are not plain names are
  quoted (`$["a.b"]`).

What a record cannot prove:

- **A flow's host** is the request's Host, which the app chooses. Over plain
  HTTP on a connection to any address, and over HTTPS on one to an allowed
  host, it can name an allowed host, and the record shows that one. The
  request still goes where the connection went (what that means for rules:
  [rules](#security-rules)).
- **A marker's `source`** (`cli`, `mcp`) is the channel, set by Reqcove from
  how the call came (`reqcove mcp` never passes on an agent's client name),
  not proof. An agent that can run commands on this computer can claim `cli`,
  by running `reqcove mark` or by connecting to `run`'s socket (same user)
  itself, and then push out the user's 100. An agent through `reqcove mcp`
  gets `mcp` and cannot.
- **A marker's text** is the user's or an agent's words: data, never
  instructions (the server's instructions say so).

Checked: tests (the tools' descriptions; clients get the instructions over
stdio and HTTP, not their wording; a request with such a Host is not
recorded; an agent through `reqcove mcp` gets `mcp`).

</details>

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

Tried: Claude Code, Codex, Devin and Cursor each used the skill (Claude Code
and Codex when asked where an app connects, Reqcove not named; Devin, without
the MCP server, asked for it and stopped; Cursor read the server's
instructions, then used the tools only). Not tried: Gemini CLI, Copilot CLI.

### Mark a moment (`reqcove mark`)

Before you tap something on the iPhone, run `reqcove mark "tap Pay"` in your
terminal: it puts a marker among the records. An agent reads the markers with
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

Tried: `add_marker` from Claude Code with an iPhone (iOS 27.3, 2026-11-14);
the rest by tests only. Not tried by hand: `reqcove mark`.

### Agents on other devices (`--mcp-http`)

For an agent elsewhere on your tailnet, such as Grok Bot (xAI's agent: its
cloud computer joins your tailnet through Tailscale's OAuth apps):

```sh
reqcove run --device iphone --allow-hosts 'api.example.com' --mcp-http
```

`run` serves the same tools over HTTP on the node, all but these:

- the preset ones: `list_presets`, `activate_preset`, `deactivate_preset`;
- the rule ones: `list_rules`, `explain_rules`;
- the marker ones: `add_marker`, `list_markers`.

It prints the URL, `http://reqcove.<tailnet>.ts.net:8090/mcp`, and the header
to give the agent, `Authorization: Bearer <token>`. `reqcove links` prints
them again; off a terminal, only `reqcove links` does.

- **Grok Bot**:
  1. Connect apps › Tailscale, to join your tailnet. Under Tailnet Lock, sign
     its device.
  2. Connect apps › Add a custom connector. Type: Remote HTTPS (an `http://`
     tailnet URL works there; WireGuard encrypts it). Server URL: the URL.
     Header key: `Authorization`. Value: `Bearer <token>`. To copy the value
     unseen: `printf 'Bearer %s' "$(cat ~/.reqcove/mcp-token)" | pbcopy`.
  3. Ask it in a chat. Its settings show the connector with an error and no
     tools: it reaches the tailnet from its chats only.
- **Claude Code** on another computer (the header stays in `~/.claude.json`):
  `claude mcp add --transport http reqcove-remote http://reqcove.<tailnet>.ts.net:8090/mcp --header "Authorization: Bearer <token>"`
- **Codex** on another computer, the token in that variable:
  `codex mcp add reqcove-remote --url http://reqcove.<tailnet>.ts.net:8090/mcp --bearer-token-env-var REQCOVE_TOKEN`.
  Codex asks before each MCP tool call; for `codex exec`, which cannot ask, set
  `default_tools_approval_mode = "approve"` for this server.

What to know:

- Only your own untagged devices on the tailnet can call it, with the token
  ([security details](#security-mcp-http)). A tagged device is
  refused (`run` logs it once): do not tag an agent's device to restrict it.
- What the agent reads goes to its computer and model provider (for Grok Bot,
  xAI's cloud). To cut it off, delete `mcp-token` in the state directory and
  restart `run` (otherwise the token stays the same), or remove its device
  from the tailnet.
- Restarting `run` needs no reconnecting (calls fail meanwhile); the records
  start empty, and an earlier cursor is refused.
- `run`'s log shows each call (`--mcp-http: grokbot-user-1 (100.104.0.1)
  called "list_flows"`): an agent that only says it is checking leaves no
  line.
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

<a id="security-mcp-http"></a>

<details>
<summary>Security details: the token, what the tools leave out, and the rate limit</summary>

Who can call it, and where the answers go:
[SECURITY](SECURITY.md#mcp-over-http---mcp-http). Beyond that:

- **The token is what tells your devices apart**: an agent's device and your
  other computers all count as your own devices. It is compared in constant
  time, and requests from a browser page of another origin are refused.
- **The token is not printed in a log line, by `reqcove status` or by the
  tools**: agents may run those. In a container run with `-t`, `docker logs`
  keeps it.
- **`--mcp-http` has its own server.** It has neither the preset tools,
  `list_rules` and `explain_rules`, nor the marker tools (`add_marker`,
  `list_markers`).
- **`run` logs each tool call over HTTP** with the calling device and the
  tool's name (not its arguments), and each request with no token or a wrong
  one.
- **`capture_stats` and `status` leave out the `resolve` rules and the
  upstream proxy's address**, but not `rules_error`: when a `--rules-reload`
  change fails on a `resolve` line, the error (and `status`'s `next_steps`,
  which quotes it) can name that line's host and address (from reading the
  code).
- **The rate limit** is about 10 calls a second for each device, 30 at once;
  past that a call gets `429 Too Many Requests`. So a runaway agent on one
  device does not keep `run` busy for the others. A call ends when its caller
  disconnects.

Checked: tests (another user's device refused over a real tailnet; the token,
`Host` and origin checks; the tools the server does not have; what
`capture_stats` and `status` leave out; the 429; a call ending when its
caller disconnects). Tried from this Mac over the tailnet, and with Grok Bot.

</details>

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
  ([who else, and the token](#security-ui)).
- The link is the same at each start, so a bookmark should work after a
  restart. To change it, delete `ui-token` in the state directory and start
  again.
- Tailscale must be on; the exit node and the
  [Remote Proxy](#without-the-exit-node-the-wi-fi-proxy) need not be. The
  page's own requests are not recorded.

Tried on an iPhone: opened from the camera, new flows following, search, Clear
and Show all, and reopening the page in Safari after a restart of `run`; new
flows following with `run` on Linux too (Ubuntu 24.04, arm64; 2026-11-15).

<a id="security-ui"></a>

<details>
<summary>Security details: who can read the page, and what its checks do not cover</summary>

In short: [SECURITY](SECURITY.md#the-page---ui). The page shows what the MCP
tools return, masked the same way. Who can read it:

- **Your own devices and the `--device` devices**; others get nothing.
- **A `--device` device of another user sees only its own flows**, in the
  list and by ID, and its own counts and next steps: not the other devices',
  nor their names. Your own devices see every device's flows, with the
  device's name.
- **Only a browser holding the token.** The link `run` prints sets it as an
  HttpOnly, SameSite=Strict cookie kept 400 days. Another app on the same
  iPhone can reach the port, but not read the page without the token. A link
  that leaks works only from the devices above.
- **The token is the same at each start**, so a link, a bookmark or a cookie
  keeps working until you delete `ui-token` and start again; then they get
  403.
- **Only by the node's name in `Host`**: a site the iPhone visits cannot
  point its own name at the node and read the page as its own (DNS
  rebinding).
- **GET and HEAD only**, also when the request comes through the Remote
  Proxy. The search form goes to the page itself (CSP `form-action 'self'`),
  and Clear only hides flows from the list (a `since` in its URL), deleting
  nothing.
- **Its only script is its own `/app.js`**: the Content-Security-Policy
  allows no other, and nothing inline. It asks `/flows.json` for the list
  once a second and puts it in with DOM calls and `textContent` only, so what
  sites wrote into headers and bodies stays text. It is not cached
  (`no-store`).

What those checks do not cover:

- Pages still go through Safari. Its history may keep the URLs of the flow
  pages viewed, the first link with the token (useless without the device;
  it lasts until `ui-token` is deleted), and the URLs of searches, with what
  was searched. With `--no-redact`, a search for a secret's value keeps it
  there.
- A JSON body nested deeper than 32 levels is shown as it is, not indented:
  indenting deep nesting takes memory that grows with the square of the
  depth.

The token appears only on `run`'s terminal and through `reqcove links`, as the
login URL does: never in a log line or the MCP tools.

Checked: tests (one for each point of who can read it; `/app.js` run over a
stand-in DOM in node).

</details>

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
  ([SECURITY](SECURITY.md#what-is-recorded)). On a computer others use,
  `(umask 077; reqcove har > flows.har)` makes it yours only; keep it out of
  `/tmp` otherwise, and out of the repository.

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

- Nothing is masked, and anyone with its password can edit and replay
  requests and change its options (scripts included), which runs code on
  this computer ([security details](#security-web)).
- It shows bodies up to 2 MB each, and keeps the newest 10,000 flows and
  256 MB of bodies ([what those bounds count](#security-web)).
- The link is the same at each start (`web-token` in the state directory).
  After a restart, open it again: a bookmark without the token asks for it.
- In its Capture tab, leave "Run SOCKS Proxy" on, or the devices' HTTP(S)
  stops. The other modes there are not Reqcove's. Changes last until reqcove
  starts again.

Tried: from an iPhone on the exit node, with `run` on macOS and on Linux
(Ubuntu 24.04, arm64; 2026-11-15). From reading code, not tried: with
options changed there, Reqcove's records stay scoped and masked.

<a id="security-web"></a>

<details>
<summary>Security details: who reaches mitmweb, its password, and what its options change</summary>

What it shows, and to whom: [SECURITY](SECURITY.md#mitmweb---web). Beyond
that:

- It listens on 127.0.0.1. Its password is kept in `web-token` (the same at
  each start until you delete that file and start again) and passed through a
  0600 file, never the command line.
- The node relays its port 8081 to mitmweb for your own devices only: not a
  `--device` device of another user, nor anyone else. The password still
  guards it, and it gives what it gives on this computer.
- A phone on the Remote Proxy reaches it the same way: its requests and
  WebSocket tunnels to the node's port 8081 go to mitmweb, for your own
  devices only. A WebSocket already open stays open if the device stops
  counting as yours.
- On a terminal `run` prints the links with the tokens: they stay in its
  scrollback, valid until the token files are deleted. Off one it prints
  none. `reqcove links` prints them again, from `links`.
- A link with the password (`?token=`) opened by a browser through the node
  is answered, once mitmweb accepts it, with a redirect to the same URL
  without it, so the password does not stay in the address bar. Whether
  Safari's history keeps the first URL is not checked.
- mitmweb's cookie does not outlast its restart: it signs it with a key made
  at each start (from reading its code). After one the link is needed again.
- It shows every flow mitmproxy decrypted, including requests to hosts
  outside `--allow-hosts` that rode on an allowed connection (HTTP/2
  connection reuse): the per-request check keeps those out of Reqcove's
  records only.
- It shows bodies up to 2 MB each, whole and unmasked (Reqcove gives it them,
  as mitmproxy keeps no body it streams), and keeps the newest 10,000 flows
  and 256 MB of bodies. Those bounds count finished flows: one still in
  progress (a download or an event stream still coming, a request waiting
  for its answer) counts once it ends, and what is kept of its bodies
  meanwhile (up to 2 MB each way) is outside them (from reading the code; not
  measured).

What its options change (from reading the code, not tried):

- mitmproxy's behaviour only, until Reqcove starts it again. Reqcove's
  records stay scoped to `--allow-hosts` and masked, since Reqcove checks
  both again as they arrive.
- Turning off the SOCKS proxy in its Capture tab stops the devices' HTTP(S):
  that is how Reqcove hands them to mitmproxy.
- Another mode turned on there listens on 127.0.0.1 (the listen host Reqcove
  sets) and bypasses Reqcove's device names and its refusals of this computer
  and the LAN.

Checked: a test with a stand-in for mitmweb (the redirect). Tried from an
iPhone on the exit node.

</details>

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

Tried: on an iPhone; a test for a pass host's decrypted requests going
through `--upstream-proxy`. That they skip `--rules` is from reading the code.

### Connections not read as HTTP (raw TCP)

mitmproxy picks how to read a connection to an allowed host (once
decrypted, for TLS). One it does not take for HTTP it carries as raw TCP: the
app works, but what the connection carries is not recorded as flows. That
happens for:

- an ALPN name mitmproxy does not know, when the server speaks first or the
  client's bytes do not look like HTTP (otherwise it reads the connection as
  HTTP/1, which fails for a client speaking another protocol);
- bytes that do not look like HTTP;
- what a request upgrades to with a `101` other than a WebSocket (the request
  itself is a flow).

Reqcove records the connection instead:

- `list_passthrough` lists it with `reason: raw_tcp`: host, server, times, the
  protocols the client offered and the one it got, and bytes each way (inside
  TLS, for TLS), never the bytes themselves. At most 1000 such connections
  are kept, apart from the `--pass-hosts` ones.
- `capture_stats` counts it (`raw_tcp`, and `raw_tcp_hosts` by device and
  host, the busiest 30), and `list_devices` counts it per device (`raw_tcp`).
- `reqcove status` names its hosts in the next steps.
- `list_flows`, `search_flows`, `summarize` and `wait_for_flows` with a host
  filter naming such a host say so in `note`.

Not caught at all, with nothing recorded or counted: connections mitmproxy
passes through itself (Apple's hosts, hosts outside `--allow-hosts`, a
connection it knows by its address only), an allowed host's HTTP/2 requests
riding a connection the app opened for a sibling name outside the list, and
TLS with Encrypted Client Hello. Each case, and what to allow:
[connections that leave no record](masking.md#connections-that-leave-no-record)
(in short: [SECURITY](SECURITY.md#not-caught)).

Tried: E2E tests (an unknown ALPN from a server that speaks first; plain
HTTP upgraded with a `101`) and unit tests (the `note`, the 1000 kept). By
hand with mitmproxy, 2026-11-15: an unknown ALPN with HTTP/1 bytes, and with
other bytes to a server that waits; a `101` over TLS. Not tried on an iPhone.

### gRPC

A gRPC call is a flow. Its path names the method (`/pkg.Service/Method`).

- **Status**: rows and `summarize` show `grpc_status` (`0` is OK, `16`
  UNAUTHENTICATED, …; `pending` until its trailers come). It is read from the
  response headers when there is no message (a trailers-only answer, the
  usual error), else from the trailers: HTTP/2's, or gRPC-Web's last frame
  when the kept head holds it (a body over 64 KiB loses it).
- **`grpc_message`** is decoded and masked (with `--no-redact`, as sent).
- **Trailers** are searched, compared by `diff_flows` and written to a HAR's
  comment.
- **Messages**: a body's note counts its messages and their sizes. JSON ones
  (`application/grpc+json`, `connect+json`) are handed out one a line, masked
  as JSON; protobuf ones as below.
- **A Connect stream**: its last frame (its error, its trailers: JSON) is
  handed out as `[end of stream]`, masked as JSON. The stream's outcome is in
  that frame, not in `grpc_status`.
- **Metadata** ending in `-bin` (binary) shows its size only.

Protobuf bodies (gRPC's messages, and `application/x-protobuf` and the like)
are not text, so reqcove hands out its own rendering of them, marked by the
body's `view`. Without a schema it is the structure only:

- field numbers, types and lengths;
- `string(12)` for a string, never its text;
- numbers in responses. In requests, only numbers under 128 (such as enums
  and booleans): a PIN under 128 shows too. A larger one, such as a code sent
  as a number, shows its byte count.

For example:

```
1: 150
2: string(12)
3 {
  1: string(3)
}
```

Give `--proto FILE` your compiled schema
(`protoc --descriptor_set_out=FILE --include_imports`). A message whose type
is known is then shown as JSON with its field names, and masked by name, as
JSON is.

- The type comes from the method its path names (gRPC, gRPC-Web, Connect,
  Twirp: `/pkg.Service/Method`; the input in a request, the output in a
  response), or from `messageType` in the content type.
- `bytes` fields show their length; fields the schema does not have, their
  structure.

With `--no-redact`, protobuf bodies are kept as they came.

Apps built on gRPC-core (Google's SDKs among them) trust their own list of
CAs, not the ones the iPhone trusts, so their calls show as TLS failures (from
gRPC's mailing list, not tried). So do apps whose gRPC library is told whose
certificates to trust, unless a debug build trusts Reqcove's CA (not tried).

grpc-swift (2, both transports; 1 too, from its sources) offers ALPN
`grpc-exp` before `h2`, and some servers pick it (Connect's demo server
does). Reqcove offers the server `h2` without `grpc-exp`, so such a call goes
over HTTP/2 and is recorded. A server that takes only `grpc-exp`, not `h2`,
would fail such a call through Reqcove, as it is offered no `grpc-exp` when
the client offers `h2` too (from reading the code; no such server was found).

Tried on an iPhone (iOS 27.3): a test app over URLSession calling Connect's
demo server by Connect, gRPC-Web and gRPC, with `--proto`; grpc-swift 2, both
transports. By tests only: the reading without a schema, a Connect stream's
last frame, a body over 64 KiB with its status in the trailers, a
trailers-only error, and gRPC's answer by its names (it showed nothing in the
iPhone trial; fixed after it, not tried again on the iPhone).

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

- It has no password: any process on this computer, of any user, can use it.
  Keep it on only while you need it
  ([security details](#security-local-proxy)).
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
  it ([security details](#security-local-proxy)).
- Automatic proxy configuration (PAC) and authenticated proxies are left as
  they are.

To record this computer's own browsers too (as `local`, mixed with the
Simulator's) rather than have them warn, trust Reqcove's CA here once: `run`
prints the command, and `reqcove status` and `reqcove cleanup` how to stop.
The CA's key can then impersonate any HTTPS site to this computer too
([security details](#security-local-proxy)).

- macOS (TLS only; it asks for your password):
  `security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`.
  Firefox may keep its own store. To stop, run the command `reqcove status`
  prints, or delete the CA in Keychain Access (its trust goes with it).
- Debian and Ubuntu: `sudo cp ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/reqcove.crt && sudo update-ca-certificates`.
  Fedora: into `/etc/pki/ca-trust/source/anchors/` and `sudo update-ca-trust`.
- Chrome and Chromium on Linux: `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n Reqcove -i ~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`.
  Node: `NODE_EXTRA_CA_CERTS=` that file. Python: the system's bundle once
  updated, not that file alone (it would replace every other CA).

Tried on macOS 27: the system's web proxies set and put back at Ctrl-C; the
CA added to the booted Simulators, and Safari on the iOS 27 Simulator
recorded as `local`; the CA trusted here and the trust removed, with Chrome
on the Mac recorded without a warning; RoamRun 0.12.0 (with its PR #253)
alongside. Not tried: whether apps skip the proxy for the address forms in
the exceptions, PAC and authenticated proxies, Linux.

<a id="security-local-proxy"></a>

<details>
<summary>Security details: what the local proxy lets through, the system proxy settings, and the CA on this computer</summary>

Who can use it, and what a page in a browser here can reach through it:
[SECURITY](SECURITY.md#the-local-proxy---local-proxy). Beyond that:

- Its apps reach the LAN, VPNs and the tailnet as they would without it, by
  this computer's own lookups. This computer, the LAN and the tailnet are in
  the system proxy's exceptions, so apps reach them directly, as without
  Reqcove.
- It refuses IPv6, and a name that leads to this computer itself (loopback,
  its own addresses) or to a link-local address unless this computer's
  `/etc/hosts` gives it. A page in a browser here could otherwise reach this
  computer's services through it by pointing its own name there (DNS
  rebinding).
- A page could still point its name at a LAN, VPN or tailnet address, and
  the proxy lets it on (so that names inside a VPN keep working). A browser
  going direct faces the same, but through the proxy it does not see the
  address, so its own protection for private networks (Chrome's Private
  Network Access) does not apply: keep `--local-proxy` on only while you need
  it.
- Apple's hosts are not decrypted.
- On macOS, `run` points the system's web proxies at it while it runs,
  keeping what they were in the state directory (0600) to put back when it
  stops (also on SIGHUP), at the next start, or with `reqcove cleanup`. It
  never saves over settings not put back yet, and cleanup will not delete the
  state while it holds them. If Reqcove is killed outright, apps here that
  use the system proxy cannot connect until they are put back.
- Reqcove never makes this computer trust its CA; `run` prints the command
  (TLS only, for this user). Once trusted, the CA's private key in
  `<state>/mitmproxy/` can impersonate any HTTPS site to this computer too,
  not only to the devices. Keep the state directory, and its copies and
  backups, private, and remove the trust when done (`reqcove status` and
  `cleanup` print how, by its fingerprint).

Checked: a test (names that lead to this computer or to a link-local address
are refused). Tried with the real `networksetup` (set, and put back at
Ctrl-C) and an iOS 27 Simulator.

</details>

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

### Another Mac

A Mac named with `--device` that chooses the exit node in the Tailscale app is
recorded as an iPhone is ([the steps](another-mac.md)). With Homebrew's
open-source `tailscaled` the exit node shows as on, but that Mac's traffic does
not go through it.

Tried with a macOS 27 VM. Not tried: that Mac's iOS Simulator (it should go
through with the Mac's own traffic, once it trusts Reqcove's CA).

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
- To send a request to another server, use `map_remote` (or `resolve`), not
  a `modify_headers` rule that sets `Host`: such a rule is not applied on its
  own (next point). A `map_remote` that changes only the path, the host
  staying the same, sends the request on too: mitmproxy connects to that host
  by its name, looked up on this computer, not to the address the app
  dialled, and the header rules apply.
- `modify_headers` applies only to a request that goes to its `Host`, and to
  its response: one sent to the Host's address, or over HTTPS to its TLS
  name, or that `map_remote` or `resolve` sends on. A rule that changes
  `Host` applies only with one of those two; on its own, none of the
  request's header rules do. The record's `rewrites` say when they were not
  applied ([security details](#security-rules)).
- `map_local` answers only requests whose body is at most 1 MiB and of known
  length; others go on to the real destination (the record says so).
- An HTTP/2 GET (HEAD, OPTIONS, DELETE) without a length is answered by
  `map_local` when its stream ends with no body: with its headers, as GETs
  with no body do, or with an empty DATA frame (Go's client sends one for a
  body of unknown length that turns out empty). One that sends a body anyway
  gets a 502, recorded as an error, and its body is not held. With a
  mitmproxy other than 12.3.1 (another `--mitmproxy-spec`), a stream not
  ended with its headers gets the 502, empty DATA frame or not (from reading
  the code).
- Read someone else's rules file before using it: rules can send your apps'
  requests, cookies and tokens included, wherever they say.

Tried with the E2E tests: each kind of rule above (`map_remote` also for a
POST not yet ended and for SSE, which reach the other end as they stream), a
request outside `--allow-hosts` left alone, the rules' values kept out of the
records, the refusals at load, and an HTTP/2 GET without a length from Go's
client. The limits of that:

- A path-only `map_remote` was tried in mitmproxy's Python on made requests,
  not over the network.
- macOS's URLSession was tried against a test server, without mitmproxy: it
  ends a GET's and a HEAD's stream with their headers and gives DELETE and
  OPTIONS a length of 0, so none is refused.
- iPhone apps' HTTP/2 requests without a length were not tried.
- How mitmproxy tells a stream's end is from reading its code.

#### Connect elsewhere (`resolve`)

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
  100.100.100.100 ([security details](#security-rules)), and `resolve`
  together with `--upstream-proxy`.

Tried with the E2E tests: plain HTTP sent to the rule's
address with the app's `Host`, the record saying where it went; `resolve` after
a `map_remote`; over TLS, the target asked for the name (SNI) and a 502 for a
certificate not trusted; the refusals at load (cloud metadata,
100.100.100.100, a name as the target, shared addresses, a host outside
`--allow-hosts`, with `--upstream-proxy`). Tried: a server with a trusted
certificate for another name gets a 502 ([security details](#security-rules)).
A `resolve` preset was not tried on an iPhone
([below](#map_remote-modify_headers-and-resolve-presets)).

#### Answer a request here (`mock`)

`mock` answers a request here, with what you write: use it to see how the app
takes an expired session or an empty list. The request is not sent to the
server (for HTTPS, mitmproxy may have connected to it already, to read its
certificate).

```yaml
mock:                           # Reqcove's own; the first that matches answers, before map_remote and map_local
  - match: {method: POST, url: "https://api.example.com/v1/login"}
    status: 401
    headers: {Content-Type: application/json}
    body: '{"error":"expired"}'
  - match: {url: "https://api.example.com/graphql", operation: Feed}
    body_file: feed.json        # relative to the rules file
```

- **`url`** matches the URL the app sent, without its query, exactly (the host
  in any case). Ending in `*` after a path (`https://api.example.com/v1/*`),
  it matches any URL that starts with the rest. It takes no query, fragment,
  user or default port (refused: it would never match). The host must be in
  `--allow-hosts` and not in `--pass-hosts`.
- **`method`** and **`operation`** are optional. `operation` is a GraphQL
  operation: `operationName`, Apollo's `X-APOLLO-OPERATION-NAME` header, or
  the document's first named operation.
- **The answer**: `status` is 100 to 599 (200 if left out). A body is at most
  1 MiB, inline or in a file, and none goes with `HEAD`, 204 or 304.
  `Cache-Control: no-store` is added unless you set one.
- **With `modify_headers`**: request rules apply before the match, response
  ones still apply.
- **What is held**: a request a mock may answer (its method and URL match) is
  held whole until its body is in. One whose length is over 1 MiB, or a POST
  of unknown length, goes on unanswered, its `rewrites` saying
  `mock: skipped, …`. As with `map_local`, a GET (HEAD, OPTIONS, DELETE)
  without a length is held too; over HTTP/2, one that sends a body anyway
  gets a 502 instead of being held (an empty DATA frame is no body).
- **The record** says so: `mocked: true` on its row, `rewrites` with the
  rule's number and status (`mock[0]: 401`), a note in a HAR. `capture_stats`
  has `rules_loaded`, when the file was last taken.

Tried with the E2E tests: a 401 with headers for a POST, a
GraphQL operation from the body, a prefix, HEAD, the server never reached, and
rules refused (a bad status, a line break in a header, a missing file, a host
outside `--allow-hosts`). On an iPhone: a 401 for Safari (httpbin.org), and one
GraphQL operation of the GitHub app mocked while its others, on the same
connection, reached GitHub.

#### When the file is read (`--rules-reload`)

The file is read when `run` starts, and again by `reqcove reload` (since v1.1,
with the hosts: [edit, then reload](#edit-the-files-then-reqcove-reload)). When reqcove restarts mitmproxy, it gives
it the rules that loaded last (a private copy, `rules-loaded` in the state
directory), not the file as it is on disk then: a file broken meanwhile never
leaves mitmproxy without its rules. Files the rules name (`map_local`, `@file`
values, mock bodies) are still read from disk, relative to the rules file; if
the rules that loaded last no longer load (such a file is gone), `run` stops
with the reason rather than go on without them.

With `--rules-reload`, it is read again once a change has settled. The new
rules are for requests that start after that; one under way keeps the rules it
started with.

- A file that does not load leaves the earlier rules in place, and `run` and
  `reqcove status` say why, after a restart of mitmproxy too (the restarted
  one looks at the file again and says why it does not load).
- Whatever can write the file (an agent included) can then change where the
  devices' requests go, without you restarting anything.

Checked: an E2E test (real mitmproxy, macOS): with the file broken on disk
and mitmdump killed, the next one applied the rules that loaded last (a
reload's, with `--rules-reload`), a value file named relative to the rules
file included. From reading code: a change is read within about two seconds.

#### Add a mock from your terminal (`reqcove mock add`)

`reqcove mock add` writes a mock into the file for you, checked first:

```sh
reqcove mock add --rules rules.yaml --url https://api.example.com/v1/login \
  --method POST --status 401 --header 'Content-Type: application/json' \
  --body '{"error":"expired"}'
```

- **The other flags**: `--operation NAME`, `--body-file PATH` (from where you
  type it; written as a full path), `--delay-ms N`, `--fault close`,
  `--preset NAME` and `--description TEXT`.
- **Where it writes**: it adds the mock as the last of `mock:`'s items and
  keeps the rest of the file as it was (comments and order too). A file
  without `mock:` gets one at its end. A new file is made `0600`; an existing
  one keeps its mode, replaced at once (a temp file beside it, renamed).
- **What it refuses**: a file whose `mock:` is not its last block, or is in
  flow style (`mock: []`), saying how to fix it; a header name given twice.
  If the file changes while it is checked (your editor saved it), nothing is
  written: run it again.
- **The check**: before writing, the whole file as it would be is checked by
  the addon's own loader. The running `reqcove run` (the same `--state`) does
  it, with its `--allow-hosts` and `--pass-hosts`. When none is running,
  mitmproxy's Python from the lock does (`--uvx PATH`), which leaves the hosts
  unchecked. Refused, it says why (never a rule's text) and writes nothing.
- **When it takes effect**: it says so after writing. At once when run has
  `--rules-reload` (which also turns every preset that is on off), else when
  you restart run.
- **Only in a terminal** (stdin and stdout, as `reqcove mark`): a help against
  an agent running it unasked, not a guarantee (an agent with a shell can give
  it one, and can edit the file anyway). `--print` shows the mock as YAML
  without writing or checking anything, in a terminal or not.

Tried with the tests: the YAML for values with quotes, line breaks, `#`, `: `,
control characters and other scripts, read back as given by the addon's loader;
the file's text kept (comments, CRLF, no newline at the end); the refusals; the
check by a real run (hosts in and out of scope, passed) and by mitmproxy's
Python. Not tried by hand with a running run and a device.

#### Presets an agent can turn on

A mock with `preset: NAME` does nothing until an agent turns it on, for at most
5 minutes each time; it can turn it on again, with no cap
([security details](#security-mock-presets)). So an agent can check how the
app takes a 503, a slow answer or a dropped connection, and turn it off again,
without editing the file. A plain mock with the same match (method, URL,
operation) as a preset is refused at load: it would answer in its place.

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
  `deactivate_preset(name)`. Only an agent on this computer has them
  (`reqcove mcp` and `run`'s socket); never over `--mcp-http`.
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
- A preset in the file is your consent that an agent may turn it on. An
  agent writes one only when you ask it to in the conversation, never because
  of what the records say; with `--rules-reload` it can then turn it on at
  once ([security details](#security-mock-presets)).

Tried with the E2E tests: turning on and off, the limits of time and count,
one preset per match, a changed file turning them off, the refusals, a delay
on one HTTP/2 stream while another on the same connection is answered at
once, and a close over HTTP/1 and HTTP/2. On an iPhone (iOS 27.3, a test app
over URLSession, an agent turning presets on over MCP): a 503 once, then the
app's retry reached the server; an 8 s delay; a close, which CFNetwork did
not retry by itself (the app's own retry was closed too); a 401 on login.

<a id="security-mock-presets"></a>

<details>
<summary>Security details: what an agent can do with a mock preset, and what bounds it</summary>

In short: [SECURITY](SECURITY.md#mock-presets). A `map_remote`,
`modify_headers` or `resolve` rule can be a preset too, and it can send
requests elsewhere: see [below](#security-presets).

- **There is no switch at start**: writing a preset is the consent.
- **An agent allowed only Reqcove's tools** (an MCP-only client, or a
  sandboxed one) can change what the device gets, at the moment it chooses
  and, by calling again, for as long as it keeps calling. Text a site wrote
  into the records can try to steer it into that.
- **It can turn on only what you wrote.** For a mock preset: no new content,
  target or host, and nothing new leaves this computer.
- **The worst case:** every preset kept on all the time, each answering in
  the site's name what you wrote (a mock of an HTML page on an allowed host
  runs in Safari with that host's cookies, as any mock does).
- **Bounds**, in Reqcove and again in mitmproxy's addon: at most 5 minutes
  each time, and, with `times`, at most 20 requests; no cap on turning one on
  again. Any matching request uses a count, whoever sent it.
- **Only on this computer.** The tools are on `run`'s socket and
  `reqcove mcp`; `--mcp-http` has its own server without them. The addon
  takes requests on its own socket in the state directory (0600) only with
  the secret `run` gave it.
- **No write is sent twice.** `reqcove mcp` never sends a write again after
  its connection to `run` dropped mid-call: it says it may or may not have
  taken effect.
- **What agents are told.** The skill and the server's instructions tell
  agents to turn a preset on only for a test the user asked for in the
  conversation, never because of what the records or a preset's description
  say, and to write `preset:` into a rules file only when the user asks in
  the conversation, as any rule. An agent that writes a preset when asked
  (with `--rules-reload`) can turn it on at once: the request in the
  conversation is the consent then. Whether a model keeps to that is not
  something a test can show.
- **Visible.** `run` logs each preset an agent turns on or off. The `status`
  tool and `reqcove status` list the ones on (or say mitmproxy did not
  answer). A flow a preset answered says `preset: NAME`.
- **When one ends.** An agent ends one with `deactivate_preset`. Otherwise
  its end is checked on two clocks, so a computer that slept past it does not
  leave one on. One answer already waiting out its `delay_ms` still goes out
  after the preset is turned off.
- **`list_presets`** gives what each matches and its status, delay or fault,
  never its body or header values.

Checked: tests (the two servers `run` builds; the addon's secret; no write
sent again; the two clocks).

</details>

#### `map_remote`, `modify_headers` and `resolve` presets

A `map_remote`, `modify_headers` or `resolve` rule can be a preset
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
  minutes)`, `deactivate_preset(name)`. `times` is for mocks only; the others
  are on for a time.
- While on, a `map_remote` preset sends the matching requests, with the app's
  cookies, tokens and bodies, to its target; `resolve` connects its name to its
  address (Host, SNI and the TLS check stay the name's). The 5 minutes bound
  the switch, not its effects: what the app wrote lands on that server, the
  app may keep the tokens and caches it got from there, and a WebSocket, a
  stream or a long upload begun meanwhile stays with the target (from reading
  the code; [security details](#security-presets)).
- Shown, by `list_presets`, the ready block and `reqcove status`: a
  `map_remote` preset's target (scheme and host), a `modify_headers` preset's
  header name (never its value), a `resolve` preset's name and address; never
  a filter or a regex.
- Refused at load:
  - a `map_remote` preset whose replacement does not start with `http://` or
    `https://`, a host and `/` (its target could not be shown), has a user or
    password, takes its host from the request (`\1`), goes to a link-local
    address, or is plain `http://` to anything but this computer or a LAN
    address (`localhost`, `*.local`, a private address);
  - a `modify_headers` preset on responses (`~s`);
  - a preset in `map_local`;
  - a plain rule with the same match as a preset (`map_remote`: the same
    filter and regex; `modify_headers`: the same filter and header).
- Not sent, and answered with a 502 instead: a request whose rewritten URL
  would be outside the target shown (a regex that matched inside the URL).
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
  `capture_stats`' `presets` names every preset.

Tried with the E2E tests, over plain HTTP: each kind changes requests only
while on, and a changed file turns them off; the refusals at load, in
mitmproxy's Python. On an iPhone in LAN mode (iOS 27.3, 2026-11-14): a
`map_remote` preset to a dev server on this Mac and a mock preset with
`times: 1`, turned on over MCP. Not tried:

- a `resolve` or a `modify_headers` preset on an iPhone;
- HTTPS through a `map_remote` or `resolve` preset turned on while the app's
  connections are open (pooled HTTP/1, HTTP/2): the app may keep using a
  connection opened before.

<a id="security-presets"></a>

<details>
<summary>Security details: what these presets can send elsewhere, and what stays after one turns off</summary>

In short: [SECURITY](SECURITY.md#map_remote-modify_headers-and-resolve-presets).
These presets change where requests go or what they carry, not only what the
app gets.

- **Every device recorded is switched**, in LAN mode every address you
  allowed: a `map_remote` preset sends the matching requests of all of them
  to its target, with everything in them.
- **The worst case**, through text a site wrote into the records: your
  production credentials sent to the staging or dev server in the preset,
  again and again. An agent chooses only when, and for how long by turning it
  on again; never the target.
- **What stays after a preset turns off.** What the app wrote while it was
  on (orders, edits) is on that server. The app may keep the tokens, cookies
  and caches it got there, and send them to the usual server once the preset
  is off.
- **`resolve` is the safer kind.** It connects a name elsewhere but keeps
  Host, SNI and the TLS check the name's (from reading the code): over HTTPS
  the other server needs a certificate for that name.
- **`modify_headers` presets change requests only.** One on responses (`~s`)
  is refused at load, as it could drop a page's protections (CSP, HSTS) or
  set cookies on a host Safari shows. Its value is never shown. One that is
  on applies after the plain rules, so its header is the one sent.
- **Refused at load**, so that the target can be shown and checked: the
  `map_remote` presets listed
  [above](#map_remote-modify_headers-and-resolve-presets), such as one that
  takes its host from the request, or goes by plain `http://` to anything but
  this computer or a LAN address (`localhost`, `*.local`, a private address).
- **Checked on each request**: the rewritten URL's scheme, host and port,
  against the target shown. A regex that matched inside the URL gets a 502,
  never a request elsewhere.
- **Shown**: each preset's target (`map_remote`) or address (`resolve`) in
  `run`'s ready block and log and in `list_presets`, the ones on in
  `reqcove status`; never a filter, a regex or a header's value. A flow a
  preset changed lists it in `presets`; the skill and the server's
  instructions tell agents never to report such a flow's answer as the usual
  server's.
- **`activate_preset` takes every kind.** It is not marked read-only, and is
  asked about by clients that ask before such tools; a client that allowed
  `"mcp__reqcove"` wholesale allows it too. Allowing it without a prompt
  allows these kinds too (the guide's [example](#allow-the-tools)
  keeps it under `ask`).
- **The same bounds and visibility as mock presets**: at most 5 minutes each
  time (no `times` for these kinds), only on this computer, never over
  `--mcp-http`, off after a reload or a restart, both clocks.
- **Not tried:** what an app does with connections it opened before a preset
  turned on or off (pooled HTTP/1, HTTP/2). It may keep using them, so a
  switch may not take effect at once, or may last past the end.
- **From reading the code:** rules apply when a request starts, so a
  WebSocket, a stream or a long upload begun while a `map_remote` or
  `resolve` preset was on stays with its target after the preset is off, past
  the 5 minutes.

Checked: tests (the 502 for a URL rewritten outside the target shown; a
preset's header applied after the plain rules); an E2E test over plain HTTP
(what `resolve` keeps).

</details>

#### Why a rule did or did not apply (`list_rules`, `explain_rules`)

An agent on this computer can read the rules without the file.

`list_rules` gives each rule by kind and number (`mock[0]`, as `rewrites`
names them), its preset and whether it is on, and only what is derived from
the rule:

| Kind | What `list_rules` gives |
|---|---|
| `mock` | its match and answer |
| `map_remote` | its target's scheme and host (`path only` when the replacement is a path, `not shown` when it does not write the host out) |
| `modify_headers` | its header name and direction (`request` for `~q`, `response` for `~s`, else `both`) |
| `resolve` | its name and address |
| `map_local` | the rule's number only |

Never a filter, a regex, a header value, a body or a file's path.

`explain_rules` says why a request got, or would get, which rules. Give it a
flow's id, or a method and URL (and a GraphQL operation).

1. It answers the scope first: a host not in `--allow-hosts`, or in
   `--pass-hosts`, gets no rule.
2. Then it runs the request path's own code on a request it makes up and
   never sends. It returns `rewrites` as the record would say them, `mocked`,
   `mapped_to`, the presets on now that apply, and `if_turned_on`: what each
   preset that is off would do.

What to know:

- A filter that reads headers, a body or the response (`~h`, `~b`, `~t`,
  `~c`…) cannot be told from a method and URL: that rule is counted as not
  matching, and listed in `cannot_tell`.
- With a flow's id, `recorded` is what the flow got. The rules, or a preset's
  state, may have changed since.
- It uses no preset's count, and turns none on or off.
- A recorded URL is masked: a value masked in its path or query
  (`[redacted]`) can change what a filter or regex sees.
- A GraphQL operation in the URL comes before the one given, as for a real
  request.

Tried with the E2E tests (plain HTTP): no filter, regex,
header value, body or path in `list_rules` (marker strings); an out-of-scope
host, a `--pass-hosts` host, a mock preset off and then on (its count unused,
the server never reached), a GraphQL mock with and without the operation, a
`~h` filter in `cannot_tell`, a `map_remote` then `resolve` explained as the
recorded flow got them; without a rules file. Both tools from Claude Code
with an iPhone too (iOS 27.3, 2026-11-14).

<a id="security-rules"></a>

<details>
<summary>Security details: who can change the rules, which host a header rule reaches, and where rules connect</summary>

In short: [SECURITY](SECURITY.md#rules---rules). Over `--mcp-http` an agent
has no way to the file at all.

- **`run --rules-reload` reads the file again whenever it changes.**
  Whatever can write it (any process as your user, an agent with file access
  included) can then change where the devices' requests go while `run` runs.
  Without it, the file is read only when `run` starts.
- **A mitmproxy that Reqcove restarts after it exits gets the rules that
  loaded last**, from a copy in the state directory (`rules-loaded`, 0600 in
  the 0700 directory; it holds whatever the file holds, tokens in
  `modify_headers` included). `run` removes it when it stops; a run that is
  killed leaves it until the next start, which replaces it (unit test) or,
  without `--rules`, removes it (from reading code). If those rules no longer
  load, `run` stops rather than go on without them: a mock or `map_remote`
  lost would send test requests to the real servers.
- **`reqcove mock add` writes a mock into a rules file for you**, and runs
  only when its input and output are a terminal: a help against an agent
  running it unasked, not a guarantee (an agent that can run commands can
  give it a terminal, or edit the file itself). Writing rules stays yours:
  the skill tells agents never to run it. To have `run` check the file first,
  it reads `run`'s SOCKS5 password from the state directory (0600, your
  user); `run` checks the file it is pointed at without taking it.
- **A request a rule fails on** (say, a `map_remote` making a bad port) is
  answered with a 502 rather than sent on as it was. A `map_remote` whose
  replacement cannot work at all stops `run` at start.
- **`modify_headers`** takes header names that are HTTP tokens, and values
  without a line break or NUL (they would start a header of their own on the
  wire). A value file read again for a later flow and given one since is
  dropped from that flow's headers.
- **`resolve` names** are host names only, so nothing in them reaches the
  log as control characters.

**A header rule reaches only the host the request names.** A request's Host
is the app's to write, and mitmproxy connects where the app dialled whatever
it says, while rules (`~d`) read the Host. So a header a rule sets
(`modify_headers`, presets too) goes only to the host the request names, and
one set on a response only to that host's response. When no `map_remote` or
`resolve` sends the request on, the rules apply only if one of these holds:

- the address dialled is the Host as the app sent it (read before any rule);
- over HTTPS, that Host is the TLS name mitmproxy checks the server's
  certificate for, and a server without a certificate for the name gets no
  request (not through `--upstream-proxy`: mitmproxy then checks the proxy's
  certificate, and the server's is the proxy's to check);
- the Host's addresses, as this computer looks them up, include the address
  dialled.

Otherwise the request goes on as the app sent it, and its response as the
server sent it, their rewrites saying the rules were not applied
(`explain_rules` names the condition). The edges:

- The rules do not apply to such a request when a rule changes its Host
  either: a rule's own Host would vouch for itself (a token rule for the
  Host, then one setting Host to the address dialled). Where a request goes
  is for `map_remote` and `resolve` to change.
- A `map_remote` rule that changes only the path, the host staying the same,
  sends the request on as any other does: mitmproxy then connects to that
  host by its name, looked up on this computer, not to the address the app
  dialled, and the header rules apply.
- Names are compared in IDNA's ASCII form (HTTP/2's `:authority` comes
  decoded, SNI does not). A Host with İ, ı, ſ or K (as such or in `xn--`
  form) gets no rules, as `~d`, case-insensitive, matches it to an ASCII name
  it is not (`mysıte.com` to `mysite.com`).
- Each name is looked up on a thread of its own, one lookup at a time per
  name, 16 names at most at once, and its answer kept 30 seconds: a stalled
  resolver leaves the loop's executor free and the process able to exit. A
  request whose Host takes over 3 seconds, or comes while 16 names are being
  looked up, goes without the rules.
- This computer's lookup can disagree with the device's (the exit node asks
  `--dns`, 1.1.1.1 by default, and a CDN may answer resolvers differently):
  such a request then goes without the rule. A `resolve` rule for the name
  avoids that (from reading the code, not tried with a CDN), except through
  `--upstream-proxy`, which takes no `resolve`: there such a request stays
  without the rule.
- Sending such a request to its Host instead was not done: mitmproxy would
  look the name up itself, past the exit node's refusals of this computer and
  the LAN (from reading its code).

**`map_remote` and `resolve` connect from this computer**, where the rule
says, this computer and the LAN included. The exit node's refusal of those
addresses is about the devices' own connections, and a rule opens its target
to every app on the carried devices that sends a request for the rule's host
(a web page included).

- `resolve` takes IPv4 addresses only, never a name to look up, and refuses
  `0.0.0.0/8`, link-local, multicast and reserved ranges, Tailscale's
  100.100.100.100 and the cloud metadata addresses 169.254.169.254 and
  100.100.100.200. `map_remote` takes whatever it is given.
- A `resolve` rule without a port takes the request's port (the app's, or a
  `map_remote` URL's).
- TLS to a `resolve` target is checked against the rule's name, with
  mitmproxy's own CA list (certifi, from reading its code), so a request goes
  on only to a server with a certificate for that name. Plain HTTP is not
  checked.
- Each `resolve` name needs its own address: mitmproxy reuses a connection
  by address, so names sharing one would share one name's check, and are
  refused.
- A `map_remote` to a `resolve` target's address shares its connections,
  both ways: a request of one can ride on a connection made, and checked, for
  the other, and a failed connection fails both for as long as the app's
  connection lasts.

**A `mock` answers in the site's name.** The app, and a web view's page,
take it as the site's own answer: a script in it runs in that origin, a
redirect is followed.

- It is for hosts in `--allow-hosts` only (refused otherwise), and its
  header values are checked as `modify_headers`'s are.
- The records say a flow was mocked, with the rule's number and status,
  never its text.
- A request a mock may answer is held whole until its body is in (the
  operation is in it): at most 1 MiB when it says its length.
- A GET that says no length is held only while it has no body. Over HTTP/2,
  one that sends a body anyway gets a 502 at its first body byte and its body
  is not held, as for `map_local`; one whose stream ends with an empty DATA
  frame is answered. While it waits for that byte or the stream's end, none
  of its body is held and no server is connected to (from reading the code).
- With a mitmproxy other than 12.3.1 (another `--mitmproxy-spec`), a stream
  not ended with its headers gets the 502 at once (from reading the code).

**`list_rules` and `explain_rules` are read-only.**

- They show only what is derived from a rule, as the
  [table above](#why-a-rule-did-or-did-not-apply-list_rules-explain_rules)
  says: for a `map_remote` rule "path only" or "not shown" when it does not
  write its target out, for a `map_local` rule its number only; never a
  filter, a regex, a header value, a body or a file's path.
- `explain_rules` runs the request path's own code on a request it makes up,
  never sent, with a copy of the presets' state, so it uses no preset's count
  and turns none on or off.
- Like the preset tools they are on `run`'s local socket and `reqcove mcp`
  only, never over `--mcp-http`: the targets say where the devices' requests
  can be sent.

Checked: tests for the points above, and tests with real mitmproxy and a
stand-in server for which host a header rule reaches (plain HTTP and HTTPS,
both ways). The limits of that:

- Not over the network: IDNA and İ, ı, ſ, K (on mitmproxy's own made flows);
  the lookup bounds (in mitmproxy's Python with a lookup that never answers,
  not in a running mitmdump); the path-only `map_remote` (in mitmproxy's
  Python).
- The 502 and the empty DATA frame: with Go's HTTP/2 client only. How
  mitmproxy tells a stream's end is from reading its code.
- Tried by hand: a `resolve` target with a trusted certificate for another
  name gets a 502.

</details>

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
  cover it ([security details](#security-upstream-proxy)): keep
  `--allow-hosts` to the hosts you test (`run` warns about `'*'`). `resolve`
  rules are refused for the same reason; use the proxy's own overrides (Burp's
  Hostname resolution overrides).
- HTTPS through the proxy is checked against the proxy's CA only: Burp's, on
  this computer, is fetched at start (from its listener's `/cert`); another proxy
  that decrypts (ZAP, Charles) needs `--upstream-ca FILE` (PEM or DER);
  otherwise the public CAs are used (for a proxy that does not decrypt). With
  a proxy other than Burp on this computer, `run` still asks its listener for
  `/cert` at start, which fails there and changes nothing.
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
certificate was not trusted). Not tried: other proxies. From reading the
code: other protocols going straight to their servers.

<a id="security-upstream-proxy"></a>

<details>
<summary>Security details: what the proxy sees, whose certificate is checked, and where the proxy connects</summary>

In short: [SECURITY](SECURITY.md#an-upstream-proxy---upstream-proxy). Beyond
that:

- **Reqcove's mitmproxy does not connect to the servers itself** (connection
  strategy lazy). Other protocols over TLS to an allowed host still go
  straight to their servers (from reading the code). The flag is read at
  start; no tool changes it.
- **Burp's own MCP server or extensions** give agents what Reqcove's tools
  hold back, and the ability to send requests.
- **Checking the real server's certificate is the proxy's job.** With the
  proxy's CA (`--upstream-ca`, or Burp's fetched at start), Reqcove trusts
  only that CA, so it checks the proxy, not the server. Burp, by default, did
  not check when tried.
- **Burp's CA is fetched over plain HTTP** from the proxy's own listener
  (`http://127.0.0.1:PORT/cert`, no name looked up, so no other server can
  answer), only when the proxy is on this computer, and only a CA named
  "PortSwigger CA" is taken.
- **Where the proxy connects is the proxy's choice.** Reqcove hands it the
  address the exit node allowed, but Burp connects by the name in the SNI,
  looked up again on this computer.
- **Why to keep `--allow-hosts` narrow.** A site the iPhone visits can make
  its own name resolve into this computer's LAN only for the proxy's lookup
  (DNS rebinding: from reading the code, not tried). `resolve` rules are
  refused with `--upstream-proxy` for this reason.
- **The CONNECT lines (an IP address and port) and plain HTTP reach the
  proxy unencrypted**: keep it on this computer, or on the tailnet.

Checked: tests (one counts the server's connections; only a CA named
"PortSwigger CA" is taken). Tried with Burp: it answered at `/cert` (checked
with curl), did not check the server's certificate by default, and connected
by the name in the SNI.

</details>

## Without Tailscale: LAN mode (`--lan`)

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
3. Allow the iPhone on this computer. Its first connection is refused, and run
   logs its address. Answer run's question (`Allow ADDR? [y/N]`, asked while
   run is the terminal's foreground job), or run `reqcove lan allow ADDR` in a
   terminal.
4. Trust the CA, once per device: open `http://mitm.it` with the proxy set, as
   with the exit node. Anyone else on the LAN can swap plain HTTP, so run's
   ready block also names the CA file, to send by AirDrop instead, and prints
   the CA's SHA-256 to compare as iOS shows it (lowercase pairs,
   `ab 90 7e …`). On the iPhone it is under Settings, General, VPN & Device
   Management, the profile, More Details. AirDrop of that file has not been
   tried.

`reqcove lan list` shows the allowed addresses and when each was allowed;
`reqcove lan deny ADDR` takes one back. The `reqcove lan` commands refuse to
run off a terminal: they are not for an agent.

In the records and in `reqcove status`:

- The records name the device `lan:ADDR`. The tools' `device` filter and
  `reqcove har --device lan:ADDR` take that name, and `list_devices` gives its
  first and last request this run.
- `reqcove status` (and the `status` tool, as `mode: "lan"`) shows where it
  listens, the allowed addresses and the ones refused this run. Of the refused
  ones it shows the 50 last seen, and how many more (`refused_more`), as
  anyone on the network can add to them. The list behind them holds up to
  10,000 and is emptied when it fills.

There is no password. Who may use the proxy is decided on this computer, by
address, as in Charles Proxy (its documentation describes an access control
list, and a dialog for a new address). What that means:

- An allowed entry is an address, not a device: whoever has that address later
  is allowed too, also on another network with the same prefix
  ([security details](#security-lan)). Use `reqcove lan list` and `lan deny`
  when done. Not checked: whether an iPhone keeps the same private Wi-Fi
  address on a network over time.
- Through this computer, an allowed address reaches the internet from your
  address, on ports 80 and 443 only, and private hosts named exactly in
  `--allow-hosts` (no `*`), those behind this computer's VPN included. Never
  this computer, link-local addresses, or the network the proxy is on, even by
  an exact name. Its requests to the allowed hosts are recorded.
- `lan deny` refuses new connections within two seconds, but HTTPS tunnels
  already open go on until they close (or are idle for 15 minutes:
  [Limits](#limits)).
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

Tried: tests with real mitmproxy on the loopback interface (HTTP and HTTPS
recorded, `http://mitm.it` serving the CA, the refusals above). With an
iPhone on a home Wi-Fi (iOS 27.3, 2026-11-14): the four steps, with Safari's
HTTPS recorded and the SHA-256 compared, then `reqcove lan deny` and
`lan allow` again. On Linux (a VM, 2026-11-14), with curl from the Mac
running the VM and no iPhone: allowing and denying, plain HTTP and HTTPS
recorded, port 22 refused. Not tried: a change of network; an iPhone with a
Linux computer.

<a id="security-lan"></a>

<details>
<summary>Security details: who is refused, how a deny takes effect, and what an allowed address reaches</summary>

In short: [SECURITY](SECURITY.md#lan-mode---lan). Beyond that:

- **Where it listens.** On one address of this computer, that of one LAN
  interface (never 0.0.0.0, never a VPN's tunnel), on `--proxy-port`.
- **The list of allowed addresses outlasts the network.** It is kept in the
  state directory, so an address stays allowed on another network with the
  same prefix (a café's 192.168.1.0/24 as your home's). The ready block,
  `reqcove status` and `reqcove lan list` show the list.
- **Other addresses are refused.** A connection from outside that
  interface's network is closed as it is accepted, as is one from an address
  not allowed. Nothing is recorded, and each new address is logged once,
  until the list of addresses seen (10,000) fills and is emptied: then once
  more, and `run` asks again.
- **A deny refuses new requests within two seconds**: each request on a kept
  connection is checked again. An HTTPS tunnel already open goes on until it
  closes, or until no bytes went either way for 15 minutes. An address keeps
  at most 256 tunnels open at once.
- **The allowed addresses** are kept in `<state>/lan-allowed` (0600, with
  when each was allowed). They change through `reqcove lan allow|deny`, or
  through `run`'s question on its own terminal. No MCP tool changes the list.
- **The `lan` commands refuse to run unless stdin and stdout are a
  terminal**, as `reqcove links` does: an agent's shell usually has neither
  (a help, not a guarantee: a script can give it one).
- **`run`'s question** is asked only while `run` is the terminal's
  foreground job, and input typed before it is dropped first, so an earlier
  Enter or `y` does not answer it.
- **`--lan` is refused in a `--config` file**, so `brew services` and
  `reqcove service install` (which refuses the file at install too) never
  keep an open proxy running.

What an allowed address reaches through this computer:

| Destination | Reached |
|---|---|
| Ports other than 80 and 443 | Never: refused before any lookup |
| Public addresses | Yes, from your address |
| Private ranges (10/8, 172.16/12, 192.168/16, 100.64/10), those behind this computer's VPN included | Only by a name written exactly in `--allow-hosts` (no `*`) |
| This computer (loopback, its addresses), link-local addresses, the network the proxy is on, this computer's other networks numbered from public space, special-purpose ranges, IPv6 | Never, even by an exact name |

- Names are looked up with this computer's resolver, `/etc/hosts` first.
- `map_remote` and `resolve` targets in `--rules` are dialled by mitmproxy,
  outside these checks: a rule sending an allowed host to a server on this
  computer serves the LAN clients' requests there too.
- The CA at `http://mitm.it` comes over plain HTTP, which anyone else on the
  LAN can swap: hence the CA file to send by AirDrop, and the SHA-256 to
  compare with the profile's More Details (step 4 above).

Checked: tests (the refused connections and the log of addresses; the deny,
the idle tunnel and the 256 tunnels, with smaller values; what an allowed
address reaches; `run`'s question through a seam, the terminal calls
themselves not tested). Tried with an iPhone on a home Wi-Fi, 2026-11-14:
refused until allowed, then recorded; refused again after `reqcove lan deny`;
the SHA-256 matched what iOS showed.

</details>

## Run it in the background

`reqcove run` in a terminal is the simplest: Ctrl-C stops it, and its
terminal shows the login URL, the QR codes and what is left to do. To have
`run` start at login instead, a service starts it: Homebrew's `brew services`,
or `reqcove service install` (any install, Homebrew's included since v1.1).
Use one of them, not both. `--lan` is refused in both
([LAN mode](#without-tailscale-lan-mode---lan)).

Both read the same flags as a terminal's `run`: one config file
([below](#the-config-file---config)), which `reqcove setup` writes. First:
while `run` is down, and while the Mac sleeps, an iPhone on its exit node has
no internet; turn the exit node off then.

### Start, update, stop

| | In a terminal | `reqcove service install` | `brew services` |
|---|---|---|---|
| Start | `reqcove run` (Ctrl-C stops it) | `reqcove service install`: now and at each login | `brew services start reqcove`: now and at each login |
| After it ended | `reqcove run` | `reqcove service restart` (after stopping it until the next login too) | `brew services restart reqcove` |
| After an update | Ctrl-C, then `reqcove run` | `reqcove service restart`; after moving to another binary (a new path, or Homebrew's), `reqcove service install` | `brew upgrade reqcove`, then `brew services restart reqcove` |
| After editing the config, hosts or rules file | `reqcove reload` for the hosts and rules; for the rest, `reqcove restart`, or Ctrl-C, then `reqcove run` | `reqcove reload`; for the rest, `reqcove restart` or `reqcove service restart` | `reqcove reload`; for the rest, `reqcove restart` or `brew services restart reqcove` |
| Restart in the same process (since v1.3) | `reqcove restart` ([restart in place](#restart-in-place-reqcove-restart)) | `reqcove restart` | `reqcove restart` |
| Stop until the next login | Ctrl-C | `launchctl bootout gui/$(id -u)/io.github.mh-mobile.reqcove`, or `systemctl --user stop reqcove` | `brew services kill reqcove` (from Homebrew's help, not tried) |
| Stop and remove | Ctrl-C | `reqcove service uninstall` | `brew services stop reqcove` |
| The log | the terminal | macOS: `service.log` in the state directory; Linux: `journalctl --user -u reqcove` | `$(brew --prefix)/var/log/reqcove.log` |

- **Every restart empties the records**: they are in memory. Keep them first
  with `reqcove har > flows.har`.
- **To change the hosts recorded, no restart**: `reqcove capture add HOST`
  (`remove`, `set`), then `reqcove capture save` to keep them for the next
  start ([change what is recorded](#change-what-is-recorded-while-it-runs)).
  After editing the config, its hosts file or the rules file, `reqcove reload`
  takes their hosts and rules, no restart
  ([edit, then reload](#edit-the-files-then-reqcove-reload)); any other
  change: restart as above.
- **After an update**, `reqcove status` (the new one) says so: the running
  version against its own, and the one command that restarts it under what
  started it. `run` keeps running the old binary until then, even after
  `brew upgrade` (a running process keeps its files).
- **`reqcove status`** also says what started `run` (a terminal, `reqcove
  service install`'s service, `brew services`), the config and hosts files it
  read, and warns when two services for reqcove are installed at once, or
  when `reqcove service install`'s service runs a binary that is gone or is
  not this one (`reqcove service install` again points it at this one).
  Since v1.3 it also names the other `reqcove` files on your shell's PATH
  (none of them run; `type reqcove` says which one your shell runs); this
  computer's agents and `reqcove status --json` get the same from `run`'s
  own PATH (a service's may differ). Unit tests.
- **A `run` in your terminal** on the same state as a service finds it in
  use: stop the service first.
- **Sleep**: `run` keeps the Mac from idle sleep while it runs
  (`caffeinate -i`, also on battery: it drains it), not from closing the lid
  or choosing Sleep. Since v1.2, `--keep-awake` chooses (in the config file
  too; a restart takes a change, not `reqcove reload`):
  - `always` (the default, as before);
  - `ac`: no sleep while on AC power (`caffeinate -s`); on battery the Mac
    sleeps as the Energy settings say, and a phone using its exit node has
    no internet meanwhile;
  - `never`: Reqcove holds nothing. The Energy settings, or `sudo pmset -c
    sleep 0` (on AC power only), do the same for the whole Mac, as Tailscale
    suggests for a Mac exit node.

  Other apps that keep the Mac awake (Amphetamine, a `caffeinate` of yours)
  add up with it: whatever Reqcove holds, the Mac stays awake while one of
  them does. `pmset -g assertions` lists who holds what; `reqcove status`
  shows `run`'s choice ("keep awake:"). Seen on a Mac (2026-11-16): the
  Claude and ChatGPT desktop apps (Electron) held `NoIdleSleepAssertion`
  for as long as they ran, so it did not idle-sleep whatever `--keep-awake`
  said.

  Tried: unit tests (the flag, the config file, caffeinate's assertion for
  each, status); two `caffeinate` assertions seen side by side in `pmset -g
  assertions`; `run --keep-awake=ac` on AC power holding `PreventSystemSleep`
  (not `always`'s `PreventUserIdleSystemSleep`) and `reqcove status` saying
  so. Not tried: a real sleep on battery with `ac`, nor with `never`.

Tried: unit tests of what `reqcove status` prints for each case (a v1.0.0
`run` and a newer CLI, each service, two services at once, a binary gone or
another one), with service files written in a temporary home. By hand
(2026-11-16): `brew upgrade` from v1.1.0 to a v1.2 build with `brew services`
running, `reqcove status` naming the version difference, then `brew services
restart reqcove`. Not tried by hand: `reqcove service install` over an
installed one.

### The config file (`--config`)

`run --config FILE` takes `run`'s flags from a file, one a line.

- **Its place**: `~/.config/reqcove/config`. For a brew install (this binary
  under `Cellar/reqcove/`), `reqcove setup` writes Homebrew's
  `$(brew --prefix)/etc/reqcove/config` instead, which `brew services` reads.
  The hosts go in `hosts` beside it, read with `--allow-hosts=@FILE`.
- **`reqcove run` with no arguments at all** (since v1.1) reads
  `~/.config/reqcove/config`, else Homebrew's (when this `reqcove` is
  Homebrew's), and says which in its log. With both there, it reads the first
  and `reqcove status` names both. With any argument, it reads a file only
  when `--config` names it, as before; with neither file, it asks for
  `--device` as before.
- **`reqcove service install`** takes the file a bare `run` reads (or
  `--config FILE`); installed again, it keeps the file it had. `brew services`
  always reads Homebrew's. So with both files there, the two services read
  different files.
- Its lines:
  - `#` starts a comment. Quote as a shell would: `--device "Taro's iPhone"`.
    `~/` is your home. Give paths in full or from `~/`, as a service starts
    in `/`.
  - The command line's flags come after the file's: a flag given once is the
    command line's, a repeatable one adds up.
  - Refused in the file: `--no-redact`, `--web`, `--rules-reload`, `--lan`,
    `--config` and `--allow-hosts '*'` (also from an `@FILE`). They stay on
    the command line.
- The file must be yours and readable by you only (`chmod 600`): it may hold
  `--mask-values` patterns. One `--config` only.
- **When it is refused** (missing, or a flag refused), a service ends once
  (`brew services` shows an error); it is not started again in a loop, nor
  after any other end.

Tried: unit tests (the parsing and the refusals; a bare `run` reading either
file, both, neither, and with an argument none).

### With Homebrew (`brew services`)

```sh
reqcove setup                # writes $(brew --prefix)/etc/reqcove/config
brew services start reqcove
reqcove links                # the login URL, the first time (after a minute: the first start fetches mitmproxy; tail -f "$(brew --prefix)/var/log/reqcove.log")
reqcove status               # "service: sh.brew.reqcove" (homebrew.mxcl.reqcove with an older Homebrew)
```

- **The logs**: `$(brew --prefix)/var/log/reqcove.log`, and `mitmproxy.log` in
  the state directory, which grows too. Neither is rotated (by launchd or by
  reqcove): truncate them now and then. Neither carries a login URL or a
  token: `reqcove links` prints them, in your terminal.
- **The formula's service runs Homebrew's stable path**
  (`$(brew --prefix)/opt/reqcove/bin/reqcove`): after `brew upgrade`,
  `brew services restart reqcove` starts the new version.
- **Linux**: Homebrew's `brew services` makes a systemd unit from the same
  formula (from Homebrew's documentation, not tried). `reqcove status` names
  it from the process' cgroup (from reading systemd's documentation, not
  tried).

Tried: `brew services start` and `stop` on macOS 27 with the formula, an
iPhone recorded through it (no token or login URL in the log; `links` and
`login-url` gone after stop). Not tried with `brew services`: a start at
login or after a reboot, sleep, and whether macOS asks for Local Network
access for a `run` not started from a terminal (all three tried with
`reqcove service install`, below); whether launchd's default background
priority slows it.

### Without Homebrew (`reqcove service install`)

It writes a LaunchAgent on macOS
(`~/Library/LaunchAgents/io.github.mh-mobile.reqcove.plist`), a systemd user
unit on Linux (`~/.config/systemd/user/reqcove.service`). The service runs
this binary (its full path) with `run --config FILE`. It starts now and at
each login, and is not started again when it ends (as `brew services`).

```sh
reqcove setup                 # writes ~/.config/reqcove/config
reqcove service install       # --config FILE for another file, --state DIR for another state
reqcove links                 # the login URL, the first time (after a minute)
reqcove status                # "service: io.github.mh-mobile.reqcove" (Linux: reqcove.service)
reqcove service restart       # after it ended, or after a change to the file
reqcove service uninstall     # stops it and removes the file
```

- **The file** is the one a bare `run` reads (above) unless `--config` names
  another.
  - Install refuses a missing file (saying how to write one), one that is not
    yours or that others can read, and `--no-redact`, `--web`,
    `--rules-reload`, `--lan` or `--config` in it.
  - `--allow-hosts '*'` there is refused when `run` starts (the service then
    ends once).
  - A `--state` in the file is the state directory (in full or from `~/`).
    The state directory must be empty, new or reqcove's (as for `run`).
- **Homebrew's binary** (since v1.1): the service runs Homebrew's stable path,
  `$(brew --prefix)/opt/reqcove/bin/reqcove`, not its Cellar path, which
  `brew upgrade` removes. After an upgrade, `reqcove service restart`.
- **Installed already** (since v1.1): install again re-points it at this
  binary and restarts it, and says so (the records start empty). It keeps the
  installed service's `--config` and `--state` unless you give them. Use it
  after moving to another binary, or to change them. On macOS it starts the
  new one once the old one has let go of the state directory (at most 10
  seconds; past that it starts it all the same and says so: a `run` in a
  terminal holding it, say).
- **Refused while Homebrew's service is there** (its file or loaded:
  `sh.brew.reqcove`, `homebrew.mxcl.reqcove`; on Linux
  `sh.brew.reqcove.service`, `homebrew.reqcove.service`, the Linux names from
  reading Homebrew's code, not tried): two services would fight over the
  state directory. `brew services stop reqcove` first.
- **When it ends**: once `run` ends (an error, a refused file, `kill`), it
  stays down until the next login. `reqcove service restart` starts it again
  (`launchctl kickstart -k gui/$(id -u)/io.github.mh-mobile.reqcove`, or
  `systemctl --user restart reqcove`; not tried on macOS).
- **The log**:
  - macOS: `service.log` in the state directory. It is not rotated: truncate
    it now and then, as `mitmproxy.log`. `service install` makes it 0600
    before launchd opens it, which would make it 0644 (not tried with
    launchd).
  - Linux: `journalctl --user -u reqcove`.
  - It prints no login URL or token, nor does `service install`:
    `reqcove links` does, in your terminal.
- **`PATH`** is uvx's directory where you installed it, then `~/.local/bin`,
  `/opt/homebrew/bin`, `/usr/local/bin` and the system's. Elsewhere, give
  `--uvx /full/path/uvx` in the file.
- **Local Network access** (macOS): when this was tried, macOS asked for it,
  before and after a sleep. Its list shows each build at another path as its
  own entry.
- **Linux**: a user unit runs while you are logged in. Without
  `loginctl enable-linger $USER`, systemd stops it when your last session
  ends (within 15 seconds of the last logout, over ssh), and starts it again
  at the next login. With linger it keeps running after the logout, and it
  starts at boot before any login (from systemd's documentation; no reboot
  tried).

Tried: unit tests, which never run launchctl or systemctl (the files written,
the refusals, the commands, the log's mode; Homebrew's opt path written; an
install over an installed one: `launchctl bootout` then `bootstrap`, or
`systemctl --user restart`, its `--config` and `--state` kept). By hand,
2026-11-14 (v1.0), with no login URL or token in the log: on macOS, install to
uninstall with an iPhone recorded through it, a sleep, and a start at login
after a reboot (no alert at login); on Linux (a VM), with the node not logged
in to a tailnet, install to uninstall, `service restart` after a `kill` and
after `systemctl --user stop reqcove`, and the logout with and without
linger. Not tried: v1.1's install over an installed one and with Homebrew's
binary, with launchd or systemd; `service restart` on macOS; on Linux, a node
logged in to a tailnet, a device recorded through it, a reboot.

<a id="security-config"></a>

### Security details

In short: [SECURITY](SECURITY.md#a-flags-file---config).

`run --config FILE` (for `brew services` and `reqcove service install`) takes
`run`'s flags from a file: what can write that file decides the next start's
flags. Since v1.1 a `reqcove run` with no arguments reads one too
([the config file](#the-config-file---config)), with the same checks.

- The file must be yours and readable by you only (refused otherwise): it
  may hold `--mask-values` patterns.
- Errors name its lines, never a value.
- Five flags are refused in it and stay on the command line: `--no-redact`
  (takes masking off), `--web` (shows traffic unmasked), `--allow-hosts '*'`,
  also through `@FILE` (records every site), `--rules-reload` (lets a file
  change where requests go while running) and `--lan` (an open proxy on the
  LAN).
- Others, such as `--upstream-proxy` or `--rules`, are allowed there.
- Since v1.3, reqcove writes the file itself in one case: `capture save` on a
  config naming no hosts file adds its `--allow-hosts=@FILE` (or
  `--pass-hosts=@FILE`) line, after y/N ([capture save](#keep-the-hosts-for-the-next-start-reqcove-capture-save)).
  It writes only that line, the file whole (0600, the one before kept as
  `config.prev`), never through a link nor to a file not yours, and checks
  first that the next start would take it.

Checked: tests (the refusals; the line added, and a link or another user's
file refused).

<a id="security-logs"></a>

The logs:

- `mitmproxy.log` in the state directory holds mitmproxy's error lines only.
- `run`'s own output, when it is a file, is made 0600 as `run` starts,
  before its first line: a redirect, or brew services'
  `$(brew --prefix)/var/log/reqcove.log`, which launchd makes 0644.
- `reqcove setup` makes brew's log 0600 before the service first starts, as
  `reqcove service install` does its `service.log`. Not tried with brew
  services.
- That output holds no token or login URL, but what `run` logs of the
  devices.

Checked: tests (secrets sent in failing and malformed requests do not reach
`mitmproxy.log`; `run` making its output 0600; making the service's log).

## Containers

`reqcove run` runs in a container too (Docker, or Podman). The steps, what is
different there and what was checked are on their own page:
[Reqcove in a container](container.md). What this guide says about containers:

- An agent on another device: `--mcp-http` is the same flag there, with no
  port to publish ([Agents on other devices](#agents-on-other-devices---mcp-http)).
- The login URL and the links: off a terminal (`docker logs`), `run` does not
  print them; `reqcove links` does ([First start](#first-start)).
- Security: what a container changes is in
  [SECURITY](SECURITY.md#in-a-container). Two points beyond it are below.

<a id="security-container"></a>

- Without a terminal, `run` names `reqcove links` in place of the login URL,
  the links and the token.
- `reqcove mcp` runs with `--log-driver none`, so the tools' answers are not
  logged.

Checked: `scripts/container-smoke.sh` (the state directory's owner and mode,
no network needed); not by an attack.

## Troubleshooting

Start with `reqcove status`: it says what reqcove is doing, and the next steps
(an agent has the `status` tool). Then, by what you see:

| What you see | Where it is explained |
|---|---|
| `run` started, but something is left to do: the login, Tailnet Lock, the exit node's approval | [First start](#first-start) |
| The login URL or a link with its token is not shown (a service, `docker logs`) | `reqcove links`: [First start](#first-start) |
| The iPhone's DNS stays stuck after `run` stopped | [Stop, restart, update](#stop-restart-update) |
| The agent's tools answer that reqcove is not running, or the records are empty after a restart | [Stop, restart, update](#stop-restart-update) |
| The tools say the versions differ, or `reqcove status` says the skill is from another version | [Stop, restart, update](#stop-restart-update), [the skill](#teach-the-agent-the-skill-reqcove-init) |
| Traffic is carried, but nothing is recorded | `--allow-hosts` in [Options](#options) |
| An app's requests fail, and `reqcove status` names its hosts (certificate pinning) | [Apps that pin certificates](#apps-that-pin-certificates---pass-hosts) |
| An Android app refuses the CA | [Android](#android) |
| A gRPC app's calls show as TLS failures | [gRPC](#grpc) |
| An allowed host's traffic is missing, and `reqcove status` says its connections were carried as raw TCP | [Connections not read as HTTP](#connections-not-read-as-http-raw-tcp) |
| With `--local-proxy`: apps on this computer cannot connect after `kill -9` or a crash, or an allowed host breaks in an app here | [The iOS Simulator](#the-ios-simulator---local-proxy) |
| A rule did not apply | [Why a rule did or did not apply](#why-a-rule-did-or-did-not-apply-list_rules-explain_rules) |
| A rules file does not load, or a change to it is not taken | [When the file is read](#when-the-file-is-read---rules-reload) |
| With `--upstream-proxy`: requests wait, or HTTPS through the proxy fails | [An upstream proxy](#an-upstream-proxy---upstream-proxy) |
| In mitmweb: the devices' HTTP(S) stopped, or a bookmark asks for the token | [In mitmweb](#in-mitmweb---web) |
| Over `--mcp-http`: a device is refused, calls get `429`, or Grok Bot's settings show the connector with an error | [Agents on other devices](#agents-on-other-devices---mcp-http) |
| LAN mode: the iPhone's first connection is refused, something blocks it, or a development server on another port is refused | [LAN mode](#without-tailscale-lan-mode---lan) |
| An iPhone on the exit node has no internet while the Mac sleeps | [Run it in the background](#run-it-in-the-background) |
| A service ended and did not start again, or a `run` in your terminal finds the state in use | [Start, update, stop](#start-update-stop) |
| The log says `did not answer within 10s (through mitmproxy)` or `the client left before … answered (through mitmproxy)` | [Limits](#limits) |
| reqcove restarts mitmproxy again and again, or `run` stops on mitmproxy | [Limits](#limits) (a huge WebSocket message; when mitmproxy exits or does not start), [Rules](#rules---rules) (a very large body to a host a `map_local` rule matches; rules that no longer load) |
| IPv6, QUIC, phone calls | [Limits](#limits) |

This section only points to the others: what was tried, and what was not, is
said there.

## Options

`reqcove run`:

| | |
|---|---|
| `--device NAME` | a device to carry: machine name, device name (your own untagged devices only), tailnet IP or StableID; repeat for more |
| `--allow-hosts HOSTS` | hosts to decrypt and record: `api.example.com`, `*.example.com` (the domain itself and every subdomain), `'*'` for all, or `@FILE`, one a line (`#` for comments; a file without hosts gives none, since v1.3). Without it, traffic is carried but nothing is recorded |
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
| `--config FILE` | [run's flags from a file](#the-config-file---config), one a line, before the command line's (not `--no-redact`, `--web`, `--rules-reload`, `--lan`, `--config`, `--allow-hosts '*'`); the file `chmod 600` |
| `--uvx PATH` | the uvx to run; the `uv` beside it runs the default mitmproxy from Reqcove's lock (hashes checked). A path not named `uvx` is run as uvx: no lock, no hashes |
| `--python VERSION` | the Python to run mitmproxy with, 3.14 by default |
| `--mitmproxy-spec SPEC` | another mitmproxy than the locked `mitmproxy==12.3.1`, fetched through uvx (no lock, no hashes) |

The other commands (all but `init`, `version`, `setup`, `service restart` and
`service uninstall` take `--state DIR` too):

| | |
|---|---|
| `reqcove status` | what reqcove is doing, and the next steps; `--json` for the `status` tool's JSON (with no run to answer: nothing on stdout, exit status 1, the reason on stderr); `--uvx PATH` |
| `reqcove links` | the login URL and the `--ui`, `--web`, `--mcp-http` links again, with QR codes; only to a terminal ([first start](#first-start)) |
| `reqcove mark` | `[TEXT]` (`-- TEXT` for one starting with `-`): a [marker](#mark-a-moment-reqcove-mark) among the records, as yours (`cli`); only in a terminal |
| `reqcove mock add` | `--rules FILE --url URL` and the mock's flags: [a mock added to the file](#add-a-mock-from-your-terminal-reqcove-mock-add), checked first; only in a terminal (`--print` shows it, anywhere); `--uvx PATH` |
| `reqcove mcp` | the MCP server for an agent on this computer |
| `reqcove lan` | `allow ADDR`, `deny ADDR`, `list`: the addresses [LAN mode](#without-tailscale-lan-mode---lan) carries; only in a terminal |
| `reqcove har` | [the flows as a HAR file](#as-a-har-file-reqcove-har): `--host`, `--device`, `--since`, `--until`, `--status`, `--method`, `--user-agent`, `--limit N` |
| `reqcove init` | [the agent skill](#teach-the-agent-the-skill-reqcove-init): `--client NAME`, `--print`, `--uninstall` |
| `reqcove setup` | [the first run](#first-start): no flags; only in a terminal |
| `reqcove service install` | `--config FILE`, `--state DIR`; then `reqcove service restart`, `reqcove service uninstall`: [without Homebrew](#without-homebrew-reqcove-service-install) |
| `reqcove cleanup` | how to undo everything; `--delete-state`; `--hostname NAME` |
| `reqcove version` | the version |

Tried on an iPhone: `--mask-names`; `wait_for_flows` after acting through
RoamRun; with a test app, `diff_flows` (a request sent twice),
`list_ws_messages` and `--proto`. By tests only: `--mask-values`, `max_body`,
the `--mcp-http` rate limit, `multipart/form-data`, XML bodies (and an E2E test
with a SOAP request through mitmproxy).

From reading code (the flags' help), not tried for this guide: `--proxy-port 0`,
`--hostname`, `--verbose`, `--uvx`, `--python`, `--mitmproxy-spec`.
`status --json`: used in the LAN mode trial on Ubuntu; its exit status 1
with no run, by a unit test.

## MCP tools

| Tool | |
|---|---|
| `list_flows` | flows, newest first; filter by device, host (and subdomains), time (`since: "10m"`), status (`404`, `4xx`, `none`), method, User-Agent (text in it, such as an app's name; the app's bundle id is not in its traffic), GraphQL operation (`operation: "Login"`: its `operationName`, or the document's first operation; rows show it); paged. A host that matches nothing brings `similar_hosts`, recorded hosts that look alike (`acme-shop.com` for `acmeshop.com`) |
| `search_flows` | text in URLs and headers (and body heads with `bodies`); the same filters and `similar_hosts` |
| `wait_for_flows` | what an action on the device sent: take `checkpoint` from `list_flows` (or `capture_stats`) before acting, then call with `after: checkpoint`. Returns the flows answered since (a response or an error), oldest answer first, waiting up to `timeout` seconds (default 20, at most 30) for the first. Pass its `after` to the next call: each flow comes once. The same filters. A WebSocket is answered once, when it opens (`101`), and stays `open` until it closes |
| `get_flow` | one flow; bodies only with `bodies`, cut to `max_body` bytes each if given; `response_trailers` (HTTP/2's, or gRPC-Web's last frame); a body with `view` is reqcove's rendering, not its bytes: protobuf ([gRPC](#grpc)), or `multipart/form-data` with each part masked and files by their size |
| `list_ws_messages` | a WebSocket's messages, oldest first: a text message's first 4 KiB, masked, the others by their size ([what is kept, and the cursor](#websocket-messages-list_ws_messages)) |
| `diff_flows` | two flows compared (one that worked and one that failed): method, URL, status, error, headers by name, bodies (JSON by path). While masking is on, values masked on both sides are listed under `masked`, never as equal (they may differ), and bodies that are not text are not compared; with `--no-redact` everything is compared |
| `summarize` | counts by host, User-Agent, status, method, device, content type, gRPC status (`by_grpc_status`), and endpoint (`by_endpoint`: method, host and path without the query, ids as `{id}`, then the GraphQL operation: `GET api.example.com/v1/users/{id}`, `POST api.example.com/graphql Login`); the same filters and `similar_hosts` |
| `list_devices` | carried devices (`lan:ADDR` in LAN mode), their counts, and first and last activity this run |
| `list_tls_failures` | handshakes a device refused: often certificate pinning, or a CA not trusted yet |
| `list_passthrough` | connections whose contents are not recorded as flows, with `reason`: to `--pass-hosts` hosts (`pass_hosts`), and to allowed hosts mitmproxy carried as raw TCP, not read as HTTP (`raw_tcp`, with the ALPN the client got: [raw TCP](#connections-not-read-as-http-raw-tcp)); host, server, times, bytes; no URLs or contents |
| `capture_stats` | mitmproxy's state, the window the records cover, drops |
| `status` | the mode (`tailnet` or `lan`, with the LAN addresses allowed and refused), whether everything is set up, and the next steps if not; the presets turned on, of every kind (`active_presets`, with `kind`; not over `--mcp-http`, which has no preset tools) |
| `list_presets` | the [presets](#presets-an-agent-can-turn-on) in the `--rules` file, of every kind (`kind`): a mock's match and answer, a `map_remote` preset's target, a `modify_headers` preset's header name, a `resolve` preset's name and address; whether it is on, when it turns off. Never bodies, header values, filters or regexes. Not over `--mcp-http` |
| `activate_preset` | turn a preset of any kind on, for at most 5 minutes (`minutes`; `times`, at most 20 requests, for a mock); returns `checkpoint` for `wait_for_flows` and the preset it turned off for the same match. Not over `--mcp-http` |
| `deactivate_preset` | turn a preset off. Not over `--mcp-http` |
| `list_rules` | the `--rules` file's [rules](#why-a-rule-did-or-did-not-apply-list_rules-explain_rules) by kind and number, with their presets and what is derived from them (a mock's match and answer, a `map_remote` target, a `modify_headers` header name and direction, a `resolve` name and address); never filters, regexes, header values, bodies or paths. Not over `--mcp-http` |
| `explain_rules` | why a flow (`flow_id`), or a method and URL, got or would get which rules: the scope, then the rewrites, a mock, the presets on and what one off would do; rules whose filter reads more than a method and URL in `cannot_tell`. Sends nothing, uses no preset's count. Not over `--mcp-http` |
| `add_marker` | a [marker](#mark-a-moment-reqcove-mark) (`text`, at most 80 characters, one line, masked); returns `id`, `time` (for `since`) and `checkpoint` (for `wait_for_flows`' `after`). Changes nothing on the device. Not over `--mcp-http` |
| `list_markers` | the markers, oldest first (`since`), with `source`: `cli` (`reqcove mark`) or `mcp` (an agent). Not over `--mcp-http` |
| `request_capture_add` | ask you to record 1 to 5 more host names; records nothing until you approve it ([how](#let-an-agent-ask-for-a-host-reqcove-capture-approve)). `reqcove mcp` only (since v1.2) |
| `get_capture_request` | what came of a request (`id`): `pending`, `applied`, `denied`, `expired`… `reqcove mcp` only (since v1.2) |

### WebSocket messages (`list_ws_messages`)

`list_ws_messages` reads the messages of one WebSocket: a flow whose row has
`websocket_messages`.

- **Order and paging**: oldest first, after a cursor (`after`: a checkpoint,
  or the last page's `after`). The filters are `direction` (`client`,
  `server`) and `text`.
- **What a message gives**: a text message gives its first 4 KiB, masked as
  it arrived, as bodies are. A binary one, one past about 20 a second on its
  socket, or text that masking cannot read gives its size only
  ([what masking finds in a message](masking.md#websocket-messages)).
- **What is kept**: the socket's first 5 messages (an auth message is
  usually one) and its newest 100. `missed` counts the others after the
  cursor. It is `missed_at_most` when the cursor itself falls among them:
  then some may be from before it.
- **The socket's state**: `open` and `close` (code, who closed).
- **With the other tools**: messages wake no `wait_for_flows`, but a
  timed-out wait lists the sockets that got messages since
  (`websocket_activity`). `search_flows` with `bodies` looks in the kept
  messages.

## Limits

The main ones are in the [README](../README.md#limits). The rest:

- IPv6 is refused; apps fall back to IPv4 at once.
- QUIC is dropped except to Apple, so apps fall back to TCP. This is by
  address, not by host: QUIC to hosts outside `--allow-hosts` falls back too
  (and without `--allow-hosts` as well). QUIC on a port other than 443 goes on,
  unrecorded.
- mitmproxy holds each WebSocket message until it is complete, and inflates a
  compressed one (permessage-deflate) whole (from reading mitmproxy's code),
  so one huge message can use a lot of memory: Reqcove's 4 KiB bound is on
  what it keeps, not on mitmproxy. Compressed messages are recorded inflated
  and masked.
- **When mitmproxy exits** (out of memory, say) **or does not start**,
  reqcove starts it again, without end: after 1 second, then each wait
  doubled up to 5 minutes, back to 1 second once it stayed up a minute.
  Meanwhile devices' connections wait or fail; `reqcove status` (and
  `capture_stats`) says why (`last_failure`), how many attempts in a row
  (`retries`) and when the next is (`next_attempt`). At the start, one that
  does not say hello within 2 minutes (a slow machine, uv still downloading)
  is tried again too; until the first one is up, `run` answers no status, so
  those attempts are in its log only. `run` stops with an error (exit status
  1, not the 0 of Ctrl-C, so a service shows it failed) only on what trying
  again cannot mend: rules that do not load, and, before mitmproxy has come
  up once in this run, one that cannot be launched or exits before its hello
  (bad options, `--mitmproxy-spec` or `--python`; not tried: uv that cannot
  download without network, which exits too).
- A connection reqcove gives to mitmproxy waits for mitmproxy to connect to
  the server, as a direct one waits for the server: 10 seconds at most. The
  log then says `<address>:<port> did not answer within 10s (through
  mitmproxy)`, or, when the app gave up first, `the client left before
  <address>:<port> answered (through mitmproxy)`: the server was slow or not
  reachable from this computer at that moment.
- Through the Remote Proxy, LAN mode and `--local-proxy`, a client (one
  address; with `--local-proxy`, all of this computer's apps together) keeps
  at most 256 tunnels (CONNECT: HTTPS, WebSockets) open: the next one gets a
  503 until one closes. A tunnel with no bytes either way for 15 minutes is
  closed; a WebSocket or an event stream that keeps talking stays open. The
  exit node's own connections have neither limit (from reading the code).
- Phone calls through the exit node have not been tried.
- Limits of one feature are in its section: [`--ui`](#on-the-iphone---ui),
  [`--web`](#in-mitmweb---web), [`--local-proxy`](#the-ios-simulator---local-proxy),
  [LAN mode](#without-tailscale-lan-mode---lan), [rules](#rules---rules), [an upstream proxy](#an-upstream-proxy---upstream-proxy).

Tried: compressed WebSocket messages by an E2E test with Go's client and
server, and from an iPhone (iOS 27.3, 2026-11-15) to a server that accepts
them; the restarts, by unit tests with a stand-in for mitmproxy (one that
kept exiting was tried 8 times with growing waits and `run` went on; one
silent at the start was tried again; one that exited at the start ended it);
the 10 seconds, with an address that never answers (why the two
such lines seen with real apps were slow is not known); the tunnels' limits,
by a test with 2 tunnels and 300 ms.

## Security

In short, for deciding whether to trust Reqcove: [SECURITY.md](SECURITY.md).
Each option's own points are under "Security details" in its section above.
The rest:

- [What is recorded](SECURITY.md#what-is-recorded): only `--allow-hosts`
  hosts, never Apple's. [Masking](SECURITY.md#masking): what it finds, and
  what it does not. [Not caught](SECURITY.md#not-caught): the connections
  that leave no record.
- [What the agent sees goes further](SECURITY.md#what-the-agent-sees-goes-further),
  to its model provider, and bodies may try to instruct it
  ([prompt injection](SECURITY.md#prompt-injection)).
- [What the devices can reach](SECURITY.md#what-the-devices-can-reach): not
  this computer, its LAN or the tailnet.
- [The CA's private key](SECURITY.md#the-cas-private-key), in the state
  directory and its backups: a device trusts that CA for every site until
  its profile is removed.
- [Other people's devices](SECURITY.md#other-peoples-devices) need their
  consent; [a computer shared with other users](SECURITY.md#a-computer-shared-with-other-users);
  [what `cleanup` leaves](SECURITY.md#what-reqcove-cleanup-leaves).
- [The exit node's DNS](SECURITY.md#the-exit-nodes-dns) (`--dns`), and
  [a container](SECURITY.md#in-a-container).

Five of these have more detail below, which adds to SECURITY and does not
repeat it: [the exit node's DNS](#security-dns),
[what the devices can reach](#security-reach),
[a computer shared with other users](#security-shared-computer),
[other processes on this computer](#security-other-processes) and
[mitmproxy's own code](#security-mitmproxy-code).

<a id="security-dns"></a>

### The exit node's DNS (`--dns`)

Who can resolve names through the exit node, who sees them, and what a
false answer gets: [SECURITY](SECURITY.md#the-exit-nodes-dns). Beyond that:

- The exit node answers DNS over HTTPS (Tailscale's PeerAPI) for the devices
  that use it. It answers any peer the tailnet policy lets use an exit node
  (from reading Tailscale's code).
- Those peers ask the same upstream as your devices: `1.1.1.1` by default.
  With `--dns system`, or a LAN resolver in `--dns`, that is your router's or
  your company's resolver, and they can look up names only it knows.
- The DNS from this computer to the upstream is plain for the exit node and
  for the Remote Proxy alike.
- Answering falsely from off the path is hard: each query has a random ID
  and its own random port, and answers from any other address are dropped.
- The certificate a false answer would need is checked by mitmproxy for
  decrypted hosts, and by the phone itself for the others. An answer pointing
  at this computer, its LAN or loopback is refused like any connection there.
- To hide the names, a local DNS-over-HTTPS relay could serve as
  `--dns 127.0.0.1:PORT`; that has not been tried.

Checked: a test (an answer pointing at this computer, its LAN or loopback is
refused). Tried: the exit node answered this computer, which was not one of
`--device`.

<a id="security-reach"></a>

### What the devices can reach

What the devices reach, what Reqcove refuses, and what it does not catch
(your network's public address):
[SECURITY](SECURITY.md#what-the-devices-can-reach). Beyond that:

- Public networks reached only through a route (behind a router, not on an
  interface's subnet) are not refused (from reading the code).
- Pings (ICMP echo) follow the same rules: one from a device not in
  `--device`, or to a refused address, is dropped. A listed device's ping to
  a public address is answered by pinging from this computer (from reading
  the code).
- While a device's UDP flow lasts (2 minutes after its last packet, 30
  seconds for DNS), only the address and port it was sent to can answer
  through it. Datagrams from anyone else that reach its port on this computer
  are dropped.

Checked: tests (pings to 127.0.0.1, from a device not in `--device` and from
a listed one; a datagram sent from this computer).

<a id="security-shared-computer"></a>

### A computer shared with other users

What keeps other users out, and what is not covered:
[SECURITY](SECURITY.md#a-computer-shared-with-other-users). The four
sockets it names are the MCP tools', `reqcove capture`'s (`ctl.sock`; 0600,
a test) and mitmproxy's two. What another user
can still see or reach, in full:

- **`ps`.** `run`'s and mitmproxy's command lines, with the device names,
  the hosts in `--allow-hosts` and `--pass-hosts`, the paths of the rules
  file and the state directory, the upstream proxy's address, and any
  `--mask-names` or `--mask-values` given there rather than in an `@FILE`
  (from reading the code). Never the SOCKS5 password, the tokens or mitmweb's
  password: those go in 0600 files.
- **`--local-proxy`.** Its port takes any user's requests, and records those
  to allowed hosts as `local` ([its security details](#security-local-proxy)).
  mitmproxy's SOCKS5 port and mitmweb's are on 127.0.0.1 too, behind their
  passwords ([below](#security-other-processes)).
- **The node's ports**, when this computer itself is on your tailnet as you.
  The node tells devices apart, not this computer's users, so another user's
  programs here come to `--ui`, `--web` and `--mcp-http` as one of your own
  devices, and to the exit node and the Remote Proxy when this computer is a
  `--device`. The tokens are what keep them out of the first three (from
  reading the code; not tried with a second user).
- **What you write outside the state directory.** A HAR file gets your
  shell's mode, usually readable by others, and `/tmp` is everyone's.
  `(umask 077; reqcove har > FILE)` makes a new file 0600 (tried with zsh).
  A service's file (the LaunchAgent, the systemd unit) is 0644: it holds
  paths, no token (from reading the code).

<a id="security-other-processes"></a>

### Other processes on this computer

The password on mitmproxy's port, and what is not covered:
[SECURITY](SECURITY.md#other-processes-on-this-computer). How the port is
held:

- **The port stays Reqcove's.** Reqcove binds it itself, once per `run`, and
  hands the listening socket to each mitmdump it starts. mitmproxy (12.3.1)
  has no option for that, so Reqcove's launcher (`mitm.py`, also used with
  another `--mitmproxy-spec`) has it serve on that socket instead of binding
  its own. When mitmdump dies, Reqcove starts it again (visible in `ps`)
  while the port stays held: no other process can take 127.0.0.1 on that port
  in between, nor before the first mitmdump.
- **Connections made meanwhile wait** in the socket's queue for the next
  mitmdump. The devices' connections wait (15 seconds at most, then fail)
  until its addon says hello.
- **A connection queued there must not be read before the addon is
  loaded**: mitmproxy runs with `proxyauth=any` and only Reqcove's addon
  checks the password. So the launcher has mitmproxy make its server on the
  socket without accepting, and the addon starts accepting when it is loaded,
  just before its hello.
- **Were the launcher's change missed** (a mitmproxy that binds another
  way), its own bind fails on the held port and it exits before its hello,
  never ready.
- **Another user was not tried.** As both kernels document it (not checked
  here), a second socket gets that address only if both set SO_REUSEPORT (on
  Linux, only for the same user), which Reqcove's never does.

Checked: tests with real mitmproxy on macOS, and a unit test that CI on Linux
runs too.

- Through uvx only: connections queued while mitmdump is down, with a wrong
  password sent all at once and step by step, are refused, and nothing is
  carried or recorded.
- From the lock and through uvx: the port cannot be bound while mitmdump
  restarts, and a request sent then is recorded by the next mitmdump.
- The unit test: the port cannot be bound while mitmdump is down or after a
  failure that ended it; Stop frees it.

Tried by hand on macOS, as the same user:

- Binding 127.0.0.1 on the port fails even with SO_REUSEADDR and
  SO_REUSEPORT. Binding 0.0.0.0 works with SO_REUSEADDR, but connections to
  127.0.0.1 still reach the more specific socket, Reqcove's.
- The queued-connection test fails when the launcher accepts at once and the
  addon loads 1.5 seconds late. Without that delay, mitmproxy happened to
  load the addon first.
- A launcher change made too late ends in "address already in use".

<a id="security-mitmproxy-code"></a>

### mitmproxy's own code

The lock, when hashes are checked, and the one version the lock overrides:
[SECURITY](SECURITY.md#mitmproxys-own-code). Beyond that:

- The lock file is `internal/capture/mitm.py.lock`. `run` writes it and a
  small launcher into the state directory.
- A `--uvx` whose file is not named `uvx` is a wrapper, whose `uv` is not
  known. Plain `uvx`, used for it and for another `--mitmproxy-spec`, takes
  releases from before a fixed date (`--exclude-newer`).
- CI also checks that the lock matches the launcher.
- Through a `--uvx` wrapper, the default mitmproxy gets the lock's override
  too, with tornado from the lock's date: 6.6.1, its hashes unchecked.
- Another `--mitmproxy-spec` gets the tornado its mitmproxy asks for,
  without the override (from reading the code): for mitmproxy 12.3.1,
  6.5.10, whose vulnerabilities are in mitmweb's server, which `--web` runs.

Checked: tried (a lock with one package's hashes changed was refused, with an
empty cache and with a full one; `uvx` given hashes checked none; mitmproxy
12.3.1 as another `--mitmproxy-spec` got tornado 6.5.10). Tried on 2026-11-14
with uv 0.13.4: through a wrapper the other packages came at the lock's
versions, and the `--web` tests passed. Reqcove's `--web` test passes with
tornado 6.6.1.
