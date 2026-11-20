# Changelog

## Unreleased

### Added

- **The devices the exit node refused.** A device on the tailnet that picks
  this exit node but is not in `--device` gets nothing carried, yet its names
  still resolve (from reading Tailscale's code), so it looked online and
  reached nothing; only `--verbose` logged it. `reqcove status` and the `status` tool now name the devices
  refused this run, through the exit node or the Remote Proxy, by machine name
  (`refused_devices`, the last seen first, at most 50, then
  `refused_devices_more`; an address when the tailnet no longer lists it), with
  a next step: add it to `--device` and restart `run`. `run` logs each new set
  once. Counted from refused TCP connections alone: a device that sends only
  UDP (QUIC) or pings is not named. Refusing them is unchanged. `--ui`'s page
  for another user's device does not show them. Any device's owner chooses
  its machine name, so it reaches what agents read
  ([SECURITY](docs/SECURITY.md)). Tried: unit tests, and two tsnet nodes on a local control
  server (a device not in `--device` going out through the exit node). Not
  tried on an iPhone.

## v1.3.1 — 2026-11-17

### Fixed

- **`reqcove console`'s page asks in the page.** Its confirms (a setting
  marked confirm, Save, Restart…, Restart with mitmweb, Allow all, Remove,
  Stop recording, a preset turned on, the HAR file before a restart) were the
  browser's own dialog. With the page auto-opened by `reqcove console` in Arc,
  it answered no without showing: Save did nothing. Opened by hand from
  `--print`'s link in Arc, Safari or Chrome, it showed. Each is now one dialog
  of the page's own (an HTML `<dialog>`, modal: the page behind it waits),
  centered, in the page's light or dark colors, in the same words, with Cancel
  and the action button. Esc and Cancel cancel; Cancel has the focus, so Enter
  cancels too and the action takes a click. `run`'s checks are the same. Each
  answer, and "Sending…", "Saving…" or "Restarting…" while it is asked, shows
  under the row of the button pressed (under the list for a list's buttons),
  not only at the panel's end. A setting's control shows the value the file
  gives (its last, as `run` reads it; `1` or `t` as `true`), else the default,
  and again after a Cancel: with the dialog answering no unseen, the `--ui`
  choice kept `false` under a value `true`. Tried: unit tests (no browser
  dialog left in the page's code, the `<dialog>` there), and in headless
  Chrome against a stand-in for `run`: the old page with the dialog
  answering no (the choice left `false` under `true`, nothing sent, nothing
  said), and the new one, with real clicks and keys: the words,
  buttons and answer of `--ui`'s Save, Remove, Save, Stop recording, Allow
  all, a preset turned on, Restart…, and Restart with mitmweb through the HAR
  offer and a failed HAR file; Esc, Cancel and Enter cancelling (nothing
  sent, the choice put back), a click behind the dialog doing nothing, Cancel
  having the focus, the dialog centered in light and dark, the revision and
  values sent, "Sending…", "Saving…" and "Restarting…" in flight. By hand on macOS
  with a real `run`: the page auto-opened by `reqcove console` in Arc showed
  the dialog each time, `--local-proxy`'s Save asked in it, and Cancel wrote
  nothing. Not tried: the other confirms by hand (a passed host's Remove, a
  device or masked name added or removed, Clear, Discover).

## v1.3.0 — 2026-11-17

v1.3 makes `reqcove console` the place to see and change a running `run`
(the hosts, the settings, the agents' requests, a restart), adds a page for
your own devices on the tailnet, and `reqcove restart`. What the page shows
and how it talks to `run` are not stable ([COMPATIBILITY](docs/COMPATIBILITY.md#not-stable)).
Walked by hand on 2026-11-17 (macOS, a desktop browser on the Mac, the
iPhone's Safari, an Ubuntu 24.04 VM): this computer's page and parts of its panels,
`reqcove restart` in a terminal and under `reqcove service install`'s
launchd and systemd services, the tailnet page in the iPhone's Safari over
the exit node and through the Remote Proxy; each entry says what. After
the release (macOS): `brew upgrade` from v1.2.0 to v1.3.0 under `brew
services`, `brew services restart`, and `reqcove restart` under it. Not
tried: `reqcove restart` after a `brew upgrade` from one v1.3.x to a later
one, another user's or a tagged device on the tailnet page, Safari on the
Mac, a 5th session.

### Added

- **`reqcove restart`** (in a terminal only) restarts the running `run`
  in the same process (an exec: launchd, systemd and brew services see the
  same process; seen under launchd, systemd and brew services). Before anything stops, it checks
  the config on disk and the command line as the next start reads them, that
  the binary `run` was started from (its path as started, links kept:
  Homebrew's `opt` path) is still there, and then asks that binary itself
  (a hidden check mode, `run --check-config`: it starts nothing, takes no
  lock, writes no file), so a newer binary after `brew upgrade` that checks
  more refuses too; a binary without the mode (older than v1.3, which could
  not take over the state) is refused. Refused, nothing stops, and it says why. Then it stops
  as Ctrl-C does (system proxy put back, mitmproxy, the node and caffeinate
  stopped) and starts again. The state's lock and the `reqcove console`
  page's port and sessions (as hashes) are carried across, so no other run
  takes the state and an open page stays open. A start that fails puts back
  the config `run` had started from (kept from its start, in memory, then in
  a 0600 file in the state directory; not `config.prev`), keeps the failed
  one as `config.failed`, and starts once more; failing again, it stays
  down; `reqcove status` says what happened. A start counts as good once it
  is ready, or 2 minutes after it serves its tools. A stop (Ctrl-C, a
  service's SIGTERM) during the restart or the new start is a stop: no exec,
  nothing put back. A new ctl op, `restart`, in LAN
  mode too; a `run` older than v1.3 says to stop it and start it again. Unit
  tests (an exec of a test binary among them) and an E2E test with real
  mitmproxy (LAN mode on the loopback); by hand (2026-11-17): in a terminal
  (the pid, the page's port and session kept; a rebuilt binary taken), a
  failed new start (`--uvx=/usr/bin/false` in the config: the config put
  back, `config.failed` kept, `status`'s `restart:` line, the page's session
  kept), Ctrl-C during the new start (stayed down, the config untouched, no
  copy left), under `reqcove service install`'s services: launchd's,
  restarted from the page (the same pid, no exit seen by launchd), and the
  systemd user service on Ubuntu 24.04 (the same MainPID, NRestarts 0; `systemctl --user
  stop` during a restart: stayed stopped, the config unchanged, no
  `config.failed`), and another OS user there retrying to bind the page's
  port throughout a restart never got it; after the release, under brew
  services (after `brew upgrade` from v1.2.0 and `brew services restart`):
  the same pid in `launchctl list`, exit status 0, the restart exec'd
  `/opt/homebrew/opt/reqcove/bin/reqcove`, and again after `brew cleanup
  reqcove`, still v1.3.0; not tried: after a `brew upgrade` from one v1.3.x
  to a later one (the running version's Cellar gone).
- **mitmweb for one start: `reqcove restart --web`**, and the
  `reqcove console` page's **Restart with mitmweb (this start only)…** (this
  computer's page alone; the tailnet page has no such button and `run`
  refuses a restart from it, directly or through the Remote Proxy). The new
  start runs with `--web`, that start alone: the choice crosses the exec in
  the environment (unset at start), never in the config, where `--web` stays
  refused, or in the start config's copy. A failed start's retry, and the
  next restart of any kind (the page, `reqcove restart`, the service, a
  reboot), start without it; `--web` on `run`'s command line stays on as
  before. Before anything stops, the restart's checks are made with `--web`
  (`--proxy-port 8081` refused; LAN mode allowed, mitmweb on 127.0.0.1
  there; the binary's `run --check-config` given `--web`). The new start
  makes a new `web-token`, so earlier links stop working. The page asks
  first in words of its own (unmasked flows with bodies, up to 256 MB in
  memory; editing, replaying and scripts, which run code here; where it
  opens; where its link is; this start only), and the restart's list shows
  `+ --web (this start only; unmasked)`. `reqcove status` (`mitmweb: on —
  unmasked; this start only` or `from the command line`), the MCP `status`
  (`mitmweb`, `mitmweb_this_start_only`: booleans) and both pages say it is
  on, never its link or password. Unit tests and the E2E restart test with
  real mitmproxy (LAN mode); by hand (2026-11-17): the page's button, its
  confirm, `mitmweb: on — unmasked; this start only` on the page and in
  `reqcove status`, mitmweb opened from the iPhone over the tailnet, and a
  plain Restart… dropping it; not tried: under a service.
- **`reqcove console --end`** (in a terminal only, as `console`) ends every
  session of the pages and every link not opened yet; the pages say so, the
  links say they were ended. A new ctl op, `console-end`, in LAN mode too; a
  `run` older than v1.3 says to restart it with v1.3. Unit tests; by hand
  (2026-11-17): it ended the page open in the browser.
- **The `reqcove console` page's Scope panel** (127.0.0.1 alone) changes
  the hosts as `reqcove capture` does (`run` checks each again; LAN mode
  refuses them): add and remove (with "pass undecrypted"), stop and start,
  allow-all and discovery for 30 minutes to 24 hours with End and the time
  left, discovery's names (host names alone, at most 30) each with Add, and
  Save. Never `capture set`, `reload` or `restart`: the page's endpoint takes
  its own changes alone. Stop, remove and allow-all first show `reqcove
  capture`'s own warning, then ask. Save first shows what it would write
  (each hosts file now and once saved, the pinned hosts, and on a config
  without `--allow-hosts=@FILE` the file it creates and the line it adds)
  and writes only that; hosts not saved yet are marked "unsaved". A change
  made on a page that read the hosts before another change (another tab, the
  CLI) is refused. Changes are traced "(from the console on this computer)"
  (the log, a `cli` marker, `scope_change`). The page keeps v1.2's guards on
  its new endpoints. Unit tests and an E2E test with real mitmproxy; by
  hand in a browser (2026-11-17): add, remove, a host "unsaved", Save on a
  config with its hosts inline (the line added, the hosts file made 0600,
  `config.prev` kept, the change listed in the confirm), Save refused after
  another tab added a host and after an edit by hand to the hosts file
  between the confirm and OK (nothing written); not tried there: stop and
  start, allow-all, discovery.
- **The `reqcove console` page's Settings panel** (127.0.0.1 alone): writes
  `--device` (picked among your own untagged devices on the tailnet, as
  `run`'s node sees them; written as the StableID), `--keep-awake`,
  `--proxy-port`, `--hostname` and `--verbose`, and, once it showed
  `run -h`'s words for the flag and asked, `--ui`, `--mcp-http`,
  `--local-proxy`, `--dns`, `--upstream-proxy` (a URL, no user or password),
  a `--device` added and `--mask-names`, to the `--config` file for the
  next start, through the config writer alone (below); `--upstream-ca` may
  be taken out. Shown, never written: `--upstream-ca`, `--rules` and
  `--proto` (their paths), `--mask-values` ("set" and a count, never a
  pattern), a masking `@FILE`'s contents, the settings given on `run`'s command
  line (pinned), and every setting of a run started from flags alone.
  `run`'s log names the flag written, never its values. **Restart…** lists
  every setting the config on disk has otherwise than `run` started with
  (edits by hand and terminal-only flags included; `--mask-values` and a
  masking `@FILE`'s contents as "changed" alone; a hosts file's hosts now
  against when `run` last read or wrote them) and the records it empties,
  offers the HAR file first, asks, and restarts as `reqcove restart` does;
  an edit after the list was shown, to the config or a hosts or masking file
  it reads, is refused, nothing stopped. Unit tests; by hand in a browser
  (2026-11-17): `--keep-awake` written and Restart… with its list, a change
  in the hosts file alone shown in that list, a run from flags alone
  read-only; not tried: the other settings, the device list.
- **The `reqcove console` page's other panels** (127.0.0.1 alone):
  **Presets and rules**: the `--rules` file's presets by name and kind,
  whether each is on and until when, each turned on for 1 to 5 minutes (a
  mock for a count too) or off, as `activate_preset` and `deactivate_preset`
  make them (refused while recording is stopped, as there); the page first
  says what the preset's kind changes, and for a `map_remote` preset where
  the requests then go (a scheme and host alone; anything else "not shown"),
  which goes back with the request: a destination changed since is refused.
  The rules by kind, index and preset name, never a value (no URL, filter,
  header, body, address, path, description or the file's error text). A
  **marker** (source `console`). The **CA**: its name, SHA-256 fingerprint,
  expiry, a QR code of http://mitm.it, and how to add it on an iPhone and
  remove it (the public certificate's fields alone). **Save the records as
  a HAR file**: what `reqcove har` writes, fetched with the session header
  and saved from a blob (never a token in a URL), as an attachment of
  `application/json`, `nosniff`, `no-store`; refused while `run` masks
  nothing (`--no-redact`); the page says where the file lands. **This
  run**: the service's commands, and with `--ui` a link to its page's bare
  address (never its token). Presets turned on or off and HAR files are
  logged "(from the console on this computer)". Unit tests and an E2E test
  with real mitmproxy (presets and rules); by hand in a browser
  (2026-11-17): a marker, the HAR download (the browser renamed the file);
  not tried in a browser: the presets, the CA, This run.
- **`reqcove console --tailnet`** (in a terminal only; refused in LAN mode
  and on a tagged node) opens a second page, for your own devices on the
  tailnet: a QR code and `http://100.x.y.z:PORT/#c=CODE` in the terminal
  alone (no browser opened, no file), a one-use code for 60 seconds, on the
  node's tailnet IPv4 address and a port of its own (not `--ui`'s 80). It
  serves what ends with the run: the state without this computer's paths,
  Approve and Deny, the Scope changes but Save (discovery's names as a count
  alone), presets on and off, the rules by name, a marker and the CA panel;
  `run` refuses Save, the settings, the restart and the HAR file there. Every
  request is checked from its connection, never a header: one of your own
  devices (your user's, untagged; another user's, a tagged or a shared-in
  device refused, even one `--device` carries), as the tailnet is now (a
  device retagged is refused on a kept-alive connection), the device that
  traded the code (its session refused from another), the exact Host (the
  address and port; a MagicDNS name refused) and, when sent, its own Origin
  (`--ui`'s refused). Sessions last 1 hour unused and 12 hours in all, are
  its own (this computer's page's codes and tokens refused, and the
  reverse), end with `run` (not carried across `reqcove restart`) and at
  `reqcove console --end`; `reqcove status` counts them by page and device
  (`console_sessions`, on this computer only, not stable). Changes are
  traced "(from the console on NAME, over the tailnet)". With the iPhone's
  Wi-Fi proxy set to the Remote Proxy, the page's requests are served by the
  Remote Proxy itself, in-process, with the page's own handler and checks
  (who calls: the proxy's client, from its connection; a forwarded header
  counts for nothing), for your own devices that `--device` carries; never a
  reverse proxy, never through mitmproxy, so no flow, under allow-all too. A
  tunnel (CONNECT) to the page's port is refused; the local proxy and LAN
  mode never serve it. Unit tests, real tsnet nodes (the listener's address,
  another user's device refused, a connection's address the peer's) and E2E
  tests with real mitmproxy (the Remote Proxy under allow-all among them);
  by hand in the iPhone's Safari (2026-11-17), over the exit node and through
  the Remote Proxy: the state without the Mac's paths, a host added, an
  agent's request approved, allow-all on and End, and `reqcove restart`
  ending its session (a new QR code needed); not tried: another user's or a
  tagged device, presets, a 5th session.
- **`reqcove capture save` on a config with its hosts inline** (v1.0's
  setup, or one written by hand): the first save shows what it would do and
  asks y/N, then creates the hosts file beside the config (`hosts`; 0600,
  created anew, never over a file or link there: refused, naming the file
  and the choices) and adds one line, `--allow-hosts=@FILE`, at the config's
  end; no other line changes, the config before is kept as `config.prev`
  (0600), and a config write that fails removes the file created. The hosts
  inline stay there, never written to the file. `run` takes the new file at
  once: a second save writes it, and `reqcove status` and the page name it
  (before: after a restart; a `reqcove reload` that changes the hosts files
  too, from the code, not tried). The same for the hosts passed undecrypted
  (`pass-hosts`, `--pass-hosts=@FILE`), which are saved now. A new field of
  the ctl op `save`, `confirm` (the token of the change and of the config
  and hosts files as read: an edit to one since it was shown refuses the
  save, and a hosts file changed since it was read is never replaced). Unit tests and an E2E
  test (Save from the page); Save from the page by hand (above).
- **A config writer**, the one way `capture save` and the page change the
  `--config` file: it writes only the flags of a fixed list, each value
  checked (no line break, control character or leading `@`), never through
  a link nor to a file not yours, the file read back as the old flags plus
  the change, its revision checked before the rename, the whole flag set
  checked first as the next start reads it, the file before kept as
  `config.prev` (0600). Unit tests.
- **`reqcove status` names the other `reqcove` executables on PATH**
  besides this one ("other reqcove on PATH: /opt/homebrew/bin/reqcove (your
  shell runs the first one; `type reqcove`)", among the next steps): only
  executable files (a directory or a file that cannot run is skipped), by
  their symlinks resolved (this binary through a symlink is not another; one
  file found twice is named once), none of them run. The text uses your
  shell's PATH and this binary; `status --json` and `status` (on this
  computer only, never over `--mcp-http`) give `run`'s, from `run`'s own PATH
  (a service's may differ). Unit tests.

### Changed

- **`reqcove setup` always writes `--allow-hosts=@FILE`** and the hosts file
  beside the config, a file of comments alone when no host is answered
  (before: a commented-out line and no file), so `capture save` and the
  page's Save write it later. It checks the config and the hosts file it
  would write as the next start reads them, and writes nothing (no `.old`
  either) if that start would refuse them. Where the Tailscale CLI answers
  on this computer, it lists your own untagged devices to pick by number,
  iPhones first; a name can still be typed. Unit tests; v1.3's setup was not
  tried by hand.
- **A hosts file without hosts** (comments only, or empty) is taken, giving
  none; it was refused ("has no hosts"). `--mask-names` and `--mask-values`
  `@FILE`s without lines are still refused. `--pass-hosts`, `--rules` and
  `--upstream-proxy` need hosts recorded by the hosts given, not by the flag:
  an empty `--pass-hosts` file with no `--allow-hosts` is taken. `capture
  save` may leave a hosts file without hosts when the next start would still
  take the flags it leaves (checked first, without side effects); a save
  leaving none with `--rules` is refused. Unit tests.
- **`run -h`'s words** (which the page's confirm shows) say who reads more:
  `--upstream-proxy`, that the proxy reads the decrypted requests unmasked;
  `--mask-names`, that a name taken out leaves its values unmasked;
  `--device`, that a device's requests are decrypted and recorded for the
  agents; `--mcp-http`, that its agents and their model providers read the
  records; `--ui`, that whoever has its link reads them. Unit tests.
- **A marker's `source` may be `console`** (`list_markers`): one put on the
  `reqcove console` page. `get_capture_request`'s `approved_in` may be
  `console on NAME (tailnet)`.
- **caffeinate** (`--keep-awake`) is stopped when `run` stops, not left to
  end with `run`'s process: a restart keeps the process. E2E test.
- **Own devices: a sharee node is left out by its own flag** too (one in
  the netmap only because Reqcove's node is shared with its owner), not only
  by its user, for `--ui`'s every-device view, `--mcp-http`, the console's
  device list and its tailnet page; no change expected, as such a node is
  another user's. A unit test.
- **The skill and the server's instructions** name `reqcove restart` and
  `reqcove console` (`--tailnet`, `--end` and `--print` too) among the commands agents
  never run, with `setup` and `capture` as before; an agent may still ask
  for a host with `request_capture_add`, which the user may now approve on
  the console's page too. Nothing else of v1.3 changes what an agent does.
- **`reqcove console` prints the link only when it did not open it**: once
  the browser opened the page, it prints neither the link nor its code, but
  a line saying the link works once and how to get one to open by hand
  (found walking v1.3: clicking the printed link after the browser opened
  used the code twice, which ends every session of the page, the one just
  opened too). When the opener fails, or against a v1.2 `run` (no file), it
  prints the link as before. **`reqcove console --print`** (new) prints a
  link and opens nothing, for another browser or one that cannot read the
  state directory; it removes the file `run` wrote for it at once. `run`'s
  first line no longer says to open the link within 60 s, which read wrong
  once the browser had opened it: it says the link works once, within 60 s,
  for both. In a terminal only; refused with `--end` or `--tailnet`.
  Unit tests; by hand (2026-11-17): no link once the browser opened, one
  with `--print`.

### Fixed

- **The Remote Proxy drops a URL's `#fragment`**: iOS sends it to an HTTP
  proxy, so the tailnet page's link (`#c=…`) through the Remote Proxy got
  `404 page not found` (found trying it in the iPhone's Safari), and a
  fragment (a token in it, say) went on to the site. Now the request-target
  of a plain-HTTP request through the Remote Proxy (and the local and LAN
  proxies) is cut at its first `#` and read again: nothing after it reaches a
  page, a site or mitmproxy (a `?` inside the fragment too), and an escaped
  `%23` in a path is kept. Requests inside a CONNECT tunnel are not touched
  (whether iOS sends a fragment there was not checked).
- **Found by the review before v1.3's release** (none of it was released):
  a restart's retry carried the page's sessions handed over at the restart,
  so one ended by `reqcove console --end` meanwhile came back (now the
  page's sessions as they are; the ones handed over if it never served); a page carried
  across a restart served before its sessions were in place (a poll then
  got 401); a restart asked as `ctl.sock` began serving was refused; a
  binary older than v1.3 was restarted into and stayed down (now refused,
  nothing stopped); Ctrl-C or a service's SIGTERM during a restart was
  ignored, or taken as a failed start (config put back, exec'd again); a
  restarted run that never got ready kept the start config's copy and could
  put it back hours later; Save's confirmation and the page's restart did
  not see an edit to a hosts file (or a masking file) made after they were
  shown; the tailnet page could keep the tail of a path with a space in a
  next step. Unit tests for each.
- **The `reqcove console` page's words** (not released): pinned hosts said
  once in Save's confirm, results beside their buttons, "(not set)" in the
  restart confirm, "restarted at …" once the new start answers, the HAR
  name "offered", the ended text (a restart keeps the sessions), and a run
  from flags alone: a failed restart stays down, Settings show the command
  line's. Unit tests for the Go texts; the page's from the code, not
  checked one by one in a browser.
- **A computer whose name is long** (over 39 characters, GitHub's macOS
  runners among them) could not start a `run` that makes its own CA: the
  CA's name (`Reqcove CA (<computer>, <date>)`) went over X.509's 64
  characters and mitmproxy refused it ("making the CA: exit status 1"; a
  GitHub macOS runner's name made it 86 characters). The computer's name in
  it is cut to 39 characters. Unit test; the E2E test of `reqcove restart`
  on CI's macOS.
- **Tests only:** `TestMaskingLinear` (a timing ratio) failed now and then on
  CI's loaded macOS runners with a linear input (x25 and x26.5 against a x24
  bound; once x78 while the whole package ran 491 s instead of about 180):
  when allocation grows linearly the time bound is x32, and a time-only
  failure is measured again, both sizes back to back, up to 4 times; a
  quadratic input still takes about x64. `TestRestartE2E` takes its LAN port
  in 20000-29999, below Linux's and macOS's ephemeral ranges (a port picked
  with `:0` and closed was taken by another test's connection before `run`
  bound it).

### Security

- **`reqcove console` no longer gives the link with its code to `open` or
  `xdg-open`**, whose arguments `ps` shows other users of this computer
  (v1.2 did, for a moment). `run` writes a file in the state directory
  (0600, created anew, never through a symlink, a random name) that sends
  the browser to the link; `reqcove console` opens that file, and prints
  the link only when it could not (or with `--print`, above). `run` removes the file after 60 seconds, at `--end`, and when
  it ends and starts; the code's 60 seconds stay `run`'s, as before. Against
  a v1.2 `run` (no file) it opens nothing and prints the link alone; a v1.2
  `reqcove console` still passes the link in the opener's arguments: update
  both. Unit tests; the link's `#c=` kept through the file in headless
  Chromium and Firefox (not tried: Safari).
- **The console's session header (`X-Reqcove-Session`) is masked in any
  record, with `--no-redact` too**: it is Reqcove's own credential, and
  `--no-redact` otherwise masks nothing. The tailnet page's requests never
  reach mitmproxy (the Remote Proxy serves them in-process); this is a second
  guard. Nothing to do. Unit tests.

## v1.2.0 — 2026-11-16

### Added

- **`reqcove run` with arguments but without `--device` or `--config`**,
  while the file a bare run reads is there: the error says that file is not
  read when run has arguments, and to add `--config FILE`. Unit test.
- **An agent asks, you approve: `request_capture_add`** (a tool of
  `reqcove mcp` alone, never `run`'s socket nor `--mcp-http`) asks for 1 to
  5 host names to be recorded; it records nothing itself. `run` keeps the
  request (an id, the hosts fixed, 10 minutes by either clock, dropped at a
  restart; 3 pending, 10 made in 10 minutes; the same hosts asked again give
  the same request; refused when all are recorded already, passed
  undecrypted, or in LAN mode, and when any host in it was denied in the last
  10 minutes, alone or with others). **`reqcove capture requests`, `capture
  approve ID`** (shows the hosts, asks y/N) **and `capture deny ID`**, in a
  terminal only; an approval adds exactly those hosts as `capture add` does
  (not saved, never starts a stopped recording). A client that declares MCP
  form elicitation also gets a dialog with Reqcove's text alone and one box,
  "Record these hosts", off at first (accept with it ticked approves, so
  Enter on Accept alone does not; decline, close, accept without the box or
  2 minutes without an answer leave it pending;
  over MCP's newest protocol its answer counts only for a dialog shown on
  that connection, once, within 2 minutes by either clock).
  Every view of a request says `unmasked` under `--no-redact`.
  `get_capture_request` says what came of it; `status` (on this computer)
  gives `capture_requests`, `reqcove status` "asked:". Traced in `run`'s log,
  and on approval as a marker with source `mcp` and `scope_change`. Unit and
  E2E tests; a real client's dialog not tried.
- **`reqcove console`: the state and the agents' requests in a page.** In a
  terminal only, it asks `run` (a new `ctl.sock` op) for a page on 127.0.0.1
  alone (a port the system picks, kept until `run` ends) and a one-use code
  good for 60 seconds, prints `http://127.0.0.1:PORT/#c=CODE` and opens it
  (`open`, `xdg-open`). The page trades the code for a session token sent
  as a header (no cookie; at most 4, ended after 12 hours idle and at
  `run`'s end; a code used twice ends them all) and shows what
  `reqcove status` shows, refreshed every 5 seconds, and the requests
  waiting with Approve (as `capture approve`, for the hosts asked only;
  traced "approved in the console", `approved_in: console`) and Deny. Never the
  flows, a token or link, or an agent's text. Exact Host, same Origin, JSON
  POSTs, no CORS, CSP `default-src 'self'` and `frame-ancestors 'none'`,
  `no-store`. A `run` older than v1.2 says to restart it. Unit and E2E
  tests; not tried in a real browser.
- **`--keep-awake=always|ac|never`** (macOS; in the config file too): what
  `run` does about sleep. `always` is the default and v1.1's behaviour
  (`caffeinate -i`: no idle sleep, on battery too); `ac` holds it on AC power
  only (`caffeinate -s`); `never` holds nothing (the Energy settings decide).
  `reqcove status` shows it ("keep awake:"), and `status` (on this computer)
  gives `keep_awake`; `reqcove reload` names it as needing a restart. Unit
  tests; a real sleep not tried.
- **`reqcove status` names `run`'s binary when it is not this one**
  ("binary:"), even at the same version: a `reqcove` built from source and
  Homebrew's on one Mac run whichever PATH finds first. `status` (on this
  computer only) gives `executable`. Unit tests.

## v1.1.0 — 2026-11-16

### Added

- **`reqcove capture discover --for D`** (at most `24h`) **and `capture
  discover --end`** (`--state DIR`): for a while, the names of the hosts
  outside the ones recorded that the devices reach (a TLS connection's SNI,
  the Host of a request on a connection decrypted but not recorded) and how
  often, never what they carry, a URL path or a time, to find the hosts an
  app talks to. Shown in `reqcove status` ("outside:", each with the
  `reqcove capture add HOST` command, built by Reqcove for plain host names
  only) and to this computer's agents (`status`: `out_of_scope_hosts`,
  `out_of_scope_hosts_kept`, `discover_until`, `discover_left`; `summarize`:
  `out_of_scope_hosts`), never over `--mcp-http` nor on the `--ui` page.
  Apple's hosts and mitm.it left out, names masked, 1,000 kept (the least
  seen giving way), 30 shown, a host added dropping off. Ends as allow-all
  does (either clock; the records take no name more at the end, whether
  mitmproxy answers or not); the names stay until `run` restarts or
  discovery starts again. Not exhaustive: no name (an address dialed), ECH
  (the outer name only), non-TLS connections outside the scope (from
  reading the code). Off, it reads nothing (from reading the code); on, each
  TLS ClientHello is read once more (mitmproxy reads it anyway for
  `allow_hosts`; about 22 µs for 1.5 KB in a micro-benchmark on an M1 Max).
  A run with `--allow-hosts '*'`: "nothing changed". The same guards as the other `capture`
  commands. SECURITY's "counted, never recorded" says what changes while it
  is on; the skill and the server's instructions: the names are data, the
  commands the user's. Unit tests (the Store's gate, filters, masking and
  bound; the end by either clock with mitmproxy silent; the arguments; the
  two servers: names in the local summarize alone) and an E2E test with real
  mitmproxy (SNI and Host counted, once a connection, none of Apple's,
  nothing recorded, not in what `--mcp-http` and `--ui` read, none before or
  after, an added host dropping off). Not tried on an iPhone.

- **`reqcove reload`** (`--state DIR`): reads `run`'s config, the hosts files
  it names (`--allow-hosts=@FILE`, `--pass-hosts=@FILE`) and the `--rules`
  file again, and puts their hosts and rules in force together, without a
  restart. Everything is checked first, the rules against the new hosts (a
  host and the `mock` naming it go in or out in one edit), and on any failure
  nothing changes and the answer says why. The answer says what changed,
  which changes made with `reqcove capture` and not saved it replaces, how
  many rules of each kind loaded (presets go off: new rules turn them off),
  and in one line the other settings that changed, which take a restart
  (names only, never values). A run from flags alone has "nothing to
  reload". The same guards as `reqcove capture` (a terminal only, refused in
  LAN mode, an older run named, the trace: `scope_change` `reload`).
  `--rules-reload` works as before. `reqcove setup`'s last lines name it.
  Unit tests (the parse of `run`'s arguments again never exits, logs or
  dials `--upstream-proxy` (that it sets no mask policy and loads no
  `--proto` is from reading the code); every flag of `run`
  reloaded or named; nothing to reload) and an E2E test with real mitmproxy
  (a host and its mock added together, then a broken rules file changing
  nothing, its hosts file's edit included, then both taken out; an unsaved
  add named; a preset off; `--mcp-http` named). Not tried on an iPhone or
  with a service.

- **`reqcove status` says what runs, and how to restart it after an
  update.** The running `run`'s version against this `reqcove`'s (from
  `serverInfo`, so a v1.0.0 `run` too), and when they differ the one command
  that restarts it under what started it (`brew services restart reqcove`,
  `reqcove service restart`, `reqcove service install` when its service runs
  another binary, or Ctrl-C in its terminal), with "a restart empties the
  records: `reqcove har > flows.har` first" and "while it is down, a phone
  using its exit node has no internet". It also says what started `run`
  (none: a terminal), the config and hosts files it read, and warns when two
  services for reqcove are installed at once (`reqcove service install`'s and
  Homebrew's) or when `reqcove service install`'s service runs a binary that
  is gone or is not this one; read from the service files only, never from
  launchctl or systemctl. The `status` tool and `--json` get `version`,
  `manager`, `restart_command`, and on this computer only `config_file`,
  `config_unused` and `hosts_files`; the warnings come in `next_steps`. On
  Linux, Homebrew's unit is told from the process' cgroup (not tried). Unit
  tests (each case, against a faked v1.0.0 `run` and with service files in a
  temporary home); not tried by hand.
- **`reqcove run` with no arguments at all** (refused before) reads
  `~/.config/reqcove/config`, else Homebrew's `etc/reqcove/config` when this
  `reqcove` is Homebrew's, and says which in its log; with both there, the
  first, and `reqcove status` names both. Any argument: as before, a file
  only when `--config` names it. Unit tests.

- **`reqcove capture allow-all --for D`** (at most `24h`) **and `capture
  allow-all --end`** (`--state DIR`): record every host for a while, as
  `--allow-hosts '*'` does, without a restart, to see what the other apps
  send. Apple's hosts and the `--pass-hosts` ones still pass undecrypted; the
  `--rules` file's rules apply to the hosts allowed alone (a `modify_headers`
  rule naming no host is not sent to the others). It ends by the wall clock
  or `run`'s monotonic clock, whichever comes first (a sleep does not extend
  it), within about a second, and fails closed: the records first, then
  mitmproxy, which is restarted without it if it does not answer; a restart
  of mitmproxy keeps it until its end only, a restart of `run` ends it. The
  records made meanwhile are kept after it ends. The answer repeats `'*'`'s
  warnings (every app's traffic readable by agents and their providers;
  pinned apps such as banks fail meanwhile; `--upstream-proxy`,
  `--mcp-http`, `--web`, `--local-proxy` when on). `--for` again moves the
  end; `capture stop` ends it; refused while stopped; `capture add`,
  `remove` and `set` meanwhile change the hosts recorded after it. `status`
  gets `recording` `allow-all`, `allow_hosts` `["*"]`, `allow_all_until`,
  `allow_all_left` and `records_outside_scope` (the records kept of hosts
  outside the ones recorded); `capture_stats`' `recording` too; `next_steps`
  gives the time left and `reqcove capture allow-all --end`; `explain_rules`
  says no rule applies to the other hosts. Same rules as the other `capture`
  commands (a terminal only, refused in LAN mode, an older run named, the
  trace; the end by time leaves a log line and `scope_change`). Unit tests
  (the duration's bounds, mitmproxy's arguments, a stop ending it, an add
  changing the base, the end by either clock with mitmproxy silent: the
  records narrowed first, mitmproxy killed) and E2E tests with real
  mitmproxy (a host outside the base recorded with no rule applied, not
  after the end, its records kept; a `--pass-hosts` host undecrypted;
  mitmproxy killed just before the end comes back without it; the CLI's
  answers, status and markers). Not tried on an iPhone, nor across a real
  sleep.
- **`reqcove capture save`** (`--state DIR`): write the hosts recorded now
  (the base scope, while stopped too) into the hosts file `run` read them
  from (`--allow-hosts=@FILE`), for the next start. `reqcove setup` now writes
  the hosts to their own file beside the config (`~/.config/reqcove/hosts`;
  Homebrew: `$(brew --prefix)/etc/reqcove/hosts`, the config staying at
  `etc/reqcove/config`) and the config line `--allow-hosts=@FILE` (an old
  hosts file kept as `hosts.old`); configs written before work unchanged.
  `run` remembers which of its hosts came from which `@FILE`, and which were
  given as they are (command line, or `--config`): those are not written, and
  the answer names them, with the ones removed now that a start with them
  records again. The file is replaced atomically, 0600, keeping its comments
  and the lines whose hosts are all kept. Refused, nothing written: `"*"`, no
  hosts to write (`run` refuses a hosts file without hosts), a file not plain
  or not yours, the `--pass-hosts` file, LAN mode; with no hosts file (or
  several): "nothing to save to". Hosts passed undecrypted are not saved. The
  trace: `run`'s log, a `cli` marker, `scope_change` "capture save". Unit
  tests (setup's files, where the hosts came from, what is written, each
  refusal) and an E2E test with real mitmproxy (add, remove a command-line
  host, save, then a new `run` from the config records the host added). Not
  tried on an iPhone or with `brew services`.
- **`reqcove capture stop` and `capture start`** (`--state DIR`): stop
  recording for a while, without a restart, and start again with the same
  hosts. While stopped, mitmproxy decrypts mitm.it alone, nothing new is
  recorded (an open WebSocket's flow is closed with "recording stopped: its
  host left the scope", and does not resume after the start), and no rule of
  the `--rules` file applies: mock, map_local, map_remote, modify_headers and
  resolve, presets included (those on are turned off; `activate_preset` is
  refused with a note). The records stay readable. `stop`'s answer warns that
  the app's requests then go to the real servers, a mocked API's too, and
  says how many records are kept; `start`'s says the hosts it records again
  (new connections only). `capture add`, `remove` and `set` while stopped
  change the hosts `start` records. A restart of mitmproxy keeps it stopped; a
  restart of `run` records again. `status` (and `reqcove status --json`) gets
  `recording` (`on`, `stopped`), `allow_hosts` `[]` while stopped, and the
  hosts kept in `base_allow_hosts` and `base_pass_hosts`; `capture_stats`
  gets `recording`; `next_steps`, and the note of an empty `list_flows`,
  `search_flows`, `summarize` or `wait_for_flows`, give `reqcove capture
  start`; `explain_rules` says no rule applies. Same rules as the other
  `capture` commands (a terminal only, refused in LAN mode, an older run named,
  the trace). Unit tests (mitmproxy's arguments while stopped: mitm.it only,
  never empty, with `"*"` too; the order of a stop and a start; the step) and
  E2E tests with real mitmproxy (a WebSocket; a mocked URL reaching the
  server, on a new connection and on one decrypted before; a preset turned
  off and refused; mitmproxy killed while stopped; the CLI's answers, status
  and markers). Not tried on an iPhone.
- **`reqcove capture add HOST…`, `capture remove HOST…` and `capture set
  --allow-hosts HOSTS [--pass-hosts HOSTS]`** (`--pass` for the hosts carried
  undecrypted; `--state DIR`): change the hosts the running `run` records
  from your terminal, without a restart, so the records stay. They talk to
  `run` over a new socket in the state directory, `ctl.sock` (0600), not the
  agents' `mcp.sock`. Each answer says what happened (applied, or pending
  while mitmproxy has not acknowledged it), how many records are kept, that
  the change is not saved (a restart goes back to `run`'s own hosts), and
  that an added host is decrypted on new connections only (reopen the app).
  Refused: `"*"`, removing a host a wildcard takes in (naming the wildcard),
  a change that takes out a host a `mock` rule names (naming the rules), any
  change in LAN mode, and outside a terminal (a guard against mistakes, not a
  boundary: SECURITY); a `run` older than v1.1 is named, with "restart it".
  Each change leaves a line in `run`'s log, a marker with source `cli`, and
  in `status` `scope_change` and `scope_changed_at` ("last changed at …" in
  `reqcove status`, which now also prints the hosts recorded). With nothing
  recorded, `next_steps` gives `reqcove capture add api.example.com` in
  place of "restart with --allow-hosts" (not in LAN mode); a host filter of
  `list_flows`, `search_flows`, `summarize` or `wait_for_flows` that matches
  nothing, for a host outside the hosts recorded, gets a note saying so with
  the command, for the user. The skill and the server's instructions tell
  agents never to run `reqcove capture`. Unit tests (the arguments and
  refusals, `ctl.sock`'s mode, an older run, no answer, the note, the step)
  and an E2E test with real mitmproxy (add: a new connection is recorded;
  remove: one is not; the log line, markers and status); not tried on an
  iPhone. The pending answer and the `mock` refusal as `capture` words them:
  from reading the code (the mechanics behind them are tested, above).
- **The hosts recorded can change while `run` runs**, without restarting
  mitmproxy (the groundwork for `reqcove capture`, above). A host added is decrypted on new connections; a host removed
  is no longer recorded from the next event on, a WebSocket open to it
  included (that flow ends with the error "recording stopped: its host left
  the scope", and does not come back if the host is added again), while its
  open connections stay decrypted (unrecorded) until they close. A change
  that takes out a host a `mock` rule names is refused, naming the rules
  (checked against the rules loaded, not the file on disk), and nothing
  changes; a `resolve` rule's host is checked the same way (from reading the
  code; not tested). A restarted mitmproxy keeps the change. Masking is
  never touched. `status` shows the hosts mitmproxy has acknowledged
  (`scope_pending` while it has not). E2E tests with real mitmproxy (add,
  then kill mitmdump; remove with a WebSocket and a keep-alive connection
  open; a stop and a start; a mock naming the host; status); unit tests for
  the per-event check and the order of a change.

### Changed

- **`reqcove service install` takes Homebrew's binary**, running Homebrew's
  stable path `$(brew --prefix)/opt/reqcove/bin/reqcove` (it refused it
  before, as its Cellar path goes at each `brew upgrade`). Still refused while
  Homebrew's own service is there. **Installed already, it installs again**
  (it refused before): the service is re-pointed at this binary and
  restarted (`launchctl bootout` then `bootstrap`, or `systemctl --user
  restart`), keeping the installed service's `--config` and `--state` unless
  given, and says so. Without `--config` and none installed, it takes the
  file a bare `run` reads. Unit tests only, never with launchd or systemd.
- **`reqcove setup`'s last lines**: the terminal first (`reqcove run`, or
  `reqcove run --config FILE` when a bare `run` would read another file),
  then the start at login (`reqcove service install`, or `brew services start
  reqcove`), then how to change things while it runs (`reqcove capture add
  HOST`, `capture save`; else edit the file and restart). The guide's service
  sections become "Run it in the background": a table of how to start,
  update and stop per way of running, and one config file. Unit tests.

- **A restarted mitmproxy gets the rules that loaded last**, from a private
  copy in the state directory (`rules-loaded`, 0600, removed when `run`
  stops), not the rules file as it is on disk then. Up to v1.0, a file broken
  meanwhile ended `run` at the restart, or, with `--rules-reload`, the
  restarted mitmproxy went on without any rules (a mock or `map_remote` lost
  sends test requests to the real servers). Now, under `--rules-reload`, the
  restarted one also looks at the file again and says why it does not load;
  if the rules that loaded last no longer load (a file they name is gone),
  `run` stops with the reason, with or without `--rules-reload`. E2E test
  with real mitmproxy (file broken, mitmdump killed); unit tests with a
  stand-in.
- **mitmproxy is started again without end**: after it exits, and at the
  start when it does not say hello within 2 minutes, it is retried after 1
  second, each wait doubled up to 5 minutes. Up to v1.0, `run` stopped after 5
  failed restarts in a row (or on a slow first start). `run` still stops with
  an error on what retrying cannot mend: rules that do not load, and, before
  mitmproxy has come up once, one that cannot be launched or exits before its
  hello. `capture_stats` (and `status`, `reqcove status`) has `retries`,
  `last_failure` and `next_attempt`; `reqcove status` says the retry and when
  the next is (at the first start, before `run` answers status, only its log
  does). Unit tests with a stand-in for mitmproxy.
- **Changes mitmproxy did not acknowledge** (`scope_pending`, discovery
  asked) are told it again every few seconds, not only when it starts again.
  A `capture stop` during allow-all that it does not acknowledge restarts it,
  stopped, as allow-all's end does (it would have gone on decrypting every
  host, with no end). A `reqcove reload` whose new rules it does not
  acknowledge restarts it with the new hosts and rules, never one without the
  other. Host discovery shows on only once mitmproxy has it on, and one asked
  while mitmproxy starts is turned on at its hello. Unit tests.
- **While mitmproxy restarts**, `capture add`, `remove`, `set` and `reqcove
  reload` answer "mitmproxy is restarting: try again in a moment; nothing
  changed" (the guide said they went pending). Unit test.
- **A body under way when its host leaves what is recorded** (a remove, a
  stop, allow-all's end) is copied no more: nothing more queued for reqcove,
  nothing kept for mitmweb; a WebSocket's next message closes its flow, the
  ones after it are not queued. With `--web`, mitmweb still lists the
  requests on connections decrypted before, unmasked, without bodies: the
  answers say so (from reading the code). A test with mitmproxy's Python.
- **`reqcove reload` refuses a hosts file that gives `"*"`** while the hosts
  recorded are not `"*"`, as `capture set` does (`capture allow-all --for D`
  is the way). Unit test.
- **`capture save`**: a host given on the command line and in the hosts file
  too, removed, is named as coming back at the next start (it was dropped
  from the file silently). Unit test.
- **`status`'s `restart_command`** is `reqcove service install` when the
  service runs another binary than `run`, or one gone, as `reqcove status`
  says. Unit test.
- **`reqcove service install` again, on macOS**, waits (at most 10 s) for the
  old run to let go of the state directory before starting the new one, and
  says so when it does not. Unit test.
- **`reqcove service restart` on macOS starts a service stopped until the
  next login** (`launchctl bootout`), also right after it, while launchd is
  still taking it out: it takes it out and loads it again, as `service
  install` does, waiting for the old run to let go of the state and retrying
  while launchd refuses (at most 5 s). `launchctl kickstart -k` alone
  answered that it could not find it, or failed (37) while it was going.
  Unit tests; both errors seen by hand.
- **`reqcove status`, while `run` is not running**, says that its service is
  installed and the command that starts it (`reqcove service restart`, `brew
  services restart reqcove`), for the service of that state directory. Unit
  test.
- **`reqcove service install` and `service restart` wait** (at most 5 s) for
  the run they started to take its state directory, so a `reqcove status`
  right after says it is starting rather than not running; when it has not,
  they say so, with the log. Unit test; the race seen by hand (`status` typed
  with `service install`).
- **`reqcove status` waits a moment** (at most 5 s) when a run holds the state
  but its tools do not answer yet (just started, or stopping), then says
  running or not running; still neither, it says which: "reqcove is
  starting" or "reqcove is stopping" (`run` leaves a `stopping` file in the
  state directory while it stops). Before: "starting, or stopping", read as
  "running or stopped". Unit tests.
- **`reqcove status` in the seconds after a start**, while the node is still
  connecting to Tailscale (`NoState`, `Starting`), says "the tailnet node is
  starting" rather than "ready: turn on the exit node". Unit test; seen by
  hand after `reqcove service restart`.
- **`reqcove status` right after `brew services start`** (or a login): with a
  service installed for that state and no run holding it yet, it waits (at
  most 3 s) for one, rather than "not running: start it with brew services
  restart reqcove". Unit test; seen by hand.
- **A `--config` file that is not there** (a service started before `reqcove
  setup`): the error says `reqcove setup` writes it. Unit test.

## v1.0.0 — 2026-11-15

### Security

- A header your `--rules` set on requests (`modify_headers`, and presets of
  that kind) now goes only to the host the request names, and one set on
  responses only to that host's response. Up to v0.8, any app
  on a carried device, an address allowed in LAN mode, or any user of this
  computer through `--local-proxy` could send a plain-HTTP request naming an
  allowed host in `Host` to its own server and get the rule's value (a token,
  say); over HTTPS the same worked with a certificate for another allowed name
  (`--allow-hosts '*'`, or a wide pattern). Reproduced with mitmproxy 12.3.1
  through its SOCKS5 port; the other ways from reading code.
  Now, unless `map_remote` or `resolve` sends it elsewhere, such a request
  goes on as the app sent it, without the rules, its response as the server
  sent it, and their `rewrites` say so; a request to its host's own address
  (as this computer looks the name up), or over HTTPS to its TLS name, keeps
  them (the TLS name not through `--upstream-proxy`, where mitmproxy checks
  the proxy's certificate; a Host with İ, ı, ſ or K, which `~d` matches to an
  ASCII name, never). The Host checked is the app's, read before any rule; a
  `modify_headers` rule that changes `Host` is no longer applied to a
  request nothing sends elsewhere (nor are the request's other header
  rules): use `map_remote` to change where it goes. When this computer's
  lookup of a CDN's name differs from the device's, the rules can be left out
  of a real request: a `resolve` rule for the name avoids it (not through
  `--upstream-proxy`, which takes no `resolve`). E2E tests with
  real mitmproxy: a stand-in server gets no rule's value (nor an active
  preset's), over plain HTTP and over HTTPS, nor with a rule setting `Host`
  to its address, and the app gets no response rule's value from it;
  requests to the right server still get them. Lookups run on threads of
  their own, bounded (16 names at once, 3 seconds each, answers kept 30
  seconds), so a stalled resolver holds nothing else up (tested in
  mitmproxy's Python, not in a running mitmdump); names are compared
  in IDNA's ASCII form (tests with mitmproxy's own made flows).
  docs/SECURITY.md, Rules.
- HTML pages are masked by their tags too: hidden form fields and meta tags
  named as secrets (an OAuth `form_post`'s `code` and `id_token`, Rails'
  `authenticity_token`, ASP.NET's `__RequestVerificationToken`, `csrf-token`)
  and attributes named so (`data-auth-token`), and a `<textarea>`'s text;
  comments and scripts' text read only to their end, so a quote in them
  hides no field after them; in pages and JavaScript, object fields with
  unquoted secret names (`{accessToken: "…"}`, up to two short comments
  around them, strings over lines, template literals). Up to v0.8 these
  reached the tools unmasked. `hmac`, `verifier` (`oauth_verifier`), `privkey`
  and `mnemonic` count as secret names now. Tests, and new shapes in the fuzz
  test; what it does not catch is in docs/SECURITY.md.
- `run`'s log is 0600 when its output is a file: brew services'
  `$(brew --prefix)/var/log/reqcove.log` was 0644 (launchd's), readable by
  other users of this computer. `run` makes it 0600 as it starts, and
  `reqcove setup` before the service first starts. Tests; not tried with brew
  services.
- Over `--mcp-http`, `capture_stats` and `status` no longer carry `resolve`'s
  rules (a name and the address it is sent to) nor the upstream proxy's
  address, as docs/SECURITY.md said (a test). A `resolve` line that fails to
  load can still be named in `rules_error` (docs/SECURITY.md).
- With masking off (`--no-redact`), every tool answer with flows in it
  (`get_flow`, `list_flows`, `search_flows`, `wait_for_flows`, `summarize`,
  `list_ws_messages`, `diff_flows`) says so in `note`, as the `--ui` page
  shows a badge (a test).
- LAN mode refuses this computer's other networks before letting Apple's
  17.0.0.0/8 through: an interface numbered in 17/8 is a LAN, and its
  neighbours were reachable (found by a code review; unit test).
- Through a `--uvx` wrapper (a path not named `uvx`), the default mitmproxy
  gets the lock's tornado, 6.6.1, not 6.5.10, whose vulnerabilities are in
  mitmweb's server (`--web`): the lock's override and its date for tornado
  are passed to uvx (tried with uv 0.13.4; the other packages come at the
  lock's versions, and the `--web` tests pass through a wrapper). Another
  `--mitmproxy-spec` still gets the tornado its mitmproxy asks for
  ([SECURITY](docs/SECURITY.md#mitmproxys-own-code)).
- Masking catches more of what an app sends: a credential behind JSON's
  escapes (`Basic\t…`, `\/` in a token, also in a string cut at 64 KiB); the
  rest of a secret-named line (`password: …`) even when a token sits in it;
  folded `multipart/form-data` part headers (a field's name or a cookie on the
  next line), and a part naming no field shows its size only; a token-shaped
  host, SNI, method, ALPN name or `Content-Encoding` and the notes quoting
  them (found by a code review; unit tests, and the fuzz test for the line).
- Masking catches more cookies and names: a cookie value without a name after
  the first (`Cookie: theme=dark; <a JWT>` kept the JWT), and each cookie of
  a `Set-Cookie` line joining several with commas after another's attributes
  (only the first was masked; an `Expires` date's comma is not a cookie's,
  nor one before a cookie's first `;`, which may be its value's:
  `v1,QUJD…==`); `name=value` lines in a text
  body or a WebSocket message (a `.env` file's `API_KEY=…`, `export` too) and
  a form body ending with a newline, whose secrets were kept; and a short
  secret word with a number after it (`key1`, `pin2`; not `auth0`, a
  service's name) and `primaryKey`, which were not secret (found by a code
  review; unit tests, an E2E test for the joined `Set-Cookie`, and the fuzz
  test for the `.env` line).

### Removed

- v0.6's names, deprecated in v0.8: the tools `list_mock_presets`,
  `activate_mock` and `deactivate_mock` (use `list_presets`,
  `activate_preset` and `deactivate_preset`, which take mocks and the other
  kinds), `status`' `active_mock_presets` and `active_mock_presets_error` (use
  `active_presets` and `active_presets_error`), and `capture_stats`'
  `mock_presets` (use `presets`). No tool list has them, local or
  `--mcp-http`, nor does a tool description or the server's instructions
  (unit tests). A call to one of the tools, from a script or from an agent
  whose `reqcove mcp` is older than `run`, gets a tool error naming the tool
  that replaces it, not "unknown tool": `run`'s socket and `reqcove mcp`
  answer so (unit tests), and a v0.8 `reqcove mcp` passes that answer on
  (from reading its code). `reqcove status` still reads the old fields from a
  v0.6 or v0.7 `run` not yet restarted (unit test); nothing writes them.

### Added

- A connection to an allowed host that mitmproxy carries as raw TCP, not
  read as HTTP, is recorded as a connection: up to v0.8 nothing showed it,
  and grpc-swift's calls on the iPhone left nothing at all (below).
  mitmproxy does so (once decrypted, for TLS) with an ALPN name it does not
  know when the server speaks first or the client's bytes do not look like
  HTTP (otherwise it reads HTTP/1), with bytes that do not look like HTTP,
  and for what a request upgrades to with a `101` other than a WebSocket,
  over plain HTTP too, where the connection is named by the request's host
  (each tried with mitmproxy 12.3.1, 2026-11-15; two by the E2E tests below).
  `list_passthrough` lists it with `reason: raw_tcp` (every row now has
  `reason`: `pass_hosts` or `raw_tcp`; a host filter naming such a host in
  `list_flows`, `search_flows`, `summarize` or `wait_for_flows` says so in
  `note`), with the protocol the client got
  (`alpn_negotiated`) and the bytes relayed each way (inside TLS, for TLS),
  never the bytes themselves; at most 1000 are kept, apart from the
  `--pass-hosts` connections, which they cannot push out. `capture_stats`
  counts it (`raw_tcp`, and `raw_tcp_hosts`, the busiest 30 by device and
  host), `list_devices` per device (`raw_tcp`; a device with only such
  connections is listed), and `status`' next steps name its hosts for its
  device. A device with only such connections, in LAN mode too, is no longer
  told it has no traffic, however many devices and hosts there are.
  `passed_through` and `list_devices`' `passthroughs` still count
  `--pass-hosts` connections only. E2E tests with real mitmproxy (an unknown
  ALPN from a server that speaks first; plain HTTP upgraded with a `101`),
  which fail without the change, and unit tests; not tried on an iPhone.
  Connections mitmproxy passes through itself (Apple's hosts, hosts outside
  `--allow-hosts`, a connection it knows by its address only) still leave
  nothing (from reading mitmproxy 12.3.1's code), nor do a few others
  (HTTP/2 coalescing onto a sibling host's connection, Encrypted Client
  Hello: tried with mitmproxy 12.3.1, 2026-11-15; docs/SECURITY.md).

### Fixed

Found by a code review of v0.8.0, the last two while looking into a test app's grpc-swift calls on the iPhone; each test fails without its fix.

- A body that is empty with nothing to stream (an HTTP/1 GET's request, a 204,
  304 or 101's response) was recorded as not ended (`final: false`, not
  decoded): mitmproxy never calls the stream then. It is now recorded whole
  and empty (E2E test; seen on the iPhone in the v1.0 sitting, up to v0.8).
- `reqcove status --json`, with no run to answer (none, or one starting or
  stopping), printed text: it prints nothing on stdout and exits 1, the
  reason on stderr, so a script reads only the status tool's JSON (unit test).
- A flow that fails mid-body keeps the head that came and its size, not
  final; before, what came in its last second was left out (size 0 for a
  body cut within a second). Tested with real mitmproxy (HTTP/1.1): a
  response the server cuts, an upload the client gives up on; an SSE stream
  that ends in an error goes the same way (from reading code).
- A gzip body of several members and a zstd body of several frames are
  decoded whole (up to the head's bound, as before). Before, gzip stopped
  after its first member, and zstd too, or, when the next frame came in a
  chunk of its own, gave a decode error and hid the head. Zero padding after
  a gzip member is skipped, as Python's gzip does; other bytes after a member
  are now a decode error (the head is not handed out), where they were
  ignored. Past 1024 members or frames the head stops, cut: each costs
  mitmproxy CPU. Test with real mitmproxy.
- Through mitmproxy, a client that is done sending (a half-close, `nc -N`)
  gets the answer still to come; before, the connection was closed both ways
  and the answer cut. Unit test of the exit node with a SOCKS5 server; the
  Remote Proxy's `CONNECT` dials the same way (from reading code).
- When mitmdump exits, the lines it left in reqcove's socket are read before
  its open flows are closed (for at most 2 s): before, a request among them
  stayed open for good and the addon's counters were counted twice. Test
  with a stand-in mitmdump (`addon_dropped_events`; the other counters come
  the same way, from reading code).
- `run --local-proxy … 2>&1 | tee FILE`, stopped with Ctrl-C (which stops
  `tee` too), left the system's web proxies pointed at the local proxy:
  `run`'s next line to the closed pipe killed it (SIGPIPE) before it put them
  back (from reading code; not tried with the real system proxy). A write to
  a closed stdout or stderr now fails instead, and the proxies are put back
  before anything is logged (unit tests: a `run` whose stderr is closed exits
  as usual, where it was killed by SIGPIPE; nothing is logged before the
  proxies are back).
- `reqcove status`, while `run` starts (mitmproxy first, up to 2 minutes) or
  stops, said reqcove was not running and how to start it: it says it is
  starting, or stopping, as do `reqcove har` and `reqcove mark` (unit test).
  To tell, they hold the state's lock for a moment, as `reqcove cleanup`
  does: a `run` taking it then (a service starting while a script polls
  `status`) waits that out, up to a second, instead of exiting with
  "another reqcove is using" (unit test).
- `reqcove status` and `reqcove har`, against a `run` stopped with Ctrl-Z,
  waited forever: they give up after 5 seconds, as `reqcove mark` and
  `reqcove mcp` do (unit test).
- `--proxy-port` out of 0 to 65535 is refused: in LAN mode 65616 would have
  listened on port 80 (from reading code; unit test of the refusal).
- With `--rules-reload` and a preset in the file, saving it could freeze
  `run` (v0.7.0–v0.8.0): nothing more was recorded, and the MCP tools,
  `reqcove status` and `--ui` stopped answering (they all wait on the store)
  until `run` was killed. Tests:
  a unit test, and one with real mitmproxy and `run`'s own rules log (the
  file saved twice; flows still recorded, the stats still answering).
- When mitmproxy kept failing and reqcove gave up on it (5 restarts in a
  row), `run` stopped with exit status 0, as for Ctrl-C, so a service looked
  as if it had ended fine. It now exits with status 1 and mitmproxy's error
  (test: a stand-in for mitmproxy that dies at every restart).
- An HTTP/2 GET (HEAD, OPTIONS, DELETE) without a length, to a URL a mock or
  `map_local` may answer, that sent a body anyway had all of it held in
  mitmproxy's memory (up to v0.8.0; the guide said so). It now gets a 502,
  recorded as an error, and its body is not held; one with no body is
  answered as before, as is one whose stream ends with an empty DATA frame
  instead of with its headers (Go's client does, for a body of unknown
  length that turns out empty). Tested with Go's HTTP/2 client and real
  mitmproxy (an endless body, or a single byte, gets its 502 at once; an
  empty DATA frame, the answer). macOS's URLSession sends none of these
  with an open stream (tried against a test server, without mitmproxy);
  iPhone apps not tried. A client that sends the headers and then waits
  gets its 502 at its first body byte, and with a mitmproxy other than
  12.3.1 (another `--mitmproxy-spec`), a stream still open after its
  headers gets the 502 at once, empty DATA frame or not (both from reading
  code).
- Masking an Apple plist whose `<key>` text comes in many pieces (split by
  comments, CDATA or child elements) copied the text so far at each piece,
  so its time and memory grew with the square of its size (up to v0.8):
  64 KiB of `    <b/>` in one key allocated about 140 MB and took 26 ms on
  an M1 Max, 16 KiB 9 MB. It now grows with the size (64 KiB: 1.8 MB,
  6 ms); what is masked does not change. Masking runs on the path every
  event from a connection takes, in order, so such a body held up what came
  after it (from reading code). Found by the growth test (Inside), which
  fails without the fix.
- Plain HTTP whose `Host` ends in the root's dot (`curl
  http://api.example.com./`) passed through undecrypted and unrecorded,
  though the host was allowed (up to v0.8): mitmproxy's `allow_hosts`
  patterns did not take the dot. They do now, and a flow's host is recorded
  without it, so a host filter finds it; over HTTPS, such a request was
  recorded with the dot, which the filter missed (tried with mitmproxy
  12.3.1, 2026-11-15). Unit test, and an E2E test with real mitmproxy, which
  fails without the fix (found by a review of the v1.0 changes).
- A grpc-swift call (2, both transports; 1 offers the same, from its
  sources) to a server that picks ALPN `grpc-exp` (Connect's demo server
  does) failed through Reqcove, unrecorded (up to v0.8): grpc-swift offers `grpc-exp`
  before `h2`, mitmproxy offered the server the same, then gave the app
  `grpc-exp`, read its HTTP/2 as HTTP/1 and dropped the connection. Such a
  server is now offered `h2` without `grpc-exp`; the call goes on and is
  recorded. Tried with grpc-swift 2 on this Mac against Connect's demo
  server, through a relay that dials mitmproxy as the exit node does (both
  transports, the CA given as the trust root), and on an iPhone (iOS 27.3,
  both transports): grpc-swift's calls on the iPhone are now recorded. There, before the fix, the server's HTTP/2 settings came first,
  so mitmproxy, not knowing `grpc-exp`, carried the connection as raw TCP,
  decrypted but not read as HTTP: nothing was recorded, no flow, TLS failure
  or count. E2E test, which fails without the fix. gRPC-core, grpc-java and
  grpc-go offer `h2` only (from their sources). A server that takes only
  `grpc-exp`, not `h2`, would now fail such a call, being offered no
  `grpc-exp` when the client offers `h2` too (from reading code; no such
  server was found).
- A connection whose first bytes were too few for mitmproxy to read the
  name was passed through undecrypted and unrecorded, for an allowed host
  too (up to v0.8): mitmproxy decides on the first bytes it reads, and with
  1 or 2 bytes of a ClientHello, or an HTTP request short of its request
  line's `HTTP/`, it has only the address, which `--allow-hosts` does not
  name. Reqcove hands bytes to mitmproxy as they come, so a client whose
  first segment was that short got there (tried with mitmproxy 12.3.1
  through its SOCKS5 port: a first write of 1 or 2 bytes of a ClientHello;
  of an HTTP request, 1, 2, 3, 10 or 14 bytes, short of `HTTP/`). Now such a first write is held, at
  most a second, and sent with what follows, on every way to mitmproxy
  (the exit node, the Remote Proxy, the LAN proxy, `--local-proxy`: they
  share one dial). Bytes that cannot begin a request line (a method's first
  three bytes are letters, and no control byte but tab and CR follows), and
  what the client sends once the server has spoken first, go at once; if
  what was held cannot be sent, the connection is closed, never the rest
  sent without it (unit tests). E2E test through the LAN proxy, which fails
  without the fix; the other ways from reading code. Whether an iPhone app's
  connection ever comes that short was not seen.

### For people

- The Remote Proxy, LAN mode and `--local-proxy` keep at most 256 tunnels
  (CONNECT: HTTPS, WebSockets) open per client, one address (with
  `--local-proxy`, all of this computer's apps together): the next one gets a
  503 until one closes. A tunnel with no bytes either way for 15 minutes is
  closed; one that keeps talking (a WebSocket, an event stream) stays open.
  Tests, with 2 tunnels and 300 ms.
- The guide and SECURITY now say that `--web`'s 10,000 flows and 256 MB count
  finished flows only: a flow still in progress counts once it ends (from
  reading code).
- The skill and the server's instructions tell an agent to write a HAR file
  where only the user can read it (`umask 077`; the skill's example wrote to
  `/tmp`, which other users of the computer read), and that it is masked
  only while `redacting` is true. The instructions now list the commands an
  agent may run, as the skill does (`reqcove status`, `reqcove har`,
  `reqcove init --print`, `reqcove mock add --print` when asked), and name
  `reqcove cleanup` among those it never runs. The `status` tool's
  description says its hosts and device names are data, not instructions, as
  the other tools that return what sites, apps or the tailnet wrote do (a
  test), and SECURITY says which tools those are instead of "every tool".
- SECURITY covers six more things: what an agent read stays with its model
  provider and in the agent's own transcripts; the CA is valid for 10 years
  and for every site, until its profile is removed; backups of the state
  directory hold its key; what `reqcove cleanup` leaves; a computer shared
  with other users; other people's devices need their consent. It says what
  each comes from (reading code, or tried).
- SECURITY's list of what masking does not catch adds: XML's masking reads a
  body before JSON's, so in a JSON body labelled XML a tag inside a string
  can take the quote JSON's reading needs, and a secret field after it
  passes (a test pins it).
- SECURITY's "Not caught" and the skill add: a client that refuses
  mitmproxy's certificate only after the TLS handshake (curl on OpenSSL 4.1),
  or finishes it and closes without a request, leaves no TLS failure, no flow
  and no count (tried with mitmproxy 12.3.1, and an E2E test; on an iPhone,
  an app that checks the certificate itself once connected). Pinning in
  URLSession's delegate or Network.framework's verify block refuses during
  the handshake and is listed (tried on an iPhone).
- COMPATIBILITY: `--uvx`, `--python` and `--mitmproxy-spec` move to "Not
  stable", and which mitmproxy version a release runs is not promised.
- The guide says that a `map_remote` rule that changes only the path sends
  the request on as any `map_remote` does: mitmproxy connects to the host by
  its name, and the header rules apply (tried in mitmproxy's Python).

### Inside

- An E2E test sends compressed WebSocket messages (permessage-deflate) through
  mitmproxy: each is recorded inflated, with its inflated size, and masked.
- A test measures how masking's time and allocations grow between two
  sizes 8 times apart (mostly 16 and 128 KiB for bodies, 64 and 512 KiB for
  headers and URLs; protobuf's below its caps), for 152 inputs
  built to be slow for its regexps and loops: each content type a body is
  masked differently for (JSON, forms, text, none, HTML, JavaScript, XML,
  GraphQL, multipart, protobuf with and without `--proto`, gRPC frames),
  headers, URLs, WebSocket messages, error text and `Apply` as a whole; more
  than 24 times fails (CI's shared machines vary up to about 3 times; a run
  over 2 s fails at once). It catches the two this
  version's reviews found (script comments, folded multipart headers: checked
  by putting them back). Under the race detector, which distorts both
  measures, only the inputs that caught one run (those two and the
  plist's). The fuzz tests also fail an input whose masking takes over 2 s.
- The release workflow refuses a tag whose commit has no successful run of
  the test workflow (macOS and Linux, end to end with mitmproxy, the
  container, the checks). Checked with actionlint and by running its query
  against this repository; the workflow itself runs only on a tag, not yet.
- `TestWebMadeResponse` called the addon's `request`, a coroutine, without
  awaiting it, so that half never ran (Python only warned). It is awaited
  now; the test still fails with the addon's fix taken out.

### Upgrading from v0.8

- Restart `reqcove run` with the new version (or `reqcove service restart`,
  or `brew services restart reqcove`), then reconnect the agent's MCP server
  once (`/mcp` in Claude Code): until then its `reqcove mcp`, of v0.8, still
  lists the removed tools.
- Run `reqcove init` (or `reqcove setup`) again to update the skill.
- In permission lists, replace `mcp__reqcove__list_mock_presets`,
  `mcp__reqcove__activate_mock` and `mcp__reqcove__deactivate_mock` with
  `mcp__reqcove__list_presets`, `mcp__reqcove__activate_preset` and
  `mcp__reqcove__deactivate_preset`. `activate_preset` also turns on
  `map_remote`, `modify_headers` and `resolve` presets: put it under `ask`,
  even where `activate_mock` was allowed
  ([guide](docs/guide.md#allow-the-tools)).
- In scripts, read `active_presets`, `active_presets_error` and `presets`
  instead of `active_mock_presets`, `active_mock_presets_error` and
  `mock_presets`.
- In a `--rules` file, a `modify_headers` rule that sets `Host` to send a
  request to another server is no longer applied on its own, nor are that
  request's other header rules (its `rewrites` say so): write a `map_remote`
  rule, or `resolve`, for where the request should go
  ([guide](docs/guide.md#rules---rules)). A header rule for a plain-HTTP
  host, or for any host through `--upstream-proxy`, applies only when this
  computer's lookup of the Host includes the address the device dialled; its
  `rewrites` say when it did not. A script that reads
  `reqcove status --json` gets nothing on stdout and exit status 1 while no
  run answers, where it got text.

## v0.8.0 — 2026-11-14

### For people

- Security, on a computer shared with other users: up to v0.7, another
  user's process could take mitmproxy's SOCKS5 port before the first mitmdump
  bound it, or in the milliseconds between a mitmdump's death and reqcove
  noticing it, and get the SOCKS password and the devices' connections sent
  then: plain HTTP readable, HTTPS not (from reading code, as SECURITY.md
  said). Now the port stays reqcove's for the whole `run`; nothing to change.
  Tried on macOS as the same user (binding the port fails); another user: not
  tried.
  reqcove binds the port once per `run` and hands the socket to each mitmdump
  (through its launcher, `mitm.py`, with another `--mitmproxy-spec` too),
  which accepts only once its addon, the one that checks the SOCKS password,
  is loaded. Tests: binding the port fails while mitmdump is down (unit, and
  with real mitmproxy); a request sent then is recorded by the next mitmdump,
  and one with a wrong password is refused, nothing carried or recorded (real
  mitmproxy; the test fails if mitmdump accepts before the addon is loaded,
  its loading delayed by hand). SECURITY.md says what is covered and what not.
- [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) (and .ja): what stays stable from v1.0.0, and how it changes.
- Tried on a Linux host, Ubuntu 24.04.5 LTS (arm64, a tart VM, 2026-11-14):
  `reqcove setup`, `service install` (a systemd user unit; its journal holds
  no login URL or token), `status`, `service restart` and `uninstall`, and LAN
  mode with curl from another computer (HTTP and HTTPS recorded, refused until
  allowed, `lan deny`). The guide (EN, JA) says what was tried and what was
  not, and that without `loginctl enable-linger` systemd stops the user unit
  at the last logout (tried).
- Containers with Podman 6.2.0 on macOS (rootless `podman machine`): the smoke
  script passes, `run` up to the login, `--rules`, `host.containers.internal`
  ([container](docs/container.md#with-podman)); not tried: a login, an iPhone, an agent.
- docs/SECURITY.ja.md: the security model in Japanese, section for section
  with SECURITY.md; README.ja.md and guide.ja.md link to it.
- LAN mode's question and `lan` commands, and the refusals of this computer's
  own addresses, say "this computer", not "this Mac" (seen on Linux).
- Fixes from a try on Ubuntu 24.04 and with Podman (unit tests):
  - `reqcove status` with no run says "not logged in yet" for a node that
    started but never logged in (tsnet's state file holds no profile), not
    "has logged in before".
  - `run --lan` with another `--state` no longer suggests `--hostname`
    (refused with `--lan`).
  - No empty "carrying traffic from " line at LAN mode's start or after
    `reqcove lan deny` of the last client; the exit node's same line goes
    through the same check (not tried with a tailnet).
  - The service's PATH (systemd unit, launchd plist) lists uvx's directory once
    when it is `~/.local/bin`.
  - In a container, `run` prints the agent command with `podman run` under
    Podman (`/run/.containerenv`), `docker run` under Docker (`/.dockerenv`),
    and with neither a note to use `podman run` under Podman; not tried under
    Podman. docs/container.md said `run` printed the host's form of that
    command, and its Podman section that it printed `docker run`; it did not.
  - The guide's `--state` row names `~/.reqcove/ca-copies`, the list of the
    directories its CA was copied into (as docs/SECURITY.md did).
- The guide reorganised for reading; no claim changed. Its commands table
  lists `reqcove setup` and `reqcove service`; its Rules and `resolve`
  sections say what the E2E tests tried.

### Upgrading from v0.7

- Restart `reqcove run` with the new version (or `reqcove service restart`,
  or `brew services restart reqcove`), then reconnect the agent's MCP server
  once (`/mcp` in Claude Code).
- Run `reqcove init` (or `reqcove setup`) again to update the skill.
- Before v1.0: in permission lists, replace `mcp__reqcove__list_mock_presets`,
  `mcp__reqcove__activate_mock` and `mcp__reqcove__deactivate_mock` with
  `mcp__reqcove__list_presets`, `mcp__reqcove__activate_preset` and
  `mcp__reqcove__deactivate_preset`; in scripts, read `active_presets` and
  `presets` instead of `active_mock_presets` and `mock_presets`.

### For agents

- `status` (and `reqcove status --json`) has `active_presets`, the presets on
  of every kind, each with `kind`, and `active_presets_error` when mitmproxy
  did not say which; `capture_stats` has `presets`, every preset's name. They
  hold what `active_mock_presets`, `active_mock_presets_error` and
  `mock_presets` hold (unit tests). `reqcove status`, run's log and the ready
  block read the new names; `reqcove status` against a v0.7 run not yet
  restarted reads the old ones (unit test). The `status` and `capture_stats`
  descriptions name the new fields and the old ones as deprecated (unit test).
  The skill and the server's instructions name the `*_preset` tools first and
  the v0.6 ones as deprecated.

### Deprecated

- v0.6's names, removed in v1.0: the tools `list_mock_presets`,
  `activate_mock` and `deactivate_mock` (use `list_presets`, `activate_preset`
  and `deactivate_preset`; their descriptions say so, their behaviour is
  unchanged), `status`' `active_mock_presets` and `active_mock_presets_error`,
  and `capture_stats`' `mock_presets` (filled as before until then).

## v0.7.0 — 2026-11-14

### For people

- `run --lan`: LAN mode without Tailscale, an HTTP proxy on this computer's
  LAN address for the client addresses you allow (`reqcove lan allow ADDR`,
  or run's question), recorded as `lan:ADDR`; ports 80 and 443 only, private
  hosts only for exact `--allow-hosts` names, never this computer or its own
  network. Refused in `--config`. The ready block says what to enter on the
  iPhone, who is allowed, and the CA's file and SHA-256 (plain HTTP on a LAN
  can be swapped); `reqcove status` shows the allowed addresses and the
  refused ones (the 50 last seen, and how many more; unit tests). README, the
  guide and SECURITY have a section. Tried with an iPhone on a home Wi-Fi
  (iOS 27.3): allowed, recorded, denied.
- Presets of `map_remote`, `modify_headers` (requests only) and `resolve`: a
  rule written as `{rule: "…", preset: NAME}` applies only while an agent turns
  it on, for at most 5 minutes each time, as mock presets. A `map_remote`
  preset sends the app's requests, cookies and tokens to its target: SECURITY
  has a section on what that allows. Targets are shown in the ready block, the
  log, `list_presets` and (the ones on) `reqcove status`; a request a preset
  would send outside its target gets a 502; refused at load: a target that cannot be shown,
  with a user or password, or plain `http://` beyond this computer and the LAN.
  `capture_stats.rules` and run's "rules from FILE" log count them in their
  kind, as they count mock presets (a test with mitmproxy's Python).
  Tried on an iPhone (LAN mode): a `map_remote` preset to a dev server on this
  Mac. Not tried on an iPhone: `resolve` and `modify_headers` presets.
- `reqcove setup`: the first run, in a terminal only. It checks uv (printing
  how to install it), asks for the device and the hosts to record and writes
  them to the file the service reads, `~/.config/reqcove/config` or, for a
  brew install, Homebrew's `etc/reqcove/config` (0600; an existing file is
  shown and kept unless you say to replace it, then kept as `config.old`; `*`
  and refused flags never written), adds the skill as `reqcove init` does if
  you say so, prints `claude mcp add reqcove -- reqcove mcp`, and says how to
  start (`brew services`, `reqcove service install`, or `run --config` in a
  terminal). It starts nothing and prints no login URL; Ctrl-C stops it. README
  starts with it; the guide's First start has the details; the Homebrew
  formula's caveats name it. Unit tests, Ctrl-C in a terminal, and a run on
  macOS. Not tried on Linux.
- `reqcove service install` (`service restart`, `service uninstall`): `run` at login without
  Homebrew, as `brew services` does, from a LaunchAgent (macOS) or a systemd
  user unit (Linux) running `run --config ~/.config/reqcove/config` (or
  `--config FILE`); the log in the state directory's `service.log` (macOS) or
  journald. Refused while Homebrew's service is there; for Homebrew's own
  binary, whose path `brew upgrade` removes (it names `reqcove setup`, then
  `brew services start reqcove`; a unit test); and for a config file
  missing, readable by others, or with `--no-redact`, `--web`,
  `--rules-reload` or `--lan`. `reqcove status` names it and says how to stop it. The
  guide has a section. Tried on macOS: install (an iPhone recorded), a sleep,
  a start at login after a reboot, and uninstall. Not tried yet: `service
  restart`, Linux.
- `list_rules` and `explain_rules`: an agent can list the `--rules` file's
  rules (never their filters, values or bodies) and say which of them apply to
  a request, and why one did not (For agents has the details).
- `reqcove mark [TEXT]` puts a marker among the records (a time and a
  checkpoint to read from), in your terminal only; agents put theirs with
  `add_marker`. At most 80 characters on one line, masked; at most 100 per
  source (`cli`, `mcp`: the channel, not proof); in memory only. It gives up
  after 5 seconds when `run` takes the connection but does not answer
  (stopped with Ctrl-Z; a unit test). The guide has a section. `add_marker`
  used from Claude Code during an iPhone sitting; `reqcove mark` not tried by
  hand.
- `reqcove mock add --rules FILE --url URL …` adds a mock to a rules file,
  keeping the file's text, comments and order; refused when `mock:` is not the
  last block or is in flow style. The whole file is checked first by the
  addon's loader (by the running `run`, with its hosts, else by mitmproxy's
  Python, hosts unchecked) and written at once, its mode kept. In your
  terminal only (a help, not a guarantee); `--print` shows the mock without
  writing. The guide has a section. Tried with the tests, not by hand.
- XML bodies (`text/xml`, `application/xml`, `application/*+xml` such as
  SOAP) are masked by names: an element or attribute whose local name
  (`wsse:Password`) is one JSON's keys are masked by, the element's whole
  content (CDATA and child elements too), a SAML `Assertion` whole (a bearer
  credential), and in a plist the value after a secret `<key>`. Changed in
  place, the rest as it came; a head cut inside a secret element is masked to
  its end; no DTD is read. The text masking still applies on top. SECURITY
  lists the limits. Tests and an E2E test with a SOAP request.
- mitmproxy's lock takes tornado 6.6.1: 6.6 has CVE-2026-126347 (pip-audit).
  v0.6.0's lock has tornado 6.6: updating to v0.7.0 is the fix. tornado is
  mitmweb's server (`--web`; from reading code). Reqcove's `--web` test passes
  with 6.6.1.
- A connection carried through mitmproxy (hosts outside `--allow-hosts` too)
  gives up after 10 seconds, as a direct one does, when the server does not
  answer: mitmproxy answers reqcove only once connected, and waited up to the
  OS's 75 s (macOS). The log names the server (`… did not answer within 10s`,
  or `the client left before … answered`) instead of x/net's
  `read 127.0.0.1:…->127.0.0.1:…: i/o timeout`. Tried with an address that
  never answers.
- The guide says RoamRun works alongside `--local-proxy` (tried with RoamRun
  0.12.0 and its PR #253: doctor, and a bridge over the tailnet to Ready).
- LAN mode prints the CA's SHA-256 as iOS shows it (`ab 90 7e …`) and where:
  Settings, General, VPN & Device Management, the profile, More Details
  (checked on iOS 27.3: it matched). `reqcove status`'s CA line keeps the
  form `security delete-certificate -Z` takes.
- The proxy's log (LAN mode, the Remote Proxy, `--local-proxy`) gives the same
  failure again (client address, host, error) at most once a minute, with how
  many were left out: an app retrying a name that does not resolve no longer
  fills it.
- `reqcove setup` and `reqcove service install` print this binary's full path
  in their commands when `reqcove` on `PATH` is not it.
- `reqcove service install` (macOS) makes `service.log` 0600 (launchd made it
  0644). Unit test only.
- `--local-proxy` also keeps the tailnet's IPv6 range (`fd7a:115c:a1e0::/48`)
  out of the proxy, as its IPv4 range already was.
- The guide shows which Reqcove tools to allow by name in Claude Code's
  settings, with the preset tools under `ask`; says that Claude Code's `!`
  gets nothing from `reqcove links` (tried), and that `status` over
  `--mcp-http` has no `active_mock_presets`.
- SECURITY's promise of what the tools can change names every kind of preset,
  not mocks only; the README's LAN paragraph says how to trust the CA.

### Upgrading from v0.6

- `list_mock_presets`, `activate_mock` and `deactivate_mock` stay, for mocks
  only: `list_presets`, `activate_preset` and `deactivate_preset` take the
  other kinds.
- `status`'s `active_mock_presets` holds the presets on of every kind, each
  with `kind`; `list_mock_presets` leaves out fields that do not apply
  instead of giving `null`.
- Flows gain `presets`, `status` gains `mode` and (in LAN mode) `lan`, and
  `list_devices` gains `first_seen`.
- If you allowed `"mcp__reqcove"` wholesale in Claude Code, that now also
  allows `activate_preset` (a `map_remote` preset sends the app's requests
  and credentials to its target) and `add_marker`: allow the read tools by
  name instead (the guide lists them).
- Run `reqcove init` (or `reqcove setup`) again to update the skill.
- Homebrew: `brew trust --formula mh-mobile/tap/reqcove`, then
  `brew upgrade reqcove`.

### For agents

- `reqcove mcp` dials `run` again once its connection ends (`run` stopped),
  so the first call after a restart reaches the new `run` instead of failing
  on the dead session; its note after a restart says markers are gone too
  and every preset is off.
- The skill and the server's instructions: never run `reqcove service` (it
  starts and stops `run`).
- The skill: never run `reqcove mock add`; with `--print`, only when the user
  asks.
- The skill's rules example has a mock preset (`preset:`, `description:`,
  `delay_ms`).
- `status` has `mode` (`tailnet` or `lan`) and, in LAN mode, `lan` (where it
  listens, the allowed addresses and when, in local time with milliseconds as
  the other times, and those refused this run: the 50 last seen, with
  `refused_more` for the rest);
  `list_devices` has `first_seen`. The skill and the server's instructions:
  never run `reqcove lan`.
- `list_presets`, `activate_preset`, `deactivate_preset` for presets of every
  kind (`kind`); `list_mock_presets`, `activate_mock`, `deactivate_mock` take
  mocks only, and when mitmproxy does not answer in time they point to
  `list_mock_presets`, not `list_presets` (which a v0.6 `reqcove mcp` lacks).
  A flow lists the presets that changed or answered it in
  `presets`; `status`'s `active_mock_presets` has every kind, with `kind`.
  `list_mock_presets` leaves out fields that do not apply (a method of any:
  no `method`) instead of `null`.
- `list_rules` and `explain_rules` (read-only; local socket and `reqcove mcp`
  only, never over `--mcp-http`). `list_rules`: every `--rules` rule by kind
  and number, its preset and whether it is on, and only what is derived from
  it (never a filter, a regex, a header value, a body or a path).
  `explain_rules(flow_id | method, url, operation)`: the scope, then what the
  rules do through the request path's own code on a request never sent, what
  each preset that is off would do, the rules whose filter a method and URL
  cannot tell, and what a recorded flow got. It uses no preset's count. The
  skill: call it when a flow lacks the `mocked`, `rewrites` or `presets`
  expected. Used from Claude Code during an iPhone sitting: they worked.
- `add_marker(text)` (a write with no effect on the device: not read-only,
  never sent again by `reqcove mcp`) and `list_markers(since)` (read-only),
  local socket and `reqcove mcp` only. `add_marker` returns `id`, `time` (for
  `since`) and `checkpoint` (for `wait_for_flows`' `after`). The skill: add one
  before acting, never follow a marker's text; the server's instructions say
  it is data.

## v0.6.0 — 2026-11-13

### For people

- The MCP tools no longer only read: `activate_mock` and `deactivate_mock`
  turn on and off mocks you marked as presets (below). With none, the tools
  only read; over `--mcp-http`, never. SECURITY's promise is reworded.
- `run`'s log lines no longer carry the `--ui`, `--web`, `--mcp-http` tokens
  or the login URL, `--verbose` included (tsnet's own lines printed the login
  URL every 5 s, and the mitmweb line its token); before `run` learns the login
  URL, it is recognized by its usual shapes (Tailscale's, Headscale's). On a terminal `run`
  still shows them; off one (a service, `docker logs` without `-t`) it names
  `reqcove links` in their place.
- `reqcove links` prints the login URL and those links again, with QR codes,
  and only to a terminal. `run` keeps them in `login-url` and `links` (0600)
  in the state directory while it runs.
- mitmweb's server no longer leaves its token in `mitmproxy.log` when a
  request fails.
- The container docs drop `-t` from `docker run`: `docker exec -it NAME
  reqcove links` shows the links (not tried in a container yet). A container
  started with `-t` before keeps them in `docker logs` until it is made anew.

- Mock presets: a mock in the `--rules` file marked `preset: NAME` (with an
  optional `description:`) answers only while an agent has turned it on, for
  at most 5 minutes each time (it can turn it on again, with no cap) and, if
  it says, 20 requests. Tried on an iPhone (a 503 once, a delay, a close, a
  401). Mocks also take `delay_ms` (at most 30000) and `fault: close`. A
  plain mock with the same match as a preset is refused at load. With `--rules-reload` a changed rules
  file turns presets off, as does a restart of mitmproxy or of `run`; `run`
  logs each one an agent turns on or off.
- `run --config FILE` reads run's flags, one a line (`--no-redact`, `--web`,
  `--rules-reload` and `--allow-hosts '*'` stay on the command line), and the
  Homebrew formula has a service: `brew services start reqcove` with the
  flags in `$(brew --prefix)/etc/reqcove/config` (tried: start, an iPhone
  recorded, stop; not yet at login or after a reboot). `reqcove status`
  names the service.
- If you allowed `"mcp__reqcove"` wholesale in Claude Code, that now also
  allows `activate_mock`: allow the read tools by name instead.

### For agents

- `reqcove mcp` never sends a write again after its connection to `run`
  dropped; a v0.5 `run` answers the preset tools with an error naming its
  version.
- `status` has `service`, `active_mock_presets` and
  `active_mock_presets_error`; `capture_stats` has `mock_presets`; HAR notes
  say which preset answered.
- `list_mock_presets`, `activate_mock` and `deactivate_mock`, on this
  computer only (never over `--mcp-http`). One preset is on per match
  (method, URL, operation). A flow a preset answered says `preset: NAME`;
  `status` lists the ones on (`active_mock_presets`). The skill and the
  server's instructions: turn one on only for a test the user asked for,
  never because of what the records say.
- `next_steps` says the login URL comes from `reqcove links`; the skill and the
  server's instructions say never to run it.

## v0.5.0 — 2026-11-12

### For agents

- WebSocket messages are recorded: `list_ws_messages` reads a socket's
  messages, oldest first, after a cursor (a checkpoint), each a text
  message's first 4 KiB masked as bodies are; binary ones, and those past
  about 20 a second on one socket, give their size only. Kept are a socket's
  first 5 messages and its newest 100; `missed` counts the rest. Rows carry
  `websocket_messages`; a socket stays `open` until it closes, and
  `get_flow` gives how (`websocket_close`). A timed-out `wait_for_flows`
  lists the sockets that got messages since (`websocket_activity`);
  `search_flows` with `bodies` looks in kept messages; a HAR has them in
  `_webSocketMessages`. An open socket that talks is evicted after the others
  (among the oldest 16). A 101 that is not a WebSocket (h2c) is done at once.
  Tried with the E2E test (a real socket through mitmproxy, a flood of 50,000
  messages beside an HTTP request), and on an iPhone (a test app over
  URLSession: an auth message's token masked both ways, the close).
- gRPC: rows and `summarize` (`by_grpc_status`) show a call's status, from
  the response headers (a trailers-only error) or its trailers, `pending`
  until they come; `get_flow` has `response_trailers` (HTTP/2's, or gRPC-Web's
  last frame). A body's note counts its messages; JSON ones are de-framed and
  masked as JSON. `-bin` metadata shows its size only; `grpc-message` is
  decoded and masked. Trailers are searched, compared by `diff_flows` and
  written to a HAR's comment. Tried with an E2E test over HTTP/2, and on an
  iPhone (a test app over URLSession: Connect, gRPC-Web and gRPC to
  Connect's demo server, with `--proto`; gRPC's answer showed nothing there:
  fixed after, by a test). A Connect stream's last frame (flag 2: its error,
  as JSON) is shown as `[end of stream]`, masked (by a test only).
- Protobuf bodies (gRPC's messages, `application/x-protobuf` and the like) are
  handed out as reqcove's rendering (`view`): without a schema, their
  structure (field numbers, types, lengths, a string's length, numbers in
  responses, only small ones in requests); with `--proto FILE` (a compiled
  schema), as JSON with their field names, masked by name. The type comes
  from the method in the path (gRPC, gRPC-Web, Connect, Twirp) or
  `messageType` in the content type. A body that does not read as protobuf
  to its end shows nothing. `diff_flows` never calls two structures, nor
  lengths-only values, the same. Tried with tests and a fuzz test (of the
  reading without a schema).
- `multipart/form-data` bodies (uploads) are handed out, part by part: a
  secret-named part masked whole, text parts masked as bodies, files and
  parts that are not text by their size only. Before, they were left out as
  "not text". Tried with tests and an E2E test (Go's multipart writer).

### Masking

- Token shapes (JWTs, keys with known prefixes, `Bearer …`) are found behind
  percent-encoding too: JSON encoded in a form field or a URL parameter,
  `Bearer+…` (before, the shapes needed a word boundary that `%22` and `+` do
  not give).
- A `name: value` line with a secret name, in a text body that is not a
  GraphQL document or in a JSON string (a STOMP frame's `passcode:`, also in
  SockJS's JSON; a YAML mapping), has the rest of the line masked.
- Base64 of a JSON object with a secret in it, as a URL parameter or form field
  (AppSync realtime's `?header=`), is masked whole; so is a credential carried
  in `Sec-WebSocket-Protocol` (`access_token, …`, AppSync's `header-…`,
  Kubernetes' bearer prefix).
- Bodies of JSON under other content types (`application/x-amz-json-1.1`, as
  Cognito and Amplify send, any type naming `json`) and Sentry envelopes are
  handed out when they hold no control characters; before, they were masked
  but left out as "not text".

### Inside

- Cursors (checkpoints, `next_cursor`, `after`) count in microseconds, so a
  run handing out many (WebSocket messages take one each) cannot reach the
  next run's, which would make old cursors look current. A line from the
  addon that masking fails on is counted as a bad line instead of stopping
  `reqcove run`.
- A GraphQL request's operation is read by its keys' exact case, as mocks
  read it (`OperationName` is not it); in a head cut before its end, only a
  top-level `operationName` counts, not one nested in variables. Mocks no
  longer take a no-break space for GraphQL's space, as the row does not.

## v0.4.0 — 2026-11-12

### For agents

- Response mocks: a `mock:` rule in the `--rules` file answers a request
  (method, URL exact or by prefix, GraphQL operation) with a status, headers
  and a body (inline or a file, at most 1 MiB), before `map_remote` and
  `map_local` (request `modify_headers` rules apply first); the
  request is not sent to the server (for HTTPS, mitmproxy may have connected
  to it already, to read its certificate). One it would have to hold but
  cannot (a length over 1 MiB, a POST of unknown length) goes on, its
  `rewrites` saying `mock: skipped, …`. Its row says `mocked: true`, `rewrites` gives
  `mock[i]: status` (never the rule's text), a HAR notes it, `summarize`
  counts them. `Cache-Control: no-store` unless the rule sets one. Hosts in
  `--allow-hosts` only. `capture_stats.rules_loaded` says when the file was
  last taken. Tried with the E2E tests, and on an iPhone (Safari; one GraphQL
  operation of the GitHub app).
- `summarize` counts by endpoint (`by_endpoint`): method, host and path
  without the query, with segments of digits only or a UUID as `{id}`, then
  a GraphQL operation (`POST api.example.com/graphql Login`).
- Rows (`list_flows`, `search_flows`, `wait_for_flows`) and `get_flow` carry
  a GraphQL request's `operation`, as mocks read it: the URL's
  (`?operationName=`, else the `?query=` document's), else Apollo's
  `X-APOLLO-OPERATION-NAME` header, else the body's (`operationName`, else
  its document's first operation); `(anonymous)` or `(batched)`; a name GraphQL does not allow is not shown. A filter
  `operation` selects them. Worked out from the masked request as it arrives.

### Masking

- GraphQL documents are read by a lexer instead of a pattern. An argument, an
  input object's field or a variable's default whose name is secret has its
  whole value masked: a string, a number, a list or an object
  (`pin: "[redacted]"`), as a JSON field's is; enums, booleans, `$variables`
  and aliases stay. Documents are found where a JSON string at depth 0 or 1
  (any key, requests and responses), the body or a URL parameter starts like
  one; a GET `?query=` is masked and escaped again rather than replaced. One
  that cannot be read is masked whole. Before, variable defaults, lists,
  numbers, quotes written `\u0022` and responses without a trigger word passed.
  A second fuzz test writes documents from a small grammar.
  A `name: "value"` outside a document (prose, a script's object, an error
  message quoting part of a query) is no longer masked: the pattern caught it
  in requests, and in responses with a trigger word.
- A field with a secret name whose value is a list or an object is masked
  whole (`{"password": "[redacted]"}`; cut by the head's end, to the end).
- A URL in a form's first field is looked into, as the other fields are.
- A URL parameter's value goes on after `\/` and Gson's `\u0027` and
  `\u003d` (before, what followed was left).
- A string cut by the head's end is read with its escapes undone (`\u`
  escapes, a cut one dropped), as a whole one is.
- The fuzz test checks every 5 characters of the secret, as written and
  decoded, at every cut, in 21 shapes (it checked the whole secret at one cut).

### Inside

- Masking happens before the Store's lock is taken: an event's URLs,
  headers and error text, and a body's head (the lock is held only to read
  its content type). Tools no longer wait while a body is masked: with 64 KiB
  JSON bodies arriving back to back, a `list_flows` and a `get_flow` waited
  12 ms at the median (17 ms at the 99th percentile) before, 6 µs (95 µs)
  after (`BenchmarkToolsWhileIngesting`, this Mac). A body whose flow was not
  there when it was masked is dropped as an orphan, as before.

## v0.3.0 — 2026-11-11

### For agents

- `wait_for_flows`: read what an action on the device sent. Take `checkpoint`
  from `list_flows` (or `capture_stats`) before acting (a tap through RoamRun,
  or the user), then wait with `after: checkpoint`: the flows answered since
  come oldest answer first, as soon as there is one, each once across calls
  (pass the answer's `after` on), even when they finish out of order; one that
  never ends (SSE, a long poll) holds nothing up. Up to 30 seconds a call, 16
  waits at once (4 for one `--mcp-http` device); an `after` no checkpoint gave
  is refused; flows evicted unread are said at once (`evicted`). Tried with one iPhone (Safari, httpbin.org) acted on through
  RoamRun, on the Mac's Wi-Fi and from another network (tethering).
- `diff_flows`: two flows compared (one that worked, one that failed): method,
  URL, status, error, headers by name, bodies (JSON by path). Values masked on
  both sides are listed as masked, never as equal; bodies that are not text
  are not compared while masking is on; with `--no-redact` everything is. JSON
  numbers are compared as written (IDs past 2^53 too).
- `get_flow` takes `max_body`, at most that many bytes of each body head.
- Every tool is marked read-only and not destructive (`readOnlyHint`,
  `destructiveHint`). `run` prints Codex's command to add the tools beside
  Claude Code's; the guide says how to allow the tools in each, and not to
  allow a shell or network tools along with them.
- The skill covers `wait_for_flows` and `diff_flows`: run `reqcove init`
  again to update it.

### Masking

- `--mask-names a,b`: your own names treated as secret (headers, parameters,
  JSON fields, GraphQL arguments; any spelling). `--mask-values RE`: a
  pattern's matches masked wherever they are (the `key=…` seen in a bank app's
  User-Agent; a literal secret in a file goes as `\Q…\E`). Both `@FILE` too;
  errors never quote a pattern; `capture_stats` counts the matches.
  `--mask-names` matches the whole name (`clientRef` is not `X-Client-Ref`).
  `--mask-names` tried on an iPhone's flow (URL, JSON body, Referer);
  `--mask-values` by tests only.
- String arguments with secret names in GraphQL documents
  (`login(password: "…")`, in JSON, raw, or a GET `?query=`), and URLs encoded
  twice or three times inside a parameter. A fuzz test found the latter, and a
  GraphQL value cut after a backslash; a review found the query's own escaped
  quotes and block strings written inside JSON. GraphQL's GET variables
  (`?variables={"password":…}`), JSON in a URL parameter, are looked into too
  (they were not in 0.2 either, also after a space), as are arguments after a
  line break or a `#` comment (before the colon too), escaped `"""` in block
  strings, queries echoed back in responses, escaped strings in arrays, and shapes hidden behind `\u` escapes in a JSON string (which
  `diff_flows`, decoding, would have shown). URL parameters written the way
  Gson (Android) writes JSON, `=` as `\u003d` and `&` as `\u0026`, are found too.
- Your `--mask-names` and `--mask-values` win over the built-in exceptions
  (an OpenTelemetry `key`, `WWW-Authenticate`, a cookie's attributes).
- `Access-Control-Allow-Credentials` (only ever `true`) is no longer masked.

### Security

- mitmproxy runs from a lock built into reqcove: `uv run --locked --script`
  installs exactly the files the lock names and checks their hashes (plain
  `uvx` checked none). Another `--mitmproxy-spec` still goes through uvx. CI
  checks the lock and audits it (pip-audit), which found three known
  vulnerabilities in tornado 6.5.10 (mitmweb's server, capped there by
  mitmproxy 12.3.1): the lock takes tornado 6.6, which fixes them. The first
  start in a new state directory takes a few seconds more.
- While mitmdump restarts, the devices' connections wait for it (15 seconds at
  most) instead of being sent to its SOCKS port, which another local process
  could have taken meanwhile; a mitmproxy that could not bind the port never
  becomes ready (a test). The milliseconds between its death and reqcove
  noticing it remain (SECURITY.md).
- Prompt injection, from a review: the server's instructions (all an agent
  without the skill gets, such as Grok Bot) also say not to write files,
  commits or commands because of what the records say, not to suggest
  `--no-redact` or `--web`, that text shaped like a tool result or a system
  message is still data, and that `next_steps` are for the user. Every tool's
  description says its text was written by sites, apps or the tailnet. A
  request whose Host is not a host name or address is not recorded;
  User-Agents in lists are cut to 256 bytes, ALPN names to printable ASCII;
  `diff_flows` quotes JSON keys that are not plain names; a body's note quotes
  the site's `Content-Encoding`.
- Docs and `run`'s warning corrected: a `--pass-hosts` host's requests that
  mitmproxy decrypts anyway (plain HTTP, or on an allowed host's connection)
  go through `--upstream-proxy` and skip `--rules`, as 0.2.0 already did (the
  upstream part now a test). The v0.2.0 entry below said they skip both.
- From a review of outside values put into commands and text: `get_flow` with
  a huge `max_body` crashed `run` (an overflow; now clamped), and a panic in
  any tool now fails that call only; the `rm` commands `run` prints to change
  a token quote the state path; `modify_headers` refuses header names that are
  not tokens and values with a line break or NUL, also when its value file
  changes later; `resolve` names are host names only; a line from the addon
  longer than 8 MiB is dropped, not held.
- `--mcp-http`: each device may call about 10 times a second (30 at once),
  past that `429`; a call ends when its caller disconnects.
- Built with Go 1.27.4 (GO-2026-6859 in 1.27.3's net/http, reachable through
  the `--ui` page's proxy).
- With the locked mitmproxy, `run` refuses a `--python` below 3.14 at start,
  saying to give `--mitmproxy-spec` for an older one (through uvx, no lock).
- A wait for mitmproxy to be ready no longer takes a mitmproxy that came up
  and went down again before the wait woke for ready.
  A `--uvx` whose file is not named `uvx` also goes through uvx, unlocked.

### Inside

- store.go and main.go are split by concern (moves only).

## v0.2.0 — 2026-11-11

- `reqcove status` knows Android devices (the OS Tailscale reports): their apps
  trust only the system's CAs, so it says to check the CA in Chrome and to keep
  `--allow-hosts` to the hosts under test, instead of asking to install a CA
  that is installed.
- Names with `sign` as a whole word (`sign`, `X-Sign`) are masked: an app's
  request-signing header was seen unmasked. `design` and `signup` are not.
- In the container image, `run`'s log names the `docker run -i … reqcove mcp`
  command for Claude Code, not `reqcove mcp` inside the container.
- `run --mcp-http`: the MCP tools over HTTP on the node's port 8090, for agents
  on your own devices on the tailnet (Grok Bot, through Tailscale's OAuth apps),
  with a token `run` prints. Stateless: agents go on across restarts of `run`.
  `run` logs each call over HTTP: the device and the tool.
- The MCP server gives clients short instructions (the skill's rules), for
  agents without the skill. `capture_stats` has `started`, and a cursor from
  before a restart of `run` is refused instead of paging the new records.
- The README is shorter: what Reqcove does and how to start. Every option and
  the details (rules, `--ui`, the Simulator, HAR, an upstream proxy, pinning,
  the skill, more limits) moved to `docs/guide.md` (and `guide.ja.md`).
- `run --ui`: a read-only page of the flows on the tailnet node, opened from a QR
  code: your own devices on the tailnet see every device's flows, a `--device`
  device of another user its own. It follows new flows without reloading.
- `run --web`: mitmweb also opens from your own devices on the tailnet, on the
  node's port 8081, with the link `run` prints. It now shows bodies (up to 2 MB
  each; before, none: they stream past mitmproxy), and keeps the newest 10,000
  flows and 256 MB of bodies instead of every flow.
- The `--ui` and `--web` links stay the same across starts (their tokens are
  kept in the state directory; delete `ui-token` or `web-token` to change one).
- `run --upstream-proxy http://HOST:PORT` (and `--upstream-ca FILE`): decrypted
  requests go on through Burp Suite or another HTTP proxy, which sees the same
  traffic while Reqcove keeps its records. See "An upstream proxy" in docs/guide.md.
- Burp's CA is fetched from the proxy's own `/cert` at start when the proxy is on this
  computer, so `--upstream-ca` is needed only for other proxies that decrypt.
- `run --local-proxy`: an HTTP proxy on `127.0.0.1:8082` for this computer's own
  apps, such as the iOS Simulator, recorded as the device `local`. On macOS the
  system's web proxies point at it while `run` runs and go back when it stops,
  and the CA goes into the booted Simulators; on Linux, point apps at it.
  `run` prints how to have this computer trust the CA too (its own browsers'
  requests to allowed hosts are then recorded), and `status` and `cleanup` how
  to stop.
- `reqcove har > flows.har`: the recorded flows as a HAR 1.2 file, masked, with
  the same filters as `list_flows`.
- `run --rules-reload`: the `--rules` file is read again when it changes; a
  file that does not load leaves the rules before it, and says why.
- `reqcove help` (also `-h`, `--help`) shows the commands.
- A build from source is versioned by its commit (`dev-77e6706`, `-dirty` with
  uncommitted changes) instead of `dev`, so `reqcove mcp` can tell a `run` of
  another build and say to reconnect.
- `run --pass-hosts HOSTS` (and `@FILE` for it and `--allow-hosts`, one host
  a line): allowed hosts carried undecrypted, for apps that refuse Reqcove's
  certificate there (certificate pinning). Only their connections are recorded (host, server,
  times, bytes; the new tool `list_passthrough`), no URL or contents; a host
  filter naming one says so in a `note`. `reqcove status` names hosts a
  device refused again and again while accepting the CA elsewhere, with the
  `--pass-hosts` to add. They skip `--rules` and `--upstream-proxy` (`run`
  warns).
- `reqcove init`: the agent skill (`skills/reqcove/SKILL.md`, carried in the
  binary) into `~/.claude/skills` and `~/.agents/skills` for the agents found
  in `~` (or `--client`); it updates only its own unchanged file, and leaves
  others' skills, edited ones and links alone. `reqcove status` and `run` say
  when an installed one is from another version. The `status` tool now lists
  `allow_hosts`.
- A container image (`Dockerfile`, distroless, not root), built from the
  repository: one container and volume per environment, the agent through
  `docker run -i … reqcove mcp` ([docs/container.md](docs/container.md)).
  `scripts/container-smoke.sh` checks it without a tailnet login; CI runs it.
- `reqcove mcp` serves the tools itself and forwards each call to `run`,
  dialling it again when needed: the agent stays connected while `run`
  restarts (before, the relay ended with it, and Claude Code needed `/mcp`;
  tried in a Claude Code session).
  While `run` is not running, the tools say so; the first answer after a
  restart says flow ids and cursors from before it are gone, and one from a
  `run` of another version says to reconnect the agent. When `run` stops,
  the agents' connections to it close at once.
- Names containing `ticket` (a WebSocket's `wsTicket`, seen unmasked) or
  `dpop` are secrets too; `ticket_id` and `ticketNumber` are not.
- A body's `"key"` holding a dotted lowercase name (OpenTelemetry's
  `{"key": "service.name", …}`) is no longer masked: the attributes' names
  were lost (seen by Claude Code reading an app's traces). Mixed case, no
  dots, JWTs, and `key=` in URLs are still masked.
- `list_flows`, `search_flows`, `summarize` (and `reqcove har --user-agent`)
  filter by text in the User-Agent, case-insensitive: one app's traffic, as
  summarize lists the User-Agents. A host filter that matches no flow answers
  with `similar_hosts`, recorded hosts that look alike (`acme-shop.com`
  for `acmeshop.com`). The host filter takes a URL, a port or a final
  dot too, and Unicode names (as punycode). `list_tls_failures` takes only
  device, host, since, until and limit (before, status and method were
  accepted and matched nothing: a failed handshake has no response).
- Several exit nodes on one computer, one `run` per `--state`
  ([docs/several-exit-nodes.md](docs/several-exit-nodes.md)): a `--state`
  directory named `reqcove-NAME` names the node so, and the name is kept in it
  (`node-name`; a directory an older reqcove used keeps `reqcove`), one without
  a CA gets a copy of `~/.reqcove`'s (listed in `~/.reqcove/ca-copies`, named
  by its `cleanup`), mitmweb takes 8091-8099 on this computer while 8081 is
  taken (the node's port stays 8081), the `--ui` page shows the node's name,
  and the commands reqcove prints for the node carry `--state`. A second
  `--local-proxy` stops at once, before anything changes.
- `--hostname` is kept in the state directory: the next runs, and `cleanup`,
  use it without the flag.
- Every command refuses a `--state` starting with `~` (`--state=~/x`, left
  unexpanded by the shell).
- A `~/.reqcove` holding only a `mitmproxy/` folder with a CA copied from
  another computer is taken as a state directory (README, Tips); before,
  `run` refused it.
- A CA's key (`mitmproxy-ca.pem`) is never replaced: certificate files
  missing beside it are written again from it at start.
- `--dns 1.1.1.1` works without the port (53).
- `--allow-hosts` takes pasted URLs and host:port, using the host (and says so);
  `.example.com` is refused with the right spelling, `*.example.com`.
- Without `--device`, `run` suggests your iPhones and iPads on the tailnet (from the
  Tailscale CLI, when there is one), and it prints the `claude mcp add` command.
- The exit node approval step says how to skip it next time (`autoApprovers` in
  the tailnet policy).
- A request a `--rules` rule fails on (such as a `map_remote` making a bad port)
  is answered with a 502 instead of going on unrewritten.
- `resolve` and `--upstream-proxy` are refused together: Burp connects by the
  name, so a `resolve` rule would not apply. A `map_remote` whose replacement
  cannot work (a missing group) stops `run` at start.
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
