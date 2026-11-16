# Reqcove's security model

[日本語](SECURITY.ja.md)

Reqcove decrypts a phone's HTTPS and hands what it reads to an AI agent. This
page says what it protects, what it trusts, and what it does not try to do,
for v1.0. It keeps to what you need to decide whether to trust Reqcove; the
detail is on two other pages. [masking.md](masking.md) has what masking finds
in each format, and which connections leave no record. The
[guide](guide.md) has each option's "Security details" in the option's own
section, and the rest in its [Security](guide.md#security) section.

A point that was not tried, or that comes from reading code, says so where it
stands. What tests and trials covered is in the "Checked:" line that ends a
section, here or in the guide. Tried with mitmproxy 12.3.1, an iPhone on iOS
27.3 and macOS, unless a line names something else.

Two terms. The **state directory** is `~/.reqcove`, or the one `--state`
names. **Your own devices** are those on the tailnet as the same user as
Reqcove's node, neither tagged: Reqcove checks that when a connection opens
and on every request.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository rather
than a public issue.

## What leaves the phone, and where it goes

### What is recorded

- Only requests to hosts in `--allow-hosts`, and not in `--pass-hosts`, are
  recorded. Two checks enforce it: mitmproxy passes other connections through
  undecrypted, and each request's Host is checked again.
- Connections to Apple's hosts always pass through undecrypted.
- A connection to an allowed host can carry requests to other hosts (HTTP/2
  connection reuse). Those are decrypted with it and not recorded, but `--web`
  shows them and they may be sent on to `--upstream-proxy`.
- Requests and TLS failures outside the list are counted, never recorded,
  but while `reqcove capture allow-all` is on (below): then every host is.
  While `reqcove capture discover` is on (below), their host **names** are
  kept too, with a count: never what they carry.
- A `--pass-hosts` host, and a connection mitmproxy carries as raw TCP, leave
  a record of the connection only, never of what it carried
  ([detail](masking.md#connections-recorded-without-their-content)).
- Some connections leave no record at all: [Not caught](#not-caught).
- The secrets Reqcove recognises are masked as they arrive, so no tool can
  return them: [Masking](#masking).
- Bodies are returned only when a tool is asked for them (`bodies` in
  `get_flow` and `search_flows`), and by `diff_flows`, which compares them.
- Records live in memory, at most 10,000 flows and 64 MiB of text, and are
  gone when `reqcove run` stops. Reqcove writes no flow to disk itself
  ([what a record keeps](masking.md#what-a-record-keeps)).
- `reqcove har > FILE` writes the records where you send them, masked as the
  tools return them, with your shell's file mode: often readable by other
  users, while the state directory is 0700.
- Reqcove does not record DNS.

### What the agent sees goes further

- Whatever a tool returns is sent to the agent's model provider. Choose
  `--allow-hosts` with that in mind: `--allow-hosts '*'` sends other apps' and
  sites' traffic too, and Reqcove warns when it starts; `reqcove capture
  allow-all` does for a while, and its answer warns.
- Besides the traffic, the `status` and `list_devices` tools carry the node's
  MagicDNS name (which includes the tailnet's name), its tailnet addresses and
  the devices' machine names; not your login (from reading the code).
- It stays there. The provider keeps what it received for as long as its
  terms say.
- It stays with the agent too, which keeps its conversations on the computer
  it runs on. Claude Code writes each session, tool results included, to
  files under `~/.claude/projects/`. Other agents were not looked at.
- Those copies are not Reqcove's: stopping `run` empties its records, not
  them, and `reqcove cleanup` does not touch them.
- A secret that masking did not find, or anything read with `--no-redact`,
  stays readable there, and in whatever the agent wrote from it (a summary, a
  file, a commit).

Checked: seen on this Mac with Claude Code 2.1, 2026-11-14.

### The exit node's DNS

- **Other tailnet devices can resolve names through the exit node**, if the
  tailnet policy lets them use an exit node (from reading Tailscale's code).
  With `--dns system`, or a LAN resolver in `--dns`, they can look up names
  only your router's or your company's resolver knows.
- **From this computer to the upstream, DNS is plain**, and answers are not
  checked with DNSSEC (from reading the code). The network this computer is
  on (its Wi-Fi, the ISP) sees the names the devices look up, and someone on
  that path can answer falsely.
- **A false answer gets little** (from reading the code, not tried). HTTPS
  still has to show a certificate for the name, and an answer pointing at
  this computer, its LAN or loopback is refused. Plain HTTP can be sent
  elsewhere, as it can on any network.

[Details](guide.md#security-dns).

### Logs to Tailscale

Reqcove's node does not send logs to Tailscale. A tailnet that requires data
plane audit logs is not supported (`reqcove status` says so); Reqcove never
turns logs on.

## What is stored, and who can read it

The keys and the tokens are in the state directory. It is 0700 and the files
in it 0600: open to your OS user only, and to any process running as that
user. The records themselves are in memory only. A service's files and
Homebrew's log are outside it
([what `reqcove cleanup` leaves](#what-reqcove-cleanup-leaves)).

| In the state directory | What it holds |
|---|---|
| `mitmproxy/mitmproxy-ca.pem`, `mitmproxy/mitmproxy-ca.p12` | The CA and its private key |
| `tsnet/` | The node's key, and tsnet's own log lines |
| `ui-token`, `web-token`, `mcp-token` | The tokens of `--ui`, `--web` and `--mcp-http` |
| `login-url`, `links` | The login URL while login is pending; the links with tokens once `run` is ready |
| `lan-allowed` | The addresses LAN mode allows |
| `mitmproxy.log` | mitmproxy's error lines only |
| `ca-copies` (in `~/.reqcove`) | Which other state directories hold a copy of the CA |
| Also | mitmproxy's lock file and launcher, the SOCKS5 password, four sockets, and with `--local-proxy` the system proxy settings to put back |

The state directory is checked itself, not the directories above it. Keep it
(and `--state`) under directories only you can write: someone who can rename
entries in a parent can swap the state directory for their own.

### The CA's private key

- `~/.reqcove/mitmproxy/mitmproxy-ca.pem`, and `mitmproxy-ca.p12` next to it
  (a PKCS#12 file without a passphrase), hold the private key of a CA your
  iPhone trusts. Whoever has it can impersonate any HTTPS site to that iPhone.
- The CA is not limited to any names (from reading mitmproxy's code). A
  device that trusts it trusts it for every HTTPS site, not only the hosts in
  `--allow-hosts`: that list is what Reqcove decrypts, not what the key can
  sign for.
- The CA is made at the first start and is valid for 10 years (mitmproxy
  12.3.1's lifetime for a CA, from reading its code). `run` and
  `reqcove status` print the date.
- The trust lasts until the profile is removed from the device. Stopping
  `run`, `reqcove cleanup` and deleting the state directory do not remove it.
- Keep the directory to yourself. When you stop using Reqcove, remove the
  profile from the iPhone first, then delete the directory (`reqcove cleanup`
  lists the steps).
- Copying the directory to another computer copies the key.
- A `--state` directory without a CA gets a copy of `~/.reqcove`'s at start,
  key included. So "delete the directory" means each of them, and removing
  the profile from the iPhone is what stops them all.
- Backups hold the key too (from reading the code; no backup was looked at).
  Exclude the directory, or count the backup as one more place the key is.

[Details](guide.md#security-ca-copies).

Checked: the E2E test checks only that the CA is valid for over 9 years.

### The login URL

While the node is not logged in, `reqcove run` prints a login URL. Whoever
opens it first puts this node in their own tailnet. The same care goes to the
links that carry the `--ui`, `--web` and `--mcp-http` tokens.

- **Terminal only.** The login URL and the links are printed on `run`'s
  terminal and by `reqcove links`, never in a log line or by the MCP tools.
  The `status` tool, and with it the agent and its model provider, says where
  to find the login URL but does not carry it.
- **`reqcove links` refuses when its output is not a terminal**: a help
  against an agent running it, not a guarantee (a program can give it a
  terminal).
- **In the state directory** they are in files only your user can read
  (0600). That keeps other users out, not a program running as you: an agent
  with a shell can read them, as it can the node's key, the tokens and the
  CA's key there.

[Details](guide.md#security-login-url).

### Logs

`mitmproxy.log` in the state directory holds mitmproxy's error lines only.
`run`'s own output, when it is a file (a redirect, a service's log), is made
0600 as `run` starts, before its first line. It holds no token or login URL,
but what `run` logs of the devices. [Details](guide.md#security-logs).

### What `reqcove cleanup` leaves

`reqcove cleanup` prints the steps and takes none of them itself, with one
exception: system web proxies that a `run` which died left pointed at
`--local-proxy` are put back. With `--delete-state` it also deletes the state
directory (the node's key, the CA and its key, the tokens, `lan-allowed`, the
logs kept there), unless `run` holds it, it still holds proxy settings to put
back, or it is not Reqcove's (from reading the code).

These stay until you remove them: the CA's profile on each device and its
trust on this computer or in a Simulator, the node in the tailnet, other
state directories, a service, the skill and the agent's MCP server entry, and
what left Reqcove (HAR files, the agent's transcripts, backups, uv's cache).
[Details](guide.md#security-cleanup).

### In a container

mitmproxy, which opens what sites send, runs in the container. A flaw there
reaches the container (the records, the CA's key in its volume), not the rest
of the user's files. The image has no shell or package manager and runs as a
user of its own, not root. In exchange, whoever can use the Docker daemon's
socket can read the volume, the CA's key included. When the container is
given a terminal (`docker run -t`), `docker logs` keeps the login URL, the
links and the `--mcp-http` token until the container is removed.

How to run it: [container.md](container.md).
[Details](guide.md#security-container).

<a id="trust"></a>

## Who can use it

- **Your OS user is trusted.** The state directory and the MCP socket in it
  are open to that user only. Any process running as that user can read the
  records, and the CA's private key. Reqcove promises nothing stronger.
- **The devices you name are trusted to use the exit node**, nothing else.
  Traffic from other tailnet devices is refused, on the exit node and on the
  Remote Proxy.
- **A device name is what each device calls itself.** So `--device` takes
  one only from your own user's devices, and only while neither it nor
  Reqcove's node is tagged (a tagged node keeps the user ID of whoever tagged
  it). Name other devices by machine name, IP or StableID.
- **In LAN mode (`--lan`), the addresses you allow are trusted to use the
  proxy**, with no password: an address, not a device
  ([LAN mode](#lan-mode---lan)).

### What the devices can reach

Through the exit node and the Remote Proxy, the devices reach public IPv4
addresses. Reqcove refuses:

- this computer's own addresses (those of every interface) and the networks
  those interfaces are on, so a LAN with public addresses, or a cloud
  server's subnet with its neighbours, is refused too;
- loopback, private and link-local ranges, the tailnet's range, multicast
  and the other special-purpose ranges;
- all of IPv6.

**Not caught: your network's public address.** It is not an address of this
computer's interfaces. A device that connects to it may reach what the router
forwards (port forwarding), or, on a cloud server, this computer. Not tested.

Routes, pings and UDP: [details](guide.md#security-reach).

### A computer shared with other users

Reqcove trusts your OS user, not the others on the computer. File modes keep
them out: the state directory is 0700, the files in it 0600, and so are the
four sockets there. Another user cannot read the records, call the tools or
take the keys (from reading the code, where each is made; not tried with a
second user). Another user can still:

- see `run`'s and mitmproxy's command lines in `ps`: the device names, the
  hosts, and any `--mask-names` or `--mask-values` given there rather than in
  an `@FILE` (from reading the code); never the SOCKS5 password, the tokens
  or mitmweb's password;
- send requests through `--local-proxy`, whose port takes any user's;
- reach the node's ports, when this computer itself is on your tailnet as
  you: the tokens are what keep them out of `--ui`, `--web` and `--mcp-http`,
  and the one-use code out of `reqcove console --tailnet`'s page (from
  reading the code; to that page they are one of your own devices, this
  computer);
- read what you write outside the state directory: a HAR file gets your
  shell's file mode, usually readable by others.

Not covered: root, and anyone who can become your user.
[Details](guide.md#security-shared-computer).

### Other processes on this computer

mitmproxy's SOCKS5 port is on 127.0.0.1, protected by a password made at each
start (kept in a 0600 file, never in process arguments). Only Reqcove knows
it, so another local process can neither use the proxy nor pose as a device.
Reqcove holds the port itself for the whole of `run`, also while it restarts
mitmproxy, and no connection is read before the password check is loaded.

Not covered: processes of your own user, which can read the password file
anyway, and root. Another user was not tried. How the port is held, and what
was tried: [details](guide.md#security-other-processes).

`reqcove capture` (add, remove, set, stop, start, save, allow-all, discover; requests, approve, deny since v1.2) changes which hosts `run` records, over
`ctl.sock` in the state directory (0600, a test), not over the MCP tools'
socket: no tool changes what is recorded (one can ask you since v1.2,
below). It runs only when its input and
output are a terminal, and the skill and the server's instructions tell agents
never to run it. The terminal check is a guard against mistakes, not a
boundary: any process of your user (an agent that can run commands among
them) can give it a terminal, or write to `ctl.sock` itself, and so record
more hosts, every host for up to 24 hours with `allow-all`. `run` checks each
request itself: `"*"` is refused (but as `allow-all --for`, time-limited),
and so is a change in LAN mode (tests). Each change leaves a line in `run`'s log, a
marker with source `cli` and `scope_change` in `status` (an E2E test), so
one you did not make shows. Since v1.3 the `reqcove console` page makes the
same changes but `set` ([below](#reqcove-console-page)).

`reqcove reload` (since v1.1) goes the same way, with the same guards and
trace: it reads the config, its hosts files and the `--rules` file again and
puts their hosts and rules in force. So whatever can write those files and
run it (or write to `ctl.sock`) changes what is recorded and where requests
go while `run` runs, without `--rules-reload`. It never takes `--no-redact`,
`--web` or any other setting but the hosts and the rules: those take a
restart (a unit test names every other flag as taking one; that none of them
applies is from reading the code).

`reqcove capture stop` turns the `--rules` file off with the recording: no
mock, map_local, map_remote, modify_headers or resolve rule applies while
stopped, presets included (turned off, and `activate_preset` refused), so
the app's requests go to the real servers as it sends them: test requests a
mock or map_remote kept off production reach it then. The answer of `stop`
warns of it, and `status` says `"recording": "stopped"` (E2E tests: a mocked
URL reaches the server, on a new connection and on one decrypted before the
stop; a preset cannot be turned on). mitmproxy decrypts mitm.it alone
meanwhile, never an empty list (which would decrypt everything); connections
decrypted before stay decrypted until they close, unrecorded (an E2E test),
a body under way on them copied no more (a unit test); `--web`'s mitmweb
still lists their requests, unmasked, without their bodies (from reading the
code).

`reqcove capture allow-all --for D` records **everything** for a while (at
most 24 hours), as `--allow-hosts '*'` does: every app's and site's
traffic on the devices but Apple's and the `--pass-hosts` hosts (an E2E
test), readable by agents and their model providers, sent on to
`--upstream-proxy` and shown by `--web` if they are on (from reading the
code). Apps that pin their certificates fail meanwhile. The answer warns of
it, and `status` says `"recording": "allow-all"` with `allow_all_until`.
- **Time-limited:** it ends by this computer's clock or by `run`'s own
  running time, whichever comes first, so a sleep does not extend it, and
  fails closed: reqcove stops recording the other hosts first, then tells
  mitmproxy; if mitmproxy does not answer, it is restarted without it (unit
  tests, with either clock, and for a `capture stop` meanwhile; an E2E test kills mitmproxy just before the end:
  the one started next does not decrypt the other hosts). Never kept past a
  restart of `run`, and never written to a file: `capture save` writes the
  hosts you allowed, never `"*"`. Not tried across a real sleep.
- **Kept after:** the records made meanwhile stay in memory until evicted or
  `run` stops (the maintainer's choice), so agents can still read other apps'
  traffic after it ends; `status`'s `records_outside_scope` counts them. A
  restart of `run` empties them, as all records.
- **The rules** apply to the hosts you allowed alone: a `modify_headers`
  rule naming no host (a token, say) is not sent to the other hosts (an E2E
  test).
- Connections decrypted meanwhile stay decrypted, unrecorded, until they
  close after it ends (an E2E test).

`reqcove capture discover --for D` (at most 24 hours) keeps, for a while,
the **names** of the hosts outside the ones recorded that the devices reach
(a TLS connection's SNI, a request's Host on a connection decrypted but not
recorded) and how often: never content, a URL path or a time. So while it is
on, "counted, never recorded" holds for what those hosts carry, not for their
names.
- **Local only:** the names reach `reqcove status`, this computer's
  agents (`status`, `summarize`) and, since v1.3, the `reqcove console` page
  on 127.0.0.1 (host names alone, put in as text: tests; at most 30, from
  the code), never
  `--mcp-http`, the `--ui` page nor the tailnet page of `reqcove console
  --tailnet`, which shows how many (an E2E test: not in what `--mcp-http`,
  `--ui` and the tailnet page read; unit tests of the two servers and of the
  tailnet page). Agents read them as data,
  not instructions, as other names from the traffic; they are masked as
  other host fields, Apple's hosts and mitm.it are left out, and a command
  to add one is built by Reqcove only for a plain host name.
- **Time-limited** as allow-all (either clock, a sleep does not extend it):
  at its end the records take no name more, whether mitmproxy answers or not
  (unit tests). The names seen stay in memory until `run` restarts or
  discovery starts again; never in a file. Bounded: 1,000 names.
- **Not exhaustive:** a connection without a name, one with ECH (its outer
  name only), and a non-TLS connection to a host outside the scope are not
  seen (from reading the code, not tried). Who can turn it on: as `reqcove capture` (above).

Since v1.2 an agent can **ask** for hosts to be recorded
(`request_capture_add`, a tool of `reqcove mcp` alone: never on `run`'s own
socket's tool list, never over `--mcp-http`; refused in LAN mode). The
request records nothing; you approve it with `reqcove capture approve ID`
(it shows the hosts and asks y/N) or in the agent's client's dialog, and it
then adds those hosts as `reqcove capture add` does (unit tests; an E2E test
through `reqcove mcp`).
- **What it guards:** an agent that has Reqcove's MCP tools and no shell, steered by text a
  page or an app put in the records: it can ask, but not record a
  host, and cannot see anything new unless you approve. What reaches you is
  Reqcove's text and host names checked as such (letters, digits, `-`, `.`;
  no wildcard, no IP address; at most 5), never the agent's words. The id is
  bound to the hosts it was made with: an approval for others is refused.
  Requests are bounded (3 pending, 10 made in 10 minutes, no host you denied
  asked again for 10 minutes, alone or with others) and expire in 10 minutes
  by either clock (unit tests). Over MCP's newest protocol the dialog's answer
  comes back in a second call: it counts only for a dialog `reqcove mcp`
  showed on that connection, once, within 2 minutes by either clock; one made
  up, replayed or late approves nothing (unit tests).
- **What a steering page can still do:** make the agent ask for hosts it
  names, again and again within those bounds, and word its chat to you so
  that you approve. Read the hosts before you type `y`.
- **What it does not guard:** an agent that can run commands as your user is
  not kept out, as above: it can write to `ctl.sock` itself (approve
  included), or give `reqcove capture approve` a pseudo terminal. The client's
  dialog is the client's: whatever answers it for you (hooks can, in Claude Code, as
  reported by others; not tried here) approves. A client that
  declines without showing it leaves the request pending (a test with an
  in-memory client). In Claude Code's terminal CLI (2026-11-16), Esc and
  Accept with the box unticked left the request pending; ticked, it was
  approved ("approved in the dialog").
- **The trace:** each state is a line in `run`'s log; an approval is a
  marker with source `mcp` and `scope_change` ("capture add HOST (asked by an
  agent, approved in the terminal)" or "in the dialog"), as a change of yours
  (an E2E test). Requests live in memory only, and a restart of `run` drops
  them.

Since v1.3 **`reqcove restart`** (a terminal only, as `capture`; an agent
with a shell can run it, as it can `capture`) makes `run` stop as Ctrl-C does
and exec the binary it was started from, in the same process
([guide](guide.md#restart-in-place-reqcove-restart)). Before it stops, it
checks the config and the command line itself, then asks the binary it would
exec to check them (a hidden check mode of `run`'s, with the same
arguments: it reads them as a start would, and starts nothing, takes no
lock, creates no state directory and writes no file; tests). Refused by
either, nothing stops (a test); a binary without the mode (built before it)
leaves the check to `run`, which says so. What crosses the exec:
- **The state's lock and this computer's page's port**, as open files: no other `run`
  takes the state, and no other process the port, in between (an E2E test
  tries the lock throughout; that no one else bound the port was not tried
  with another user). The new process makes them close-on-exec again before
  it starts anything, so mitmdump and caffeinate never get them (tests: a
  child of the new process holds neither).
- **In its environment:** their numbers, the page's sessions as hashes with
  how long each was unused (never a token or a code: the hashes let no one
  in, and nothing logs them; tests), and the path of the start config's copy.
  The new process unsets them before it starts anything (tests: a child's
  environment holds none), but its own initial environment stays readable to
  your user and root for its life (`ps -E`, `/proc/PID/environ`); hence
  nothing secret goes there. Without the port, no session is taken.
- **The start config's copy:** the bytes `run` read from `--config` at its
  start, held in memory, written at the restart to a new file in the state
  directory (0600, created anew, never through a symlink, a random name),
  so that a failed start can put that config back. It can hold what the
  config holds (`--mask-values` patterns): the same exposure as the config.
  The new process reads it only from the path in its environment, and only a
  plain file of your user's, mode 0600, named as a copy, directly in a
  reqcove state directory; anything else is neither read nor removed, and no
  start is retried (tests). It is removed once the new start is up, or when
  the retry fails and `run` stays down; a copy a crash left is removed by the
  next start in that state directory, after the same checks, never the one
  handed over before the retry is decided (tests).
- **Not carried:** the records, markers and the agents' requests (in memory),
  the console's links not opened yet, the tailnet page and its sessions
  (they end with the run; from reading the code). The retry is made once (marked in the
  environment): a start that fails again stays down.

### The `reqcove console` pages

<a id="reqcove-console-page"></a>
`run` serves two pages, both opened from your terminal and both served by
`run` itself, their sessions in its memory alone: since v1.2
**`reqcove console`**'s, on 127.0.0.1 for this computer, and since v1.3
**`reqcove console --tailnet`**'s, for your own devices on the tailnet. This
section says what each lets in, then, in one place, what neither guards
against and what never reaches a page. Each point says whether a test
checks it or it comes from reading the code.

Since v1.2 **`reqcove console`** opens a page of `run`'s state and of the
agents' requests (above), with Approve and Deny, in this computer's browser
([guide](guide.md#see-the-state-and-approve-in-a-page-reqcove-console)). An approval goes as
`reqcove capture approve` does, for the hosts the request holds, traced
"approved in the console"; a denial as `capture deny`. Since v1.3 the page
also changes the hosts, as `reqcove capture` does and through the same
checks in `run` (an E2E test: each change answers as through `ctl.sock`):
add and remove (recorded or passed undecrypted), stop and start, allow-all
and discovery for 30 minutes to 24 hours and their end, and save, which
writes the hosts files and, on a config without `--allow-hosts=@FILE`,
creates the hosts file beside it and adds that line, after showing it. Its
endpoint for the hosts takes those changes alone: never `capture set`,
`reload`, a restart, a rule, a setting, a path, or a field other than the
change's (tests: each refused before it reaches `run`); the settings and the
restart have endpoints of their own (below). Stop, remove and allow-all
show `run`'s own warnings before a confirm. A change made on a page that read
the hosts before another change (another tab, the CLI) is refused (tests).
Each is traced "(from the console on this computer)": `run`'s log, a `cli`
marker and `scope_change` (an E2E test).

Since v1.3 the page also writes some of `run`'s settings to the `--config`
file, for the next start, and restarts `run`
([guide](guide.md#see-the-state-and-approve-in-a-page-reqcove-console)):
`--device` (the own untagged devices `run`'s node sees; another device is
refused), `--keep-awake`, `--proxy-port`, `--hostname`, `--verbose`, and,
after showing `run -h`'s words for the flag and asking, `--ui`,
`--mcp-http`, `--local-proxy`, `--dns`, `--upstream-proxy` (a URL without
user or password), a `--device` added and `--mask-names`; `--upstream-ca`
may be taken out. It goes through the config writer alone, which writes
those flags only, refuses a line break, a control character or a leading
`@` in a value, keeps the other lines, keeps the file before as
`config.prev`, checks the whole config as the next start would, and refuses
a page that read the config before another change (tests). It never writes
the flags that stay on the command line, the ones naming code or a file to
read or trust (`--rules`, `--proto`, `--upstream-ca`, `--uvx`, `--state`,
…) or `--mask-values`, nor a setting given on `run`'s command line (tests).
It shows `--mask-values` as "set" and a count, never a pattern, and an
`@FILE` by its path, never what it holds (a test: no pattern in any answer
or log line). A restart from the page lists first every setting that
differs from the ones `run` started with and asks; it is the op of
`reqcove restart`, with its checks ([above](#other-processes-on-this-computer)).

Since v1.3 the page also turns the `--rules` file's presets on (for 1 to 5
minutes; a mock for a count too) and off, as `activate_preset` and
`deactivate_preset` do, with their limits: mitmproxy refuses one while
recording is stopped (an E2E test). Before it turns one on, it says what
the preset's kind changes and, for a `map_remote` preset, the destination
the requests then go to with their cookies and tokens: a scheme and a host
name or IPv4 address alone, anything else "not shown". That destination goes
back with the request, and one changed since (the file reloaded) is refused
(tests). It lists the rules by kind, index and preset name, never a value:
no URL, filter, regex, header, body, address, path, description or the
file's error text (tests, unit and E2E). It puts a marker, source `console`
(a help, not proof, as `cli` and `mcp` are). Its CA panel shows the CA's
name, SHA-256 fingerprint and expiry, a QR code of http://mitm.it and how
to add and remove it on an iPhone: the certificate's public fields alone,
never the private key the state directory holds (a test). It gives the
records as a HAR file, the one `reqcove har` writes (what the MCP tools
return: masked, body heads), fetched with the session header and saved from
a blob; no route takes a token in its URL (tests). The answer is an
attachment of `application/json`, with `nosniff` and `no-store`, and it is
refused while `run` masks nothing (`--no-redact`) (tests). The file lands
where the browser saves downloads, with the permissions the browser gives
it there (not checked; the download was not tried in a browser). A restart
from the page offers that file first. With `--ui`, the page links to that
page's bare address, never its token. Presets turned on or off and HAR
files given are logged "(from the console on this computer)".
- **Where:** `run` listens on 127.0.0.1 alone, on a port the system picks,
  from the first `reqcove console` until it ends (`reqcove restart` keeps it,
  below); never on the tailnet node, the
  LAN, the Remote Proxy or `--ui`'s page (a test checks the address).
  `reqcove console --tailnet` opens another page on the node, with codes and
  sessions of its own ([below](#tailnet-console-page)).
- **The way in:** `reqcove console` (a terminal only, as `capture`) gets a one-use
  code from `run` over `ctl.sock`, good for 60 seconds by either clock, and
  prints `http://127.0.0.1:PORT/#c=CODE`. Since v1.3 the browser gets the
  link from a file `run` writes in the state directory (0600, created anew,
  never through a symlink, a random name; tests), which sends it on, and
  `open` or `xdg-open` is given that file's path, never the link (a test
  checks their arguments). `run` removes the file after 60 seconds, at
  `reqcove console --end`, when it ends, and when it starts (one a killed
  `run` left) (tests). The code is after `#`,
  which the browser does not send; the page trades it once for a session
  token, kept in that tab's sessionStorage and sent in a header, never a
  cookie, and takes the code out of the address bar. A code traded a second
  time ends every session and the page says so; so does
  `reqcove console --end`, which also ends every code not traded yet (tests).
  At most 4 sessions, in
  `run`'s memory only, each ending after 12 hours unused and all at `run`'s
  end (but at `reqcove restart`, below). The code and tokens are never logged and never in an answer but the
  trade's own (tests); `run` keeps them as hashes (from the code).
- **What it guards against:** a page open in the browser (another site, or
  one pointing its own name at 127.0.0.1): every request must name exactly
  `127.0.0.1:PORT` as its Host, a change is a POST with the page's own Origin
  and a JSON body (at most 4 KiB), a GET changes nothing, every API call
  needs the session header, which another site's page cannot send without
  CORS (none is given) nor read, and a cookie alone counts for nothing; the
  page sets `default-src 'self'` and `frame-ancestors 'none'`, `no-store`
  and `no-referrer`, loads nothing from elsewhere and puts every value in as
  text. Another user of this computer reaches the port (127.0.0.1 is every
  user's) but without a session gets the page's own files alone (tests
  without a session; another user was not tried); a tailnet device or the
  LAN does not reach 127.0.0.1. Tried by hand in a Chromium-based browser on
  macOS (2026-11-16): the page showed the state and the requests, and Approve
  applied the hosts ("approved in the console"); another browser was not
  tried.

<a id="tailnet-console-page"></a>
Since v1.3 **`reqcove console --tailnet`** opens a second page, for your
own devices on the tailnet
([guide](guide.md#tailnet-page)). It serves only what ends with the run: the
state without this computer's paths, Approve and Deny, the Scope panel's
changes but Save, presets on and off, a marker and the CA panel; never Save,
a setting, a restart or the HAR file, which `run` refuses there, not only
hides (tests: every other route of this computer's page refused, Save too).
- **Where:** on the node's tailnet IPv4 address, on a port of its own (not
  `--ui`'s 80: another origin), from the first `reqcove console --tailnet`
  until `run` ends; `reqcove restart` does not carry it nor its sessions.
  Refused in LAN mode and on a tagged node (tests).
- **The way in:** a one-use code, 60 seconds, as for this computer's page,
  shown in the terminal alone, as a QR code and a link: no opener is run and
  no file written (a test). Its codes and sessions are its own: one page's
  code or token is refused by the other (tests).
- **Every request:** who calls is taken from the connection's address, never
  a header, and checked against the tailnet as it is now: one of your own
  devices (your user's, as Reqcove's node is, neither tagged, not a node
  shared in), so another user's device, a tagged one or one shared in is
  refused, even when `--device` carries it, and on a connection kept alive
  too once that changes (tests, with a stand-in for the tailnet; the
  listener and the connection's address with real tsnet nodes). A session
  is the device's that traded the code (its StableID): used from another
  device, it is refused and ends (a test). The Host must be the page's
  address and port (the MagicDNS name or another port is refused), and an
  Origin, when one is sent, the page's own (`--ui`'s is another; tests).
  Sessions: 1 hour unused and 12 hours in all, in memory only, at most 4
  (from reading the code); `reqcove console --end` ends them, and
  `reqcove status` counts them by page and device (tests). The tailnet as
  `run` sees it is read every 3 seconds: a change counts from then (the
  delay not measured). Changes are traced with the device's machine
  name, "(from the console on NAME, over the tailnet)" (an E2E test).
- **Through the Remote Proxy** (an iPhone whose Wi-Fi proxy is the node's
  `:8080`): a request to the page's address and port goes to the page's own
  handler, in the same process, as it came: never a reverse proxy to its
  listener, never a header added or read. Who calls is the proxy's client,
  from its connection's address, and the page's checks above run unchanged
  (the Remote Proxy itself takes `--device` devices alone, then refuses one
  not your own; a forwarded header naming one of yours counts for nothing).
  A tunnel (CONNECT) to the page's port is refused; the local proxy
  (`--local-proxy`) and LAN mode never serve it. These requests never reach
  mitmproxy, so they make no flow, under allow-all too, and the page's
  session header (`X-Reqcove-Session`) is masked in any record, with
  `--no-redact` too, as a second guard (unit tests; an E2E test with real
  mitmproxy under allow-all; not tried in an iPhone's Safari).

<a id="console-limits"></a>

#### What the pages do not guard against

- **The code is the boundary, on both pages.** Whoever trades a link's
  one-use code first has the session. A code traded a second time ends
  every session of that page and the page says so (tests), but in the
  moment before your tab's trade fails, the other session can act, an
  approval of a pending request included (`reqcove capture requests` then
  shows it approved in the console; read from the code). On the tailnet
  page the own-device check comes on top of the code, not in its place.
- **A device shared on your account is not told apart.** The own-device
  check tells your user's devices from others', not one of your devices
  from another: a device signed in as you that someone else uses (a family
  iPad), this computer's other OS users (when this computer is on the
  tailnet as you, they reach the node from it), and a cloud or CI machine
  signed in to the tailnet as you (an agent's host) are your own devices to
  it. Each still needs the code (from reading the code; not tried with a
  second user or a real tailnet with devices of your own).
- **An agent with a shell, or one that drives the browser or the phone's
  screen, is not kept out.** `reqcove console`, `--tailnet`, `--end`,
  `capture` and `restart` run only in a terminal, and the skill and the
  server's instructions tell agents never to run them; that is a guard
  against mistakes, not a boundary. A process of your user can give them a
  pseudo terminal and trade the code before you, or write to `ctl.sock`
  directly (above). An agent that drives the browser or the phone's screen
  acts as you on a page you opened, and nothing tells it apart. An agent
  with the MCP tools alone gets no code nor any way to make one: no tool
  opens a page or reads the code file (the tool list has none; from reading
  the code).
- **What a session can do**, yours or one someone else traded first:
  everything the page offers. On either page: change the hosts as
  `reqcove capture` does, allow-all for up to 24 hours (every app's traffic
  recorded for agents to read) or stop recording; approve an agent's
  request; turn on one of your `--rules` file's presets for up to 5 minutes
  (a `map_remote` preset sends the device's matching requests, with their
  cookies and tokens, to the destination your file names). On this
  computer's page also: write the settings above for the next start and
  restart `run`, so send the decrypted requests on to a proxy it names
  (`--upstream-proxy`, unmasked there), serve the records to your devices on
  the tailnet (`--ui`, `--mcp-http`), carry one more of your devices, take a
  name out of `--mask-names`, and restart, which empties the records; and
  download the records as a HAR file, masked. Each change is traced: `run`'s
  log "(from the console on this computer)" or "(from the console on NAME,
  over the tailnet)", a `cli` marker and `scope_change` for the hosts, and
  `config.prev` for the file before a settings write (E2E and unit tests).
- **The link on this computer:** the file that holds it is 0600 in the 0700
  state directory, so root and your user can read it for up to 60 seconds (a
  `run` killed meanwhile leaves it until its next start, its code expired
  long before). v1.2's `reqcove console`, against any `run`, still gives the
  link in the opener's arguments, which `ps` shows other users for a moment;
  v1.3's, against a v1.2 `run` (no file), opens nothing and prints the link
  alone (a test). The tailnet page's link is shown in your terminal alone (a
  test).

<a id="console-never-shown"></a>

#### What never reaches a page

- **On either page:** a token, a link with a token, a login URL, the
  `--mask-values` patterns ("set" and a count), what an `@FILE` holds (its
  path at most), an `--upstream-proxy` value `run` would refuse (a password
  written in by hand), and text from an agent or an MCP client (the hosts it
  asked for are checked as host names first); tests: no code or token in an
  answer or `run`'s log, no pattern in any answer or log line, no rule's
  value, description or error text. The flows' contents are never on the
  page itself; this computer's page hands out the records as a HAR file,
  masked, when you ask, and refuses it while `run` masks nothing (tests).
- **Not on the tailnet page:** this computer's paths (the binary, the config
  and hosts files, the state directory in a command's `--state`: taken out
  of every answer; a test with a `--state` not the default), and
  discovery's names (their count alone; tests, unit and E2E).
- **What a page shows beyond `reqcove status` and the config:** the list of
  your own devices on the tailnet (their machine names), to pick from on
  this computer's page; the presets' names, kinds and `map_remote`
  destinations (a scheme and host, as `list_presets` gives an agent); the
  rules' kinds and preset names; the CA's name and fingerprint.

## Masking

The secrets Reqcove recognises are masked as they arrive, so no tool can
return them. `--no-redact` turns masking off, but for the console's
session header (`X-Reqcove-Session`, Reqcove's own credential), masked
always (a test).

- **By name.** A header, query parameter or body field whose name says it is
  a secret (`token`, `password`, `apiKey`, …) has its value masked. Cookie
  values are masked whatever their names.
- **By shape.** `Bearer`, `Basic` and `Token` credentials, JWTs and keys
  with well-known prefixes are masked wherever they appear.
- **By format.** JSON, forms, text lines, GraphQL, XML, HTML and JavaScript,
  `multipart/form-data`, gRPC and WebSocket messages are each read for secret
  names. Protobuf, gRPC's protobuf messages too, is read for names only with
  your schema (`--proto`): without one it shows its structure, never a
  string's text, and is not masked by name.
- **By your own rules.** `--mask-names` and `--mask-values` add names and
  patterns.

The words, the shapes and each format, with what each leaves unmasked, are in
[masking.md](masking.md). The main gaps:

- A secret under a name that does not say so (`{"data": "…"}`), in any
  format. `--mask-names` or `--mask-values` can add it.
- Personal data, such as e-mail addresses and names, is not masked:
  debugging needs it.
- A secret in a format masking does not read (`multipart/mixed`, a base64
  `SAMLResponse` form field), or sent by its position rather than under a
  name.
- A body masking could not look at (not text, or not decoded) is neither
  handed out nor searched while masking is on. `--no-redact` returns it.
- A secret that masking did not find stays with the agent and its model
  provider ([above](#what-the-agent-sees-goes-further)).

## Not caught

These connections leave nothing: no record, no count. The conditions, and how
each was tried, are in
[masking.md](masking.md#connections-that-leave-no-record).

- Connections mitmproxy passes through itself: Apple's hosts, hosts outside
  `--allow-hosts`, and connections it knows by their address only, unless
  `--allow-hosts` names the address. It knows two kinds by address only:
  - TLS without SNI;
  - plain TCP on port 80 or 443 whose first bytes do not name an allowed
    host as mitmproxy reads them: HTTP/2 without TLS, for one.
- An allowed host's HTTP/2 requests riding a connection the app opened for a
  sibling name outside the list. Allow the names that share the certificate
  (`*.example.com`).
- TLS with Encrypted Client Hello, unless the provider's public name is
  allowed.
- A connection to an allowed host whose first HTTP/1 request names one of
  Apple's hosts in `Host`: carried whole, decrypted.
- Raw TCP to a host you allowed by its address only, when the client names
  the host in SNI: `list_passthrough` does not list it, as the record is
  checked by that name.
- A client that finishes the TLS handshake and only then refuses Reqcove's
  certificate and closes, or closes without a request. A pinning app that
  checks the certificate itself does this; one that refuses during the
  handshake is listed.

## Options that widen exposure

For each option, this page says what it exposes, to whom, its main limit and
what to do. How it behaves, and what was checked, is under "Security details"
in the option's section of the guide.

Three options open a port on the node:

| Option | Port | Open to | Guarded by |
|---|---|---|---|
| `--ui` | 80 | your own devices, and the `--device` devices | a token (`ui-token`), set as a cookie |
| `--web` | 8081, relayed to mitmweb | your own devices | mitmweb's password (`web-token`) |
| `--mcp-http` | 8090, at `/mcp` | your own devices | a token (`mcp-token`), sent as `Authorization: Bearer` |

Each answers only requests that name the node (its MagicDNS name or tailnet
address) in `Host`. Each token is kept in the state directory (0600) and
appears only on `run`'s terminal and through `reqcove links`, as the login
URL does ([The login URL](#the-login-url)).

### mitmweb (`--web`)

mitmweb shows traffic **unmasked**: every flow mitmproxy decrypted, bodies
included. From its page, anyone with its password can edit and replay
requests and change options (scripts included), which runs code on this
computer. It is open on this computer and, through the node, to your own
devices only. The password is the same at each start: to change it, delete
`web-token` and start again. [Details](guide.md#security-web).

### The page (`--ui`)

`--ui` serves a read-only page of the records, masked as the MCP tools return
them. It is open to your own devices and the `--device` devices, and only to
a browser holding the token; a `--device` device of another user sees only
its own flows. The token is the same at each start, so a link works until you
delete `ui-token` and start again. Safari's history may keep the URLs of the
pages viewed and of searches. [Details](guide.md#security-ui).

### MCP over HTTP (`--mcp-http`)

The node serves the MCP tools to your own devices that send the token. On a
personal tailnet an agent's device joined through Tailscale's OAuth apps
(Grok Bot) counts as one of your own devices, and whatever the tools answer
reaches it and its model provider (for Grok Bot, xAI's cloud). It gets the
same masked records, without the preset, rule and marker tools. The agent
keeps the token until you delete `mcp-token` and restart `run`.
[Details](guide.md#security-mcp-http).

### The local proxy (`--local-proxy`)

An HTTP proxy on 127.0.0.1:8082 for this computer's own apps (the iOS
Simulator), with no password: any process here, of any user, can use it, and
what it sends to `--allow-hosts` hosts is recorded as the device `local`. A
page in a browser here can point its own name at a LAN, VPN or tailnet
address and reach it through the proxy (DNS rebinding), so keep
`--local-proxy` on only while you need it. Reqcove never makes this computer
trust its CA. Once you do, the CA's private key can impersonate any HTTPS
site to this computer too: remove the trust when done.
[Details](guide.md#security-local-proxy).

### LAN mode (`--lan`)

`run --lan` starts no tailnet node: an HTTP proxy listens on one LAN address
of this computer, with no password. Who may use it is decided by address, and
an address is not a device: whoever has an allowed address later is allowed
too, on this network or on another with the same prefix. An allowed address
reaches public addresses on ports 80 and 443, and private ones only by a name
written exactly in `--allow-hosts`; never this computer or the network the
proxy is on. Use LAN mode on a network you trust, and stop it when done.
[Details](guide.md#security-lan).

### An upstream proxy (`--upstream-proxy`)

Decrypted HTTP(S) requests then go on through that proxy. It sees the
requests and responses unmasked (Burp, for one, keeps them in its project, on
disk), and checking the real server's certificate becomes its job. Where it
connects is its choice too: Burp looks the name up again on this computer, so
a name that resolves into this computer's LAN reaches it, past the exit
node's refusal. Keep `--allow-hosts` narrow, and keep the proxy on this
computer or on the tailnet. [Details](guide.md#security-upstream-proxy).

### Rules (`--rules`)

Rules are yours, read from a file when `run` starts; no MCP tool writes or
changes one. A rules file from someone else is code: it can send your
apps' requests, cookies and tokens included, anywhere. `map_remote` and
`resolve` connect from this computer, this computer and the LAN included, and
a `mock` answers in the site's name. With `--rules-reload`, whatever can
write the file (an agent with file access included) can change where the
devices' requests go while `run` runs; without it, what can write the file
and run `reqcove reload` (since v1.1, [above](#other-processes-on-this-computer)). A mitmproxy that reqcove restarts gets
the rules that loaded last from a private copy (0600, tokens included, removed
when `run` stops); if those no longer load, `run` stops rather than go on
without rules. [Details](guide.md#security-rules).

### Mock presets

A mock marked `preset: NAME` in the rules file does nothing until an agent
turns it on with `activate_preset`. Writing a preset is your consent to that.
An agent can turn on only what you wrote, for at most 5 minutes each time,
with no cap on turning it on again, and text a site wrote into the records
can try to steer it into that. Allow the read tools by name: a client that
allowed `"mcp__reqcove"` wholesale turns presets on without a prompt.
[Details](guide.md#security-mock-presets).

### map_remote, modify_headers and resolve presets

A preset of these kinds changes where the device's requests go, or what they
carry, while it is on. A `map_remote` preset sends the matching requests,
with the app's cookies, tokens and login bodies, to the target you wrote. An
agent cannot choose the target, only when. The risk to weigh is a stale
target: an old tunnel or staging name someone else holds now. The 5 minutes
bound the switch, not its effects: the app may keep what it got there.
[Details](guide.md#security-presets).

### A flags file (`--config`)

`run --config FILE` (for `brew services` and `reqcove service install`) takes
`run`'s flags from a file: what can write that file decides the next start's
flags. Since v1.1, a `reqcove run` with no arguments at all reads
`~/.config/reqcove/config` too (else Homebrew's `etc/reqcove/config`), with
the same checks. The file must be yours and readable by you only. Five flags are
refused in it and stay on the command line: `--no-redact`, `--web`,
`--allow-hosts '*'`, `--rules-reload` and `--lan`.
Since v1.1, `reqcove setup` puts the hosts in a file beside it (`hosts`,
0600), which the file reads with `--allow-hosts=@FILE`: what can write that
file decides what the next start records too. `run` does not check its owner
or mode (from reading the code); `reqcove capture save` writes it only when
it is a plain file of yours. Since v1.3, on a config that names no hosts file,
`capture save` asks y/N, then creates one beside it (0600, never over a file
or link there) and adds its `--allow-hosts=@FILE` line to the config: only
that line, never through a link nor to a config not yours (unit tests).
[Details](guide.md#security-config).

## Prompt injection

What the records hold was written by others. Response bodies, and also
response headers, status reasons, redirect targets and error messages, are
written by remote sites and may contain text meant to steer the agent. An app
chooses its User-Agent, its TLS names and the JSON keys it sends, and a
tailnet peer its device name.

- **Reqcove's tools read, with one exception.** An agent can turn on a rule
  you marked as a preset ([Mock presets](#mock-presets),
  [the other kinds](#map_remote-modify_headers-and-resolve-presets)). No tool
  writes or changes a rule; with no presets, nothing an agent calls changes
  traffic.
- **The agent may also hold other tools**: a shell, file writes, the
  network, other MCP servers. Text a site wrote into a record can try to
  steer it into using those (send a cookie somewhere, edit a file). Reqcove
  cannot stop that from its side; your agent's own settings can.
- **What to do.** Give an agent that reads Reqcove only what the task needs:
  one that only reads Reqcove and answers you is the safest shape. In Claude
  Code, allow Reqcove's read tools by name (not `activate_preset`) without
  allowing shell commands or network tools along with them. In Codex, keep
  its sandbox and approvals.
- **What Reqcove does.** Each tool that returns what sites, apps or the
  tailnet wrote says in its description that it is data, not instructions,
  and so do the server's instructions, sent to every client. Whether a model
  keeps to them is not something a test can show.
- **What a record cannot prove.** A flow's host is the request's Host, which
  the app chooses, and a marker's `source` is the channel, not proof.

[Details](guide.md#security-agent).

## mitmproxy's own code

mitmproxy and its dependencies (44 packages) come from a lock file built into
Reqcove. `run` starts mitmproxy with `uv run --locked --script`, which
installs exactly the files the lock names and checks each one's hash. CI
audits the lock for known vulnerabilities (pip-audit).

- Plain `uvx` checks no hash, even when given them. It is used for another
  `--mitmproxy-spec`, and for a `--uvx` whose file is not named `uvx`.
- The lock overrides one version. mitmproxy 12.3.1 caps tornado, mitmweb's
  server, at 6.5.10, in which the audit found three vulnerabilities. The lock
  pins 6.6.1: 6.6 fixed those three, and 6.6 itself has CVE-2026-126347.
  mitmproxy's own tests were not run with it.

[Details](guide.md#security-mitmproxy-code).

## Your responsibilities

Reqcove leaves these to you:

- **Consent.** Carry and record another person's device only with their
  consent ([below](#other-peoples-devices)).
- **The CA.** Remove its profile from each device when you stop, and keep
  the state directory, its copies and its backups to yourself
  ([The CA's private key](#the-cas-private-key),
  [What `reqcove cleanup` leaves](#what-reqcove-cleanup-leaves)).
- **A shared computer.** Other users can still see and reach some things
  ([A computer shared with other users](#a-computer-shared-with-other-users)).
- **What the agent may read and do.** Choose `--allow-hosts` narrowly, and
  give the agent only the tools the task needs
  ([Prompt injection](#prompt-injection)).

### Other people's devices

`--device` can name a device that is not yours, and LAN mode carries whatever
address you allow.

- Carry and record a device only with the consent of the person who uses it.
- Its requests to the allowed hosts are decrypted and recorded, and what an
  agent reads of them goes to its model provider.
- The device trusts a CA whose key you hold, for every site, until its
  profile is removed ([The CA's private key](#the-cas-private-key)).
- Reqcove asks no one and checks no consent (from reading the code).
- Recording someone's traffic without consent may be against the law where
  you are.
- Your own device's traffic holds other people's words too (a chat's
  messages), and personal data is not masked.
