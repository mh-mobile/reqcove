# Reqcove's security model

[日本語](SECURITY.ja.md)

Reqcove decrypts a phone's HTTPS and hands what it reads to an AI agent. This
page says what it protects, what it trusts, and what it does not try to do. It
describes v1.0. What masking finds in each format, and which connections leave
no record, is in [masking.md](masking.md).

A point that was not tried, or that comes from reading code, says so where it
stands. What tests and trials covered is in the "Checked:" line that ends a
section. Tried with mitmproxy 12.3.1, an iPhone on iOS 27.3 and macOS, unless
a line names something else.

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
- Requests and TLS failures outside the list are counted, never recorded.
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
  sites' traffic too, and Reqcove warns when it starts.
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

- The exit node answers DNS over HTTPS (Tailscale's PeerAPI) for the devices
  that use it. Other devices of the tailnet that may use the exit node can
  resolve names through it too (from reading Tailscale's code: it answers any
  peer the tailnet policy lets use an exit node).
- They ask the same upstream as your devices: `1.1.1.1` by default. With
  `--dns system`, or a LAN resolver in `--dns`, that is your router's or your
  company's resolver, and they can look up names only it knows.
- From this computer to the upstream, DNS is plain and unencrypted, for the
  exit node and for the Remote Proxy alike, and answers are not checked with
  DNSSEC (from reading the code). So the network this computer is on (its
  Wi-Fi, the ISP) sees the names the devices look up, and someone on that
  path can answer falsely.
- Off the path that is hard: each query has a random ID and its own random
  port, and answers from any other address are dropped.
- A false answer gets little (from reading the code, not tried). HTTPS still
  has to show a certificate for the name: mitmproxy checks it for decrypted
  hosts, the phone itself for the others. An answer pointing at this
  computer, its LAN or loopback is refused like any connection there. Plain
  HTTP can be sent elsewhere, as it can on any network.
- To hide the names, a local DNS-over-HTTPS relay could serve as
  `--dns 127.0.0.1:PORT`; that has not been tried.

Checked: a test (an answer pointing at this computer, its LAN or loopback is
refused). Tried: the exit node answered this computer, which was not one of
`--device`.

### Logs to Tailscale

Reqcove's node does not send logs to Tailscale. A tailnet that requires data
plane audit logs is not supported (`reqcove status` says so); Reqcove never
turns logs on.

## What is stored, and who can read it

What Reqcove keeps on disk is in the state directory. It is 0700 and the
files in it 0600: open to your OS user only, and to any process running as
that user. The records themselves are in memory only.

| In the state directory | What it holds |
|---|---|
| `mitmproxy/mitmproxy-ca.pem`, `mitmproxy/mitmproxy-ca.p12` | The CA and its private key |
| `tsnet/` | The node's key, and tsnet's own log lines |
| `ui-token`, `web-token`, `mcp-token` | The tokens of `--ui`, `--web` and `--mcp-http` |
| `login-url`, `links` | The login URL while login is pending; the links with tokens once `run` is ready |
| `lan-allowed` | The addresses LAN mode allows |
| `mitmproxy.log` | mitmproxy's error lines only |
| `ca-copies` (in `~/.reqcove`) | Which other state directories hold a copy of the CA |
| Also | mitmproxy's lock file and launcher, the SOCKS5 password, three sockets, and with `--local-proxy` the system proxy settings to put back |

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

Copies in other state directories:

- A `--state` directory without a CA gets a copy of `~/.reqcove`'s at start
  (several exit nodes on one computer, one profile on the iPhone):
  `mitmproxy-ca.pem` with the key, and the certificate files; not
  `mitmproxy-ca.p12`, nor mitmweb's password. `run` logs where it copied it.
- The key is then in each such directory, each 0700 with the files 0600.
  Deleting one leaves it in the others, so "delete the directory" above means
  each of them. Removing the profile from the iPhone is what stops them all.
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
- Exclude the directory, or count the backup as one more place the key is.
- A restore can widen the modes: `run` makes the directory 0700 and the
  token files 0600 again at start, not the other files (from reading the
  code).

Checked: tests (a copy's directory is 0700 and its files 0600; the E2E test
checks only that the CA is valid for over 9 years).

### The login URL

While the node is not logged in, `reqcove run` prints a login URL. Whoever
opens it first puts this node in their own tailnet. The same care goes to the
links that carry the `--ui`, `--web` and `--mcp-http` tokens.

- **Terminal only.** The login URL and the links are printed on `run`'s
  terminal and by `reqcove links`, never in a log line or by the MCP tools.
  The `status` tool, and with it the agent and its model provider, says where
  to find the login URL but does not carry it.
- **Off a terminal** (a service, `docker logs` without `-t`, an agent's
  shell), `run` prints neither the URL nor the links, only that
  `reqcove links` prints them.
- **`reqcove links` refuses when its output is not a terminal**: a help
  against an agent running it, not a guarantee (a program can give it a
  terminal). The skill and the server's instructions tell agents never to run
  it.
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
- **0600 keeps other users out, not a program running as you.** An agent
  with a shell can read those files, as it can the node's key, the tokens and
  the CA's key in the same directory.
- **mitmweb's server logs a failed request's URL**, `?token=` included, into
  `mitmproxy.log`: the addon masks the token there first.

Checked: tests (tsnet's lines, read from a test control server; the mitmweb
E2E test for `mitmproxy.log`). Tried 2026-11-13: Claude Code's `!` gets
nothing from `reqcove links`.

### Logs

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

### What `reqcove cleanup` leaves

`reqcove cleanup` prints the steps and takes none of them itself, with one
exception: system web proxies that a `run` which died left pointed at
`--local-proxy` are put back. With `--delete-state` it also deletes the state
directory (the node's key, the CA and its key, the tokens, `lan-allowed`, the
logs kept there), unless `run` holds it, it still holds proxy settings to put
back, or it is not Reqcove's (from reading the code).

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
  ([above](#what-the-agent-sees-goes-further)), backups, and uv's cache of
  mitmproxy and Python.

Checked: tests (the refusals to delete, the proxies put back, the CA copies
it names).

### In a container

How to run it: [container.md](container.md).

- mitmproxy, which opens what sites send, runs in the container. A flaw
  there reaches the container (the records, the CA's key in its volume), not
  the rest of the user's files.
- The image has no shell or package manager and runs as a user of its own,
  not root.
- In exchange, whoever can use the Docker daemon's socket can read the
  volume, the CA's key included.
- When the container is given a terminal (`docker run -t`), `docker logs`
  keeps the login URL, the `--ui`/`--web` links and the `--mcp-http` token
  until the container is removed. Without one, `run` names `reqcove links`
  in their place.
- `reqcove mcp` runs with `--log-driver none`, so the tools' answers are not
  logged.

Checked: `scripts/container-smoke.sh` (the state directory's owner and mode,
no network needed); not by an attack.

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

Beyond that:

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
- **Not caught: your network's public address.** It is not an address of
  this computer's interfaces. A device that connects to it may reach what the
  router forwards (port forwarding), or, on a cloud server, this computer.
  Not tested.

Checked: tests (pings to 127.0.0.1, from a device not in `--device` and from
a listed one; a datagram sent from this computer).

### A computer shared with other users

Reqcove trusts your OS user, not the others on the computer. File modes keep
them out: the state directory is 0700, the files in it 0600, and so are the
three sockets there (the MCP tools', mitmproxy's two). Another user cannot
read the records, call the tools or take the keys (from reading the code,
where each is made; not tried with a second user). What another user can
still see or reach:

- **`ps`.** `run`'s and mitmproxy's command lines, with the device names,
  the hosts in `--allow-hosts` and `--pass-hosts`, the paths of the rules
  file and the state directory, the upstream proxy's address, and any
  `--mask-names` or `--mask-values` given there rather than in an `@FILE`
  (from reading the code). Never the SOCKS5 password, the tokens or mitmweb's
  password: those go in 0600 files.
- **`--local-proxy`.** Its port takes any user's requests, and records those
  to allowed hosts as `local` ([below](#the-local-proxy---local-proxy)).
  mitmproxy's SOCKS5 port and mitmweb's are on 127.0.0.1 too, behind their
  passwords ([below](#other-processes-on-this-computer)).
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

Not covered: root, and anyone who can become your user.

### Other processes on this computer

- **A password.** mitmproxy's SOCKS5 port is on 127.0.0.1, protected by a
  password made at each start (kept in a 0600 file, never in process
  arguments). Only Reqcove knows it, so another local process can neither use
  the proxy nor pose as a device.
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
- **No connection is read before the password check is loaded.** mitmproxy
  runs with `proxyauth=any` and only Reqcove's addon checks the password, so
  the launcher has mitmproxy make its server on the socket without accepting,
  and the addon starts accepting when it is loaded, just before its hello.
- **Were the launcher's change missed** (a mitmproxy that binds another
  way), its own bind fails on the held port and it exits before its hello,
  never ready.
- **Another user was not tried.** As both kernels document it (not checked
  here), a second socket gets that address only if both set SO_REUSEPORT (on
  Linux, only for the same user), which Reqcove's never does.
- **Not covered:** processes of your own user, which can read the password
  file anyway, and root.

Checked: tests with real mitmproxy on macOS, from the lock and through uvx
(connections queued while mitmdump is down, with a wrong password sent all at
once and step by step, are refused, and nothing is carried or recorded; the
port cannot be bound while mitmdump restarts, and a request sent then is
recorded by the next mitmdump); a unit test, also in CI on Linux (the port
cannot be bound while mitmdump is down or given up on; Stop frees it). Tried
by hand on macOS as the same user: binding 127.0.0.1 on the port fails even
with SO_REUSEADDR and SO_REUSEPORT; binding 0.0.0.0 works with SO_REUSEADDR,
but connections to 127.0.0.1 still reach the more specific socket,
Reqcove's; the queued-connection test fails when the launcher accepts at once
and the addon loads 1.5 seconds late (without the delay mitmproxy happened to
load the addon first); a launcher change made too late ends in "address
already in use".

## Masking

The secrets Reqcove recognises are masked as they arrive, so no tool can
return them. `--no-redact` turns masking off.

- **By name.** A header, query parameter or body field whose name says it is
  a secret (`token`, `password`, `apiKey`, …) has its value masked. Cookie
  values are masked whatever their names.
- **By shape.** `Bearer`, `Basic` and `Token` credentials, JWTs and keys
  with well-known prefixes are masked wherever they appear.
- **By format.** JSON, forms, text lines, GraphQL, XML, HTML and JavaScript,
  `multipart/form-data`, protobuf, gRPC and WebSocket messages are each read
  for secret names.
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
  `--allow-hosts`, and connections it knows by their address only.
- TLS without SNI, unless `--allow-hosts` names the address.
- Plain TCP on port 80 or 443 whose first bytes do not name an allowed host
  as mitmproxy reads them: HTTP/2 without TLS, for one.
- An allowed host's HTTP/2 requests riding a connection the app opened for a
  sibling name outside the list. Allow the names that share the certificate
  (`*.example.com`).
- TLS with Encrypted Client Hello, unless the provider's public name is
  allowed.
- A connection to an allowed host whose first HTTP/1 request names one of
  Apple's hosts in `Host`: carried whole, decrypted.
- A connection allowed by its address but named otherwise in SNI, once
  mitmproxy carries it as raw TCP.
- A client that finishes the TLS handshake and only then refuses Reqcove's
  certificate and closes, or closes without a request. A pinning app that
  checks the certificate itself does this; one that refuses during the
  handshake is listed.

## Options that widen exposure

Three options open a port on the node:

| Option | Port | Open to | Guarded by |
|---|---|---|---|
| `--ui` | 80 | your own devices, and the `--device` devices | a token (`ui-token`), set as a cookie |
| `--web` | 8081, relayed to mitmweb | your own devices | mitmweb's password (`web-token`) |
| `--mcp-http` | 8090, at `/mcp` | your own devices | a token (`mcp-token`), sent as `Authorization: Bearer` |

Each answers only requests that name the node (its MagicDNS name or tailnet
address) in `Host`. Each token is kept in the state directory (0600) and
appears only on `run`'s terminal and through `reqcove links`
([The login URL](#the-login-url)).

### mitmweb (`--web`)

mitmweb shows traffic **unmasked**. From its page anyone with the password
can edit and replay requests and change options (scripts included), which
runs code on this computer.

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
  progress counts once it ends, and what is kept of its bodies meanwhile (up
  to 2 MB each way) is outside them (from reading the code).

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

### The page (`--ui`)

`--ui` serves a read-only page of the records, with what the MCP tools
return, masked the same way. Who can read it:

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

Checked: tests (one for each point of who can read it; `/app.js` run over a
stand-in DOM in node).

### MCP over HTTP (`--mcp-http`)

The node serves the MCP tools to your own devices, with the token compared in
constant time. Requests from a browser page of another origin are refused.

- **The token is what tells your devices apart.** On a personal tailnet an
  agent's device joined through Tailscale's OAuth apps (Grok Bot) counts as
  one of your own devices, as do your other computers.
- **Whatever the tools answer then reaches that device and its model
  provider** (for Grok Bot, xAI's cloud). The agent keeps the token until you
  delete `mcp-token` and restart `run`.
- **The token is not printed in a log line, by `reqcove status` or by the
  tools**: agents may run those. In a container run with `-t`, `docker logs`
  keeps it.
- **Fewer tools than over `reqcove mcp`.** `--mcp-http`'s own server does
  not have the preset tools, `list_rules` and `explain_rules`, nor the marker
  tools (`add_marker`, `list_markers`). The rest are the same, and give the
  same masked records.
- **`capture_stats` and `status` leave out the `resolve` rules and the
  upstream proxy's address**, but not `rules_error`: when a `--rules-reload`
  change fails on a `resolve` line, the error (and `status`'s `next_steps`,
  which quotes it) can name that line's host and address (from reading the
  code).
- **`run` logs each tool call over HTTP** with the calling device and the
  tool's name (not its arguments), and each request with no token or a wrong
  one.
- **Each device may call about 10 times a second** (30 at once). Past that
  it gets `429 Too Many Requests` for the moment, logged once a minute: a
  runaway agent on one device does not keep `run` busy for the others. A call
  ends when its caller disconnects.

Checked: tests (another user's device refused over a real tailnet; the token,
`Host` and origin checks; the tools the server does not have; what
`capture_stats` and `status` leave out; the 429; a call ending when its
caller disconnects). Tried from this Mac over the tailnet, and with Grok Bot.

### The local proxy (`--local-proxy`)

An HTTP proxy on 127.0.0.1:8082 for this computer's own apps (the iOS
Simulator), with no password.

- Any process on this computer, of any user, can use it, and what it sends
  to `--allow-hosts` hosts is recorded as the device `local`.
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

### LAN mode (`--lan`)

`run --lan` starts no tailnet node. An HTTP proxy listens on one address of
this computer, that of one LAN interface (never 0.0.0.0, never a VPN's
tunnel), on `--proxy-port`. There is no password: who may use it is decided
by address. Use LAN mode on a network you trust, and stop it when done.

- **An address is not a device.** Whoever has an allowed address later is
  allowed too, on this network or on another with the same prefix (a café's
  192.168.1.0/24 as your home's). The ready block, `reqcove status` and
  `reqcove lan list` show the list.
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
- `map_remote` and `resolve` targets are dialled by mitmproxy, outside these
  checks: a rule sending an allowed host to a server on this computer serves
  the LAN clients' requests too.
- The CA at `http://mitm.it` comes over plain HTTP, which anyone else on the
  LAN can swap. The ready block names the CA file, to send by AirDrop
  instead, and prints its SHA-256 as iOS shows it in the profile's More
  Details.

Checked: tests (the refused connections and the log of addresses; the deny,
the idle tunnel and the 256 tunnels, with smaller values; what an allowed
address reaches; `run`'s question through a seam, the terminal calls
themselves not tested). Tried with an iPhone on a home Wi-Fi, 2026-11-14:
refused until allowed, then recorded; refused again after `reqcove lan deny`;
the SHA-256 matched what iOS showed.

### An upstream proxy (`--upstream-proxy`)

Decrypted HTTP(S) requests then go on through that proxy, and Reqcove's
mitmproxy does not connect to their servers itself (connection strategy
lazy). Other protocols over TLS to an allowed host still go straight to their
servers (from reading the code). The flag is read at start; no tool changes
it.

- **The proxy sees the requests and responses unmasked.** Burp, for one,
  keeps them in its project, on disk. Its own MCP server or extensions give
  agents what Reqcove's tools hold back, and the ability to send requests.
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
  looked up again on this computer: a name that resolves into this
  computer's LAN reaches it, past the exit node's refusal.
- **Keep `--allow-hosts` narrow.** A site the iPhone visits can make its own
  name do that only for the proxy's lookup (DNS rebinding: from reading the
  code, not tried). `run` warns when the list is `'*'`. `resolve` rules are
  refused with `--upstream-proxy` for this reason.
- **The CONNECT lines (an IP address and port) and plain HTTP reach the
  proxy unencrypted**: keep it on this computer, or on the tailnet.

Checked: tests (one counts the server's connections; only a CA named
"PortSwigger CA" is taken). Tried with Burp: it answered at `/cert` (checked
with curl), did not check the server's certificate by default, and connected
by the name in the SNI.

### Rules (`--rules`)

Rules are yours, read from a file when mitmproxy starts. No MCP tool writes
or changes a rule, and over `--mcp-http` an agent has no way to the file at
all. A rules file from someone else is code: it can send your apps' requests,
cookies and tokens included, anywhere.

- **`run --rules-reload` reads the file again whenever it changes.**
  Whatever can write it (any process as your user, an agent with file access
  included) can then change where the devices' requests go while `run` runs.
  Without it, the file is read only when mitmproxy starts (with `run`, or
  when Reqcove restarts it after it exits).
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

**`list_rules` and `explain_rules` are read-only.** They show each rule by
kind and number with its preset, and only what is derived from it:

- a mock's method, URL, operation, status, delay and fault; a `map_remote`
  target's scheme and host (or "path only", or "not shown" when the rule
  does not write it out); a `modify_headers` header name and direction; a
  `resolve` name and address; for a `map_local` rule, its number only;
- never a filter, a regex, a header value, a body or a file's path.
- `explain_rules` runs the request path's own code on a request it makes up,
  never sent, with a copy of the presets' state, so it uses no preset's count
  and turns none on or off.
- Like the preset tools they are on `run`'s local socket and `reqcove mcp`
  only, never over `--mcp-http`: the targets say where the devices' requests
  can be sent.

Checked: tests (header names and values; `resolve` names; the 502 for a
failing rule; `run` checking a file without taking it; `explain_rules` and
the presets' counts; what the two tools show, with marker strings, end to
end). With real mitmproxy: a stand-in server dialled with another host's Host
gets no rule's value (over plain HTTP, over HTTPS with a valid certificate
for its own name, and with a rule setting Host to its address), and the app
gets no response rule's value from it; one without a certificate for the name
gets no request; the Host's own address, and a `resolve` target, get the
rules, both ways. Not over the network: IDNA and İ, ı, ſ, K (on mitmproxy's
own made flows); the lookup bounds (in mitmproxy's Python with a lookup that
never answers, not in a running mitmdump); the path-only `map_remote` (in
mitmproxy's Python). With Go's HTTP/2 client: the 502 and the empty DATA
frame (the stream's end as mitmproxy tells it is from reading its code).
Tried: a `resolve` target with a trusted certificate for another name gets a
502.

### Mock presets

A mock in the `--rules` file marked `preset: NAME` does nothing until an
agent turns it on with `activate_preset` (`list_presets`,
`deactivate_preset`). A `map_remote`, `modify_headers` or `resolve` rule can
be a preset too, and it can send requests elsewhere: see
[below](#map_remote-modify_headers-and-resolve-presets).

- **Writing a preset is your consent** that an agent may turn it on; there
  is no switch at start.
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
- **The write tools are not marked read-only**, so a client that asks before
  other tools asks before them. A client that allowed `"mcp__reqcove"`
  wholesale gets them allowed without a prompt: allow the read tools by name.
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
- **Turned off** by a changed rules file (with `--rules-reload`), and by a
  restart of mitmproxy or of `run`. An end is checked on two clocks, so a
  computer that slept past it does not leave one on. One answer already
  waiting out its `delay_ms` still goes out after the preset is turned off.
- **`list_presets`** gives what each matches and its status, delay or fault,
  never its body or header values.

Checked: tests (the two servers `run` builds; the addon's secret; no write
sent again; the two clocks).

### map_remote, modify_headers and resolve presets

A preset of these kinds changes where the device's requests go, or what they
carry, while it is on: not only what the app gets.

- **A `map_remote` preset sends the matching requests**, with the app's
  cookies, tokens, login bodies and everything else in them, to the target
  you wrote, from every device recorded (in LAN mode, every address you
  allowed).
- **An agent cannot choose the target**, only when, and for how long by
  turning it on again. The worst case through text a site wrote into the
  records: your production credentials sent to the staging or dev server in
  the preset, again and again.
- **The risk to weigh is a stale target**: an old tunnel or staging name
  someone else holds now.
- **The 5 minutes bound the switch, not its effects.** What the app wrote
  while it was on (orders, edits) is on that server; the app may keep the
  tokens, cookies and caches it got there, and send them to the usual server
  once it is off.
- **`resolve` is the safer kind.** It connects a name elsewhere but keeps
  Host, SNI and the TLS check the name's (from reading the code): over HTTPS
  the other server needs a certificate for that name.
- **`modify_headers` presets change requests only.** One on responses (`~s`)
  is refused at load, as it could drop a page's protections (CSP, HSTS) or
  set cookies on a host Safari shows. Its value is never shown. One that is
  on applies after the plain rules, so its header is the one sent.
- **Refused at load**, so the target can be shown and checked: a
  `map_remote` preset whose replacement is not `http://` or `https://`, a
  host and `/`, has a user or password, takes its host from the request, or
  goes to a link-local address; plain `http://` to anything but this computer
  or a LAN address (`localhost`, `*.local`, a private address).
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
  allows these kinds too (the guide's [example](guide.md#allow-the-tools)
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

### A flags file (`--config`)

`run --config FILE` (for `brew services` and `reqcove service install`) takes
`run`'s flags from a file: what can write that file decides the next start's
flags.

- The file must be yours and readable by you only (refused otherwise): it
  may hold `--mask-values` patterns.
- Errors name its lines, never a value.
- Five flags are refused in it and stay on the command line: `--no-redact`
  (takes masking off), `--web` (shows traffic unmasked), `--allow-hosts '*'`,
  also through `@FILE` (records every site), `--rules-reload` (lets a file
  change where requests go while running) and `--lan` (an open proxy on the
  LAN).
- Others, such as `--upstream-proxy` or `--rules`, are allowed there.

Checked: tests (the refusals).

## Prompt injection

What the records hold was written by others. Response bodies, and also
response headers, status reasons, redirect targets and error messages, are
written by remote sites and may contain text meant to steer the agent. An app
chooses its User-Agent, its TLS names and the JSON keys it sends, and a
tailnet peer its device name.

What an agent can do:

- **Reqcove's tools read, with one exception.** An agent can turn on, for at
  most 5 minutes each time (no cap on turning it on again), a rule you marked
  as a preset: a mock ([Mock presets](#mock-presets)), or a `map_remote`,
  `modify_headers` or `resolve` rule, which changes what requests carry or
  where they go
  ([those presets](#map_remote-modify_headers-and-resolve-presets)). It turns
  on only what you wrote.
- `add_marker` writes too, but only a marker in Reqcove's memory.
- No tool writes or changes a rule; with no presets, nothing an agent calls
  changes traffic. (`--rules` are yours, from a file, at start.)
- **The agent may also hold other tools**: a shell, file writes, the
  network, other MCP servers. Text a site wrote into a record can try to
  steer it into using those (send a cookie somewhere, edit a file). Reqcove
  cannot stop that from its side; your agent's own settings can.

What to do:

- Give an agent that reads Reqcove only what the task needs. An agent that
  only reads Reqcove and answers you is the safest shape.
- In Claude Code, allow Reqcove's read tools by name (not `activate_preset`)
  without allowing shell commands or network tools along with them, and keep
  its permission prompts for the rest.
- In Codex, keep its sandbox (by default without network, from its
  documentation, not tried) and approvals.

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
  [Rules](#rules---rules)).
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

## mitmproxy's own code

- mitmproxy and its dependencies (44 packages) come from a lock file built
  into Reqcove (`internal/capture/mitm.py.lock`). `run` writes it and a small
  launcher into the state directory and starts mitmproxy with
  `uv run --locked --script`, which installs exactly the files the lock names
  and checks each one's hash.
- Plain `uvx` checks no hash, even when given them. It is used for another
  `--mitmproxy-spec`, and for a `--uvx` whose file is not named `uvx` (a
  wrapper, whose `uv` is not known), from releases before a fixed date
  (`--exclude-newer`).
- CI checks that the lock matches the launcher and audits it for known
  vulnerabilities (pip-audit).
- The lock overrides one version. mitmproxy 12.3.1 caps tornado, mitmweb's
  server, at 6.5.10, in which the audit found three vulnerabilities. The lock
  pins 6.6.1: 6.6 fixed those three, and 6.6 itself has CVE-2026-126347.
  mitmproxy's own tests were not run with it.
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
