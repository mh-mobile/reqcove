# Reqcove's security model

Reqcove decrypts a phone's HTTPS and hands what it reads to an AI agent. This page
says what it protects, what it trusts, and what it does not try to do. Points that
come from reading code rather than from a test say so. It describes `main`:
`--upstream-proxy`, `--ui`, and the 502 for a request a rule fails on are not in
v0.1.0.

## Trust

- **Your OS user is trusted.** The state directory (`~/.reqcove`, mode 0700) and
  the MCP socket in it are open to that user only. Any process running as that user
  can read the records, and the CA's private key. Reqcove promises nothing stronger.
- **The devices you name are trusted to use the exit node**, nothing else. Traffic
  from other tailnet devices is refused, on the exit node and on the Remote Proxy.
  A device name is what each device calls itself, so `--device` takes one only from
  your own user's devices, and only while neither it nor Reqcove's node is tagged
  (a tagged node keeps the user ID of whoever tagged it); name other devices by
  machine name, IP or StableID.

## The CA's private key

`~/.reqcove/mitmproxy/mitmproxy-ca.pem`, and `mitmproxy-ca.p12` next to it (a
PKCS#12 file without a passphrase), hold the private key of a CA your iPhone
trusts. Whoever has it can impersonate any HTTPS site to that iPhone. Keep the
directory to yourself; when you stop using Reqcove, remove the profile from the
iPhone first, then delete the directory (`reqcove cleanup` lists the steps).
Copying the directory to another computer copies the key.

## What is recorded

- Only requests to hosts in `--allow-hosts` are decrypted and recorded. Two checks
  enforce it: mitmproxy passes other connections through undecrypted, and each
  request's Host is checked again (a connection to an allowed host can carry
  requests to others, as with HTTP/2 connection reuse). Requests and TLS failures
  outside the list are counted, never recorded.
- Apple's hosts always pass through undecrypted.
- Secrets are masked as they arrive, so no tool can return them. A header, query
  parameter or body field is secret by its name: a name containing token,
  secret, password, passwd, passphrase, passcode, credential, signature, session,
  jwt, apikey, privatekey, authorization, authentication, csrf or xsrf, even run
  together (`accesstoken`, `X-AuthToken`), or having auth, key, sid, sig, pwd,
  pw, pass, otp, totp, pin or code as a whole word (names split at punctuation
  and case changes, so `apiKey`, `XAuth` and `X-Amz-Signature` count, while
  `author` and `keyword` do not). `code` and `key` next to an everyday word
  (`country_code`, `error_code`, `sort_key`) and `token_type` are not secrets.
  Cookie values are masked (names stay), and query parameters wherever a URL
  appears (any header, such as `Referer`, `Location` or `Link`; fragments such
  as `#/callback?access_token=`; a URL inside another parameter; bodies; error
  messages), as is a URL's password (`https://user:…@host`) and the response's
  reason text. Raw bytes that mitmproxy quotes in an error message (`b'…'`) are
  masked whole. `--no-redact` turns this off.
- Bodies are masked as they arrive too, as far as they can be recognised: in JSON
  (whatever the content type says), the string and number values of fields
  whose names are secret by the same rule, also in JSON sent as a string inside
  JSON or as a form field (one level deep). In a response a lone `code` is
  kept, as it is usually an error code (`verification_code` and `device_code`
  are masked); in a request it is masked, as it carries one-time and OAuth
  codes. In forms (or bodies that look like one), such fields' values, a lone
  `code` included. Anywhere in a header value, URL, body or error message,
  credentials recognisable by their shape are masked: `Bearer`/`Basic`/`Token`
  values that look like credentials (not the next word of a sentence), JWTs,
  and keys with well-known prefixes (GitHub, `sk-…`, Slack, AWS access key IDs,
  Google API keys). `WWW-Authenticate` keeps its challenge (scheme, realm,
  error), with only such shapes masked.
  A body is kept up to 64 KiB, in memory only, and works on a head that may be cut:
  a value cut before its closing quote is masked too.
- **What this does not catch:** a secret under a name that does not say so
  (`{"data": "…"}`), in arrays, in GraphQL arguments written into the query
  text (`login(password: "…")`), or in formats other than JSON, forms and text
  (protobuf, multipart, XML elements and attributes). Personal data, such as e-mail addresses
  and names, is not masked: debugging needs it. A body is handed out and searched
  only if masking could look at it: decoded (not wire bytes of an encoding it
  could not undo) and text, by its content type (JSON, XML, forms, text, …) or,
  with none, by its bytes. Others, a protobuf that happens to be valid UTF-8
  included, are neither handed out nor searched while masking is on;
  `--no-redact` returns them.
- Bodies are returned only when a tool is asked for them (`bodies`).
- Records live in memory (at most 10,000 flows and 64 MiB of body heads, headers,
  URLs and other text together; a site's reason text, `Content-Encoding` and
  error messages are cut to 1 KiB, 64 bytes and 1 KiB) and are gone
  when `reqcove run` stops; reqcove writes no flow to disk itself. `reqcove har >
  FILE` (after v0.1.0) writes them where you send it, masked as the tools return
  them, with your shell's file mode (often readable by other users; the state
  directory is 0700). `mitmproxy.log` in the
  state directory holds mitmproxy's error lines only (a test checks that secrets
  sent in failing and malformed requests do not reach it).

## What the agent sees goes further

Whatever a tool returns is sent to the agent's model provider. Choose
`--allow-hosts` with that in mind; `--allow-hosts '*'` sends other apps' and sites'
traffic too, and Reqcove warns when it starts. Besides the traffic, the `status`
and `list_devices` tools carry the node's MagicDNS name (which includes the
tailnet's name), its tailnet addresses and the devices' machine names; not your
login (from reading code).

## Prompt injection

Response bodies, and also response headers, status reasons, redirect targets
and error messages, are written by remote sites and may contain text meant to
steer the agent. Tools return bodies only on request, and say all of it is
untrusted.
The MCP tools only read; nothing an agent calls changes traffic. (`--rules` are
yours, from a file, at start.)

## Rules (`--rules`)

Rules are yours, read from a file when mitmproxy starts; no tool changes them.
With `run --rules-reload` (after v0.1.0) the file is also read again whenever it
changes, so whatever can write it (any process as your user, an agent with file
access included) can then change where the devices' requests go while `run`
runs; without it, the file is read only when mitmproxy starts (with `run`, or
when reqcove restarts it after it exits).
`map_remote` and `resolve` make mitmproxy connect, from this computer, where the
rule says, this computer and the LAN included: the exit node's refusal of those
addresses is about the devices' own connections, and a rule opens its target to
every app on the carried devices that sends a request for the rule's host (a web
page included). `resolve` takes IPv4 addresses only, never a name to look up, and
refuses `0.0.0.0/8`, link-local, multicast and reserved ranges, Tailscale's
100.100.100.100 and the cloud metadata addresses 169.254.169.254 and
100.100.100.200; `map_remote` takes whatever it is given. A `resolve` rule
without a port takes the request's port (the app's, or a `map_remote` URL's). TLS to a `resolve` target is
checked against the rule's name, with mitmproxy's own CA list (certifi, from
reading its code), so a request goes on only to a server with a certificate for
that name (tried: one with a trusted certificate for another name gets a 502); plain HTTP is not checked. Each
`resolve` name needs its own address: mitmproxy reuses a connection by address,
so names sharing one would share one name's check, and are refused. A
`map_remote` to a `resolve` target's address shares its connections, both ways:
a request of one can ride on a connection made, and checked, for the other, and a
failed connection fails both for as long as the app's connection lasts.
A request a rule fails on (say, a `map_remote` making a bad port) is answered with
a 502 rather than sent on as it was (a test), and a `map_remote` whose replacement
cannot work at all stops `run` at start.
A rules file from someone else is code: it can send your apps' requests, cookies
and tokens included, anywhere.

## An upstream proxy (`--upstream-proxy`)

Decrypted HTTP(S) requests then go on through that proxy, and Reqcove's mitmproxy
does not connect to their servers itself (connection strategy lazy; a test counts
the server's connections). Other protocols over TLS to an allowed host still go
straight to their servers (from reading code; a review saw it). What changes:

- The proxy sees the requests and responses unmasked, and Burp, for one, keeps them
  in its project, on disk. Its own MCP server or extensions give agents what
  Reqcove's tools hold back, and the ability to send requests.
- Checking the real server's certificate is the proxy's job: with the proxy's CA
  (`--upstream-ca`, or Burp's fetched at start), Reqcove trusts only that CA, so it
  checks the proxy, not the server. Burp's is fetched over plain HTTP from
  `http://burp/cert` through the proxy, only when the proxy is on this computer,
  and only a CA named "PortSwigger CA" is taken (a test). Burp, by
  default, did not check (tried, a review).
- Where the proxy connects is the proxy's choice. Reqcove hands it the address the
  exit node allowed, but Burp connects by the name in the SNI, looked up again on
  this computer (tried, a review): a name that resolves into this computer's LAN
  reaches it, past the exit node's refusal. A site the iPhone visits can make
  its own name do that only for the proxy's lookup (DNS rebinding: from reading
  code, not tried), so keep `--allow-hosts` narrow; `run` warns when it is `'*'`.
  `resolve` rules are refused with `--upstream-proxy` for this reason.
- The CONNECT lines (an IP address and port) and plain HTTP reach the proxy
  unencrypted: keep it on this computer, or on the tailnet.
- The flag is read at start; no tool changes it.

## The page (`--ui`)

`--ui` serves a read-only page of the records on the node's port 80, with what the
MCP tools return, masked the same way. Who can read it (each a test):

- Only your own devices on the tailnet (logged in as the same user as reqcove's
  node, and untagged) and the `--device` devices, checked when a connection opens
  and on every request; others get nothing.
- Your own devices see every device's flows, with the device's name. A `--device`
  device of another user sees only its own flows, in the list and by ID, and its
  own counts and next steps (not the other devices', nor their names).
- Only a browser holding the token: the link `run` prints sets it as an HttpOnly,
  SameSite=Strict cookie kept 400 days. Another app on the same iPhone can reach
  the port, but not read the page without the token. The token is kept in
  `ui-token` in the state directory (0600) and is the same at each start, so a
  link, a bookmark or a cookie keeps working until you delete that file and start
  again; then they get 403. Your own devices and the `--device` devices reach the
  page; a link that leaks works only from those.
- Only requests that name the node (its MagicDNS name or tailnet address) in
  `Host`: a site the iPhone visits cannot point its own name at the node and read
  the page as its own (DNS rebinding).
- GET and HEAD only, also when the request comes through the Remote Proxy; the
  search form goes to the page itself (CSP `form-action 'self'`), and Clear only
  hides flows from the list (a `since` in its URL), deleting nothing. The
  page's only script is its own `/app.js` (the Content-Security-Policy allows no
  other, and nothing inline), which asks `/flows.json` for the list once a second
  and puts it in with DOM calls and `textContent` only, so what sites wrote into
  headers and bodies stays text (a test runs it over a stand-in DOM in node); it is not cached
  (`no-store`). Pages still go through Safari: its history may keep the URLs of
  the flow pages viewed, and the first link with the token (useless without the
  device; it lasts until `ui-token` is deleted), and the URLs of searches, with
  what was searched (with `--no-redact`, a search for a secret's value keeps it
  there). A JSON body nested deeper than 32 levels is
  shown as it is, not indented (indenting deep nesting takes memory that grows
  with the square of the depth).

The token appears only in `run`'s terminal, as the login URL does: never in the
MCP tools.

## mitmweb (`--web`)

mitmweb listens on 127.0.0.1, with a password kept in `web-token` in the state
directory (0600; the same at each start until you delete that file and start
again) and passed through a 0600 file, never the command line. A link with it
(`?token=`) opened by a browser through the node is answered, once mitmweb
accepts it, with a redirect to the same URL without it (a test, with a stand-in
for mitmweb), so the password does not stay in the address bar; whether
Safari's history keeps the first URL is not checked. `run` prints the links with
the tokens on its standard error: in the terminal's scrollback, and in a file if
you send it there, they stay valid until the token files are deleted. mitmweb's
cookie does not outlast its restart (it signs it with a key made at each start,
from reading its code), so after one the link is needed again. After v0.1.0, the node also relays
its port 8081 to it for your own devices on the tailnet (the same user, untagged:
not a `--device` device of another user, nor anyone else; checked when a
connection opens and on every request, by the node's name or address in `Host`).
The password still guards it, and it gives what it gives on this computer: with
it, mitmweb's options can be changed (scripts included), which runs code on this
computer. The link with the password is printed in `run`'s terminal only. A phone on the
Remote Proxy reaches it the same way (its requests and WebSocket tunnels to the
node's port 8081 go to mitmweb, for your own devices only). A WebSocket already
open stays open if the device stops counting as yours. Tried from an iPhone on
the exit node. It shows traffic **unmasked**, and
from its page anyone with the password can edit and replay requests and change
options. It shows bodies up to 2 MB each (after v0.1.0; Reqcove gives it them,
as mitmproxy keeps no body it streams), whole and unmasked, and keeps the newest
10,000 flows and 256 MB of bodies. It shows every flow mitmproxy decrypted, including requests to hosts
outside `--allow-hosts` that rode on an allowed connection (HTTP/2 connection
reuse): the per-request check keeps those out of Reqcove's records only.

What its options change (from reading code, not tried): mitmproxy's behaviour
only, until reqcove starts it again. Reqcove's records stay scoped to
`--allow-hosts` and masked, since Reqcove checks both again as they arrive.
Turning off the SOCKS proxy in its Capture tab stops the devices' HTTP(S)
(that is how Reqcove hands them to mitmproxy). Another mode turned on there
listens on 127.0.0.1 (the listen host reqcove sets) and bypasses Reqcove's
device names and its refusals of this computer and the LAN.

## The local proxy (`--local-proxy`)

After v0.1.0. An HTTP proxy on 127.0.0.1:8082 for this computer's own apps (the
iOS Simulator), with no password: any process on this computer, of any user, can
use it, and what it sends to `--allow-hosts` hosts is recorded as the device
`local`. Its apps reach the LAN, VPNs and the tailnet as they would without it,
by this computer's own lookups. It refuses IPv6, and a name that leads to this
computer itself (loopback, its own addresses) or to a link-local address unless
this computer's `/etc/hosts` gives it (a test): a page in a browser here could
otherwise reach this computer's services through it by pointing its own name
there (DNS rebinding). A page could still point its name at a LAN address; a
browser going direct faces the same. This computer, the LAN and the tailnet are
in the system proxy's exceptions, so apps reach them directly, as without
reqcove. Apple's hosts are not decrypted. On macOS, `run` points the system's web
proxies at it while it runs, keeping what they were in the state directory
(0600) to put back when it stops (also on SIGHUP), at the next start, or with
`reqcove cleanup`; it never saves over settings not put back yet, and cleanup
will not delete the state while it holds them. If reqcove is killed outright,
apps here that use the system proxy cannot connect until they are put back.
Reqcove never makes this computer trust its CA; `run` prints the command (TLS
only, for this user). Once trusted, the CA's private key in `<state>/mitmproxy/`
can impersonate any HTTPS site to this computer too, not only to the devices:
keep the state directory, and its copies and backups, private, and remove the
trust when done (`reqcove status` and `cleanup` print how, by its fingerprint). Not
tried yet with the real `networksetup` and Simulator: the tests use stand-ins.

## Other processes on this computer

mitmproxy's SOCKS5 port is on 127.0.0.1, protected by a password made at each
start (kept in a 0600 file, never in process arguments). Only reqcove knows it, so
another local process can neither use the proxy nor pose as a device. One gap,
from reading code: when mitmdump dies, reqcove starts it again on the same port
(visible in `ps`), and until it is listening (up to about 30 seconds) another
user's process on this computer could take the port. Reqcove would then send it
the SOCKS password and the devices' TCP traffic: plain HTTP readable, HTTPS not.
On a computer shared with users you do not trust, keep that in mind.

The state directory is checked itself, not the directories above it. Keep it
(and `--state`) under directories only you can write: someone who can rename
entries in a parent can swap the state directory for their own.

## mitmproxy's own code

mitmproxy runs through `uvx` at a fixed version, with its dependencies resolved
only from releases before a fixed date (`--exclude-newer`), so a dependency
released later, a compromised one included, is not picked up. They are not
pinned by hash.

## The exit node's DNS

The exit node answers DNS over HTTPS (Tailscale's PeerAPI) for devices that use it.
It also answered this computer, which was not one of `--device`, when tried: other
devices of the tailnet that may use the exit node can resolve names through it.
They ask the same upstream as your devices: `1.1.1.1` by default. With `--dns system`,
or a LAN resolver in `--dns`, that is your router's or your company's resolver, and
they can look up names only it knows. (From reading Tailscale's code: it answers any
peer the tailnet policy lets use an exit node.) Reqcove does not record DNS.

From this computer to the upstream, DNS is plain, unencrypted DNS, for the exit
node and for the Remote Proxy alike, and answers are not checked with DNSSEC
(from reading code). So the network this computer is on (its Wi-Fi, the ISP) sees
the names the devices look up, and someone on that path can answer falsely.
Off the path that is hard: each query has a random ID and its own random port,
and answers from any other address are dropped. A false answer gets little
(from reading code, not tried): HTTPS still has to show a certificate for the
name (mitmproxy checks it for decrypted hosts, the phone itself for the others),
and an answer pointing at this computer, its LAN or loopback is refused like any
connection there (tested). Plain HTTP can be sent elsewhere, as it can on any
network. To hide the names, a local DNS-over-HTTPS relay could serve as
`--dns 127.0.0.1:PORT`; that has not been tried.

## What the devices can reach

Public IPv4 addresses. Reqcove refuses this computer's own addresses (those of every
interface) and the networks those interfaces are on (so a LAN with public addresses,
or a cloud server's subnet with its neighbours, is refused too), loopback, private
and link-local ranges, the tailnet's range, multicast and the other special-purpose
ranges, and all of IPv6, on the exit node and on the Remote Proxy. Public networks
reached only through a route (behind a router, not on an interface's subnet) are
not refused (from reading code). Pings (ICMP echo) follow the same rules: one
from a device not in `--device`, or to a refused address, is dropped (tests send
pings to 127.0.0.1 from both); a listed device's ping to a public address is
answered by pinging from this computer (from reading code).

While a device's UDP flow lasts (2 minutes after its last packet, 30 seconds for
DNS), only the address and port it was sent to can answer through it; datagrams
from anyone else that reach its port on this computer are dropped (a test sends
one from this computer).

What it does not catch:

- **Your network's public address.** It is not an address of this computer's
  interfaces. A device that connects to it may reach what the router forwards
  (port forwarding), or, on a cloud server, this computer. Not tested.

## The login URL

While the node is not logged in, `reqcove run` prints a login URL. Whoever opens it
first puts this node in their own tailnet, so it is printed in `run`'s terminal
only: the `status` tool, and with it the agent and its model provider, says where
to find it but does not carry it.

## Logs to Tailscale

Reqcove's node does not send logs to Tailscale. A tailnet that requires data plane
audit logs is not supported (`reqcove status` says so); Reqcove never turns logs on.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository rather than
a public issue.
