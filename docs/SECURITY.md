# Reqcove's security model

Reqcove decrypts a phone's HTTPS and hands what it reads to an AI agent. This page
says what it protects, what it trusts, and what it does not try to do. Points that
come from reading code rather than from a test say so.

## Trust

- **Your OS user is trusted.** The state directory (`~/.reqcove`, mode 0700) and
  the MCP socket in it are open to that user only. Any process running as that user
  can read the records, and the CA's private key. Reqcove promises nothing stronger.
- **The devices you name are trusted to use the exit node**, nothing else. Traffic
  from other tailnet devices is refused, on the exit node and on the Remote Proxy.
  A device name is what each device calls itself, so `--device` takes one only from
  your own user's devices; name other users' devices by machine name, IP or StableID.

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
  jwt, apikey, privatekey or authorization, even run together (`accesstoken`,
  `X-AuthToken`), or having auth, key, sid, sig, pwd, otp, pin or code as a whole
  word (names split at punctuation and case changes, so `apiKey`, `XAuth` and
  `X-Amz-Signature` count, while `author` and `keyword` do not). `code` and `key`
  next to an everyday word (`country_code`, `error_code`, `sort_key`) and
  `token_type` are not secrets. Cookie values are masked (names stay), and query
  parameters wherever a URL appears (`Referer`, `Location`, fragments such as
  `#/callback?access_token=`, a URL inside another parameter, error messages),
  as is the response's reason text. Raw bytes that mitmproxy quotes in an error
  message (`b'…'`) are masked whole. `--no-redact` turns this off.
- Bodies are masked as they arrive too, as far as they can be recognised: in JSON
  (whatever the content type says), the string values of fields whose names are
  secret by the same rule, except a lone `code`, which in a body is usually an
  error code (`verification_code` and `device_code` are masked); in forms (or
  bodies that look like one), such fields' values, a lone `code` included: it
  carries OAuth authorization codes. Anywhere in a
  header value, URL, body or error message, credentials recognisable by their
  shape are masked: `Bearer`/`Basic`/`Token` values that look like credentials
  (not the next word of a sentence), JWTs, and keys with
  well-known prefixes (GitHub, `sk-…`, Slack, AWS access key IDs, Google API keys).
  A body is kept up to 64 KiB, in memory only, and works on a head that may be cut:
  a value cut before its closing quote is masked too.
- **What this does not catch:** a secret under a name that does not say so
  (`{"data": "…"}`), in arrays, or in formats other than JSON, forms and text
  (protobuf, multipart, XML attributes). Personal data, such as e-mail addresses
  and names, is not masked: debugging needs it. Bodies that are not text (or could
  not be decompressed) cannot be checked, so they are neither handed out nor
  searched while masking is on; `--no-redact` returns them.
- Bodies are returned only when a tool is asked for them (`bodies`).
- Records live in memory (at most 10,000 flows and 64 MiB of body heads, headers,
  URLs and error text together) and are gone
  when `reqcove run` stops; no flow is written to disk. `mitmproxy.log` in the
  state directory holds mitmproxy's error lines only (a test checks that secrets
  sent in failing and malformed requests do not reach it).

## What the agent sees goes further

Whatever a tool returns is sent to the agent's model provider. Choose
`--allow-hosts` with that in mind; `--allow-hosts '*'` sends other apps' and sites'
traffic too, and Reqcove warns when it starts.

## Prompt injection

Response bodies, and also response headers, status reasons, redirect targets
and error messages, are written by remote sites and may contain text meant to
steer the agent. Tools return bodies only on request, and say all of it is
untrusted.
The MCP tools only read; nothing an agent calls changes traffic. (`--rules` are
yours, from a file, at start.)

## mitmweb (`--web`)

mitmweb listens on 127.0.0.1 only, with a password made at each start and passed
through a 0600 file, never the command line. It shows traffic **unmasked**, and
from its page anyone with the password can edit and replay requests and change
options. It shows every flow mitmproxy decrypted, including requests to hosts
outside `--allow-hosts` that rode on an allowed connection (HTTP/2 connection
reuse): the per-request check keeps those out of Reqcove's records only.

## Other processes on this computer

mitmproxy's SOCKS5 port is on 127.0.0.1, protected by a password made at each
start (kept in a 0600 file, never in process arguments). Only reqcove knows it, so
another local process can neither use the proxy nor pose as a device.

## The exit node's DNS

The exit node answers DNS over HTTPS (Tailscale's PeerAPI) for devices that use it.
It also answered this computer, which was not one of `--device`, when tried: other
devices of the tailnet that may use the exit node can resolve names through it.
They ask the same upstream as your devices: `1.1.1.1` by default. With `--dns system`,
or a LAN resolver in `--dns`, that is your router's or your company's resolver, and
they can look up names only it knows. (From reading Tailscale's code: it answers any
peer the tailnet policy lets use an exit node.) Reqcove does not record DNS.

## What the devices can reach

Public IPv4 addresses. Reqcove refuses this computer's own addresses (those of every
interface), loopback, private and link-local ranges, the tailnet's range, multicast
and the other special-purpose ranges, and all of IPv6, on the exit node and on the
Remote Proxy. Two things it does not catch:

- **Your network's public address.** It is not an address of this computer's
  interfaces. A device that connects to it may reach what the router forwards
  (port forwarding), or, on a cloud server, this computer. Not tested.
- **Replies to UDP.** While a device's UDP flow lasts (2 minutes after its last
  packet, 30 seconds for DNS), whatever arrives at the port it went out from, from
  any sender, is handed to the device, as with a full-cone NAT. (From reading code.)

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
