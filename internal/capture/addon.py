"""mitmproxy addon for reqcove: send each flow to reqcove over a Unix socket.

Embedded in the reqcove binary and loaded with -s. Uses only the standard
library and mitmproxy (and its pinned dependencies), so it needs no
`uv tool install --with`.

Bodies are never buffered in mitmproxy: requestheaders/responseheaders set
flow.request.stream / flow.response.stream to a callable that passes every
chunk through unchanged and copies only the decoded head (up to
reqcove_body_head bytes). Run mitmdump WITHOUT store_streamed_bodies, or
mitmproxy keeps the whole body anyway.

Hooks and stream callables run on mitmproxy's event loop, so they only copy
small values onto a queue. A daemon thread encodes JSON lines and writes them
to the socket. When the queue is over its byte budget, body heads are dropped
first; header, done and error events are kept so flows are never orphaned.
"""

import asyncio
import collections
import base64
import copy
import os
import hmac
import ipaddress
import json
import logging
import queue
import re
import socket
import sys
import threading
import time
import urllib.parse
import zlib
from pathlib import Path

import brotli
import ruamel.yaml  # mitmproxy's own dependency
from mitmproxy import connection, ctx, flowfilter, http
from mitmproxy import version as mitmproxy_version
from mitmproxy.addons import maplocal, mapremote, modifyheaders


class _NoWebToken(logging.Filter):
    """mitmweb's server (tornado) logs a failed request's URI, ?token= and
    all, into mitmproxy.log: the token is masked first."""

    def filter(self, record):
        msg = record.getMessage()
        if "token=" in msg:
            record.msg, record.args = re.sub(r"token=[^&\s'\")]+", "token=[redacted]", msg), None
        return True


for _name in ("tornado.access", "tornado.application", "tornado.general"):
    logging.getLogger(_name).addFilter(_NoWebToken())
from mitmproxy.net import check
from mitmproxy.net.tls import starts_like_tls_record
from mitmproxy.proxy.layers import tcp as tcp_layer
from mitmproxy.proxy.layers.tls import parse_client_hello
from mitmproxy.utils import strutils
from mitmproxy.utils.spec import parse_spec

try:  # Python 3.14+; mitmproxy also runs on 3.12/3.13
    from compression import zstd
except ImportError:
    zstd = None

VERSION = 2
FLUSH_SECONDS = 1.0  # send a partial head this often while a body trickles (SSE)
WS_HEAD = 4 << 10  # a WebSocket text message's head, as reqcove keeps it
WS_RATE, WS_BURST = 20.0, 100.0  # message heads a second per socket, and the burst


def _brotli_ok():
    try:
        return tuple(int(x) for x in brotli.__version__.split(".")[:3]) >= (1, 2, 1)
    except Exception:
        return False


BROTLI_OK = _brotli_ok()  # CVE-2026-111497: never decode br with an older brotli


def _device(flow):
    auth = flow.metadata.get("proxyauth")  # (user, password) from proxyauth
    return auth[0] if auth else None


MAX_HEADERS = 256           # per message, as recorded
MAX_HEADER_BYTES = 256 << 10  # names and values together, as recorded


SHORT = 1024  # other text a site sends (reason, encoding, error), as recorded


def _headers(h):
    """The headers as [name, value] pairs (repeated Set-Cookie kept), bounded:
    a site can send many or huge ones, and they are queued and kept. The note
    says what was left out; it goes apart from the headers, which a site names."""
    out, total = [], 0
    for k, v in h.items(multi=True):
        if len(out) == MAX_HEADERS:
            return out, "more headers not recorded"
        room = MAX_HEADER_BYTES - total - len(k)
        if room <= 0:
            return out, "more header bytes not recorded"
        if len(v) > room:
            v = v[:room] + " [cut]"
        out.append([k, v])
        total += len(k) + len(v)
    return out, ""


# ponytail: gzip members or zstd frames decoded in one body. Each new one copies
# the rest of its chunk (zlib's unused_data), so many empty ones would cost
# CPU on mitmproxy's loop; past this the head stops, cut. Raise it if a real
# body needs more.
MAX_MEMBERS = 1024


class _Decoder:
    """Incrementally decodes one content-encoding with a bounded output."""

    def __init__(self, enc):
        self.enc = enc
        self.d = None
        if enc in ("gzip", "x-gzip", "deflate"):
            self.d = zlib.decompressobj(47)  # gzip or zlib, by header
        elif enc == "br" and BROTLI_OK:
            self.d = brotli.Decompressor()
        elif enc == "zstd" and zstd is not None:
            self.d = zstd.ZstdDecompressor()
        elif enc not in ("", "identity"):
            raise ValueError("cannot decode Content-Encoding " + json.dumps(enc))  # quoted: the site's text
        self.raw_deflate_tried = False
        self.members, self.capped = 1, False

    def feed(self, data, limit):
        if self.d is None:
            return data[:limit]
        if self.enc == "br":
            return self.d.process(data, output_buffer_limit=limit)
        if self.enc == "deflate":
            try:
                return self.d.decompress(data, limit)
            except zlib.error:
                if not self.raw_deflate_tried:
                    self.raw_deflate_tried = True  # some servers send raw deflate
                    self.d = zlib.decompressobj(-15)
                    return self.d.decompress(data, limit)
                raise
        # gzip and zstd: a body can be several members (frames), one after another,
        # each read by a decompressor of its own.
        out = b""
        while len(out) < limit:
            if self.d.eof:
                data = self.d.unused_data + data
                if self.enc != "zstd":
                    data = data.lstrip(b"\0")  # zero padding after a member, skipped as gzip.decompress does
                if not data:
                    break
                if self.members == MAX_MEMBERS:
                    self.capped = True
                    break
                self.members += 1
                self.d = zstd.ZstdDecompressor() if self.enc == "zstd" else zlib.decompressobj(47)
            out += self.d.decompress(data, limit - len(out))
            data = b""
            if not self.d.eof:
                break
        return out


class _Head:
    """The stream callable for one body: pass chunks through, copy the head."""

    def __init__(self, addon, flow, direction, headers):
        self.addon, self.flow_id, self.dir = addon, flow.id, direction
        self.limit = addon.head_limit
        self.head = bytearray()
        # --web: the whole body as on the wire, up to web_keep, for mitmweb (which
        # keeps no streamed body); None once it is over.
        self.addon, self.keep = addon, (bytearray() if addon.web_keep > 0 else None)
        self.size = 0  # bytes on the wire
        self.truncated = False
        self.decoding = True
        self.encoding = headers.get("content-encoding", "").strip().lower()[:64]
        self.note = ""
        self.sent_len = -1
        self.sent_size = 0
        self.last_flush = time.monotonic()
        try:
            if "," in self.encoding:
                raise ValueError("chained content-encoding")
            self.dec = _Decoder(self.encoding)
        except Exception as e:
            self.dec, self.note = None, str(e)[:SHORT]  # copy the head as it is on the wire

    def __call__(self, data):
        try:
            self.size += len(data)
            if self.keep is not None:
                if len(self.keep) + len(data) <= self.addon.web_keep:
                    self.keep += data
                else:
                    self.keep = None
                if not data and self.keep is not None:
                    self.addon.kept[(self.flow_id, self.dir)] = bytes(self.keep)
            room = self.limit - len(self.head)
            if data and room > 0 and self.decoding:
                try:
                    out = self.dec.feed(data, room) if self.dec else data[:room]
                    self.head += out[:room]
                except Exception as e:
                    self.decoding, self.note = False, ("decode error: " + str(e))[:SHORT]
                if len(self.head) >= self.limit or self.dec and self.dec.capped:
                    self.truncated = True
                    self.decoding = False  # stop decoding once the head is full
                    self._send()
            elif data and room <= 0:
                self.truncated = True
            now = time.monotonic()
            if not data:
                self._send(final=True)
            elif now - self.last_flush >= FLUSH_SECONDS and len(self.head) != self.sent_len:
                self._send()
        except Exception:
            pass  # never break the flow
        return data  # always bytes; b"" at the end

    def flush(self):
        """The flow failed: what came of the body since the last send, not final
        (one that had ended was sent final, with this size)."""
        if self.size != self.sent_size:
            self.sent_len = -1  # sent even with the head as it was: its size is not
            self._send()

    def _send(self, final=False):
        self.last_flush = time.monotonic()
        if len(self.head) == self.sent_len and not final:
            return
        self.sent_len, self.sent_size = len(self.head), self.size
        self.addon.put_body({
            "v": VERSION, "ev": "body", "id": self.flow_id, "dir": self.dir,
            "head": bytes(self.head), "size": self.size, "final": final,
            "truncated": self.truncated,
            # head is the decoded body (or identity); false means wire bytes as received
            "decoded": self.dec is not None and not self.note,
            "encoding": self.encoding, "note": self.note,
        })


RULE_KINDS = ("mock", "map_remote", "map_local", "modify_headers", "resolve")  # mock and resolve are reqcove's own
RULE_SETTINGS = ("keep_host_header",)  # reqcove's own: map_remote keeps the app's Host
MAP_LOCAL_BODY = 1 << 20  # map_local answers only requests whose body is known to be this small
# Where a request is held while only its stream's end can say it has no body
# (HTTP/2 without a length): server_connect refuses it, so if a body comes after
# all, mitmproxy's start at streaming it fails there (a 502), never on to a server.
HOLD = ("reqcove-hold.invalid", 1)
HOLD_REFUSED = "reqcove: a body came with this request of unknown length that a mock or map_local may answer: refused, not held in memory"


def _parse_rule(kind, spec, base):
    """One rule in mitmproxy's syntax; files are relative to the rules file."""
    if kind == "map_remote":
        rule = mapremote.parse_map_remote_spec(spec)
        re.sub(rule.subject, rule.replacement, "")  # a bad group reference (\\2) fails now, not on every request
        return rule
    flt, subject, replacement = parse_spec(spec)
    if kind == "map_local":
        re.compile(subject)
        path = (base / Path(replacement).expanduser()).resolve(strict=True)
        return maplocal.MapLocalSpec(flt, subject, path)
    if replacement.startswith("@"):
        replacement = "@" + str(base / Path(replacement[1:]).expanduser())
    rule = modifyheaders.ModifySpec(flt, strutils.escaped_str_to_bytes(subject), replacement)
    if not HEADER_NAME.match(rule.subject):
        raise RuleError("the header name must be a plain token (letters, digits, - and the like)")
    if BAD_IN_VALUE.search(rule.read_replacement()):  # a missing @file fails now too, not on the first flow
        raise RuleError("a header value cannot hold a line break or NUL")
    return rule


def _spec_parts(spec):
    """A mitmproxy-syntax rule's filter text ("" for none) and subject, for
    telling two rules with the same match apart; never shown."""
    parts = spec[1:].split(spec[0], 2) if spec else []
    return (parts[0], parts[1]) if len(parts) == 3 else ("", parts[0] if parts else "")


# A map_remote preset's target, written whole: https://host[:port] then /. Plain http only to this computer or a LAN address: the app's cookies
# and tokens would cross the internet in clear.
PRESET_TARGET = re.compile(r"(https?)://([^/?#]*)/")
LOCAL_NAMES = re.compile(r"(?:localhost|[a-z0-9_.-]+\.local)")


def _map_remote_target(replacement, plain=False):
    """The scheme and host a map_remote preset (or, plain, a plain rule) sends
    requests to, as shown; RuleError when it cannot be shown or checked."""
    m = PRESET_TARGET.match(replacement)
    if not m:
        raise RuleError("a map_remote preset's replacement starts with http:// or https://, a host and /, so its target can be shown")
    scheme, netloc = m.groups()
    if "@" in netloc:
        raise RuleError("a map_remote preset's target takes no user or password")
    if "\\" in netloc or "$" in netloc or "{" in netloc or any(c.isspace() for c in netloc):
        raise RuleError("a map_remote preset's target host is written out, not taken from the request (no \\1)")
    u = urllib.parse.urlsplit(f"{scheme}://{netloc}")
    try:
        host, port = (u.hostname or "").rstrip("."), u.port
    except ValueError:
        raise RuleError("a map_remote preset's target has a bad port") from None
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is None and (not HOST_NAME.match(host) or re.fullmatch(r"\d+|0x[0-9a-f]*", host.rsplit(".", 1)[-1])):
        # A last label of digits or 0x…: a resolver may read it as an address (2852039166 is 169.254.169.254).
        raise RuleError("a map_remote preset's target must be a host name or an address")
    if port == 0:
        raise RuleError("a map_remote preset's target has a bad port")
    if addr is not None and (addr.is_link_local or addr.is_unspecified or addr.is_multicast):
        raise RuleError("a map_remote preset's target cannot be a link-local, unspecified or multicast address")
    if scheme == "http" and not plain and not (addr is not None and (addr.is_private or addr.is_loopback) or LOCAL_NAMES.fullmatch(host)):
        raise RuleError("a map_remote preset over plain http only to this computer or a LAN address (localhost, *.local, a private address); use https")
    return _origin(f"{scheme}://{netloc}/")


def _shown_target(replacement):
    """A plain map_remote rule's target as list_rules shows it: its scheme and
    host when written out, "path only", or "not shown" (taken from the request,
    with a user, …); never the regex or the rest of the replacement."""
    if re.match(r"/(?!/)", replacement):
        return "path only"
    if re.fullmatch(r"https?://[^/?#]*", replacement):
        replacement += "/"  # https://staging.example.com, the path left as it was
    try:
        return _map_remote_target(replacement, plain=True)
    except ValueError:  # RuleError, or urllib's on a bad address
        return "not shown"


# Filter parts a method and URL tell (and whether a response is in yet); any
# other (~h, ~b, ~t, ~c, ~src, ~comment…) reads what explain_rules has not got.
URL_ONLY = (flowfilter.FMethod, flowfilter.FDomain, flowfilter.FUrl, flowfilter.FReq, flowfilter.FResp, flowfilter.FHTTP, flowfilter.FAll)


def _decide(f, flow):
    """mitmproxy's filter f on flow, its own parts deciding: True, False, or
    None when what decides it reads more than the method and URL."""
    if isinstance(f, flowfilter.FNot):
        v = _decide(f.itm, flow)
        return None if v is None else not v
    if isinstance(f, (flowfilter.FAnd, flowfilter.FOr)):
        vs = {_decide(x, flow) for x in f.lst}
        win = isinstance(f, flowfilter.FOr)  # any True decides an or, any False an and
        return win if win in vs else None if None in vs else not win
    return bool(f(flow)) if isinstance(f, URL_ONLY) else None


def _direction(f):
    """A modify_headers rule's direction as list_rules shows it: request (~q)
    or response (~s) when its filter requires one, else both."""
    parts = f.lst if isinstance(f, flowfilter.FAnd) else [f]
    for cls, d in ((flowfilter.FReq, "request"), (flowfilter.FResp, "response")):
        if any(isinstance(x, cls) for x in parts):
            return d
    return "both"


def _origin(url):
    """scheme://host[:port] of url, the port left out when it is the scheme's."""
    u = urllib.parse.urlsplit(url)
    host = (u.hostname or "").rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    port = u.port
    return f"{u.scheme}://{host}" + (f":{port}" if port is not None and (u.scheme, port) not in (("http", 80), ("https", 443)) else "")


class RuleError(ValueError):
    """A rule refused by reqcove itself: its message quotes nothing of the rule."""


# HTTP header syntax: a name is a token; a value has no CR, LF or NUL (they
# would start a header of their own on the wire).
HEADER_NAME = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
BAD_IN_VALUE = re.compile(rb"[\r\n\x00]")


HOST_NAME = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$")


class Resolve:
    """resolve: name=IPv4[:port] rules, reqcove's own (mitmproxy has no such
    option in this mode): requests whose Host is name go to that address, with
    Host and SNI left as they were, and TLS checked against name."""

    # Never a target: no host there, a cloud's metadata service (169.254.169.254,
    # Alibaba's 100.100.100.200), or Tailscale's own 100.100.100.100.
    REFUSED = [ipaddress.ip_network(n) for n in ("0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "100.100.100.100/32", "100.100.100.200/32")]

    def __init__(self):
        self.replacements = {}  # name -> (ip, port or None)
        self.presets = []  # (preset, name, ip, port or None): only while an agent has it on
        self.order = []  # each rule's name, in the file's order (for errors)

    def target(self, name, book):
        """Where name goes now: a preset that is on for it first, then a plain rule.
        (address, preset or None), or None."""
        for preset, n, ip, port in self.presets:
            if n == name and book.on(preset):
                return (ip, port), preset
        t = self.replacements.get(name)
        return (t, None) if t else None

    def names(self):
        return list(self.replacements) + [n for _, n, _, _ in self.presets if n not in self.replacements]

    def add(self, spec, preset=None):
        name, sep, target = spec.partition("=")
        name = name.strip().lower().rstrip(".")
        # A host name only (no wildcard, address or control characters): it is
        # shown in run's log and in errors.
        if not sep or not HOST_NAME.match(name) or name == "mitm.it":
            raise ValueError("write name=IPv4 or name=IPv4:port, one exact host name")
        ip, _, port = target.strip().partition(":")
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            raise ValueError(f"{name}: the target must be an IPv4 address, not {target.strip()!r}") from None
        if any(addr in n for n in self.REFUSED):
            raise ValueError(f"{name}: {addr} cannot be a target (no host there, or a metadata service)")
        if port and not (port.isdigit() and 0 < int(port) < 65536):
            raise ValueError(f"{name}: bad port {port!r}")
        if preset is None and name in self.replacements:
            raise ValueError(f"{name}: listed twice")
        port = int(port) if port else None
        # mitmproxy reuses a connection by address, not name: two names at one
        # address would share connections, one name's TLS check standing for
        # both. Without a port, a rule takes whatever port the app uses. Presets
        # count too, on or not; one name's own presets may share an address.
        for other, (ip, p) in list(self.replacements.items()) + [(n, (i, q)) for _, n, i, q in self.presets]:
            if other != name and ip == str(addr) and (port is None or p is None or port == p):
                raise ValueError(f"{name}: {addr} is {other}'s target too; give each name its own address or port")
        if preset is None:
            self.replacements[name] = (str(addr), port)
        else:
            self.presets.append((preset, name, str(addr), port))
        self.order.append(name)
        return name, str(addr), port


MOCK_BODY = 1 << 20  # a mock's body, inline or from a file, at most
MOCK_DELAY_MS = 30000  # under URLSession's default timeout (60 s): slow, not a timeout
PRESET_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")
PRESET_SECONDS, PRESET_TIMES = 300, 20  # activate_preset's bounds (Go checks them too)
GQL_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]{0,99}")
GQL_NAME_RUN = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")
GQL_NUMBER_RUN = re.compile(r"[-0-9][0-9.eE+-]*")
GQL_BLOCK = re.compile(r'"""(?:\\"""|[\s\S])*?(?:"""|\Z)')
GQL_STRING = re.compile(r'"(?:[^"\\\n\r]|\\[\s\S])*(?:"|\Z)')
# GraphQL tokens, for the first operation: read once, front to back (a pattern
# searched from every "}" read the rest again from each: quadratic).
GQL_TOKEN = re.compile(r'''(?P<skip>[ \t\n\r,\ufeff]+|#[^\n\r]*)|(?P<block>"""(?:\\"""|[\s\S])*?(?:"""|\Z))|(?P<str>"(?:[^"\\\n]|\\.)*"?)|(?P<name>[_A-Za-z][_0-9A-Za-z]*)|(?P<punct>[\s\S])''')


def _head(doc, limit=5):
    """doc's first limit tokens as (kind, text), and whether all of doc fits
    in fewer; None at a character GraphQL does not allow or a line break in a
    string, with the tokens before it. As reqcove's Go lexes (gqlLex)."""
    toks, i, n = [], 0, len(doc)
    while i < n:
        c = doc[i]
        if c in " \t\n\r,\ufeff":
            i += 1
            continue
        if c == "#":
            while i < n and doc[i] not in "\n\r":
                i += 1
            continue
        if len(toks) == limit:
            return toks, False
        if c == "_" or "A" <= c <= "Z" or "a" <= c <= "z":
            m = GQL_NAME_RUN.match(doc, i)
            toks.append(("n", m.group()))
            i = m.end()
        elif c == "-" or "0" <= c <= "9":
            i = GQL_NUMBER_RUN.match(doc, i).end()
            toks.append(("0", ""))
        elif doc.startswith('"""', i):
            m = GQL_BLOCK.match(doc, i)
            toks.append(("b", ""))
            i = m.end()
        elif c == '"':
            m = GQL_STRING.match(doc, i)
            if m is None:
                return toks, None
            toks.append(("s", ""))
            i = m.end()
        elif doc.startswith("...", i) or n - i < 3 and "...".startswith(doc[i:]):
            toks.append((".", ""))
            i += 3
        elif c in "!$&():=@[]{|}":
            toks.append((c, ""))
            i += 1
        else:
            return toks, None
    return toks, True


def _starts(doc):
    """doc's first tokens start a document, as reqcove's Go decides it
    (gqlStart): an operation, a fragment, or { then a field with arguments,
    selections, an alias, another field or a spread, or { name } alone or
    before another definition. "{count} items" and "query cats" are not."""
    toks, ok = _head(doc)
    ended = ok is True and len(toks) < 5
    if toks and toks[0][0] in "sb":
        toks = toks[1:]  # a description
    def is_(k, kind, text=""):
        return k < len(toks) and toks[k][0] == kind and (not text or toks[k][1] == text)
    def opens(k):
        return k < len(toks) and toks[k][0] in "({@"
    if is_(0, "n", "query") or is_(0, "n", "mutation") or is_(0, "n", "subscription"):
        return opens(1) or is_(1, "n") and opens(2)
    if is_(0, "n", "fragment"):
        return is_(1, "n") and is_(2, "n", "on")
    if is_(0, "{"):
        if is_(1, "."):
            return True
        if not is_(1, "n"):
            return False
        return (opens(2) or is_(2, "n") or is_(2, ".") or is_(2, ":") and is_(3, "n")
                or is_(2, "}") and (ended and len(toks) == 3 or any(is_(3, "n", w) for w in ("fragment", "query", "mutation", "subscription"))))
    return False


def _first_operation(doc):
    """The name of doc's first operation (past fragments and descriptions),
    "" for an anonymous one, None if doc does not start like a document; one
    pass, as reqcove's Go reads it (gqlDocOperation)."""
    if not _starts(doc):
        return None
    depth, fragment, keyword = 0, False, False
    for m in GQL_TOKEN.finditer(doc):
        kind, text = m.lastgroup, m.group()
        if kind == "skip":
            continue
        if keyword:  # the token just after query, mutation or subscription
            return text if kind == "name" else ""
        if kind in ("block", "str"):
            continue
        if kind == "punct" and text in "{([":
            if text == "{" and depth == 0:
                if not fragment:
                    return ""  # { … } alone: an anonymous query
                fragment = False
            depth += 1
        elif kind == "punct" and text in "})]":
            depth -= 1
        elif kind == "name" and depth == 0:
            keyword = text in ("query", "mutation", "subscription")
            fragment = fragment or text == "fragment"
    return ""


def _name(n):
    return n if isinstance(n, str) and GQL_NAME.fullmatch(n) else None


def _doc_name(doc):
    """"" for an anonymous operation (it ends the search), None for no
    document or a name GraphQL does not allow (the search goes on)."""
    op = _first_operation(doc) if isinstance(doc, str) else None
    return op if op == "" else _name(op)


def _operations(r):
    """Where a request names its operation, in the order reqcove's Go reads
    them (gqlURLOperation, the header, gqlBodyOperation); lazily: the body is
    decoded only when the URL and header name none."""
    yield _name(r.query.get("operationName"))
    yield _doc_name(r.query.get("query"))
    yield _name(r.headers.get("x-apollo-operation-name"))
    if r.method == "GET":
        return
    try:  # decoded with a bound: a compressed body may be a bomb
        body = _Decoder(r.headers.get("content-encoding", "").strip().lower()).feed(r.raw_content or b"", MAP_LOCAL_BODY + 1)
    except Exception:
        body = b""
    text = body.decode("utf-8", "replace") if len(body) <= MAP_LOCAL_BODY else ""
    try:
        d = json.loads(text or "null")
    except RecursionError:
        d = None  # nested past Python's limit: no GraphQL request
    except ValueError:
        yield _doc_name(text)  # a document as the body (application/graphql)
        return
    if isinstance(d, dict):
        yield _name(d.get("operationName"))
        yield _doc_name(d.get("query"))


def _operation(r):
    """A request's GraphQL operation, as reqcove names it: the first place
    that names one; None for none, an anonymous one or a batch."""
    for op in _operations(r):
        if op is not None:
            return op or None
    return None


class Presets:
    """Every preset in the --rules file, of any kind (mock, map_remote,
    modify_headers, resolve), by name: what an agent may turn on. Kept with the
    rules, so a reload (new Presets) turns every one off."""

    def __init__(self):
        self.entries = {}  # name -> (kind, match key, what list shows)
        self.specs = {"map_remote": [], "modify_headers": []}  # kind -> [(name, mitmproxy's rule)]
        # Every rule in the file's order, for list_rules and explain_rules:
        # (kind, index, preset or None, what list_rules shows, mitmproxy's rule or None).
        self.rules = []
        # name -> [deadline (time.monotonic()), requests left or None, expires_at (time.time())]
        self.active = {}

    def add(self, name, kind, key, info):
        if not (isinstance(name, str) and PRESET_NAME.fullmatch(name)):
            raise RuleError("preset must be a name of letters, digits, '.', '_' and '-', at most 64")
        if name in self.entries:
            raise RuleError("another rule has this preset name")
        self.entries[name] = (kind, key, info)

    def names(self):
        return list(self.entries)

    def on(self, name):
        """Whether preset name is on now; one past its time is turned off.
        Both clocks: the monotonic one stops while the computer sleeps (macOS,
        Linux), the wall clock can be set back; whichever ends first wins."""
        a = self.active.get(name)
        if a and (time.monotonic() >= a[0] or time.time() >= a[2]):
            del self.active[name]
            a = None
        return a is not None

    def use(self, name):
        """A request a preset changed or answered: one of its requests used."""
        a = self.active.get(name)
        if a and a[1] is not None:
            a[1] -= 1
            if a[1] <= 0:
                del self.active[name]

    def control(self, req):
        """An agent's request through reqcove (activate_preset and the others):
        the answer, or ValueError with why not."""
        op = req.get("op")
        if op == "list":
            out = []
            for name, (kind, _, info) in self.entries.items():
                on = self.on(name)
                a = self.active.get(name)
                out.append(dict(info, name=name, kind=kind, active=on, remaining=a[1] if a else None, expires_at=a[2] if a else None))
            return {"presets": out}
        name = req.get("name")
        entry = self.entries.get(name) if isinstance(name, str) else None
        if entry is None:
            raise ValueError(f"no preset named {name!r}" if isinstance(name, str) and PRESET_NAME.fullmatch(name) else "no preset by that name")
        if op == "deactivate":
            on = self.on(name)
            self.active.pop(name, None)
            return {"name": name, "was_active": on}
        if op != "activate":
            raise ValueError("unknown request")
        seconds, times = req.get("seconds"), req.get("times")
        if not isinstance(seconds, int) or isinstance(seconds, bool) or not 1 <= seconds <= PRESET_SECONDS:
            raise ValueError(f"seconds must be from 1 to {PRESET_SECONDS}")
        if times is not None and entry[0] != "mock":
            raise ValueError("times is for mocks only: a preset of this kind is on for a time")
        if times is not None and (not isinstance(times, int) or isinstance(times, bool) or not 1 <= times <= PRESET_TIMES):
            raise ValueError(f"times must be from 1 to {PRESET_TIMES}")
        off, expires = self.turn_on(name, seconds, times)
        return {"name": name, "expires_at": expires, "times": times, "turned_off": off}

    def turn_on(self, name, seconds, times):
        """Turn preset name on; one preset on per match, so another for the same
        match goes off. The ones turned off, and when name turns off."""
        kind, key, _ = self.entries[name]
        off = [n for n, (k, kk, _) in self.entries.items() if n != name and k == kind and kk == key and self.on(n)]
        for other in off:
            del self.active[other]
        now = time.time()
        self.active[name] = [time.monotonic() + seconds, times, now + seconds]
        return off, now + seconds


class Mock:
    """mock: answers made here, reqcove's own. A request whose method, URL and
    GraphQL operation match the first such rule gets its status, headers and
    body; nothing of it reaches the origin (no request is sent: a connection
    mitmproxy opened early may exist). Errors quote nothing of the rule."""

    KEYS = {"match", "status", "headers", "body", "body_file", "preset", "description", "delay_ms", "fault"}

    def __init__(self, presets=None):
        # (method or None, url, operation or None, status, headers, body, preset or None, description, delay_ms, fault or None)
        self.replacements = []
        # A preset answers only while an agent has turned it on (activate_preset).
        self.book = presets if presets is not None else Presets()

    def add(self, spec, base):
        if not isinstance(spec, dict) or set(map(str, spec)) - self.KEYS:
            raise RuleError("a mock is a mapping of match, status, headers, body or body_file, and preset, description, delay_ms, fault")
        m = spec.get("match")
        if not isinstance(m, dict) or set(map(str, m)) - {"method", "url", "operation"} or not isinstance(m.get("url"), str):
            raise RuleError("match needs url, and may have method and operation")
        method, op, url = m.get("method"), m.get("operation"), m["url"]
        if method is not None and not (isinstance(method, str) and re.fullmatch(r"[A-Za-z]{1,20}", method)):
            raise RuleError("method must be a word such as POST")
        if op is not None and not (isinstance(op, str) and GQL_NAME.fullmatch(op)):
            raise RuleError("operation must be a GraphQL name")
        u = urllib.parse.urlsplit(url.removesuffix("*"))
        if u.scheme not in ("http", "https") or not u.hostname or not HOST_NAME.match(u.hostname):
            raise RuleError("url must be an http or https URL with a host name (a * at the end matches any rest)")
        if u.query or u.fragment or u.username is not None or url.endswith("*") and not u.path:
            # Never matched (the query is not compared; a * after the host would match other hosts too).
            raise RuleError("url takes no query, fragment or user, and a * only after a path (https://host/*)")
        if u.port in (80, 443):
            raise RuleError("leave out the default port")
        url = f"{u.scheme}://{u.netloc.lower()}{u.path or '/'}" + ("*" if url.endswith("*") else "")  # a request's path is / at least
        preset, description = spec.get("preset"), spec.get("description", "")
        if preset is not None and not (isinstance(preset, str) and PRESET_NAME.fullmatch(preset)):
            raise RuleError("preset must be a name of letters, digits, '.', '_' and '-', at most 64")
        if preset is not None and preset in self.book.entries:
            raise RuleError("another rule has this preset name")
        if "description" in spec and (preset is None or not isinstance(description, str) or len(description) > 200 or BAD_IN_VALUE.search(description.encode()) or "\n" in description):
            raise RuleError("description goes with preset: one line of text, at most 200 characters")
        delay = spec.get("delay_ms", 0)
        if not isinstance(delay, int) or isinstance(delay, bool) or not 0 <= delay <= MOCK_DELAY_MS:
            raise RuleError(f"delay_ms must be a number from 0 to {MOCK_DELAY_MS}")
        fault = spec.get("fault")
        if fault is not None and fault != "close":
            raise RuleError("fault can only be close")
        if fault and {"status", "headers", "body", "body_file"} & set(spec):
            raise RuleError("a mock with fault: close sends no answer: no status, headers or body")
        key = (method.upper() if method else None, url, op)
        for other in self.replacements:
            if other[:3] == key and (other[6] is None) != (preset is None):
                # A plain mock would always answer before the preset, or never let it.
                raise RuleError("a plain mock and a preset have the same match")
        status = spec.get("status", 200)
        if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
            raise RuleError("status must be a number from 100 to 599")
        headers = spec.get("headers") or {}
        if not isinstance(headers, dict) or not all(isinstance(k, str) and isinstance(v, (str, int)) and not isinstance(v, bool) for k, v in headers.items()):
            raise RuleError("headers must map names to text values")
        hs = [(k.encode(), str(v).encode()) for k, v in headers.items()]
        for k, v in hs:
            if not HEADER_NAME.match(k):
                raise RuleError("a header name must be a plain token (letters, digits, - and the like)")
            if BAD_IN_VALUE.search(v):
                raise RuleError("a header value cannot hold a line break or NUL")
        if not any(k.lower() == b"cache-control" for k, _ in hs):
            hs.append((b"Cache-Control", b"no-store"))  # an app must not keep a made answer
        if "body" in spec and "body_file" in spec:
            raise RuleError("body or body_file, not both")
        if "body_file" in spec:
            if not isinstance(spec["body_file"], str):
                raise RuleError("body_file must be a path")
            try:
                path = (base / Path(spec["body_file"]).expanduser()).resolve(strict=True)
                if not path.is_file():  # a FIFO or a device: no size to trust, and a read may never end
                    raise RuleError("body_file must be a plain file")
                with path.open("rb") as f:
                    body = f.read(MOCK_BODY + 1)
                too_big = len(body) > MOCK_BODY
            except OSError:
                raise RuleError("body_file cannot be read") from None
        else:
            body = spec.get("body", "")
            if not isinstance(body, str):
                raise RuleError("body must be text (or use body_file)")
            body = body.encode()
            too_big = len(body) > MOCK_BODY
        if too_big:
            raise RuleError("the body is over 1 MiB")
        if preset is not None:
            self.book.add(preset, "mock", key, {
                "description": description, "method": key[0], "url": url, "operation": op,
                "status": None if fault else status, "delay_ms": delay, "fault": fault,
            })
        self.replacements.append(key + (status, hs, body, preset, description, delay, fault))

    def hosts(self):
        return [urllib.parse.urlsplit(url.removesuffix("*")).hostname for _, url, *_ in self.replacements]

    def presets(self):
        return [m[6] for m in self.replacements if m[6] is not None]

    def candidates(self, flow):
        """The rules flow's method and URL match, operation aside: presets that
        are on first, then plain mocks; a preset that is off is none."""
        r = flow.request
        port = "" if (r.scheme, r.port) in (("http", 80), ("https", 443)) else f":{r.port}"
        bare = f"{r.scheme}://{r.pretty_host.lower().rstrip('.')}{port}{r.path.split('?', 1)[0]}"
        whole = bare + ("?" + r.path.split("?", 1)[1] if "?" in r.path else "")
        hits = [i for i, (method, url, *_) in enumerate(self.replacements)
                if (method is None or method == r.method.upper()) and (whole.startswith(url[:-1]) if url.endswith("*") else bare == url)]
        on = [i for i in hits if self.replacements[i][6] is not None and self.book.on(self.replacements[i][6])]
        return on + [i for i in hits if self.replacements[i][6] is None]

    def answer(self, flow, op=False):
        """The first rule matching flow, made into its response:
        (index, status or "close", preset or None, delay_ms), or None. A preset
        that answers uses one of its requests. op: the GraphQL operation, if
        known (explain_rules); False reads it from the request."""
        for i in self.candidates(flow):
            want = self.replacements[i][2]
            if want is not None:
                if op is False:
                    op = _operation(flow.request)
                if op != want:
                    continue
            _, _, _, status, hs, body, preset, _, delay, fault = self.replacements[i]
            if preset is not None:
                self.book.use(preset)
            if fault == "close":
                return i, "close", preset, delay
            if flow.request.method == "HEAD" or status in (204, 304) or status < 200:
                body = b""
            flow.response = http.Response.make(status, body, hs)
            return i, status, preset, delay
        return None


# --web: mitmweb's flows are bounded as Reqcove's records are.
WEB_MAX_FLOWS = 10000
WEB_MAX_BYTES = 256 << 20

RULES_POLL = 1.0  # seconds between looks at the --rules file, with --rules-reload


def _stamp(path):
    """What changes when the file is saved, in place or by a rename; None when it is gone."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


def _rule_items(data, kind):
    """kind's rules as (spec, preset or None, description): a plain string, or
    a mapping {rule: …, preset: NAME, description: …} for a preset."""
    specs = data.get(kind) or []
    if not isinstance(specs, list):
        raise ValueError(f"{kind} must be a list")
    out = []
    for i, item in enumerate(specs):
        if isinstance(item, str):
            out.append((item, None, ""))
            continue
        if not isinstance(item, dict) or set(map(str, item)) - {"rule", "preset", "description"} or not isinstance(item.get("rule"), str):
            raise ValueError(f"{kind}[{i}]: a rule is a string, or a mapping of rule, preset and description")
        preset, description = item.get("preset"), item.get("description", "")
        if preset is None:
            raise ValueError(f"{kind}[{i}]: a mapping is for a preset (preset: NAME); write a plain rule as a string")
        if not (isinstance(preset, str) and PRESET_NAME.fullmatch(preset)):
            raise ValueError(f"{kind}[{i}]: preset must be a name of letters, digits, '.', '_' and '-', at most 64")
        if not isinstance(description, str) or len(description) > 200 or BAD_IN_VALUE.search(description.encode()) or "\n" in description:
            raise ValueError(f"{kind}[{i}]: description: one line of text, at most 200 characters")
        out.append((item["rule"], preset, description))
    return out


def load_rules(path):
    """The --rules file as mitmproxy's own rule addons, which reqcove calls
    from its hooks (so rules never touch skipped flows or mitm.it).

    Errors name the rule by kind and index, never its text (filters, regexes
    and values can carry tokens); only resolve's names and addresses are said."""
    data = ruamel.yaml.YAML(typ="safe", pure=True).load(Path(path).read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError("the file must map mock, map_remote, map_local, modify_headers and resolve to lists")
    extra = sorted(str(k) if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", str(k)) else "(a key that is not a name)" for k in data if k not in RULE_KINDS + RULE_SETTINGS)
    if extra:  # a key that is not a name is not quoted: it may be a misplaced rule
        raise ValueError(f"only {', '.join(RULE_KINDS + RULE_SETTINGS)} are allowed, not {', '.join(extra)}")
    keep = data.get("keep_host_header", False)
    if not isinstance(keep, bool):
        raise ValueError("keep_host_header must be true or false")
    addons = {"map_remote": mapremote.MapRemote(), "map_local": maplocal.MapLocal(), "modify_headers": modifyheaders.ModifyHeaders()}
    addons["map_remote"].keep_host_header = keep
    book = Presets()
    resolve = Resolve()
    for i, item in enumerate(_rule_items(data, "resolve")):
        spec, preset, description = item
        try:
            if preset is not None and preset in book.entries:
                raise RuleError("another rule has this preset name")
            name, ip, port = resolve.add(spec, preset)
            shown = {"host": name, "address": f"{ip}:{port}" if port else ip}
            book.rules.append(("resolve", i, preset, shown, None))
            if preset is not None:
                book.add(preset, "resolve", ("resolve", name), dict(shown, description=description))
        except ValueError as e:
            raise ValueError(f"resolve[{i}]: {e}") from None
    for kind, addon in addons.items():
        plain, presets = [], []  # match keys, so a plain rule and a preset never share one
        for i, (spec, preset, description) in enumerate(_rule_items(data, kind)):
            try:
                rule = _parse_rule(kind, spec, Path(path).parent)
                flt, subject = _spec_parts(spec)
                key = (kind, flt, subject.lower() if kind == "modify_headers" else subject)
                # Derived parts only: never the filter, the regex, a value or a path.
                shown = {}
                if kind == "map_remote":
                    shown = {"target": _map_remote_target(rule.replacement) if preset else _shown_target(rule.replacement)}
                elif kind == "modify_headers":
                    shown = {"header": rule.subject.decode(), "direction": "request" if preset else _direction(rule.matches)}
                book.rules.append((kind, i, preset, shown, rule))
                if preset is None:
                    if key in presets:
                        raise RuleError("a plain rule and a preset have the same match")
                    plain.append(key)
                    addon.replacements.append(rule)
                    continue
                if key in plain:
                    raise RuleError("a plain rule and a preset have the same match")
                if kind == "map_remote":
                    info = {"description": description, "target": shown["target"]}
                elif kind == "modify_headers":
                    if re.search(r"(?:^|[\s!(&|])~s(?:$|[\s)])", flt):
                        raise RuleError("a modify_headers preset changes requests only (no ~s): a response one could drop a page's protections")
                    info = {"description": description, "header": subject}
                else:
                    raise RuleError("map_local takes no preset")
                book.add(preset, kind, key, info)
                presets.append(key)
                book.specs[kind].append((preset, rule))
            except RuleError as e:
                raise ValueError(f"{kind}[{i}]: {e}") from None
            except Exception as e:
                # Only the error's kind: mitmproxy's messages quote the filter, the
                # regex or the value, and any of them can carry a token. They go
                # to the log, and after a reload to the status tool and the page.
                raise ValueError(f"{kind}[{i}]: {type(e).__name__}") from None
    addons["resolve"] = resolve
    mock = Mock(book)
    specs = data.get("mock") or []
    if not isinstance(specs, list):
        raise ValueError("mock must be a list of mappings")
    for i, spec in enumerate(specs):
        try:
            mock.add(spec, Path(path).parent)
            method, url, op, status, _, _, preset, _, delay, fault = mock.replacements[-1]
            book.rules.append(("mock", i, preset, {"method": method, "url": url, "operation": op, "status": None if fault else status, "delay_ms": delay, "fault": fault}, None))
        except RuleError as e:
            raise ValueError(f"mock[{i}]: {e}") from None
        except Exception as e:
            raise ValueError(f"mock[{i}]: {type(e).__name__}") from None
    addons["mock"] = mock
    return addons


def rule_counts(rules):
    """The rules loaded, by kind, presets in their kind (capture_stats.rules)."""
    kinds = [r[0] for r in rules["mock"].book.rules]
    return dict({k: kinds.count(k) for k in rules}, keep_host_header=int(rules["map_remote"].keep_host_header))


def _dry_rules(rules, unknown, also=None):
    """rules for explain_rules' dry run: the same rules, a copy of the presets'
    state (nothing here turns a real one off or uses a request of it), preset
    also turned on as activate_preset would, and each filter decided by what a
    method and URL tell: one that reads more (a header, a body, the response)
    counts as not matching, and its rule goes into unknown as kind[index]."""
    book = copy.copy(rules["mock"].book)
    book.active = {n: list(a) for n, a in book.active.items()}
    if also:
        book.turn_on(also, PRESET_SECONDS, None)
    where = {id(spec): f"{kind}[{i}]" for kind, i, _, _, spec in book.rules if spec is not None}

    def wrap(spec):
        def matches(flow):
            v = _decide(spec.matches, flow)
            if v is None:
                unknown.add(where[id(spec)])
            return bool(v)
        return spec._replace(matches=matches)

    book.specs = {k: [(p, wrap(s)) for p, s in v] for k, v in book.specs.items()}
    out = dict(rules, mock=copy.copy(rules["mock"]))
    out["mock"].book = book
    for kind in ("map_remote", "map_local", "modify_headers"):
        out[kind] = copy.copy(rules[kind])
        out[kind].replacements = [wrap(s) for s in rules[kind].replacements]
    return out


class Reqcove:
    def __init__(self):
        self.q = queue.Queue()
        self.lock = threading.Lock()
        self.queued_bytes = 0
        self.path = ""
        self.head_limit = 64 * 1024
        self.queue_limit = 32 << 20
        self.dropped_bodies = 0
        self.dropped_events = 0
        self.out_of_scope = 0
        self.secret = None  # SOCKS5 password; None rejects every connection
        self.allow_all = False
        self.allow = []
        self.passing = []  # --pass-hosts: allowed hosts carried undecrypted, their connections' metadata recorded
        self.conn_device = {}  # client connection id -> device (SOCKS5 user), while connected
        self.resolve_sni = {}  # (client connection id, (ip, port)) -> the name a resolve rule sent there
        self.rules = None  # load_rules(), or None without --rules
        self.web_keep = 0  # --web: bodies up to this many bytes kept for mitmweb
        self.kept = {}  # (flow id, "request" or "response") -> the body to give mitmweb
        self.web_flows = collections.deque()  # (flow, bytes kept): mitmweb's flows, oldest first
        self.web_bytes = 0
        self.flow_rules = {}  # flow id -> the rules its request got, so a reload mid-flow does not mix two sets
        self.rules_stamp = None  # the file's (mtime, size, inode) when loaded, for --rules-reload
        self.rules_watch = None
        self.upstream = None  # (host, port) of --upstream-proxy
        self.rules_error = ""
        self.control_server = None
        threading.Thread(target=self._writer, daemon=True).start()

    async def _serve_control(self, path):
        """reqcove's requests about presets and rules, one JSON line each way,
        on the event loop as the hooks (so a count never races a request). Each
        must carry the SOCKS5 secret: run's, and `reqcove mock add`'s, which
        reads it from the state directory (0600) to check a --rules file."""
        async def one(reader, writer):
            try:
                line = await asyncio.wait_for(reader.readline(), 5)
                req = json.loads(line or b"{}")
                if not isinstance(req, dict) or self.secret is None or not hmac.compare_digest(str(req.get("secret", "")).encode(), self.secret.encode()):
                    out = {"error": "refused"}
                elif req.get("op") in ("rules", "explain"):  # list_rules, explain_rules: with or without presets
                    try:
                        out = self._list_rules() if req["op"] == "rules" else self._explain(req)
                    except RuleError as e:
                        out = {"error": str(e)}
                    except Exception as e:  # never mitmproxy's text: it quotes URLs, filters and regexes
                        out = {"error": f"explain_rules failed: {type(e).__name__}"}
                elif req.get("op") == "check":  # reqcove mock add: the file as it would be, at path (next to target), checked as at start
                    out = self._check(str(req.get("path", "")), str(req.get("target", "")), ctx.options.reqcove_rules, ctx.options.reqcove_rules_reload)
                elif not self.rules or not self.rules["mock"].book.entries:
                    out = {"error": "no presets: the --rules file marks no rule with preset:"} if req.get("op") != "list" else {"presets": []}
                else:
                    try:
                        out = self.rules["mock"].book.control(req)
                    except ValueError as e:
                        out = {"error": str(e)}
                writer.write((json.dumps(out) + "\n").encode())
                await writer.drain()
            except Exception:
                pass  # a bad request: no answer
            finally:
                writer.close()
        try:
            os.unlink(path)  # a crashed run's
        except OSError:
            pass
        try:
            server = await asyncio.start_unix_server(one, path)
            os.chmod(path, 0o600)
        except OSError as e:
            print(f"reqcove: the presets' socket: {type(e).__name__}", file=sys.stderr)
            return
        async with server:
            await server.serve_forever()

    def _list_rules(self):
        """list_rules: each rule by kind and its index in the file, its preset
        and whether it is on, and derived parts only (never a filter, a regex, a
        header value, a body or a path)."""
        rules = self.rules
        out = {"loaded": rules is not None, "rules_error": self.rules_error, "rules": []}
        if rules:
            book = rules["mock"].book
            out["keep_host_header"] = rules["map_remote"].keep_host_header
            for kind, i, preset, shown, _ in book.rules:
                out["rules"].append(dict(shown, kind=kind, index=i, preset=preset, active=book.on(preset) if preset else None))
        return out

    def _explain(self, req):
        """explain_rules: what the rules do now to a request of this method, URL
        and GraphQL operation, through the request path's own code on a made
        flow (never sent; no preset's state or count changes); its text
        quotes no rule."""
        method, url, op = req.get("method"), req.get("url"), req.get("operation")
        if not (isinstance(method, str) and re.fullmatch(r"[A-Za-z]{1,20}", method)):
            raise RuleError("method must be a word such as GET")
        # A record's (anonymous) or (batched): no one operation, so no operation mock answers it.
        anon = op in ("(anonymous)", "(batched)")
        if op is not None and not anon and not (isinstance(op, str) and GQL_NAME.fullmatch(op)):
            raise RuleError("operation must be a GraphQL name")
        try:
            if not isinstance(url, str) or len(url) > 16384:
                raise ValueError
            # With the Host a client sends: after resolve (or keep_host_header) a
            # real request keeps it, and ~d and ~u read it.
            r = http.Request.make(method.upper(), url, b"", {"Host": urllib.parse.urlsplit(url).netloc.rpartition("@")[2]})
            port = r.port
        except Exception:
            raise RuleError("url must be an http or https URL") from None
        if r.scheme not in ("http", "https"):
            raise RuleError("url must be an http or https URL")
        host = r.pretty_host.lower().rstrip(".")
        rules = self.rules
        out = {"in_scope": False, "loaded": rules is not None, "rules_error": self.rules_error}
        # As requestheaders and next_layer decide it.
        if not check.is_valid_host(r.pretty_host) or not self._allowed(host):
            return dict(out, scope="not in --allow-hosts: carried but not recorded, and no rule applies to it")
        if self._passed(host):
            return dict(out, scope="in --pass-hosts: carried undecrypted (or, on an allowed host's connection, passed on unrecorded), and no rule applies to it")
        if any(re.search(p, f"{host}:{port}") for p in ctx.options.ignore_hosts):
            return dict(out, scope="mitmproxy passes this host through undecrypted (Apple's, as apple-ignore-hosts.txt lists): not recorded, and no rule applies to it")
        out["in_scope"] = True
        if not rules:
            return out
        # The URL first, as a real request is read (_operations); then the one given.
        op = _operation(r) or (None if anon else op)
        from mitmproxy.test import tflow  # mitmproxy's own made flows (12.3.1 ships them)

        unknown = set()

        def dry(also=None):
            flow = tflow.tflow(req=r.copy())  # content-length 0: a small body
            d = _dry_rules(rules, unknown, also)
            mocks = d["mock"].candidates(flow)
            try:
                done = self._rewrite_request(flow, d, mocks=bool(mocks), dry=True, op=op or False)
            except Exception as e:  # as requestheaders: a 502, never sent on
                return {"rewrites": [f"rules failed: {type(e).__name__}"]}, mocks
            m = flow.metadata
            res = {"rewrites": done, "mocked": bool(m.get("reqcove_mocked"))}
            if not m.get("reqcove_close"):  # a response, made or the server's: response rules apply to it
                if flow.response is None:
                    flow.response = http.Response.make(200)
                res["response_rewrites"] = self._modify_headers(flow, flow.response.headers, "response", d)
            if "reqcove_mapped" in m:
                res["mapped_to"] = _origin(m["reqcove_mapped"])
            res["presets"] = list(dict.fromkeys(list(m.get("reqcove_presets") or []) + ([m["reqcove_preset"]] if m.get("reqcove_preset") else [])))
            return res, mocks

        now, mocks = dry()
        out.update(now)
        book = copy.copy(rules["mock"].book)
        book.active = dict(book.active)  # on() drops one past its time: not from the real state
        if_on, said, seen = {}, list(now["rewrites"]), set(mocks)
        # ponytail: one dry run per preset that is off, on the event loop (a map_local
        # hit reads its file each time); fine for a hand-written file's few presets.
        for name in book.entries:
            if not book.on(name):
                res, more = dry(name)
                seen.update(more)  # a mock preset off: its candidates too
                if name in res.get("presets", []):
                    if_on[name] = res["rewrites"] + res.get("response_rewrites", [])
                    said += res["rewrites"]
        out["if_turned_on"] = if_on
        cannot, conditions = sorted(unknown), []
        wants_op = [i for i in sorted(seen) if rules["mock"].replacements[i][2] is not None]
        if anon and wants_op:
            conditions.append("the request names no one GraphQL operation (anonymous or batched): no mock for an operation answers it")
        elif op is None:
            cannot += [f"mock[{i}]: its method and URL match; it answers one GraphQL operation (pass operation)" for i in wants_op]
        out["cannot_tell"] = cannot
        if seen or any(s.startswith(("mock", "map_local")) for s in said):
            conditions.append("a mock or map_local answers only a request whose body is known to be at most 1 MiB; a larger one, or a POST of unknown length, goes on to the server (its rewrites say skipped); over HTTP/2, a GET of unknown length that sends a body anyway gets a 502")
        if conditions:
            out["conditions"] = conditions
        return out

    def load(self, loader):
        loader.add_option("reqcove_socket", str, "", "Unix socket of `reqcove run`.")
        loader.add_option("reqcove_body_head", int, 64 * 1024, "Bytes of each decoded body sent to reqcove.")
        loader.add_option("reqcove_queue_bytes", int, 32 << 20, "Byte budget of the queue to reqcove.")
        loader.add_option("reqcove_secret_file", str, "", "File holding the SOCKS5 password reqcove uses.")
        loader.add_option("reqcove_allow_hosts", str, "{}", "Hosts recorded, as JSON from reqcove.")
        loader.add_option("reqcove_rules", str, "", "The --rules file.")
        loader.add_option("reqcove_rules_reload", bool, False, "Re-read the --rules file when it changes.")
        loader.add_option("reqcove_web_keep", int, 0, "With mitmweb: keep bodies up to this many bytes for it to show.")
        loader.add_option("reqcove_web_max_flows", int, WEB_MAX_FLOWS, "With mitmweb: the most flows it keeps (tests set fewer).")
        loader.add_option("reqcove_upstream", str, "", "host:port of an HTTP proxy that decrypted requests go on to.")
        loader.add_option("reqcove_control", str, "", "Unix socket where reqcove turns presets on and off.")

    def configure(self, updated):
        self.path = ctx.options.reqcove_socket
        self.head_limit = ctx.options.reqcove_body_head
        self.web_keep = ctx.options.reqcove_web_keep
        self.queue_limit = ctx.options.reqcove_queue_bytes
        if "reqcove_secret_file" in updated:
            try:
                with open(ctx.options.reqcove_secret_file) as f:
                    self.secret = f.read().strip() or None
            except OSError:
                self.secret = None
        if "reqcove_allow_hosts" in updated:
            rules = json.loads(ctx.options.reqcove_allow_hosts or "{}")
            self.allow_all = bool(rules.get("all"))
            self.allow = [re.compile(p) for p in rules.get("patterns") or []]
            self.passing = [re.compile(p) for p in rules.get("pass") or []]
        if "reqcove_upstream" in updated:
            host, _, port = ctx.options.reqcove_upstream.rpartition(":")
            self.upstream = (host.strip("[]"), int(port)) if host else None  # [::1]:8080
        if "reqcove_rules" in updated:
            self.rules, self.rules_error = None, ""
            if ctx.options.reqcove_rules:
                self.rules_stamp = _stamp(ctx.options.reqcove_rules)
                # On an error reqcove reads it from the hello and refuses to start;
                # none of the rules applies meanwhile.
                self.rules, self.rules_error = self._load_checked(ctx.options.reqcove_rules)

    def _load_checked(self, path):
        """The rules in path, checked as at start, or None and why not (never a
        rule's text: modify_headers rules often carry tokens)."""
        try:
            rules = load_rules(path)
            if self.upstream and rules["resolve"].names():
                # Burp connects by the name in the SNI, looked up again on this computer: the rule would not apply.
                raise ValueError("resolve does not go with --upstream-proxy (Burp connects by the name, not the address); use the proxy's own host overrides, such as Burp's Hostname resolution overrides")
            for i, name in enumerate(rules["resolve"].order):
                if self._passed(name):  # never decrypted, so no rule applies to it
                    raise ValueError(f"resolve[{i}]: {name} is in --pass-hosts: carried undecrypted, no rule applies to it")
                if not self._in_scope(name):  # would never apply: a typo
                    raise ValueError(f"resolve[{i}]: {name} is not in --allow-hosts")
            for i, name in enumerate(rules["mock"].hosts()):
                if self._passed(name):
                    raise ValueError(f"mock[{i}]: {name} is in --pass-hosts: carried undecrypted, no rule applies to it")
                if not self._in_scope(name):
                    raise ValueError(f"mock[{i}]: {name} is not in --allow-hosts")
            return rules, ""
        except Exception as e:
            why = str(e) if isinstance(e, ValueError) else type(e).__name__
            if mark := getattr(e, "problem_mark", None):  # YAML syntax: where, not what
                why += f" at line {mark.line + 1}"
            return None, why

    def _check(self, path, target, rules, reload):
        """op check: why the --rules file at path would not load with this
        run's hosts ("" when it would), and whether this run reads target
        (same) and takes it again when it changes (reload). Changes nothing.
        A path, not the text: a control line is at most 64 KiB."""
        _, why = self._load_checked(path)
        try:
            same = bool(rules) and os.path.samefile(rules, target)
        except OSError:  # target not there yet
            same = False
        return {"check": why, "same": same, "reload": same and bool(reload)}

    async def _watch_rules(self, path):
        """--rules-reload: once a second, look at the file; take it again when it
        changed and then looked the same twice in a row (not mid-save).
        A file that does not load leaves the rules before it in place, and says
        why. On the event loop, as the hooks, so a swap never lands mid-hook."""
        seen = self.rules_stamp
        while True:
            await asyncio.sleep(RULES_POLL)
            try:
                stamp = _stamp(path)
                # Taken once it looks the same twice in a row: not halfway through
                # a save (an editor's truncate, then write).
                changed, settled, seen = stamp != self.rules_stamp, stamp == seen, stamp
                if not changed or not settled:
                    continue
                self.rules_stamp = stamp
                if self.rules:
                    self.rules["mock"].book.active.clear()  # a changed file turns presets off, loaded or not
                rules, why = self._load_checked(path) if stamp else (None, "the file is gone")
                if rules is not None:
                    self.rules = rules
                self.rules_error = why
            except Exception as e:  # the watch must not die quietly
                self.rules_error = type(e).__name__
            self.put_event(dict(self._rules_info(), v=VERSION, ev="rules"))

    def _rules_info(self):
        rules = self.rules  # once: the writer thread asks too, for the hello on a reconnect
        return {
            "rules": rule_counts(rules) if rules else None,
            "resolve": [f"{n} -> {ip}:{port or 'as asked'}" for n, (ip, port) in rules["resolve"].replacements.items()] if rules else None,
            "rules_error": self.rules_error,
            "presets": rules["mock"].book.names() if rules else [],
            "preset_targets": {n: info.get("target") or info.get("address") for n, (_, _, info) in rules["mock"].book.entries.items() if info.get("target") or info.get("address")} if rules else {},
        }

    def socks5_auth(self, data):
        # mitmproxy's proxyauth=any has already accepted any user and password;
        # only reqcove, which holds the secret, may use this listener.
        if self.secret is None or not hmac.compare_digest(data.password.encode(), self.secret.encode()):
            data.valid = False
        else:
            self.conn_device[data.client_conn.id] = data.username  # for TLS failures, which have no flow

    def client_disconnected(self, client):
        self.conn_device.pop(client.id, None)
        for k in [k for k in self.resolve_sni if k[0] == client.id]:
            del self.resolve_sni[k]

    def server_connect(self, data):
        if data.server.address == HOLD:
            data.server.error = HOLD_REFUSED

    def tls_start_server(self, data):
        # A connection a resolve rule made: TLS says, and is checked for, the
        # name the app asked for, not the address. tls_start_server sees the
        # server connection itself; server_connect, behind a tunnel, would not.
        name = self.resolve_sni.get((data.context.client.id, data.conn.address))
        if name:
            data.conn.sni = name

    def _via_upstream(self, flow):
        """Send a request on through --upstream-proxy. HTTPS goes in a CONNECT
        tunnel to the address (an IP, as the exit node gave it; Burp makes its
        certificate from the SNI). Plain HTTP goes as a proxy request
        (absolute-form): Burp does not take plain HTTP inside CONNECT."""
        if not self.upstream or flow.response:
            return
        r = flow.request
        if r.scheme == "http":
            if r.is_http2 or r.is_http3:
                # mitmproxy would turn it into HTTP/1.1 itself and drop the
                # authority, so the proxy would get "GET /path" alone. Do it
                # here, keeping the Host the app sent (or keep_host_header's).
                host, cookies = r.host_header or r.pretty_host, r.headers.get_all("Cookie")
                r.http_version = "HTTP/1.1"
                r.headers["Host"] = host
                if len(cookies) > 1:
                    r.headers["Cookie"] = "; ".join(cookies)
                # As mitmproxy does for a converted request: one request per
                # connection (the app's HTTP/2 stream cannot reuse it, and
                # left open, a proxy that keeps them alive runs out at five).
                r.headers["Connection"] = "close"
                if "content-length" not in r.headers and r.method not in ("GET", "HEAD", "OPTIONS", "DELETE", "TRACE"):
                    r.headers["Transfer-Encoding"] = "chunked"  # a body of unknown length needs framing in HTTP/1.1
            host = r.data.host
            r.data.authority = (f"[{host}]" if ":" in host else host).encode() + f":{r.port}".encode()
            r.data.host, r.data.port = self.upstream
            flow.server_conn = connection.Server(address=self.upstream)
        else:
            flow.server_conn = connection.Server(address=(r.data.host, r.port))
            flow.server_conn.via = ("http", self.upstream)

    def _allowed(self, host):
        host = host.lower().rstrip(".")
        if host == "mitm.it":
            return False  # decrypted so iPhones can get the CA; never recorded
        return self.allow_all or any(r.match(host) for r in self.allow)

    def _passed(self, host):
        host = host.lower().rstrip(".")
        return any(r.match(host) for r in self.passing)

    def _in_scope(self, host):
        # A --pass-hosts host is not recorded as flows, even in a request riding
        # an allowed host's decrypted connection (HTTP/2 coalescing).
        return self._allowed(host) and not self._passed(host)

    def running(self):
        # Connect now, not on the first flow: reqcove waits for this hello
        # before it advertises the exit node. The writer says hello again on
        # every reconnect.
        # The SOCKS5 listener accepts only from now (mitm.py): proxyauth=any,
        # so before this addon is loaded nothing would check the password.
        serve = getattr(sys.modules.get("__main__"), "serve_socks", None)
        if serve:
            serve()
        self.put_event(self._hello())
        if ctx.options.reqcove_control and self.control_server is None:
            self.control_server = asyncio.get_running_loop().create_task(self._serve_control(ctx.options.reqcove_control))
        if ctx.options.reqcove_rules_reload and ctx.options.reqcove_rules and self.rules_watch is None:
            self.rules_watch = asyncio.get_running_loop().create_task(self._watch_rules(ctx.options.reqcove_rules))

    # Queueing: small events always go in (bounded by count); body heads need byte budget.
    def _put(self, msg, size):
        with self.lock:
            self.queued_bytes += size
        self.q.put((msg, size))

    def put_event(self, msg):
        if self.q.qsize() > 100000:
            self.dropped_events += 1
            return
        # Headers and URLs count toward the queue's byte budget too: a site can
        # send large ones.
        size = 512 + len(msg.get("url") or "") + len(msg.get("reason") or "") + len(msg.get("msg") or "") + sum(len(k) + len(v) + 64 for k, v in (msg.get("headers") or []) + (msg.get("trailers") or []))
        with self.lock:
            over = self.queued_bytes + size > 2 * self.queue_limit  # bodies give way first, at the plain limit
        if over:
            self.dropped_events += 1
            return
        self._put(msg, size)

    def put_body(self, msg):
        size = len(msg["head"]) + len(msg["encoding"]) + len(msg["note"]) + 512
        with self.lock:
            over = self.queued_bytes + size > self.queue_limit
        if over:
            self.dropped_bodies += 1
            return
        self._put(msg, size)

    def requestheaders(self, flow):
        # A Host that is no host name or address (an app's own HTTP stack can
        # send any text there) is never recorded: it would show as a host.
        if not check.is_valid_host(flow.request.pretty_host) or not self._in_scope(flow.request.pretty_host):
            # allow_hosts works per connection, so a connection to an allowed host
            # can carry requests to others (HTTP/2 coalescing). Pass them through.
            flow.metadata["reqcove_skip"] = True
            flow.request.stream = True
            if flow.request.pretty_host.lower().rstrip(".") == "mitm.it":
                return  # the CA's page: served, never recorded, and not "out of scope" either
            self.out_of_scope += 1
            self.put_event({"v": VERSION, "ev": "skip"})  # carries the count to reqcove
            # Decrypted all the same, a --pass-hosts host's too (coalesced onto an
            # allowed connection): only the upstream's CA may be trusted.
            self._via_upstream(flow)
            return
        device = _device(flow)
        if device:
            flow.comment = device  # shows the device in mitmweb
        r = flow.request
        peer = flow.client_conn.peername
        headers, note = _headers(r.headers)
        # Recorded as the app sent it: the host is checked again in reqcove,
        # and a rule may send the request to a host outside --allow-hosts.
        ev = {
            "v": VERSION, "ev": "request", "id": flow.id, "device": device, "conn": flow.client_conn.id,
            "client": f"{peer[0]}:{peer[1]}" if peer else None,
            "ts": r.timestamp_start, "method": r.method, "url": r.pretty_url,
            "host": r.pretty_host, "path": r.path, "http_version": r.http_version,
            "headers": headers, "note": note,
        }
        rules = self.rules
        if rules:
            self.flow_rules[flow.id] = rules  # the response's rules too, whatever a reload does meanwhile
            mocks = rules["mock"].candidates(flow)
            small = self._small_body(r)
            if small is None and (mocks or any(m.matches(flow) for m in rules["map_local"].replacements)):
                # HTTP/2 without a length: mitmproxy streams it only if a body
                # follows the headers (it alone knows the stream's end), and then
                # to HOLD. One that ended with them goes on to request(), as below.
                flow.metadata["reqcove_hold"] = (r.data.host, r.data.port)
                r.data.host, r.data.port = HOLD
                r.stream = True
                flow.metadata["reqcove_pending"] = ev
                return
            if mocks and small:
                # A mock may answer it: decided in request(), once the body (and a
                # GraphQL operation in it) is in. Not streamed, so buffered: at most
                # MAP_LOCAL_BODY. The event goes then, with what the rules did.
                flow.metadata["reqcove_pending"] = ev
                return
            try:
                ev["rewrites"] = self._rewrite_request(flow, rules)
                if mocks:  # a mock would need the body whole: say why none answered
                    ev["rewrites"].append("mock: skipped, request body over 1 MiB or of unknown length")
            except Exception as e:
                # A rule that fails (map_remote making a bad URL) must not let the
                # request go on unrewritten, around the rule or the upstream proxy.
                flow.response = http.Response.make(502, f"reqcove: a --rules rule failed on this request ({type(e).__name__})".encode())
                ev["rewrites"] = [f"rules failed: {type(e).__name__}"]
            if "reqcove_mapped" in flow.metadata:
                ev["mapped_url"] = flow.metadata["reqcove_mapped"]  # whatever Host says (keep_host_header)
            if ps := flow.metadata.get("reqcove_presets"):
                ev["presets"] = list(dict.fromkeys(ps))
        self.put_event(ev)
        if flow.response:
            # map_local answered. mitmproxy cannot stream a request that already
            # has a response, so its body is buffered and copied in request().
            # ponytail: that body is unbounded (body_size_limit would cap every flow, streamed or not).
            flow.metadata["reqcove_local"] = True
            return
        self._via_upstream(flow)
        r.stream = _Head(self, flow, "request", r.headers)

    def _rewrite_request(self, flow, rules, mocks=False, dry=False, op=False):
        """Apply --rules in requestheaders, before the body streams: mitmproxy's
        map_remote and map_local run in request(), after the body, too late.
        With mocks (from request(), the body in), a mock comes first. dry:
        explain_rules' made flow, never sent (op: its GraphQL operation)."""
        book = rules["mock"].book
        done = self._modify_headers(flow, flow.request.headers, "request", rules)
        if mocks and (hit := rules["mock"].answer(flow, op)):
            i, status, preset, delay = hit
            flow.metadata["reqcove_mocked"] = True
            flow.metadata["reqcove_delay"] = delay
            if preset is not None:
                flow.metadata["reqcove_preset"] = preset
            if status == "close":
                flow.metadata["reqcove_close"] = True
            # Its index, preset name and status, never its text.
            done.append(f"mock[{i}]" + (f" preset {preset}" if preset else "") + f": {status}" + (f", after {delay} ms" if delay else ""))
            return done
        if mocks or self._small_body(flow.request):  # mocks: from request(), the body is in
            rules["map_local"].request(flow)
        elif any(s.matches(flow) for s in rules["map_local"].replacements):
            # A local answer would make mitmproxy buffer the whole request body
            # (it cannot stream one that already has a response): only for small ones.
            done.append("map_local: skipped, request body over 1 MiB or of unknown length")
        if flow.response:
            done.append(f"map_local: {flow.response.status_code}")
            return done
        r = flow.request
        before, host_header = r.pretty_url, r.host_header
        # Presets that are on first, each matching one in turn as mitmproxy's
        # map_remote does, then the plain rules.
        for preset, spec in book.specs["map_remote"]:
            if book.on(preset) and spec.matches(flow):
                url = r.pretty_url
                new = re.sub(spec.subject, spec.replacement, url)
                if new != url:
                    if _origin(new) != book.entries[preset][2]["target"]:
                        # Its regex matched elsewhere than the URL's start: never
                        # somewhere other than the target shown to the user and the agent.
                        raise RuleError("a map_remote preset made a URL outside its target")
                    r.url = new
                    flow.metadata.setdefault("reqcove_presets", []).append(preset)
                    done.append(f"map_remote preset {preset}")
        mid = r.pretty_url
        rules["map_remote"].request(flow)
        if r.pretty_url != mid:
            done.append("map_remote")
        name = r.pretty_host  # after map_remote, the name it sent the request to
        if r.pretty_url != before:
            flow.metadata["reqcove_mapped"] = r.url  # map_remote's URL, before resolve changes the address
            if rules["map_remote"].keep_host_header:
                r.host_header = host_header  # Host (or :authority) as the app sent it
        name = name.lower().rstrip(".")
        hit = rules["resolve"].target(name, book)
        if hit:
            (ip, port), preset = hit
            # Only where to connect changes: not Host, nor the URL recorded
            # (the setters would rewrite Host).
            address = (ip, port or r.port)
            r.data.host, r.data.port = address
            if not dry:  # a made flow's connection never ends: its entry would stay
                self.resolve_sni[(flow.client_conn.id, address)] = name
            if preset:
                flow.metadata.setdefault("reqcove_presets", []).append(preset)
            done.append("resolve" + (f" preset {preset}" if preset else "") + f": {address[0]}:{address[1]}")
        return done

    @staticmethod
    def _small_body(r):
        """Whether a request's body is known to be at most MAP_LOCAL_BODY bytes;
        None: HTTP/2 (or 3) with no length, of a method that usually has no body,
        where only the stream's end tells."""
        cl = r.headers.get("content-length")
        if cl is not None:
            try:
                return int(cl) <= MAP_LOCAL_BODY
            except ValueError:
                return False
        # No length: a body may follow (chunked, HTTP/2) unless the method takes none.
        if r.method not in ("GET", "HEAD", "OPTIONS", "DELETE") or "transfer-encoding" in r.headers:
            return False
        return None if r.is_http2 or r.is_http3 else True  # HTTP/1: no length and no chunks is no body

    @staticmethod
    def _modify_headers(flow, headers, direction, rules):
        mh = rules["modify_headers"]
        names = [s.subject.decode(errors="replace") for s in mh.replacements if s.matches(flow)]
        mh.run(flow, headers)
        if direction == "request":  # presets change requests only (checked at load); after the plain rules, so one that is on wins
            book = rules["mock"].book
            on = [(p, s) for p, s in book.specs["modify_headers"] if book.on(p) and s.matches(flow)]
            if on:
                pre = modifyheaders.ModifyHeaders()
                pre.replacements = [s for _, s in on]
                pre.run(flow, headers)
                names += [f"{s.subject.decode(errors='replace')} (preset {p})" for p, s in on]
                flow.metadata.setdefault("reqcove_presets", []).extend(p for p, _ in on)
        # An @file is read again for each flow: one changed since it was
        # checked must not put a line break into the headers either.
        if any(BAD_IN_VALUE.search(v) for _, v in headers.fields):
            headers.fields = tuple((k, v) for k, v in headers.fields if not BAD_IN_VALUE.search(v))
            names.append("(a header with a line break dropped)")
        return [f"modify_headers {direction}: {n}" for n in dict.fromkeys(names)]  # names, never values

    async def request(self, flow):
        self._request(flow)
        # A mock's delay_ms, then its answer or fault: close. Awaited, so the
        # loop (other flows, other HTTP/2 streams) goes on meanwhile.
        if delay := flow.metadata.pop("reqcove_delay", 0):
            await asyncio.sleep(delay / 1000)
        if flow.metadata.get("reqcove_close"):
            if flow.killable:
                flow.kill()  # HTTP/1: the connection; HTTP/2: this stream
            else:  # never on to the server: the mock answered for it
                flow.response = http.Response.make(502, b"reqcove: a mock's fault: close could not close this request")

    def _request(self, flow):
        if hold := flow.metadata.pop("reqcove_hold", None):
            flow.request.data.host, flow.request.data.port = hold  # its stream ended with the headers: no body
        ev = flow.metadata.pop("reqcove_pending", None)
        if ev is not None:
            try:
                ev["rewrites"] = self._rewrite_request(flow, self.flow_rules[flow.id], mocks=True)
            except Exception as e:
                flow.response = http.Response.make(502, f"reqcove: a --rules rule failed on this request ({type(e).__name__})".encode())
                ev["rewrites"] = [f"rules failed: {type(e).__name__}"]
            if "reqcove_mapped" in flow.metadata:
                ev["mapped_url"] = flow.metadata["reqcove_mapped"]
            ev["mocked"] = bool(flow.metadata.get("reqcove_mocked"))
            if preset := flow.metadata.get("reqcove_preset"):
                ev["preset"] = preset
            ps = list(flow.metadata.get("reqcove_presets") or []) + ([preset] if preset else [])
            if ps:
                ev["presets"] = list(dict.fromkeys(ps))
            self.put_event(ev)
            if flow.response:
                flow.metadata["reqcove_local"] = True  # made here: copied whole in response()
            self._via_upstream(flow)  # none for a made response
            self._copy_whole(flow, "request", flow.request)  # buffered, not streamed
        elif flow.metadata.get("reqcove_local"):
            self._copy_whole(flow, "request", flow.request)
        self._give_web(flow, "request", flow.request)

    def _give_web(self, flow, direction, msg):
        """--web: the streamed body, kept whole, goes into the flow mitmweb shows
        (it was already sent on: this is the record only)."""
        body = self.kept.pop((flow.id, direction), None)
        if body is not None and msg is not None:
            msg.raw_content = body

    def _web_done(self, flow):
        """--web: mitmweb keeps every flow; past WEB_MAX_FLOWS, or WEB_MAX_BYTES of
        kept bodies, the oldest go (as Reqcove's own records do)."""
        self.kept.pop((flow.id, "request"), None)
        self.kept.pop((flow.id, "response"), None)
        if not self.web_keep:
            return
        size = 0
        for m in (getattr(flow, "request", None), getattr(flow, "response", None)):  # a TCP flow has neither
            if m is not None and m.raw_content:
                size += len(m.raw_content)
        self.web_flows.append((flow, size))
        self.web_bytes += size
        old = []
        while len(self.web_flows) > ctx.options.reqcove_web_max_flows or self.web_bytes > WEB_MAX_BYTES:
            f, n = self.web_flows.popleft()
            self.web_bytes -= n
            old.append(f)
        if old:
            try:
                ctx.master.commands.call("view.flows.remove", old)
            except Exception:
                pass

    def _copy_whole(self, flow, direction, msg):
        h = _Head(self, flow, direction, msg.headers)
        h.keep = None  # mitmweb holds a made message whole: nothing to keep for it (kept, it would never be freed)
        h(msg.raw_content or b"")
        h(b"")

    def responseheaders(self, flow):
        if flow.metadata.get("reqcove_skip"):
            flow.response.stream = True
            return
        s = flow.response
        rules = self.flow_rules.get(flow.id)
        rewrites = self._modify_headers(flow, s.headers, "response", rules) if rules else []
        headers, note = _headers(s.headers)
        self.put_event({
            "v": VERSION, "ev": "response", "id": flow.id, "ts": s.timestamp_start,
            "status": s.status_code, "reason": s.reason[:SHORT], "http_version": s.http_version[:SHORT],
            "headers": headers, "note": note, "rewrites": rewrites,  # as the app receives them
        })
        if flow.metadata.get("reqcove_local"):
            return  # mitmproxy sends a made response whole, never through .stream
        s.stream = _Head(self, flow, "response", s.headers)

    def response(self, flow):
        self.flow_rules.pop(flow.id, None)
        self._give_web(flow, "response", flow.response)
        self._web_done(flow)
        if flow.metadata.get("reqcove_skip"):
            return
        if flow.metadata.get("reqcove_local"):
            self._copy_whole(flow, "response", flow.response)
        done = {"v": VERSION, "ev": "done", "id": flow.id, "ts_end": flow.response.timestamp_end}
        if flow.response.trailers:  # HTTP/2's, set before this hook also when streamed: gRPC's status
            done["trailers"], done["note"] = _headers(flow.response.trailers)
        self.put_event(done)

    def error(self, flow):
        self.flow_rules.pop(flow.id, None)
        self._web_done(flow)
        if flow.metadata.get("reqcove_skip"):
            return
        if ev := flow.metadata.pop("reqcove_pending", None):
            self.put_event(ev)  # it failed before its body was in: recorded as it came
        for m in (flow.request, flow.response):  # a body cut off: the head that came, and its size
            if m is not None and isinstance(m.stream, _Head):
                m.stream.flush()
        msg = flow.error.msg[:SHORT]
        if flow.metadata.get("reqcove_close"):
            msg = "closed by a mock (fault: close)" + (f", preset {flow.metadata['reqcove_preset']}" if flow.metadata.get("reqcove_preset") else "")
        self.put_event({"v": VERSION, "ev": "error", "id": flow.id, "msg": msg})

    def websocket_message(self, flow):
        if flow.metadata.get("reqcove_skip"):
            flow.websocket.messages.clear()
            return
        m = flow.websocket.messages[-1]
        ev = {
            "v": VERSION, "ev": "ws", "id": flow.id, "from_client": m.from_client,
            "size": len(m.content), "text": m.is_text, "ts": m.timestamp,
        }
        if m.is_text:
            # A token bucket per socket: past it a message keeps its count, not
            # its head, so a flood cannot fill the one pipeline into reqcove.
            tokens, last = flow.metadata.get("reqcove_ws_bucket", (WS_BURST, m.timestamp))
            tokens = min(WS_BURST, tokens + max(m.timestamp - last, 0) * WS_RATE)
            if tokens >= 1:
                tokens -= 1
                ev["head"] = m.content[:WS_HEAD]  # never m.text: it decodes the whole message
                ev["truncated"] = len(m.content) > WS_HEAD
            else:
                ev["capped"] = True
            flow.metadata["reqcove_ws_bucket"] = (tokens, m.timestamp)
        flow.websocket.messages.clear()  # mitmproxy would keep every message for the connection's life
        if "head" not in ev:
            self.put_event(ev)
            return
        size = len(ev["head"]) + 512
        with self.lock:
            over = self.queued_bytes + size > self.queue_limit
        if over or self.q.qsize() > 100000:  # heads give way first, as bodies do: the message still counts
            del ev["head"], ev["truncated"]
            ev["capped"] = True
            self.put_event(ev)
            return
        self._put(ev, size)

    def websocket_end(self, flow):
        if flow.metadata.get("reqcove_skip"):
            return
        ws = flow.websocket
        self.put_event({
            "v": VERSION, "ev": "ws_end", "id": flow.id, "ts_end": ws.timestamp_end or time.time(),
            "code": ws.close_code or 0, "by_client": bool(ws.closed_by_client),
            "reason": (ws.close_reason or "")[:SHORT],  # the peer's text: masked in reqcove
        })

    def tcp_message(self, flow):
        p = flow.metadata.get("reqcove_pass")
        if p is not None:
            m = flow.messages[-1]
            p["up" if m.from_client else "down"] += len(m.content)
        flow.messages.clear()  # same for raw TCP

    def next_layer(self, nl):
        """A --pass-hosts host is carried as raw TCP, undecrypted: a TCPLayer that
        keeps a flow (unlike ignore_connection), so its hooks fire and its bytes
        are counted. Only for allowed hosts, and not ones mitmproxy ignores
        (Apple's): those it passes through itself, unrecorded. Script addons run
        before mitmproxy's own NextLayer (12.3.1), which leaves a layer chosen
        here; a change of that order fails TestPassHosts."""
        if not self.passing or nl.layer is not None or len(nl.context.layers) != 1:
            return
        data = nl.data_client()
        if not starts_like_tls_record(data):
            return
        try:
            hello = parse_client_hello(data)
        except ValueError:
            return
        if hello is None:
            return  # more to come: mitmproxy asks again (it waits, as it has ignore_hosts: Apple's, always)
        ip, port = nl.context.server.address or ("", 443)
        # The name the client sent, or without one (an app dialing an address),
        # the address: what --pass-hosts names, and what status suggests.
        sni = (hello.sni or ip).lower().rstrip(".")
        if not sni or not (self._allowed(sni) and self._passed(sni)):
            return
        # mitmproxy's own ignore_hosts (Apple's) come first, by name or address.
        if any(re.search(p, f"{sni}:{port}") or re.search(p, f"{ip}:{port}") for p in ctx.options.ignore_hosts):
            return
        layer = tcp_layer.TCPLayer(nl.context, ignore=False)
        layer.flow.metadata["reqcove_pass"] = {
            "device": self.conn_device.get(nl.context.client.id), "sni": sni, "up": 0, "down": 0,
            # The client's own bytes: printable ASCII only, cut (protocol ids are short).
            "alpn": ["".join(c if " " <= c <= "~" else "?" for c in a.decode("latin-1"))[:32] for a in hello.alpn_protocols[:8]],
        }
        nl.layer = layer

    def tcp_start(self, flow):
        p = flow.metadata.get("reqcove_pass")
        if p is None:
            return
        s = flow.server_conn
        addr = s.peername or s.address
        self.put_event({
            "v": VERSION, "ev": "pass_open", "conn": flow.client_conn.id, "device": p["device"],
            "sni": p["sni"], "alpn": p["alpn"], "server": f"{addr[0]}:{addr[1]}" if addr else None,
            "ts": flow.client_conn.timestamp_start or time.time(),
        })

    def tcp_end(self, flow):
        self._pass_closed(flow)

    def tcp_error(self, flow):
        self._pass_closed(flow)

    def _pass_closed(self, flow):
        p = flow.metadata.get("reqcove_pass")
        if p is None:
            return
        self.put_event({
            "v": VERSION, "ev": "pass_close", "conn": flow.client_conn.id,
            "ts_end": time.time(), "up": p["up"], "down": p["down"],
            "msg": (flow.error.msg if flow.error else "")[:SHORT],  # never connected, say
        })
        self._web_done(flow)

    def tls_failed_client(self, data):
        peer = data.context.client.peername
        self.put_event({
            "v": VERSION, "ev": "tls_failed", "conn": data.context.client.id, "ts": time.time(),
            "device": self.conn_device.get(data.context.client.id),
            "client": f"{peer[0]}:{peer[1]}" if peer else None,
            "sni": data.context.client.sni, "msg": str(data.conn.error or "")[:SHORT],
            # without SNI (an IP address dialed directly), the destination
            "host": data.context.server.address[0] if data.context.server.address else None,
        })

    def _hello(self):
        return {
            "v": VERSION, "ev": "hello", "mitmproxy": mitmproxy_version.VERSION,
            "python": sys.version.split()[0], "brotli": getattr(brotli, "__version__", "?"),
            "brotli_decode": BROTLI_OK, "zstd_decode": zstd is not None,
            "dropped_bodies": self.dropped_bodies, "dropped_events": self.dropped_events,
            **self._rules_info(),
            "upstream": "%s:%d" % self.upstream if self.upstream else "",
        }

    def _encode(self, msg):
        if "head" in msg:
            msg["head"] = base64.b64encode(msg["head"]).decode()
        msg["dropped_bodies"] = self.dropped_bodies
        msg["dropped_events"] = self.dropped_events
        msg["out_of_scope"] = self.out_of_scope
        return (json.dumps(msg) + "\n").encode()

    def _writer(self):
        sock = None
        while True:
            msg, size = self.q.get()
            with self.lock:
                self.queued_bytes -= size
            try:
                if sock is None:
                    if not self.path:
                        raise OSError("no socket configured")
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.connect(self.path)
                    if msg.get("ev") != "hello":
                        sock.sendall(self._encode(self._hello()))  # on every reconnect
                sock.sendall(self._encode(msg))
            except OSError:
                if msg.get("ev") == "body":
                    self.dropped_bodies += 1
                else:
                    self.dropped_events += 1
                if sock is not None:
                    sock.close()
                sock = None


addons = [Reqcove()]
