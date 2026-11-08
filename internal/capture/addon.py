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

import base64
import hmac
import json
import queue
import re
import socket
import sys
import threading
import time
import zlib
from pathlib import Path

import brotli
import ruamel.yaml  # mitmproxy's own dependency
from mitmproxy import ctx
from mitmproxy import version as mitmproxy_version
from mitmproxy.addons import maplocal, mapremote, modifyheaders
from mitmproxy.utils import strutils
from mitmproxy.utils.spec import parse_spec

try:  # Python 3.14+; mitmproxy also runs on 3.12/3.13
    from compression import zstd
except ImportError:
    zstd = None

VERSION = 2
FLUSH_SECONDS = 1.0  # send a partial head this often while a body trickles (SSE)


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


def _headers(h):
    """The headers as [name, value] pairs (repeated Set-Cookie kept), bounded:
    a site can send many or huge ones, and they are queued and kept."""
    out, total = [], 0
    for k, v in h.items(multi=True):
        if len(out) == MAX_HEADERS:
            out.append(["X-Reqcove-Note", "more headers not recorded"])
            break
        room = MAX_HEADER_BYTES - total - len(k)
        if room <= 0:
            out.append(["X-Reqcove-Note", "more header bytes not recorded"])
            break
        if len(v) > room:
            v = v[:room] + " [cut]"
        out.append([k, v])
        total += len(k) + len(v)
    return out


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
            raise ValueError("cannot decode " + enc)
        self.raw_deflate_tried = False

    def feed(self, data, limit):
        if self.d is None:
            return data[:limit]
        if self.enc == "br":
            return self.d.process(data, output_buffer_limit=limit)
        if self.enc == "zstd":
            return self.d.decompress(data, max_length=limit)
        try:
            return self.d.decompress(data, limit)
        except zlib.error:
            if self.enc == "deflate" and not self.raw_deflate_tried:
                self.raw_deflate_tried = True  # some servers send raw deflate
                self.d = zlib.decompressobj(-15)
                return self.d.decompress(data, limit)
            raise


class _Head:
    """The stream callable for one body: pass chunks through, copy the head."""

    def __init__(self, addon, flow, direction, headers):
        self.addon, self.flow_id, self.dir = addon, flow.id, direction
        self.limit = addon.head_limit
        self.head = bytearray()
        self.size = 0  # bytes on the wire
        self.truncated = False
        self.decoding = True
        self.encoding = headers.get("content-encoding", "").strip().lower()
        self.note = ""
        self.sent_len = -1
        self.last_flush = time.monotonic()
        try:
            if "," in self.encoding:
                raise ValueError("chained content-encoding")
            self.dec = _Decoder(self.encoding)
        except Exception as e:
            self.dec, self.note = None, str(e)  # copy the head as it is on the wire

    def __call__(self, data):
        try:
            self.size += len(data)
            room = self.limit - len(self.head)
            if data and room > 0 and self.decoding:
                try:
                    out = self.dec.feed(data, room) if self.dec else data[:room]
                    self.head += out[:room]
                except Exception as e:
                    self.decoding, self.note = False, "decode error: " + str(e)
                if len(self.head) >= self.limit:
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

    def _send(self, final=False):
        self.last_flush = time.monotonic()
        if len(self.head) == self.sent_len and not final:
            return
        self.sent_len = len(self.head)
        self.addon.put_body({
            "v": VERSION, "ev": "body", "id": self.flow_id, "dir": self.dir,
            "head": bytes(self.head), "size": self.size, "final": final,
            "truncated": self.truncated,
            # head is the decoded body (or identity); false means wire bytes as received
            "decoded": self.dec is not None and not self.note,
            "encoding": self.encoding, "note": self.note,
        })


RULE_KINDS = ("map_remote", "map_local", "modify_headers")
MAP_LOCAL_BODY = 1 << 20  # map_local answers only requests whose body is known to be this small


def _parse_rule(kind, spec, base):
    """One rule in mitmproxy's syntax; files are relative to the rules file."""
    if kind == "map_remote":
        return mapremote.parse_map_remote_spec(spec)
    flt, subject, replacement = parse_spec(spec)
    if kind == "map_local":
        re.compile(subject)
        path = (base / Path(replacement).expanduser()).resolve(strict=True)
        return maplocal.MapLocalSpec(flt, subject, path)
    if replacement.startswith("@"):
        replacement = "@" + str(base / Path(replacement[1:]).expanduser())
    rule = modifyheaders.ModifySpec(flt, strutils.escaped_str_to_bytes(subject), replacement)
    rule.read_replacement()  # a missing @file fails now, not on the first flow
    return rule


def load_rules(path):
    """The --rules file as mitmproxy's own rule addons, which reqcove calls
    from its hooks (so rules never touch skipped flows or mitm.it).

    Errors name the rule by kind and index, never its text: modify_headers
    rules often carry tokens."""
    data = ruamel.yaml.YAML(typ="safe", pure=True).load(Path(path).read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError("the file must map map_remote, map_local and modify_headers to lists")
    extra = sorted(str(k) for k in data if k not in RULE_KINDS)
    if extra:
        raise ValueError(f"only {', '.join(RULE_KINDS)} are allowed, not {', '.join(extra)}")
    addons = {"map_remote": mapremote.MapRemote(), "map_local": maplocal.MapLocal(), "modify_headers": modifyheaders.ModifyHeaders()}
    for kind, addon in addons.items():
        specs = data.get(kind) or []
        if not isinstance(specs, list) or not all(isinstance(s, str) for s in specs):
            raise ValueError(f"{kind} must be a list of strings")
        for i, spec in enumerate(specs):
            try:
                addon.replacements.append(_parse_rule(kind, spec, Path(path).parent))
            except Exception as e:
                # map_remote and map_local errors quote a regex or a path; a
                # modify_headers error could quote the value, so only its kind.
                why = f"{type(e).__name__}: {e}" if kind != "modify_headers" else type(e).__name__
                raise ValueError(f"{kind}[{i}]: {why}") from None
    return addons


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
        self.conn_device = {}  # client connection id -> device (SOCKS5 user), while connected
        self.rules = None  # load_rules(), or None without --rules
        self.rules_error = ""
        threading.Thread(target=self._writer, daemon=True).start()

    def load(self, loader):
        loader.add_option("reqcove_socket", str, "", "Unix socket of `reqcove run`.")
        loader.add_option("reqcove_body_head", int, 64 * 1024, "Bytes of each decoded body sent to reqcove.")
        loader.add_option("reqcove_queue_bytes", int, 32 << 20, "Byte budget of the queue to reqcove.")
        loader.add_option("reqcove_secret_file", str, "", "File holding the SOCKS5 password reqcove uses.")
        loader.add_option("reqcove_allow_hosts", str, "{}", "Hosts recorded, as JSON from reqcove.")
        loader.add_option("reqcove_rules", str, "", "The --rules file.")

    def configure(self, updated):
        self.path = ctx.options.reqcove_socket
        self.head_limit = ctx.options.reqcove_body_head
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
        if "reqcove_rules" in updated:
            self.rules, self.rules_error = None, ""
            if ctx.options.reqcove_rules:
                try:
                    self.rules = load_rules(ctx.options.reqcove_rules)
                except Exception as e:  # reqcove reads it from the hello and refuses to start
                    self.rules_error = str(e) if isinstance(e, ValueError) else type(e).__name__
                    if mark := getattr(e, "problem_mark", None):  # YAML syntax: where, not what
                        self.rules_error += f" at line {mark.line + 1}"

    def socks5_auth(self, data):
        # mitmproxy's proxyauth=any has already accepted any user and password;
        # only reqcove, which holds the secret, may use this listener.
        if self.secret is None or not hmac.compare_digest(data.password.encode(), self.secret.encode()):
            data.valid = False
        else:
            self.conn_device[data.client_conn.id] = data.username  # for TLS failures, which have no flow

    def client_disconnected(self, client):
        self.conn_device.pop(client.id, None)

    def _in_scope(self, host):
        host = host.lower().rstrip(".")
        if host == "mitm.it":
            return False  # decrypted so iPhones can get the CA; never recorded
        return self.allow_all or any(r.match(host) for r in self.allow)

    def running(self):
        # Connect now, not on the first flow: reqcove waits for this hello
        # before it advertises the exit node. The writer says hello again on
        # every reconnect.
        self.put_event(self._hello())

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
        size = 512 + len(msg.get("url") or "") + len(msg.get("reason") or "") + sum(len(k) + len(v) + 64 for k, v in msg.get("headers") or [])
        with self.lock:
            over = self.queued_bytes + size > 2 * self.queue_limit  # bodies give way first, at the plain limit
        if over:
            self.dropped_events += 1
            return
        self._put(msg, size)

    def put_body(self, msg):
        size = len(msg["head"]) + 512
        with self.lock:
            over = self.queued_bytes + size > self.queue_limit
        if over:
            self.dropped_bodies += 1
            return
        self._put(msg, size)

    def requestheaders(self, flow):
        if not self._in_scope(flow.request.pretty_host):
            # allow_hosts works per connection, so a connection to an allowed host
            # can carry requests to others (HTTP/2 coalescing). Pass them through.
            flow.metadata["reqcove_skip"] = True
            flow.request.stream = True
            if flow.request.pretty_host.lower().rstrip(".") == "mitm.it":
                return  # the CA's page: served, never recorded, and not "out of scope" either
            self.out_of_scope += 1
            self.put_event({"v": VERSION, "ev": "skip"})  # carries the count to reqcove
            return
        device = _device(flow)
        if device:
            flow.comment = device  # shows the device in mitmweb
        r = flow.request
        peer = flow.client_conn.peername
        # Recorded as the app sent it: the host is checked again in reqcove,
        # and a rule may send the request to a host outside --allow-hosts.
        ev = {
            "v": VERSION, "ev": "request", "id": flow.id, "device": device, "conn": flow.client_conn.id,
            "client": f"{peer[0]}:{peer[1]}" if peer else None,
            "ts": r.timestamp_start, "method": r.method, "url": r.pretty_url,
            "host": r.pretty_host, "path": r.path, "http_version": r.http_version,
            "headers": _headers(r.headers),
        }
        if self.rules:
            ev["rewrites"] = self._rewrite_request(flow)
            if r.pretty_url != ev["url"]:
                ev["mapped_url"] = r.pretty_url
        self.put_event(ev)
        if flow.response:
            # map_local answered. mitmproxy cannot stream a request that already
            # has a response, so its body is buffered and copied in request().
            # ponytail: that body is unbounded (body_size_limit would cap every flow, streamed or not).
            flow.metadata["reqcove_local"] = True
            return
        r.stream = _Head(self, flow, "request", r.headers)

    def _rewrite_request(self, flow):
        """Apply --rules in requestheaders, before the body streams: mitmproxy's
        map_remote and map_local run in request(), after the body, too late."""
        done = self._modify_headers(flow, flow.request.headers, "request")
        if self._small_body(flow.request):
            self.rules["map_local"].request(flow)
        elif any(s.matches(flow) for s in self.rules["map_local"].replacements):
            # A local answer would make mitmproxy buffer the whole request body
            # (it cannot stream one that already has a response): only for small ones.
            done.append("map_local: skipped, request body over 1 MiB or of unknown length")
        if flow.response:
            done.append(f"map_local: {flow.response.status_code}")
            return done
        before = flow.request.pretty_url
        self.rules["map_remote"].request(flow)
        if flow.request.pretty_url != before:
            done.append("map_remote")
        return done

    @staticmethod
    def _small_body(r):
        """Whether a request's body is known to be at most MAP_LOCAL_BODY bytes."""
        cl = r.headers.get("content-length")
        if cl is not None:
            try:
                return int(cl) <= MAP_LOCAL_BODY
            except ValueError:
                return False
        # No length: a body may follow (chunked, HTTP/2) unless the method takes none.
        return r.method in ("GET", "HEAD", "OPTIONS", "DELETE") and "transfer-encoding" not in r.headers

    def _modify_headers(self, flow, headers, direction):
        mh = self.rules["modify_headers"]
        names = [s.subject.decode(errors="replace") for s in mh.replacements if s.matches(flow)]
        mh.run(flow, headers)
        return [f"modify_headers {direction}: {n}" for n in dict.fromkeys(names)]  # names, never values

    def request(self, flow):
        if flow.metadata.get("reqcove_local"):
            self._copy_whole(flow, "request", flow.request)

    def _copy_whole(self, flow, direction, msg):
        h = _Head(self, flow, direction, msg.headers)
        h(msg.raw_content or b"")
        h(b"")

    def responseheaders(self, flow):
        if flow.metadata.get("reqcove_skip"):
            flow.response.stream = True
            return
        s = flow.response
        rewrites = self._modify_headers(flow, s.headers, "response") if self.rules else []
        self.put_event({
            "v": VERSION, "ev": "response", "id": flow.id, "ts": s.timestamp_start,
            "status": s.status_code, "reason": s.reason, "http_version": s.http_version,
            "headers": _headers(s.headers), "rewrites": rewrites,  # as the app receives them
        })
        if flow.metadata.get("reqcove_local"):
            return  # mitmproxy sends a made response whole, never through .stream
        s.stream = _Head(self, flow, "response", s.headers)

    def response(self, flow):
        if flow.metadata.get("reqcove_skip"):
            return
        if flow.metadata.get("reqcove_local"):
            self._copy_whole(flow, "response", flow.response)
        self.put_event({"v": VERSION, "ev": "done", "id": flow.id, "ts_end": flow.response.timestamp_end})

    def error(self, flow):
        if flow.metadata.get("reqcove_skip"):
            return
        self.put_event({"v": VERSION, "ev": "error", "id": flow.id, "msg": flow.error.msg})

    def websocket_message(self, flow):
        if flow.metadata.get("reqcove_skip"):
            flow.websocket.messages.clear()
            return
        m = flow.websocket.messages[-1]
        self.put_event({
            "v": VERSION, "ev": "ws", "id": flow.id, "from_client": m.from_client,
            "size": len(m.content), "text": m.is_text,
        })
        flow.websocket.messages.clear()  # mitmproxy would keep every message for the connection's life

    def tcp_message(self, flow):
        flow.messages.clear()  # same for raw TCP

    def tls_failed_client(self, data):
        peer = data.context.client.peername
        self.put_event({
            "v": VERSION, "ev": "tls_failed", "conn": data.context.client.id, "ts": time.time(),
            "device": self.conn_device.get(data.context.client.id),
            "client": f"{peer[0]}:{peer[1]}" if peer else None,
            "sni": data.context.client.sni, "msg": str(data.conn.error or ""),
            # without SNI (an IP address dialed directly), the destination
            "host": data.context.server.address[0] if data.context.server.address else None,
        })

    def _hello(self):
        return {
            "v": VERSION, "ev": "hello", "mitmproxy": mitmproxy_version.VERSION,
            "python": sys.version.split()[0], "brotli": getattr(brotli, "__version__", "?"),
            "brotli_decode": BROTLI_OK, "zstd_decode": zstd is not None,
            "dropped_bodies": self.dropped_bodies, "dropped_events": self.dropped_events,
            "rules": {k: len(a.replacements) for k, a in self.rules.items()} if self.rules else None,
            "rules_error": self.rules_error,
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
