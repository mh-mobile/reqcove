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
import json
import queue
import socket
import sys
import threading
import time
import zlib

import brotli
from mitmproxy import ctx
from mitmproxy import version as mitmproxy_version

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


def _headers(h):
    return [[k, v] for k, v in h.items(multi=True)]  # keeps repeated Set-Cookie


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
        threading.Thread(target=self._writer, daemon=True).start()

    def load(self, loader):
        loader.add_option("reqcove_socket", str, "", "Unix socket of `reqcove run`.")
        loader.add_option("reqcove_body_head", int, 64 * 1024, "Bytes of each decoded body sent to reqcove.")
        loader.add_option("reqcove_queue_bytes", int, 32 << 20, "Byte budget of the queue to reqcove.")

    def configure(self, updated):
        self.path = ctx.options.reqcove_socket
        self.head_limit = ctx.options.reqcove_body_head
        self.queue_limit = ctx.options.reqcove_queue_bytes

    # Queueing: small events always go in (bounded by count); body heads need byte budget.
    def _put(self, msg, size):
        with self.lock:
            self.queued_bytes += size
        self.q.put((msg, size))

    def put_event(self, msg):
        if self.q.qsize() > 100000:
            self.dropped_events += 1
            return
        self._put(msg, 512)

    def put_body(self, msg):
        size = len(msg["head"]) + 512
        with self.lock:
            over = self.queued_bytes + size > self.queue_limit
        if over:
            self.dropped_bodies += 1
            return
        self._put(msg, size)

    def requestheaders(self, flow):
        device = _device(flow)
        if device:
            flow.comment = device  # shows the device in mitmweb
        r = flow.request
        peer = flow.client_conn.peername
        self.put_event({
            "v": VERSION, "ev": "request", "id": flow.id, "device": device,
            "client": f"{peer[0]}:{peer[1]}" if peer else None,
            "ts": r.timestamp_start, "method": r.method, "url": r.pretty_url,
            "host": r.pretty_host, "path": r.path, "http_version": r.http_version,
            "headers": _headers(r.headers),
        })
        r.stream = _Head(self, flow, "request", r.headers)

    def responseheaders(self, flow):
        s = flow.response
        self.put_event({
            "v": VERSION, "ev": "response", "id": flow.id, "ts": s.timestamp_start,
            "status": s.status_code, "reason": s.reason, "http_version": s.http_version,
            "headers": _headers(s.headers),
        })
        s.stream = _Head(self, flow, "response", s.headers)

    def response(self, flow):
        self.put_event({"v": VERSION, "ev": "done", "id": flow.id, "ts_end": flow.response.timestamp_end})

    def error(self, flow):
        self.put_event({"v": VERSION, "ev": "error", "id": flow.id, "msg": flow.error.msg})

    def websocket_message(self, flow):
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
            "v": VERSION, "ev": "tls_failed", "conn": data.context.client.id,
            "client": f"{peer[0]}:{peer[1]}" if peer else None,
            "sni": data.context.client.sni, "msg": str(data.conn.error or ""),
        })

    def _hello(self):
        return {
            "v": VERSION, "ev": "hello", "mitmproxy": mitmproxy_version.VERSION,
            "python": sys.version.split()[0], "brotli": getattr(brotli, "__version__", "?"),
            "brotli_decode": BROTLI_OK, "zstd_decode": zstd is not None,
            "dropped_bodies": self.dropped_bodies, "dropped_events": self.dropped_events,
        }

    def _encode(self, msg):
        if "head" in msg:
            msg["head"] = base64.b64encode(msg["head"]).decode()
        msg["dropped_bodies"] = self.dropped_bodies
        msg["dropped_events"] = self.dropped_events
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
                    sock.sendall(self._encode(self._hello()))  # on every (re)connect
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
