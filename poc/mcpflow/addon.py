"""mitmproxy addon for reqcove: send each flow to reqcove over a Unix socket.

Embedded in the reqcove binary and loaded with -s. Uses only the standard
library and mitmproxy itself, so it needs no `uv tool install --with`.

Hooks run on mitmproxy's event loop, so they only copy what is needed
(strings and references to immutable bytes) onto a bounded queue. A daemon
thread decodes bodies, encodes JSON lines and writes them to the socket.
If the queue is full or reqcove is not listening, events are dropped and
counted; proxying never waits for reqcove.
"""

import base64
import json
import queue
import socket
import threading

from mitmproxy import ctx
from mitmproxy.net import encoding

VERSION = 1
MAX_BODY = 1 << 20  # bytes of each body sent to reqcove; the rest is cut off


def _device(flow):
    auth = flow.metadata.get("proxyauth")  # (user, password) from proxyauth=any
    return auth[0] if auth else None


def _headers(h):
    return [[k, v] for k, v in h.items(multi=True)]  # keeps repeated Set-Cookie


class Reqcove:
    def __init__(self):
        self.q = queue.Queue(maxsize=10000)
        self.path = ""
        self.dropped = 0
        threading.Thread(target=self._writer, daemon=True).start()

    def load(self, loader):
        loader.add_option("reqcove_socket", str, "", "Unix socket of `reqcove run`.")

    def configure(self, updated):
        if "reqcove_socket" in updated:
            self.path = ctx.options.reqcove_socket

    def _put(self, msg):
        try:
            self.q.put_nowait(msg)
        except queue.Full:
            self.dropped += 1

    def requestheaders(self, flow):
        device = _device(flow)
        if device:
            flow.comment = device  # shows the device in mitmweb
        r = flow.request
        peer = flow.client_conn.peername
        self._put({
            "v": VERSION, "ev": "request", "id": flow.id, "device": device,
            "client": f"{peer[0]}:{peer[1]}" if peer else None,
            "ts": r.timestamp_start, "method": r.method, "url": r.pretty_url,
            "host": r.pretty_host, "path": r.path, "http_version": r.http_version,
            "headers": _headers(r.headers),
        })

    def response(self, flow):
        r, s = flow.request, flow.response
        self._put({
            "v": VERSION, "ev": "response", "id": flow.id,
            "ts_end": s.timestamp_end, "status": s.status_code, "reason": s.reason,
            "headers": _headers(s.headers),
            "req_body": (r.raw_content, r.headers.get("content-encoding", "")),
            "body": (s.raw_content, s.headers.get("content-encoding", "")),
        })

    def error(self, flow):
        self._put({"v": VERSION, "ev": "error", "id": flow.id, "msg": flow.error.msg})

    def _encode(self, msg):
        for key in ("req_body", "body"):
            if key not in msg:
                continue
            raw, enc = msg.pop(key)
            data = raw or b""
            if data and enc:
                try:
                    data = encoding.decode(data, enc)
                except Exception:
                    pass  # keep the encoded bytes
            msg[key + "_size"] = len(data)
            msg[key + "_truncated"] = len(data) > MAX_BODY
            msg[key] = base64.b64encode(data[:MAX_BODY]).decode()
        if self.dropped:
            msg["dropped"] = self.dropped
        return (json.dumps(msg) + "\n").encode()

    def _writer(self):
        sock = None
        while True:
            msg = self.q.get()
            try:
                line = self._encode(msg)
                if sock is None:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.connect(self.path)
                sock.sendall(line)
            except OSError:
                self.dropped += 1
                if sock is not None:
                    sock.close()
                sock = None


addons = [Reqcove()]
