# /// script
# requires-python = ">=3.14"
# dependencies = ["mitmproxy==12.3.1"]
# [tool.uv]
# exclude-newer = "2026-11-14T00:00:00Z"
# override-dependencies = ["tornado>=6.6.1"]  # mitmproxy 12.3.1 caps it at 6.5.10, which has CVE-2026-116577 and -115927 (mitmweb); 6.6 has CVE-2026-126347
# ///
"""Reqcove's launcher for mitmproxy, from mitm.py.lock: `uv run --locked
--script` installs exactly the files the lock names, their hashes checked.
The first argument is the tool: mitmdump, mitmweb, or python (-c CODE ARGS).
Update with `uv lock --script mitm.py --upgrade-package mitmproxy` after
changing the version and the date above (and capture.LockedMitmSpec)."""
import sys

tool = sys.argv.pop(1)
if tool == "python":  # python -c CODE ARGS…, as python itself takes them
    code = sys.argv[2]
    sys.argv = ["-c"] + sys.argv[3:]
    exec(compile(code, "<reqcove>", "exec"), {"__name__": "__main__"})
    sys.exit(0)
sys.argv[0] = tool


def serve_inherited_socks():
    """reqcove binds the SOCKS5 port once and hands the listening socket to
    each mitmdump (fd REQCOVE_SOCKS_FD), so the port is never free while
    mitmdump restarts. mitmproxy (12.3.1) has no option for that: it binds
    with asyncio.start_server(handler, host, port), which for that address
    makes a server on the inherited socket instead. Done here, not in the
    addon: mitmproxy loads -s scripts after it binds. Were it missed (another
    mitmproxy), mitmproxy's own bind fails, the port being held, and it
    exits before the addon's hello: never ready, nothing sent to it.

    The server does not accept until the addon's running() calls serve_socks:
    mitmproxy runs with proxyauth=any and only the addon checks the password,
    so a connection queued while mitmdump was down must not be read first."""
    import asyncio
    import os
    import socket

    fd = os.environ.get("REQCOVE_SOCKS_FD")
    if not fd:
        return
    fd = int(fd)
    with socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM) as s:
        addr = s.getsockname()[:2]
    start = asyncio.start_server
    waiting = []  # servers made before serve_socks; once it ran, None: serve at once

    async def start_server(cb, host=None, port=None, **kw):
        if (host, port) != addr:
            return await start(cb, host, port, **kw)
        # fromfd dups: mitmproxy may close and reopen its servers
        srv = await start(cb, sock=socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM), start_serving=waiting is None, **kw)
        if waiting is not None:
            waiting.append(srv)
        return srv

    def serve_socks():
        nonlocal waiting
        for srv in waiting or []:
            if not srv.is_serving() and srv.sockets:  # not one mitmproxy closed since
                asyncio.get_running_loop().create_task(srv.start_serving())
        waiting = None

    asyncio.start_server = start_server
    globals()["serve_socks"] = serve_socks  # the addon finds it in __main__


serve_inherited_socks()
from mitmproxy.tools import main  # noqa: E402

sys.exit({"mitmdump": main.mitmdump, "mitmweb": main.mitmweb}[tool]())
