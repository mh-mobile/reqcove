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
from mitmproxy.tools import main  # noqa: E402

sys.exit({"mitmdump": main.mitmdump, "mitmweb": main.mitmweb}[tool]())
