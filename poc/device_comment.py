"""mitmproxy addon for the reqcove PoC: show the device name in mitmweb.

reqcove passes the device name as the SOCKS5 user name, and mitmproxy's
proxyauth (with proxyauth=any) puts (user, password) in flow.metadata.
requestheaders runs before the body ends, so long-lived requests such as
LINE's push channel get the name too. ProxyAuth is a built-in addon and
runs before scripts, so its metadata is already set here.
"""


def requestheaders(flow):
    auth = flow.metadata.get("proxyauth")
    if auth:
        flow.comment = auth[0]
