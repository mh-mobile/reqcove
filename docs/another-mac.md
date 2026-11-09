# Another Mac through Reqcove's exit node

[日本語](another-mac.ja.md)

Another Mac (a second MacBook, say) can use Reqcove's exit node as an iPhone
does: its HTTP(S) to the `--allow-hosts` hosts is recorded, its iOS Simulator's
too. Not tried yet: these steps come from how the exit node works.

## 1. On the Mac running Reqcove: add it to `--device`

```sh
reqcove run --device iphone --device macbook-sub --allow-hosts api.example.com --ui
```

`macbook-sub` is that Mac's machine name on the tailnet (`tailscale status`
lists them). Reqcove carries only the `--device` devices' traffic.

## 2. On the other Mac: choose the exit node

- The Tailscale menu bar icon › Exit Node › `reqcove`, or
- `tailscale set --exit-node=reqcove` (add `--exit-node-allow-lan-access=true`
  to keep reaching your LAN, a printer say, directly).

## 3. To see HTTPS: trust Reqcove's CA on that Mac

With the exit node on, open `http://mitm.it` in Safari there (type the `http://`)
and get the macOS certificate, or copy `~/.reqcove/mitmproxy/mitmproxy-ca-cert.pem`
from the Mac running Reqcove, then:

```sh
security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db mitmproxy-ca-cert.pem
```

That trusts it for TLS only, for that user; macOS asks for the password. For
its iOS Simulator, also `xcrun simctl keychain booted add-root-cert mitmproxy-ca-cert.pem`.

## Good to know

- All of that Mac's traffic goes through Reqcove (and the Mac running it);
  only the `--allow-hosts` hosts are decrypted and recorded.
- Once that Mac trusts the CA, the CA's private key, on the Mac running
  Reqcove, can impersonate any HTTPS site to it too. Remove the trust when done.
- Its records carry its machine name, as an iPhone's do.

## To undo

- The exit node: Tailscale menu › Exit Node › None, or `tailscale set --exit-node=`.
- The CA: delete `Reqcove CA (…)` in Keychain Access (its trust goes with it),
  or `security delete-certificate -t -Z <SHA-256> ~/Library/Keychains/login.keychain-db`
  with the fingerprint `reqcove status` shows.
