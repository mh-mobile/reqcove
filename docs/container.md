# Reqcove in a container

[日本語](container.ja.md)

Reqcove runs in a container too (Docker; Podman should take the same
commands): uv, Python, mitmproxy and the CA's private key stay inside it, and
removing the container and its volume cleans up. One container per environment
gives several exit nodes on one machine, each closed in.

Best on Linux. On macOS the container runs in a VM (Docker Desktop, OrbStack,
colima): the Simulator and `--local-proxy` are not there, and the Mac must stay
awake. To run several exit nodes on a Mac, one `run` per `--state` on the Mac
itself ([several exit nodes](several-exit-nodes.md)) keeps those.

**What was checked**: `scripts/container-smoke.sh` on OrbStack (macOS, arm64)
and in CI (Linux, amd64 and arm64):
the image builds; with no network, mitmproxy
and mitmweb start from what the image holds; a new volume's state directory is
the container user's, 0700; `reqcove mcp` in another container reaches `run`
through the volume; `docker exec … reqcove status` answers; a second `run` on the same volume is refused; `docker stop`
ends it cleanly. By hand on OrbStack: logging in to a tailnet from a container
(Tailnet Lock signed, the exit node approved), an iPhone through it (its own
CA installed; GitHub's app recorded), `reqcove mcp` through `docker run -i`
answering an MCP client, `docker exec … reqcove har`, and `--mcp-http` read by
Grok Bot; Claude Code (`claude -p`) through `docker run -i` read `status`.
**Not tried yet**: Linux hosts by hand, Podman.

## 1. Build the image

No image is published; build it from the repository:

```sh
docker build -t reqcove .
```

It is distroless (no shell, no package manager), and runs as a user of its
own (65532), not root.

## 2. Start one: pick a NAME

One name, used four times: the container, its volume, the container's hostname
(the CA is named after it) and the node's name.

```sh
NAME=reqcove-staging
docker run -d --init --name $NAME --hostname $NAME \
  -v $NAME:/home/nonroot/.reqcove reqcove \
  run --device iphone --allow-hosts api.staging.example.com --hostname $NAME --ui
docker logs -f $NAME
```

- The log says what is left to do. The login URL and the links are not in it:
  `docker exec -it $NAME reqcove links` prints them, with QR codes (not tried in
  a container yet). With `-t` (a terminal), `run` prints them in the log as on
  the host, and `docker logs` keeps them. Approve the exit node once, as on the
  host.
- `--init` reaps mitmproxy's processes when they end.
- Only a named volume (`-v NAME:…`): a folder of the Mac bound in does not
  carry the lock and the socket across the VM's border.
- Each volume makes its own CA: the iPhone installs a profile per container.

## 3. The agent

```sh
claude mcp add $NAME -- docker run -i --rm --network none --log-driver none --volumes-from $NAME reqcove mcp
```

A container per agent session, reaching `run`'s socket through the volume
(checked with the smoke script and with Claude Code, `claude -p`). `--volumes-from`
fails at once if the run container is not there; `--log-driver none` keeps the
tools' answers out of Docker's logs.

`docker exec $NAME reqcove status` and `reqcove har` work as on the host.

An agent on another device of yours (Grok Bot): add `--mcp-http` to `run`.
The node is in the container, so no port is published; `docker exec -it $NAME
reqcove links` prints the URL and the token
([how](guide.md#agents-on-other-devices---mcp-http); tried with Grok Bot when
`docker logs` had them, `reqcove links` not tried in a container yet).

Times in the records carry the container's time zone, UTC by default.

## What is different in a container

- `--local-proxy`, the Simulator, and trusting the CA on this computer: not in a
  container.
- macOS: the Mac sleeping stops the VM; keep `caffeinate -i` running while you use it.
- Without `-t`, `docker logs` keeps no login URL or token; with it, it keeps
  them until the container is removed. A token stays valid until its file in
  the volume is deleted. `--log-opt max-size=10m` bounds the log.
- `localhost` in `--rules` and `--upstream-proxy` is the container itself; the
  host is `host.docker.internal` on Docker Desktop and OrbStack (not tried). Bind
  a folder for `--rules` (`-v ./rules:/rules:ro`, then `--rules /rules/x.yaml`),
  and the same for `--proto`.
- The commands `run` prints (`claude mcp add … reqcove mcp`, `reqcove status`)
  are the host's; use the forms above.
- Over a VM's network the tailnet may relay more (DERP); speed was not measured.

## Several environments

Repeat step 2 with another NAME (and other flags). Each has its own node, CA,
records and agent registration.

## To undo

```sh
docker rm -f $NAME && docker volume rm $NAME   # the CA's key and the logs go with them
```

Then remove the machine in the Tailscale admin console, and the CA's profile
from the iPhone.
