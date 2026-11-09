# Several exit nodes on one computer

[日本語](several-exit-nodes.ja.md)

One computer can run several Reqcove exit nodes at once, each with its own
settings (`--allow-hosts`, `--rules`, `--ui`, …), and the iPhone picks one in
the Tailscale app. One `reqcove run` per state directory. After v0.1.0. Not
tried yet with an iPhone switching between them: what is below comes from the
tests (the names, the ports, the CA) and from how the exit node works.

## 1. Start each with its own `--state`

```sh
reqcove run --device iphone --allow-hosts api.example.com --ui
reqcove run --device iphone --allow-hosts api.staging.example.com --rules staging.yaml --ui --state ~/.reqcove-staging
```

Each in a terminal of its own. The first uses `~/.reqcove` and is named
`reqcove`, as before.

- **The name.** A `--state` directory named `reqcove-NAME` (a leading dot left
  out) names the node `reqcove-NAME`: here `reqcove-staging`. Other directory
  names keep `reqcove`, and then Tailscale renames the second `reqcove-1`; give
  `--hostname` to choose. A directory used before with another name gets the new
  one (Tailscale renames the machine); `--hostname reqcove` keeps the old.
- **Log in and approve each node once**, as the first time (`reqcove status
  --state ~/.reqcove-staging` says what is missing). An `autoApprovers` entry in
  the tailnet policy approves them for you (README, Tips).
- **The CA.** A new state directory gets a copy of `~/.reqcove`'s CA on its first
  start (`run` says so), so the profile already on the iPhone serves every node.
  A directory used before keeps its own CA, and so does one started before
  `~/.reqcove` had a CA: start the default node first.

## 2. On the iPhone: switch in the Tailscale app

Exit Node › `reqcove` or `reqcove-staging`. If pages stop loading after a switch,
turn the exit node off and on again (as after a restart of reqcove).

Each node's records are its own: an agent sees the node it is connected to.

## 3. The agents: one MCP server per node

`run` prints the command for its node, with its state directory:

```sh
claude mcp add reqcove -- reqcove mcp
claude mcp add reqcove-staging -- reqcove mcp --state /Users/you/.reqcove-staging
```

`reqcove status`, `reqcove har` and `reqcove cleanup` take `--state` too.

## Ports

- `--ui` is on each node's own port 80, `--web` on each node's port 8081: their
  links name the node's address, so each node's link opens its own page. The
  `--ui` page shows the node's name, unless it is `reqcove`.
- mitmweb listens on `127.0.0.1:8081` on this computer, or, while another run
  has it, on the first free one of 8091-8099 (`run` prints which). The node's
  port stays 8081, so the iPhone's links do not change with the order of starts.
- `--local-proxy` is one per computer (port 8082, and the system's one set of
  web proxies): a second run asking for it stops at once, before it changes
  anything.

## Good to know

- The CA's private key is then in each state directory (`mitmproxy/` in each).
  Deleting one (`reqcove cleanup --delete-state --state …`) leaves it in the
  others; removing the profile from the iPhone stops every node's decryption
  (`cleanup` says so for a node that shares `~/.reqcove`'s CA).
- Each node is a machine in the Tailscale admin console; remove those you no
  longer use (`reqcove cleanup --state …` names it).
