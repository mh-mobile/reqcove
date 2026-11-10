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
`reqcove`, as before. Write `--state ~/x` with a space: with `--state=~/x`
the shell leaves the `~` as it is, and every reqcove command refuses it.

- **The name.** A new `--state` directory named `reqcove-NAME` (a leading dot
  left out) names the node `reqcove-NAME`: here `reqcove-staging`. Other
  directory names give `reqcove`; give `--hostname` to choose (then two nodes
  are not both `reqcove`, which Tailscale would tell apart by renaming one,
  from its documentation; not tried). The name is kept in the state directory
  (`node-name`): the next start and `cleanup` use it, so a `--hostname` given
  once stays (give another to change it). A directory an older reqcove used
  keeps `reqcove`.
- **Log in and approve each node once**, as the first time (`reqcove status
  --state ~/.reqcove-staging` says what is missing). An `autoApprovers` entry in
  the tailnet policy approves them for you ([guide](guide.md#first-start)).
- **The CA.** A state directory without a CA gets a copy of `~/.reqcove`'s at
  start (`run` says where), so the profile already on the iPhone serves every
  node. One with a CA of its own keeps it. If `~/.reqcove` has no CA yet, the
  node makes its own (`run` says so): start the default node first, and wait
  until it prints its CA (its first start downloads mitmproxy, which takes
  minutes). If `~/.reqcove`'s CA lacks a file, `run` stops and names it. For
  a node with a CA of its own (for testers' devices you will untrust apart,
  say), stop the default node and move `~/.reqcove/mitmproxy` aside while the
  other starts the first time, then put it back.

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

`reqcove status`, `reqcove har` and `reqcove cleanup` take `--state` too; what
`run` and `status` print for the node carries it.

## Ports

`--ui` is on each node's port 80. mitmweb (`--web`) has two addresses:

| | `reqcove` (started first) | `reqcove-staging` (started next) |
|---|---|---|
| The node: what the iPhone opens, the link and QR code `run` prints | `http://100.1.1.1:8081/…` | `http://100.2.2.2:8081/…` |
| This computer: what a browser here opens | `http://127.0.0.1:8081/…` | `http://127.0.0.1:8091/…` |

- On the node it is port 8081, on every node: each node has its own address,
  so they do not clash, and the iPhone's links do not change with the order of
  starts.
- On this computer, 127.0.0.1 is one for all, so the first mitmweb takes 8081
  and the next ones the first free of 8091-8099 (`run` prints which). The node
  relays its 8081 there.
- The `--ui` page shows the node's name, unless it is `reqcove`.
- `--local-proxy` is one per computer (port 8082, and the system's one set of
  web proxies): a second run asking for it stops at once, before it changes
  anything.

## Good to know

- The CA's private key is then in each state directory (`mitmproxy/` in each).
  Deleting one (`reqcove cleanup --delete-state --state …`) leaves it in the
  others; `reqcove cleanup` of `~/.reqcove` names the directories it was copied
  into (listed in `~/.reqcove/ca-copies`). Removing the profile from the iPhone
  stops every node's decryption (`cleanup` of a node sharing the CA says so).
- Each node is a machine in the Tailscale admin console; remove those you no
  longer use (`reqcove cleanup --state …` names it as `run` gave it; one
  Tailscale renamed, `reqcove-1` say, shows with that name there).
