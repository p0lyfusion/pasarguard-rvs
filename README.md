# pasarguard-rvs

Shells through Pasarguard VLESS reverse-tunnel devices. `rvs devices` lists the devices online on
the panel's nodes. The container runs a session: a shell whose traffic exits through the device
`rvs select` fuzzy-picks, and running `rvs select` again moves it to another one. Everything runs in
a container: the tun, routes and resolv.conf changes never touch the host.

```
cp rvs.env.example .env && $EDITOR .env
docker compose run --rm rvs                   # = rvs session: opens the picker, then the shell
docker compose run --rm rvs session -d 42.7   # start on that device; refuses if it's offline
docker compose run --rm rvs devices           # list what's online
```

Inside the shell, `curl -s ifconfig.me` should print the device's public IP.

## Selecting devices

```
rvs select              # inside the shell: pick a device (any user, any node)
rvs select -d 51.3      # no picker
rvs select -d 51.3 --allow-offline   # go ahead before it connects (needs a single session node)
rvs select --dry-run    # print the node rule and xray config it would use, change nothing
```

The session starts with no device, and traffic is blocked until a select succeeds. Cancel the
first picker (or run without a terminal and without `-d`) to get the shell anyway; `-d` on
`rvs session` refuses to start without that device.

A select stops xray, moves the node rule (old one removed, then the new one added, on whichever
node each device is on) and starts xray again, so open connections drop and nothing keeps exiting
through the old device. If the new device can't be found, the shell stays on the current one; if it
is found but fails to come up, traffic stays blocked until a select succeeds.

Moving to another node assumes every node's entry inbound shares the same port, tag and VLESS
encryption key (the session has one of each); a mismatch only fails closed. With `RVS_ENTRY_HOST`
set the session needs a single node (`--node` / `RVS_NODE`), since that entry is one node's.

`rvs devices` and `rvs standalone` make their own panel and node calls, which from inside the
session go through the device (or fail before one is selected): run them as their own
`docker compose run`.

## Several people at once

Each `docker compose run` is its own container, so local routing never collides. The node is
shared: its rule sends entry traffic to a device by panel user, and every session of one user
authenticates as that user, so the node can't tell them apart. Hence:

- Devices of different users: independent, any number of sessions.
- A second session for a user that already has one on that node (same device or another of its
  devices) is refused: `already routed by rvs-shell-...`. A rule left by a session that didn't exit
  cleanly looks the same; `--take-over` (on `rvs select`, `rvs session`, `standalone --hold`)
  removes it. Taking over from a live session cuts that session off.
- While a session runs it asks the node every 15 s (`--check-interval`) which outbound the user's
  entry traffic takes. If it is no longer the device (taken over, the rule gone after a node
  resync, an earlier rule on the node matching first), it stops xray and says so: traffic is
  blocked, never silently exiting at the node or another device. A select runs the same check at
  once.

Rule tags carry a per-session id (`rvs-shell-<device>-<id>`), so a session only ever removes its
own rule.

## What goes through the device

Everything the shell runs, the panel and every node included (the session's own node too), so you
can test them as the device sees them. Only rvs itself leaves the container directly, on its
original default route (table 77): the image's entrypoint (`as-rvs`) runs rvs as uid 7777 with the
few capabilities it needs, and the session routes that uid around the tun. That covers rvs's panel
and node calls and the xray it starts (its link to the entry inbound); the shell is started as full
root, so it doesn't. Run nothing else as uid 7777 in the shell. `rvs session` refuses to start as
any other uid (e.g. with `--entrypoint` overridden).

Replies to that direct traffic need reverse-path filtering off in the container
(`net.ipv4.conf.{all,default}.rp_filter=0`, set in `compose.yaml`): even loose mode drops them while
xray is down, e.g. mid-select. `rvs session` refuses to start otherwise. rvs resolves names through
the session's DNS (`--dns`, reached directly), not the container's original resolver, so the panel
and node addresses must be public names or IPs.

## Standalone: your own xray instead of the container's tunnel

```
docker compose run --rm -T rvs standalone --json -d 42.7 > 42.7.json
docker compose run --rm -T rvs standalone --rule -d 42.7          # rule JSON for the node's admin
docker compose run --rm rvs standalone --rule --hold -d 42.7      # or add it yourself until Ctrl-C
xray run -c 42.7.json; curl -x socks5h://127.0.0.1:10808 ifconfig.me
```

The config is SOCKS5 + HTTP on 127.0.0.1 (no root, no tun) out to the entry inbound as the user's
main UUID; it reaches the device only while the node has the rule. A permanent rule goes in the
node's routing ahead of any rule matching the entry inbound. Without it, the node routes that
traffic by its own rules, so it exits at the node, not the device. The entry port's firewall must
allow wherever you run xray. `-T` keeps the status lines (stderr) out of a redirected file, and
leaves no terminal for the picker, so give `-d`; to pick interactively, write with `-o` into a
mounted directory instead.

## Requirements

- **Panel and node on the reverse v2 build.** The panel sends each user's devices to the nodes; only a
  v2 node turns them into per-device accounts (`<uid>.<row>`) on the `_is_reverse` inbound. A v1 node
  accepts the main account but rejects every device UUID (`invalid request user id` on that inbound).
- **Entry inbound**: a plain VLESS inbound found by tag (`RVS_ENTRY_TAG`, default `RVS_ENTRY`, port
  10900; no marker, `_level` optional) with VLESS encryption: the
  node holds `decryption`, `.env` holds the matching `encryption` half (`xray vlessenc`). Xray refuses
  plain VLESS to a public address. Firewall the port to this container's egress IP: the user's main
  UUID is not a secret.
- **A panel admin** with `users:read` + `nodes:read`. `nodes:read` returns every node's `api_key`, so
  this login amounts to full control of all nodes; keep `.env` private.

## Troubleshooting a device that doesn't show up

`rvs devices` prints a line per node: `N accounts online, M of them per-device`.

- `invalid request user id: <uuid>` in the node log on the reverse inbound: the node has no account
  for that device. Check that the user's group includes the `_is_reverse` inbound, that the HWID row
  still exists (`GET /api/user/<uid>/hwids`), that the node runs the v2 build, then force a node sync.
- The device UUID is `uuid5(main_uuid, "rvs:<row>")`; you can recover the row from a rejected UUID.

## Tests

```
docker build -t rvs .
docker run --rm --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.conf.all.rp_filter=0 \
  --sysctl net.ipv4.conf.default.rp_filter=0 \
  -v "$PWD/tests:/h:ro" --entrypoint as-rvs rvs python /h/routing_harness.py
```

## Vendored from the panel repo

`proto/service.proto` and `scripts/regenerate_node_bridge_proto.py` are copies from the Pasarguard
panel repo. The image regenerates the bridge's gRPC stubs from them to get `GetUsersOnlineIpListStats`,
which pasarguard-node-bridge 0.9.4 lacks. Update both copies (and the bridge pin in `pyproject.toml`)
together with the panel.
