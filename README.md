# pasarguard-rvs

Shells through Pasarguard VLESS reverse-tunnel devices. `rvs devices` lists the devices online on
the panel's nodes; `rvs shell` fuzzy-picks one and opens a shell whose traffic exits through it.
Everything runs in a container: the tun, routes and resolv.conf changes never touch the host.

```
cp rvs.env.example .env && $EDITOR .env
docker compose run --rm rvs                 # = rvs shell: pick a device, get a shell through it
docker compose run --rm rvs shell -d 42.7   # no picker; finds the node the device is on, refuses if it's offline
docker compose run --rm rvs devices         # list what's online
```

Inside the shell, `curl -s ifconfig.me` should print the device's public IP.

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
- **Entry inbound** (`_rvs_entry`, default tag `RVS_ENTRY`, port 10900) with VLESS encryption: the
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
docker run --rm --cap-add NET_ADMIN --device /dev/net/tun -v "$PWD/tests:/h:ro" \
  --entrypoint python rvs /h/routing_harness.py
```

## Vendored from the panel repo

`proto/service.proto` and `scripts/regenerate_node_bridge_proto.py` are copies from the Pasarguard
panel repo. The image regenerates the bridge's gRPC stubs from them to get `GetUsersOnlineIpListStats`,
which pasarguard-node-bridge 0.9.4 lacks. Update both copies (and the bridge pin in `pyproject.toml`)
together with the panel.
