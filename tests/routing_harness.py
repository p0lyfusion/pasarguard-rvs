"""Privileged routing test: the real tunnel session, with only the node gRPC call faked.

Checks the container-side routing (tun routes, node pinned to the gateway, resolv.conf, kill switch
after an xray crash, teardown before the node rule is removed). Needs no panel and no node:

  docker run --rm --cap-add NET_ADMIN --device /dev/net/tun -v "$PWD/tests:/h:ro" \
    --entrypoint python rvs /h/routing_harness.py
"""

import asyncio
import subprocess

from pasarguard_rvs import node as node_mod, tunnel
from pasarguard_rvs.node import Device, NodeConfig
from pasarguard_rvs.panel import PanelUser
from pasarguard_rvs.targets import Target
from pasarguard_rvs.xray import Entry

# a throwaway key pair; only the client half is needed for xray to accept the config
ENCRYPTION = "mlkem768x25519plus.native.0rtt.JatLo-Ey-mzIzJM032xr3pIY5WkOcLeUXvzNNQmCo0w"


def fake_hold_rule(node, rule, during):
    print("  (fake) node rule add:", rule)
    try:
        asyncio.run(asyncio.to_thread(during))  # in a worker thread, as the real hold_rule runs it
    finally:
        print("  (fake) node rule remove:", rule["ruleTag"])
        print("  routes at rule-removal time (should be the 'before' set):")
        print(subprocess.run(["ip", "route"], check=False, capture_output=True, text=True).stdout)


node_mod.hold_rule = fake_hold_rule
node = NodeConfig(name="fake", address="203.0.113.1", port=62050, api_key="k", server_ca="unused")
user = PanelUser(42, "alice", "11111111-2222-3333-4444-555555555555")
opts = tunnel.SessionOptions(shell="/h/routing_check.sh")
tunnel.run_device_shell(Target(node, Device(42, 7), user), Entry(encryption=ENCRYPTION), opts)
