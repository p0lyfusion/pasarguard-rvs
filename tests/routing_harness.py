"""Privileged routing test: the real tunnel session, with only the node gRPC call faked.

Checks the container-side routing (tun routes, node pinned to the gateway, resolv.conf, kill switch
after an xray crash, teardown before the node rule is removed). Needs no panel and no node:

  docker run --rm --cap-add NET_ADMIN --device /dev/net/tun -v "$PWD/tests:/h:ro" \
    --entrypoint python rvs /h/routing_harness.py
"""

import asyncio
import subprocess

from pasarguard_rvs import tunnel
from pasarguard_rvs.node import Device, NodeConfig

# a throwaway key pair; only the client half is needed for xray to accept the config
ENCRYPTION = "mlkem768x25519plus.native.0rtt.JatLo-Ey-mzIzJM032xr3pIY5WkOcLeUXvzNNQmCo0w"


async def fake_rule(node, rule, run_session):
    print("  (fake) node rule add:", rule)
    try:
        await asyncio.to_thread(run_session)
    finally:
        print("  (fake) node rule remove:", rule["ruleTag"])
        print("  routes at rule-removal time (should be the 'before' set):")
        print(subprocess.run(["ip", "route"], check=False, capture_output=True, text=True).stdout)  # noqa: ASYNC221


tunnel.with_node_rule = fake_rule
node = NodeConfig(name="fake", address="203.0.113.1", port=62050, api_key="k", server_ca="unused")
opts = tunnel.SessionOptions(shell="/h/routing_check.sh", entry_encryption=ENCRYPTION)
tunnel.run_device_shell(node, Device(42, 7), "11111111-2222-3333-4444-555555555555", opts)
