"""Privileged routing test: the real tunnel session, with only the panel/node calls faked.

Checks the container-side routing: everything into the tun (the node too), only xray's mark and the
helper uid direct, resolv.conf, the first select, `rvs select` to another node's device, the kill switch after an
xray crash, and a clean teardown. Needs no panel and no node:

  docker run --rm --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.conf.all.rp_filter=0 \
  --sysctl net.ipv4.conf.default.rp_filter=0 \
  -v "$PWD/tests:/h:ro" --entrypoint python rvs /h/routing_harness.py
"""

import subprocess

from pasarguard_rvs import tunnel
from pasarguard_rvs.cli import _select
from pasarguard_rvs.node import Device, NodeConfig, RvsError
from pasarguard_rvs.panel import PanelUser
from pasarguard_rvs.targets import Target
from pasarguard_rvs.xray import Entry

# a throwaway key pair; only the client half is needed for xray to accept the config
ENCRYPTION = "mlkem768x25519plus.native.0rtt.JatLo-Ey-mzIzJM032xr3pIY5WkOcLeUXvzNNQmCo0w"


def node(n: int) -> NodeConfig:
    return NodeConfig(name=f"fake{n}", address=f"203.0.113.{n}", port=62050, api_key="k", server_ca="unused")


alice = PanelUser(42, "alice", "11111111-2222-3333-4444-555555555555")
first, second = Target(node(1), Device(42, 7), alice), Target(node(2), Device(42, 8), alice)


class FakeRemote:
    def online(self):
        return [first, second]

    def find(self, device, allow_offline=False):
        print("  (fake) find", device)
        for t in self.online():
            if t.device == device:
                return t
        raise RvsError(f"device {device} is not connected to any selected node")

    def resolve(self, host):
        return host  # the fake nodes' addresses are IPs

    def add_rule(self, node, rule):
        print(f"  (fake) node {node.name}: rule add {rule['ruleTag']} -> {rule['outboundTag']}")

    def remove_rule(self, node, tag):
        print(f"  (fake) node {node.name}: rule remove {tag}")


def show(title, *cmd):
    print(f"== {title}")
    print(subprocess.run(cmd, check=False, capture_output=True, text=True).stdout)


show("before: ip rule", "ip", "rule")
show("before: routes", "ip", "route")
opts = tunnel.SessionOptions(shell="/h/routing_check.sh")
# the session's first select, as `rvs session -d 42.7` makes it
tunnel.run_session(Entry(encryption=ENCRYPTION), opts, FakeRemote(), lambda: _select(first.device, "", False))
print("##### a session started with no device")
nodevice = tunnel.SessionOptions(shell="/h/routing_nodevice.sh")
tunnel.run_session(Entry(encryption=ENCRYPTION), nodevice, FakeRemote())
show("after: ip rule (expect the 'before' set)", "ip", "rule")
show("after: routes (expect the 'before' set)", "ip", "route")
show("after: table 77 (expect empty)", "ip", "route", "show", "table", "77")
