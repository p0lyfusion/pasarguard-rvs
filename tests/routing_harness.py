"""Privileged routing test: the real session, with only the panel and the node's gRPC faked.

Checks the container-side routing (everything into the tun, the node too; only rvs's uid direct),
the shell as full root, resolv.conf, selects, the conflict refusal and the watchdog, the kill switch
after an xray crash, and a clean teardown. Needs no panel and no node:

  docker run --rm --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.conf.all.rp_filter=0 \
  --sysctl net.ipv4.conf.default.rp_filter=0 \
  -v "$PWD/tests:/h:ro" --entrypoint as-rvs rvs python /h/routing_harness.py
"""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

from PasarGuardNodeBridge import NodeAPIError

from pasarguard_rvs import node as node_mod, session
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


class FakeBridge:
    """A node's routing rules, first match wins (as xray). Rules of "other sessions" can be planted
    by the test shell: one "<ruleTag> <outboundTag>" per line in /tmp/foreign-<node>, matched first."""

    rules: dict[str, list[dict]] = {}  # node name -> this process's rules, in order

    def __init__(self, name):
        self.name, self.foreign = name, Path(f"/tmp/foreign-{name}")

    def _foreign(self):
        lines = self.foreign.read_text().split("\n") if self.foreign.exists() else []
        return [{"ruleTag": t, "outboundTag": o, "user": [str(node_mod.rule_user(t))]} for t, o in (l.split() for l in lines if l)]

    def _all(self):
        return self._foreign() + self.rules.setdefault(self.name, [])

    def _close_chan(self):
        pass

    async def list_routing_rules(self):
        return SimpleNamespace(rules=[SimpleNamespace(rule_tag=r["ruleTag"]) for r in self._all()])

    async def add_routing_rule(self, rule, should_reset=False):
        self.rules.setdefault(self.name, []).append(json.loads(rule))
        print(f"  (fake) node {self.name}: rules now {[r['ruleTag'] for r in self._all()]}")

    async def remove_routing_rule(self, tag):
        own = self.rules.setdefault(self.name, [])
        own[:] = [r for r in own if r["ruleTag"] != tag]
        foreign = self._foreign()
        if any(r["ruleTag"] == tag for r in foreign):  # only then: a file rvs's uid creates in sticky
            # /tmp is one the root shell may no longer write (fs.protected_regular)
            kept = [f"{r['ruleTag']} {r['outboundTag']}" for r in foreign if r["ruleTag"] != tag]
            self.foreign.write_text("\n".join(kept))
        print(f"  (fake) node {self.name}: rules now {[r['ruleTag'] for r in self._all()]}")

    async def test_route(self, inbound_tag, user, **_):
        for r in self._all():
            if user in r["user"]:
                return SimpleNamespace(outbound_tag=r["outboundTag"])
        raise NodeAPIError(-1, "common: not enough information for making a decision")


node_mod._bridge = lambda n: FakeBridge(n.name)  # the real rule logic in node.py, on fake nodes


class FakeFleet:
    """The panel side: two of alice's devices, on two nodes."""

    def online(self):
        return [first, second]

    def find(self, device, node_name=None, allow_offline=False):
        print("  (fake) find", device)
        for t in self.online():
            if t.device == device and node_name in (None, t.node.name):
                return t
        raise RvsError(f"device {device} is not connected to any selected node")


def show(title, *cmd):
    print(f"== {title}")
    print(subprocess.run(cmd, check=False, capture_output=True, text=True).stdout)


show("before: ip rule", "ip", "rule")
show("before: routes", "ip", "route")
entry = Entry(encryption=ENCRYPTION)
opts = session.SessionOptions(shell="/h/routing_check.sh", check_interval=1)
session.run_session(entry, opts, FakeFleet(), first, need_first=True)  # as `rvs session -d 42.7`
print("##### a session started with no device")
nodevice = session.SessionOptions(shell="/h/routing_nodevice.sh", check_interval=1)
session.run_session(entry, nodevice, FakeFleet())
show("after: ip rule (expect the 'before' set)", "ip", "rule")
show("after: routes (expect the 'before' set)", "ip", "route")
show("after: table 77 (expect empty)", "ip", "route", "show", "table", "77")
