"""Panel and node calls made while a tunnel session runs, in a helper process that bypasses the tun.

The session routes all of the container's traffic through the device, panel and nodes included:
that is what the shell is for. Only xray's entry link (by SO_MARK) and this helper (by uid, see
tunnel.CTL_UID) are routed around it. The supervisor runs each call as

  python -m pasarguard_rvs.ctl   (as CTL_UID)   one JSON request on stdin, one JSON reply on stdout
"""

import json
import logging
import os
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field

from . import node as _node
from . import targets
from .node import Device, NodeConfig, RvsError
from .targets import Target

CTL_UID = 7777  # the session's `ip rule uidrange` sends this uid around the tun
TIMEOUT = 60


@dataclass(frozen=True)
class Remote:
    """The supervisor's side: each method runs one helper process as CTL_UID."""

    panel_url: str
    admin: str
    password: str = field(repr=False)
    node_name: str | None = None  # the only node to list and find on (None: every connected one)

    def online(self) -> list[Target]:
        return [Target.from_json(t) for t in self._call("online")]

    def find(self, device: Device, allow_offline: bool = False) -> Target:
        return Target.from_json(self._call("find", device=str(device), allow_offline=allow_offline))

    def resolve(self, host: str) -> str:
        """IPv4 for `host`, looked up directly, not through the device's DNS."""
        return self._call("resolve", host=host)

    def add_rule(self, node: NodeConfig, rule: dict) -> None:
        self._call("add_rule", node=asdict(node), rule=rule)

    def remove_rule(self, node: NodeConfig, tag: str) -> None:
        self._call("remove_rule", node=asdict(node), tag=tag)

    def _call(self, op: str, **args):
        request = {"op": op, "args": args, **asdict(self)}
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pasarguard_rvs.ctl"],
                input=json.dumps(request),
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
                user=CTL_UID,
                group=CTL_UID,
                extra_groups=[],
                cwd="/",
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            )
        except subprocess.TimeoutExpired:
            raise RvsError(f"{op}: no reply in {TIMEOUT}s") from None
        try:
            reply = json.loads(proc.stdout)
        except ValueError:
            raise RvsError(f"{op}: helper failed ({proc.returncode}): {proc.stderr.strip()[-500:]}") from None
        if "error" in reply:
            raise RvsError(reply["error"])
        return reply["ok"]


def _panel(req: dict):
    from .panel import Panel

    return Panel(req["panel_url"], req["admin"], req["password"])


def _run(req: dict):
    op, args = req["op"], req["args"]
    if op == "add_rule":
        return _node.add_rule(NodeConfig(**args["node"]), args["rule"])
    if op == "remove_rule":
        return _node.remove_rule(NodeConfig(**args["node"]), args["tag"])
    if op == "resolve":
        return socket.gethostbyname(args["host"])
    with _panel(req) as panel:
        nodes = targets.nodes(panel, req["node_name"])
        if op == "online":
            return [t.to_json() for t in targets.online(panel, nodes)]
        if op == "find":
            return targets.find(panel, nodes, Device.parse(args["device"]), args["allow_offline"]).to_json()
    raise RvsError(f"unknown op {op!r}")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="  %(message)s", stream=sys.stderr)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        reply = {"ok": _run(json.load(sys.stdin))}
    except Exception as exc:  # every failure goes back as one line
        reply = {"error": str(exc) or type(exc).__name__}
    json.dump(reply, sys.stdout)


if __name__ == "__main__":
    main()
