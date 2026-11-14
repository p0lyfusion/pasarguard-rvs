"""Node side: connection details, which devices are online, and the ad-hoc routing rule.

Everything here talks to the node's gRPC API through pasarguard-node-bridge with the same
address/port/server_ca/api_key the panel uses. Nothing here starts, stops or reconfigures the
node's backend: the reads are GetUsersOnlineIpListStats, the writes AddRoutingRule/RemoveRoutingRule.
"""

import asyncio
import json
import logging
import signal
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)


class NodeError(RuntimeError):
    pass


@dataclass(frozen=True)
class NodeConfig:
    name: str
    address: str
    port: int
    api_key: str
    server_ca: str = field(repr=False)

    @classmethod
    def from_file(cls, path: str | Path) -> NodeConfig:
        """JSON with address, port, api_key, server_ca (PEM); optional name."""
        raw = json.loads(Path(path).read_text())
        missing = [k for k in ("address", "port", "api_key", "server_ca") if not raw.get(k)]
        if missing:
            raise NodeError(f"{path}: missing {', '.join(missing)}")
        return cls(
            name=raw.get("name") or raw["address"],
            address=raw["address"],
            port=int(raw["port"]),
            api_key=raw["api_key"],
            server_ca=raw["server_ca"],
        )


@dataclass(frozen=True, order=True)
class Device:
    """A per-device reverse account: node email "<user_id>.<row_id>". row_id None = the shared tunnel."""

    user_id: int
    row_id: int | None = None

    @classmethod
    def parse(cls, ident: str) -> Device:
        uid, _, row = ident.partition(".")
        return cls(int(uid), int(row) if row else None)

    def __str__(self) -> str:
        return str(self.user_id) if self.row_id is None else f"{self.user_id}.{self.row_id}"

    @property
    def outbound_tag(self) -> str:
        """The node's reverse outbound for this device."""
        return f"r-{self}"


def _bridge(node: NodeConfig):
    from PasarGuardNodeBridge import NodeAPIError, NodeType, create_node

    try:
        # api_port is required by the constructor but unused over gRPC (it is the REST/metrics port).
        return create_node(
            connection=NodeType.grpc,
            address=node.address,
            port=node.port,
            server_ca=node.server_ca,
            api_key=node.api_key,
            api_port=node.port,
        )
    except NodeAPIError as exc:  # raised for a bad api_key / server_ca before any call
        raise NodeError(f"node {node.name}: {exc.detail}") from exc


def _close(bridge) -> None:
    # Close only the channel. disconnect() leaves it open, and `async with` / __aexit__ would also
    # send Stop to the node's backend.
    bridge._close_chan()


async def online_devices(node: NodeConfig) -> dict[Device, dict[str, int]]:
    """{device: {ingress_ip: last_seen}} for every per-device account online on the node now.

    Needs a node with per-device online stats and a bridge carrying the GetUsersOnlineIpListStats
    stub (the image regenerates it from the panel's proto). Bare user ids are not devices and are
    left out; the IP is how the device reached the node, not its egress IP.
    """
    from PasarGuardNodeBridge import NodeAPIError
    from PasarGuardNodeBridge.common import service_pb2 as service

    bridge = _bridge(node)
    # The bulk RPC has no wrapper in the bridge; call the raw stub as the panel does.
    client = getattr(bridge, "_client", None)
    handle = getattr(bridge, "_handle_grpc_request", None)
    if client is None or handle is None or not hasattr(client, "GetUsersOnlineIpListStats"):
        raise NodeError(
            "bridge has no GetUsersOnlineIpListStats stub; regenerate it with scripts/regenerate_node_bridge_proto.py"
        )
    try:
        resp = await handle(method=client.GetUsersOnlineIpListStats, request=service.Empty())
    except NodeAPIError as exc:
        raise NodeError(f"node {node.name}: {exc.detail} (code {exc.code})") from exc
    finally:
        _close(bridge)
    if resp is None:
        log.warning("node %s (%s:%s): empty reply to GetUsersOnlineIpListStats", node.name, node.address, node.port)
        return {}
    devices = {Device.parse(email): dict(stats.ips) for email, stats in resp.users.items() if "." in email}
    log.info(
        "node %s (%s:%s): %d accounts online, %d of them per-device",
        node.name,
        node.address,
        node.port,
        len(resp.users),
        len(devices),
    )
    return devices


@asynccontextmanager
async def routing_rule(node: NodeConfig, rule: dict) -> AsyncIterator[None]:
    """Add `rule` (with a "ruleTag") on the node for the duration of the block; always remove it."""
    from PasarGuardNodeBridge import NodeAPIError

    bridge = _bridge(node)
    try:
        try:
            await bridge.add_routing_rule(json.dumps(rule), should_reset=False)
        except NodeAPIError as exc:
            raise NodeError(f"node {node.name}: adding rule failed: {exc.detail} (code {exc.code})") from exc
        log.info("node %s: routing rule %s added", node.name, rule["ruleTag"])
        yield
    finally:
        try:
            await bridge.remove_routing_rule(rule["ruleTag"])
            log.info("node %s: routing rule %s removed", node.name, rule["ruleTag"])
        except Exception as exc:
            log.error("failed to remove rule %s on node %s: %s -- remove it by hand", rule["ruleTag"], node.name, exc)
        _close(bridge)


async def hold_routing_rule(node: NodeConfig, rule: dict) -> None:
    """Add `rule` on the node and keep it until SIGINT/SIGTERM, then remove it."""
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    async with routing_rule(node, rule):
        log.info("holding rule %s on %s; Ctrl-C removes it", rule["ruleTag"], node.name)
        await stop.wait()
