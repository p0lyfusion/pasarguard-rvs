"""Node side: connection details, which devices are online, and holding a routing rule.

Everything here talks to the node's gRPC API through pasarguard-node-bridge with the same
address/port/server_ca/api_key the panel uses. Nothing here starts, stops or reconfigures the
node's backend: the reads are GetUsersOnlineIpListStats, the writes AddRoutingRule/RemoveRoutingRule.
"""

import asyncio
import json
import logging
import signal
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


class RvsError(RuntimeError):
    """Every expected failure (panel, node, tunnel); the CLI prints it as one line."""


@dataclass(frozen=True)
class NodeConfig:
    name: str
    address: str
    port: int
    api_key: str
    server_ca: str = field(repr=False)


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
        raise RvsError(f"node {node.name}: {exc.detail}") from exc


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
        raise RvsError(
            "bridge has no GetUsersOnlineIpListStats stub; regenerate it with scripts/regenerate_node_bridge_proto.py"
        )
    try:
        resp = await handle(method=client.GetUsersOnlineIpListStats, request=service.Empty())
    except NodeAPIError as exc:
        raise RvsError(f"node {node.name}: {exc.detail} (code {exc.code})") from exc
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


async def _add_rule(bridge, node: NodeConfig, rule: dict) -> None:
    from PasarGuardNodeBridge import NodeAPIError

    tag = rule["ruleTag"]
    try:
        try:
            await bridge.add_routing_rule(json.dumps(rule), should_reset=False)
        except NodeAPIError as exc:
            if "duplicate ruleTag" not in str(exc.detail):
                raise
            # Left by a session that did not exit cleanly. The tag is per device, so the old
            # rule is this same rule: replace it. (A session for this device that is still
            # running loses its rule too -- one session per device is all the tag allows.)
            log.warning("node %s: rule %s already there (stale session?); replacing it", node.name, tag)
            await bridge.remove_routing_rule(tag)
            await bridge.add_routing_rule(json.dumps(rule), should_reset=False)
    except NodeAPIError as exc:
        raise RvsError(f"node {node.name}: adding rule failed: {exc.detail} (code {exc.code})") from exc
    log.info("node %s: routing rule %s added", node.name, tag)


async def _remove_rule(bridge, node: NodeConfig, tag: str) -> None:
    from PasarGuardNodeBridge import NodeAPIError

    try:
        await bridge.remove_routing_rule(tag)
    except NodeAPIError as exc:
        raise RvsError(f"node {node.name}: removing rule {tag} failed: {exc.detail} (code {exc.code})") from exc
    log.info("node %s: routing rule %s removed", node.name, tag)


def _on_bridge(node: NodeConfig, call) -> None:
    """Run `await call(bridge)` on a fresh bridge to the node, closing it afterwards."""

    async def go():
        bridge = _bridge(node)
        try:
            await call(bridge)
        finally:
            _close(bridge)

    asyncio.run(go())


def add_rule(node: NodeConfig, rule: dict) -> None:
    """Add `rule` (with a "ruleTag") on the node; an identical stale one is replaced."""
    _on_bridge(node, lambda bridge: _add_rule(bridge, node, rule))


def remove_rule(node: NodeConfig, tag: str) -> None:
    _on_bridge(node, lambda bridge: _remove_rule(bridge, node, tag))


def hold_rule(node: NodeConfig, rule: dict) -> None:
    """Add `rule` on the node, wait for SIGINT/SIGTERM, and always remove the rule afterwards."""
    stop = (signal.SIGINT, signal.SIGTERM)
    # blocked from before the add: a signal during the add RPC is kept, and still ends in the removal
    signal.pthread_sigmask(signal.SIG_BLOCK, stop)
    try:
        add_rule(node, rule)
        try:
            log.info("holding rule %s on %s; Ctrl-C removes it", rule["ruleTag"], node.name)
            signal.sigwait(stop)
        finally:
            try:
                remove_rule(node, rule["ruleTag"])
            except Exception as exc:
                log.error("%s -- remove it by hand", exc)
    finally:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, stop)
