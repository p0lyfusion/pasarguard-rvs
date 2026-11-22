"""Which device to use: what is online across the nodes, and resolving a given user_id[.row_id]."""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import httpx

from .node import Device, NodeConfig, RvsError, online_devices
from .panel import Panel, PanelUser

log = logging.getLogger(__name__)
PANEL_LOOKUPS = 16  # concurrent user lookups


@dataclass(frozen=True)
class Target:
    """A device, the node it is on, and its user (whose main uuid authenticates the entry)."""

    node: NodeConfig
    device: Device
    user: PanelUser
    ips: dict[str, int] = field(default_factory=dict)  # ingress IP -> last seen; empty when offline

    @property
    def line(self) -> str:
        """One line for lists and the picker."""
        return f"{self.user.username}  {self.device}  {self.node.name}  {', '.join(sorted(self.ips))}"


@dataclass(frozen=True)
class Fleet:
    """The panel's connected nodes (only `node_name`, if set) and their devices. Every call logs in
    afresh, so a long session never holds an expired token."""

    panel_url: str
    admin: str
    password: str = field(repr=False)
    node_name: str | None = None

    def nodes(self) -> list[NodeConfig]:
        with self._panel() as panel:
            return connected_nodes(panel, self.node_name)

    def online(self, user_id: int | None = None) -> list[Target]:
        with self._panel() as panel:
            return online(panel, connected_nodes(panel, self.node_name), user_id)

    def find(self, device: Device, node_name: str | None = None, allow_offline: bool = False) -> Target:
        """See `find`; node_name narrows it to that node (e.g. the one a picker line showed)."""
        with self._panel() as panel:
            return find(panel, connected_nodes(panel, node_name or self.node_name), device, allow_offline)

    def _panel(self) -> Panel:
        try:
            return Panel(self.panel_url, self.admin, self.password)
        except httpx.HTTPError as exc:
            raise RvsError(f"panel login failed: {exc}") from exc


def connected_nodes(panel: Panel, name: str | None = None) -> list[NodeConfig]:
    """The panel's connected gRPC nodes (only `name`, if given); none is an error."""
    if found := panel.nodes(name):
        return found
    raise RvsError(f"no connected gRPC node named {name!r}" if name else "the panel lists no connected gRPC nodes")


def online(panel: Panel, nodes: list[NodeConfig], user_id: int | None = None) -> list[Target]:
    """Every device online on any of `nodes` whose user resolves in the panel."""

    async def gather():
        return await asyncio.gather(*(online_devices(n) for n in nodes), return_exceptions=True)

    found: list[tuple[NodeConfig, Device, dict]] = []
    for node, res in zip(nodes, asyncio.run(gather())):
        if isinstance(res, BaseException):
            log.warning("node %s (%s:%s): %s", node.name, node.address, node.port, res)
        else:
            found += [(node, d, ips) for d, ips in res.items() if user_id in (None, d.user_id)]

    uids = sorted({d.user_id for _, d, _ in found})
    with ThreadPoolExecutor(PANEL_LOOKUPS) as pool:
        users = dict(zip(uids, pool.map(lambda uid: _user(panel, uid), uids)))
    if unresolved := [uid for uid in uids if not users[uid]]:
        log.warning("users without a VLESS id in the panel (left out): %s", ", ".join(map(str, unresolved)))
    # a user gone from the panel, or without a VLESS id, can't authenticate the entry
    targets = [Target(n, d, users[d.user_id], ips) for n, d, ips in found if users[d.user_id]]
    return sorted(targets, key=lambda t: (t.device, t.node.name))


def find(panel: Panel, nodes: list[NodeConfig], device: Device, allow_offline: bool = False) -> Target:
    """The node `device` is online on. An offline device (or the shared tunnel, which the online
    stats don't list) needs allow_offline and a single node."""
    if device.row_id is not None:
        if hits := [t for t in online(panel, nodes, device.user_id) if t.device == device]:
            return hits[0]
        if not allow_offline:
            raise RvsError(
                f"device {device} is not connected to any selected node; "
                "--allow-offline goes ahead anyway (traffic fails until it connects)"
            )
    if len(nodes) > 1:
        raise RvsError("several connected nodes; pick one with --node: " + ", ".join(n.name for n in nodes))
    user = panel.user(device.user_id)
    if user is None:
        raise RvsError(f"user {device.user_id} has no VLESS id in the panel")
    return Target(nodes[0], device, user)


def _user(panel: Panel, uid: int) -> PanelUser | None:
    try:
        return panel.user(uid)
    except httpx.HTTPError as exc:
        log.warning("panel lookup for user %s failed: %s", uid, exc)
        return None
