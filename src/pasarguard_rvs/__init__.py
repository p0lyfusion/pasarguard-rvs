"""Shells through Pasarguard reverse-tunnel devices.

xray      the JSON: entry outbound, tun / standalone client configs, the node rule (pure)
node      a node's gRPC API: who is online, adding / holding a routing rule
panel     the panel API: node credentials, users
targets   which device: what is online, resolving user_id[.row_id] to a node and user
ctl       panel/node calls during a session, in a helper process that bypasses the tun
tunnel    the container session: routes, kill switch, the shell, selecting a device (xray tun)
"""

from .ctl import Remote
from .node import Device, NodeConfig, RvsError, add_rule, hold_rule, online_devices, remove_rule
from .panel import Panel, PanelUser
from .targets import Target, find, nodes, online
from .tunnel import SessionOptions, run_session
from .xray import Entry, client_config, device_rule, tun_config

__all__ = [
    "Device",
    "Entry",
    "NodeConfig",
    "Panel",
    "PanelUser",
    "Remote",
    "RvsError",
    "SessionOptions",
    "Target",
    "add_rule",
    "client_config",
    "device_rule",
    "find",
    "nodes",
    "hold_rule",
    "online",
    "online_devices",
    "remove_rule",
    "run_session",
    "tun_config",
]
