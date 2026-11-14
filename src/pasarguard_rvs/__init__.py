"""Shells through Pasarguard reverse-tunnel devices.

xray      the JSON: entry outbound, tun / standalone client configs, the node rule (pure)
node      a node's gRPC API: who is online, holding a routing rule
panel     the panel API: node credentials, users
targets   which device: what is online, resolving user_id[.row_id] to a node and user
tunnel    the container session: routes, kill switch, xray tun, the shell
"""

from .node import Device, NodeConfig, RvsError, hold_rule, online_devices, routing_rule
from .panel import Panel, PanelUser
from .targets import Target, find, online
from .tunnel import SessionOptions, run_device_shell
from .xray import Entry, client_config, device_rule, tun_config

__all__ = [
    "Device",
    "Entry",
    "NodeConfig",
    "Panel",
    "PanelUser",
    "RvsError",
    "SessionOptions",
    "Target",
    "client_config",
    "device_rule",
    "find",
    "hold_rule",
    "online",
    "online_devices",
    "routing_rule",
    "run_device_shell",
    "tun_config",
]
