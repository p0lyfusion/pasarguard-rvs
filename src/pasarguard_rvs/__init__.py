"""Shells through Pasarguard reverse-tunnel devices.

xray      the JSON (entry outbound, tun / standalone configs, the node rule), and running xray
node      a node's gRPC API: who is online, adding / checking / holding a routing rule
panel     the panel API: node credentials, users
targets   which device: what is online, resolving user_id[.row_id] to a node and user (Fleet)
routing   the session's container network: table 77 for rvs's uid, kill switch, resolv.conf
session   the container session: selecting a device, the watchdog, the control socket, the shell
"""

from .node import Device, NodeConfig, RvsError, add_rule, hold_rule, online_devices, remove_rule, route
from .panel import Panel, PanelUser
from .session import SessionOptions, run_session
from .targets import Fleet, Target, connected_nodes, find, online
from .xray import Entry, client_config, device_rule, tun_config

__all__ = [
    "Device",
    "Entry",
    "Fleet",
    "NodeConfig",
    "Panel",
    "PanelUser",
    "RvsError",
    "SessionOptions",
    "Target",
    "add_rule",
    "client_config",
    "connected_nodes",
    "device_rule",
    "find",
    "hold_rule",
    "online",
    "online_devices",
    "remove_rule",
    "route",
    "run_session",
    "tun_config",
]
