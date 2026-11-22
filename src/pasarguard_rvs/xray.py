"""Xray: the JSON, and running it for the session. Every config here reaches a device the same way:

  client --VLESS, user's MAIN uuid--> node entry inbound --device_rule--> r-<device> reverse outbound

The entry inbound authenticates the user; the rule on the node is what picks the device.
"""

import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .node import RULE_PREFIX, Device, NodeConfig, RvsError

TUN_NAME = "rvstun0"
TUN_CIDR = "10.77.0.1/30"
HALF_ROUTES = ["0.0.0.0/1", "128.0.0.0/1"]  # beat the default route without replacing it
LOG = Path(tempfile.gettempdir()) / "rvs-xray.log"  # kept out of the interactive shell


@dataclass(frozen=True)
class Entry:
    """The node's entry inbound (a plain VLESS inbound, found by tag) as a client sees it."""

    encryption: str = "none"  # client half of its VLESS encryption (`xray vlessenc`)
    host: str | None = None  # data-plane address; default: the node's address
    port: int = 10900
    tag: str = "RVS_ENTRY"

    def address(self, node: NodeConfig) -> str:
        """Where to reach the entry for a device on `node`."""
        return self.host or node.address


def device_rule(device: Device, entry_tag: str, owner: str | None = None) -> dict:
    """Node routing rule: this user's traffic on the entry inbound goes out the device's reverse outbound.

    `owner` (a per-session id) makes the tag unique, so removing it never removes someone else's.
    """
    return {
        "ruleTag": f"{RULE_PREFIX}{device}" + (f"-{owner}" if owner else ""),
        "inboundTag": [entry_tag],
        "user": [str(device.user_id)],
        "outboundTag": device.outbound_tag,
    }


def _entry_outbound(main_uuid: str, address: str, entry: Entry) -> dict:
    return {
        "tag": "entry",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": entry.port,
                    "users": [{"id": main_uuid, "encryption": entry.encryption, "flow": ""}],
                }
            ]
        },
        "streamSettings": {"network": "tcp", "security": "none"},
    }


def _config(inbounds: list[dict], main_uuid: str, address: str, entry: Entry) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [_entry_outbound(main_uuid, address, entry)],
        "routing": {"rules": [{"inboundTag": [i["tag"] for i in inbounds], "outboundTag": "entry"}]},
    }


def tun_config(main_uuid: str, entry_ip: str, entry: Entry, mtu: int) -> dict:
    """For the container session: a tun that xray routes itself (Linux, Xray >= 26.6.27)."""
    tun = {
        "tag": "tun",
        "protocol": "tun",
        "settings": {
            "name": TUN_NAME,
            "mtu": mtu,
            "gateway": [TUN_CIDR],
            "autoSystemRoutingTable": HALF_ROUTES,  # xray adds these into the tun, removes them on exit
            "autoOutboundsInterface": "auto",  # xray's own sockets bind to the default-route iface
        },
    }
    return _config([tun], main_uuid, entry_ip, entry)


def client_config(main_uuid: str, address: str, entry: Entry, socks_port: int) -> dict:
    """Standalone: SOCKS5 on 127.0.0.1:socks_port, HTTP on the next port. No root, no tun.

    Names travel unresolved (socks5h / CONNECT), so they resolve on the device's side.
    """
    local = {"listen": "127.0.0.1", "settings": {}}
    socks = {"tag": "socks", "protocol": "socks", "port": socks_port, **local, "settings": {"udp": True}}
    http = {"tag": "http", "protocol": "http", "port": socks_port + 1, **local}
    return _config([socks, http], main_uuid, address, entry)


def start(cfg_path: Path) -> subprocess.Popen:
    """Run xray on the config; return once it has put HALF_ROUTES into its tun (or failed)."""
    proc = subprocess.Popen(["xray", "run", "-c", str(cfg_path)], stdout=LOG.open("w"), stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RvsError(f"xray exited ({proc.returncode}); see {LOG}")
            show = ["ip", "route", "show", "dev", TUN_NAME]
            if all(h in subprocess.run(show, check=False, capture_output=True, text=True).stdout for h in HALF_ROUTES):
                return proc
            time.sleep(0.2)
        raise RvsError(f"xray never routed {TUN_NAME}; see {LOG}")
    except BaseException:
        stop(proc)
        raise


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
    proc.wait(timeout=10)
