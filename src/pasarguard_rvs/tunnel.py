"""Inside a container: a shell whose traffic exits through one device's reverse tunnel.

Meant for a dedicated container started with NET_ADMIN and /dev/net/tun. Every change is to the
CONTAINER's own network; the host's routes and firewall are never touched.

Per session it:
  1. pins the node (gRPC API + entry inbound) to the container's normal gateway with /32 host
     routes, so the session's own node calls never ride the device, whatever happens to Xray;
  2. adds a `prohibit` fallback for 0.0.0.0/1 + 128.0.0.0/1, so if Xray's tun goes away mid-session
     the shell's traffic fails instead of leaking out as the container;
  3. runs a throwaway xray with a `tun` inbound: xray creates the tun, installs the 0/1 + 128/1
     routes into it (autoSystemRoutingTable) and binds its own sockets to the uplink
     (autoOutboundsInterface), then carries everything as the user's MAIN uuid to the entry inbound;
  4. calls AddRoutingRule on the node pinning that user's entry traffic to the device tunnel;
  5. points /etc/resolv.conf at the session DNS so names resolve at the device, and runs a shell.
On exit or signal: restore resolv.conf, stop xray (its routes go with the tun), drop the host and
prohibit routes -- then RemoveRoutingRule on the node, over the container's normal network.

Needs an xray with Linux `autoSystemRoutingTable` (Xray-core #6366, >= 26.6.27). IPv4 only: IPv6 is
prohibited for the session rather than routed.

The node side must already be set up: the entry inbound `listen: 0.0.0.0` with VLESS encryption
(`"decryption"` from `xray vlessenc`; the matching `"encryption"` goes in
SessionOptions.entry_encryption -- Xray refuses plain VLESS to a public address), and a node
firewall allowing the entry port only from this container's egress IP(s).
"""

import asyncio
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .node import Device, NodeConfig, routing_rule

log = logging.getLogger(__name__)

TUN_NAME = "rvstun0"
TUN_CIDR = "10.77.0.1/30"
HALF_ROUTES = ["0.0.0.0/1", "128.0.0.0/1"]  # beat the container's default route without replacing it
RESOLV_CONF = Path("/etc/resolv.conf")
XRAY_LOG = Path(tempfile.gettempdir()) / "rvs-xray.log"  # kept out of the interactive shell


class TunnelError(RuntimeError):
    pass


@dataclass(frozen=True)
class SessionOptions:
    entry_encryption: str = "none"  # client half of the entry inbound's VLESS encryption
    entry_host: str | None = None  # data-plane address; default: the node's address
    entry_port: int = 10900
    entry_tag: str = "RVS_ENTRY"
    mtu: int = 1380
    dns: str = "1.1.1.1"  # resolver the shell uses, reached through the device
    shell: str = field(default_factory=lambda: os.environ.get("SHELL", "/bin/bash"))
    dry_run: bool = False  # print every command and the xray config, change nothing


class Runner:
    """Runs (or, in dry-run, prints) commands and unwinds a teardown stack."""

    def __init__(self, dry_run: bool):
        self.dry_run = dry_run
        self._teardown: list[tuple[str, object]] = []

    def run(self, *cmd: str, check: bool = True) -> None:
        if self.dry_run:
            print("  $ " + " ".join(cmd))
            return
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if check and proc.returncode != 0:
            raise TunnelError(" ".join(cmd) + ": " + (proc.stderr.strip() or proc.stdout.strip()))

    def defer(self, desc: str, action) -> None:
        """action: a command tuple, or a zero-arg callable."""
        self._teardown.append((desc, action))

    def teardown(self) -> None:
        while self._teardown:
            desc, action = self._teardown.pop()
            try:
                action() if callable(action) else self.run(*action, check=False)
            except Exception as exc:
                log.error("teardown '%s' failed: %s", desc, exc)


def _entry_outbound(main_uuid: str, entry_ip: str, entry_port: int, encryption: str) -> dict:
    """The user's MAIN uuid to the node's entry inbound; the node rule takes it on to the device."""
    return {
        "tag": "entry",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": entry_ip,
                    "port": entry_port,
                    "users": [{"id": main_uuid, "encryption": encryption, "flow": ""}],
                }
            ]
        },
        "streamSettings": {"network": "tcp", "security": "none"},
    }


def xray_config(main_uuid: str, entry_ip: str, entry_port: int, mtu: int, encryption: str) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
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
        ],
        "outbounds": [_entry_outbound(main_uuid, entry_ip, entry_port, encryption)],
        "routing": {"rules": [{"inboundTag": ["tun"], "outboundTag": "entry"}]},
    }


def client_config(main_uuid: str, entry_host: str, opts: SessionOptions, socks_port: int) -> dict:
    """A standalone xray config: SOCKS5 on 127.0.0.1:socks_port and HTTP on socks_port+1, out via the device.

    Needs no root and no tun, so it runs anywhere xray does. Names travel to the device unresolved
    (socks5h / HTTP CONNECT), so they resolve on the device's side. Reaches the device only while the
    node has session_rule(device) for this user.
    """
    local = {"listen": "127.0.0.1", "settings": {}}
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "protocol": "socks", "port": socks_port, **local, "settings": {"udp": True}},
            {"tag": "http", "protocol": "http", "port": socks_port + 1, **local},
        ],
        "outbounds": [_entry_outbound(main_uuid, entry_host, opts.entry_port, opts.entry_encryption)],
        "routing": {"rules": [{"inboundTag": ["socks", "http"], "outboundTag": "entry"}]},
    }


def session_rule(device: Device, entry_tag: str) -> dict:
    """Node rule sending this user's entry-inbound traffic into the device's reverse outbound."""
    return {
        "ruleTag": f"rvs-shell-{device}",
        "inboundTag": [entry_tag],
        "user": [str(device.user_id)],
        "outboundTag": device.outbound_tag,
    }


async def with_node_rule(node: NodeConfig, rule: dict, run_session) -> None:
    """Add the rule on the node, run the (blocking) session, always remove the rule."""
    async with routing_rule(node, rule):
        await asyncio.to_thread(run_session)


def run_device_shell(node: NodeConfig, device: Device, main_uuid: str, opts: SessionOptions) -> None:
    """Pin the bypass routes, start xray, add the node rule, run the shell, undo it all."""
    entry_ip = socket.gethostbyname(opts.entry_host or node.address)
    # Only the node needs pinning: its gRPC channel stays open across the session. Panel calls all
    # finish before the tun exists, and a per-IP pin would let the shell reach anything else on that
    # IP (a CDN) as the container.
    bypass = {entry_ip} | _ipv4_all(node.address)
    # pin each peer to the route it takes now; loopback/on-link peers already beat the tun's /1s
    pins = {ip: via for ip in sorted(bypass) if (via := _gateway_route(ip))}

    tag = device.outbound_tag
    rule = session_rule(device, opts.entry_tag)
    cfg = xray_config(main_uuid, entry_ip, opts.entry_port, opts.mtu, opts.entry_encryption)

    print(
        f"device {device}"
        + (" (shared tunnel)" if device.row_id is None else "")
        + f" -> {tag}; entry {entry_ip}:{opts.entry_port}; node {node.name} gRPC {node.address}:{node.port}"
        + "; kept direct: "
        + (", ".join(f"{ip} via {gw} dev {dev}" for ip, (gw, dev) in pins.items()) or "nothing to pin")
    )
    if opts.dry_run:
        print("\n--- xray config ---\n" + json.dumps(cfg, indent=2) + "\n\n--- commands ---")

    r = Runner(opts.dry_run)

    def build():
        # the session's own peers keep the container's normal path, whatever happens to the tun
        for ip, (gw, dev) in pins.items():
            r.run("ip", "route", "replace", f"{ip}/32", "via", gw, "dev", dev)
            r.defer(f"del route {ip}", ("ip", "route", "del", f"{ip}/32"))
        # kill switch: if xray's tun routes vanish, fail closed instead of leaking as the container
        for half in HALF_ROUTES:
            r.run("ip", "route", "add", "prohibit", half, "metric", "100")
            r.defer(f"del prohibit {half}", ("ip", "route", "del", "prohibit", half, "metric", "100"))
        r.run("ip", "-6", "route", "add", "prohibit", "::/0", "metric", "1", check=False)
        r.defer("del v6 prohibit", ("ip", "-6", "route", "del", "prohibit", "::/0", "metric", "1"))

        cfg_path = Path(tempfile.gettempdir()) / f"rvs-tun-{device}.json"
        if opts.dry_run:
            print(f"  $ write xray config -> {cfg_path}")
            print(f"  $ xray run -c {cfg_path}   &   (background; adds {' + '.join(HALF_ROUTES)} into {TUN_NAME})")
            print(f"  $ write {RESOLV_CONF}: nameserver {opts.dns}   (restored on exit)")
            return
        cfg_path.write_text(json.dumps(cfg))
        r.defer("rm config", lambda: cfg_path.unlink(missing_ok=True))
        xray_log = XRAY_LOG.open("w")
        proc = subprocess.Popen(["xray", "run", "-c", str(cfg_path)], stdout=xray_log, stderr=subprocess.STDOUT)
        print(f"  xray log: {XRAY_LOG}")
        r.defer("stop xray", lambda: (proc.terminate(), proc.wait(timeout=10)))
        _wait_for_routes(proc)
        # names resolve at the device; the container's own resolv.conf, put back afterwards
        saved = RESOLV_CONF.read_text()
        RESOLV_CONF.write_text(f"nameserver {opts.dns}\n")
        r.defer("restore resolv.conf", lambda: RESOLV_CONF.write_text(saved))

    def run_session():
        # local teardown happens here, BEFORE the node rule is removed, so that removal (and any
        # gRPC reconnect / re-resolve it needs) runs on the container's normal network
        try:
            build()
            print(f"\nTraffic now exits device {tag}. 'exit' to tear down.\n")
            if opts.dry_run:
                print(f"  $ {opts.shell}")
            else:
                subprocess.run([opts.shell], check=False)
        finally:
            r.teardown()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: sys.exit(0))
    try:
        if opts.dry_run:
            run_session()  # no node calls in dry-run
        else:
            asyncio.run(with_node_rule(node, rule, run_session))
    finally:
        r.teardown()  # no-op after a normal session; covers failures before run_session


def _ipv4_all(host: str) -> set[str]:
    return {ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)}


def _gateway_route(ip: str) -> tuple[str, str] | None:
    """(gateway, interface) the container uses for ip now, or None when it needs no gateway."""
    out = subprocess.run(["ip", "-j", "route", "get", ip], check=False, capture_output=True, text=True).stdout
    routes = json.loads(out or "[]")
    if not routes or "gateway" not in routes[0]:
        return None  # loopback or on-link: a more specific route than the tun's /1s already wins
    return routes[0]["gateway"], routes[0]["dev"]


def _wait_for_routes(proc: subprocess.Popen, timeout: float = 10.0) -> None:
    """Block until xray has put the half routes into its tun (or died trying)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise TunnelError(f"xray exited ({proc.returncode}); see {XRAY_LOG}")
        out = subprocess.run(
            ["ip", "route", "show", "dev", TUN_NAME], check=False, capture_output=True, text=True
        ).stdout
        if all(h in out for h in HALF_ROUTES):
            return
        time.sleep(0.2)
    raise TunnelError(f"xray never routed {TUN_NAME}; see {XRAY_LOG}")
