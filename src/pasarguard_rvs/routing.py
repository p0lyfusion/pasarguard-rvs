"""The session's container network, set up once and undone on exit. Linux, NET_ADMIN.

Invariants:
- Everything goes into xray's tun, or fails on `prohibit` while there is no tun: nothing leaks.
- Only RVS_UID goes direct (table 77, the container's original default route). rvs runs as that uid
  (the image's entrypoint), so its panel/node calls and the xray it starts bypass the tun; the shell
  runs as root and does not.
"""

import json
import logging
import os
import subprocess
from pathlib import Path

from .node import RvsError
from .xray import HALF_ROUTES

log = logging.getLogger(__name__)
RVS_UID = 7777
TABLE = "77"
RESOLV_CONF = Path("/etc/resolv.conf")


class Steps:
    """Runs steps and undoes them in reverse. A step or an undo is a command tuple or a callable;
    an undo that fails is logged and skipped."""

    def __init__(self):
        self._undo: list = []

    def __call__(self, do, undo=None, check: bool = True):
        result = do() if callable(do) else run(do, check)
        if undo:
            self._undo.append(undo)
        return result

    def undo_all(self) -> None:
        while self._undo:
            undo = self._undo.pop()
            try:
                undo() if callable(undo) else run(undo, check=False)
            except Exception as exc:
                log.error("undo %s failed: %s", undo, exc)


def run(cmd: tuple[str, ...], check: bool = True) -> str:
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RvsError(" ".join(cmd) + ": " + (proc.stderr.strip() or proc.stdout.strip()))
    return proc.stdout


def preflight() -> tuple[str, str]:
    """Refuse to start where the session can't work; (gateway, interface) of the default route."""
    if os.geteuid() != RVS_UID:
        raise RvsError(
            f"the session runs as uid {RVS_UID} (the image's entrypoint, `as-rvs`, does that), "
            f"not {os.geteuid()}: as any other uid its own panel and node calls would go into the tun"
        )
    if not Path("/dev/net/tun").exists():
        raise RvsError("needs /dev/net/tun (and NET_ADMIN): see compose.yaml")
    gw, dev = _default_route()
    _check_rp_filter(dev)
    return gw, dev


def setup(step: Steps, gw: str, dev: str, dns: str) -> None:
    """Table 77 for RVS_UID, the kill switch, resolv.conf. Each step registers its undo."""
    step(("ip", "route", "replace", "default", "via", gw, "dev", dev, "table", TABLE), ("ip", "route", "flush", "table", TABLE))
    rule = ("uidrange", f"{RVS_UID}-{RVS_UID}", "lookup", TABLE, "priority", "100")
    step(("ip", "rule", "add", *rule), ("ip", "rule", "del", *rule))
    for half in HALF_ROUTES:
        route = ("prohibit", half, "metric", "100")
        step(("ip", "route", "add", *route), ("ip", "route", "del", *route))
    route = ("prohibit", "::/0", "metric", "1")
    step(("ip", "-6", "route", "add", *route), ("ip", "-6", "route", "del", *route), check=False)
    saved = RESOLV_CONF.read_text()
    step(lambda: RESOLV_CONF.write_text(f"nameserver {dns}\n"), lambda: RESOLV_CONF.write_text(saved))
    log.info("direct via %s dev %s (table %s): rvs itself and its xray (uid %s)", gw, dev, TABLE, RVS_UID)


def _default_route() -> tuple[str, str]:
    for route in json.loads(run(("ip", "-j", "route", "show", "default"), check=False) or "[]"):
        if "gateway" in route and "dev" in route:
            return route["gateway"], route["dev"]
    raise RvsError("the container has no IPv4 default route via a gateway")


def _check_rp_filter(dev: str) -> None:
    """Replies to the direct traffic come in on `dev`. The kernel checks their source as if sent by
    root, so the uid rule doesn't apply: it finds the tun, or with xray down (session start,
    mid-select, after a crash) the prohibit routes, which fail even loose mode. So reverse-path
    filtering must be off. The effective value is max(all, dev)."""
    values = {}
    for name in ("all", dev):
        try:
            values[name] = int(Path(f"/proc/sys/net/ipv4/conf/{name}/rp_filter").read_text())
        except (OSError, ValueError):
            values[name] = 0
    if any(values.values()):
        raise RvsError(
            f"rp_filter is on ({', '.join(f'{k}={v}' for k, v in values.items())}): it would drop replies to "
            "rvs's direct traffic whenever xray is down; run the container with --sysctl "
            "net.ipv4.conf.all.rp_filter=0 --sysctl net.ipv4.conf.default.rp_filter=0 (compose.yaml sets both)"
        )
