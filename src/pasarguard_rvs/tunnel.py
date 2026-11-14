"""Inside a container: a shell whose traffic exits through one device's reverse tunnel.

Meant for a dedicated container with NET_ADMIN and /dev/net/tun; every change is to the container's
own network. In order, each step undone in reverse on exit:
  1. pin the node (gRPC API + entry inbound) to the container's gateway with /32 routes, so the
     session's own node calls never ride the device, whatever happens to xray;
  2. `prohibit` 0/1 + 128/1 (and IPv6): if xray's tun goes away mid-session, traffic fails instead
     of leaking out as the container;
  3. run xray with a tun inbound; it installs 0/1 + 128/1 into the tun itself and carries everything
     as the user's main uuid to the entry inbound;
  4. point /etc/resolv.conf at the session DNS, reached through the device;
  5. run the shell.
The node rule (xray.device_rule) is held around all of it, and removed only after the local steps
are undone, so that removal runs on the container's normal network.
"""

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

from . import node as _node
from .node import RvsError
from .targets import Target
from .xray import HALF_ROUTES, TUN_NAME, Entry, device_rule, tun_config

log = logging.getLogger(__name__)
RESOLV_CONF = Path("/etc/resolv.conf")
XRAY_LOG = Path(tempfile.gettempdir()) / "rvs-xray.log"  # kept out of the interactive shell


@dataclass(frozen=True)
class SessionOptions:
    mtu: int = 1380
    dns: str = "1.1.1.1"  # resolver the shell uses, reached through the device
    shell: str = field(default_factory=lambda: os.environ.get("SHELL", "/bin/bash"))
    dry_run: bool = False  # print every step and the xray config, change nothing


class Steps:
    """Runs steps and undoes them in reverse. A step or an undo is a command tuple or a callable.
    In dry-run nothing runs: each step prints as `show` (or its command), command undos print too."""

    def __init__(self, dry_run: bool):
        self.dry_run = dry_run
        self._undo: list = []

    def __call__(self, do, undo=None, show: str | None = None, check: bool = True):
        result = None
        if self.dry_run:
            print("  $ " + (show or " ".join(do)))
        else:
            result = do() if callable(do) else _run(do, check)
        if undo and not (self.dry_run and callable(undo)):
            self._undo.append(undo)
        return result

    def undo_all(self) -> None:
        while self._undo:
            undo = self._undo.pop()
            try:
                if callable(undo):
                    undo()
                elif self.dry_run:
                    print("  $ " + " ".join(undo))
                else:
                    _run(undo, check=False)
            except Exception as exc:
                log.error("undo %s failed: %s", undo, exc)


def run_device_shell(target: Target, entry: Entry, opts: SessionOptions) -> None:
    node, device = target.node, target.device
    entry_ip = socket.gethostbyname(entry.host or node.address)
    # Only the node needs pinning: panel calls are all done before the tun exists, and pinning a
    # shared IP (a CDN) would let the shell reach everything else on it as the container.
    pins = {ip: via for ip in sorted({entry_ip} | _ipv4_all(node.address)) if (via := _gateway_route(ip))}
    cfg = tun_config(target.user.main_uuid, entry_ip, entry, opts.mtu)
    cfg_path = Path(tempfile.gettempdir()) / f"rvs-tun-{device}.json"

    print(
        f"device {device}"
        + (" (shared tunnel)" if device.row_id is None else "")
        + f" -> {device.outbound_tag}; entry {entry_ip}:{entry.port}; node {node.name} gRPC {node.address}:{node.port}"
        + "; kept direct: "
        + (", ".join(f"{ip} via {gw} dev {dev}" for ip, (gw, dev) in pins.items()) or "nothing to pin")
    )
    if opts.dry_run:
        print("\n--- xray config ---\n" + json.dumps(cfg, indent=2) + "\n\n--- commands ---")
    step = Steps(opts.dry_run)

    def session():
        try:
            for ip, (gw, dev) in pins.items():
                step(("ip", "route", "replace", f"{ip}/32", "via", gw, "dev", dev), ("ip", "route", "del", f"{ip}/32"))
            for half in HALF_ROUTES:
                route = ("prohibit", half, "metric", "100")
                step(("ip", "route", "add", *route), ("ip", "route", "del", *route))
            route = ("prohibit", "::/0", "metric", "1")
            step(("ip", "-6", "route", "add", *route), ("ip", "-6", "route", "del", *route), check=False)

            step(
                lambda: cfg_path.write_text(json.dumps(cfg)),
                lambda: cfg_path.unlink(missing_ok=True),
                show=f"write xray config -> {cfg_path}",
            )
            xray = step(
                lambda: _start_xray(cfg_path),
                lambda: _stop(xray),  # runs at undo time, by when `xray` holds the process
                show=f"xray run -c {cfg_path}   &   (background; adds {' + '.join(HALF_ROUTES)} into {TUN_NAME})",
            )
            saved = None if opts.dry_run else RESOLV_CONF.read_text()
            step(
                lambda: RESOLV_CONF.write_text(f"nameserver {opts.dns}\n"),
                lambda: RESOLV_CONF.write_text(saved),
                show=f"write {RESOLV_CONF}: nameserver {opts.dns}   (restored on exit)",
            )

            print(f"\nTraffic now exits device {device.outbound_tag}. 'exit' to tear down.\n")
            step(lambda: subprocess.run([opts.shell], check=False), show=opts.shell)
        finally:
            step.undo_all()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: sys.exit(0))
    try:
        if opts.dry_run:
            session()  # no node calls in dry-run
        else:
            _node.hold_rule(node, device_rule(device, entry.tag), session)  # module lookup: the test seam
    finally:
        step.undo_all()  # no-op after a normal session; covers failures before session() ran


def _run(cmd: tuple[str, ...], check: bool) -> None:
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RvsError(" ".join(cmd) + ": " + (proc.stderr.strip() or proc.stdout.strip()))


def _start_xray(cfg_path: Path) -> subprocess.Popen:
    """Start xray and block until it has put the half routes into its tun (or died trying)."""
    proc = subprocess.Popen(["xray", "run", "-c", str(cfg_path)], stdout=XRAY_LOG.open("w"), stderr=subprocess.STDOUT)
    print(f"  xray log: {XRAY_LOG}")
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RvsError(f"xray exited ({proc.returncode}); see {XRAY_LOG}")
            show = ["ip", "route", "show", "dev", TUN_NAME]
            if all(h in subprocess.run(show, check=False, capture_output=True, text=True).stdout for h in HALF_ROUTES):
                return proc
            time.sleep(0.2)
        raise RvsError(f"xray never routed {TUN_NAME}; see {XRAY_LOG}")
    except BaseException:
        _stop(proc)  # the step failed, so Steps registered no undo for it
        raise


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    proc.wait(timeout=10)


def _ipv4_all(host: str) -> set[str]:
    return {ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)}


def _gateway_route(ip: str) -> tuple[str, str] | None:
    """(gateway, interface) the container uses for ip now, or None when it needs no gateway."""
    out = subprocess.run(["ip", "-j", "route", "get", ip], check=False, capture_output=True, text=True).stdout
    routes = json.loads(out or "[]")
    if not routes or "gateway" not in routes[0]:
        return None  # loopback or on-link: a more specific route than the tun's /1s already wins
    return routes[0]["gateway"], routes[0]["dev"]
