"""Inside a container: a session whose shell's traffic exits through the device it selects.

Meant for a dedicated container with NET_ADMIN and /dev/net/tun; every change is to the container's
own network. Everything the shell does goes through the device, the panel and every node included.
Only rvs's own plumbing goes direct, by policy routing on the container's original default route
(table 77): xray's entry link by SO_MARK, and the panel/node calls by uid (ctl.CTL_UID helper).

Session layer, set up once and undone in reverse on exit:
  1. table 77 + `ip rule` for the mark and the helper uid;
  2. `prohibit` 0/1 + 128/1 (and IPv6): with no xray tun, traffic fails instead of leaking;
  3. /etc/resolv.conf -> the session DNS, reached through the device;
  4. the control socket (`rvs select` inside the shell) and the shell.
The session starts with no device, so nothing leaves until the first select.
Target layer, rebuilt on every select: the node rule (xray.device_rule), then xray with a tun
inbound, which puts 0/1 + 128/1 into its tun. A select stops xray first, so nothing flows while
the rule moves, and nothing still exits through the old device afterwards.
"""

import json
import logging
import os
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .ctl import CTL_UID, Remote
from .node import Device, RvsError
from .targets import Target
from .xray import HALF_ROUTES, TUN_NAME, Entry, device_rule, tun_config

log = logging.getLogger(__name__)
RESOLV_CONF = Path("/etc/resolv.conf")
XRAY_LOG = Path(tempfile.gettempdir()) / "rvs-xray.log"  # kept out of the interactive shell
SOCK = Path("/run/rvs.sock")
FWMARK = 0x77
TABLE = "77"


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


class Session:
    def __init__(self, entry: Entry, opts: SessionOptions, remote: Remote):
        self.entry, self.opts, self.remote = entry, opts, remote
        self.current: Target | None = None
        self._lock = threading.Lock()
        self._steps = Steps(opts.dry_run)  # the target layer's; down() undoes it
        self._listed: dict[tuple[str, str], Target] = {}  # the last `list`, by (device, node name)

    def label(self) -> str | None:
        return f"{self.current.device} on {self.current.node.name}" if self.current else None

    def plan(self, target: Target, entry_ip: str) -> tuple[dict, dict]:
        """(xray config, node rule) for the target."""
        cfg = tun_config(target.user.main_uuid, entry_ip, self.entry, self.opts.mtu, FWMARK)
        return cfg, device_rule(target.device, self.entry.tag)

    def up(self, target: Target, entry_ip: str) -> None:
        """Rule, then xray. On failure the caller runs down()."""
        node, device = target.node, target.device
        step = self._steps = Steps(self.opts.dry_run)
        cfg, rule = self.plan(target, entry_ip)
        cfg_path = Path(tempfile.gettempdir()) / "rvs-tun.json"
        print(
            f"device {device}"
            + (" (shared tunnel)" if device.row_id is None else "")
            + f" -> {device.outbound_tag}; entry {entry_ip}:{self.entry.port}; node {node.name}"
        )
        if self.opts.dry_run:
            print("\n--- xray config ---\n" + json.dumps(cfg, indent=2) + "\n\n--- commands ---")
        step(
            lambda: cfg_path.write_text(json.dumps(cfg)),
            lambda: cfg_path.unlink(missing_ok=True),
            show=f"write xray config -> {cfg_path}",
        )
        step(
            lambda: self.remote.add_rule(node, rule),
            lambda: self.remote.remove_rule(node, rule["ruleTag"]),
            show=f"node {node.name}: add routing rule {rule['ruleTag']}   (removed on select/exit)",
        )
        xray = step(
            lambda: _start_xray(cfg_path),
            lambda: _stop(xray),  # runs at undo time, by when `xray` holds the process
            show=f"xray run -c {cfg_path}   &   (background; adds {' + '.join(HALF_ROUTES)} into {TUN_NAME})",
        )
        self.current = target

    def down(self) -> None:
        """xray, then the rule: traffic is blocked (prohibit) before the rule goes."""
        self._steps.undo_all()
        self.current = None

    def close(self) -> None:
        with self._lock:
            self.down()

    def select(self, device: Device, node_name: str | None = None, allow_offline: bool = False) -> None:
        with self._lock:
            target, entry_ip = self._resolve(device, node_name, allow_offline)
            self.down()
            try:
                self.up(target, entry_ip)
            except BaseException:
                self.down()  # left with no device: traffic blocked, the session stays
                raise

    def _resolve(self, device: Device, node_name: str | None, allow_offline: bool) -> tuple[Target, str]:
        """Both fail before anything is torn down; a pick from `list` needs no second lookup."""
        target = self._listed.get((str(device), node_name)) or self.remote.find(device, allow_offline)
        return target, self.remote.resolve(self.entry.address(target.node))

    def handle(self, req: dict) -> dict:
        if req.get("op") == "list":
            self._listed = {(str(t.device), t.node.name): t for t in self.remote.online()}
            return {
                "current": self.label(),
                "targets": [{"line": t.line, "device": d, "node": n} for (d, n), t in self._listed.items()],
            }
        if req.get("op") == "select":
            device, node_name, allow_offline = Device.parse(req["device"]), req.get("node"), req.get("allow_offline")
            if req.get("dry_run"):
                target, entry_ip = self._resolve(device, node_name, allow_offline)
                cfg, rule = self.plan(target, entry_ip)
                return {"current": self.label(), "plan": {"node": target.node.name, "rule": rule, "xray": cfg}}
            self.select(device, node_name, allow_offline)
            return {"current": self.label()}
        raise RvsError(f"unknown op {req.get('op')!r}")


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            reply = self.server.session.handle(json.loads(self.rfile.readline()))
        except Exception as exc:
            reply = {"error": str(exc) or type(exc).__name__, "current": self.server.session.label()}
        self.wfile.write((json.dumps(reply) + "\n").encode())


def _serve(session: Session) -> socketserver.UnixStreamServer:
    SOCK.unlink(missing_ok=True)
    server = socketserver.ThreadingUnixStreamServer(str(SOCK), _Handler)
    SOCK.chmod(0o600)
    server.daemon_threads = True
    server.session = session
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _unserve(server: socketserver.UnixStreamServer) -> None:
    server.shutdown()
    server.server_close()
    SOCK.unlink(missing_ok=True)


def run_session(
    entry: Entry,
    opts: SessionOptions,
    remote: Remote,
    first_select: Callable[[], None] | None = None,
    preview: Target | None = None,
) -> None:
    """Set up the session with no device, run `first_select()` (a client of the control socket,
    whose failure ends the session), then the shell. With opts.dry_run: print the session's steps,
    and `preview`'s as if it were selected, then stop."""
    gw, dev = _default_route()
    if not opts.dry_run:
        _check_rp_filter(dev)
    print(f"direct via {gw} dev {dev} (table {TABLE}): xray's entry link (mark {FWMARK:#x}), rvs's helper (uid {CTL_UID})")
    session = Session(entry, opts, remote)
    step = Steps(opts.dry_run)
    server = None

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: sys.exit(0))
    try:
        step(
            ("ip", "route", "replace", "default", "via", gw, "dev", dev, "table", TABLE),
            ("ip", "route", "flush", "table", TABLE),
        )
        for match, prio in ((("fwmark", hex(FWMARK)), "100"), (("uidrange", f"{CTL_UID}-{CTL_UID}"), "101")):
            rule = (*match, "lookup", TABLE, "priority", prio)
            step(("ip", "rule", "add", *rule), ("ip", "rule", "del", *rule))
        for half in HALF_ROUTES:
            route = ("prohibit", half, "metric", "100")
            step(("ip", "route", "add", *route), ("ip", "route", "del", *route))
        route = ("prohibit", "::/0", "metric", "1")
        step(("ip", "-6", "route", "add", *route), ("ip", "-6", "route", "del", *route), check=False)
        saved = None if opts.dry_run else RESOLV_CONF.read_text()
        step(
            lambda: RESOLV_CONF.write_text(f"nameserver {opts.dns}\n"),
            lambda: RESOLV_CONF.write_text(saved),
            show=f"write {RESOLV_CONF}: nameserver {opts.dns}   (restored on exit)",
        )
        if opts.dry_run:
            if preview:
                session.up(preview, socket.gethostbyname(entry.address(preview.node)))
            return  # no node calls, no control socket, no shell
        server = _serve(session)
        os.environ["RVS_SOCK"] = str(SOCK)  # for first_select, the shell and every `rvs select` in it
        if first_select:
            first_select()
        if not session.current:
            print("\nNo device selected: traffic is blocked. `rvs select` picks one.")
        print("'exit' tears the session down.\n")
        subprocess.run([opts.shell], check=False)
    finally:
        if server:
            _unserve(server)  # no select starts after this; one already running holds the lock
        session.close()
        step.undo_all()


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
    if proc.poll() is None:
        proc.terminate()
    proc.wait(timeout=10)


def _default_route() -> tuple[str, str]:
    """(gateway, interface) of the container's default route, before the session changes anything."""
    out = subprocess.run(["ip", "-j", "route", "show", "default"], check=False, capture_output=True, text=True).stdout
    for route in json.loads(out or "[]"):
        if "gateway" in route and "dev" in route:
            return route["gateway"], route["dev"]
    raise RvsError("the container has no IPv4 default route via a gateway")


def _check_rp_filter(dev: str) -> None:
    """Replies to the direct traffic come in on `dev`. The kernel checks their source against the
    main table, as if sent by root with no mark, so neither the mark nor the uid rule applies: with
    xray up that finds the tun (strict mode drops, loose passes), and with xray down (session start,
    mid-switch, after a crash) only the prohibit routes, which fail even loose mode. So reverse-path
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
