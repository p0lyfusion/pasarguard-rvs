"""The container session: a shell whose traffic exits through the device `rvs select` picks.

routing.py sets up the network once. On top of it, each select rebuilds the target layer: the node
rule (refused while another rvs rule routes the same user there), a check that the node really
routes the user to the device, then xray. A select stops xray first, so nothing flows while the rule
moves. A watchdog repeats the check and stops xray if the node stops routing to the device: traffic
is then blocked, never exiting somewhere else. `rvs select` in the shell talks to SOCK.
"""

import json
import logging
import os
import secrets
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

from . import node, routing, xray
from .node import Device, RvsError
from .routing import Steps
from .targets import Fleet, Target
from .xray import Entry, device_rule, tun_config

log = logging.getLogger(__name__)
SOCK = Path("/run/rvs.sock")
CONFIG = Path(tempfile.gettempdir()) / "rvs-tun.json"


@dataclass(frozen=True)
class SessionOptions:
    mtu: int = 1380
    dns: str = "1.1.1.1"  # resolver the shell uses, reached through the device
    shell: str = field(default_factory=lambda: os.environ.get("SHELL", "/bin/bash"))
    check_interval: float = 15  # seconds between checks that the node routes to the device; 0: never


class Session:
    def __init__(self, entry: Entry, opts: SessionOptions, fleet: Fleet):
        self.entry, self.opts, self.fleet = entry, opts, fleet
        self.current: Target | None = None
        self._lock = threading.Lock()
        self._steps = Steps()  # the target layer's; down() undoes it
        self.owner = secrets.token_hex(3)  # in this session's rule tags, so it only ever removes its own

    def label(self) -> str | None:
        return f"{self.current.device} on {self.current.node.name}" if self.current else None

    def plan(self, target: Target) -> tuple[str, dict, dict]:
        """(entry IP, xray config, node rule) for the target. The IP is looked up as rvs, so directly."""
        entry_ip = socket.gethostbyname(self.entry.address(target.node))
        cfg = tun_config(target.user.main_uuid, entry_ip, self.entry, self.opts.mtu)
        return entry_ip, cfg, device_rule(target.device, self.entry.tag, self.owner)

    def problem(self, target: Target) -> str | None:
        """Why the node would not send the target user's entry traffic to its device, or None."""
        got = node.route(target.node, self.entry.tag, target.device.user_id)
        if got == target.device.outbound_tag:
            return None
        return (
            f"node {target.node.name} routes user {target.device.user_id}'s entry traffic to "
            f"{got or 'its default outbound'}, not {target.device.outbound_tag}"
        )

    def select(self, target: Target, take_over: bool = False) -> None:
        """Move to `target`. Left with no device (traffic blocked) if it fails to come up."""
        with self._lock:
            entry_ip, cfg, rule = self.plan(target)  # fails before anything is torn down
            self.down()
            try:
                self._up(target, entry_ip, cfg, rule, take_over)
            except BaseException:
                self.down()
                raise

    def _up(self, target: Target, entry_ip: str, cfg: dict, rule: dict, take_over: bool) -> None:
        device, step = target.device, self._steps
        print(
            f"device {device}" + (" (shared tunnel)" if device.row_id is None else "")
            + f" -> {device.outbound_tag}; entry {entry_ip}:{self.entry.port}; node {target.node.name}"
            + f"; xray log {xray.LOG}"
        )
        step(lambda: CONFIG.write_text(json.dumps(cfg)), lambda: CONFIG.unlink(missing_ok=True))
        step(
            lambda: node.add_rule(target.node, rule, take_over),
            lambda: node.remove_rule(target.node, rule["ruleTag"]),
        )
        if problem := self.problem(target):
            raise RvsError(problem)  # e.g. an earlier rule on the node matches the entry traffic first
        proc = step(lambda: xray.start(CONFIG), lambda: xray.stop(proc))  # undo runs once proc is set
        self.current = target

    def down(self) -> None:
        """xray, then the rule: traffic is blocked (prohibit) before the rule goes."""
        self._steps.undo_all()
        self.current = None

    def close(self) -> None:
        with self._lock:
            self.down()

    def watch(self, stop: threading.Event) -> None:
        """Every check_interval: block traffic if the node no longer routes to the current device."""
        while not stop.wait(self.opts.check_interval):
            if not (target := self.current):
                continue
            try:
                problem = self.problem(target)
            except Exception as exc:  # the node is unreachable: nothing known either way
                log.warning("route check for %s failed: %s", target.device, exc)
                continue
            if not problem:
                continue
            with self._lock:
                if self.current is not target:  # a select ran meanwhile
                    continue
                self.down()
            print(f"\n[rvs] {problem}: traffic blocked. `rvs select` (--take-over) to retry.", file=sys.stderr, flush=True)

    def handle(self, req: dict) -> dict:
        """One request from `rvs select`: list what is online, or select (or plan) a device."""
        if req.get("op") == "list":
            targets = [{"line": t.line, "device": str(t.device), "node": t.node.name} for t in self.fleet.online()]
            return {"current": self.label(), "targets": targets}
        if req.get("op") == "select":
            target = self.fleet.find(Device.parse(req["device"]), req.get("node"), req.get("allow_offline"))
            if req.get("dry_run"):
                _, cfg, rule = self.plan(target)
                return {"current": self.label(), "plan": {"node": target.node.name, "rule": rule, "xray": cfg}}
            self.select(target, req.get("take_over"))
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
    SOCK.chmod(0o600)  # rvs's uid; the root shell reaches it anyway
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
    fleet: Fleet,
    first: Target | None = None,
    take_over: bool = False,
    need_first: bool = False,
) -> None:
    """Set up the network, select `first` (failing ends the session only with need_first), then run
    the shell as root. Everything is undone when the shell exits."""
    gw, dev = routing.preflight()
    session = Session(entry, opts, fleet)
    step = Steps()
    server = None
    stop_watch = threading.Event()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: sys.exit(0))
    try:
        routing.setup(step, gw, dev, opts.dns)
        server = _serve(session)
        if opts.check_interval > 0:
            threading.Thread(target=session.watch, args=(stop_watch,), daemon=True).start()
        if first:
            try:
                session.select(first, take_over)
            except RvsError as exc:
                if need_first:
                    raise
                print(f"Error: {exc}", file=sys.stderr)
        if not session.current:
            print("\nNo device selected: traffic is blocked. `rvs select` picks one.")
        print("'exit' tears the session down.\n")
        env = {**os.environ, "RVS_SOCK": str(SOCK)}
        subprocess.run([opts.shell], check=False, user=0, group=0, extra_groups=[], env=env)
    finally:
        stop_watch.set()
        if server:
            _unserve(server)  # no select starts after this; one already running holds the lock
        session.close()
        step.undo_all()
