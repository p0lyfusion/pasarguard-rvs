"""rvs: shells through Pasarguard reverse-tunnel devices.

\b
  rvs devices          list the devices online on the panel's connected nodes
  rvs session          the container's entrypoint: a shell whose traffic exits through a device
  rvs select           inside it: fuzzy-pick the device (again, to move to another one)
  rvs select -d 42.7   skip the picker (rvs session -d 42.7: start on that device)
  rvs standalone --json   an xray client config for the device, to run anywhere
  rvs standalone --rule   the node routing rule that config needs (--hold: add it until Ctrl-C)

Every option also reads an RVS_* environment variable (shown in --help); a flag beats its variable.
The entry inbound's address, port and tag are environment-only: RVS_ENTRY_HOST (default: the
node's address), RVS_ENTRY_PORT (10900), RVS_ENTRY_TAG (RVS_ENTRY).
"""

import json
import logging
import os
import secrets
import socket
import sys
from dataclasses import dataclass, field, replace

import click
import httpx

from . import routing
from .node import Device, RvsError, hold_rule
from .session import SessionOptions, run_session
from .targets import Fleet, Target
from .xray import Entry, client_config, device_rule

log = logging.getLogger("pasarguard_rvs")
ENTRY, SESSION = Entry(), SessionOptions()  # the library's defaults are the CLI's defaults


@dataclass
class Ctx:
    panel_url: str | None
    admin: str | None
    password: str | None = field(repr=False)
    node_name: str | None

    def fleet(self) -> Fleet:
        given = {
            "--panel/RVS_PANEL": self.panel_url,
            "--admin/RVS_PANEL_ADMIN": self.admin,
            "--password/RVS_PANEL_PASSWORD": self.password,
        }
        if missing := [name for name, value in given.items() if not value]:
            raise click.UsageError("missing " + ", ".join(missing))
        return Fleet(self.panel_url, self.admin, self.password, self.node_name)


def _target(fleet: Fleet, device: Device | None, query: str, allow_offline: bool) -> Target:
    """From -d, or from the picker over what is online."""
    if device:
        return fleet.find(device, allow_offline=allow_offline)
    if not (online := fleet.online()):
        raise click.ClickException("no devices connected (or none of their users resolve in the panel)")
    return online[_pick([t.line for t in online], query, "device (username  uid.row  node  ingress IPs):")]


class _Group(click.Group):
    """Turns library errors into a clean one-line CLI error, once for every command."""

    def invoke(self, ctx: click.Context):
        try:
            return super().invoke(ctx)
        except (httpx.HTTPError, RvsError, OSError) as exc:
            raise click.ClickException(str(exc)) from exc


def _device(ctx, param, value: str | None) -> Device | None:
    try:
        return Device.parse(value) if value else None
    except ValueError:
        raise click.BadParameter(f"{value!r} is not user_id[.row_id]") from None


def opt(*decls, env: str | None = None, **kw):
    """click.option, with `env` as its RVS_* variable shown in --help."""
    if env:
        kw |= {"envvar": env, "show_envvar": True}
    return click.option(*decls, **kw)


def _options(*decorators):
    """Several options as one decorator, for options shared between commands."""

    def apply(f):
        for decorator in reversed(decorators):
            f = decorator(f)
        return f

    return apply


def target_options(env: bool):
    """-d / -q / --allow-offline. `rvs select` has no env vars: the shell inherits the session's."""

    def var(name: str) -> str | None:
        return name if env else None

    return _options(
        opt(
            "-d",
            "--device",
            callback=_device,
            env=var("RVS_DEVICE"),
            help="user_id[.row_id] to use without the picker (no row_id = the shared tunnel)",
        ),
        opt("-q", "--query", default="", env=var("RVS_QUERY"), help="pre-fill the fuzzy search"),
        opt(
            "--allow-offline",
            is_flag=True,
            env=var("RVS_ALLOW_OFFLINE"),
            help="with -d: go ahead even if the device isn't connected (needs a single node, e.g. --node); "
            "traffic fails until it connects, then flows with nothing restarted",
        ),
    )


TAKE_OVER_HELP = (
    "replace another rvs rule routing the same user on that node (a session that didn't exit cleanly; "
    "a live one is cut off and blocks its traffic)"
)
ENTRY_OPTION = opt(
    "--entry-encryption",
    "encryption",
    default=ENTRY.encryption,
    env="RVS_ENTRY_ENCRYPTION",
    help="client half of the entry inbound's VLESS encryption (`xray vlessenc`); "
    "Xray refuses plain VLESS to a public address",
)


def _entry(encryption: str) -> Entry:
    """--entry-encryption plus the environment-only RVS_ENTRY_HOST / RVS_ENTRY_PORT / RVS_ENTRY_TAG."""
    port = os.environ.get("RVS_ENTRY_PORT") or str(ENTRY.port)
    if not port.isdigit():
        raise click.UsageError(f"RVS_ENTRY_PORT={port!r} is not a port number")
    host, tag = os.environ.get("RVS_ENTRY_HOST") or None, os.environ.get("RVS_ENTRY_TAG") or ENTRY.tag
    return Entry(encryption, host, int(port), tag)


@click.group(cls=_Group, context_settings={"show_default": True, "help_option_names": ["-h", "--help"]}, help=__doc__)
@opt("--panel", env="RVS_PANEL", help="panel URL")
@opt("--admin", env="RVS_PANEL_ADMIN", help="panel admin with users:read + nodes:read")
@opt("--password", env="RVS_PANEL_PASSWORD", help="prefer the env var: argv shows up in ps and shell history")
@opt("--node", "node_name", env="RVS_NODE", help="only this panel node (default: every connected gRPC node)")
@click.pass_context
def main(ctx: click.Context, panel, admin, password, node_name):
    logging.basicConfig(level=logging.INFO, format="  %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # no per-request lines
    ctx.obj = Ctx(panel, admin, password, node_name)


@main.command()
@opt("--user", "user_id", type=int, env="RVS_USER", help="only this user id")
@opt("--json", "as_json", is_flag=True, help="emit JSON instead of a table")
@click.pass_obj
def devices(c: Ctx, user_id: int | None, as_json: bool):
    """List devices online now (read-only; tunnels untouched). IPs are ingress, not egress."""
    online = c.fleet().online(user_id)
    if as_json:
        rows = [
            {
                "node": t.node.name,
                "device": str(t.device),
                "user_id": t.device.user_id,
                "row_id": t.device.row_id,
                "username": t.user.username,
                "ips": sorted(t.ips),
                "last_seen": max(t.ips.values(), default=0),
            }
            for t in online
        ]
        click.echo(json.dumps(rows, indent=2))
    elif not online:
        click.echo("no devices connected", err=True)
    else:
        for t in online:
            click.echo(t.line)


@main.command()
@target_options(env=True)
@ENTRY_OPTION
@opt("--mtu", default=SESSION.mtu, env="RVS_MTU")
@opt("--dns", default=SESSION.dns, env="RVS_DNS", help="resolver the shell uses, reached through the device")
@opt("--shell", "shell_cmd", default=lambda: SessionOptions().shell, env="RVS_SHELL", show_default="$SHELL or /bin/bash")
@opt("--take-over", is_flag=True, env="RVS_TAKE_OVER", help="for the first device: " + TAKE_OVER_HELP)
@opt(
    "--check-interval",
    type=float,
    default=SESSION.check_interval,
    env="RVS_CHECK_INTERVAL",
    help="seconds between checks that the node still routes to the device (traffic is blocked if not); 0: off",
)
@click.pass_obj
def session(c: Ctx, device, query, allow_offline, encryption, mtu, dns, shell_cmd, take_over, check_interval):
    """The container's entrypoint: a shell whose traffic exits through the device `rvs select` picks.

    Needs NET_ADMIN, /dev/net/tun and the image's entrypoint (which runs rvs as its own uid).
    Everything the shell runs goes through the device, the panel and every node included; only
    xray's link to the entry and rvs's own panel/node calls go direct. It starts with the picker
    (-d: that device, or no session; no terminal: none); until a device is selected, traffic is
    blocked.
    """
    routing.preflight()  # before the picker, not after
    entry, fleet = _entry(encryption), c.fleet()
    if entry.host:
        # one fixed entry reaches one node: a device elsewhere would exit at that node, by its own
        # rules, and not at the device
        if len(nodes := fleet.nodes()) > 1:
            raise click.UsageError("RVS_ENTRY_HOST is one node's entry: pick that node with --node / RVS_NODE")
        fleet = replace(fleet, node_name=nodes[0].name)
    first = None
    if device or sys.stdout.isatty():
        try:
            first = _target(fleet, device, query, allow_offline)
        except (click.ClickException, RvsError) as exc:
            if device:
                raise
            click.echo(f"Error: {exc}", err=True)
    opts = SessionOptions(mtu, dns, shell_cmd, check_interval)
    run_session(entry, opts, fleet, first, take_over, need_first=device is not None)


@main.command()
@target_options(env=False)
@opt("--dry-run", is_flag=True, help="print the node rule and xray config it would use, change nothing")
@opt("--take-over", is_flag=True, help=TAKE_OVER_HELP)
def select(device, query, allow_offline, dry_run, take_over):
    """Inside `rvs session`: exit through this device from now on (restarts the tunnel).

    Devices are found on the session's nodes (its --node / RVS_NODE). Open connections drop. If the
    device can't be found, the current one stays; if it is found but can't be brought up, traffic
    stays blocked until a select succeeds.

    Refused while another rvs rule routes the same user on that node (the node can't tell two
    sessions of one user apart): pick another user's device, or --take-over. While the session runs
    it keeps checking that the node routes to the device, and blocks traffic if it stops.
    """
    if not (sock := os.environ.get("RVS_SOCK")):
        raise click.ClickException("not inside an rvs session (no RVS_SOCK)")
    node_name = None
    if device is None:
        listed = _control(sock, {"op": "list"})
        if not listed["targets"]:
            raise click.ClickException("no devices connected (or none of their users resolve in the panel)")
        now = listed["current"] or "none"
        lines = [t["line"] for t in listed["targets"]]
        pick = listed["targets"][_pick(lines, query, f"device (now: {now}; username  uid.row  node  ingress IPs):")]
        device, node_name = pick["device"], pick["node"]
    request = {
        "op": "select",
        "device": str(device),
        "node": node_name,
        "allow_offline": allow_offline,
        "dry_run": dry_run,
        "take_over": take_over,
    }
    if dry_run:
        click.echo(json.dumps(_control(sock, request)["plan"], indent=2))
        return
    click.echo(f"selecting {device}...", err=True)
    click.echo(f"traffic now exits device {_control(sock, request)['current']}", err=True)


def _control(sock: str, request: dict) -> dict:
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(sock)
        s.sendall((json.dumps(request) + "\n").encode())
        reply = json.loads(s.makefile().readline() or "{}")
    if "error" in reply or not reply:
        current = reply.get("current")
        raise click.ClickException(
            reply.get("error", "no reply from the session")
            + (f" (still on {current})" if current else " (no device now: traffic is blocked)")
        )
    return reply


@main.command()
@target_options(env=True)
@ENTRY_OPTION
@opt("--json", "as_json", is_flag=True, help="print an xray client config (SOCKS5 + HTTP on 127.0.0.1)")
@opt("--rule", "as_rule", is_flag=True, help="print the node routing rule that config needs")
@opt("--hold", is_flag=True, help="with --rule: add it on the node instead, and remove it on Ctrl-C")
@opt("--take-over", is_flag=True, help="with --hold: " + TAKE_OVER_HELP)
@opt("--socks-port", default=10808, env="RVS_SOCKS_PORT", help="--json: SOCKS5 port; HTTP is the next one")
@opt(
    "-o", "--output", type=click.File("w"), default="-", help="where --json/--rule go (a file keeps the picker usable)"
)
@click.pass_obj
def standalone(
    c: Ctx, device, query, allow_offline, encryption, as_json, as_rule, hold, take_over, socks_port, output
):
    """No local tunnel: the pieces to reach a device from your own xray.

    \b
      --json          client config: run it with `xray run -c`, then use socks5h://127.0.0.1:10808
      --rule          the rule for the node's routing, ahead of any rule matching the entry inbound
      --rule --hold   add that rule over the node API for as long as this runs

    Without the rule the node routes the entry traffic by its own rules, so the config then exits at
    the node (or wherever those rules send it), not at the device.
    """
    if as_json == as_rule:
        raise click.UsageError("give exactly one of --json, --rule")
    if hold and not as_rule:
        raise click.UsageError("--hold goes with --rule")
    if take_over and not hold:
        raise click.UsageError("--take-over goes with --hold")
    target = _target(c.fleet(), device, query, allow_offline)
    log.info("device %s on node %s", target.device, target.node.name)
    entry = _entry(encryption)
    if hold:
        # held rules get an owner id, like a session's: removing it never removes someone else's
        hold_rule(target.node, device_rule(target.device, entry.tag, secrets.token_hex(3)), take_over)
        return
    if as_json:
        doc = client_config(target.user.main_uuid, entry.address(target.node), entry, socks_port)
    else:
        doc = device_rule(target.device, entry.tag)
    output.write(json.dumps(doc, indent=2) + "\n")


def _pick(lines: list[str], query: str, message: str) -> int:
    from InquirerPy import inquirer
    from InquirerPy.base.control import Choice

    if not sys.stdout.isatty():
        raise click.ClickException("the picker needs a terminal on stdout: give -d, or -o FILE")
    # The value is the list index: InquirerPy hands back an object value as a dict, not the object.
    try:
        index = inquirer.fuzzy(
            message=message,
            choices=[Choice(value=i, name=line) for i, line in enumerate(lines)],
            default=query,
        ).execute()
    except KeyboardInterrupt:
        index = None
    if index is None:
        raise click.ClickException("nothing selected")
    return index
