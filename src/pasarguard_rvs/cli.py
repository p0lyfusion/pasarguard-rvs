"""rvs: shells through Pasarguard reverse-tunnel devices.

\b
  rvs devices          list the devices online on the panel's connected nodes
  rvs shell            fuzzy-pick one of them, get a shell whose traffic exits through it
  rvs shell -d 42.7    skip the picker
  rvs standalone --json   an xray client config for the device, to run anywhere
  rvs standalone --rule   the node routing rule that config needs (--hold: add it until Ctrl-C)

Every option also reads an RVS_* environment variable (shown in --help); a flag beats its variable.
"""

import json
import logging
import os
import sys
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

import click
import httpx

from . import targets
from .node import Device, NodeConfig, RvsError, hold_rule
from .panel import Panel
from .targets import Target
from .tunnel import SessionOptions, run_device_shell
from .xray import Entry, client_config, device_rule

log = logging.getLogger("pasarguard_rvs")
ENTRY, SESSION = Entry(), SessionOptions()  # the library's defaults are the CLI's defaults


@dataclass
class Ctx:
    panel_url: str | None
    admin: str | None
    password: str | None = field(repr=False)
    node_name: str | None
    node_config: Path | None

    @cached_property
    def panel(self) -> Panel:
        """Logged in on first use, so --help and the like never touch the panel."""
        given = {
            "--panel/RVS_PANEL": self.panel_url,
            "--admin/RVS_PANEL_ADMIN": self.admin,
            "--password/RVS_PANEL_PASSWORD": self.password,
        }
        if missing := [name for name, value in given.items() if not value]:
            raise click.UsageError("missing " + ", ".join(missing))
        try:
            panel = Panel(self.panel_url, self.admin, self.password)
        except httpx.HTTPError as exc:
            raise click.ClickException(f"panel login failed: {exc}") from exc
        return click.get_current_context().with_resource(panel)

    @cached_property
    def nodes(self) -> list[NodeConfig]:
        if self.node_config:
            return [NodeConfig.from_file(self.node_config)]
        if nodes := self.panel.nodes(self.node_name):
            return nodes
        raise click.ClickException(
            f"no connected gRPC node named {self.node_name!r}"
            if self.node_name
            else "the panel lists no connected gRPC nodes"
        )

    def online(self, user_id: int | None = None) -> list[Target]:
        return targets.online(self.panel, self.nodes, user_id)

    def target(self, device: Device | None, query: str, allow_offline: bool) -> Target:
        """From -d, or from the picker over what is online."""
        if device:
            return targets.find(self.panel, self.nodes, device, allow_offline)
        if not (online := self.online()):
            raise click.ClickException("no devices connected (or none of their users resolve in the panel)")
        return _pick(online, query)


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


TARGET_OPTIONS = _options(
    opt(
        "-d",
        "--device",
        callback=_device,
        env="RVS_DEVICE",
        help="user_id[.row_id] to use without the picker (no row_id = the shared tunnel)",
    ),
    opt("-q", "--query", default="", env="RVS_QUERY", help="pre-fill the fuzzy search"),
    opt(
        "--allow-offline",
        is_flag=True,
        env="RVS_ALLOW_OFFLINE",
        help="with -d: go ahead even if the device isn't connected (needs a single node, e.g. --node); "
        "traffic fails until it connects, then flows with nothing restarted",
    ),
)
ENTRY_OPTIONS = _options(
    opt(
        "--entry-encryption",
        "encryption",
        default=ENTRY.encryption,
        env="RVS_ENTRY_ENCRYPTION",
        help="client half of the entry inbound's VLESS encryption (`xray vlessenc`); "
        "Xray refuses plain VLESS to a public address",
    ),
    opt("--entry-host", "host", env="RVS_ENTRY_HOST", help="data-plane address [default: node address]"),
    opt("--entry-port", "port", default=ENTRY.port, env="RVS_ENTRY_PORT"),
    opt("--entry-tag", "tag", default=ENTRY.tag, env="RVS_ENTRY_TAG"),
)


@click.group(cls=_Group, context_settings={"show_default": True, "help_option_names": ["-h", "--help"]}, help=__doc__)
@opt("--panel", env="RVS_PANEL", help="panel URL")
@opt("--admin", env="RVS_PANEL_ADMIN", help="panel admin with users:read + nodes:read")
@opt("--password", env="RVS_PANEL_PASSWORD", help="prefer the env var: argv shows up in ps and shell history")
@opt("--node", "node_name", env="RVS_NODE", help="only this panel node (default: every connected gRPC node)")
@opt(
    "--node-config",
    env="RVS_NODE_CONFIG",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="JSON with address, port, api_key, server_ca: use this node instead of the panel's list",
)
@click.pass_context
def main(ctx: click.Context, panel, admin, password, node_name, node_config):
    logging.basicConfig(level=logging.INFO, format="  %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # no per-request lines
    ctx.obj = Ctx(panel, admin, password, node_name, node_config)


@main.command()
@opt("--user", "user_id", type=int, env="RVS_USER", help="only this user id")
@opt("--json", "as_json", is_flag=True, help="emit JSON instead of a table")
@click.pass_obj
def devices(c: Ctx, user_id: int | None, as_json: bool):
    """List devices online now (read-only; tunnels untouched). IPs are ingress, not egress."""
    online = c.online(user_id)
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
            click.echo(_line(t))


@main.command()
@TARGET_OPTIONS
@ENTRY_OPTIONS
@opt("--mtu", default=SESSION.mtu, env="RVS_MTU")
@opt("--dns", default=SESSION.dns, env="RVS_DNS", help="resolver the shell uses, reached through the device")
@opt(
    "--shell",
    "shell_cmd",
    default=lambda: SessionOptions().shell,
    env="RVS_SHELL",
    show_default="$SHELL or /bin/bash",
)
@opt("--dry-run", is_flag=True, env="RVS_DRY_RUN", help="print every command and the xray config, change nothing")
@click.pass_obj
def shell(c: Ctx, device, query, allow_offline, mtu, dns, shell_cmd, dry_run, **entry):
    """Get a shell whose traffic exits through a device. Needs NET_ADMIN and /dev/net/tun."""
    if not dry_run and (os.geteuid() != 0 or not Path("/dev/net/tun").exists()):
        raise click.ClickException("needs root in a container with NET_ADMIN and /dev/net/tun (try --dry-run)")
    target = c.target(device, query, allow_offline)
    run_device_shell(target, Entry(**entry), SessionOptions(mtu, dns, shell_cmd, dry_run))


@main.command()
@TARGET_OPTIONS
@ENTRY_OPTIONS
@opt("--json", "as_json", is_flag=True, help="print an xray client config (SOCKS5 + HTTP on 127.0.0.1)")
@opt("--rule", "as_rule", is_flag=True, help="print the node routing rule that config needs")
@opt("--hold", is_flag=True, help="with --rule: add it on the node instead, and remove it on Ctrl-C")
@opt("--socks-port", default=10808, env="RVS_SOCKS_PORT", help="--json: SOCKS5 port; HTTP is the next one")
@opt(
    "-o", "--output", type=click.File("w"), default="-", help="where --json/--rule go (a file keeps the picker usable)"
)
@click.pass_obj
def standalone(c: Ctx, device, query, allow_offline, as_json, as_rule, hold, socks_port, output, **entry):
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
    target = c.target(device, query, allow_offline)
    log.info("device %s on node %s", target.device, target.node.name)
    entry = Entry(**entry)
    rule = device_rule(target.device, entry.tag)
    if hold:
        hold_rule(target.node, rule)
        return
    if as_json:
        doc = client_config(target.user.main_uuid, entry.host or target.node.address, entry, socks_port)
    else:
        doc = rule
    output.write(json.dumps(doc, indent=2) + "\n")


def _line(t: Target) -> str:
    return f"{t.user.username}  {t.device}  {t.node.name}  {', '.join(sorted(t.ips))}"


def _pick(online: list[Target], query: str) -> Target:
    from InquirerPy import inquirer
    from InquirerPy.base.control import Choice

    if not sys.stdout.isatty():
        raise click.ClickException("the picker needs a terminal on stdout: give -d, or -o FILE")
    # The value is the list index: InquirerPy hands back an object value as a dict, not the object.
    try:
        index = inquirer.fuzzy(
            message="device (username  uid.row  node  ingress IPs):",
            choices=[Choice(value=i, name=_line(t)) for i, t in enumerate(online)],
            default=query,
        ).execute()
    except KeyboardInterrupt:
        index = None
    if index is None:
        raise click.ClickException("nothing selected")
    return online[index]
