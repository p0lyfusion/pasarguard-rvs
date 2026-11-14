"""rvs: shells through Pasarguard reverse-tunnel devices.

\b
  rvs devices          list the devices online on the panel's connected nodes
  rvs shell            fuzzy-pick one of them, get a shell whose traffic exits through it
  rvs shell -d 42.7    skip the picker
  rvs standalone --json   an xray client config for the device, to run anywhere
  rvs standalone --rule   the node routing rule that config needs (--hold: add it until Ctrl-C)

Every option also reads an RVS_* environment variable (shown in --help); a flag beats its variable.
"""

import asyncio
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

import click
import httpx

from .node import Device, NodeConfig, NodeError, hold_routing_rule, online_devices
from .panel import Panel, PanelUser
from .tunnel import SessionOptions, TunnelError, client_config, run_device_shell, session_rule

log = logging.getLogger("pasarguard_rvs")
DEFAULTS = SessionOptions()  # the library's defaults are the CLI's defaults
PANEL_LOOKUPS = 16  # concurrent user lookups


@dataclass(frozen=True)
class Online:
    node: NodeConfig
    device: Device
    ips: dict[str, int]
    user: PanelUser


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
        missing = [
            n
            for n, v in (
                ("--panel/RVS_PANEL", self.panel_url),
                ("--admin/RVS_PANEL_ADMIN", self.admin),
                ("--password/RVS_PANEL_PASSWORD", self.password),
            )
            if not v
        ]
        if missing:
            raise click.UsageError("missing " + ", ".join(missing))
        try:
            panel = Panel(self.panel_url, self.admin, self.password)
        except httpx.HTTPError as exc:
            raise click.ClickException(f"panel login failed: {exc}") from exc
        return click.get_current_context().with_resource(panel)

    def nodes(self) -> list[NodeConfig]:
        if self.node_config:
            return [NodeConfig.from_file(self.node_config)]
        nodes = self.panel.nodes(self.node_name)
        if not nodes:
            raise click.ClickException(
                f"no connected gRPC node named {self.node_name!r}"
                if self.node_name
                else "the panel lists no connected gRPC nodes"
            )
        return nodes

    def online(self, user_id: int | None = None) -> list[Online]:
        """Every device online on any selected node whose user resolves in the panel."""
        nodes = self.nodes()
        results = asyncio.run(_gather(online_devices(n) for n in nodes))
        found: list[tuple[NodeConfig, Device, dict]] = []
        for node, res in zip(nodes, results):
            if isinstance(res, BaseException):
                log.warning("node %s (%s:%s): %s", node.name, node.address, node.port, res)
            else:
                found += [(node, d, ips) for d, ips in res.items() if user_id in (None, d.user_id)]
        uids = sorted({d.user_id for _, d, _ in found})
        with ThreadPoolExecutor(PANEL_LOOKUPS) as pool:
            users = dict(zip(uids, pool.map(self._user, uids)))
        if unresolved := [uid for uid in uids if not users[uid]]:
            log.warning("users without a VLESS id in the panel (left out): %s", ", ".join(map(str, unresolved)))
        # a user gone from the panel, or without a VLESS id, can't authenticate the entry
        return sorted(
            (Online(n, d, ips, users[d.user_id]) for n, d, ips in found if users.get(d.user_id)),
            key=lambda o: (o.device, o.node.name),
        )

    def _user(self, uid: int) -> PanelUser | None:
        try:
            return self.panel.user(uid)
        except httpx.HTTPError as exc:
            log.warning("panel lookup for user %s failed: %s", uid, exc)
            return None


async def _gather(coros):
    return await asyncio.gather(*coros, return_exceptions=True)


def _line(o: Online) -> str:
    return f"{o.user.username}  {o.device}  {o.node.name}  {', '.join(sorted(o.ips))}"


class _Group(click.Group):
    """Turns library errors into a clean one-line CLI error, once for every command."""

    def invoke(self, ctx: click.Context):
        try:
            return super().invoke(ctx)
        except (httpx.HTTPError, NodeError, TunnelError, OSError) as exc:
            raise click.ClickException(str(exc)) from exc


def _device(ctx, param, value: str | None) -> Device | None:
    try:
        return Device.parse(value) if value else None
    except ValueError:
        raise click.BadParameter(f"{value!r} is not user_id[.row_id]") from None


@click.group(cls=_Group, context_settings={"show_default": True, "help_option_names": ["-h", "--help"]}, help=__doc__)
@click.option("--panel", envvar="RVS_PANEL", show_envvar=True, help="panel URL")
@click.option("--admin", envvar="RVS_PANEL_ADMIN", show_envvar=True, help="panel admin with users:read + nodes:read")
@click.option(
    "--password",
    envvar="RVS_PANEL_PASSWORD",
    show_envvar=True,
    help="prefer the env var: argv shows up in ps and shell history",
)
@click.option(
    "--node",
    "node_name",
    envvar="RVS_NODE",
    show_envvar=True,
    help="only this panel node (default: every connected gRPC node)",
)
@click.option(
    "--node-config",
    envvar="RVS_NODE_CONFIG",
    show_envvar=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="JSON with address, port, api_key, server_ca: use this node instead of the panel's list",
)
@click.pass_context
def main(ctx: click.Context, panel, admin, password, node_name, node_config):
    logging.basicConfig(level=logging.INFO, format="  %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # no per-request lines
    ctx.obj = Ctx(panel, admin, password, node_name, node_config)


@main.command()
@click.option("--user", "user_id", type=int, envvar="RVS_USER", show_envvar=True, help="only this user id")
@click.option("--json", "as_json", is_flag=True, help="emit JSON instead of a table")
@click.pass_obj
def devices(c: Ctx, user_id: int | None, as_json: bool):
    """List devices online now (read-only; tunnels untouched). IPs are ingress, not egress."""
    rows = c.online(user_id)
    if as_json:
        click.echo(
            json.dumps(
                [
                    {
                        "node": o.node.name,
                        "device": str(o.device),
                        "user_id": o.device.user_id,
                        "row_id": o.device.row_id,
                        "username": o.user.username,
                        "ips": sorted(o.ips),
                        "last_seen": max(o.ips.values(), default=0),
                    }
                    for o in rows
                ],
                indent=2,
            )
        )
    elif not rows:
        click.echo("no devices connected", err=True)
    else:
        for o in rows:
            click.echo(_line(o))


def _options(*opts):
    def apply(f):
        for o in reversed(opts):
            f = o(f)
        return f

    return apply


SELECT_OPTIONS = _options(
    click.option(
        "-d",
        "--device",
        envvar="RVS_DEVICE",
        show_envvar=True,
        callback=_device,
        help="user_id[.row_id] to use without the picker (no row_id = the shared tunnel)",
    ),
    click.option("-q", "--query", default="", envvar="RVS_QUERY", show_envvar=True, help="pre-fill the fuzzy search"),
    click.option(
        "--allow-offline",
        is_flag=True,
        envvar="RVS_ALLOW_OFFLINE",
        show_envvar=True,
        help="with -d: go ahead even if the device isn't connected (needs a single node, e.g. --node); "
        "traffic fails until it connects, then flows with nothing restarted",
    ),
)
ENTRY_OPTIONS = _options(
    click.option(
        "--entry-encryption",
        default=DEFAULTS.entry_encryption,
        envvar="RVS_ENTRY_ENCRYPTION",
        show_envvar=True,
        help="client half of the entry inbound's VLESS encryption (`xray vlessenc`); "
        "Xray refuses plain VLESS to a public address",
    ),
    click.option(
        "--entry-host", envvar="RVS_ENTRY_HOST", show_envvar=True, help="data-plane address [default: node address]"
    ),
    click.option("--entry-port", default=DEFAULTS.entry_port, envvar="RVS_ENTRY_PORT", show_envvar=True),
    click.option("--entry-tag", default=DEFAULTS.entry_tag, envvar="RVS_ENTRY_TAG", show_envvar=True),
)


def _select(c: Ctx, device: Device | None, query: str, allow_offline: bool) -> tuple[NodeConfig, Device, str]:
    """(node, device, main uuid) from -d, or from the picker over the online devices."""
    if device is None:
        online = c.online()
        if not online:
            raise click.ClickException("no devices connected (or none of their users resolve in the panel)")
        chosen = _pick(online, query)
        if chosen is None:
            raise click.ClickException("nothing selected")
        return chosen.node, chosen.device, chosen.user.main_uuid
    # A device account shows up in the nodes' online stats; the shared tunnel (no row) does not.
    found = [o for o in c.online(device.user_id) if o.device == device] if device.row_id is not None else []
    if found:
        return found[0].node, device, found[0].user.main_uuid
    if device.row_id is not None and not allow_offline:
        raise click.ClickException(
            f"device {device} is not connected to any selected node; "
            "--allow-offline goes ahead anyway (traffic fails until it connects)"
        )
    nodes = c.nodes()
    if len(nodes) > 1:
        raise click.ClickException("several connected nodes; pick one with --node: " + ", ".join(n.name for n in nodes))
    user = c.panel.user(device.user_id)
    if user is None:
        raise click.ClickException(f"user {device.user_id} has no VLESS id in the panel")
    return nodes[0], device, user.main_uuid


@main.command()
@SELECT_OPTIONS
@ENTRY_OPTIONS
@click.option("--mtu", default=DEFAULTS.mtu, envvar="RVS_MTU", show_envvar=True)
@click.option(
    "--dns",
    default=DEFAULTS.dns,
    envvar="RVS_DNS",
    show_envvar=True,
    help="resolver the shell uses, reached through the device",
)
@click.option(
    "--shell",
    "shell_cmd",
    default=lambda: SessionOptions().shell,
    envvar="RVS_SHELL",
    show_envvar=True,
    show_default="$SHELL or /bin/bash",
)
@click.option(
    "--dry-run",
    is_flag=True,
    envvar="RVS_DRY_RUN",
    show_envvar=True,
    help="print every command and the xray config, change nothing",
)
@click.pass_obj
def shell(c: Ctx, device, query: str, allow_offline: bool, shell_cmd: str, dry_run: bool, **entry):
    """Get a shell whose traffic exits through a device. Needs NET_ADMIN and /dev/net/tun."""
    if not dry_run and (os.geteuid() != 0 or not Path("/dev/net/tun").exists()):
        raise click.ClickException("needs root in a container with NET_ADMIN and /dev/net/tun (try --dry-run)")
    opts = SessionOptions(shell=shell_cmd, dry_run=dry_run, **entry)
    node, dev, main_uuid = _select(c, device, query, allow_offline)
    run_device_shell(node, dev, main_uuid, opts)


@main.command()
@SELECT_OPTIONS
@ENTRY_OPTIONS
@click.option("--json", "as_json", is_flag=True, help="print an xray client config (SOCKS5 + HTTP on 127.0.0.1)")
@click.option("--rule", "as_rule", is_flag=True, help="print the node routing rule that config needs")
@click.option("--hold", is_flag=True, help="with --rule: add it on the node instead, and remove it on Ctrl-C")
@click.option(
    "--socks-port",
    default=10808,
    envvar="RVS_SOCKS_PORT",
    show_envvar=True,
    help="--json: SOCKS5 port; HTTP is the next one",
)
@click.option(
    "-o", "--output", type=click.File("w"), default="-", help="where --json/--rule go (a file keeps the picker usable)"
)
@click.pass_obj
def standalone(
    c: Ctx,
    device,
    query: str,
    allow_offline: bool,
    as_json: bool,
    as_rule: bool,
    hold: bool,
    socks_port: int,
    output,
    **entry,
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
    opts = SessionOptions(**entry)
    node, dev, main_uuid = _select(c, device, query, allow_offline)
    rule = session_rule(dev, opts.entry_tag)
    log.info("device %s on node %s", dev, node.name)
    if hold:
        asyncio.run(hold_routing_rule(node, rule))
        return
    doc = client_config(main_uuid, opts.entry_host or node.address, opts, socks_port) if as_json else rule
    output.write(json.dumps(doc, indent=2) + "\n")
    output.flush()


def _pick(online: list[Online], query: str) -> Online | None:
    from InquirerPy import inquirer
    from InquirerPy.base.control import Choice

    if not sys.stdout.isatty():
        raise click.ClickException("the picker needs a terminal on stdout: give -d, or -o FILE")
    # The value is the list index: InquirerPy hands back an object value as a dict, not the object.
    try:
        index = inquirer.fuzzy(
            message="device (username  uid.row  node  ingress IPs):",
            choices=[Choice(value=i, name=_line(o)) for i, o in enumerate(online)],
            default=query,
        ).execute()
    except KeyboardInterrupt:
        return None
    return None if index is None else online[index]
