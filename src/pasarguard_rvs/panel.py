"""Panel side: admin login, node connection details, user lookups.

The admin needs users:read and nodes:read. nodes:read returns every node's api_key, so this
login is effectively full control of all nodes.
"""

import logging
from dataclasses import dataclass
from typing import Self

import httpx

from .node import NodeConfig

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PanelUser:
    id: int
    username: str
    main_uuid: str  # VLESS id; authenticates the data plane to the entry inbound


class Panel:
    def __init__(self, url: str, admin: str, password: str, timeout: float = 30):
        self._http = httpx.Client(base_url=url.rstrip("/"), timeout=timeout)
        resp = self._http.post("/api/admin/token", data={"username": admin, "password": password})
        resp.raise_for_status()
        self._http.headers["Authorization"] = f"Bearer {resp.json()['access_token']}"

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def _get(self, path: str, **params) -> dict:
        resp = self._http.get(path, params=params)
        resp.raise_for_status()
        return resp.json()

    def nodes(self, name: str | None = None) -> list[NodeConfig]:
        """Connected gRPC nodes (optionally only the one called `name`) with their credentials."""
        out = []
        for n in self._get("/api/nodes", status="connected")["nodes"]:
            if name and n["name"] != name:
                continue
            if n.get("connection_type") != "grpc":
                log.warning(
                    "skipping node %s: %s connection, only grpc is supported", n["name"], n.get("connection_type")
                )
                continue
            if not n.get("api_key"):
                log.warning("skipping node %s: panel returned no api_key", n["name"])
                continue
            out.append(
                NodeConfig(
                    name=n["name"],
                    address=n["address"],
                    port=n["port"],
                    api_key=n["api_key"],
                    server_ca=n["server_ca"],
                )
            )
        return out

    def user(self, user_id: int) -> PanelUser | None:
        """The user, or None when it has no VLESS id (it could not authenticate the entry)."""
        u = self._get(f"/api/user/by-id/{user_id}")
        main = ((u.get("proxy_settings") or {}).get("vless") or {}).get("id")
        return PanelUser(user_id, u.get("username") or str(user_id), main) if main else None
