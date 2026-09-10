"""Fabric REST client for OneLake data access roles.

Note the API contract: PUT dataAccessRoles REPLACES the item's entire role set
("creates, updates, or deletes roles to match the provided payload"), so callers
must always send unmanaged roles back verbatim. Etag concurrency via If-Match.
"""

from __future__ import annotations

import logging

import httpx

from ..auth import FABRIC_SCOPE, TokenProvider
from ..http_util import authorized_request

logger = logging.getLogger(__name__)

BASE_URL = "https://api.fabric.microsoft.com/v1"


def _quote_etag(etag: str | None) -> str | None:
    if etag is None:
        return None
    etag = etag.strip()
    return etag if etag.startswith('"') else f'"{etag}"'


class FabricClient:
    def __init__(self, token_provider: TokenProvider):
        self._tokens = token_provider
        self._http = httpx.Client(timeout=httpx.Timeout(120.0, connect=30.0))

    def close(self) -> None:
        self._http.close()

    def _request(self, method: str, path_or_url: str, *, headers: dict | None = None,
                 params: dict | None = None, json: object | None = None) -> httpx.Response:
        url = path_or_url if path_or_url.startswith("http") else f"{BASE_URL}{path_or_url}"
        return authorized_request(
            self._http, method, url,
            token_provider=self._tokens, scope=FABRIC_SCOPE,
            headers=headers, params=params, json=json,
        )

    def get_item(self, workspace_id: str, item_id: str) -> dict:
        return self._request("GET", f"/workspaces/{workspace_id}/items/{item_id}").json()

    def get_data_access_roles(self, workspace_id: str, item_id: str) -> tuple[list[dict], str | None]:
        roles: list[dict] = []
        url = f"/workspaces/{workspace_id}/items/{item_id}/dataAccessRoles"
        etag: str | None = None
        while url:
            response = self._request("GET", url)
            etag = response.headers.get("ETag") or response.headers.get("Etag") or etag
            payload = response.json()
            roles.extend(payload.get("value", []))
            url = payload.get("continuationUri")
        return roles, etag

    def put_data_access_roles(
        self,
        workspace_id: str,
        item_id: str,
        roles: list[dict],
        etag: str | None = None,
        dry_run: bool = False,
    ) -> str | None:
        headers: dict = {}
        quoted = _quote_etag(etag)
        if quoted:
            headers["If-Match"] = quoted
        response = self._request(
            "PUT",
            f"/workspaces/{workspace_id}/items/{item_id}/dataAccessRoles",
            headers=headers,
            params={"dryRun": "true"} if dry_run else None,
            json={"value": roles},
        )
        return response.headers.get("ETag") or response.headers.get("Etag")
