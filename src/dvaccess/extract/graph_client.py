"""Microsoft Graph client: resolves Entra-group team membership and manages the
per-profile security groups.

Application permissions required (admin consent):
- GroupMember.Read.All  (resolve transitive members of Entra-group teams)
- Group.ReadWrite.All   (create and reconcile per-profile security groups)
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator

import httpx

from ..auth import GRAPH_SCOPE, TokenProvider
from ..http_util import authorized_request

logger = logging.getLogger(__name__)

BASE_URL = "https://graph.microsoft.com/v1.0"
_BIND_BATCH = 20  # max members@odata.bind entries per PATCH


class GraphClient:
    def __init__(self, token_provider: TokenProvider):
        self._tokens = token_provider
        self._http = httpx.Client(timeout=httpx.Timeout(60.0, connect=30.0))

    def close(self) -> None:
        self._http.close()

    def _request(self, method: str, path_or_url: str, *, params: dict | None = None,
                 json: object | None = None) -> httpx.Response:
        url = path_or_url if path_or_url.startswith("http") else f"{BASE_URL}{path_or_url}"
        return authorized_request(
            self._http, method, url,
            token_provider=self._tokens, scope=GRAPH_SCOPE,
            headers={"Accept": "application/json"}, params=params, json=json,
        )

    def _get_paged(self, path: str, params: dict | None = None) -> Iterator[dict]:
        payload = self._request("GET", path, params=params).json()
        while True:
            yield from payload.get("value", [])
            next_link = payload.get("@odata.nextLink")
            if not next_link:
                return
            payload = self._request("GET", next_link).json()

    # ---------------------------------------------------- team resolution

    def transitive_user_member_ids(self, group_object_id: str) -> set[str]:
        """All user object ids in a group, nested groups flattened."""
        return {
            row["id"]
            for row in self._get_paged(
                f"/groups/{group_object_id}/transitiveMembers/microsoft.graph.user",
                {"$select": "id", "$top": "999"},
            )
        }

    # ------------------------------------------------- profile group admin

    def find_group_id(self, display_name: str) -> str | None:
        escaped = display_name.replace("'", "''")
        rows = list(
            self._get_paged("/groups", {"$filter": f"displayName eq '{escaped}'", "$select": "id"})
        )
        if len(rows) > 1:
            raise RuntimeError(f"Multiple Entra groups named {display_name!r}; refusing to guess.")
        return rows[0]["id"] if rows else None

    def create_security_group(self, display_name: str, description: str) -> str:
        mail_nickname = re.sub(r"[^A-Za-z0-9]", "", display_name)[:60] or "dvaccess"
        response = self._request(
            "POST", "/groups",
            json={
                "displayName": display_name,
                "description": description[:1024],
                "mailEnabled": False,
                "mailNickname": mail_nickname,
                "securityEnabled": True,
            },
        )
        group_id = response.json()["id"]
        logger.info("Created Entra security group %s (%s)", display_name, group_id)
        return group_id

    def list_member_ids(self, group_id: str) -> set[str]:
        return {
            row["id"]
            for row in self._get_paged(f"/groups/{group_id}/members", {"$select": "id", "$top": "999"})
        }

    def add_members(self, group_id: str, member_ids: list[str]) -> None:
        for start in range(0, len(member_ids), _BIND_BATCH):
            chunk = member_ids[start:start + _BIND_BATCH]
            self._request(
                "PATCH", f"/groups/{group_id}",
                json={
                    "members@odata.bind": [
                        f"{BASE_URL}/directoryObjects/{mid}" for mid in chunk
                    ]
                },
            )

    def remove_member(self, group_id: str, member_id: str) -> None:
        self._request("DELETE", f"/groups/{group_id}/members/{member_id}/$ref")
