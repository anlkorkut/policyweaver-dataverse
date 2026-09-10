"""OneLake filesystem client: lists the tables actually present in a Fabric item.

Dataverse grants read privileges on every table in the environment (882 here), but
only the synced subset exists in the lakehouse. Emitting permissions for absent
tables inflates the per-role permission count against the 500 limit and produces
paths that match nothing, so the compiler intersects privilege targets with this
listing. It also settles whether the item is schema-enabled.
"""

from __future__ import annotations

import logging

import httpx

from ..auth import ONELAKE_SCOPE, TokenProvider
from ..http_util import authorized_request

logger = logging.getLogger(__name__)

BASE_URL = "https://onelake.dfs.fabric.microsoft.com"
_PAGE_SIZE = 5000


class OneLakeClient:
    def __init__(self, token_provider: TokenProvider):
        self._tokens = token_provider
        self._http = httpx.Client(timeout=httpx.Timeout(120.0, connect=30.0))

    def close(self) -> None:
        self._http.close()

    def _list_directory(self, workspace_id: str, directory: str) -> list[dict]:
        paths: list[dict] = []
        continuation: str | None = None
        while True:
            params = {
                "resource": "filesystem",
                "recursive": "false",
                "directory": directory,
                "maxResults": str(_PAGE_SIZE),
            }
            if continuation:
                params["continuation"] = continuation
            response = authorized_request(
                self._http, "GET", f"{BASE_URL}/{workspace_id}",
                token_provider=self._tokens, scope=ONELAKE_SCOPE,
                headers={"x-ms-version": "2021-06-08"}, params=params,
            )
            paths.extend(response.json().get("paths", []))
            continuation = response.headers.get("x-ms-continuation")
            if not continuation:
                return paths

    def list_tables(self, workspace_id: str, item_id: str, schema_name: str | None) -> set[str]:
        """Table names present in the item. For a schema-enabled item, lists inside the
        schema folder; otherwise lists Tables/ directly."""
        directory = f"{item_id}/Tables"
        if schema_name:
            directory = f"{directory}/{schema_name}"
        tables = {
            entry["name"].rsplit("/", 1)[-1]
            for entry in self._list_directory(workspace_id, directory)
            if str(entry.get("isDirectory", "false")).lower() == "true"
        }
        logger.info("Item %s exposes %d tables under %s", item_id, len(tables), directory)
        return tables

    def is_schema_enabled(self, workspace_id: str, item_id: str) -> bool:
        """A schema-enabled item holds schema folders under Tables/; a non-schema item
        holds table folders (each containing _delta_log) directly."""
        entries = self._list_directory(workspace_id, f"{item_id}/Tables")
        names = {e["name"].rsplit("/", 1)[-1] for e in entries}
        return "dbo" in names and len(names) < 50
