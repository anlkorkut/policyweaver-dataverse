"""Token acquisition for Dataverse, Microsoft Graph, and Fabric.

Uses a client-secret service principal when DVACCESS_CLIENT_SECRET is set and
auth.client_id is configured; otherwise falls back to DefaultAzureCredential
(Azure CLI login, managed identity, VS Code, etc.). Tokens are cached per scope
and refreshed 120 seconds before expiry.
"""

from __future__ import annotations

import os
import time

from azure.identity import ClientSecretCredential, DefaultAzureCredential

from .config import AuthConfig

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
FABRIC_SCOPE = "https://api.fabric.microsoft.com/.default"
# OneLake's DFS endpoint authenticates with a storage-resource token, not the
# Fabric control-plane token.
ONELAKE_SCOPE = "https://storage.azure.com/.default"

_REFRESH_MARGIN_SECONDS = 120


def dataverse_scope(environment_url: str) -> str:
    return f"{environment_url.rstrip('/')}/.default"


class TokenProvider:
    def __init__(self, cfg: AuthConfig):
        secret = os.environ.get("DVACCESS_CLIENT_SECRET")
        if cfg.client_id and secret:
            self._credential = ClientSecretCredential(
                tenant_id=cfg.tenant_id, client_id=cfg.client_id, client_secret=secret
            )
            self.mode = "client_secret"
        else:
            self._credential = DefaultAzureCredential()
            self.mode = "default"
        self._cache: dict[str, tuple[str, float]] = {}

    def token(self, scope: str, claims: str | None = None) -> str:
        """Get a CAE-capable token. `claims` carries a Continuous Access Evaluation
        claims challenge (decoded JSON from a WWW-Authenticate header) and forces a
        fresh acquisition satisfying it."""
        if claims is None:
            cached = self._cache.get(scope)
            if cached and cached[1] - _REFRESH_MARGIN_SECONDS > time.time():
                return cached[0]
        access = self._credential.get_token(scope, claims=claims, enable_cae=True)
        self._cache[scope] = (access.token, float(access.expires_on))
        return access.token

    def invalidate(self, scope: str) -> None:
        self._cache.pop(scope, None)
