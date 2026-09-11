"""Token acquisition for Dataverse, Microsoft Graph, Fabric, and OneLake.

Credential selection, in order:

1. Service principal - auth.client_id plus the DVACCESS_CLIENT_SECRET environment
   variable. Recommended: pinned to auth.tenant_id by construction, and able to
   answer Continuous Access Evaluation claims challenges.
2. Azure CLI selected by subscription - auth.cli_subscription. Authenticates as the
   cached `az` account that owns that subscription WITHOUT changing the global
   default, so a machine signed into several tenants still targets the right one.
   (`az --tenant` is not enough: it reuses the default user against the other
   tenant, and `az` refuses --tenant and --subscription together.)
3. DefaultAzureCredential - managed identity, environment, or the default `az`
   account.

Every token's tenant is checked against auth.tenant_id before use. A mismatch means
the credential resolved to the wrong directory; left unchecked, the target APIs fail
with misleading errors such as Fabric's "401 UserNotLicensed".
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time

from azure.identity import AzureCliCredential, ClientSecretCredential, DefaultAzureCredential

from .config import AuthConfig

logger = logging.getLogger(__name__)

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
FABRIC_SCOPE = "https://api.fabric.microsoft.com/.default"
# OneLake's DFS endpoint authenticates with a storage-resource token, not the
# Fabric control-plane token.
ONELAKE_SCOPE = "https://storage.azure.com/.default"

_REFRESH_MARGIN_SECONDS = 120


class WrongTenantError(RuntimeError):
    """The credential produced a token for a tenant other than auth.tenant_id."""


def dataverse_scope(environment_url: str) -> str:
    return f"{environment_url.rstrip('/')}/.default"


def token_tenant(token: str) -> str | None:
    """Read the tid claim from a JWT access token. No signature validation: used only
    to detect credential misconfiguration, never to make an authorization decision."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("tid")
    except (IndexError, ValueError):
        return None


class TokenProvider:
    def __init__(self, cfg: AuthConfig):
        self._tenant_id = cfg.tenant_id.lower()
        secret = os.environ.get("DVACCESS_CLIENT_SECRET")
        if cfg.client_id and secret:
            self._credential = ClientSecretCredential(
                tenant_id=cfg.tenant_id, client_id=cfg.client_id, client_secret=secret
            )
            self.mode = "service principal"
        elif cfg.cli_subscription:
            self._credential = AzureCliCredential(subscription=cfg.cli_subscription)
            self.mode = f"Azure CLI account for subscription {cfg.cli_subscription}"
        else:
            self._credential = DefaultAzureCredential()
            self.mode = "DefaultAzureCredential"
        logger.debug("Authenticating via %s, expecting tenant %s", self.mode, cfg.tenant_id)
        self._cache: dict[str, tuple[str, float]] = {}

    def token(self, scope: str, claims: str | None = None) -> str:
        """Get a CAE-capable token for the configured tenant. `claims` carries a
        Continuous Access Evaluation claims challenge (decoded JSON from a
        WWW-Authenticate header) and forces a fresh acquisition satisfying it."""
        if claims is None:
            cached = self._cache.get(scope)
            if cached and cached[1] - _REFRESH_MARGIN_SECONDS > time.time():
                return cached[0]
        access = self._credential.get_token(scope, claims=claims, enable_cae=True)
        issued_for = token_tenant(access.token)
        if issued_for and issued_for.lower() != self._tenant_id:
            raise WrongTenantError(
                f"{self.mode} returned a token for tenant {issued_for}, but auth.tenant_id "
                f"is {self._tenant_id}: the signed-in account belongs to a different "
                "directory. Set auth.cli_subscription to a subscription in the target "
                "tenant, configure the service principal (auth.client_id + "
                "DVACCESS_CLIENT_SECRET), or `az account set` to the right tenant."
            )
        self._cache[scope] = (access.token, float(access.expires_on))
        return access.token

    def invalidate(self, scope: str) -> None:
        self._cache.pop(scope, None)
