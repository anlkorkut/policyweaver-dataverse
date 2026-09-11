import base64
import json
import time
from types import SimpleNamespace

import pytest

from dvaccess.auth import TokenProvider, WrongTenantError, token_tenant
from dvaccess.config import AuthConfig


def _jwt(tid: str) -> str:
    def enc(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    return f"{enc({'alg': 'none'})}.{enc({'tid': tid})}.sig"


class _FakeCredential:
    def __init__(self, token: str):
        self._token = token

    def get_token(self, *scopes, **kwargs):
        return SimpleNamespace(token=self._token, expires_on=time.time() + 3600)


def _provider(configured: str, issued: str) -> TokenProvider:
    provider = TokenProvider(AuthConfig(tenant_id=configured))
    provider._credential = _FakeCredential(_jwt(issued))
    return provider


def test_token_for_configured_tenant_is_returned_case_insensitively():
    provider = _provider("tenant-a", "TENANT-A")
    assert token_tenant(provider.token("scope")) == "TENANT-A"


def test_token_for_another_tenant_is_rejected_with_actionable_message():
    """A machine signed into several tenants must not silently call the APIs as the
    wrong identity - Fabric would report that as a misleading 'UserNotLicensed'."""
    provider = _provider("tenant-a", "tenant-b")
    with pytest.raises(WrongTenantError, match="cli_subscription"):
        provider.token("scope")


def test_token_tenant_tolerates_opaque_tokens():
    assert token_tenant("not-a-jwt") is None


def test_cli_subscription_selects_azure_cli_credential():
    provider = TokenProvider(AuthConfig(tenant_id="t", cli_subscription="sub-1"))
    assert "subscription sub-1" in provider.mode
