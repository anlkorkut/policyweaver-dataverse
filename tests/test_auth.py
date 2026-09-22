from types import SimpleNamespace
import pytest
from policyweaver.auth import CachedCredential


def test_token_cache_separates_audiences_and_refreshes_before_expiry():
    now = [1000]
    calls = []
    class Credential:
        def get_token(self, *scopes, **kwargs):
            calls.append((scopes, kwargs))
            return SimpleNamespace(token=f"test-{len(calls)}", expires_on=now[0] + 3600)
    cache = CachedCredential(Credential(), clock=lambda: now[0])
    source = cache.get_token("source")
    assert cache.get_token("source") is source
    assert cache.get_token("fabric") is not source
    now[0] = 4490
    assert cache.get_token("source") is not source
    assert len(calls) == 3
    cache.get_token("source", claims="challenge")
    assert len(calls) == 4


def test_expired_token_is_never_cached():
    class Credential:
        def get_token(self, *scopes):
            return SimpleNamespace(token="test", expires_on=1)
    with pytest.raises(RuntimeError, match="expired"):
        CachedCredential(Credential(), clock=lambda: 100).get_token("source")
