import hashlib
import json

import pytest
from pydantic import ValidationError

from policyweaver.config import AdapterConfig


def base():
    return {"environment_url": "https://test.crm.dynamics.com",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "organization_id": "00000000-0000-0000-0000-000000000002",
            "workspace_id": "00000000-0000-0000-0000-000000000003",
            "tables": [{"name": "account", "columns": ["accountid"]}]}


def test_case_variant_duplicate_serving_items_rejected():
    item = "abcdefab-abcd-abcd-abcd-abcdefabcdef"
    with pytest.raises(ValidationError):
        AdapterConfig(**base(), serving_items={"a000_t000": item, "a001_t000": item.upper()})


@pytest.mark.parametrize("field", ["tenant_id", "organization_id", "workspace_id"])
def test_zero_security_scope_rejected(field):
    raw = base()
    raw[field] = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(ValidationError):
        AdapterConfig(**raw)


def test_invalid_shard_key_rejected():
    with pytest.raises(ValidationError):
        AdapterConfig(**base(), serving_items={"../elsewhere": base()["workspace_id"]})


def test_identity_verification_is_explicit_and_bound_into_config_fingerprint():
    original = AdapterConfig(**base())
    custom = AdapterConfig(**base(), identity_verification="custom_api", identity_api_name="bank_ReadContext",
                           identity_api_assembly_sha256="a" * 64)
    assert original.identity_verification == "fetchxml"
    assert original.identity_api_name == "pw_ReadContext"
    assert custom.fingerprint != original.fingerprint
    with pytest.raises(ValidationError):
        AdapterConfig(**base(), identity_verification="automatic_fallback")


@pytest.mark.parametrize("name", ["", "../pw_ReadContext", "pw_ReadContext()", "pw_ReadContext?x=y",
                                 "pw_ReadContext%28", "https://other/api", "name with spaces", "x" * 129])
def test_custom_api_name_cannot_inject_a_path_or_function_parameter(name):
    with pytest.raises(ValidationError):
        AdapterConfig(**base(), identity_verification="custom_api", identity_api_name=name,
                      identity_api_assembly_sha256="a" * 64)


@pytest.mark.parametrize("digest", [None, "", "a" * 63, "A" * 64, "z" * 64])
def test_custom_api_configuration_requires_trusted_lowercase_assembly_pin(digest):
    with pytest.raises(ValidationError):
        AdapterConfig(**base(), identity_verification="custom_api", identity_api_assembly_sha256=digest)


def test_manual_retention_is_explicit_and_timed_fingerprint_is_backward_compatible():
    timed = AdapterConfig(**base())
    legacy_payload = timed.model_dump(mode="json")
    legacy_payload.pop("retention_mode")
    legacy_payload.pop("role_naming")
    legacy_payload.pop("source_workers")
    assert timed.retention_mode == "timed"
    assert timed.fingerprint == hashlib.sha256(json.dumps(legacy_payload, sort_keys=True).encode()).hexdigest()
    assert AdapterConfig(**base(), retention_mode="timed").fingerprint == timed.fingerprint
    manual = AdapterConfig(**base(), retention_mode="manual")
    assert manual.fingerprint != timed.fingerprint
    assert manual.generation_lifetime_seconds == timed.generation_lifetime_seconds
    for invalid in ("sticky", "forever", "", None, True):
        with pytest.raises(ValidationError):
            AdapterConfig(**base(), retention_mode=invalid)


@pytest.mark.parametrize("retention_mode", ["timed", "manual"])
def test_retention_mode_does_not_expand_source_freshness_budget(retention_mode):
    with pytest.raises(ValidationError):
        AdapterConfig(**base(), retention_mode=retention_mode,
                      generation_lifetime_seconds=3000, publication_budget_seconds=1200)


def test_labelled_role_names_are_opt_in_and_bound_into_fingerprint():
    legacy = AdapterConfig(**base())
    assert legacy.role_naming == "legacy"
    assert AdapterConfig(**base(), role_naming="legacy").fingerprint == legacy.fingerprint
    readable = AdapterConfig(**base(), role_naming="readable")
    assert readable.fingerprint != legacy.fingerprint
    simple = AdapterConfig(**base(), role_naming="user_business_role")
    assert simple.fingerprint not in {legacy.fingerprint, readable.fingerprint}
    # Adding the mode cannot invalidate pre-existing readable generations.
    readable_payload = readable.model_dump(mode="json")
    readable_payload.pop("retention_mode")
    readable_payload.pop("source_workers")
    assert readable.fingerprint == hashlib.sha256(json.dumps(readable_payload, sort_keys=True).encode()).hexdigest()
    for invalid in ("friendly", "", None, True):
        with pytest.raises(ValidationError):
            AdapterConfig(**base(), role_naming=invalid)


def test_parallel_sources_are_opt_in_bounded_and_bound_into_fingerprint():
    legacy = AdapterConfig(**base())
    assert legacy.source_workers == 1
    assert AdapterConfig(**base(), source_workers=1).fingerprint == legacy.fingerprint
    assert AdapterConfig(**base(), source_workers=2).fingerprint != legacy.fingerprint
    for invalid in (0, 5, None, True, 2.0, "2"):
        with pytest.raises(ValidationError):
            AdapterConfig(**base(), source_workers=invalid)
