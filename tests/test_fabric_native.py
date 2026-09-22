"""Security invariants for the native planner and tenant-bound publisher."""
from __future__ import annotations

import base64
import copy
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest

from policyweaver.fabric_native import (
    BoundaryAttestation, DataReadyReceipt, FabricNativeClient, FabricRequestError,
    NativePolicyError, PublicationUncertain, TableSpec, plan_roles,
    _role_namespace,
)

TENANT = str(UUID(int=9001))
WORKSPACE = str(UUID(int=9002))
ITEM = str(UUID(int=9003))
NOW = datetime(2026, 9, 18, 12, tzinfo=timezone.utc)
TABLE = TableSpec("/Tables/dbo/account", ("accountid", "name", "revenue"))


def reader(number: int) -> str:
    return str(UUID(int=number + 1))


def shard(count=2, generation=7):
    return plan_roles(TENANT, [TABLE], [reader(n) for n in range(count)], generation).shards[0]


def assertions(s):
    receipt = DataReadyReceipt(WORKSPACE, ITEM, s.key, s.generation, s.plan_digest,
                               "a" * 64, NOW - timedelta(minutes=5), NOW,
                               NOW + timedelta(minutes=45))
    boundary = BoundaryAttestation(WORKSPACE, ITEM, s.reader_ids, NOW, True, True, "UserIdentity")
    return receipt, boundary


class Credential:
    def __init__(self, tenant=TENANT, audience="https://api.fabric.microsoft.com"):
        self.tenant = tenant
        self.audience = audience
        self.calls = 0

    def get_token(self, scope):
        assert scope == "https://api.fabric.microsoft.com/.default"
        self.calls += 1
        encoded = base64.urlsafe_b64encode(json.dumps({"tid": self.tenant,
                                                      "aud": self.audience}).encode()).decode().rstrip("=")
        return SimpleNamespace(token="header." + encoded + ".signature")


class FabricMock:
    def __init__(self, roles=()):
        self.roles = copy.deepcopy(list(roles))
        self.etag = '"1"'
        self.calls = []
        self.fail_commit = None
        self.change_dry_run = False
        self.commit_mismatch = False
        self.normalize_persisted = False
        self.workspace_assignments = []

    def __call__(self, request):
        self.calls.append(request)
        assert request.headers["authorization"].startswith("Bearer ")
        if request.method == "GET":
            if request.url.path.endswith("/roleAssignments"):
                return httpx.Response(200, json={"value": copy.deepcopy(self.workspace_assignments)})
            if request.url.path.endswith("/dataAccessRoles"):
                return httpx.Response(200, json={"value": copy.deepcopy(self.roles)}, headers={"ETag": self.etag})
            return httpx.Response(200, json={"id": ITEM, "type": "Lakehouse"})
        assert request.method == "PUT"
        assert request.headers["if-match"] == self.etag
        payload = json.loads(request.content)
        # Live Fabric rejects multiple decision rules within a role, even when
        # each rule addresses a different table.
        if any(len(role.get("decisionRules", [])) != 1 for role in payload["value"]):
            return httpx.Response(400, json={"errorCode": "InvalidDecisionRuleCount"})
        if request.url.query == b"dryRun=true":
            if self.change_dry_run:
                self.etag = '"2"'
            return httpx.Response(200)
        if isinstance(self.fail_commit, int):
            return httpx.Response(self.fail_commit)
        if self.fail_commit == "transport":
            raise httpx.ReadTimeout("this error might contain a secret URL", request=request)
        self.roles = copy.deepcopy(payload["value"])
        for n, role in enumerate(self.roles):
            role.setdefault("id", reader(10000 + n))
            role["eTag"] = "server-assigned"
            if self.normalize_persisted:
                for member in role["members"]["microsoftEntraMembers"]:
                    member.pop("objectType", None)
                for rule in role["decisionRules"]:
                    for row in rule.get("constraints", {}).get("rows", []):
                        row["type"] = "Fabric"
        if self.commit_mismatch:
            self.roles = []
        self.etag = '"2"'
        return httpx.Response(200, headers={"ETag": self.etag})


def client(handler, **kwargs):
    return FabricNativeClient(TENANT, WORKSPACE, ITEM, kwargs.pop("credential", Credential()),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        clock=kwargs.pop("clock", lambda: NOW), sleep=lambda _: None, **kwargs)


def admin_role(member=None, scope="*", name="ExistingAdministrator"):
    return {"name": name, "kind": "Policy", "id": reader(9999), "decisionRules": [{
        "effect": "Permit", "permission": [
            {"attributeName": "Path", "attributeValueIncludedIn": [scope]},
            {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]}]}],
        "members": {"microsoftEntraMembers": [member or {
            "objectType": "User", "tenantId": TENANT, "objectId": reader(999)}]}}


def test_200_reader_plan_stays_under_verified_default_quota():
    p = plan_roles(TENANT, [TABLE], [{"entra_id": reader(n)} for n in range(200)], 1)
    assert p.audience_shards == p.table_shards == len(p.shards) == 1
    assert len(p.shards[0].roles) == 200
    assert p.shards[0].role_limit == 250


def test_1000_reader_default_quota_uses_five_items_not_1000_roles_on_one():
    p = plan_roles(TENANT, [TABLE], [reader(n) for n in range(1000)], 2)
    assert [len(s.reader_ids) for s in p.shards] == [240, 240, 240, 240, 40]
    assert len(set(r for s in p.shards for r in s.reader_ids)) == 1000


def test_table_permissions_shard_independently_and_maintain_exact_coverage():
    tables = [TableSpec(f"/Tables/dbo/table_{n}", ("id",)) for n in range(501)]
    p = plan_roles(TENANT, tables, [reader(n) for n in range(241)], 2)
    assert len(p.shards) == 4
    assert p.audience_shards == p.table_shards == 2
    assert [len(s.tables) for s in p.shards] == [500, 1, 500, 1]
    pairs = {(r, t.path) for s in p.shards for r in s.reader_ids for t in s.tables}
    assert len(pairs) == 241 * 501


def test_support_exception_is_explicit_and_reserved_slots_still_count():
    p = plan_roles(TENANT, [TABLE], [reader(n) for n in range(1000)], 2,
                   role_limit=1000, reserve_roles=10)
    assert [len(s.reader_ids) for s in p.shards] == [990, 10]


def test_roles_bind_one_identity_and_both_constraints_in_the_same_rule():
    s = shard(1)
    role = s.roles[0]
    assert role["name"].isalnum() and role["name"][0].isalpha()
    assert role["members"]["microsoftEntraMembers"] == [
        {"tenantId": TENANT, "objectId": reader(0), "objectType": "User"}]
    rule = role["decisionRules"][0]
    assert rule["constraints"]["columns"][0]["columnNames"] == list(TABLE.columns)
    predicate = rule["constraints"]["rows"][0]["value"]
    assert f"__pw_reader = '{reader(0)}'" in predicate
    assert "__pw_generation = 7" in predicate
    assert len(predicate) < 1000
    role["decisionRules"].clear()
    assert s.roles[0]["decisionRules"]  # No caller mutation of the frozen plan.


def test_multi_table_role_publishes_one_rule_with_exact_per_table_row_and_column_scope():
    contact = TableSpec("/Tables/dbo/contact", ("contactid", "fullname"))
    s = plan_roles(TENANT, [contact, TABLE], [reader(0), reader(1)], 7,
        reader_table_paths={reader(0): [TABLE.path, contact.path], reader(1): [TABLE.path]}).shards[0]
    mock = FabricMock()
    mock.normalize_persisted = True
    result = client(mock).publish(s, *assertions(s))
    assert result.status == "published_control_plane_verified"
    for role, expected in zip(mock.roles, ((TABLE, contact), (TABLE,))):
        assert len(role["decisionRules"]) == 1
        rule = role["decisionRules"][0]
        assert rule["permission"] == [
            {"attributeName": "Path", "attributeValueIncludedIn": [t.path for t in expected]},
            {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]}]
        rows = rule["constraints"]["rows"]
        columns = rule["constraints"]["columns"]
        assert [r["tablePath"] for r in rows] == [t.path for t in expected]
        assert [c["tablePath"] for c in columns] == [t.path for t in expected]
        for table, row, column in zip(expected, rows, columns):
            assert f"FROM {table.sql_name} WHERE __pw_reader = '" in row["value"]
            assert row["value"].endswith("AND __pw_generation = 7")
            assert column["columnNames"] == list(table.columns)
            assert column["columnEffect"] == "Permit"
            assert column["columnAction"] == ["Read"]


@pytest.mark.parametrize("path,columns", [
    ("/Tables/account;DROP TABLE account", ("id",)),
    ("/Tables/../account", ("id",)), ("/Files/account", ("id",)),
    ("/Tables/account", ("*",)), ("/Tables/account", ("__pw_reader",)),
    ("/Tables/account", ("__PW_generation",)), ("/Tables/account", ()),
    ("/Tables/account", ("Id", "id")), ("/Tables/account", ("x] OR 1=1",)),
    ("/Tables/account", "name"),
])
def test_invalid_table_and_column_inputs_never_generate_policies(path, columns):
    with pytest.raises(NativePolicyError):
        TableSpec(path, columns)


@pytest.mark.parametrize("generation", [0, -1, True, "1 OR 1=1", "01", 2**63, 1.5])
def test_generation_is_strictly_integer(generation):
    with pytest.raises(NativePolicyError):
        shard(1, generation)


def test_reader_duplicates_and_unsupported_scale_fail():
    with pytest.raises(NativePolicyError, match="duplicate"):
        plan_roles(TENANT, [TABLE], [reader(0), reader(0)], 1)
    with pytest.raises(NativePolicyError, match="1000"):
        plan_roles(TENANT, [TABLE], [reader(n) for n in range(1001)], 1)


def test_dry_run_preserves_unrelated_roles_and_never_commits():
    mock = FabricMock([admin_role()])
    before = copy.deepcopy(mock.roles)
    result = client(mock).dry_run(shard())
    assert result.status == "dry_run_validated"
    assert result.enforcement_verified is False
    assert mock.roles == before
    puts = [r for r in mock.calls if r.method == "PUT"]
    assert len(puts) == 1 and puts[0].url.query == b"dryRun=true"
    assert json.loads(puts[0].content)["value"][0] == before[0]


@pytest.mark.parametrize("existing", [
    admin_role({"objectType": "User", "tenantId": TENANT, "objectId": reader(0)}),
    admin_role({"objectType": "Group", "tenantId": TENANT, "objectId": reader(888)}),
    {**admin_role(), "members": {"fabricItemMembers": [{"itemAccess": ["ReadAll"],
        "sourcePath": WORKSPACE + "/" + ITEM}]}},
])
def test_overlapping_reader_or_unresolved_group_and_item_grants_block(existing):
    mock = FabricMock([existing])
    with pytest.raises(NativePolicyError, match="bypass"):
        client(mock).dry_run(shard())
    assert not any(r.method == "PUT" for r in mock.calls)


def test_unmanaged_nonoverlapping_role_is_preserved():
    existing = admin_role({"objectType": "Group", "tenantId": TENANT, "objectId": reader(888)},
                          scope="/Tables/dbo/unrelated")
    mock = FabricMock([existing])
    assert client(mock).dry_run(shard()).role_count == 3


def test_namespace_collision_blocks_instead_of_deleting_an_unowned_role():
    mock = FabricMock([admin_role(name="PolicyWeaver_not_created_by_this_app")])
    with pytest.raises(NativePolicyError, match="namespace"):
        client(mock).dry_run(shard())
    assert not any(r.method == "PUT" for r in mock.calls)


def test_publication_replaces_old_generation_preserves_unrelated_and_verifies():
    old = shard(generation=6).roles
    old[0]["id"] = reader(9000)
    unowned = admin_role()
    mock = FabricMock([unowned, *old])
    s = shard(generation=7)
    receipt, boundary = assertions(s)
    result = client(mock).publish(s, receipt, boundary)
    assert result.status == "published_control_plane_verified"
    assert result.control_plane_verified and not result.enforcement_verified
    assert mock.roles[0]["name"] == unowned["name"]
    own = [r for r in mock.roles if r["name"].startswith(_role_namespace("PolicyWeaver_"))]
    assert own[0]["id"] == reader(9000)
    assert len(own) == 2
    assert all("__pw_generation = 7" in r["decisionRules"][0]["constraints"]["rows"][0]["value"] for r in own)


def test_removed_reader_is_removed_on_next_generation():
    mock = FabricMock(shard(3, 6).roles)
    s = shard(2, 7)
    client(mock).publish(s, *assertions(s))
    assert len(mock.roles) == 2
    assert all(reader(2) != r["members"]["microsoftEntraMembers"][0]["objectId"] for r in mock.roles)


def test_live_get_normalization_supports_commit_verification_and_identical_retry():
    mock, s = FabricMock(), shard(2, 7)
    mock.normalize_persisted = True
    result = client(mock).publish(s, *assertions(s))
    assert result.control_plane_verified
    assert client(mock).dry_run(s).status == "dry_run_validated"


def test_unknown_row_type_cannot_be_normalized_into_canonical_same_generation():
    s = shard(2, 7)
    existing = s.roles
    existing[0]["decisionRules"][0]["constraints"]["rows"][0]["type"] = "OtherEngine"
    with pytest.raises(NativePolicyError, match="immutable"):
        client(FabricMock(existing)).dry_run(s)


def test_rollback_and_changed_policy_reuse_of_generation_are_rejected():
    mock = FabricMock(shard(3, 8).roles)
    with pytest.raises(NativePolicyError, match="older security generation"):
        client(mock).dry_run(shard(2, 7))
    with pytest.raises(NativePolicyError, match="immutable"):
        client(mock).dry_run(shard(2, 8))
    assert not any(r.method == "PUT" for r in mock.calls)


def test_identical_generation_retry_does_not_change_security_semantics():
    s = shard(2, 8)
    mock = FabricMock(s.roles)
    assert client(mock).dry_run(s).status == "dry_run_validated"


@pytest.mark.parametrize("receipt_change", [
    {"generation": 6}, {"plan_digest": "0" * 64}, {"content_digest": "not-a-digest"},
    {"valid_until": NOW}, {"valid_until": NOW + timedelta(minutes=60)},
    {"completed_at": NOW + timedelta(seconds=1)}, {"item_id": reader(123)},
    {"source_observed_at": NOW.replace(tzinfo=None)},
])
def test_invalid_or_stale_receipt_prevents_all_requests(receipt_change):
    mock, s = FabricMock(), shard()
    receipt, boundary = assertions(s)
    with pytest.raises(NativePolicyError):
        client(mock).publish(s, replace(receipt, **receipt_change), boundary)
    assert not mock.calls


@pytest.mark.parametrize("boundary_change", [
    {"reader_ids": (reader(0),)}, {"no_privileged_workspace_readers": False},
    {"no_alternate_data_access": False}, {"sql_endpoint_mode": "DelegatedIdentity"},
    {"inspected_at": NOW - timedelta(minutes=16)}, {"workspace_id": reader(123)},
])
def test_boundary_bypass_and_stale_review_prevent_all_requests(boundary_change):
    mock, s = FabricMock(), shard()
    receipt, boundary = assertions(s)
    with pytest.raises(NativePolicyError):
        client(mock).publish(s, receipt, replace(boundary, **boundary_change))
    assert not mock.calls


def test_control_plane_race_after_dry_run_never_commits():
    mock, s = FabricMock(), shard()
    mock.change_dry_run = True
    with pytest.raises(PublicationUncertain, match="dry run"):
        client(mock).publish(s, *assertions(s))
    assert not any(r.method == "PUT" and not r.url.query for r in mock.calls)


@pytest.mark.parametrize("failure", [412, 429, 503, "transport"])
def test_commit_failure_never_retries_or_restores_previous_grants(failure):
    mock, s = FabricMock(shard(generation=6).roles), shard()
    mock.fail_commit = failure
    with pytest.raises(FabricRequestError):
        client(mock).publish(s, *assertions(s))
    commits = [r for r in mock.calls if r.method == "PUT" and not r.url.query]
    assert len(commits) == 1


def test_success_response_without_matching_roles_is_not_reported_as_success():
    mock, s = FabricMock(), shard()
    mock.commit_mismatch = True
    with pytest.raises(PublicationUncertain, match="does not match"):
        client(mock).publish(s, *assertions(s))


def test_withdraw_preserves_unowned_roles_and_does_not_restore_generation():
    mock = FabricMock([admin_role(), *shard().roles])
    result = client(mock).withdraw()
    assert result.status == "withdrawn_control_plane_verified"
    assert len(mock.roles) == 1 and mock.roles[0]["name"] == "ExistingAdministrator"
    assert len([r for r in mock.calls if r.method == "PUT"]) == 1
    assert client(mock).withdraw().status == "already_withdrawn"


@pytest.mark.parametrize("credential", [Credential(tenant=reader(44)), Credential(audience="https://graph.microsoft.com")])
def test_credential_tenant_and_audience_guard(credential):
    mock = FabricMock()
    with pytest.raises(NativePolicyError):
        client(mock, credential=credential).list_roles()
    assert not mock.calls


def test_continuation_cannot_send_token_to_another_host_or_item():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"value": [], "continuationUri": "https://attacker.example/token"},
                              headers={"ETag": '"1"'})
    with pytest.raises(NativePolicyError, match="Untrusted"):
        client(handler).list_roles()
    assert len(calls) == 1


def test_paginated_roles_require_one_consistent_etag():
    calls = []
    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(200, json={"value": [], "continuationToken": "next+value"},
                                  headers={"ETag": '"1"'})
        assert request.url.params["continuationToken"] == "next+value"
        return httpx.Response(200, json={"value": []}, headers={"ETag": '"2"'})
    with pytest.raises(NativePolicyError, match="consistent ETag"):
        client(handler).list_roles()


def test_only_get_is_retried_and_error_does_not_leak_server_body():
    calls = []
    def handler(request):
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(503, text="private-data-do-not-log", headers={"Retry-After": "0"})
        return httpx.Response(200, json={"value": []}, headers={"ETag": '"1"'})
    assert client(handler).list_roles().roles == ()
    assert len(calls) == 3


def test_maximum_roles_includes_preserved_unowned_roles():
    s = plan_roles(TENANT, [TABLE], [reader(n) for n in range(2)], 1,
                   role_limit=2, reserve_roles=0).shards[0]
    mock = FabricMock([admin_role()])
    with pytest.raises(NativePolicyError, match="quota"):
        client(mock).dry_run(s)
    assert not any(r.method == "PUT" for r in mock.calls)


def test_client_rejects_cross_tenant_plan_even_with_valid_credential():
    s = plan_roles(reader(2222), [TABLE], [reader(0)], 1).shards[0]
    with pytest.raises(NativePolicyError, match="Plan tenant"):
        client(FabricMock()).dry_run(s)


@pytest.mark.parametrize("principal,role", [
    ({"id": reader(0), "type": "User"}, "Admin"),
    ({"id": reader(1), "type": "User"}, "Contributor"),
    ({"id": reader(888), "type": "Group"}, "Viewer"),
    ({"id": reader(888), "type": "EntireTenant"}, "Member"),
])
def test_live_workspace_boundary_blocks_privileged_or_unresolved_audience(principal, role):
    mock, s = FabricMock(), shard()
    mock.workspace_assignments = [{"principal": principal, "role": role}]
    with pytest.raises(NativePolicyError, match="Workspace roles"):
        client(mock).publish(s, *assertions(s))
    assert not any(r.method == "PUT" and not r.url.query for r in mock.calls)


def test_workspace_reader_viewer_and_unrelated_admin_do_not_inherit_elevation():
    mock = FabricMock()
    mock.workspace_assignments = [
        {"principal": {"id": reader(0), "type": "User"}, "role": "Viewer"},
        {"principal": {"id": reader(777), "type": "User"}, "role": "Admin"},
    ]
    review = client(mock).inspect_workspace_boundary(shard().reader_ids)
    assert review.closed and review.reader_count == 2


def test_table_read_absence_produces_no_native_table_grant_or_empty_role():
    other = TableSpec("/Tables/dbo/contact", ("contactid",))
    p = plan_roles(TENANT, [TABLE, other], [reader(0), reader(1), reader(2)], 7,
        reader_table_paths={reader(0): [TABLE.path], reader(1): [other.path], reader(2): []})
    s = p.shards[0]
    assert len(s.reader_ids) == 3 and len(s.roles) == 2
    assert p.as_dict()["shards"][0]["role_count"] == 2
    grants = {r["members"]["microsoftEntraMembers"][0]["objectId"]:
              [rule["constraints"]["rows"][0]["tablePath"] for rule in r["decisionRules"]] for r in s.roles}
    assert grants == {reader(0): [TABLE.path], reader(1): [other.path]}


@pytest.mark.parametrize("mapping", [{reader(0): []},
    {reader(0): ["/Tables/dbo/unknown"], reader(1): []},
    {reader(0): TABLE.path, reader(1): []}])
def test_invalid_or_incomplete_table_access_fails_closed(mapping):
    with pytest.raises(NativePolicyError):
        plan_roles(TENANT, [TABLE], [reader(0), reader(1)], 7, reader_table_paths=mapping)


def test_no_table_grants_in_one_table_shard_does_not_create_permissive_empty_role():
    other = TableSpec("/Tables/dbo/contact", ("contactid",))
    p = plan_roles(TENANT, [TABLE, other], [reader(0)], 7, max_table_permissions=1,
                   reader_table_paths={reader(0): [other.path]})
    assert [len(s.roles) for s in p.shards] == [0, 1]


def test_alphanumeric_role_names_preserve_distinct_punctuated_namespaces():
    assert _role_namespace("pw_ab_") != _role_namespace("pwa_b_")


def test_structured_fabric_error_exposes_codes_but_never_server_messages():
    def handler(request):
        return httpx.Response(400, json={"errorCode": "BadRequest", "message": "customer@example.com secret",
            "moreDetails": [{"errorCode": "RequestBodyValidationFailed", "message": "private role member"}]})
    with pytest.raises(FabricRequestError) as failure:
        client(handler).get_item()
    assert failure.value.code == "fabric_400_RequestBodyValidationFailed"
    assert failure.value.error_code == "BadRequest"
    assert "secret" not in str(failure.value) and "customer" not in repr(vars(failure.value))
