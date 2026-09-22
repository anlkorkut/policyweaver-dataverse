"""Identity-proof registration must never trust a name without its pinned code."""
import base64
import copy
import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import pytest

from policyweaver.config import AdapterConfig, TableSelection
from policyweaver.read_context_deployment import (
    API_NAME, ReadContextDeploymentError, install_plan, plan_install, repair_plan,
    verify_read_context_registration,
)

ORG = str(UUID(int=1))
TENANT = str(UUID(int=2))
ENV = "https://example.crm.dynamics.com"
CONTENT = b"test fixture bytes, never a deployable DLL"
IDENTITY = {"name": "PolicyWeaver.ReadContext", "version": "1.0.0.0", "culture": "neutral", "publickeytoken": "0123456789abcdef"}


def config():
    return AdapterConfig(environment_url=ENV, tenant_id=TENANT, organization_id=ORG,
        workspace_id=str(UUID(int=3)), readers=(str(UUID(int=4)),),
        tables=(TableSelection(name="account", columns=("accountid",)),))


class Server:
    environment_url, tenant_id = ENV, TENANT

    def __init__(self):
        self.rows = {}
        self.calls = []
        self.posts = []
        self.fail_after_create = False
        self.receipt = None
        self._client = self
        self.credential = SimpleNamespace(get_token=lambda *_: SimpleNamespace(token="not-a-real-token"))

    def verify_environment(self):
        return {"organization_id": ORG}

    def _safe_url(self, reference):
        assert re.fullmatch(r"[a-z]+", reference)
        return ENV + "/api/data/v9.2/" + reference

    def _collection(self, reference):
        self.calls.append(("GET", reference))
        collection = reference.split("?", 1)[0]
        rows = self.rows.get(collection, [])
        conditions = re.findall(r"(\w+) eq (?:'([^']*)'|([a-f0-9-]{36}))", reference)
        return iter(copy.deepcopy([r for r in rows if not conditions or any(r.get(k) == (s or g) for k, s, g in conditions)]))

    def _request(self, reference):
        self.calls.append(("GET", reference))
        match = re.match(r"([a-z]+)\(([a-f0-9-]{36})\)", reference)
        collection, identity = match.groups()
        singular = {"plugintypes": "plugintype", "pluginassemblies": "pluginassembly"}[collection]
        return copy.deepcopy(next(r for r in self.rows[collection] if r[singular + "id"] == identity))

    def post(self, url, headers, json, follow_redirects):
        assert follow_redirects is False
        collection = urlsplit(url).path.rsplit("/", 1)[1]
        if self.receipt:
            receipt = __import__("json").loads(self.receipt.read_text())
            assert receipt["attempted"] and receipt["status"] == "installing"
        self.posts.append((collection, copy.deepcopy(json)))
        row = copy.deepcopy(json)
        for name in list(row):
            if name.endswith("@odata.bind"):
                lookup = name.split("@")[0].lower()
                row["_" + lookup + "_value"] = row.pop(name).rsplit("(", 1)[1][:-1]
        self.rows.setdefault(collection, []).append(row)
        if self.fail_after_create:
            self.fail_after_create = False
            raise httpx.ReadTimeout("private response content must never appear")
        return httpx.Response(204)


def planned(tmp_path):
    server, c = Server(), config()
    dll = tmp_path / "ReadContext.dll"
    dll.write_bytes(CONTENT)
    receipt = tmp_path / "receipt.json"
    server.receipt = receipt
    plan = plan_install(server, c, assembly_path=dll, assembly_identity=IDENTITY, receipt_path=receipt)
    return server, c, dll, receipt, plan


def install(fixture):
    server, c, dll, receipt, plan = fixture
    return install_plan(server, c, plan=plan, assembly_path=dll, receipt_path=receipt,
                        approved_plan_sha256=plan["plan_sha256"])


def test_plan_is_remote_read_only_and_contains_concrete_closed_scope(tmp_path):
    server, c, dll, receipt, plan = planned(tmp_path)
    assert not server.posts and not receipt.exists()
    assert len(plan["mutations"]) == 10
    assert plan["scope"]["organization_id"] == ORG
    assert plan["assembly_sha256"] == hashlib.sha256(CONTENT).hexdigest()
    assert not any("content" in m["body"] for m in plan["mutations"])
    assert not plan["changes_security_roles"] and not plan["creates_business_records"]


def test_install_records_intent_and_verifies_every_component_and_code(tmp_path):
    fixture = planned(tmp_path)
    result = install(fixture)
    server, _, _, receipt, _ = fixture
    assert result["status"] == "installed_verified"
    assert len(server.posts) == 10
    assert len(json.loads(receipt.read_text())["verified"]) == 10
    assert result["evidence"]["assembly_sha256"] == hashlib.sha256(CONTENT).hexdigest()
    assert not receipt.with_name(receipt.name + ".lock").exists()
    install(fixture)
    assert len(server.posts) == 10  # Exact owned reconciliation is read-only.


def test_unknown_creation_outcome_reconciles_exact_owned_id_without_reposting(tmp_path):
    fixture = planned(tmp_path)
    fixture[0].fail_after_create = True
    with pytest.raises(ReadContextDeploymentError, match="creation_outcome_uncertain"):
        install(fixture)
    receipt = json.loads(fixture[3].read_text())
    assert receipt["attempted"] == ["publisher"] and receipt["verified"] == []
    install(fixture)
    assert len(fixture[0].posts) == 10


@pytest.mark.parametrize("changed", ["plan", "config", "artifact", "approval", "client"])
def test_changed_reviewed_inputs_block_before_posts(tmp_path, changed):
    server, c, dll, receipt, plan = planned(tmp_path)
    approved = plan["plan_sha256"]
    if changed == "plan":
        plan["mutations"][4]["body"]["allowedcustomprocessingsteptype"] = 2
    elif changed == "config":
        c = c.model_copy(update={"deployment_name": "pw_changed"})
    elif changed == "artifact":
        dll.write_bytes(b"changed")
    elif changed == "approval":
        approved = "0" * 64
    else:
        server.tenant_id = str(UUID(int=900))
    with pytest.raises(ReadContextDeploymentError):
        install_plan(server, c, plan=plan, assembly_path=dll, receipt_path=receipt, approved_plan_sha256=approved)
    assert not server.posts


def test_existing_name_is_never_adopted_without_owned_attempt_receipt(tmp_path):
    fixture = planned(tmp_path)
    server, c, dll, receipt, plan = fixture
    server.rows["publishers"] = [{"publisherid": str(UUID(int=91)), "uniquename": "PolicyWeaverReadContext"}]
    with pytest.raises(ReadContextDeploymentError, match="collision"):
        install(fixture)
    assert not server.posts and not receipt.exists()
    with pytest.raises(ReadContextDeploymentError, match="collision"):
        plan_install(server, c, assembly_path=dll, assembly_identity=IDENTITY)


def test_publisher_prefix_collision_blocks_without_adoption(tmp_path):
    server, c, dll, receipt, plan = planned(tmp_path)
    server.rows["publishers"] = [{"publisherid": str(UUID(int=91)), "uniquename": "AnotherPublisher", "customizationprefix": "pw"}]
    with pytest.raises(ReadContextDeploymentError, match="prefix_collision"):
        install_plan(server, c, plan=plan, assembly_path=dll, receipt_path=receipt, approved_plan_sha256=plan["plan_sha256"])
    assert not server.posts


def test_ambiguous_creation_followed_by_foreign_metadata_drift_is_not_adopted(tmp_path):
    fixture = planned(tmp_path)
    fixture[0].fail_after_create = True
    with pytest.raises(ReadContextDeploymentError):
        install(fixture)
    fixture[0].rows["publishers"][0]["description"] = "foreign owner"
    with pytest.raises(ReadContextDeploymentError, match="component_mismatch"):
        install(fixture)
    assert len(fixture[0].posts) == 1


def test_existing_installer_lock_cannot_be_stolen_or_expired(tmp_path):
    fixture = planned(tmp_path)
    lock = fixture[3].with_name(fixture[3].name + ".lock")
    lock.write_text('{"pid":1}')
    with pytest.raises(ReadContextDeploymentError, match="installer_locked"):
        install(fixture)
    assert lock.read_text() == '{"pid":1}' and not fixture[0].posts


@pytest.mark.parametrize("mutation", [
    lambda s: s.rows["customapis"][0].update(isfunction=False),
    lambda s: s.rows["customapis"][0].update(bindingtype=1),
    lambda s: s.rows["customapis"][0].update(allowedcustomprocessingsteptype=2),
    lambda s: s.rows["customapis"][0].update(executeprivilegename="prvReadUser"),
    lambda s: s.rows["customapis"][0].update(isprivate=True),
    lambda s: s.rows["customapis"][0].pop("workflowsdkstepenabled"),
    lambda s: s.rows["plugintypes"][0].update(typename="Another.Plugin"),
    lambda s: s.rows["pluginassemblies"][0].update(isolationmode=1),
    lambda s: s.rows["pluginassemblies"][0].update(sourcetype=1),
    lambda s: s.rows["pluginassemblies"][0].update(content=base64.b64encode(b"changed").decode()),
    lambda s: s.rows["pluginassemblies"][0].update(publickeytoken=""),
    lambda s: s.rows["customapirequestparameters"][0].update(isoptional=True),
    lambda s: s.rows["customapirequestparameters"][0].update(type=10),
    lambda s: s.rows["customapiresponseproperties"].pop(),
    lambda s: s.rows["customapiresponseproperties"].append(copy.deepcopy(s.rows["customapiresponseproperties"][0])),
])
def test_verifier_rejects_incomplete_or_changed_trust_contract(tmp_path, mutation):
    fixture = planned(tmp_path)
    install(fixture)
    server = fixture[0]
    count = len(server.posts)
    mutation(server)
    with pytest.raises(ReadContextDeploymentError):
        verify_read_context_registration(server, api_name=API_NAME, assembly_sha256=hashlib.sha256(CONTENT).hexdigest())
    assert len(server.posts) == count


def test_verification_wrong_pin_and_unknown_api_are_rejected(tmp_path):
    fixture = planned(tmp_path)
    install(fixture)
    for name, pin in ((API_NAME, "0" * 64), ("OtherAPI", hashlib.sha256(CONTENT).hexdigest())):
        with pytest.raises(ReadContextDeploymentError):
            verify_read_context_registration(fixture[0], api_name=name, assembly_sha256=pin)


def legacy_partial(tmp_path):
    fixture = planned(tmp_path)
    server, _, _, receipt, plan = fixture
    for definition in plan["mutations"][6:]:
        definition["body"]["description"] = plan["ownership_marker"]
    plan["plan_sha256"] = hashlib.sha256(json.dumps({k: v for k, v in plan.items() if k != "plan_sha256"},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    server.receipt = None
    for definition in plan["mutations"][:6]:
        body = dict(definition["body"])
        if definition["key"] == "assembly":
            body["content"] = base64.b64encode(CONTENT).decode()
        server.post(ENV + "/api/data/v9.2/" + definition["collection"], headers={}, json=body, follow_redirects=False)
    receipt.write_text(json.dumps({"schema_version": 1, "plan_sha256": plan["plan_sha256"], "scope": plan["scope"],
        "ids": plan["ids"], "status": "installing", "attempted": [d["key"] for d in plan["mutations"][:7]],
        "verified": [d["key"] for d in plan["mutations"][:6]]}))
    server.receipt = receipt
    return fixture


def test_response_descriptions_fit_actual_100_character_platform_limit(tmp_path):
    _, _, _, _, plan = planned(tmp_path)
    assert len(plan["ownership_marker"]) == 101
    assert all(len(d["body"]["description"]) == 70 for d in plan["mutations"][6:])
    assert all(d["body"]["description"] == plan["ownership_marker"] for d in plan["mutations"][:6])


def test_repair_plan_is_read_only_and_install_records_reviewed_lineage(tmp_path):
    server, c, dll, receipt, original = legacy_partial(tmp_path)
    original_copy = copy.deepcopy(original)
    receipt_before = receipt.read_bytes()
    revised = repair_plan(server, c, plan=original, receipt_path=receipt)
    assert original == original_copy and receipt.read_bytes() == receipt_before and len(server.posts) == 6
    assert revised["mutations"][:6] == original["mutations"][:6]
    assert revised["ids"] == original["ids"] and revised["scope"] == original["scope"]
    result = install_plan(server, c, plan=revised, assembly_path=dll, receipt_path=receipt,
                          approved_plan_sha256=revised["plan_sha256"], previous_plan=original)
    assert result["status"] == "installed_verified" and len(server.posts) == 10
    value = json.loads(receipt.read_text())
    assert value["plan_lineage"][0]["previous_plan_sha256"] == original["plan_sha256"]
    assert value["plan_sha256"] == revised["plan_sha256"]


def test_repair_rejects_a_response_already_created_even_under_same_owned_id(tmp_path):
    server, c, _, receipt, original = legacy_partial(tmp_path)
    server.receipt = None
    definition = original["mutations"][6]
    server.post(ENV + "/api/data/v9.2/" + definition["collection"], headers={}, json=definition["body"], follow_redirects=False)
    with pytest.raises(ReadContextDeploymentError, match="would_change_created"):
        repair_plan(server, c, plan=original, receipt_path=receipt)


def test_repair_rejects_changed_existing_metadata_and_leaves_receipt_untouched(tmp_path):
    server, c, _, receipt, original = legacy_partial(tmp_path)
    before = receipt.read_bytes()
    server.rows["customapis"][0]["isfunction"] = False
    with pytest.raises(ReadContextDeploymentError, match="component_mismatch"):
        repair_plan(server, c, plan=original, receipt_path=receipt)
    assert receipt.read_bytes() == before and len(server.posts) == 6


def test_repair_requires_reviewed_new_hash_and_original_plan_for_receipt_transition(tmp_path):
    server, c, dll, receipt, original = legacy_partial(tmp_path)
    revised = repair_plan(server, c, plan=original, receipt_path=receipt)
    for approved, previous in ((original["plan_sha256"], original), (revised["plan_sha256"], None)):
        with pytest.raises(ReadContextDeploymentError):
            install_plan(server, c, plan=revised, assembly_path=dll, receipt_path=receipt,
                         approved_plan_sha256=approved, previous_plan=previous)
    assert len(server.posts) == 6 and json.loads(receipt.read_text())["plan_sha256"] == original["plan_sha256"]


def test_repair_rechecks_absence_after_plan_before_any_receipt_revision(tmp_path):
    server, c, dll, receipt, original = legacy_partial(tmp_path)
    revised = repair_plan(server, c, plan=original, receipt_path=receipt)
    before = receipt.read_bytes()
    server.rows["customapiresponseproperties"] = [{"name": "pw_ReadContext.Nonce", "customapiresponsepropertyid": str(UUID(int=901))}]
    with pytest.raises(ReadContextDeploymentError, match="would_change_created"):
        install_plan(server, c, plan=revised, assembly_path=dll, receipt_path=receipt,
                     approved_plan_sha256=revised["plan_sha256"], previous_plan=original)
    assert receipt.read_bytes() == before and len(server.posts) == 6
