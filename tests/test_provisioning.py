"""Provisioning must never adopt or harden an unrelated lakehouse."""
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID
import base64
import copy
import json

import httpx
import pytest

from policyweaver.config import AdapterConfig, TableSelection, load_config, save_config
from policyweaver.fabric_native import RoleSnapshot
from policyweaver.materialization import DeltaDestination
from policyweaver.provisioning import ProvisioningClient, ProvisioningError, _ensure_empty_table, provision
from policyweaver.source_projection import SourceAttribute, SourceReader, SourceTable

TENANT = str(UUID(int=9001))
WORKSPACE = str(UUID(int=9002))
ORG = str(UUID(int=9003))
ITEM = str(UUID(int=101))
READER = str(UUID(int=102))
OPERATION = str(UUID(int=103))
SOURCE = SourceTable("account", "accounts", "accountid", ("accountid", "name"), (
    SourceAttribute("accountid", "accountid", "Uniqueidentifier", False),
    SourceAttribute("name", "name", "String", False)))


class Credential:
    def get_token(self, scope):
        audience = scope.removesuffix("/.default")
        encoded = base64.urlsafe_b64encode(json.dumps({"tid": TENANT, "aud": audience}).encode()).decode().rstrip("=")
        return SimpleNamespace(token="header." + encoded + ".signature")


class FakeClient:
    def __init__(self):
        self.inventory, self.creates, self.empty_checks, self.operations = [], [], [], []
        self.empty = True
        self.fail_after_creation = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def list_lakehouses(self):
        return copy.deepcopy(self.inventory)

    def get_lakehouse(self, item):
        return copy.deepcopy(next(i for i in self.inventory if i["id"] == item))

    def create(self, name, description, callback):
        self.creates.append(name)
        result = {"id": ITEM, "displayName": name, "description": description, "type": "Lakehouse",
                  "workspaceId": WORKSPACE, "properties": {"defaultSchema": "dbo"}}
        self.inventory.append(result)
        if self.fail_after_creation:
            raise ProvisioningError("creation_outcome_uncertain")
        return result

    def poll(self, operation):
        self.operations.append(operation)
        return self.inventory[0]

    def require_empty_storage(self, item):
        self.empty_checks.append(item)
        if not self.empty:
            raise ProvisioningError("not_empty")


class FakeFabric:
    roles_url = "https://api.fabric.microsoft.com/test"

    def __init__(self):
        self.roles = [{"name": "DefaultReader", "id": str(UUID(int=104))}]
        self.puts = []
        self.unavailable = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def list_roles(self):
        if self.unavailable:
            from policyweaver.fabric_native import FabricRequestError
            raise FabricRequestError("Fabric GET HTTP 400")
        return RoleSnapshot(tuple(self.roles), '"etag"')

    def _request(self, method, url, payload, etag):
        assert method == "PUT" and url == self.roles_url and etag == '"etag"'
        self.puts.append(copy.deepcopy(payload))
        self.roles = copy.deepcopy(payload["value"])


def runtime(tmp_path, *, role_naming="legacy"):
    config = AdapterConfig(environment_url="https://example.crm.dynamics.com", tenant_id=TENANT,
        organization_id=ORG, workspace_id=WORKSPACE, readers=(READER,),
        tables=(TableSelection(name="account", columns=("accountid", "name")),), role_naming=role_naming)
    config_path = tmp_path / "deployment.json"
    save_config(config, config_path)
    fabric = FakeFabric()
    source = SimpleNamespace(verify_environment=lambda: None, table_metadata=lambda *args: SOURCE)
    return SimpleNamespace(config=config, config_path=config_path, directory=tmp_path / "state",
        journal=SimpleNamespace(lock=lambda: nullcontext()), source=lambda: nullcontext(source),
        select_readers=lambda source: [SourceReader(str(UUID(int=1)), READER)], credential=Credential(),
        fabric=lambda item: fabric, fabric_mock=fabric, destination=DeltaDestination(local_root=tmp_path / "delta"))


def factory(client):
    return lambda *args: client


@pytest.mark.parametrize("role_naming", ["legacy", "readable", "user_business_role"])
def test_provision_creates_only_isolated_item_persists_receipt_then_hardens_and_types(tmp_path, role_naming):
    rt, api = runtime(tmp_path, role_naming=role_naming), FakeClient()
    seen = []
    def ensure(destination, item, path, table):
        assert (rt.directory / "provisioning.json").exists()
        assert load_config(rt.config_path).serving_items == {"a000_t000": ITEM}
        assert load_config(rt.config_path).role_naming == role_naming
        assert not rt.fabric_mock.roles
        seen.append((item, path))
        return {"path": path, "created_empty": True}
    result = provision(rt, client_factory=factory(api), ensure_table=ensure)
    assert result["status"] == "provisioned_requires_boundary_review"
    assert api.creates == ["pw_demo_a000_t000"]
    assert api.empty_checks == [ITEM]
    assert rt.fabric_mock.puts == [{"value": []}]
    assert seen == [(ITEM, "/Tables/dbo/pw_demo_account")]
    assert result["remaining_actions"]
    # A sizing plan neither requests labels nor changes the configured naming
    # mode; actual reader roles must come from a fresh prepared generation.
    assert rt.config.role_naming == role_naming


def test_existing_name_without_receipt_is_never_adopted_or_modified(tmp_path):
    rt, api = runtime(tmp_path), FakeClient()
    api.inventory = [{"id": ITEM, "displayName": "pw_demo_a000_t000", "description": "customer data"}]
    with pytest.raises(ProvisioningError, match="collision"):
        provision(rt, client_factory=factory(api))
    assert not api.creates and not rt.fabric_mock.puts


def test_configured_existing_item_without_receipt_is_never_hardened(tmp_path):
    rt, api = runtime(tmp_path), FakeClient()
    rt.config = rt.config.model_copy(update={"serving_items": {"a000_t000": ITEM}})
    with pytest.raises(ProvisioningError, match="no_matching_creation_receipt"):
        provision(rt, client_factory=factory(api))
    assert not api.creates and not rt.fabric_mock.puts


def test_ambiguous_create_reconciles_unique_durable_marker_without_second_post(tmp_path):
    rt, api = runtime(tmp_path), FakeClient()
    api.fail_after_creation = True
    with pytest.raises(ProvisioningError, match="uncertain"):
        provision(rt, client_factory=factory(api))
    api.fail_after_creation = False
    result = provision(rt, client_factory=factory(api), ensure_table=lambda *args: {"created_empty": True})
    assert result["serving_items"] == {"a000_t000": ITEM}
    assert len(api.creates) == 1


def test_unresolved_creation_never_retries_post(tmp_path):
    rt, api = runtime(tmp_path), FakeClient()
    api.fail_after_creation = True
    with pytest.raises(ProvisioningError):
        provision(rt, client_factory=factory(api))
    api.inventory.clear()
    with pytest.raises(ProvisioningError, match="manual_reconciliation"):
        provision(rt, client_factory=factory(api))
    assert len(api.creates) == 1


def test_nonempty_owned_item_prevents_defaultreader_removal(tmp_path):
    rt, api = runtime(tmp_path), FakeClient()
    api.empty = False
    with pytest.raises(ProvisioningError, match="not_empty"):
        provision(rt, client_factory=factory(api))
    assert not rt.fabric_mock.puts
    assert load_config(rt.config_path).serving_items == {"a000_t000": ITEM}


def test_other_roles_prevent_bulk_removal_even_on_new_item(tmp_path):
    rt, api = runtime(tmp_path), FakeClient()
    rt.fabric_mock.roles.append({"name": "UnexpectedAdministratorRole"})
    with pytest.raises(ProvisioningError, match="unexpected_roles"):
        provision(rt, client_factory=factory(api))
    assert not rt.fabric_mock.puts


def test_security_optin_gap_returns_portal_action_and_no_tables(tmp_path):
    rt, api = runtime(tmp_path), FakeClient()
    rt.fabric_mock.unavailable = True
    def forbidden(*args):
        pytest.fail("tables must not be initialized before item hardening")
    result = provision(rt, client_factory=factory(api), ensure_table=forbidden)
    assert result["status"] == "requires_portal_action"
    assert not rt.fabric_mock.puts
    assert "required_action" in result["items"]["a000_t000"]


def test_repeat_provision_checks_schema_without_clearing_roles_again(tmp_path):
    rt, api = runtime(tmp_path), FakeClient()
    provision(rt, client_factory=factory(api))
    rt.fabric_mock.roles = [{"name": "pw_demo_r_published_role"}]
    second = provision(rt, client_factory=factory(api))
    assert second["items"]["a000_t000"]["tables"][0]["created_empty"] is False
    assert len(api.creates) == 1 and len(rt.fabric_mock.puts) == 1


def test_local_empty_delta_preserves_an_existing_table_without_rewrite(tmp_path):
    destination = DeltaDestination(local_root=tmp_path)
    first = _ensure_empty_table(destination, ITEM, "/Tables/dbo/pw_demo_account", SOURCE)
    second = _ensure_empty_table(destination, ITEM, "/Tables/dbo/pw_demo_account", SOURCE)
    assert first["created_empty"] is True and second["created_empty"] is False
    assert first["delta_version"] == second["delta_version"] == 0


def test_provisioning_rest_uses_schema_create_and_bounded_lro():
    calls, operations = [], []
    def handler(request):
        calls.append(request)
        if request.method == "POST":
            assert json.loads(request.content)["creationPayload"] == {"enableSchemas": True}
            return httpx.Response(202, headers={"Location": f"https://api.fabric.microsoft.com/v1/operations/{OPERATION}",
                                              "Retry-After": "0"})
        if request.url.path.endswith("/result"):
            return httpx.Response(200, json={"id": ITEM})
        return httpx.Response(200, json={"status": "Succeeded"})
    c = ProvisioningClient(TENANT, WORKSPACE, Credential(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)
    result = c.create("pw_demo_a000_t000", "owned", operations.append)
    assert result["id"] == ITEM and len(operations) == 1
    assert [r.method for r in calls] == ["POST", "GET", "GET"]


def test_creation_transport_failure_has_no_post_retry():
    calls = []
    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("sensitive raw error", request=request)
    c = ProvisioningClient(TENANT, WORKSPACE, Credential(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)
    with pytest.raises(ProvisioningError, match="uncertain"):
        c.create("name", "owned", lambda _: None)
    assert len(calls) == 1


def test_operation_location_cannot_exfiltrate_bearer_token():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(202, headers={"Location": "https://attacker.example/operation"})
    c = ProvisioningClient(TENANT, WORKSPACE, Credential(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)
    with pytest.raises(ProvisioningError, match="untrusted"):
        c.create("name", "owned", lambda _: None)
    assert len(calls) == 1


def test_empty_storage_check_rejects_any_file_before_role_removal():
    calls = []
    def handler(request):
        calls.append(request)
        assert request.url.host == "onelake.dfs.fabric.microsoft.com"
        return httpx.Response(200, json={"paths": [{"name": "secret.parquet", "isDirectory": "false"}]})
    c = ProvisioningClient(TENANT, WORKSPACE, Credential(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)
    with pytest.raises(ProvisioningError, match="not_empty"):
        c.require_empty_storage(ITEM)
    assert len(calls) == 1


def test_empty_storage_check_covers_tables_and_files():
    directories = []
    def handler(request):
        directories.append(request.url.params["directory"])
        return httpx.Response(200, json={"paths": [{"name": "directory", "isDirectory": "true"}]})
    c = ProvisioningClient(TENANT, WORKSPACE, Credential(),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=lambda _: None)
    c.require_empty_storage(ITEM)
    assert directories == [ITEM + "/Tables", ITEM + "/Files"]
