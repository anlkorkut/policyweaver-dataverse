"""Create isolated, empty serving items with durable ownership receipts.

No workspace membership is granted. No existing item is adopted by name alone.
Creation POSTs are never retried; an ambiguous result is reconciled using the
unique marker persisted before the request. OneLake opt-in and SQL identity
mode have no documented public enable API in the consulted reference, so this
module reports portal actions when required rather than claiming completion.
"""
from __future__ import annotations

import base64
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID, uuid4

import httpx

from .config import save_config
from .fabric_native import FABRIC_ROOT, FabricNativeClient, FabricRequestError, NativePolicyError, _guid
from .materialization import schema_for
from .storage import _atomic_write


class ProvisioningError(RuntimeError):
    """Safe provisioning failure: no credentials or remote response bodies."""


def _now():
    return datetime.now(timezone.utc).isoformat()


class ProvisioningClient:
    """Exact-route client for create/list/get lakehouse, LRO, and empty checks."""
    def __init__(self, tenant_id, workspace_id, credential, *, http_client=None,
                 sleep=time.sleep, max_polls=40):
        self.tenant_id = _guid(tenant_id, "tenant")
        self.workspace_id = _guid(workspace_id, "workspace")
        self.credential = credential
        self.http = http_client or httpx.Client(timeout=60, follow_redirects=False, trust_env=False)
        self._owns_http = http_client is None
        self.sleep, self.max_polls = sleep, max_polls
        self.base = f"{FABRIC_ROOT}/workspaces/{self.workspace_id}/lakehouses"
        self._auth = FabricNativeClient(self.tenant_id, self.workspace_id, str(UUID(int=1)),
                                        credential, http_client=self.http)

    def close(self):
        if self._owns_http:
            self.http.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _route(self, method, url):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "api.fabric.microsoft.com" or parsed.fragment:
            raise ProvisioningError("untrusted_fabric_url")
        if method == "POST" and url == self.base:
            return
        if method == "GET":
            query = parse_qs(parsed.query, keep_blank_values=True)
            if parsed.path == urlsplit(self.base).path and (not parsed.query or
                    set(query) == {"continuationToken"} and len(query["continuationToken"]) == 1):
                return
            if (not parsed.query and re.fullmatch(re.escape(urlsplit(self.base).path) + r"/[a-f0-9-]{36}", parsed.path)):
                _guid(parsed.path.rsplit("/", 1)[1], "lakehouse")
                return
            if not parsed.query and re.fullmatch(r"/v1/operations/[a-f0-9-]{36}(?:/result)?", parsed.path):
                _guid(parsed.path.split("/")[3], "operation")
                return
        raise ProvisioningError("untrusted_fabric_route")

    def _request(self, method, url, payload=None):
        self._route(method, url)
        attempts = 3 if method == "GET" else 1
        for attempt in range(attempts):
            try:
                response = self.http.request(method, url, headers=self._auth._headers(), json=payload,
                                             follow_redirects=False)
            except httpx.TransportError:
                if method == "POST":
                    raise ProvisioningError("creation_outcome_uncertain_reconcile_receipt_before_retry") from None
                if attempt + 1 == attempts:
                    raise ProvisioningError("fabric_get_transport_failed") from None
                self.sleep(2**attempt)
                continue
            if method == "GET" and response.status_code in (429, 502, 503, 504) and attempt + 1 < attempts:
                delay = self._delay(response, default=2**attempt)
                self.sleep(delay)
                continue
            if response.status_code not in ((200,) if method == "GET" else (201, 202)):
                raise ProvisioningError(f"fabric_{method.lower()}_http_{response.status_code}")
            return response
        raise ProvisioningError("fabric_request_incomplete")

    @staticmethod
    def _delay(response, default=5):
        try:
            delay = float(response.headers.get("Retry-After", default))
        except ValueError:
            raise ProvisioningError("unrecognized_retry_after") from None
        if not 0 <= delay <= 30:
            raise ProvisioningError("retry_after_exceeds_poll_budget_resume_later")
        return delay

    @staticmethod
    def _json(response):
        try:
            body = response.json()
        except ValueError:
            raise ProvisioningError("fabric_response_not_json") from None
        if not isinstance(body, dict):
            raise ProvisioningError("fabric_response_not_object")
        return body

    def list_lakehouses(self):
        url, rows, seen = self.base, [], set()
        for _ in range(100):
            if url in seen:
                raise ProvisioningError("repeated_lakehouse_continuation")
            seen.add(url)
            body = self._json(self._request("GET", url))
            if not isinstance(body.get("value"), list):
                raise ProvisioningError("incomplete_lakehouse_inventory")
            rows.extend(body["value"])
            next_url = body.get("continuationUri")
            if not next_url and body.get("continuationToken"):
                next_url = self.base + "?" + urlencode({"continuationToken": body["continuationToken"]})
            if not next_url:
                return rows
            if not isinstance(next_url, str) or urlsplit(next_url).path != urlsplit(self.base).path:
                raise ProvisioningError("lakehouse_continuation_escaped_collection")
            self._route("GET", next_url)
            url = next_url
        raise ProvisioningError("lakehouse_pagination_exhausted")

    def get_lakehouse(self, item_id):
        item = _guid(item_id, "lakehouse")
        result = self._json(self._request("GET", self.base + "/" + item))
        if _guid(result.get("id"), "returned lakehouse") != item:
            raise ProvisioningError("unexpected_lakehouse_identity")
        return result

    def create(self, name, description, persist_operation):
        response = self._request("POST", self.base, {"displayName": name, "description": description,
                                                   "creationPayload": {"enableSchemas": True}})
        if response.status_code == 201:
            return self._json(response)
        operation = response.headers.get("Location")
        if not operation:
            raise ProvisioningError("creation_accepted_without_operation_receipt")
        self._route("GET", operation)
        if not re.fullmatch(r"/v1/operations/[a-f0-9-]{36}", urlsplit(operation).path):
            raise ProvisioningError("invalid_creation_operation_location")
        persist_operation(operation)
        self.sleep(self._delay(response))
        return self.poll(operation)

    def poll(self, operation):
        self._route("GET", operation)
        if not re.fullmatch(r"/v1/operations/[a-f0-9-]{36}", urlsplit(operation).path):
            raise ProvisioningError("invalid_creation_operation_location")
        for _ in range(self.max_polls):
            response = self._request("GET", operation)
            body = self._json(response)
            status = body.get("status")
            if status == "Succeeded":
                return self._json(self._request("GET", operation + "/result"))
            if status in ("Failed", "Cancelled"):
                raise ProvisioningError("lakehouse_creation_operation_" + status.lower())
            if status not in ("NotStarted", "Running"):
                raise ProvisioningError("unknown_creation_operation_status")
            self.sleep(self._delay(response))
        raise ProvisioningError("creation_poll_budget_exhausted_resume_receipt_later")

    def require_empty_storage(self, item_id):
        """Read both roots through ADLS; refuse role removal if any file exists."""
        item = _guid(item_id, "lakehouse")
        try:
            token = self.credential.get_token("https://storage.azure.com/.default").token
            encoded = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            if (_guid(claims.get("tid"), "storage tenant") != self.tenant_id
                    or str(claims.get("aud", "")).rstrip("/") != "https://storage.azure.com"):
                raise ProvisioningError("storage_token_scope_mismatch")
        except ProvisioningError:
            raise
        except Exception:
            raise ProvisioningError("storage_token_unavailable") from None
        for root in ("Tables", "Files"):
            continuation, seen = None, set()
            for _ in range(100):
                params = {"resource": "filesystem", "directory": item + "/" + root,
                          "recursive": "true", "maxResults": "5000"}
                if continuation:
                    params["continuation"] = continuation
                try:
                    response = self.http.get(f"https://onelake.dfs.fabric.microsoft.com/{self.workspace_id}",
                        params=params, headers={"Authorization": "Bearer " + token, "x-ms-version": "2021-06-08"},
                        follow_redirects=False)
                except httpx.TransportError:
                    raise ProvisioningError("empty_storage_check_transport_failed") from None
                if response.status_code != 200:
                    raise ProvisioningError(f"empty_storage_check_http_{response.status_code}")
                body = self._json(response)
                if not isinstance(body.get("paths"), list):
                    raise ProvisioningError("empty_storage_inventory_incomplete")
                for entry in body["paths"]:
                    if not isinstance(entry, dict) or entry.get("isDirectory") not in (True, "true"):
                        raise ProvisioningError("serving_lakehouse_not_empty_refusing_default_role_removal")
                continuation = response.headers.get("x-ms-continuation")
                if not continuation:
                    break
                if continuation in seen:
                    raise ProvisioningError("repeated_storage_continuation")
                seen.add(continuation)
            else:
                raise ProvisioningError("storage_pagination_exhausted")


def _ensure_empty_table(destination, item_id, path, source_table):
    """Initialize a table with no data, or verify the existing schema without rewriting."""
    import pyarrow as pa
    from deltalake import DeltaTable, write_deltalake
    from deltalake.exceptions import TableNotFoundError
    uri, options = destination.uri(item_id, path), destination.options()
    expected = schema_for(source_table)
    try:
        existing = DeltaTable(uri, storage_options=options)
    except TableNotFoundError:
        write_deltalake(uri, pa.Table.from_pylist([], schema=expected), mode="error", storage_options=options)
        existing = DeltaTable(uri, storage_options=destination.options())
        created = True
    else:
        created = False
    actual = existing.to_pyarrow_dataset().schema
    if not actual.equals(expected, check_metadata=False):
        raise ProvisioningError("existing_serving_table_schema_differs")
    return {"path": path, "created_empty": created, "delta_version": existing.version()}


def _check_owned_item(item, entry, config):
    if (item.get("type") != "Lakehouse" or item.get("displayName") != entry["name"]
            or item.get("description") != entry["description"]
            or item.get("workspaceId", config.workspace_id) != config.workspace_id):
        raise ProvisioningError("serving_item_ownership_marker_mismatch")
    if item.get("properties", {}).get("defaultSchema") != "dbo":
        raise ProvisioningError("serving_item_schema_enablement_unverified")


def _harden_empty_item(runtime, client, item_id, entry, persist):
    """Only a receipt-proven item before any app table initialization is eligible."""
    if entry.get("hardened"):
        return
    if entry.get("tables"):
        raise ProvisioningError("cannot_remove_initial_roles_after_table_initialization")
    with runtime.fabric(item_id) as fabric:
        try:
            snapshot = fabric.list_roles()
        except FabricRequestError:
            entry["status"] = "requires_onelake_security_enablement_or_api_access"
            entry["required_action"] = "Open this new lakehouse, Manage OneLake security, enable it if prompted, then rerun provision."
            persist()
            return
        # Never clear customer-created roles, even in an item originally created here.
        if any(r.get("name") != "DefaultReader" for r in snapshot.roles):
            raise ProvisioningError("unexpected_roles_in_new_serving_item_refusing_removal")
        if snapshot.roles:
            client.require_empty_storage(item_id)
            entry["empty_storage_verified_at"] = _now()
            entry["initial_role_digest"] = snapshot.digest
            entry["status"] = "hardening_inflight"
            persist()
            fabric._request("PUT", fabric.roles_url, payload={"value": []}, etag=snapshot.etag)
            after = fabric.list_roles()
            if after.roles:
                raise ProvisioningError("initial_role_removal_verification_failed")
        entry["hardened"] = True
        entry["hardened_at"] = _now()
        entry["status"] = "hardened_empty"
        entry.pop("required_action", None)
        persist()


def provision(runtime, *, client_factory=ProvisioningClient, ensure_table=_ensure_empty_table):
    """Provision the current reader/table plan into the configured workspace.

    Returns concrete item IDs plus remaining portal/qualification actions.
    Configuration is persisted after each item creation, before hardening or
    table initialization. The runtime must prepare a new generation afterward.
    """
    from .runtime import role_plan
    config = runtime.config
    receipt_path = Path(runtime.directory) / "provisioning.json"
    with runtime.journal.lock():
        with runtime.source() as source:
            source.verify_environment()
            readers = runtime.select_readers(source)
            tables = [source.table_metadata(t.name, t.columns) for t in config.tables]
        plan = role_plan(config, tables, [r.entra_id for r in readers], 1)
        if receipt_path.exists():
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            if any(receipt.get(k) != v for k, v in {
                "tenant_id": config.tenant_id, "workspace_id": config.workspace_id,
                "organization_id": config.organization_id, "deployment_name": config.deployment_name}.items()):
                raise ProvisioningError("provisioning_receipt_scope_mismatch")
        else:
            receipt = {"schema_version": 1, "tenant_id": config.tenant_id, "workspace_id": config.workspace_id,
                       "organization_id": config.organization_id, "deployment_name": config.deployment_name,
                       "created_at": _now(), "shards": {}}
        def persist():
            receipt["updated_at"] = _now()
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write(receipt_path, (json.dumps(receipt, indent=2) + "\n").encode())
        persist()
        with client_factory(config.tenant_id, config.workspace_id, runtime.credential) as client:
            inventory = client.list_lakehouses()
            for shard in plan.shards:
                entry = receipt["shards"].get(shard.key)
                name = config.deployment_name + "_" + shard.key
                configured_item = runtime.config.serving_items.get(shard.key)
                if configured_item and (not entry or entry.get("item_id") != configured_item):
                    raise ProvisioningError("configured_item_has_no_matching_creation_receipt")
                same_name = [i for i in inventory if i.get("displayName", "").casefold() == name.casefold()]
                if entry is None:
                    if same_name:
                        raise ProvisioningError("existing_lakehouse_name_collision_no_adoption")
                    marker = (f"PolicyWeaver serving; organization={config.organization_id}; "
                              f"deployment={config.deployment_name}; shard={shard.key}; receipt={uuid4()}")
                    entry = {"name": name, "description": marker, "status": "create_inflight", "created_at": _now()}
                    receipt["shards"][shard.key] = entry
                    persist()
                    def persist_operation(operation):
                        entry["operation_url"] = operation
                        persist()
                    result = client.create(name, marker, persist_operation)
                    entry["item_id"] = _guid(result.get("id"), "created item")
                    entry["status"] = "created"
                    persist()
                elif not entry.get("item_id"):
                    if entry.get("operation_url"):
                        result = client.poll(entry["operation_url"])
                    else:
                        matches = [i for i in same_name if i.get("description") == entry.get("description")]
                        if len(matches) != 1:
                            raise ProvisioningError("creation_outcome_uncertain_manual_reconciliation_required")
                        result = matches[0]
                    entry["item_id"] = _guid(result.get("id"), "reconciled item")
                    entry["status"] = "created_reconciled"
                    persist()
                item_id = entry["item_id"]
                if configured_item and configured_item != item_id:
                    raise ProvisioningError("configured_serving_item_changed")
                item = client.get_lakehouse(item_id)
                _check_owned_item(item, entry, config)
                items = {**runtime.config.serving_items, shard.key: item_id}
                runtime.config = runtime.config.model_copy(update={"serving_items": items})
                save_config(runtime.config, runtime.config_path)
                _harden_empty_item(runtime, client, item_id, entry, persist)
                if not entry.get("hardened"):
                    continue
                outputs = []
                for table in shard.tables:
                    source_table = next(t for t in tables if table.path.endswith("/" + config.deployment_name + "_" + t.name))
                    outputs.append(ensure_table(runtime.destination, item_id, table.path, source_table))
                    entry["tables"] = outputs
                    persist()
                entry["status"] = "empty_tables_ready_requires_boundary_review"
                persist()
        return {"status": "provisioned_requires_boundary_review" if all(
                    receipt["shards"][s.key].get("hardened") for s in plan.shards) else "requires_portal_action",
                "required_lakehouses": len(plan.shards), "serving_items": runtime.config.serving_items,
                "receipt_path": str(receipt_path), "items": {s.key: receipt["shards"][s.key] for s in plan.shards},
                "remaining_actions": [
                    "Verify OneLake security is enabled on every new serving lakehouse.",
                    "Use the SQL endpoint Security settings to select User's identity, or keep SQL inaccessible to readers. Switching modes cancels SQL endpoint queries across the workspace.",
                    "Share only the serving items with exact reader identities using base Read; do not grant workspace Viewer to expose unrelated raw items.",
                    "Review bypass paths, qualify actual reader sessions and revocation timing, then supply fresh boundary attestations.",
                    "Prepare a new generation after provisioning because serving item IDs change the configuration fingerprint."]}
