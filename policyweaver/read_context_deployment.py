"""Pinned read-context metadata verification and create-only installation.

Plan/verify use operator GETs only. Install creates only the reviewed objects,
persists planned identities before POST, never retries a POST, and never adopts,
updates or deletes pre-existing components. Recovery reads exact planned IDs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import httpx

from .storage import _atomic_write

API_NAME = "pw_ReadContext"
ASSEMBLY_NAME = "PolicyWeaver.ReadContext"
TYPE_NAME = ASSEMBLY_NAME + ".ReadContextPlugin"
SOLUTION_NAME = "PolicyWeaverReadContext"
PUBLISHER_NAME = "PolicyWeaverReadContext"
MAX_ASSEMBLY_BYTES = 10 * 1024 * 1024


class ReadContextDeploymentError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise ReadContextDeploymentError(code)


def _guid(value):
    try:
        result = str(UUID(str(value)))
        if UUID(result).int == 0:
            raise ValueError
        return result
    except (ValueError, TypeError, AttributeError):
        _fail("read_context_invalid_identifier")


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        _fail("read_context_invalid_assembly_pin")
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _bytes(value):
    if not isinstance(value, str) or len(value) > MAX_ASSEMBLY_BYTES * 2:
        _fail("read_context_invalid_assembly_content")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        _fail("read_context_invalid_assembly_content")
    if not data or len(data) > MAX_ASSEMBLY_BYTES:
        _fail("read_context_invalid_assembly_content")
    return data


def _one(rows, code):
    rows = list(rows)
    if len(rows) != 1 or not isinstance(rows[0], dict):
        _fail(code)
    return rows[0]


def _exact(row, expected, code):
    for key, value in expected.items():
        if key not in row or type(row[key]) is not type(value) or row[key] != value:
            _fail(code)


def verify_read_context_registration(client, *, api_name, assembly_sha256):
    """Verify the precise main-operation contract and pinned DLL, with GET only.

    The returned evidence contains IDs/hashes, no DLL bytes or credentials.
    Callers may cache it for one bounded source-client lifetime only.
    """
    if api_name != API_NAME:
        _fail("read_context_api_name_not_supported")
    _hash(assembly_sha256)
    environment = client.verify_environment()
    api = _one(client._collection("customapis?$select=customapiid,uniquename,bindingtype,isfunction,"
        "allowedcustomprocessingsteptype,executeprivilegename,isprivate,workflowsdkstepenabled,"
        "_plugintypeid_value,boundentitylogicalname&$filter=uniquename eq 'pw_ReadContext'"),
        "read_context_api_missing_or_ambiguous")
    _exact(api, {"uniquename": API_NAME, "bindingtype": 0, "isfunction": True,
        "allowedcustomprocessingsteptype": 0, "isprivate": False,
        "workflowsdkstepenabled": False, "boundentitylogicalname": None}, "read_context_api_contract_mismatch")
    if "executeprivilegename" not in api or api["executeprivilegename"] not in (None, ""):
        _fail("read_context_api_execute_privilege_mismatch")
    api_id, type_id = _guid(api.get("customapiid")), _guid(api.get("_plugintypeid_value"))
    plugin = client._request(f"plugintypes({type_id})?$select=plugintypeid,typename,_pluginassemblyid_value")
    _exact(plugin, {"plugintypeid": type_id, "typename": TYPE_NAME}, "read_context_plugin_type_mismatch")
    assembly_id = _guid(plugin.get("_pluginassemblyid_value"))
    assembly = client._request(f"pluginassemblies({assembly_id})?$select=pluginassemblyid,name,isolationmode,sourcetype,content,publickeytoken")
    _exact(assembly, {"pluginassemblyid": assembly_id, "name": ASSEMBLY_NAME,
        "isolationmode": 2, "sourcetype": 0}, "read_context_assembly_scope_mismatch")
    if not re.fullmatch(r"[a-fA-F0-9]{16}", str(assembly.get("publickeytoken", ""))):
        _fail("read_context_assembly_unsigned")
    if hashlib.sha256(_bytes(assembly.get("content"))).hexdigest() != assembly_sha256:
        _fail("read_context_assembly_pin_mismatch")
    expected = {"customapirequestparameters": {"Nonce": 12},
                "customapiresponseproperties": {"UserId": 12, "OrganizationId": 12, "Nonce": 12, "ProtocolVersion": 10}}
    for collection, properties in expected.items():
        request = collection == "customapirequestparameters"
        fields = "uniquename,type,_customapiid_value,logicalentityname" + (",isoptional" if request else "")
        rows = list(client._collection(f"{collection}?$select={fields}&$filter=_customapiid_value eq {api_id}"))
        if len(rows) != len(properties) or {r.get("uniquename") for r in rows} != set(properties):
            _fail("read_context_parameter_inventory_mismatch")
        for row in rows:
            wanted = {"type": properties[row["uniquename"]], "_customapiid_value": api_id, "logicalentityname": None}
            if request:
                wanted["isoptional"] = False
            _exact(row, wanted, "read_context_parameter_contract_mismatch")
    return {"verified": True, "api_name": api_name, "api_id": api_id, "plugin_type_id": type_id,
            "assembly_id": assembly_id, "assembly_sha256": assembly_sha256,
            "organization_id": environment["organization_id"], "verified_at": datetime.now(timezone.utc).isoformat()}


def _identity(value):
    if not isinstance(value, dict) or set(value) != {"name", "version", "culture", "publickeytoken"}:
        _fail("read_context_invalid_assembly_identity")
    if (value["name"] != ASSEMBLY_NAME or value["culture"] != "neutral"
            or not re.fullmatch(r"[0-9]{1,5}(?:\.[0-9]{1,5}){3}", str(value["version"]))
            or not re.fullmatch(r"[a-f0-9]{16}", str(value["publickeytoken"]))):
        _fail("read_context_invalid_assembly_identity")
    return dict(value)


def _scope(config):
    return {"environment_url": config.environment_url, "tenant_id": config.tenant_id,
            "organization_id": config.organization_id, "config_sha256": config.fingerprint}


def _verify_scope(client, config):
    environment = client.verify_environment()
    if (client.environment_url != config.environment_url or client.tenant_id != config.tenant_id
            or environment.get("organization_id") != config.organization_id):
        _fail("read_context_client_scope_mismatch")


def _artifact(path):
    data = Path(path).read_bytes()
    if not data or len(data) > MAX_ASSEMBLY_BYTES:
        _fail("read_context_invalid_assembly_artifact")
    return data, hashlib.sha256(data).hexdigest()


def _definitions(ids, identity, marker, *, legacy_response_description=False):
    """Closed set of metadata writes; executable bytes are added only at install."""
    def obj(key, collection, id_field, lookup, body):
        return {"key": key, "collection": collection, "id_field": id_field,
                "id": ids[key], "lookup": lookup, "body": {id_field: ids[key], **body}}
    result = [
        obj("publisher", "publishers", "publisherid", "uniquename", {
            "uniquename": PUBLISHER_NAME, "friendlyname": "Policy Weaver Read Context", "description": marker,
            "customizationprefix": "pw"}),
        obj("solution", "solutions", "solutionid", "uniquename", {
            "uniquename": SOLUTION_NAME, "friendlyname": "Policy Weaver Read Context", "description": marker,
            "version": "1.0.0.0", "publisherid@odata.bind": f"/publishers({ids['publisher']})"}),
        obj("assembly", "pluginassemblies", "pluginassemblyid", "name", {
            **identity, "description": marker, "isolationmode": 2, "sourcetype": 0}),
        obj("type", "plugintypes", "plugintypeid", "typename", {
            "typename": TYPE_NAME, "name": TYPE_NAME, "friendlyname": "Policy Weaver Read Context", "description": marker,
            "pluginassemblyid@odata.bind": f"/pluginassemblies({ids['assembly']})"}),
        obj("api", "customapis", "customapiid", "uniquename", {
            "uniquename": API_NAME, "name": API_NAME, "displayname": "Policy Weaver Read Context", "description": marker,
            "bindingtype": 0, "boundentitylogicalname": None, "allowedcustomprocessingsteptype": 0,
            "isfunction": True, "isprivate": False, "workflowsdkstepenabled": False, "executeprivilegename": None,
            "iscustomizable": {"Value": False}, "PluginTypeId@odata.bind": f"/plugintypes({ids['type']})"})]
    for key, field_name, request, kind in (("input_nonce", "Nonce", True, 12), ("output_nonce", "Nonce", False, 12),
            ("output_user", "UserId", False, 12), ("output_organization", "OrganizationId", False, 12),
            ("output_protocol", "ProtocolVersion", False, 10)):
        collection = "customapirequestparameters" if request else "customapiresponseproperties"
        singular = "customapirequestparameter" if request else "customapiresponseproperty"
        description = marker if request or legacy_response_description else "PWRC1:" + hashlib.sha256(marker.encode()).hexdigest()
        body = {"name": API_NAME + "." + field_name, "uniquename": field_name, "displayname": field_name,
                "description": description, "type": kind, "logicalentityname": None, "iscustomizable": {"Value": False},
                "CustomAPIId@odata.bind": f"/customapis({ids['api']})"}
        if request:
            body["isoptional"] = False
        result.append(obj(key, collection, singular + "id", "name", body))
    return result


_KEYS = ("publisher", "solution", "assembly", "type", "api", "input_nonce", "output_nonce",
         "output_user", "output_organization", "output_protocol")


def _rows(client, definition):
    field, name = definition["lookup"], definition["body"][definition["lookup"]]
    # Only locally generated, closed-definition identifiers reach this query.
    return list(client._collection(f"{definition['collection']}?$filter={field} eq '{name}' or "
                                  f"{definition['id_field']} eq {definition['id']}"))


def plan_install(client, config, *, assembly_path, assembly_identity, receipt_path=None):
    """Read-only remote collision scan and concrete create-only plan."""
    identity = _identity(assembly_identity)
    _, digest = _artifact(assembly_path)
    if receipt_path is not None and Path(receipt_path).exists():
        _fail("read_context_receipt_exists_resume_original_plan")
    _verify_scope(client, config)
    ids = {key: str(uuid4()) for key in _KEYS}
    installation_id = str(uuid4())
    marker = "PolicyWeaver.ReadContext:v1:" + config.organization_id + ":" + installation_id
    definitions = _definitions(ids, identity, marker)
    for definition in definitions:
        if _rows(client, definition):
            _fail("read_context_existing_symbol_collision")
    # A different publisher already claiming pw is not silently borrowed.
    if list(client._collection("publishers?$select=publisherid&$filter=customizationprefix eq 'pw'")):
        _fail("read_context_publisher_prefix_collision")
    plan = {"schema_version": 1, "scope": _scope(config), "installation_id": installation_id,
            "ownership_marker": marker, "assembly_sha256": digest, "assembly_identity": identity,
            "ids": ids, "mutations": definitions, "operation": "create_only",
            "creates_business_records": False, "changes_security_roles": False}
    return {**plan, "plan_sha256": _digest(plan)}


def _validate_plan(plan, config, digest, *, allow_legacy_description=False):
    if not isinstance(plan, dict) or _hash(digest) != plan.get("plan_sha256"):
        _fail("read_context_plan_approval_mismatch")
    raw = {k: v for k, v in plan.items() if k != "plan_sha256"}
    if _digest(raw) != digest or plan.get("scope") != _scope(config):
        _fail("read_context_plan_or_configuration_changed")
    if (plan.get("schema_version") != 1 or plan.get("operation") != "create_only"
            or plan.get("creates_business_records") is not False or plan.get("changes_security_roles") is not False):
        _fail("read_context_plan_contract_mismatch")
    ids = plan.get("ids", {})
    if set(ids) != set(_KEYS) or len({_guid(v) for v in ids.values()}) != len(_KEYS):
        _fail("read_context_plan_identifier_mismatch")
    marker = "PolicyWeaver.ReadContext:v1:" + config.organization_id + ":" + _guid(plan.get("installation_id"))
    identity = _identity(plan.get("assembly_identity"))
    expected = _definitions(ids, identity, marker)
    legacy = _definitions(ids, identity, marker, legacy_response_description=True)
    if marker != plan.get("ownership_marker") or (plan.get("mutations") != expected
            and not (allow_legacy_description and plan.get("mutations") == legacy)):
        _fail("read_context_plan_contract_mismatch")
    _hash(plan.get("assembly_sha256"))


def _check_created(row, definition, assembly_sha256):
    # Relationship GET names differ from create navigation properties.
    expected = {}
    for key, value in definition["body"].items():
        if key.endswith("@odata.bind"):
            field = {"publisherid": "_publisherid_value", "pluginassemblyid": "_pluginassemblyid_value",
                     "PluginTypeId": "_plugintypeid_value", "CustomAPIId": "_customapiid_value"}[key.split("@")[0]]
            expected[field] = value.rsplit("(", 1)[1][:-1]
        elif key == "iscustomizable":
            if not isinstance(row.get(key), dict) or row[key].get("Value") is not False:
                _fail("read_context_created_component_mismatch")
        else:
            expected[key] = value
    _exact(row, expected, "read_context_created_component_mismatch")
    if definition["key"] == "assembly":
        if hashlib.sha256(_bytes(row.get("content"))).hexdigest() != assembly_sha256:
            _fail("read_context_assembly_pin_mismatch")


def _post(client, collection, payload, *, solution_name):
    if collection not in {d for d in ("publishers", "solutions", "pluginassemblies", "plugintypes", "customapis",
            "customapirequestparameters", "customapiresponseproperties")}:
        _fail("read_context_mutation_route_blocked")
    url = client._safe_url(collection)
    try:
        token = client.credential.get_token(client.environment_url + "/.default")
    except Exception:
        _fail("read_context_authentication_failed")
    headers = {"Authorization": "Bearer " + token.token, "OData-Version": "4.0", "OData-MaxVersion": "4.0",
               "Accept": "application/json", "Content-Type": "application/json"}
    if solution_name is not None:
        headers["MSCRM.SolutionUniqueName"] = solution_name
    try:
        response = client._client.post(url, headers=headers, json=payload, follow_redirects=False)
    except httpx.TransportError:
        _fail("read_context_creation_outcome_uncertain_resume_receipt")
    if response.status_code not in (201, 204):
        _fail("read_context_create_http_" + str(response.status_code))


def _save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, json.dumps(value, indent=2).encode())


@contextmanager
def _receipt_lock(receipt_path, plan_sha256):
    path = Path(receipt_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + ".lock")
    try:
        stream = lock.open("x", encoding="utf-8")
    except FileExistsError:
        _fail("read_context_installer_locked_verify_process_stopped_before_recovery")
    try:
        with stream:
            json.dump({"pid": os.getpid(), "plan_sha256": plan_sha256}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        yield path
    finally:
        lock.unlink()


def _repair_preflight(client, config, original, receipt):
    _validate_plan(original, config, original.get("plan_sha256"), allow_legacy_description=True)
    _verify_scope(client, config)
    if (receipt.get("plan_sha256") != original["plan_sha256"] or receipt.get("scope") != original["scope"]
            or receipt.get("ids") != original["ids"] or not isinstance(receipt.get("attempted"), list)
            or not isinstance(receipt.get("verified"), list)
            or set(receipt["verified"]) - set(receipt["attempted"])):
        _fail("read_context_repair_receipt_mismatch")
    fixed = _definitions(original["ids"], original["assembly_identity"], original["ownership_marker"])
    changed = []
    for old, new in zip(original["mutations"], fixed):
        rows = _rows(client, old)
        if old != new:
            if old["collection"] != "customapiresponseproperties" or rows or old["key"] in receipt["verified"]:
                _fail("read_context_repair_would_change_created_component")
            changed.append(old["key"])
        else:
            row = _one(rows, "read_context_repair_existing_component_missing")
            if old["key"] not in receipt["verified"]:
                _fail("read_context_repair_existing_component_unverified")
            _check_created(row, old, original["assembly_sha256"])
    if set(changed) != {"output_nonce", "output_user", "output_organization", "output_protocol"}:
        _fail("read_context_repair_not_applicable")
    raw = {k: v for k, v in original.items() if k != "plan_sha256"}
    raw.update(mutations=fixed, previous_plan_sha256=original["plan_sha256"],
               repair_kind="response_description_max_100")
    return {**raw, "plan_sha256": _digest(raw)}


def repair_plan(client, config, *, plan, receipt_path):
    """Read-only remote repair plan for v1's overlong response descriptions.

    All four changed components must be absent, and the six unchanged components
    must still exactly match their verified receipt. No existing metadata changes.
    """
    with _receipt_lock(receipt_path, plan.get("plan_sha256")) as path:
        if not path.exists():
            _fail("read_context_repair_requires_receipt")
        receipt = json.loads(path.read_text(encoding="utf-8"))
        return _repair_preflight(client, config, plan, receipt)


def install_plan(client, config, *, plan, assembly_path, receipt_path, approved_plan_sha256, previous_plan=None):
    """Install only a reviewed plan. A failed POST is reconciled on a later call.

    This function is an explicit mutation API. CLI callers must supply the
    reviewed plan hash. It cannot overwrite, replace or uninstall any component.
    """
    _validate_plan(plan, config, approved_plan_sha256)
    with _receipt_lock(receipt_path, approved_plan_sha256) as path:
        return _install_plan_locked(client, config, plan=plan, assembly_path=assembly_path,
                                    receipt_path=path, approved_plan_sha256=approved_plan_sha256, previous_plan=previous_plan)


def _install_plan_locked(client, config, *, plan, assembly_path, receipt_path, approved_plan_sha256, previous_plan=None):
    _validate_plan(plan, config, approved_plan_sha256)
    data, digest = _artifact(assembly_path)
    if digest != plan["assembly_sha256"]:
        _fail("read_context_artifact_changed")
    _verify_scope(client, config)
    path = Path(receipt_path)
    if path.exists():
        receipt = json.loads(path.read_text(encoding="utf-8"))
        if receipt.get("plan_sha256") != plan["plan_sha256"] and previous_plan is not None:
            revised = _repair_preflight(client, config, previous_plan, receipt)
            if plan != revised:
                _fail("read_context_repair_plan_mismatch")
            receipt.setdefault("plan_lineage", []).append({"previous_plan_sha256": receipt["plan_sha256"],
                "plan_sha256": plan["plan_sha256"], "reason": plan["repair_kind"],
                "changed_absent_components": ["output_nonce", "output_user", "output_organization", "output_protocol"]})
            receipt["plan_sha256"] = plan["plan_sha256"]
            _save(path, receipt)
        if receipt.get("plan_sha256") != plan["plan_sha256"] or receipt.get("scope") != plan["scope"] or receipt.get("ids") != plan["ids"]:
            _fail("read_context_receipt_scope_mismatch")
    else:
        receipt = {"schema_version": 1, "plan_sha256": plan["plan_sha256"], "scope": plan["scope"],
                   "ids": plan["ids"], "status": "planned", "attempted": [], "verified": []}
    if (not isinstance(receipt.get("attempted"), list) or not isinstance(receipt.get("verified"), list)
            or set(receipt["attempted"]) - set(_KEYS) or set(receipt["verified"]) - set(receipt["attempted"])):
        _fail("read_context_receipt_invalid")
    existing = {}
    # All collisions are checked before the first mutation; only an attempted
    # planned ID with exact original metadata qualifies for crash recovery.
    for definition in plan["mutations"]:
        rows = _rows(client, definition)
        if rows:
            row = _one(rows, "read_context_existing_symbol_collision")
            if definition["key"] not in receipt["attempted"] or row.get(definition["id_field"]) != definition["id"]:
                _fail("read_context_existing_symbol_collision")
            _check_created(row, definition, digest)
            existing[definition["key"]] = row
        elif definition["key"] in receipt["verified"]:
            _fail("read_context_owned_component_disappeared")
    publishers = list(client._collection("publishers?$select=publisherid&$filter=customizationprefix eq 'pw'"))
    if any(p.get("publisherid") != plan["ids"]["publisher"] for p in publishers):
        _fail("read_context_publisher_prefix_collision")
    _save(path, receipt)  # Durable scope/identities exist before any POST.
    for definition in plan["mutations"]:
        key = definition["key"]
        if key not in existing:
            if key not in receipt["attempted"]:
                receipt["attempted"].append(key)
            receipt["status"] = "installing"
            _save(path, receipt)
            payload = dict(definition["body"])
            if key == "assembly":
                payload["content"] = base64.b64encode(data).decode("ascii")
            _post(client, definition["collection"], payload,
                  solution_name=None if key in ("publisher", "solution") else SOLUTION_NAME)
            row = _one(_rows(client, definition), "read_context_created_component_missing")
            _check_created(row, definition, digest)
        if key not in receipt["verified"]:
            receipt["verified"].append(key)
        _save(path, receipt)
    evidence = verify_read_context_registration(client, api_name=API_NAME, assembly_sha256=digest)
    receipt.update(status="installed_verified", evidence=evidence)
    _save(path, receipt)
    return {"status": receipt["status"], "plan_sha256": plan["plan_sha256"], "evidence": evidence}
