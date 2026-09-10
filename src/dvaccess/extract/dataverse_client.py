"""Dataverse Web API client: read-only extraction of the security model.

Endpoints used (all reads, OData v4, paged at 5000 rows via Prefer maxpagesize):
- businessunits, systemusers, teams, roles (componentstate eq 0)
- RetrieveRolePrivilegesRole(RoleId=...) per role -> privileges with depth
- roles(id)/systemuserroles_association, roles(id)/teamroles_association
- teams(id)/teammembership_association
- fieldsecurityprofiles(+associations), fieldpermissions
- EntityDefinitions -> LogicalName/SchemaName/ObjectTypeCode/OwnershipType

Read privileges are resolved to tables by matching the privilege name suffix
(prvRead<SchemaName>) against entity metadata; unmatched names are recorded in
the snapshot for the reconciliation report.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections.abc import Callable, Iterator

import httpx

from ..auth import TokenProvider, dataverse_scope
from ..http_util import authorized_request
from ..models import (
    BusinessUnit,
    DvRole,
    DvTeam,
    DvUser,
    FieldPermission,
    FieldSecurityProfile,
    RoleReadGrant,
    Snapshot,
    TableMeta,
    parse_depth,
    parse_ownership,
)

logger = logging.getLogger(__name__)

API_SEGMENT = "/api/data/v9.2"
READ_ACCESS_PREFIX = "prvRead"
FIELD_PERMISSION_ALLOWED = 4

# N:N intersect entity sets. Query these directly rather than $expand-ing the
# navigation properties: Dataverse emits a per-row @odata.nextLink for every
# expanded collection - including empty ones - so $expand over N roles costs N
# extra round trips regardless of how few assignments exist.
ROLE_USER_INTERSECT = "systemuserrolescollection"
ROLE_TEAM_INTERSECT = "teamrolescollection"
TEAM_MEMBERSHIP_INTERSECT = "teammemberships"
USER_PROFILE_INTERSECT = "systemuserprofilescollection"
TEAM_PROFILE_INTERSECT = "teamprofilescollection"


class DataverseClient:
    def __init__(self, environment_url: str, token_provider: TokenProvider, page_size: int = 5000):
        self.environment_url = environment_url.rstrip("/")
        self.base_url = f"{self.environment_url}{API_SEGMENT}"
        self._tokens = token_provider
        self._scope = dataverse_scope(self.environment_url)
        self._page_size = page_size
        self._http = httpx.Client(timeout=httpx.Timeout(120.0, connect=30.0))

    def close(self) -> None:
        self._http.close()

    # ------------------------------------------------------------------ HTTP

    def _headers(self) -> dict:
        return {
            "OData-MaxVersion": "4.0",
            "OData-Version": "4.0",
            "Accept": "application/json",
            "Prefer": f"odata.maxpagesize={self._page_size}",
        }

    def get_json(self, path_or_url: str, params: dict | None = None) -> dict:
        url = path_or_url if path_or_url.startswith("http") else f"{self.base_url}/{path_or_url}"
        response = authorized_request(
            self._http, "GET", url,
            token_provider=self._tokens, scope=self._scope,
            headers=self._headers(), params=params,
        )
        return response.json()

    def get_paged(self, path: str, params: dict | None = None) -> Iterator[dict]:
        payload = self.get_json(path, params)
        while True:
            yield from payload.get("value", [])
            next_link = payload.get("@odata.nextLink")
            if not next_link:
                return
            payload = self.get_json(next_link)

    # ----------------------------------------------------------- extraction

    def whoami(self) -> dict:
        return self.get_json("WhoAmI")

    def fetch_snapshot(self, progress: Callable[[str], None] = logger.info) -> Snapshot:
        observed_at = dt.datetime.now(dt.UTC).isoformat()
        run_id = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
        snapshot = Snapshot(run_id=run_id, observed_at=observed_at, environment_url=self.environment_url)

        progress("Fetching business units...")
        for row in self.get_paged(
            "businessunits", {"$select": "businessunitid,name,_parentbusinessunitid_value"}
        ):
            snapshot.business_units.append(
                BusinessUnit(
                    id=row["businessunitid"],
                    name=row.get("name") or row["businessunitid"],
                    parent_id=row.get("_parentbusinessunitid_value"),
                )
            )

        progress("Fetching users...")
        select = (
            "systemuserid,fullname,domainname,azureactivedirectoryobjectid,"
            "_businessunitid_value,isdisabled,accessmode,applicationid"
        )
        for row in self.get_paged("systemusers", {"$select": select}):
            snapshot.users.append(
                DvUser(
                    id=row["systemuserid"],
                    name=row.get("fullname") or row.get("domainname") or row["systemuserid"],
                    domain_name=row.get("domainname"),
                    aad_object_id=row.get("azureactivedirectoryobjectid"),
                    bu_id=row.get("_businessunitid_value") or "",
                    is_disabled=bool(row.get("isdisabled")),
                    access_mode=int(row.get("accessmode") or 0),
                    application_id=row.get("applicationid"),
                )
            )

        progress("Fetching teams...")
        for row in self.get_paged(
            "teams",
            {"$select": "teamid,name,teamtype,azureactivedirectoryobjectid,_businessunitid_value"},
        ):
            snapshot.teams.append(
                DvTeam(
                    id=row["teamid"],
                    name=row.get("name") or row["teamid"],
                    bu_id=row.get("_businessunitid_value") or "",
                    team_type=int(row.get("teamtype") or 0),
                    aad_object_id=row.get("azureactivedirectoryobjectid"),
                )
            )

        progress("Fetching security roles...")
        for row in self.get_paged(
            "roles",
            {
                "$select": "roleid,name,_businessunitid_value,_parentrootroleid_value",
                "$filter": "componentstate eq 0",
            },
        ):
            snapshot.roles.append(
                DvRole(
                    id=row["roleid"],
                    name=row.get("name") or row["roleid"],
                    bu_id=row.get("_businessunitid_value") or "",
                    root_role_id=row.get("_parentrootroleid_value"),
                )
            )

        progress("Fetching entity metadata (table ownership)...")
        table_index = self._fetch_table_metadata(snapshot)

        self._fetch_role_grants(snapshot, table_index, progress)

        progress("Fetching role assignments and team memberships (intersect entities)...")
        known_roles = {r.id for r in snapshot.roles}
        known_teams = {t.id for t in snapshot.teams}

        for row in self.get_paged(ROLE_USER_INTERSECT, {"$select": "systemuserid,roleid"}):
            if row.get("roleid") in known_roles:
                snapshot.user_roles.append((row["systemuserid"], row["roleid"]))
        progress(f"  user-role assignments: {len(snapshot.user_roles)}")

        for row in self.get_paged(ROLE_TEAM_INTERSECT, {"$select": "teamid,roleid"}):
            if row.get("roleid") in known_roles:
                snapshot.team_roles.append((row["teamid"], row["roleid"]))
        progress(f"  team-role assignments: {len(snapshot.team_roles)}")

        for row in self.get_paged(TEAM_MEMBERSHIP_INTERSECT, {"$select": "teamid,systemuserid"}):
            if row.get("teamid") in known_teams:
                snapshot.team_members.append((row["teamid"], row["systemuserid"]))
        progress(f"  team memberships: {len(snapshot.team_members)}")

        progress("Fetching field security profiles...")
        self._fetch_field_security(snapshot, table_index)

        progress("Snapshot complete: " + str(snapshot.counts()))
        return snapshot

    # ------------------------------------------------------------- internals

    def _fetch_table_metadata(self, snapshot: Snapshot) -> dict[str, str]:
        """Returns an index mapping lowercase schema/logical names -> logical name."""
        index: dict[str, str] = {}
        payload = self.get_json(
            "EntityDefinitions", {"$select": "LogicalName,SchemaName,ObjectTypeCode,OwnershipType"}
        )
        for row in payload.get("value", []):
            logical = row.get("LogicalName")
            if not logical:
                continue
            meta = TableMeta(
                logical_name=logical,
                schema_name=row.get("SchemaName") or logical,
                object_type_code=row.get("ObjectTypeCode"),
                ownership=parse_ownership(row.get("OwnershipType")),
            )
            snapshot.tables.append(meta)
            index[meta.schema_name.lower()] = logical
            index[logical.lower()] = logical
        return index

    def _fetch_role_grants(
        self, snapshot: Snapshot, table_index: dict[str, str], progress: Callable[[str], None]
    ) -> None:
        """Fetch read privileges once per distinct ROOT role. Business-unit copies of a
        role share the root role's privilege set (parentrootroleid), so grants are
        stored keyed by root id and resolved per instance at compile time."""
        representatives: dict[str, str] = {}
        for role in snapshot.roles:
            representatives.setdefault(role.root_role_id or role.id, role.id)
        progress(
            f"Fetching read privileges for {len(representatives)} root roles "
            f"({len(snapshot.roles)} instances)..."
        )
        unmatched: set[str] = set()
        skipped_depths: set[str] = set()
        for i, (root_id, instance_id) in enumerate(sorted(representatives.items()), start=1):
            if i % 25 == 0:
                progress(f"  role privileges {i}/{len(representatives)}")
            payload = self.get_json(f"RetrieveRolePrivilegesRole(RoleId=@rid)?@rid={instance_id}")
            for priv in payload.get("RolePrivileges", []):
                name = priv.get("PrivilegeName") or ""
                if not name.startswith(READ_ACCESS_PREFIX):
                    continue
                suffix = name[len(READ_ACCESS_PREFIX):].lower()
                table = table_index.get(suffix)
                if not table:
                    unmatched.add(name)
                    continue
                try:
                    depth = parse_depth(priv.get("Depth"))
                except ValueError:
                    skipped_depths.add(f"{name}:{priv.get('Depth')}")
                    continue
                snapshot.role_grants.append(
                    RoleReadGrant(role_id=root_id, table=table, depth=depth, privilege_name=name)
                )
        if skipped_depths:
            logger.warning(
                "Skipped %d privilege(s) with unsupported depth values (fail-closed): %s",
                len(skipped_depths), sorted(skipped_depths)[:10],
            )
        snapshot.unmatched_privileges = sorted(unmatched)

    def _fetch_field_security(self, snapshot: Snapshot, table_index: dict[str, str]) -> None:
        for row in self.get_paged(
            "fieldsecurityprofiles", {"$select": "fieldsecurityprofileid,name"}
        ):
            snapshot.fsps.append(
                FieldSecurityProfile(
                    id=row["fieldsecurityprofileid"], name=row.get("name") or ""
                )
            )
        known_profiles = {f.id for f in snapshot.fsps}
        for row in self.get_paged(
            USER_PROFILE_INTERSECT, {"$select": "systemuserid,fieldsecurityprofileid"}
        ):
            if row.get("fieldsecurityprofileid") in known_profiles:
                snapshot.user_fsps.append((row["systemuserid"], row["fieldsecurityprofileid"]))
        for row in self.get_paged(
            TEAM_PROFILE_INTERSECT, {"$select": "teamid,fieldsecurityprofileid"}
        ):
            if row.get("fieldsecurityprofileid") in known_profiles:
                snapshot.team_fsps.append((row["teamid"], row["fieldsecurityprofileid"]))
        for row in self.get_paged(
            "fieldpermissions",
            {"$select": "entityname,attributelogicalname,canread,_fieldsecurityprofileid_value"},
        ):
            profile_id = row.get("_fieldsecurityprofileid_value")
            entity = (row.get("entityname") or "").lower()
            if not profile_id:
                continue
            snapshot.field_permissions.append(
                FieldPermission(
                    profile_id=profile_id,
                    table=table_index.get(entity, entity),
                    attribute=row.get("attributelogicalname") or "",
                    can_read=int(row.get("canread") or 0),
                )
            )
