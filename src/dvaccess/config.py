"""Configuration loading. Secrets never live in config files: the client secret is
read from the DVACCESS_CLIENT_SECRET environment variable (or Azure CLI /
DefaultAzureCredential is used when no secret is present)."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class EnvironmentConfig(BaseModel):
    name: str = "env"
    dataverse_url: str

    @field_validator("dataverse_url")
    @classmethod
    def _strip_slash(cls, v: str) -> str:
        return v.rstrip("/")


class AuthConfig(BaseModel):
    tenant_id: str
    client_id: str | None = None
    # Used when no service-principal secret is set: the Azure CLI subscription whose
    # cached account should authenticate. Selects the right tenant on machines signed
    # into several directories, without changing the global `az` default.
    cli_subscription: str | None = None


class FabricConfig(BaseModel):
    workspace_id: str
    item_id: str
    # Schema for table paths and RLS statements. Set to None for non-schema lakehouses.
    schema_name: str | None = "dbo"
    # OneLake enforces: a role name must start with a letter and contain only
    # letters and numbers. No underscores, hyphens, or dots - the API rejects the
    # whole payload with RequestBodyValidationFailed.
    role_prefix: str = "dv"
    role_budget: int = 1000
    tenant_id: str | None = None  # defaults to auth.tenant_id
    # Restrict compilation to tables that actually exist in the item. Dataverse grants
    # privileges on every table in the environment; only the synced subset is present.
    restrict_to_item_tables: bool = True


class EntraConfig(BaseModel):
    # "group": one Entra security group per access profile (recommended at scale).
    # "direct": users assigned directly to roles, chunked at the member limit.
    membership: str = "group"
    group_prefix: str = "dvsec-"

    @field_validator("membership")
    @classmethod
    def _check_membership(cls, v: str) -> str:
        if v not in ("group", "direct"):
            raise ValueError("entra.membership must be 'group' or 'direct'")
        return v


class CompileConfig(BaseModel):
    # Empty include list = all tables that carry read privileges in Dataverse.
    include_tables: list[str] = Field(default_factory=list)
    exclude_tables: list[str] = Field(default_factory=list)
    # Column-level security from field security profiles (M4; requires column metadata).
    cls_enabled: bool = False
    # systemuser.accessmode values eligible for grants: 0 Read-Write, 1 Administrative, 2 Read.
    user_access_modes: list[int] = Field(default_factory=lambda: [0, 1, 2])
    # Columns carrying the business unit, by table ownership type. User/team-owned
    # rows use owningbusinessunit; business-owned rows use businessunitid.
    rls_column: str = "owningbusinessunit"
    rls_column_business_owned: str = "businessunitid"


class LimitsConfig(BaseModel):
    max_members_per_role: int = 500
    max_permissions_per_role: int = 500
    max_rls_chars: int = 1000


class ApplyConfig(BaseModel):
    # When False, managed roles that are no longer desired are kept and reported
    # instead of deleted.
    prune: bool = False
    # Glob patterns for pre-existing roles this app should retire (delete) so it
    # becomes the single source of truth - e.g. ["*PWPolicy"] to replace roles left
    # by Microsoft's Policy Weaver. Roles carrying the managed role_prefix are never
    # matched here; they follow the normal create/update/prune path. Every retirement
    # is listed by name in the plan before apply writes anything.
    retire_role_patterns: list[str] = Field(default_factory=list)


class AppConfig(BaseModel):
    environment: EnvironmentConfig
    auth: AuthConfig
    fabric: FabricConfig
    entra: EntraConfig = Field(default_factory=EntraConfig)
    compile: CompileConfig = Field(default_factory=CompileConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    apply: ApplyConfig = Field(default_factory=ApplyConfig)
    run_dir: str = "runs"

    @property
    def fabric_tenant_id(self) -> str:
        return self.fabric.tenant_id or self.auth.tenant_id

    @model_validator(mode="after")
    def _check_role_prefix(self) -> AppConfig:
        prefix = self.fabric.role_prefix
        if not prefix or not prefix[0].isalpha() or not prefix.isalnum():
            raise ValueError(
                f"fabric.role_prefix {prefix!r} is invalid: OneLake role names must "
                "start with a letter and contain only letters and numbers."
            )
        return self


def load_config(path: str | Path) -> AppConfig:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return AppConfig.model_validate(raw)
