"""Validated, secret-free deployment configuration for the read adapter."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TableSelection(Settings):
    name: str
    columns: tuple[str, ...] = Field(min_length=1)

    @field_validator("name")
    @classmethod
    def identifier(cls, value):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,99}", value):
            raise ValueError("Use a Dataverse logical table name")
        return value

    @field_validator("columns")
    @classmethod
    def column_names(cls, values):
        if len(set(values)) != len(values) or any(not re.fullmatch(r"[a-z_][a-z0-9_]{0,127}", v) for v in values):
            raise ValueError("Columns must be unique logical/property identifiers")
        if any(v.startswith("__pw_") for v in values):
            raise ValueError("The __pw_ namespace is reserved")
        return values


class AdapterConfig(Settings):
    schema_version: Literal[1] = 1
    environment_url: str
    tenant_id: str
    organization_id: str
    workspace_id: str
    deployment_name: str = "pw_demo"
    authentication: Literal["azure_cli", "managed_identity"] = "azure_cli"
    managed_identity_client_id: str | None = None
    identity_verification: Literal["fetchxml", "custom_api"] = "fetchxml"
    identity_api_name: str = "pw_ReadContext"
    identity_api_assembly_sha256: str | None = None
    readers: tuple[str, ...] = ()
    discover_readers: bool = False
    excluded_readers: tuple[str, ...] = ()
    max_readers: int = Field(default=1000, ge=1, le=1000)
    tables: tuple[TableSelection, ...] = Field(min_length=1)
    role_limit: int = Field(default=250, ge=2, le=1000)
    reserved_roles: int = Field(default=10, ge=0, le=100)
    tables_per_shard: int = Field(default=100, ge=1, le=500)
    serving_items: dict[str, str] = Field(default_factory=dict)
    batch_size: int = Field(default=2000, ge=1, le=10000)
    max_rows_per_reader_table: int = Field(default=1_000_000, ge=1)
    refresh_interval_seconds: int = Field(default=600, ge=30, le=1800)
    # Retention controls automatic withdrawal after publication, never the
    # finite source freshness or publication-reserve checks.
    retention_mode: Literal["timed", "manual"] = "timed"
    # Readable names are annotations over the same reader-scoped policy. They
    # require a fresh generation with complete source label provenance.
    role_naming: Literal["legacy", "readable"] = "legacy"
    source_workers: int = Field(default=1, ge=1, le=4, strict=True)
    generation_lifetime_seconds: int = Field(default=2700, ge=60, le=3000)
    publication_budget_seconds: int = Field(default=600, ge=60, le=1200)
    state_directory: str = ".policyweaver"

    @field_validator("tenant_id", "organization_id", "workspace_id")
    @classmethod
    def guid(cls, value):
        parsed = UUID(value)
        if not parsed.int:
            raise ValueError("Identity cannot be an empty GUID")
        return str(parsed)

    @field_validator("readers", "excluded_readers")
    @classmethod
    def ids(cls, values):
        normalized = tuple(str(UUID(v)) for v in values)
        if any(UUID(v).int == 0 for v in normalized):
            raise ValueError("Reader cannot be an empty GUID")
        if len(normalized) != len(set(normalized)):
            raise ValueError("Duplicate reader identity")
        return normalized

    @field_validator("deployment_name")
    @classmethod
    def deployment(cls, value):
        if not re.fullmatch(r"pw_[a-z0-9_]{1,35}", value):
            raise ValueError("Deployment name must begin pw_ and contain lowercase identifiers")
        return value

    @field_validator("identity_api_name")
    @classmethod
    def custom_api_identifier(cls, value):
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,127}", value):
            raise ValueError("Use one logical Custom API identifier without a path or parameters")
        return value

    @field_validator("identity_api_assembly_sha256")
    @classmethod
    def assembly_digest(cls, value):
        if value is not None and not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("Use the lowercase SHA-256 digest of the trusted Custom API plug-in assembly")
        return value

    @field_validator("environment_url")
    @classmethod
    def environment(cls, value):
        if not re.fullmatch(r"https://[a-zA-Z0-9-]+\.(?:crm\d*\.dynamics\.com|crm\.microsoftdynamics\.us|crm\.dynamics\.cn)/?", value):
            raise ValueError("Use an HTTPS Dataverse environment origin")
        return value.rstrip("/")

    @field_validator("serving_items")
    @classmethod
    def items(cls, values):
        normalized = {k: str(UUID(v)) for k, v in values.items()}
        if any(not re.fullmatch(r"a[0-9]{3,6}_t[0-9]{3,6}", key) for key in normalized):
            raise ValueError("Use planner shard keys such as a000_t000")
        if any(UUID(v).int == 0 for v in normalized.values()):
            raise ValueError("Serving item cannot be an empty GUID")
        if len(set(normalized.values())) != len(normalized):
            raise ValueError("A serving item cannot be reused by different shards")
        return normalized

    @model_validator(mode="after")
    def budgets(self):
        if self.identity_verification == "custom_api" and self.identity_api_assembly_sha256 is None:
            raise ValueError("Custom API identity verification requires a trusted assembly SHA-256 digest")
        if self.reserved_roles >= self.role_limit:
            raise ValueError("Role reserve must be below the item role quota")
        if self.generation_lifetime_seconds + self.publication_budget_seconds > 3600:
            raise ValueError("Freshness and enforcement reserve must fit 60 minutes")
        if self.refresh_interval_seconds >= self.generation_lifetime_seconds:
            raise ValueError("Refresh must run before a generation expires")
        if len(self.readers) > self.max_readers:
            raise ValueError("Reader count exceeds configured maximum")
        if len({t.name for t in self.tables}) != len(self.tables):
            raise ValueError("Duplicate table selection")
        return self

    @property
    def role_prefix(self):
        return self.deployment_name + "_"

    @property
    def fingerprint(self):
        # Item provisioning is a separate operation; its output must be included
        # when a prepared generation is later authorized for publication.
        value = self.model_dump(mode="json")
        # Preserve already-recorded timed configuration hashes across this
        # additive option. Explicit manual retention always changes the hash.
        if self.retention_mode == "timed":
            value.pop("retention_mode")
        if self.role_naming == "legacy":
            value.pop("role_naming")
        if self.source_workers == 1:
            value.pop("source_workers")
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def load_config(path: str | Path) -> AdapterConfig:
    return AdapterConfig.model_validate_json(Path(path).read_text(encoding="utf-8-sig"))


def save_config(config: AdapterConfig, path: str | Path) -> None:
    from .storage import _atomic_write
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, (config.model_dump_json(indent=2) + "\n").encode())


def state_path(config: AdapterConfig, config_path: Path) -> Path:
    path = Path(config.state_directory).expanduser()
    return path.resolve() if path.is_absolute() else (config_path.resolve().parent / path).resolve()
