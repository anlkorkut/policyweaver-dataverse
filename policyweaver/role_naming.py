"""Human labels for native roles, independent of all authorization decisions.

OneLake allows 128 alphanumeric characters, but SQL endpoint synchronization
adds ``OLS_`` and therefore supports only 124. The final 50 characters bind a
name to its deployment and complete reader GUID; labels are never identifiers.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping
from uuid import UUID

MAX_ROLE_NAME_LENGTH = 124
_LABEL_BUDGET = MAX_ROLE_NAME_LENGTH - 2 - 50


def _token(value: str, fallback: str) -> str:
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    words = re.findall(r"[A-Za-z0-9]+", value)
    return "".join(word[:1].upper() + word[1:] for word in words) or fallback


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError(f"Invalid reader role label {label}")
    return value.strip()


def _role_priority(name: str) -> tuple[bool, int, str, str]:
    folded = name.casefold()
    inactive = bool(re.search(r"\b(?:deprecated|do[\s_-]*not[\s_-]*use)\b|[\[(]\s*legacy\s*[\])]", folded))
    priority = (0 if "bnym" in folded else 1 if "bny" in folded else
                2 if "ecrm" in folded else 4 if folded in {"basic", "basic user"} else 3)
    return inactive, priority, folded, name


@dataclass(frozen=True)
class ReaderRoleLabel:
    """Bounded display provenance. It cannot supply permissions or membership."""

    alias: str
    business_unit_name: str
    role_names: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ReaderRoleLabel":
        if not isinstance(value, Mapping):
            raise ValueError("Reader role labels must be objects")
        alias = _text(value.get("alias", value.get("display_name", "")), "alias")
        # Only the alias is displayed: do not copy the UPN/domain into a role.
        alias = alias.split("@", 1)[0]
        unit = value.get("business_unit", {})
        if not isinstance(unit, Mapping):
            raise ValueError("Reader business unit label must be an object")
        unit_name = _text(unit.get("name", ""), "business unit")
        roles = value.get("effective_roles", [])
        if not isinstance(roles, (list, tuple)) or len(roles) > 10000:
            raise ValueError("Effective role labels must be a bounded list")
        distinct: dict[str, str] = {}
        for role in roles:
            if not isinstance(role, Mapping):
                raise ValueError("Effective role labels must be objects")
            name = _text(role.get("name", ""), "role name")
            if not name:
                raise ValueError("Effective role name must not be empty")
            identity = role.get("root_role_id") or role.get("role_id")
            if identity is not None:
                identity = str(UUID(identity))
                if UUID(identity).int == 0:
                    raise ValueError("Role label identity cannot be empty")
            else:
                identity = "name:" + name.casefold()
            # Role copies in different BUs and direct/team duplicates count
            # once by root role identity; names need not be unique in Dataverse.
            distinct[identity] = min(name, distinct.get(identity, name), key=lambda n: (n.casefold(), n))
        return cls(alias, unit_name, tuple(sorted(distinct.values(), key=_role_priority)))

    @property
    def primary_role_name(self) -> str:
        return self.role_names[0] if self.role_names else "Unroled"

    def readable_token(self) -> str:
        # Reserve independent budgets for alias and home BU so a long role
        # title cannot erase either. Complete labels remain in the manifest.
        alias = _token(self.alias, "Reader")[:18]
        if self.alias and self.alias[:1].islower():
            alias = alias[:1].lower() + alias[1:]
        unit = _token(self.business_unit_name, "Unknown")[:18]
        extra = f"Plus{len(self.role_names) - 1}" if len(self.role_names) > 1 else ""
        role_budget = _LABEL_BUDGET - len(alias) - len(unit) - 2 - len(extra)
        role = _token(self.primary_role_name, "Role")[:role_budget]
        return role + extra + alias + "BU" + unit

    def audit(self) -> dict[str, Any]:
        return {"alias": self.alias, "business_unit_name": self.business_unit_name,
                "primary_role_name": self.primary_role_name,
                "effective_role_count": len(self.role_names), "role_names": list(self.role_names)}
