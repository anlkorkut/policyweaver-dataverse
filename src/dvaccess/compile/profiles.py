"""Access-profile construction: group users with identical effective read access
into equivalence classes. One profile = one Entra group + one OneLake role family."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..config import CompileConfig
from ..models import ALL_ROWS, Profile, canonical_scope_key
from .effective_access import SecurityIndex, iter_user_scopes

logger = logging.getLogger(__name__)


@dataclass
class ProfileBuildResult:
    profiles: list[Profile] = field(default_factory=list)
    users_without_access: int = 0
    stats: dict = field(default_factory=dict)


def build_profiles(index: SecurityIndex, cfg: CompileConfig) -> ProfileBuildResult:
    by_key: dict[str, Profile] = {}
    users_without_access = 0

    for user, scopes in iter_user_scopes(index):
        if not scopes:
            users_without_access += 1
            continue
        fsp_signature = tuple(sorted(index.user_fsp_ids.get(user.id, ()))) if cfg.cls_enabled else ()
        key = canonical_scope_key(scopes, fsp_signature)
        profile = by_key.get(key)
        if profile is None:
            profile = Profile(profile_hash=key, scopes=scopes, fsp_signature=fsp_signature)
            by_key[key] = profile
        profile.user_ids.append(user.id)

    profiles = sorted(by_key.values(), key=lambda p: p.profile_hash)
    for profile in profiles:
        profile.user_ids.sort()

    sizes = sorted((len(p.user_ids) for p in profiles), reverse=True)
    table_counts = [len(p.scopes) for p in profiles]
    rls_tables = [
        sum(1 for s in p.scopes.values() if s != ALL_ROWS) for p in profiles
    ]
    stats = {
        "profiles": len(profiles),
        "users_in_profiles": sum(sizes),
        "users_without_access": users_without_access,
        "largest_profile_members": sizes[0] if sizes else 0,
        "median_profile_members": sizes[len(sizes) // 2] if sizes else 0,
        "max_tables_per_profile": max(table_counts, default=0),
        "max_rls_tables_per_profile": max(rls_tables, default=0),
    }
    logger.info("Profile stats: %s", stats)
    return ProfileBuildResult(profiles=profiles, users_without_access=users_without_access, stats=stats)
