from conftest import add_role, add_user, assign, make_snapshot

from dvaccess.compile.effective_access import build_index
from dvaccess.compile.profiles import build_profiles
from dvaccess.config import CompileConfig
from dvaccess.models import Depth, canonical_scope_key


def test_identical_access_groups_into_one_profile():
    s = make_snapshot()
    add_role(s, "r-uk", "uk", [("account", Depth.LOCAL), ("product", Depth.GLOBAL)])
    for uid in ("u1", "u2", "u3"):
        add_user(s, uid, "uk")
        assign(s, uid, "r-uk")
    add_user(s, "outlier", "de")
    add_role(s, "r-de", "de", [("account", Depth.LOCAL)])
    assign(s, "outlier", "r-de")

    result = build_profiles(build_index(s, CompileConfig()), CompileConfig())
    assert len(result.profiles) == 2
    sizes = sorted(len(p.user_ids) for p in result.profiles)
    assert sizes == [1, 3]


def test_users_with_no_access_get_no_profile():
    s = make_snapshot()
    add_user(s, "idle", "uk")
    result = build_profiles(build_index(s, CompileConfig()), CompileConfig())
    assert result.profiles == []
    assert result.users_without_access == 1


def test_profile_hash_is_deterministic_and_order_insensitive():
    scopes_a = {"account": frozenset({"uk", "de"}), "product": "ALL"}
    scopes_b = {"product": "ALL", "account": frozenset({"de", "uk"})}
    assert canonical_scope_key(scopes_a) == canonical_scope_key(scopes_b)
    assert canonical_scope_key(scopes_a) != canonical_scope_key({"account": "ALL"})
