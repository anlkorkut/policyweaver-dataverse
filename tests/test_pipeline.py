import json

from conftest import add_role, add_team, add_user, assign, make_snapshot

from dvaccess.models import Depth
from dvaccess.pipeline import compile_from_snapshot


def test_compile_from_snapshot_writes_reports(app_config, tmp_path):
    s = make_snapshot()
    add_role(s, "r-uk", "uk", [("account", Depth.LOCAL), ("product", Depth.GLOBAL)])
    add_role(s, "r-basic", "uk", [("contact", Depth.BASIC)])
    for uid in ("u1", "u2"):
        add_user(s, uid, "uk")
        assign(s, uid, "r-uk")
    add_user(s, "u3", "uk")
    assign(s, "u3", "r-basic")
    add_team(s, "t1", "apac", members=["u1"], roles=[])

    compiled = compile_from_snapshot(s, app_config, tmp_path)

    assert len(compiled.profiles) == 1  # u1/u2 share access; u3 has none representable
    assert len(compiled.roles) == 1
    role = compiled.roles[0]
    assert role.table_paths == ["/Tables/dbo/account", "/Tables/dbo/product"]
    assert role.row_constraints == [
        ("/Tables/dbo/account", "SELECT * FROM dbo.account WHERE owningbusinessunit IN ('uk')")
    ]

    for artifact in (
        "compile_summary.json", "compile_summary.md", "manifest.json",
        "profiles.csv", "skipped_users.csv", "basic_depth_exclusions.csv",
    ):
        assert (tmp_path / artifact).exists(), artifact

    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest[0]["member_count"] == 2
    assert manifest[0]["tables"]["product"] == "ALL"
    assert manifest[0]["tables"]["account"] == {"business_units": ["UK"]}

    exclusions = (tmp_path / "basic_depth_exclusions.csv").read_text(encoding="utf-8")
    assert "u3" in exclusions and "basic_only" in exclusions
