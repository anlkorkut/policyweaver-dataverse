from conftest import add_role, add_team, add_user, assign, make_snapshot

from dvaccess.extract.snapshot import latest_run_dir, load_snapshot, save_snapshot
from dvaccess.models import Depth


def test_snapshot_sqlite_roundtrip(tmp_path):
    s = make_snapshot()
    add_user(s, "alice", "uk")
    add_role(s, "r1", "uk", [("account", Depth.DEEP), ("product", Depth.GLOBAL)])
    assign(s, "alice", "r1")
    add_team(s, "t1", "apac", members=["alice"], roles=["r1"], team_type=2)
    s.unmatched_privileges = ["prvReadWeird"]

    db_path = save_snapshot(s, tmp_path)
    loaded = load_snapshot(db_path)

    assert loaded.run_id == s.run_id
    assert loaded.counts() == s.counts()
    assert {(g.role_id, g.table, g.depth) for g in loaded.role_grants} == {
        ("r1", "account", Depth.DEEP),
        ("r1", "product", Depth.GLOBAL),
    }
    assert loaded.team_members == [("t1", "alice")]
    assert loaded.users[0].aad_object_id == "aad-alice"
    assert latest_run_dir(tmp_path) == db_path.parent
