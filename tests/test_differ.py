from dvaccess.apply.differ import build_plan, normalize_role


def role(name, paths, members=(), extra=None):
    payload = {
        "name": name,
        "decisionRules": [
            {
                "effect": "Permit",
                "permission": [
                    {"attributeName": "Path", "attributeValueIncludedIn": list(paths)},
                    {"attributeName": "Action", "attributeValueIncludedIn": ["Read"]},
                ],
            }
        ],
        "members": {
            "microsoftEntraMembers": [
                {"objectId": m, "tenantId": "T", "objectType": "Group"} for m in members
            ]
        },
    }
    if extra:
        payload.update(extra)
    return payload


def test_normalize_ignores_order_id_and_guid_case():
    guid = "0AC2E25E-91A8-4BBA-AA9A-CD31FF7BC013"
    a = role("dv_x", ["/Tables/dbo/a", "/Tables/dbo/b"], [guid])
    b = role("dv_x", ["/Tables/dbo/b", "/Tables/dbo/a"], [guid.lower()], extra={"id": "server-id"})
    assert normalize_role(a) == normalize_role(b)


def test_plan_create_update_delete_and_passthrough():
    actual = [
        role("DefaultReader", ["*"]),
        role("humanRole", ["/Tables/dbo/x"]),
        role("dv_unchanged", ["/Tables/dbo/a"], ["g1"], extra={"id": "id-1"}),
        role("dv_changed", ["/Tables/dbo/a"], ["g1"], extra={"id": "id-2"}),
        role("dv_stale", ["/Tables/dbo/z"], ["g1"], extra={"id": "id-3"}),
    ]
    desired = [
        role("dv_unchanged", ["/Tables/dbo/a"], ["g1"]),
        role("dv_changed", ["/Tables/dbo/a", "/Tables/dbo/b"], ["g1"]),
        role("dv_new", ["/Tables/dbo/c"], ["g2"]),
    ]

    plan = build_plan(actual, "etag-1", desired, managed_prefix="dv_", prune=False)
    assert plan.creates == ["dv_new"]
    assert plan.updates == ["dv_changed"]
    assert plan.deletes == []
    assert plan.kept_stale == ["dv_stale"]
    assert plan.unchanged == ["dv_unchanged"]
    assert sorted(plan.unmanaged) == ["DefaultReader", "humanRole"]
    names = [r["name"] for r in plan.payload]
    assert set(names) == {
        "DefaultReader", "humanRole", "dv_unchanged", "dv_changed", "dv_new", "dv_stale",
    }
    updated = next(r for r in plan.payload if r["name"] == "dv_changed")
    assert updated["id"] == "id-2"  # server identity preserved on update

    plan_prune = build_plan(actual, "etag-1", desired, managed_prefix="dv_", prune=True)
    assert plan_prune.deletes == ["dv_stale"]
    assert "dv_stale" not in [r["name"] for r in plan_prune.payload]


def test_retire_patterns_delete_foreign_roles_but_spare_managed_and_others():
    actual = [
        role("DefaultReader", ["*"]),
        role("SalesRoleorgabcPWPolicy", ["/Tables/account"], extra={"id": "pw-1"}),
        role("ServiceRoleorgabcPWPolicy", ["/Tables/contact"], extra={"id": "pw-2"}),
        role("humanRole", ["/Tables/x"]),
        role("dv_keepme", ["/Tables/a"], ["g1"], extra={"id": "id-1"}),
    ]
    desired = [role("dv_keepme", ["/Tables/a"], ["g1"])]

    plan = build_plan(
        actual, "e1", desired, managed_prefix="dv_", prune=False,
        retire_patterns=["*PWPolicy"],
    )
    assert sorted(plan.retires) == ["SalesRoleorgabcPWPolicy", "ServiceRoleorgabcPWPolicy"]
    assert plan.has_changes  # retirement alone is a change
    payload_names = {r["name"] for r in plan.payload}
    assert "SalesRoleorgabcPWPolicy" not in payload_names  # deleted by omission
    assert {"DefaultReader", "humanRole", "dv_keepme"} <= payload_names  # untouched
    assert sorted(plan.unmanaged) == ["DefaultReader", "humanRole"]


def test_retire_patterns_never_swallow_managed_prefix_roles():
    """A careless pattern like '*' must not divert dv_ roles out of the normal path."""
    actual = [role("dv_a", ["/Tables/a"], ["g1"], extra={"id": "id-1"})]
    desired = [role("dv_a", ["/Tables/a"], ["g1"])]
    plan = build_plan(actual, "e1", desired, "dv_", prune=False, retire_patterns=["*"])
    assert plan.retires == []
    assert plan.unchanged == ["dv_a"]


def test_second_plan_after_apply_is_a_noop():
    desired = [role("dv_a", ["/Tables/dbo/a"], ["g1"])]
    first = build_plan([role("DefaultReader", ["*"])], "e1", desired, "dv_", prune=True)
    # simulate server state after apply = first payload with server ids
    applied = [dict(r, id=f"srv-{i}") for i, r in enumerate(first.payload)]
    second = build_plan(applied, "e2", desired, "dv_", prune=True)
    assert not second.has_changes
    assert second.unchanged == ["dv_a"]
