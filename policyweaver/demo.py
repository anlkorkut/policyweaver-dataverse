"""Explicitly synthetic fixtures; these are not the bank's or live users' grants."""
from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid5

from .models import Snapshot


def uid(name: str) -> str:
    return str(uuid5(NAMESPACE_URL, "https://policyweaver.invalid/demo/" + name))


def demo_snapshot() -> Snapshot:
    now = datetime.now(timezone.utc)
    return Snapshot.model_validate({
        "tenant_id": uid("tenant"), "organization_id": uid("organization"),
        "observed_at": now, "valid_until": now + timedelta(minutes=30), "source_kind": "synthetic",
        "business_units": [
            {"id": uid("root"), "name": "Demo bank"},
            {"id": uid("custody"), "name": "Custody", "parent_id": uid("root")},
            {"id": uid("funds"), "name": "Fund services", "parent_id": uid("custody")},
            {"id": uid("markets"), "name": "Markets", "parent_id": uid("root")},
        ],
        "users": [{"id": uid(n), "name": label, "entra_object_id": uid(n + "-entra"),
                   "bu_id": uid(bu), "enabled": enabled} for n, label, bu, enabled in [
                       ("analyst", "Alex • multiple BU roles", "custody", True),
                       ("teamonly", "Blair • team privileges only", "markets", True),
                       ("reader", "Casey • global rows, limited columns", "markets", True),
                       ("disabled", "Drew • disabled user", "custody", False),
                       ("unassigned", "Eden • shared record, no table privilege", "markets", True)]],
        "teams": [
            {"id": uid("owners"), "name": "Settlement owners", "bu_id": uid("custody"), "kind": "owner"},
            {"id": uid("reviewers"), "name": "Case review access team", "bu_id": uid("markets"), "kind": "access"},
        ],
        "tables": [{"name": "account", "ownership": "user_team", "columns": [
            {"name": "name"}, {"name": "creditlimit", "secured": True},
            {"name": "taxnumber", "secured": True, "masked": True}]}],
        "roles": [
            {"id": uid("deep"), "name": "Custody reader", "bu_id": uid("custody"),
             "grants": [{"table": "account", "depth": "Deep"}]},
            {"id": uid("local"), "name": "Markets reader", "bu_id": uid("markets"),
             "grants": [{"table": "account", "depth": "Local"}]},
            {"id": uid("basic"), "name": "Team-owned accounts", "bu_id": uid("custody"),
             "member_basic": False, "grants": [{"table": "account", "depth": "Basic"}]},
            {"id": uid("global"), "name": "All account rows", "bu_id": uid("root"),
             "grants": [{"table": "account", "depth": "Global"}]},
        ],
        "assignments": [
            {"principal_type": "user", "principal_id": uid("analyst"), "role_id": uid("deep")},
            {"principal_type": "user", "principal_id": uid("analyst"), "role_id": uid("local")},
            {"principal_type": "team", "principal_id": uid("owners"), "role_id": uid("basic")},
            {"principal_type": "user", "principal_id": uid("reader"), "role_id": uid("global")},
            {"principal_type": "user", "principal_id": uid("disabled"), "role_id": uid("global")},
        ],
        "memberships": [{"user_id": uid(u), "team_id": uid(t)} for u, t in [
            ("analyst", "owners"), ("analyst", "reviewers"), ("teamonly", "owners")]],
        "records": [{"id": uid(r), "table": "account", "owner_id": uid(owner), "owning_bu_id": uid(bu)}
                    for r, owner, bu in [
                        ("fund-account", "reader", "funds"), ("market-account", "reader", "markets"),
                        ("team-account", "owners", "custody"), ("private-account", "teamonly", "markets"),
                        ("shared-account", "reader", "root"), ("outside-account", "reader", "root")]],
        "record_access": [
            {"principal_type": "team", "principal_id": uid("reviewers"), "table": "account",
             "record_id": uid("shared-account"), "kind": "share", "evidence": "synthetic access-team grant"},
            {"principal_type": "user", "principal_id": uid("unassigned"), "table": "account",
             "record_id": uid("shared-account"), "kind": "share", "evidence": "synthetic share without table privilege"},
        ],
        "profiles": [
            {"id": uid("credit-profile"), "name": "Credit review", "permissions": [
                {"table": "account", "column": "creditlimit", "can_read": True}]},
            {"id": uid("tax-profile"), "name": "Masked tax review", "permissions": [
                {"table": "account", "column": "taxnumber", "can_read": True, "read_unmasked": "one"}]},
        ],
        "profile_assignments": [
            {"principal_type": "team", "principal_id": uid("reviewers"), "profile_id": uid("credit-profile")},
            {"principal_type": "user", "principal_id": uid("analyst"), "profile_id": uid("tax-profile")},
        ],
    })


def example_queries() -> list[dict]:
    return [{"label": label, "user_id": uid(user), "table": "account", "record_id": uid(record),
             "column": column, "expected_allowed": allowed}
            for label, user, record, column, allowed in [
                ("Deep reaches child BU", "analyst", "fund-account", None, True),
                ("A second role reaches a sibling BU", "analyst", "market-account", None, True),
                ("Team membership adds ownership access", "teamonly", "team-account", None, True),
                ("Team-only Basic does not grant personal ownership", "teamonly", "private-account", None, False),
                ("Access team supplies a record exception", "analyst", "shared-account", None, True),
                ("Sharing alone fails table privilege check", "unassigned", "shared-account", None, False),
                ("Global rows do not bypass secured columns", "reader", "fund-account", "creditlimit", False),
                ("Team profile adds column Read", "analyst", "fund-account", "creditlimit", True),
                ("One-record unmask cannot become bulk raw access", "analyst", "fund-account", "taxnumber", False),
                ("Disabled identity is denied", "disabled", "fund-account", None, False),
            ]]

