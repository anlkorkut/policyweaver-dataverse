"""Qualified shadow compiler specifications; these are not source parity tests."""
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from itertools import product
import random

import pytest

from policyweaver.authorization import (
    AuthorizationCompiler, AuthorizationFactsError, AuthorizationSnapshot,
    BasicQualification, BusinessUnitFact, ColumnFact, Evidence, FieldPermissionFact,
    FieldProfileAssignment, FieldProfileFact, KNOWN_ACCESS_MASK, PoaFact, PrincipalRef,
    QualifiedRecordGrant, ReadContext, ReaderFact, RecordFact, RecordFieldGrant,
    SafeMaskedValue, TableFact, TeamFact, TeamMembershipFact,
)


NOW = datetime(2026, 9, 18, 12, tzinfo=timezone.utc)
ORG = "org"


def ev(key):
    return Evidence(key, "synthetic qualified oracle", f"Fixture evidence for {key}")


def user(key):
    return PrincipalRef("user", key)


def team(key):
    return PrincipalRef("team", key)


def fixture():
    bus = tuple(BusinessUnitFact(key, parent, ev(key)) for key, parent in
                (("root", None), ("a", "root"), ("aa", "a"), ("b", "root"), ("bb", "b")))
    readers = tuple(ReaderFact(f"u{i}", f"oid{i}", "a", ev(f"u{i}")) for i in range(3))
    teams = (TeamFact("t0", "b", "owner", ev("t0")), TeamFact("access", "a", "access", ev("access")))
    memberships = (TeamMembershipFact("u0", "t0", ev("u0-t0")), TeamMembershipFact("u0", "access", ev("u0-access")))
    table = TableFact("account", "read-account-id", "user_team",
                      (ColumnFact("name"), ColumnFact("secret", secured=True)), ev("account-meta"))
    context = ReadContext("c0", "u0", table.read_privilege_id, "Basic", "a", user("u0"), False, ev("c0"))
    basic = BasicQualification("u0", "account", True, (user("u0"), team("t0")),
                               (user("u0"), team("t0"), team("access"), PrincipalRef("organization", ORG)), (), ev("b0"))
    records = tuple(RecordFact(f"{owner.kind}-{owner.id}-{bu.id}", "account", owner, bu.id, ev(f"r-{owner.id}-{bu.id}"))
                    for owner, bu in product((user("u0"), user("u1"), team("t0")), bus))
    return AuthorizationSnapshot("tenant", ORG, NOW, NOW + timedelta(minutes=60), True, ev("qualification"),
                                 bus, readers, teams, memberships, (table,), (context,), (basic,), records)


def allowed(snapshot):
    return AuthorizationCompiler(snapshot).readable_record_ids("u0", "account", now=NOW)


def poa(key, record="user-u1-b", principal=None, direct=1, inherited=0):
    return PoaFact(key, "account", record, principal or user("u0"), direct, inherited, ev(key))


@pytest.mark.parametrize("left,right", list(product(("Basic", "Local", "Deep", "Global"), repeat=2)))
def test_contextual_union_against_independent_set_oracle(left, right):
    snapshot = fixture()
    snapshot = replace(snapshot, contexts=(replace(snapshot.contexts[0], depth=left),
                                          replace(snapshot.contexts[0], id="c1", depth=right, business_unit_anchor="b", evidence=ev("c1"))))
    descendants = {"root": {"root", "a", "aa", "b", "bb"}, "a": {"a", "aa"}, "b": {"b", "bb"}}
    basic_records = {r.id for r in snapshot.records if r.owner in {user("u0"), team("t0")}}
    depth_bu_sets = {"Basic": lambda anchor: set(), "Local": lambda anchor: {anchor},
                     "Deep": lambda anchor: descendants[anchor], "Global": lambda anchor: descendants["root"]}
    bus = depth_bu_sets[left]("a") | depth_bu_sets[right]("b")
    expected = basic_records | {r.id for r in snapshot.records if r.owning_business_unit_id in bus}
    assert allowed(snapshot) == expected


def test_modernized_ownership_is_not_restricted_to_readers_home_bu():
    result = allowed(fixture())
    assert "user-u0-bb" in result
    assert "team-t0-root" in result
    assert "user-u1-a" not in result


def test_team_only_basic_and_poa_are_explicitly_qualified_independently():
    snapshot = fixture()
    snapshot = replace(snapshot,
                       contexts=(replace(snapshot.contexts[0], source_principal=team("t0")),),
                       basic_qualifications=(replace(snapshot.basic_qualifications[0], personal_basic=False,
                                                     owner_principals=(team("t0"),), sharing_principals=(team("t0"),)),),
                       poa=(poa("team-share", principal=team("t0")), poa("personal-share", record="user-u1-aa")))
    result = allowed(snapshot)
    assert result == {r.id for r in snapshot.records if r.owner == team("t0")} | {"user-u1-b"}
    assert "user-u0-a" not in result
    assert "user-u1-aa" not in result
    # Changing a recorded inheritance bit alone must not invent personal access.
    assert allowed(replace(snapshot, contexts=(replace(snapshot.contexts[0], member_basic=True),))) == result


def test_poa_direct_inherited_user_team_organization_and_access_team_are_cumulative():
    snapshot = fixture()
    principals = (user("u0"), team("t0"), PrincipalRef("organization", ORG), team("access"))
    rows = ("user-u1-root", "user-u1-aa", "user-u1-b", "user-u1-bb")
    shares = tuple(poa(f"p{i}", row, principal, direct=(1 if i % 2 == 0 else 0), inherited=(1 if i % 2 else 0))
                   for i, (row, principal) in enumerate(zip(rows, principals)))
    compiler = AuthorizationCompiler(replace(snapshot, poa=shares))
    assert set(rows) <= compiler.readable_record_ids("u0", "account", now=NOW)
    assert not compiler.evaluate_row("u1", "account", rows[0], now=NOW).allowed
    assert compiler.evaluate_row("u1", "account", rows[0], now=NOW).reasons[0].code == "no_table_read"


@pytest.mark.parametrize("mask", [0, 2, 4, 16, 32, 65536, 262144, 524288, KNOWN_ACCESS_MASK & ~1])
def test_non_read_actions_never_grant_read(mask):
    snapshot = replace(fixture(), poa=(poa("nonread", direct=mask, inherited=mask),))
    assert "user-u1-b" not in allowed(snapshot)


def test_independent_direct_inherited_and_owner_reasons_survive_revocation():
    snapshot = replace(fixture(), poa=(poa("foreign", direct=3, inherited=1), poa("own", "user-u0-b")))
    compiler = AuthorizationCompiler(snapshot)
    assert {r.code for r in compiler.evaluate_row("u0", "account", "user-u1-b", now=NOW).reasons} >= {
        "poa_direct_read", "poa_inherited_read", "table_read_gate"}
    revoked = AuthorizationCompiler(replace(snapshot, poa=()))
    assert not revoked.evaluate_row("u0", "account", "user-u1-b", now=NOW).allowed
    assert revoked.evaluate_row("u0", "account", "user-u0-b", now=NOW).allowed


def test_field_profiles_and_record_field_shares_union_with_null_denials():
    snapshot = fixture()
    profiles = (FieldProfileFact("deny-profile", ev("fp0")), FieldProfileFact("allow-profile", ev("fp1")))
    assignments = (FieldProfileAssignment("deny-profile", user("u0"), ev("fa0")),
                   FieldProfileAssignment("allow-profile", team("t0"), ev("fa1")))
    permissions = (FieldPermissionFact("deny-profile", "account", "secret", False, ev("f0")),
                   FieldPermissionFact("allow-profile", "account", "secret", True, ev("f1")))
    field_share = RecordFieldGrant("field-share", "account", "user-u0-a", "secret", user("u0"), True, ev("poaa"))
    full = replace(snapshot, field_profiles=profiles, profile_assignments=assignments,
                   field_permissions=permissions, record_field_grants=(field_share,))
    compiler = AuthorizationCompiler(full)
    projection = compiler.project("u0", "account", "user-u0-a", {"name": "ordinary", "secret": 123}, now=NOW)
    assert projection.values == {"name": "ordinary", "secret": 123}
    assert {r.code for r in projection.cells[1].reasons} == {"field_profile_read", "record_field_read"}
    profile_revoked = AuthorizationCompiler(replace(full, profile_assignments=assignments[:1]))
    assert profile_revoked.project("u0", "account", "user-u0-a", {"name": "ordinary", "secret": 123}, now=NOW).values["secret"] == 123
    denied = profile_revoked.project("u0", "account", "user-u0-b", {"name": "ordinary", "secret": 123}, now=NOW)
    assert denied.decision.allowed and denied.values["secret"] is None
    assert denied.cells[1].state == "denied_null"
    all_revoked = AuthorizationCompiler(replace(full, profile_assignments=assignments[:1], record_field_grants=()))
    assert all_revoked.project("u0", "account", "user-u0-a", {"name": "ordinary", "secret": 123}, now=NOW).values["secret"] is None


def test_field_grants_never_grant_rows_or_missing_table_privilege():
    snapshot = replace(fixture(), record_field_grants=(
        RecordFieldGrant("outside-scope", "account", "user-u1-a", "secret", user("u0"), True, ev("poaa1")),
        RecordFieldGrant("outside-privilege", "account", "user-u1-a", "secret", user("u1"), True, ev("poaa2")),))
    compiler = AuthorizationCompiler(snapshot)
    for reader in ("u0", "u1"):
        projected = compiler.project(reader, "account", "user-u1-a", {"name": "ordinary", "secret": "raw"}, now=NOW)
        assert not projected.decision.allowed and not projected.cells


def test_team_membership_revocation_removes_team_poa_profile_and_ownership():
    snapshot = fixture()
    snapshot = replace(snapshot, poa=(poa("team-only", principal=team("t0")),),
                       field_profiles=(FieldProfileFact("team-profile", ev("profile")),),
                       profile_assignments=(FieldProfileAssignment("team-profile", team("t0"), ev("assignment")),),
                       field_permissions=(FieldPermissionFact("team-profile", "account", "secret", True, ev("permission")),))
    compiler = AuthorizationCompiler(snapshot)
    assert compiler.evaluate_row("u0", "account", "user-u1-b", now=NOW).allowed
    assert compiler.evaluate_row("u0", "account", "team-t0-b", now=NOW).allowed
    assert compiler.project("u0", "account", "user-u0-a", {"name": "own", "secret": 1}, now=NOW).values["secret"] == 1
    qualification = replace(snapshot.basic_qualifications[0], owner_principals=(user("u0"),), sharing_principals=(user("u0"),))
    revoked = AuthorizationCompiler(replace(snapshot, memberships=(), basic_qualifications=(qualification,)))
    assert not revoked.evaluate_row("u0", "account", "user-u1-b", now=NOW).allowed
    assert not revoked.evaluate_row("u0", "account", "team-t0-b", now=NOW).allowed
    own = revoked.project("u0", "account", "user-u0-a", {"name": "own", "secret": 1}, now=NOW)
    assert own.decision.allowed and own.values["secret"] is None


def test_non_reader_system_user_can_own_a_shared_record_without_entra_identity():
    snapshot = fixture()
    system = ReaderFact("system", None, "a", ev("system"), application=True)
    record = RecordFact("system-owned", "account", user("system"), "b", ev("system-owned"))
    snapshot = replace(snapshot, readers=(*snapshot.readers, system), records=(*snapshot.records, record),
                       poa=(poa("system-share", record="system-owned"),))
    compiler = AuthorizationCompiler(snapshot)
    assert compiler.evaluate_row("u0", "account", "system-owned", now=NOW).allowed
    assert not compiler.evaluate_row("system", "account", "system-owned", now=NOW).allowed


def test_null_visible_data_is_not_mistaken_for_a_denied_field():
    snapshot = replace(fixture(), record_field_grants=(
        RecordFieldGrant("fg", "account", "user-u0-a", "secret", user("u0"), True, ev("fg")),))
    projection = AuthorizationCompiler(snapshot).project("u0", "account", "user-u0-a", {"name": None, "secret": None}, now=NOW)
    assert projection.values == {"name": None, "secret": None}
    assert all(c.state == "value" for c in projection.cells)


def test_masked_fields_require_qualified_values_and_never_receive_raw_value():
    snapshot = fixture()
    snapshot = replace(snapshot, tables=(replace(snapshot.tables[0], columns=(ColumnFact("name", masked=True), ColumnFact("secret", secured=True))),))
    with pytest.raises(AuthorizationFactsError, match="safe-value provider"):
        AuthorizationCompiler(snapshot)

    class SafeProvider:
        calls = []

        def project(self, reader_id, table, record_id, column):
            self.calls.append((reader_id, table, record_id, column))
            return SafeMaskedValue("***-1234", ev("source-masked-projection"))

    provider = SafeProvider()
    projection = AuthorizationCompiler(snapshot, masked_value_provider=provider).project(
        "u0", "account", "user-u0-a", {"name": "SSN RAW", "secret": "RAW"}, now=NOW)
    assert projection.values == {"name": "***-1234", "secret": None}
    assert provider.calls == [("u0", "account", "user-u0-a", "name")]
    assert projection.cells[0].state == "qualified_masked_value"


def test_mask_provider_cannot_return_unqualified_raw_scalar():
    snapshot = fixture()
    snapshot = replace(snapshot, tables=(replace(snapshot.tables[0], columns=(ColumnFact("name", masked=True), ColumnFact("secret", secured=True))),))

    class BadProvider:
        def project(self, *_):
            return "unqualified"

    with pytest.raises(AuthorizationFactsError, match="SafeMaskedValue"):
        AuthorizationCompiler(snapshot, masked_value_provider=BadProvider()).project(
            "u0", "account", "user-u0-a", {"name": "raw", "secret": "raw"}, now=NOW)


def test_activity_privilege_fans_out_through_metadata_without_name_parsing():
    snapshot = fixture()
    names = ("activitypointer", "email", "task", "phonecall", "annotation", "systemuser")
    tables = tuple(TableFact(name, "shared-activity-guid" if i < 4 else f"distinct-{i}", "user_team",
                             (ColumnFact("name"),), ev(name)) for i, name in enumerate(names))
    records = tuple(RecordFact(f"row-{i}", name, user("u0"), "a", ev(f"row-{i}")) for i, name in enumerate(names))
    contexts = (replace(snapshot.contexts[0], privilege_id="shared-activity-guid"),)
    qualifications = tuple(replace(snapshot.basic_qualifications[0], table=t.name) for t in tables[:4])
    snapshot = replace(snapshot, tables=tables, records=records, contexts=contexts, basic_qualifications=qualifications)
    compiler = AuthorizationCompiler(snapshot)
    assert [compiler.evaluate_row("u0", t.name, f"row-{i}", now=NOW).allowed for i, t in enumerate(tables)] == [True] * 4 + [False] * 2


def test_table_record_identity_prevents_cross_table_poa_leakage():
    snapshot = fixture()
    other = replace(snapshot.tables[0], name="contact", read_privilege_id="read-contact", evidence=ev("contact"))
    other_record = replace(snapshot.records[-1], table="contact", id="user-u1-b", owner=user("u1"))
    snapshot = replace(snapshot, tables=(*snapshot.tables, other), records=(*snapshot.records, other_record),
                       contexts=(*snapshot.contexts, replace(snapshot.contexts[0], id="contact-c", privilege_id="read-contact")),
                       basic_qualifications=(*snapshot.basic_qualifications, replace(snapshot.basic_qualifications[0], table="contact")),
                       poa=(poa("account-only"),))
    compiler = AuthorizationCompiler(snapshot)
    assert compiler.evaluate_row("u0", "account", "user-u1-b", now=NOW).allowed
    assert not compiler.evaluate_row("u0", "contact", "user-u1-b", now=NOW).allowed


def test_qualified_business_owned_basic_is_explicit_bu_scope():
    snapshot = fixture()
    table = replace(snapshot.tables[0], ownership="business_unit")
    records = tuple(RecordFact(f"row-{bu.id}", "account", None, bu.id, ev(f"row-{bu.id}")) for bu in snapshot.business_units)
    qualification = replace(snapshot.basic_qualifications[0], personal_basic=False, owner_principals=(), business_units=("a",))
    snapshot = replace(snapshot, tables=(table,), records=records, basic_qualifications=(qualification,))
    assert allowed(snapshot) == {"row-a"}


def test_organization_owned_tables_require_normalized_global_context():
    snapshot = fixture()
    snapshot = replace(snapshot, tables=(replace(snapshot.tables[0], ownership="organization"),),
                       records=(RecordFact("org-row", "account", None, None, ev("org-row")),),
                       basic_qualifications=(replace(snapshot.basic_qualifications[0], personal_basic=False, owner_principals=()),))
    with pytest.raises(AuthorizationFactsError, match="organization-owned"):
        AuthorizationCompiler(snapshot)
    assert allowed(replace(snapshot, contexts=(replace(snapshot.contexts[0], depth="Global"),))) == {"org-row"}


def test_additional_hierarchy_grants_require_table_gate():
    snapshot = replace(fixture(), record_grants=(
        QualifiedRecordGrant("h0", "u0", "account", "user-u1-a", "hierarchy", ev("h0")),
        QualifiedRecordGrant("h1", "u1", "account", "user-u1-a", "security_parent", ev("h1")),))
    compiler = AuthorizationCompiler(snapshot)
    assert compiler.evaluate_row("u0", "account", "user-u1-a", now=NOW).allowed
    assert not compiler.evaluate_row("u1", "account", "user-u1-a", now=NOW).allowed


@pytest.mark.parametrize("change", [dict(enabled=False), dict(application=True), dict(access_mode=4)])
def test_ineligible_reader_denies_even_with_all_privileges(change):
    snapshot = fixture()
    snapshot = replace(snapshot, readers=(replace(snapshot.readers[0], **change), *snapshot.readers[1:]),
                       contexts=(replace(snapshot.contexts[0], depth="Global"),))
    assert not allowed(snapshot)


@pytest.mark.parametrize("at,expected", [(NOW - timedelta(microseconds=1), False), (NOW, True),
                                         (NOW + timedelta(minutes=60) - timedelta(microseconds=1), True),
                                         (NOW + timedelta(minutes=60), False)])
def test_snapshot_lease_half_open_boundary(at, expected):
    decision = AuthorizationCompiler(fixture()).evaluate_row("u0", "account", "user-u0-a", now=at)
    assert decision.allowed is expected
    assert decision.publication_authorized is False


def test_identity_boundary_unknown_requests_and_naive_clock_fail_closed():
    compiler = AuthorizationCompiler(fixture())
    assert not compiler.evaluate_row("u0", "account", "user-u0-a", now=NOW, tenant_id="other").allowed
    assert not compiler.evaluate_row("u0", "account", "user-u0-a", now=NOW, organization_id="other").allowed
    assert not compiler.evaluate_row("u0", "account", "user-u0-a", now=NOW.replace(tzinfo=None)).allowed
    assert not compiler.evaluate_row("absent", "account", "user-u0-a", now=NOW).allowed
    assert not compiler.evaluate_row("u0", "unknown", "user-u0-a", now=NOW).allowed


@pytest.mark.parametrize("mask", [-1, 8, 1 << 40, True, "1"])
def test_unknown_invalid_masks_reject_whole_snapshot(mask):
    with pytest.raises(AuthorizationFactsError, match="mask"):
        AuthorizationCompiler(replace(fixture(), poa=(poa("bad", direct=mask),)))


@pytest.mark.parametrize("mutation", [
    lambda s: replace(s, complete=False),
    lambda s: replace(s, blockers=("unqualified hierarchy",)),
    lambda s: replace(s, valid_until=s.observed_at),
    lambda s: replace(s, valid_until=s.observed_at + timedelta(minutes=61)),
    lambda s: replace(s, observed_at=s.observed_at.replace(tzinfo=None)),
    lambda s: replace(s, readers=list(s.readers)),
    lambda s: replace(s, basic_qualifications=()),
    lambda s: replace(s, basic_qualifications=(replace(s.basic_qualifications[0], personal_basic=None),)),
    lambda s: replace(s, basic_qualifications=(replace(s.basic_qualifications[0], personal_basic=False),)),
    lambda s: replace(s, basic_qualifications=(replace(s.basic_qualifications[0], owner_principals=(user("u1"),)),)),
    lambda s: replace(s, contexts=(replace(s.contexts[0], privilege_id="prvReadActivity"),)),
    lambda s: replace(s, contexts=(replace(s.contexts[0], depth="County"),)),
    lambda s: replace(s, contexts=(replace(s.contexts[0], source_principal=team("access")),)),
    lambda s: replace(s, contexts=(replace(s.contexts[0], source_principal=user("u1")),)),
    lambda s: replace(s, teams=(replace(s.teams[0], kind="unsupported"), *s.teams[1:])),
    lambda s: replace(s, business_units=(replace(s.business_units[0], parent_id="aa"), *s.business_units[1:])),
    lambda s: replace(s, business_units=(s.business_units[0], replace(s.business_units[1], parent_id=None), *s.business_units[2:])),
    lambda s: replace(s, business_units=(s.business_units[0], replace(s.business_units[1], parent_id="missing"), *s.business_units[2:])),
    lambda s: replace(s, readers=(s.readers[0], replace(s.readers[1], entra_object_id=s.readers[0].entra_object_id), *s.readers[2:])),
    lambda s: replace(s, memberships=(TeamMembershipFact("u0", "missing", ev("bad")),)),
    lambda s: replace(s, records=(replace(s.records[0], owner=team("access")), *s.records[1:])),
    lambda s: replace(s, records=(replace(s.records[0], owner=PrincipalRef("department", "bad")), *s.records[1:])),
    lambda s: replace(s, poa=(poa("missing-record", record="missing"),)),
    lambda s: replace(s, poa=(poa("foreign-org", principal=PrincipalRef("organization", "other")),)),
])
def test_malformed_incomplete_or_dangling_facts_reject(mutation):
    with pytest.raises(AuthorizationFactsError):
        AuthorizationCompiler(mutation(fixture()))


def test_snapshot_and_results_are_immutable_and_have_provenance():
    snapshot = fixture()
    compiler = AuthorizationCompiler(snapshot)
    with pytest.raises(FrozenInstanceError):
        snapshot.complete = False
    projection = compiler.project("u0", "account", "user-u0-a", {"name": "hello", "secret": "private"}, now=NOW)
    with pytest.raises(TypeError):
        projection.values["secret"] = "changed"
    assert len(projection.decision.snapshot_id) == 64
    assert all(reason.evidence for reason in projection.decision.reasons)
    assert all(reason.evidence for cell in projection.cells for reason in cell.reasons)
    assert compiler.snapshot_id == AuthorizationCompiler(snapshot).snapshot_id
    assert compiler.snapshot_id != AuthorizationCompiler(replace(snapshot, valid_until=NOW + timedelta(minutes=59))).snapshot_id


@pytest.mark.parametrize("values", [{"name": "a"}, {"name": "a", "secret": "b", "raw_secret": "c"},
                                    {"name": {"expanded": "unreviewed"}, "secret": "b"},
                                    {"name": float("nan"), "secret": "b"}])
def test_projection_rejects_unknown_missing_and_unnormalized_columns(values):
    with pytest.raises(AuthorizationFactsError):
        AuthorizationCompiler(fixture()).project("u0", "account", "user-u0-a", values, now=NOW)


@pytest.mark.parametrize("count", [200, 1000])
def test_200_and_1000_reader_diagonal_poa_isolation_and_revocation(count):
    """Deterministic scale fixture plus independent edge-set oracle.

    No throughput or live tenant certification is inferred from this test.
    """
    snapshot = fixture()
    readers = tuple(ReaderFact(f"scale-u{i}", f"scale-oid{i}", "a", ev(f"su{i}")) for i in range(count))
    records = tuple(RecordFact(f"scale-r{i}", "account", user(r.id), "bb" if i % 2 else "a", ev(f"sr{i}"))
                    for i, r in enumerate(readers))
    contexts = tuple(replace(snapshot.contexts[0], id=f"sc{i}", reader_id=r.id,
                             source_principal=user(r.id), evidence=ev(f"sc{i}")) for i, r in enumerate(readers))
    qualifications = tuple(BasicQualification(r.id, "account", True, (user(r.id),), (user(r.id),), (), ev(f"sq{i}"))
                           for i, r in enumerate(readers))
    shares = tuple(PoaFact(f"sp{i}", "account", records[(i + 1) % count].id, user(r.id),
                           i % 2, (i + 1) % 2, ev(f"sp{i}")) for i, r in enumerate(readers))
    fields = tuple(RecordFieldGrant(f"sf{i}", "account", records[(i + 1) % count].id, "secret", user(r.id), True, ev(f"sf{i}"))
                   for i, r in enumerate(readers) if i % 3 == 0)
    scaled = replace(snapshot, readers=readers, teams=(), memberships=(), records=records, contexts=contexts,
                     basic_qualifications=qualifications, poa=shares, record_field_grants=fields)
    compiler = AuthorizationCompiler(scaled)
    expected_edges = {(r.id, records[i].id) for i, r in enumerate(readers)}
    expected_edges |= {(r.id, records[(i + 1) % count].id) for i, r in enumerate(readers)}
    expected_cells = {(r.id, records[(i + 1) % count].id) for i, r in enumerate(readers) if i % 3 == 0}
    randomizer = random.Random(count)
    for i, reader in enumerate(readers):
        adversarial = {i, (i + 1) % count, (i - 1) % count, (i + count // 2) % count, randomizer.randrange(count)}
        for record_index in adversarial:
            record = records[record_index]
            projected = compiler.project(reader.id, "account", record.id, {"name": record.id, "secret": record_index}, now=NOW)
            assert projected.decision.allowed == ((reader.id, record.id) in expected_edges)
            if projected.decision.allowed:
                assert projected.values["secret"] == (record_index if (reader.id, record.id) in expected_cells else None)
            else:
                assert projected.cells == ()
    # Remove one read cause. Every private ownership grant survives; shared-only
    # grants disappear, including those whose field grant still exists.
    revoked = AuthorizationCompiler(replace(scaled, poa=()))
    for i, reader in enumerate(readers):
        assert revoked.evaluate_row(reader.id, "account", records[i].id, now=NOW).allowed
        assert not revoked.evaluate_row(reader.id, "account", records[(i + 1) % count].id, now=NOW).allowed
