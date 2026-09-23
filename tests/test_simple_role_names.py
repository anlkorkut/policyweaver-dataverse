"""Display-only names must remain useful without inventing identity suffixes."""
import copy
import re

import pytest

from policyweaver.role_naming import MAX_ROLE_NAME_LENGTH, ReaderRoleLabel


def label(alias="pwtest001", unit="BNY Wealth", roles=("BNYM Contact Owner Role",)):
    return ReaderRoleLabel.from_mapping({
        "alias": alias,
        "business_unit": {"name": unit},
        "effective_roles": [{"name": name} for name in roles],
    })


def test_name_contains_only_user_home_bu_and_one_role_in_that_order():
    assert label().user_business_role_token() == "pwtest001BNYWealthBNYMContactOwnerRole"


def test_multiple_source_roles_keep_full_provenance_without_role_count_in_name():
    value = label(roles=("Basic", "ECRM Adviser", "BNYM Contact Owner Role"))
    before = copy.deepcopy(value.audit())
    assert value.user_business_role_token() == "pwtest001BNYWealthBNYMContactOwnerRole"
    assert value.audit() == before
    assert value.audit()["effective_role_count"] == 3
    assert value.audit()["role_names"] == ["BNYM Contact Owner Role", "ECRM Adviser", "Basic"]


@pytest.mark.parametrize("title, business_title", [
    ("BNYM Read Only", "BNYM"),
    ("BNYM Contact Read", "BNYMContact"),
    ("BNYMContactRead", "BNYMContact"),
    ("BNYMCreateAccountReadOnly", "BNYMAccount"),
    ("ECRM Append To Account Share", "ECRMAccount"),
    ("BNYAppendToContactAssign", "BNYContact"),
    ("BNYM CREATE READ WRITE UPDATE DELETE APPEND APPENDTO ASSIGN SHARE READONLY", "BNYM"),
    ("BNYM create read write update delete append appendto assign share readonly", "BNYM"),
    ("BusinessUnitReader SharePoint Ownership", "BusinessUnitReaderSharePointOwnership"),
    ("BNYMSharePointReadOnly", "BNYMSharePoint"),
    ("BNYM Appendage Shared Readership Creation Writeoff", "BNYMAppendageSharedReadershipCreationWriteoff"),
    ("BNYM Only Customer To Adviser", "BNYMOnlyCustomerToAdviser"),
    ("BNYMREADONLY", "BNYMREADONLY"),
])
def test_action_words_are_removed_without_erasing_business_words_or_audit(title, business_title):
    value = label(roles=(title,))
    assert value.user_business_role_token() == "pwtest001BNYWealth" + business_title
    assert value.audit()["primary_role_name"] == title
    assert value.audit()["role_names"] == [title]


@pytest.mark.parametrize("title", ["Read", "Read Only", "ReadOnly", "Append To", "AppendTo", "CreateReadWriteDeleteAssignShare"])
def test_action_only_title_fails_instead_of_fabricating_a_business_title(title):
    with pytest.raises(ValueError, match="no usable business label after removing privilege actions"):
        label(roles=(title,)).user_business_role_token()


def test_username_case_is_preserved_and_domain_is_never_emitted():
    value = label(alias="pW.test-001@example.invalid")
    assert value.user_business_role_token() == "pWtest001BNYWealthBNYMContactOwnerRole"
    direct = ReaderRoleLabel("pwtest001@example.invalid", "BNY Wealth", ("BNYM Contact Owner Role",))
    assert direct.user_business_role_token() == label().user_business_role_token()


def test_fabric_compatible_compaction_keeps_original_labels_in_audit():
    value = label(alias="josé.001", unit="Crédit / East", roles=("BNYM rôle -- O'Brien",))
    assert value.user_business_role_token() == "jose001CreditEastBNYMRoleOBrien"
    assert value.audit()["business_unit_name"] == "Crédit / East"
    assert value.audit()["role_names"] == ["BNYM rôle -- O'Brien"]


@pytest.mark.parametrize("alias", ["", "   ", "财富", "---", "001reader"])
def test_unusable_or_digit_leading_username_is_rejected_without_fake_prefix(alias):
    with pytest.raises(ValueError, match="username"):
        label(alias=alias).user_business_role_token()


@pytest.mark.parametrize("unit", ["", "   ", "财富", "---"])
def test_unusable_business_unit_is_rejected_without_fake_label(unit):
    with pytest.raises(ValueError, match="business unit"):
        label(unit=unit).user_business_role_token()


@pytest.mark.parametrize("roles", [(), ("财富",), ("---",)])
def test_missing_or_unusable_role_is_rejected_without_unroled_fallback(roles):
    with pytest.raises(ValueError, match="role"):
        label(roles=roles).user_business_role_token()


def test_long_components_reserve_username_and_bu_space_and_fit_sql_limit():
    name = label(alias="a" * 100, unit="B" * 100, roles=("C" * 200,)).user_business_role_token()
    assert name == "a" * 32 + "B" * 36 + "C" * 56
    assert len(name) == MAX_ROLE_NAME_LENGTH == 124
    assert re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", name)


def test_unused_username_and_bu_budget_is_available_for_role_title():
    name = label(alias="a", unit="B", roles=("C" * 200,)).user_business_role_token()
    assert name == "aB" + "C" * 122


def test_normalization_does_not_invent_a_suffix_to_hide_a_collision():
    first = label(alias="pw.test001", unit="East-Bank")
    second = label(alias="pwtest001", unit="East Bank")
    assert first.user_business_role_token() == second.user_business_role_token()
    # Collision refusal belongs to the complete native item plan, whose reader
    # identities and other roles this display-only helper deliberately lacks.


def test_legacy_readable_format_remains_unchanged():
    value = label(roles=("BNYM Contact Owner Role", "Basic"))
    before = value.readable_token()
    assert before == "BNYMContactOwnerRolePlus1pwtest001BUBNYWealth"
    value.user_business_role_token()
    assert value.readable_token() == before
