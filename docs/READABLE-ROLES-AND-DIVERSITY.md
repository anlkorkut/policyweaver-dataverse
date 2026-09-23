# Readable Fabric roles and varied Dataverse test personas

Policy Weaver publishes a reader's combined Dataverse Read results for the configured tables and fields. It does not copy each Dataverse business role into a separate Fabric business role. Multiple direct roles, owner-team roles, business-unit scopes, sharing and field security contribute to the source result. One native role per entitled reader per shard combines its RLS and CLS constraints.

A Dataverse role's name describes its business purpose; the actual privileges and assignments determine access. A role named Basic User is not the same concept as Basic privilege depth. A user without direct roles can still receive team roles. Conversely, a uniquely named role need not provide a unique set of permissions.

## Why selected table access can look uniform

Different readers can legitimately access the same selected tables while receiving different rows and field values. Shared table Read privileges reduce the number of independently variable table choices: activity tables such as task, email, phonecall and appointment share the activity Read privilege. A small selection may therefore be incapable of producing the number of distinct combinations a test designer requests.

Choose a client-specific fixture objective: distinct combinations, different table counts, or representative security semantics. A strictly increasing one-through-200 table ladder requires at least 200 independently variable tables. Include existing direct and inherited grants when proving diversity; adding a narrower direct role cannot remove a broader inherited grant.

## Simple names in version 0.3.1

New-client onboarding selects `"role_naming": "user_business_role"`. Existing deployments opt in by setting that value before preparing a **new** generation. Configurations that omit the option still mean `legacy`, preserving old fingerprints and prepared manifests.

```text
<Username><HomeBusinessUnit><OneBusinessRoleTitle>
pwtest001BNYWealthBNYMContactOwnerRole
```

There is no added `PW`, `BU`, role count, privilege-action label or ID suffix. The username is first, its original casing is retained and the UPN domain is omitted. Spaces and punctuation are removed because Fabric requires alphanumeric names. Username and BU receive up to 32 and 36 characters respectively; the selected role uses the remaining space within 124 characters. Full source strings remain in private audit evidence.

The title still prioritizes active BNYM, BNY and ECRM roles. Action words are removed from the selected title for display, including Create, Read, Write, Update, Delete, Append, Assign and Share. This does not change privileges or the original audit title. An unusable title/username/BU or a case-insensitive collision after normalization/truncation blocks preparation; the application never adds an undisclosed identifier or broadens access to resolve it.

One displayed role is a deterministic summary of cumulative access. It does not mean only that role contributes permissions, and the home BU does not replace the BU anchors of inherited roles.

### Ownership without an ID in the name

The canonical RLS predicate carries a versioned deployment/tenant annotation:

```sql
SELECT * FROM [dbo].[client_account]
WHERE __pw_reader = '<reader-guid>'
AND __pw_reader <> 'PolicyWeaverOwnerV1<tenant-and-deployment-sha256>'
AND __pw_generation = <generation>
```

The marker is deliberately not a GUID. Together with reader-GUID equality, the extra inequality is true for all matching reader rows; it grants no additional access and requires no new data column. It is an ownership annotation, **not a secret, signature or expiry lease**. The publisher and watchdog require the exact canonical row/column policy, single matching tenant/reader membership and deployment-owned table paths before treating a marked role as managed. Damaged marked policies block mutation. Unmarked foreign policies remain untouched; overlapping access or conflicting names block publication.

Version 0.3.1 recognizes old and new managed formats for replacement/withdrawal. Older controllers cannot recognize this new encoding. Upgrade **every publisher and independent watchdog** before publishing it; do not downgrade while these roles remain. A fresh preparation and normal engine qualification are required. A naming API dry run alone does not establish SQL/Spark enforcement.

## Previous readable format (version 0.2.3)

Set `"role_naming": "readable"` to opt in. The default remains `legacy`, preserving existing configuration fingerprints and immutable generations.

```text
PW<PrimaryBusinessRole>Plus<N><ReaderAlias>BU<HomeBusinessUnit>N<DeploymentHash16>R<ReaderGuid32>
```

Fictional example:

```text
PWContactOwnerRolePlus2reader078BUWealthN1234567890abcdefR44444444444444448444444444444444
```

- The display label prioritizes active BNYM, BNY and ECRM role titles. Deprecated and legacy titles remain in the audit record.
- `Plus2` means two additional distinct root-role families. Copies in different BUs and repeated direct/team assignment paths do not inflate that count.
- The user alias and home BU have reserved space. Long titles are truncated, punctuation is removed and Unicode is normalized to ASCII; full original strings remain in the manifest.
- The immutable suffix retains the deployment namespace and full Entra object ID. A rename or duplicate display name cannot change membership or authorization.
- The home BU is descriptive. Actual role BU anchors, cross-BU assignments and contributing teams remain in `reader_labels`; they are not replaced by that display label.

Microsoft's general role-name limit is 128 characters, but SQL endpoint synchronization supports at most 124. Role names must start with a letter, contain only alphanumeric characters and be unique without regard to case. The adapter uses 124; the requested literal hyphens/spaces are therefore not used. References: [role naming rules](https://learn.microsoft.com/en-us/fabric/onelake/security/create-manage-roles), [SQL endpoint limit](https://learn.microsoft.com/en-us/fabric/onelake/security/sql-analytics-endpoint-onelake-security#limitations).

## Complete mapping and multiple-role users

Readable preparation records each reader's immutable IDs, alias, display name, home BU, effective role instances and root IDs, each role's BU, direct/team assignment origins and observed teams. The Dataverse effective-role function supplements explicit membership observations for Entra group roles. Collection failure blocks readable preparation; it never creates a grant. The manifest includes the full provenance and each shard's `role_name_map` for inspection.

For a source role such as BNY Pershing RIA match, Organization Read on Business Unit maps to all readable `businessunit` rows only when that table is selected for export. User-depth Report access is evaluated by Dataverse for each reader, combined with any stronger grants from other roles or sharing. The Fabric role name is a useful summary of that combined result, not a claim that it exactly equals the named source role.

## Safe rollout

1. Upgrade every publisher and independent watchdog to version 0.3.1 before publishing `user_business_role` names. Verify the new scheduled execution while it still recognizes existing policies. See `deploy/README.md`.
2. Set the requested naming mode and reviewed table selection in the publisher configuration. Prepare a fresh generation; editing the old manifest or renaming roles manually is unsupported.
3. Review the mapping, run the native policy dry run, inspect the actual serving boundary and publish normally. The publisher replaces supported managed formats using ETags and preserves unrelated policies.
4. Check each reader's membership, permitted tables and representative row/field results through actual consumer sessions. Publication and role-name validation do not establish engine enforcement or data synchronization.

The publisher and upgraded watchdog recognize all three formats, including explicit withdrawal. Do not roll back a controller to an implementation that cannot identify the published policy encoding.

## Fixture fidelity and acceptance

If a client authorizes synthetic fixture variants, base them on reviewed installed roles and retain a before/after assignment ledger. Label them as test variants rather than unmodified customer roles. Account for every existing direct and inherited table grant when proving distinctness. Do not edit unrelated business roles, BU hierarchy, team memberships, POA or POAA to manufacture a desired result.

The per-user Dataverse variants are a test-fixture choice. Production Dataverse can keep shared business roles and team assignments; different combinations can arise naturally. The adapter must reproduce identical access when two readers really have identical permissions. It must never invent differences in Fabric to make a demonstration look varied.

Check catalog fidelity against the client's authoritative logical table and attribute metadata. Similar display names or empty replacement tables do not prove equivalence. Empty tables exercise permission presence and visibility; populated fixtures are needed to qualify Basic ownership, BU depth, team sharing and field results. Actual source-versus-consumer acceptance remains separate from a role or table-count comparison.

Manual retention remains a separate setting. Persistent roles represent the last published snapshot; source fixture changes do not appear in Fabric until a new generation is successfully published.
