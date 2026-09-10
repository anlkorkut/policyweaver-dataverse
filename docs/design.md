# Design: Dataverse → OneLake Security Compiler

## Problem

Fabric sync (Link to Fabric / mirroring) copies Dataverse data but not its
security model. Large regulated environments need Dataverse read entitlements
enforced on OneLake. The reference scale used throughout this document is a
tenant with roughly 15,000 users, 350+ security roles, 90+ business units, and
2,000+ privilege-target tables. Scope is **read-only** privileges by explicit
decision: create/write/delete are out of scope.

## Why role-by-role sync fails (verified limits, Aug 2026 docs)

| OneLake limit | Value | Collision at this scale |
| --- | --- | --- |
| Roles per item | 250 (1,000 by ticket) | hundreds of assigned roles × dozens of BU copies |
| Members per role | 500 | tens of thousands of users; large base roles ≫ 500 |
| Permissions per role | 500 | broad roles read ≈2K tables |
| RLS statement length | 1,000 chars, static SQL | Deep over 90+ BU GUIDs ≈ 3,800 chars |
| RLS/CLS across roles | mixing ⇒ query errors | users average ~3 roles |
| RLS dynamic functions | none (no CURRENT_USER) | Basic (own-records) depth inexpressible |

## Core idea: compile, then compress

1. **Effective access per user per table** — union over direct role instances
   and team role instances ("greatest access prevails"):
   - org-owned table or Global depth ⇒ `ALL`
   - Deep ⇒ role instance's BU subtree (⇒ `ALL` when subtree = all BUs)
   - Local ⇒ role instance's BU
   - unions of BU sets; set covering all BUs normalizes to `ALL`
   - Basic ⇒ subsumed when the user's own BU (and their teams' BUs) are inside
     the granted scope; otherwise **fail-closed excluded** and reported
     (`basic_only` = no grant at all, `basic_partial` = BU grants kept, the
     own-records increment dropped).
   Role instances are BU-stamped copies (`parentrootroleid` links them), so the
   instance's BU is the correct Local/Deep context for both user and team
   assignments.
2. **Access profiles** — users with byte-identical effective access (canonical
   SHA-256 over sorted `{table → ALL | sorted BU set}`) form one profile.
   Multi-role users and overlapping teams are resolved *before* role emission,
   so each user belongs to exactly **one** profile ⇒ no cross-role RLS/CLS
   combination hazards, and profile count ≪ user count.
3. **Role emission with limits enforced by construction**
   (`compile/onelake_model.py`):
   - one RLS statement per table: `SELECT * FROM dbo.t WHERE owningbusinessunit IN (...)`;
     over-long BU lists split across **sibling roles** (RLS ORs across roles);
     chunks of one table never share a role, and a table with RLS never also
     appears unrestricted in a sibling (that would union to all rows);
   - tables bin-packed into roles of ≤ 500 permissions (per-table anti-affinity);
   - membership: `group` mode = one Entra security group per profile (single
     member per role, deterministic name `<prefix><hash12>`); `direct` mode =
     member chunks of ≤ 500 cloning the role family;
   - role names `<prefix><hash12>pNN[mNN]` are deterministic across runs and must be alphanumeric (OneLake rejects underscores).
4. **Apply** — Fabric `dataAccessRoles` PUT **replaces the entire role set**,
   so the payload = unmanaged roles verbatim + desired managed roles (+ stale
   managed roles when `apply.prune: false`). ETag `If-Match` with one refetch
   retry on 412. Budget check: desired + unmanaged ≤ `fabric.role_budget`.

## Sizing: what actually drives role count

An access profile keys on a user's complete effective access map, so the number
of profiles equals the number of **distinct (job-access pattern × business-unit
scope)** combinations. User count is irrelevant — 15,000 users sharing 10
patterns produce 10 profiles. Measured with `tools/scale_benchmark.py`:

| Archetypes | BUs | Roles | vs 1,000 budget |
| ---: | ---: | ---: | :--- |
| 5 | 90 | 465 | fits |
| 10 | 90 | 930 | fits |
| 20 | 90 | 1,859 | exceeds |
| 40 | 90 | 3,634 | exceeds |
| 40 | 12 | 480 | fits |

Roughly, `roles ≈ archetypes × BUs`. Global-depth grants collapse across
business units (no RLS needed); Local/Deep grants do not.

### If the role budget doesn't fit

Ordered by leverage, and none of them involve over-granting:

1. **Coarsen business-unit scoping.** The BU dimension is the multiplier. Where
   Deep-depth grants sit at division level, the subtree collapses to one scope,
   and a subtree covering every BU collapses to unrestricted (already
   implemented). Going from 90+ leaf BUs to ~12 divisions cut 3,634 roles to 480.
2. **Shard across Fabric items.** The 1,000-role ceiling is **per item**, so a
   lakehouse per division or per data domain multiplies total capacity. This is
   the architectural escape hatch when BU granularity is genuinely required.
3. **Narrow the synced table set.** Fewer tables means fewer dimensions on which
   two users' access can differ. (A representative item exposed 251 of 882 environment tables.)
4. **Request a further limit increase** from Microsoft, as was done for 250→1,000.

A decomposition mode — emitting one role per (Dataverse role instance, BU) and
letting OneLake union them per user — is *not* automatically better: it trades a
multiplicative profile count for an additive grant-unit count, which wins only
when users hold diverse combinations of few shared grants. Because OneLake roles
only ever union (never intersect), a table set and its row filter must live in
the same role, so per-(role, BU) granularity is the floor for that model. Worth
implementing as an alternative mode and picking the smaller of the two, once
production numbers say which regime applies.

## Extraction notes

- `RetrieveRolePrivilegesRole(RoleId=...)` yields privilege + depth per role
  instance; read privileges are matched to tables via the `prvRead<SchemaName>`
  convention against `EntityDefinitions` (unmatched names surface in the
  reconciliation report — they are typically non-table privileges).
- `EntityDefinitions.OwnershipType` distinguishes org-owned (any read ⇒ all
  rows; such tables have no `owningbusinessunit`) from user/team-owned.
- Entra-group teams (teamtype 2/3) are materialized lazily by Dataverse, so
  extraction resolves their transitive membership through Microsoft Graph and
  merges it into the snapshot (`extract/team_resolution.py`).
- Eligibility: enabled, non-application users with an Entra object id and
  access mode in `compile.user_access_modes`; every skip is reported.
- Reads are sequential, not transactional — the snapshot records `observed_at`,
  and each run directory is a durable audit artifact (SQLite + reports).

## Residual gaps (flagged, never silently over-granted)

- Record sharing (PrincipalObjectAccess) and access teams — not modeled.
- Hierarchy/position security — not modeled.
- Basic-depth own-records visibility — fail-closed, per-user/table CSV report.
- Field security profiles → CLS — extracted and hashed into profile identity,
  emission planned for M4 (needs table column metadata to build Permit lists;
  `compile.cls_enabled` guard refuses until implemented).
- OneLake latencies: role definitions ≈5 min, group membership ≈1 h.

## Operations

- `dvaccess run` = extract → compile → plan (add `--yes` to apply); each stage
  is idempotent and re-runnable; second run after apply diffs to zero.
- Scheduling: Windows Task Scheduler / Azure Functions timer / Fabric notebook
  invoking the CLI; secret from Key Vault into `DVACCESS_CLIENT_SECRET`.
- Auditing: `manifest.json` (profile → members → per-table scopes),
  `dvaccess explain --user <upn>` (role-by-role trace), `plan.json` (change
  history per run).
