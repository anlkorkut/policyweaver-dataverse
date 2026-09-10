# dvaccess — Dataverse → Fabric OneLake security compiler

Dataverse data syncs to Microsoft Fabric. Its **security model does not** — the
roles, privileges, business units, and teams that decide who may read what stay
behind in Dataverse. That gap is a blocker for regulated organizations adopting
Fabric: the data lands in OneLake with none of the entitlements that governed it.

`dvaccess` closes the gap for **read** access. It extracts the Dataverse security
model over the Web API, computes each user's *effective* read access, compresses
users with identical access into **access profiles**, and materializes those
profiles as OneLake data access roles — with static business-unit row-level
security, inside every OneLake limit, idempotently, and fail-closed.

> Scope is deliberately read-only. Create, write, and delete privileges are not
> modeled, which removes a large amount of complexity.

---

## Contents

- [Why not one OneLake role per Dataverse role?](#why-not-one-onelake-role-per-dataverse-role)
- [How it works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Install](#install)
- [Configure](#configure)
- [Usage](#usage)
- [What you get out: run artifacts](#what-you-get-out-run-artifacts)
- [Will it fit the role budget?](#will-it-fit-the-role-budget)
- [Replacing an existing Policy Weaver deployment](#replacing-an-existing-policy-weaver-deployment)
- [Troubleshooting](#troubleshooting)
- [Guarantees, limitations, and residual gaps](#guarantees-limitations-and-residual-gaps)

---

## Why not one OneLake role per Dataverse role?

Because OneLake security has hard limits that a naive one-to-one sync breaks at
enterprise scale:

| Limit | Value |
| --- | --- |
| Roles per item | 250 (raise to 1,000 via Azure support) |
| Members per role | 500 |
| Permissions per role | 500 |
| RLS predicate | 1,000 characters, **static SQL only** — no `CURRENT_USER` |
| RLS + CLS across roles | mixing them on one table returns **query errors** |

With tens of thousands of users, hundreds of roles stamped across dozens of
business units, and thousands of tables, a role-per-role sync exceeds all of
them at once. Worse, because users typically hold several roles, the RLS/CLS
combination hazard produces users who get errors instead of data.

`dvaccess` resolves multi-role users and overlapping team memberships **before**
emitting any role, so each user lands in exactly one profile. That eliminates the
cross-role hazard by construction, and makes role count track the number of
*distinct access patterns* rather than roles × business units × users.

## How it works

```
extract  →  compile  →  plan  →  apply  →  verify
Dataverse    profiles     diff     write     read back
snapshot     + roles    (no-op)   to Fabric  and confirm
```

1. **extract** — snapshots users, teams, business units, role instances, read
   privileges with their depth, assignments, and field security profiles into
   `runs/<run_id>/snapshot.sqlite`. Entra-group-backed teams are resolved through
   Microsoft Graph, because Dataverse materializes that membership lazily.
2. **compile** — computes effective read access per user per table, applying
   Dataverse's cumulative "greatest access prevails" semantics:

   | Dataverse depth | Compiles to |
   | --- | --- |
   | Global, or any read on an org-owned table | all rows, no RLS |
   | Deep | the role instance's business-unit subtree (collapses to all rows if it spans every BU) |
   | Local | the role instance's business unit |
   | Basic on a business-owned table | the user's own business unit |
   | Basic on a user/team-owned table | **excluded and reported** — see below |

   Users whose complete access maps are identical are hashed into one profile.
3. **plan** — fetches the item's current roles, diffs only the roles this tool
   manages, passes everything else through untouched, and checks the role budget.
   Writes `plan.json`. **Never writes anything.**
4. **apply** — reconciles one Entra security group per profile, then replaces the
   item's role set with ETag concurrency control. Requires `--yes`.
5. **verify** — re-reads the item and confirms it matches the compiled state.

### Why Basic depth is excluded rather than approximated

Basic ("user owns the record") depth cannot be expressed in OneLake, because RLS
predicates are static — there is no `CURRENT_USER` function, and one role per
user is not viable at scale. Rather than over-grant to the whole business unit,
`dvaccess` **grants nothing** for those table/user pairs and lists every one of
them in `basic_depth_exclusions.csv` for compliance sign-off. Fabric access is
therefore always a subset of Dataverse access, never a superset.

## Prerequisites

**Runtime:** Python 3.11 or newer. Dependencies are pure-Python (`httpx`,
`pydantic`, `azure-identity`, `PyYAML`).

**Identity.** Either an interactive `az login`, or — recommended for production —
a service principal supplying `auth.client_id` plus a `DVACCESS_CLIENT_SECRET`
environment variable. A service principal is *required* if your tenant issues
Continuous Access Evaluation claims challenges (common with IP-bound conditional
access), because Azure CLI credentials cannot answer them.

**Permissions the identity needs:**

| System | Requirement |
| --- | --- |
| Dataverse | An application user (for a service principal) with read on `role`, `privilege`, `systemuser`, `team`, `businessunit`, `fieldsecurityprofile`, `fieldpermission` |
| Microsoft Graph | `GroupMember.Read.All` to resolve Entra-group teams; `Group.ReadWrite.All` additionally if using `entra.membership: group` |
| Fabric | A workspace role (Contributor or above) on the target workspace; for a service principal, also enable the tenant setting **"Service principals can use Fabric APIs"** |
| OneLake | Read on the item's `Tables/` directory (used to discover which tables are actually synced) |

## Install

```bash
py -3.11 -m venv .venv
```

```bash
.venv/Scripts/pip install -e ".[dev]"
```

On Linux or macOS use `.venv/bin/pip` instead. This puts a `dvaccess` executable
on the virtualenv's path.

## Configure

```bash
cp config/config.example.yaml config/config.yaml
```

Then edit `config/config.yaml`. `config.example.yaml` documents every option; the
four values you must set are:

```yaml
environment:
  dataverse_url: https://<your-org>.crm.dynamics.com
auth:
  tenant_id: "<your tenant guid>"
fabric:
  workspace_id: "<from the portal URL>"
  item_id: "<from the portal URL>"
```

**Finding the Fabric ids.** Open the lakehouse in the Fabric portal and read them
straight out of the address bar:

```
https://app.fabric.microsoft.com/groups/<workspace_id>/lakehouses/<item_id>?...
```

**Two settings worth getting right before your first run:**

- `fabric.schema_name` — set to `null` for a non-schema lakehouse (which is what
  Dataverse Link to Fabric normally creates) or to your schema name if the item is
  schema-enabled. Getting this wrong produces role paths that match nothing and
  silently grant nothing. Do not trust the `dbo` that appears in the portal URL —
  that is the SQL analytics endpoint's implicit schema. Check the item's OneLake
  `Tables/` directory instead: a `dbo/` folder means schema-enabled; table folders
  directly under `Tables/` mean it is not.
- `entra.membership` — `group` creates one Entra security group per profile and is
  the right choice at scale, since it sidesteps the 500-members-per-role limit.
  `direct` assigns users to roles individually and needs no Graph write access,
  but consumes role budget when a profile exceeds 500 members.

Secrets never belong in this file. `config/config.yaml` is gitignored so that
environment ids stay local.

## Usage

Every command takes `--config <path>` (default `config/config.yaml`) and `-v` for
debug logging.

### The safe read-only path

```bash
dvaccess extract
```

Snapshots Dataverse into `runs/<run_id>/snapshot.sqlite`. Touches nothing else.

```bash
dvaccess compile
```

Builds profiles and role definitions from the most recent snapshot, and writes
the reports. **This is the command that answers "will this fit?"** — check the
compiled role count against your budget before going further.

```bash
dvaccess plan --dry-run
```

Diffs the compiled roles against what is on the item and writes `plan.json`.
`--dry-run` additionally sends the payload to Fabric with `dryRun=true`, which
validates it server-side without changing anything — the cheapest way to prove
your credentials and payload are good.

### Writing to Fabric

```bash
dvaccess apply --yes
```

Creates or reconciles the Entra groups, then replaces the item's role set. The
`--yes` flag is mandatory; without it the command refuses. It verifies
automatically afterwards.

```bash
dvaccess verify
```

Re-reads the item and confirms it still matches the compiled state. Useful as a
scheduled drift check.

### Auditing a single user

```bash
dvaccess explain --user someone@contoso.com
```

Prints every role instance granting that user access, which table each grant
covers, at what depth, and whether it arrived directly or through a team —
followed by their resulting OneLake scopes. This is how you answer "why can this
person see this table?"

### End to end

```bash
dvaccess run
```

Runs extract → compile → plan. Add `--yes` to apply as well.

Each stage is idempotent: re-running `plan` after a successful `apply` reports no
changes. Use `--run <run_id>` to re-compile against an older snapshot.

## What you get out: run artifacts

Every run writes an audit trail to `runs/<run_id>/`:

| File | Contents |
| --- | --- |
| `snapshot.sqlite` | The raw Dataverse security model, point-in-time |
| `compile_summary.md` / `.json` | Headline numbers and every exclusion |
| `manifest.json` | Profile → members → per-table scope. Answers "why does user X see table Y" |
| `profiles.csv` | One row per profile: members, tables, RLS tables, roles emitted |
| `basic_depth_exclusions.csv` | Every (user, table) where Basic depth was fail-closed excluded |
| `skipped_users.csv` | Every user excluded, with the reason |
| `plan.json` | Roles to create, update, retire, and leave alone |
| `desired_roles.json` | The exact payload that would be sent to Fabric |

> `runs/` is gitignored. Snapshots contain the full user directory of your
> environment — names, Entra object ids, business units, role assignments. Treat
> them as sensitive and keep them out of source control.

## Will it fit the role budget?

Role count is governed by `distinct job-access patterns × distinct business-unit
scopes` — **not** by user count. Measured with `tools/scale_benchmark.py` on
synthetic data at 15,000 users and 2,000 tables:

| Job archetypes | Business units | Roles compiled | Against a 1,000 budget |
| ---: | ---: | ---: | :--- |
| 5 | 90 | 465 | fits |
| 10 | 90 | 930 | fits |
| 20 | 90 | 1,859 | exceeds |
| 40 | 90 | 3,634 | exceeds |
| 40 | 12 | 480 | fits |

Users are effectively free — 15,000 of them sharing 10 access patterns produce 10
profiles. **Business-unit granularity is the expensive dimension.**

Run the benchmark against your own assumptions:

```bash
python tools/scale_benchmark.py --archetypes 20 --business-units 90 --sweep
```

If your real numbers exceed the budget, the levers in order of leverage are:
coarsen business-unit scoping (the biggest by far), shard across multiple Fabric
items since the limit is **per item**, narrow the synced table set, or request a
further limit increase. See [docs/design.md](docs/design.md) for the full
discussion.

## Replacing an existing Policy Weaver deployment

If the item already carries roles from Microsoft's
[Policy Weaver](https://github.com/microsoft/Policy-Weaver), set:

```yaml
apply:
  retire_role_patterns: ["*PWPolicy"]
```

Those roles are then deleted on apply so this tool is the single source of truth.
Every retirement is listed by name in `plan.json` for review first. Roles carrying
your own `role_prefix` are never matched by these patterns, and anything else on
the item — `DefaultReader`, hand-authored roles — is passed through untouched.

Leaving both sets live is not recommended: OneLake unions grants across roles, so
users would receive the more permissive of the two models.

## Troubleshooting

**`CredentialUnavailableError: This credential doesn't support claims challenges`**
Your tenant issued a Continuous Access Evaluation challenge. Either run the
`az login --claims-challenge ...` command printed in the error, or switch to a
service principal, which answers challenges automatically. This is the single most
likely failure for long production extracts.

**`RequestBodyValidationFailed: Role has invalid name`**
OneLake role names must start with a letter and contain only letters and numbers.
No underscores, hyphens, or dots. One bad name rejects the entire payload. Check
`fabric.role_prefix` — the config validator enforces this at load time.

**Roles apply successfully but users see no data**
Almost always `fabric.schema_name`. A schema-enabled item needs
`/Tables/<schema>/<table>` paths; a non-schema item needs `/Tables/<table>`. The
wrong setting produces valid roles whose paths match nothing.

**`Server disconnected without sending a response`**
The Dataverse Web API drops keep-alive connections on long extracts. This is
retried automatically; no action needed.

**Permissions reference tables that are not in the lakehouse**
Set `fabric.restrict_to_item_tables: true` (the default) so compilation is
intersected against the item's actual OneLake `Tables/` listing. Dataverse grants
privileges on every table in the environment; only the synced subset exists.

**Changes applied but access has not changed yet**
OneLake takes about 5 minutes to apply role definition changes, and up to about an
hour to reflect Entra group membership changes. Some engines cache for an
additional hour.

## Guarantees, limitations, and residual gaps

**Guarantees**

- Access granted in Fabric is always a **subset** of access in Dataverse. Every
  gap is reported, never silently widened.
- Only roles carrying the configured prefix are created, updated, or deleted.
  Everything else on the item is preserved byte-for-byte.
- Runs are idempotent and concurrency-safe (ETag `If-Match`, with one refetch and
  retry on conflict).

**Not modeled** — documented rather than approximated:

- Record sharing (`PrincipalObjectAccess`) and access teams
- Hierarchy and position-based security
- Per-user record ownership (Basic depth on user/team-owned tables) — excluded
  and reported
- Column-level security from field security profiles — extracted and folded into
  profile identity, but not yet emitted (`compile.cls_enabled` refuses until
  implemented)

**Design detail** lives in [docs/design.md](docs/design.md).
