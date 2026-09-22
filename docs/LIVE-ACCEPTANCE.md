# Live acceptance with actual reader identities

The adapter's unit tests and administrative source probes are not evidence that an ordinary bank reader receives the same result through Fabric. This runbook compares Dataverse and the **curated serving lakehouse SQL endpoint** using the same real reader's delegated Entra identity. It never grants a role, changes a source record, creates a user, or signs a user in automatically.

Use the supplied `scripts/qualify_reader.py` for the selected SQL path. A successful result is named `passed_selected_sql_checks`; it deliberately retains `production_certified: false` and `revocation_sla_verified: false`. Qualification of Spark, OneLake files, Power BI, historical Delta versions, caches, identity lifecycle and the 60-minute deadline is additional work below.

## Before a real-user test

1. Hydrate the user in Dataverse, assign the intended source roles, and complete any trial-license provisioning. An Entra account alone does not establish a Dataverse identity or source entitlement.
2. Configure actual, approved test records and source permissions. Keep the fixture records stable during each differential run. A second source read detects changes during the probe; it is not a transactional snapshot of the environment.
3. Prepare and publish a fresh adapter generation to the curated serving items. Complete the deployment boundary review. The reader must not be a Fabric workspace Admin, Member or Contributor, and must not have an alternate raw-data path.
4. Obtain the SQL connection endpoint and database **for the serving lakehouse**, not the original unrestricted Dataverse lakehouse. Resolve its workspace and item IDs from the current deployment configuration and verified Fabric metadata. Its SQL endpoint values must be supplied from that item. The script does not guess them.
5. For native OneLake policies, verify the endpoint uses the qualified UserIdentity access mode and close alternative SQL grants. If the deployment instead uses a separate SQL enforcement architecture, qualify that architecture independently.
6. Install the project and its adapter requirements in the supported Python environment. Install Microsoft ODBC Driver 18 for SQL Server and `pyodbc` for this optional probe. On Windows, retain `tzdata` for timestamp conversions.

```powershell
python -m pip install -c requirements.lock -e ".[adapter,test,qualification]"
```

The runner supports the public-cloud Fabric SQL hostname ending in `.datawarehouse.fabric.microsoft.com`. It requires TLS with certificate verification, forbids connection-string injection, and obtains a `https://database.windows.net/.default` access token. Passwords, connection strings containing credentials, and arbitrary JWT input are not supported.

## Four reader personas and genuine fixture evidence

Fill these labels with actual approved UPNs, Entra object IDs, source records and expected outcomes. The labels are test organization aids; only the immutable Entra ID binds authentication. There are no assumed or invented test users.

| Template label | Source entitlement to exercise | Minimum positive and negative evidence |
| --- | --- | --- |
| `basic_owner` | Basic Read, personal ownership and ownership across the intended BU arrangement | An owned readable row; an unrelated row in the same BU that remains denied |
| `poa_recipient` | Read privilege plus direct and inherited POA sharing | A shared readable row, an unshared denied row; test direct and inherited sharing as separate fixtures |
| `team_member` | Qualified owner-team/access-team membership and team sharing | Team-owned or team-shared readable rows; unrelated-team denied rows; qualify membership changes separately |
| `bu_field_security` | Local/Deep BU anchors plus cumulative field profiles and record-field sharing | An in-scope readable row, a sibling/out-of-scope denied row, explicit expected NULL and non-NULL fields |

If one reader legitimately has Global Read for a selected table, that reader cannot supply the required denied-row example for that table. Use an appropriate sub-Global table or a separately authorized negative persona; do not invent a missing record and present it as a denied record. Confirm the denied record actually exists through an independently authorized fixture owner.

Create an unpopulated manifest. Prefer metadata from the prepared generation so lookup property names, primary keys and scalar types match publication exactly:

```powershell
python scripts/qualify_reader.py --write-template acceptance-fixtures.json `
  --prepared-manifest .policyweaver/generations/REPLACE_GENERATION/manifest.json
```

Without `--prepared-manifest`, the runner creates a deliberately incomplete account example. All `REPLACE_...` values must be filled. Generated templates contain four reader entries and cannot pass as-is.

Review and fill:

- Tenant GUID, Dataverse organization GUID and environment URL from the client's verified deployment configuration. Do not use the separate Power Platform environment ID as the organization GUID.
- Actual serving SQL server and database; target schema and table names. The template uses `dbo.pw_demo_<logical_name>` as a placeholder convention. Replace it with the deployment's real prefix.
- Each persona's actual `upn`, `entra_id` and `dataverse_id`. Obtain the immutable Entra/Dataverse ID pair from the controlled source inventory or the prepared manifest's `readers` entries, then associate it with the approved persona. The UPN helps the operator choose the sign-in account. Templates select `identity_verification: "bound_whoami"`, which requires both immutable IDs.
- For each allowed table, at least one known-visible and one known-denied record GUID. Add multiple fixtures for each access reason; four persona labels do not cover every rule automatically.
- `null_fields` and `non_null_fields` on visible records. A NULL assertion is meaningful only when the fixture owner has independently confirmed a non-NULL stored value and the reader's expected field denial. A naturally NULL source field cannot establish field-security denial.
- For a completely denied table, set `table_denied: true` and `records: []`. The expected result is query denial, not an allowed query returning zero rows.

Example reader section, with placeholders that must be replaced:

```json
{
  "label": "poa_recipient",
  "upn": "REPLACE_WITH_REAL_READER_UPN",
  "entra_id": "REPLACE_READER_ENTRA_GUID",
  "dataverse_id": "REPLACE_READER_DATAVERSE_GUID",
  "identity_verification": "bound_whoami",
  "tables": {
    "account": {
      "table_denied": false,
      "records": [
        {
          "record_id": "REPLACE_EXISTING_SHARED_RECORD_GUID",
          "visible": true,
          "null_fields": ["REPLACE_SECURED_PROPERTY"],
          "non_null_fields": ["name"]
        },
        {
          "record_id": "REPLACE_EXISTING_UNSHARED_RECORD_GUID",
          "visible": false
        }
      ]
    }
  }
}
```

Store this manifest as controlled test evidence. It contains identity and record identifiers even though reports contain neither row values nor those identifiers. Give readers only the metadata/fixtures they are authorized to know; never distribute staged Delta files or the administrative state directory to test users.

## Run as the real reader

Use a separate workstation/session or isolated Azure CLI configuration directory for each persona. The person running the test signs in interactively to the tenant using the intended reader account. Do not use the administrative publisher session, an application identity, or an admin impersonating the reader.

```powershell
# Choose a task-specific isolated location before interactive sign-in.
$env:AZURE_CONFIG_DIR = Join-Path $PWD ".azure-reader-basic"
az login --tenant <CLIENT_TENANT_GUID> --allow-no-subscriptions

python scripts/qualify_reader.py --scenario acceptance-fixtures.json `
  --reader basic_owner --output acceptance-basic-owner.json
```

Choose the matching real reader in the interactive sign-in. Repeat with the other three labels under their own sessions. The script does not invoke `az login`, change the CLI account, or collect credentials. Local CLI token caches require normal workstation protections.

Before querying data, the tool binds both SDK-acquired access tokens to the configured tenant and reader Entra object ID, checks the resource audience, and requires a delegated-user scope. No `CallerObjectId` or `MSCRMCallerID` header is used. Client-side JWT claim inspection prevents account mistakes; Dataverse and SQL perform actual token validation at their service boundaries.

The explicit `bound_whoami` mode verifies the organization and expected Dataverse user ID through unimpersonated `WhoAmI`. This uses the reader's own delegated token and the controlled immutable identity pair in the scenario. It requires no `prvReadUser`, administrative security-table inventory, impersonation permission or Custom API inspection by the reader. A missing or mismatched identity, failed token check or failed WhoAmI makes the run incomplete. The adapter continues to verify reader eligibility administratively; this direct-user probe measures the source reads available to the delegated user during the test.

Older scenarios without an explicit identity mode retain `fetchxml`, which also checks an enabled, non-application `systemuser` row in interactive access mode using `eq-userid`. That legacy mode requires ordinary Read access to the caller's own user row. A failed mode never falls back to another mode or an administrator. Changing to `bound_whoami` requires filling the verified `dataverse_id`; omitting it is an error.

## What the probe verifies

The runner executes GETs against the source and single SELECTs against SQL. It uses an explicit business-column list, never `SELECT *`.

- Exact visible record IDs and normalized selected scalar values, including Dataverse NULLs.
- Money/Decimal precision without floating-point conversion; GUID normalization; published UTC timestamp equivalence.
- Independently declared positive and negative fixture expectations, so two equal empty datasets do not pass accidentally.
- Server-side `COUNT_BIG`, record-ID filters, NULL predicates on secured fields and SUM on supported exact numeric types.
- Denial of direct SELECT on `__pw_reader` and `__pw_generation`. An empty successful result is a failure of helper-column protection.
- A second direct source read to reject unstable source fixtures during the run.
- A maximum row count and duration. Limit these to the selected acceptance dataset; this is not an unbounded production export tool.

Aggregate/filter expectations are computed from the **reader-visible projected source values**. The tool does not claim Dataverse predicates over raw secured fields have the same semantics as SQL predicates over materialized NULLs. Such source query semantics require separately defined tests when part of the consuming contract.

Recognized explicit SQL permission errors count as denied queries. Syntax errors, missing columns, login failures and network errors make the run incomplete. If a Fabric engine returns a different permission-error code, preserve redacted diagnostic evidence and qualify that code before extending the allowlist; do not broadly treat every exception as an access denial.

Reports contain row counts, categories and HMAC fingerprints generated with an ephemeral key that is never exported. Fingerprints can be compared within one report; they intentionally differ across runs. No source rows, field values, record identifiers, tokens, server response bodies or connection strings are printed. Exit codes are `0` for the selected checks passing, `1` for mismatches, and `2` for incomplete execution.

## Acceptance still required beyond one SQL comparison

Use an independently timestamped change log, approved mutation fixtures and continuous probes. Record source operation completion, adapter observation, destination publication, consumer query outcome and monitor withdrawal times. The read-only runner does not perform the changes below.

1. Revoke each independent reason separately: direct POA, inherited/cascaded sharing, owner/access-team membership, role membership, ownership and BU scope. A row with another surviving read cause must remain visible.
2. Revoke profile field Read and record-specific field sharing independently. Confirm previously non-NULL fields become NULL only when every applicable field-read cause is gone; row access must remain independent.
3. Disable/delete the user and remove eligible licensing/source access. Confirm the destination reader cannot retain published access past the agreed bound.
4. Test a failed or throttled source scan after partial results, expired generation, lost publisher response, publisher host loss, local journal failure, independent remote monitor outage, and failed withdrawal. Inspect all serving shards; never restore an older authorization generation to recover availability.
5. Re-query through existing SQL connections, newly opened connections, in-flight queries and every enabled Power BI path/cache. Measure completion of stale result delivery, not only role-API response time. The agreed bound is **60 minutes from the source security change**.
6. For Spark/OneLake/Direct Lake, run separate tests as the same genuine consumers. Attempt raw file access, SQL alternatives, shortcut paths, metadata/helper access, retained historical Delta versions/time travel and cached results. A SQL pass says nothing about those paths.
7. Exercise the full selected-table coverage and source exceptions: Activity privilege fan-out, table ownership types, modernized BU ownership, hierarchy/security-parent behavior where enabled, masked columns, lookup properties, organization principals, system-owned records, and duplicate independent grant reasons.
8. Run load tests with actual source record volumes, POA density, field variations and 200 then 1,000 reader identities. Local 200/1,000 synthetic tests establish isolation logic, not production source API capacity or refresh throughput.

Do not label the deployment production-certified until the bank approves this evidence, every enabled access path is covered, and the measured worst case—including caches and failures—satisfies the 60-minute requirement. Any unsupported source feature or unresolved negative case remains an explicit release blocker.

## Primary references

- [Microsoft: Filter rows using FetchXML](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/fetchxml/filter-rows) documents caller-relative `eq-userid` conditions.
- [Microsoft: WhoAmI function](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/reference/whoami?view=dataverse-latest) documents the Dataverse caller identity returned for the direct user.
- [Microsoft: Microsoft Entra authentication with the ODBC driver](https://learn.microsoft.com/en-us/sql/connect/odbc/using-azure-active-directory) documents access-token authentication and `SQL_COPT_SS_ACCESS_TOKEN`.
- [Microsoft: OneLake table, column and row security](https://learn.microsoft.com/en-us/fabric/onelake/security/table-column-row-security) describes the enforcement model whose engine behavior must be qualified.
