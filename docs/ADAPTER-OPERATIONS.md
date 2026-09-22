# Policy Weaver operator runbook

## Deployment model

Run analytical materialization as a controlled service outside Dataverse. It uses Dataverse Web API impersonation, local typed Delta staging and Fabric data/policy APIs. The optional [read-context plug-in](READ-CONTEXT-PLUGIN.md) supplies an execution-identity proof without reading business tables. Its installation creates isolated Dataverse customization components. Projection requests do not alter source roles, users, records or shares, and source transactions do not perform analytical materialization.

The normal lifecycle is `discover → doctor → provision → prepare → dry-run → publish`, followed by fresh generations. Establish the independent watchdog's actual rights, compatible configuration, withdrawal behavior and monitoring before the first timed publication; an inspect-only job does not protect published access from expiry. A preparation-only worker is useful while consumer access and runtime qualification are being established. Do not equate a `published` journal state with verified enforcement on every Fabric engine.

## Prerequisites and identities

1. Install Python 3.11 or later and the repository using `python -m pip install -c requirements.lock -e ".[adapter,test]"` to reproduce the tested dependency versions. Run `python -m pytest -q` before the first deployment and after upgrades.
2. Select an Entra tenant, a Dataverse organization/environment and a Fabric workspace with appropriate capacity. Confirm the enabled Fabric security features and destination quotas.
3. Use Azure CLI authentication for controlled local development. Onboarding verifies the expected operator UPN/object ID during discovery only; the adapter runtime is tenant-bound and does not pin that account. Use an isolated `AZURE_CONFIG_DIR` and recheck the active operator before operations, keeping reader acceptance sign-ins separate. Use a dedicated managed identity/application user for unattended execution after configuring the corresponding Dataverse user and Fabric access. Supply credentials through Azure identity mechanisms; the JSON configuration must contain no tokens or secrets.
4. The source operator needs the directly assigned `prvActOnBehalfOfAnotherUser` privilege, read access to metadata/security discovery, and sufficient source read and field permissions. The adapter verifies Global Read per selected table. For secured fields it additionally requires either the directly assigned built-in System Administrator role template or complete all-record Read grants for every selected secured field through the operator's direct/team field-security profiles. A record-specific field share cannot qualify the operator for all records. Missing or unavailable proof blocks preparation. Actual operator/reader projection comparison remains part of qualification.
5. Readers must exist as enabled, non-application Dataverse users with an Entra object ID and access mode Read-Write (0) or Read (2). Other access modes are rejected. Assign required Dataverse roles/teams and populate the intended fixtures. Creating Entra users and assigning Power Apps licenses does not by itself prove Dataverse hydration or table privileges. Reader discovery collects IDs and access mode, not user display names. An enabled user with verified absence of selected-table Read receives no rows or table grant, including users with no roles. A Read-positive reader must complete the selected identity proof. The default FetchXML mode requires the impersonated `systemuser` self-context query; use the qualified Custom API mode for readers without `prvReadUser`. Do not broaden their source roles to make the probe work.
6. The Fabric publisher needs the workspace/item rights to create serving lakehouses when provisioning, write Delta data, read/update OneLake data-access roles and inspect workspace assignments. Grant these only to the deployment identity. Tenant service-principal settings, managed-identity support and capacity permissions must be configured and verified for the actual APIs used.
7. Reader identities require the minimal item discovery/read access applicable to the approved engine. Configure that in Fabric's supported sharing/access workflow. Do not grant workspace Admin/Member/Contributor, broad data read, raw storage access or default unrestricted OneLake roles as a shortcut.

Impersonation applies the source execution context; it is not an authorization bypass. Microsoft documents the required privilege and operator/impersonated privilege relationship in [Dataverse impersonation](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/impersonate-another-user) and [Web API CallerObjectId](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/impersonate-another-user-web-api).

## Configuration

Copy `examples/policyweaver.config.example.json` or create a JSON file using the shape below. The example uses deliberately fictional IDs and must be replaced:

```json
{
  "schema_version": 1,
  "environment_url": "https://yourorg.crm.dynamics.com",
  "tenant_id": "11111111-1111-4111-8111-111111111111",
  "organization_id": "22222222-2222-4222-8222-222222222222",
  "workspace_id": "33333333-3333-4333-8333-333333333333",
  "deployment_name": "pw_bank",
  "authentication": "azure_cli",
  "readers": ["44444444-4444-4444-8444-444444444444"],
  "discover_readers": false,
  "excluded_readers": [],
  "max_readers": 1000,
  "tables": [
    {"name": "account", "columns": ["accountid", "name", "primarycontactid"]}
  ],
  "role_limit": 250,
  "reserved_roles": 10,
  "tables_per_shard": 100,
  "serving_items": {},
  "batch_size": 2000,
  "max_rows_per_reader_table": 1000000,
  "refresh_interval_seconds": 600,
  "generation_lifetime_seconds": 2700,
  "publication_budget_seconds": 600,
  "state_directory": ".policyweaver"
}
```

`readers` contains Entra object IDs, not Dataverse systemuser IDs or UPNs. `discover_readers: true` selects discovered eligible readers except the source operator and `excluded_readers`, subject to `max_readers`; use explicit IDs while the tenant is being hydrated. The program rejects missing/disabled configured readers instead of silently replacing the audience.

For managed identity set `authentication` to `managed_identity`; supply `managed_identity_client_id` only for a user-assigned identity. Organization ID is the Dataverse organization GUID, not the Power Platform environment ID.

After installing and qualifying the optional execution-context plug-in, set
`identity_verification` to `custom_api`, `identity_api_name` to `pw_ReadContext`,
and `identity_api_assembly_sha256` to the trusted signed DLL's lowercase SHA-256.
The source verifies the installed registration and code before using it. The
default `fetchxml` mode needs no plug-in. Changing modes or upgrading from a
configuration schema without these explicit defaults changes the configuration
fingerprint; prepare a new generation instead of reusing staged data.

Use Dataverse logical table names. Metadata resolves the actual entity set, primary key and Read privilege GUID, including shared activity privilege mappings. Columns may be logical names or supported Web API scalar property names. The primary key is included automatically. A configured `primarycontactid` lookup becomes `_primarycontactid_value` in the output. Decimal and Money values are parsed without intermediate binary floating-point loss; the materializer enforces its typed schema. Multi-select values remain the returned scalar string.

Source file/image/party-list/complex attributes are unsupported. A missing Read privilege mapping, unknown attribute security metadata or unavailable masking discovery blocks the table. Scope the initial pilot to explicit supported columns. A schema change requires fresh metadata and a newly prepared generation; do not mix a changed configuration with previously prepared data.

The state path is relative to the configuration file unless absolute. It contains business values, reader IDs, Delta generations and a local journal. Put it on encrypted storage with access limited to the deployment operator. Do not serve it through the console or commit it to source control. Manage backup, retention and capacity outside the application.

## Commands

The examples assume an activated virtual environment. Every command also works as `policyweaver-adapter` after installation.

```powershell
python -m policyweaver.adapter_cli --config policyweaver.config.json doctor
python -m policyweaver.adapter_cli --config policyweaver.config.json discover
python -m policyweaver.adapter_cli --config policyweaver.config.json provision
python -m policyweaver.adapter_cli --config policyweaver.config.json prepare
python -m policyweaver.adapter_cli --config policyweaver.config.json status
```

`doctor` verifies the source organization, selected metadata and current reader count. `discover` prints eligible identity IDs, which should be handled as administrative information. `provision` creates the planned private serving lakehouses and records their mapping in the configuration. It does not grant consumer access. Provisioning changes the configuration fingerprint: prepare again afterward. Keep production serving items separate from the raw linked Dataverse lakehouse.

Provisioning retains a durable creation receipt and refuses to adopt an existing item solely by name. For an app-created, verified empty item it removes the initial broad `DefaultReader` role before initializing empty typed tables. It never clears arbitrary customer roles. If OneLake security is not yet enabled, the command records a required portal action and stops before data initialization. Open that new lakehouse, enable **Manage OneLake security** as directed, and rerun provisioning. SQL identity mode and minimal reader item sharing also need their supported Fabric controls; the application does not invent an API setting for them.

`prepare` performs fresh full reader/table projections, writes typed staging data and a hashed manifest, and calculates the role/shard plan. Its table-Read gate explicitly includes Basic team privileges using `RetrieveUserPrivilegeByPrivilegeId(...,ExcludeTeamBasic=false)`. The general `RetrieveUserPrivileges` response is not sufficient proof of absent Read for team-only personas. Each reader/table pair receives a fresh gate; the permission plan and row iterator use the same result without repeating that inventory lookup. It makes no destination access changes. A source failure or budget overrun marks the generation failed; partial outputs cannot be published. Record the generation ID from its result and use it in these commands:

```powershell
python -m policyweaver.adapter_cli --config policyweaver.config.json dry-run --generation 1
python -m policyweaver.adapter_cli --config policyweaver.config.json boundary-template --generation 1
python -m policyweaver.adapter_cli --config policyweaver.config.json publish --generation 1 --boundary boundary.json
```

Replace `1` with the actual generation ID. `dry-run` validates the role payload against Fabric without granting access. It may still fail before data publication if the platform requires the referenced table to exist; investigate and establish the private table before retrying. The publisher validates again as part of publication.

In version 0.2.4, `source_workers` optionally controls bounded parallel extraction (integer 1–4, default 1). Each worker owns a separate Dataverse client and executes the same verified reader/table scan; only the main thread writes Delta and journal entries. Any worker failure invalidates the whole generation, and all workers close before preparation succeeds. Start with 2 only after source parity and throttling checks. The setting changes the configuration fingerprint and requires fresh preparation. It neither extends the freshness budget nor permits multiple publishers; the default preserves existing fingerprints.

`boundary-template` emits a deliberately unverified object for each shard. It is not an automatic approval or a scanner. Populate `boundary.json` only after an actual inspection of workspace role inheritance, item/data grants, SQL identity mode, shortcuts and storage access for the exact audience. `inspected_at` must be a truthful timezone-aware inspection timestamp no more than 15 minutes old. The expected shape is:

```json
{
  "AUDIENCE_AND_TABLE_SHARD_KEY": {
    "workspace_id": "33333333-3333-4333-8333-333333333333",
    "item_id": "55555555-5555-4555-8555-555555555555",
    "reader_ids": ["44444444-4444-4444-8444-444444444444"],
    "inspected_at": "2026-01-01T12:00:00+00:00",
    "no_privileged_workspace_readers": true,
    "no_alternate_data_access": true,
    "sql_endpoint_mode": "UserIdentity"
  }
}
```

Use the real key from `boundary-template`. The timestamp above is an example and must never be used as a fresh attestation. SQL must be verified as `UserIdentity`, or genuinely unavailable to those readers and represented as `DisabledForReaders`. Default delegated SQL identity does not satisfy this boundary. The role REST interface cannot establish the SQL mode by itself; inspect/configure the actual endpoint through supported Fabric controls and test a reader connection.

Publication verifies staged hashes, complete typed destination-value fingerprints and counts, current quotas, ETags, foreign-role overlap and the boundary scope. It uploads the current generation's data before switching the reader-role predicates to that generation. Reader grants for retired shards are withdrawn. Separate lakehouses are not an atomic distributed transaction; on an uncertain/partial failure the adapter attempts withdrawal and records quarantine. It never restores an old authorization generation to recover availability.

The journal binds one tenant, organization, workspace and deployment namespace. It retains the managed-item history and a monotonic activation watermark. Removing or remapping a registered item requires verified withdrawal using the previous configuration first. Explicit withdrawal also invalidates all generations already prepared at that time; prepare fresh data afterwards. Changing the journal, restoring an older copy, or deleting its registry to bypass these checks is not a supported recovery method. After an approved item migration, update every independent watchdog's item inventory before resuming publication.

## Refresh, expiry and service deployment

```powershell
python -m policyweaver.adapter_cli --config policyweaver.config.json run
python -m policyweaver.adapter_cli --config policyweaver.config.json worker
python -m policyweaver.adapter_cli --config policyweaver.config.json watchdog-worker
```

`run` prepares once; `worker` repeats preparation at the configured interval. Both invoke the watchdog before preparation, even without `--publish`, so they can withdraw expired Fabric roles. Use `prepare` for source-only preparation with no Fabric operations. Add `--publish --boundary boundary.json` only when a trusted process supplies a freshly inspected boundary for each publication and the enabled engines have passed qualification. A static boundary file expires after 15 minutes. Do not renew its timestamp automatically without rechecking the asserted facts.

Run `watchdog-worker` as a separately supervised process with access to the protected managed-item registry and the rights to withdraw roles. It checks remote role timestamps roughly every 30 seconds, including historically managed items, and must continue even while the scan worker is slow. For publisher-host or journal loss, deploy the separate stateless `policyweaver.native_watchdog` on an independent host with a complete item inventory; see the deployment runbook. Withdrawal uses the exact inspected role collection's ETag so that a concurrent fresh publication is preserved. A watchdog alone cannot force native roles to expire while Fabric's control plane is unavailable. Failed withdrawal is a critical incident, not a successful fail-closed event.

For protection against loss of the publisher host or its journal, prefer the separate `policyweaver.native_watchdog` service described in [deploy/README.md](../deploy/README.md). It reads generation-bearing policies directly from Fabric and needs no Dataverse access, local business records or publisher disk. Its `--inspect` mode is read-only; `--once` may withdraw expired app-owned roles. The supplied container and Azure Container Apps scheduled-job template support independent hosting. Configure every serving item and keep that deployment current when shards change. It accepts the application's real Unix-microsecond generation IDs; never deploy manually numbered generations into a watched item.

The default generation lifetime is 45 minutes from preparation start, with 10 minutes reserved for publication/enforcement work, within the requested 60-minute budget. The application enforces the preparation/publication deadlines it controls; real source delay, role propagation, query lifetimes and caches still need measured qualification. An hourly start schedule is insufficient because work takes additional time. A shorter preparation cadence plus an independent watchdog is required.

For a cloud host, use the same installed package and commands under an approved container/service scheduler, persistent encrypted state storage, managed identity, supervised workers and external alerting. Begin with preparation-only operation. Multi-host concurrent writers to one local journal are not supported: use one writer and a separate watchdog process on a supported shared local host, or design and qualify a distributed journal/lease provider before changing that topology. Autoscaling is not a substitute for source throttling and publication coordination.

```powershell
python -m policyweaver.adapter_cli --config policyweaver.config.json watchdog
python -m policyweaver.adapter_cli --config policyweaver.config.json withdraw
python -m policyweaver.adapter_cli --config policyweaver.config.json console --port 8000
```

`withdraw` removes roles owned by this deployment prefix. It preserves unowned roles and does not delete data. Verify revocation with real consumers and investigate any alternate grants. The local console binds to loopback; it is not an authenticated enterprise administration portal. Keep it local. Do not expose it through a reverse proxy without building a separately reviewed authentication and authorization boundary.

## Sharding and capacity

Audience capacity is `role_limit - reserved_roles`; required items are `ceil(readers / audience_capacity) × ceil(tables / tables_per_shard)`. The default 250/10 settings need one audience shard for 200 readers and five for 1,000. With 101 selected tables and the default 100-table chunk, those item counts double. Each reader belongs to exactly one audience shard per table shard. Each reader role has exactly one Permit decision rule, with all permitted table paths and a separate paired row/column constraint for each table. A reader without table Read has that table omitted entirely.

Version 0.2.1 corrects the multi-table REST encoding: Fabric rejected the earlier one-decision-rule-per-table form during a live two-table dry run. The equivalent single-rule form passed validation for 202 readers. Upgrade the independently deployed watchdog before publishing multi-table roles; the previous watchdog rejects this shape and cannot withdraw it. After upgrading, verify a controlled expired multi-table role is withdrawn through the actual deployment identity. A successful dry run alone is insufficient.

OneLake's default limits and combinations are documented in the [data access model](https://learn.microsoft.com/en-us/fabric/onelake/security/data-access-control-model) and [table, column and row security](https://learn.microsoft.com/en-us/fabric/onelake/security/table-column-row-security). Support-granted exceptions must be confirmed for each serving item. This application does not assume that the source lakehouse's quota exception transfers to new items.

Materialized row count is the sum of readable rows across readers, not the number of source rows. A universally readable table can require one representation per reader. Source API request volume, Delta size and active-query overhead must be benchmarked on the actual table/row audience distribution. The implementation does not promise that 1,000 readers over the client's entire table estate fit the 60-minute budget. Reduce the approved initial table scope or add qualified capacity before widening it; never broaden row or field permissions to improve throughput.

## Monitoring and incidents

Alert on failed preparation, exhausted freshness reserve, quarantined publication, manifest/hash failure, repeated throttling, boundary expiration, watchdog absence and any failed role withdrawal. Track rows and requests per generation, selected reader count, scan duration, publication duration, generation age, storage growth and source membership drift. Journals use safe error codes; keep infrastructure logs from capturing HTTP authorization headers or business payloads.

On failure, inspect `status` and the local journal. Correct the identity, schema, quota, boundary or source-capacity cause, then prepare a fresh generation. Do not edit manifests, reuse partial generations, delete journal locks while a writer is active, or roll back to an older generation's grants. Retained business data and prior exports are still sensitive even when the current role excludes them.

If a crashed process left a writer lock, inspect the lock file and the actual service/process state. Only after proving that writer is stopped, use `recover-lock --expected-owner ACTUAL_OWNER --worker-stopped`, supplying the exact recorded owner from the lock. This is not a remedy for a slow or live scan. Restart with a fresh generation and inspect any previously uncertain publication.

If withdrawal fails, stop new publication, alert the owner and use the bank's independent access-containment controls to close the affected reader paths. The application cannot claim successful revocation until actual reader access is denied on the supported engines.

## Required qualification

Use the release scenarios in [ADAPTER-SECURITY.md](ADAPTER-SECURITY.md#release-qualification). Capture the actual source and target reader results, record IDs/digests, field outcomes, query shapes and elapsed revocation times in protected evidence storage. Grant/mutation fixtures are required to prove POA-only, field-profile and record-specific field-sharing behavior; an all-allowed read sample is insufficient.

Use the reusable client configuration and actual source/consumer fixtures in [client onboarding](CLIENT-ONBOARDING.md) and [live acceptance](LIVE-ACCEPTANCE.md). Historical research or hydration scripts are not deployment commands and are not assumed to be present in the portable release.
