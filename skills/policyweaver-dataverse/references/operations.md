# Application operation reference

Use this reference for the installed skill's setup and recovery decisions. The maintained detailed instructions are in the application's `docs/ADAPTER-OPERATIONS.md` and `docs/ADAPTER-SECURITY.md`; locate the repository before running commands. No environment identifiers are embedded in this skill.

## Setup and source readiness

For a new clone, follow `docs/CLIENT-ONBOARDING.md` and `docs/CLIENT-INPUTS.md`: bootstrap the local environment, initialize client intake, discover with the intended Azure CLI operator, make explicit selections and render typed configuration. The onboarding commands perform local work and read-only discovery; they do not establish a publication boundary. Use 64-bit Python 3.11+ and the pinned dependency install. Organization ID is not the Power Platform environment ID. Do not run demonstration scripts or reuse client IDs from historical reports.

`readers` uses Entra object IDs. `discover_readers: true` opts into the discovered audience, subject to exclusions and the configured maximum; do not turn it on merely because a user created test accounts. The logical lookup name `primarycontactid` becomes the scalar output property `_primarycontactid_value`. The `__pw_` namespace is reserved.

The source operator needs directly assigned impersonation permission, source metadata/security discovery and sufficient data/field privileges. The adapter verifies table Global Read and secured-field coverage through a direct built-in System Administrator template or all-record direct/team profile Read grants. Missing proof blocks projection. Actual operator/reader comparison still qualifies source behavior. Never use administrator-owned record results as reader-authorized output. Azure CLI authentication supplies the configured tenant; managed identity requires a separately configured identity-enabled host, Dataverse application user and Fabric access. Neither `.env` nor arbitrary secret environment variables selects an adapter configuration.

Onboarding's expected operator UPN/object ID check applies to discovery. The runtime Azure CLI credential is tenant-bound and does not pin the operator recorded in the plan. Isolate its `AZURE_CONFIG_DIR`, recheck the active account and tenant before operations, and keep actual-reader login caches separate. If the account changed or the immutable binding is uncertain, repeat scoped read-only discovery to a new evidence file rather than assuming the prior operator observation still applies.

```text
python -m policyweaver.adapter_cli --config CONFIG doctor
python -m policyweaver.adapter_cli --config CONFIG discover
python -m policyweaver.adapter_cli --config CONFIG prepare
python -m policyweaver.adapter_cli --config CONFIG status
```

`doctor` is a source/control check, not an end-to-end certification. `prepare` is a full authoritative projection and private local write. A failed page or budget requires a fresh complete generation.

Version 0.2.4 supports `source_workers` from 1 to 4, defaulting to 1. Qualify two workers against sequential source results before enabling them in a live configuration. Each worker must own a separate source client; one consumer writes Delta and the journal. Keep the same identity proofs, privilege gates, finite freshness deadline and single-publisher lock. A failure invalidates the entire generation. Configuration changes require a new preparation; increasing concurrency is not a substitute for measuring Dataverse throttling and completion time.

## Identity proof without extra reader privileges

The default `fetchxml` proof requires the reader to query its own `systemuser` row. If an otherwise entitled business-table reader lacks `prvReadUser`, read the application's `docs/READ-CONTEXT-PLUGIN.md`. The optional `pw_ReadContext` Custom API returns only the effective context, organization, fresh nonce and protocol. Do not solve this limitation by expanding reader roles.

For a new development registration, build with `plugins/PolicyWeaver.ReadContext/build.ps1 -SignKeyPath PROTECTED_KEY`, then use the existing CLI's `plan`, explicit `install`, and `verify` operations. Review the exact tenant/organization, creates and artifact identity before installation within the authorized task. `--approved-plan-sha256` takes the canonical reviewed plan's `plan_sha256`; `verify --assembly-sha256` takes the reviewed DLL hash. Neither is the ZIP hash or a hash of pretty-printed plan JSON. Keep the installer receipt after a partial failure and follow the narrow documented recovery path; do not invent ownership or overwrite foreign components.

Alternatively, use a separately approved managed-solution artifact from the client's release pipeline and the target environment's managed import process. The portable clone does not assume that a prebuilt managed ZIP or signing key is supplied. Inspect the exact package and embedded DLL digests. After import, run the same registration/content verifier against that environment and repeat live identity tests. Do not use the first-registration installer to adopt imported components. A locally rebuilt DLL does not change a separately packaged managed ZIP.

A planned local configuration may select `identity_verification: "custom_api"`, `identity_api_name: "pw_ReadContext"`, and `identity_api_assembly_sha256` as the exact independently reviewed 64-character lowercase DLL digest before installation, including when preparing the installation plan. This local choice does not qualify the identity path. Do not prepare or publish with Custom API mode until the installed registration/content verifier and actual impersonation-header proof tests pass. Validate operator → reader A → reader B → reader A with fresh nonces, including a reader with business Read but without `prvReadUser`; all identities must match their immutable bindings. The pinned implementation supports that fixed API name. A changed configuration requires a fresh prepared generation. No exception, stale proof or metadata mismatch permits fallback to an admin query.

Keep direct-reader acceptance separate. `scripts/qualify_reader.py` templates use per-reader `identity_verification: "bound_whoami"` and `dataverse_id`, bound to the actual delegated reader's Entra ID and tenant. Fill those pairs from controlled source inventory or a prepared manifest. This mode needs no plug-in-metadata or `systemuser` Read from the consumer and sends no impersonation header. Legacy fixture scenarios remain `fetchxml` unless explicitly changed. Follow `docs/LIVE-ACCEPTANCE.md` for the required real sessions and fixtures.

## Serving and publication

For `role_naming: "user_business_role"` (new onboarding default), first upgrade every publisher and watchdog to version 0.3.1 or later, following `docs/READABLE-ROLES-AND-DIVERSITY.md`. The name is username + home BU + one prioritized role title with action words removed; the RLS annotation identifies ownership without a name suffix. Fresh source label discovery records direct/team role origins and effective Entra role results. The displayed business role is a summary, not a one-to-one source role copy or an authorization input. Review `reader_labels` and each shard's `role_name_map`. Both old formats remain supported; omitted naming configuration still means legacy. Switching modes requires a new generation. A label error or name collision blocks preparation; never repair one by inventing grants or editing an immutable manifest. Confirm all consumer paths after publication; API validation alone is insufficient.

When testing different table-access combinations, account for existing direct and inherited grants and shared Read privileges such as Activity. Different role names or direct assignments do not prove different effective table sets. Changes to a synthetic source fixture must remain in the user's authorized test cohort, preserve original business roles unless specifically authorized otherwise, and carry a before/after inventory and reversible assignment ledger. A varied test profile is not evidence of exact customer catalog fidelity.

```text
python -m policyweaver.adapter_cli --config CONFIG provision
python -m policyweaver.adapter_cli --config CONFIG prepare
python -m policyweaver.adapter_cli --config CONFIG dry-run --generation GENERATION
python -m policyweaver.adapter_cli --config CONFIG boundary-template --generation GENERATION
python -m policyweaver.adapter_cli --config CONFIG publish --generation GENERATION --boundary BOUNDARY
```

Provisioning changes the configuration; prepare after it. Keep consumers away from the source lakehouse and private staging paths. OneLake-to-OneLake shortcuts are not independent policy shards; use the adapter's separate local Delta serving tables.

The boundary file is per shard and includes workspace/item IDs, exact reader IDs, actual inspection timestamp, `no_privileged_workspace_readers`, `no_alternate_data_access` and SQL mode. It expires after 15 minutes. Valid modes are `UserIdentity` and `DisabledForReaders`, based on actual controls. A boundary template intentionally fails. Never make it pass by guessing, copying an old timestamp or representing delegated SQL as user identity. Check group-inherited workspace elevation and alternate grants as well as direct assignments. Native SQL also requires a supported actual lakehouse owner, currently excluding service principals for security sync, and direct item Read for the same principal as each reader role. Owner, creator and publisher identities may differ; verify the actual ownership state. Inspect the scope of a SQL mode change before authorizing an interruption to unrelated workspace queries.

Role publication preserves unrelated roles, checks conflicts and ETags, and activates only a staged current generation. Following a post-commit timeout or partial shard failure, inspect and contain rather than replaying an old payload. Real consumer tests determine enforcement.

Before the first timed publication grants consumer data access, the independent watchdog must be operational and monitored for the exact deployed scope. Verify the compatible image/configuration, identity rights, withdrawal behavior and scheduled heartbeat. A successful `--inspect`, an undeployed template or an unscheduled inspection job does not establish expiry protection. Follow `deploy/README.md`; the Fabric policy API and engine propagation remain external dependencies even with a healthy watchdog.

## Scheduling and incidents

```text
python -m policyweaver.adapter_cli --config CONFIG worker
python -m policyweaver.adapter_cli --config CONFIG watchdog-worker
python -m policyweaver.adapter_cli --config CONFIG withdraw
python -m policyweaver.adapter_cli --config CONFIG console --port 8000
```

Start unattended operation in preparation-only mode until a trustworthy fresh-boundary workflow and qualified engine access exist. `worker --publish --boundary BOUNDARY` is available, but a static file expires; changing the timestamp without an actual inspection is invalid. Use one controlled writer and an independently supervised watchdog with persistent protected state. Do not put SQLite state on an unqualified multi-host file share.

For publisher-host failure containment, read the application's `deploy/README.md` and use the separately hosted `policyweaver.native_watchdog`. It reads generation-bearing Fabric policies without the local journal or Dataverse credentials. `--inspect` is read-only, `--once` can withdraw expired owned roles, and its configured item list must follow shard changes. Use only application-generated Unix-microsecond generation IDs. The container/Azure job template does not qualify actual identity permissions or revoke cached queries by itself.

Default refresh cadence is 10 minutes, generation lifetime 45 minutes and publication reserve 10 minutes. These are configured budgets, not a measured Fabric revocation guarantee. Alert if the watchdog dies or role withdrawal fails, and activate the environment's independent containment process. Exported data cannot be revoked retroactively.

For an explicitly requested persistent deployment, read `docs/MANUAL-RETENTION.md` and set `retention_mode: "manual"` before preparing a new generation. Keep the finite source lifetime, publication reserve and inspected boundary checks. The manifest/journal then records `automatic_withdrawal_at: null`; finite `expires` still describes source freshness. Match every local configuration and independently hosted watchdog for the exact tenant, workspace, ownership namespace and serving items, using a compatible tested image. An old timed controller can still withdraw roles. Verify actual job/config readback and a scheduled `manual_retention_active` heartbeat after publication. Manual mode gives up automatic timed withdrawal, does not schedule refresh, and leaves Dataverse changes unapplied until the next successful publication. Explicit `withdraw` remains available. Integrity failures can still trigger alerts or protective withdrawal; manual retention is not immunity from containment.

For a deployment that requires native OneLake, Spark and Direct Lake access, read the current native-expiry evidence in `docs/ADAPTER-SECURITY.md`. Static OneLake roles do not self-expire. An outage of the role-update API therefore leaves a hard 60-minute native revocation requirement unsatisfied unless Microsoft supplies a supported expiry or independently qualified containment mechanism. Treat this as a release blocker, not something that can be approved by editing a boundary file or marking a test passed. A SQL/API-only serving boundary is a different access-path decision and cannot replace an explicit native-path requirement.

For a stale writer lock, verify the owning process is stopped before using the CLI's `recover-lock` with the exact recorded owner and `--worker-stopped`. Never clear the lock to start a competing writer. Keep journals/manifests intact for investigation; do not publish failed generations or loosen schema/security checks to make a run finish.

## Evidence to report

Separate offline unit tests, source smoke tests, role dry runs, source-vs-target negative parity and timed engine revocation tests. Include discovered/selected reader counts, tables/fields covered, source operator qualification, current generation status and enabled engines. Mandatory fixtures cover Basic-only ownership, BU depths, team and POA-only access, cumulative grants, field-profile denial and union, real record-specific field sharing, revocation, bypass paths, historical reads and caches. Missing fixtures remain unqualified even if the source probe returns rows successfully.
