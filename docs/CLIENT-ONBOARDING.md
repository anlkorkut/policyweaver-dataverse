# Onboard Policy Weaver to a client environment

This workflow configures a fresh clone for the client's own Dataverse organization and Fabric destination. It starts with read-only discovery and produces a reviewable deployment configuration before creating any cloud components or granting access.

Policy Weaver has three parts. The optional signed Dataverse `pw_ReadContext` plug-in proves which user a request actually runs as. The Python adapter runs outside Dataverse, reads selected data under each reader's verified identity, and stages those exact results as private Delta data. Fabric OneLake roles then restrict each consumer to that consumer's current projection. Dataverse evaluates Basic, business units, teams, POA and field security; the adapter does not recreate them by copying similarly named business roles.

This is a deployment and qualification workflow, not automatic production certification. The current adapter performs full selected reader/table projections. Complete security-event deltas, an automatic serving-boundary inspector and a distributed publisher service are not implemented. The native policy APIs and engine propagation remain dependencies for timely revocation.

## 1. Clone and invoke the repository skill

Clone the repository and select the revision approved by your organization. Open its root directory in the coding agent. Do not copy a previous customer's configuration or generation state.

```text
git clone https://github.com/anlkorkut/policyweaver-dataverse.git
cd policyweaver-dataverse
```

The repository includes a discoverable entry at `.agents/skills/policyweaver-dataverse/SKILL.md` and the maintained skill at `skills/policyweaver-dataverse/SKILL.md`. Codex discovers repository skills from `.agents/skills`; CLI/IDE invocation uses `$policyweaver-dataverse`, while the desktop interface can use `@policyweaver-dataverse`. [Codex skill documentation](https://learn.chatgpt.com/docs/build-skills). For example:

```text
Use $policyweaver-dataverse to onboard this repository to our environment.
Start with discovery and a deployment plan. Our tenant ID is <tenant GUID>,
Dataverse URL is <HTTPS organization origin>, and intended operator is <UPN>.
Help us choose the readers, tables and isolated Fabric destination from the
discovered inventory. Reuse the scope we authorize in this session.
```

If the agent does not discover repository skills, tell it to read `skills/policyweaver-dataverse/SKILL.md` from the clone. The skill is portable guidance and requires access to the checked-out application; installing it globally is optional. Refresh the agent's workspace/session if it cached the skill inventory before the clone was opened.

The agent should first collect the three target/account facts above. It can discover most other identifiers after authentication. The client must choose the business scope and deployment boundary; an inventory is not authorization to include every user or table. [Input definitions and permissions](CLIENT-INPUTS.md) explain the fields and account requirements.

## 2. Prepare the laptop

Use 64-bit Python 3.11 or later, Git and Azure CLI. From the repository root:

```text
python scripts/bootstrap_policyweaver.py --plan
python scripts/bootstrap_policyweaver.py --with-tests
```

The first command previews local setup. The second creates `.venv` and installs the pinned application dependencies with the test extra. It does not sign in or modify Dataverse or Fabric. Add `--with-qualification` when preparing actual-reader SQL tests; those additionally require Microsoft ODBC Driver 18 for SQL Server. Building a new signed ReadContext plug-in also requires the Windows .NET build prerequisites described in [the plug-in runbook](READ-CONTEXT-PLUGIN.md).

Activate the virtual environment before subsequent Python commands:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# macOS/Linux shell
source .venv/bin/activate
```

If local execution policy prevents PowerShell activation, use `.\.venv\Scripts\python.exe` in place of `python`; do not disable organizational execution controls. The Python adapter is portable, but each target operating system and optional native dependency must pass its own qualification.

```text
python -m pytest -q
python -m policyweaver.onboarding --help
python -m policyweaver.adapter_cli --help
```

## 3. Create client intake files and authenticate

Choose a private working directory outside the tracked repository, or a protected ignored client directory. The following examples use `clients/bank-pilot`. Replace `bank-pilot` with a client-safe local label, not a credential or business-record identifier.

```text
python -m policyweaver.onboarding init --output-dir clients/bank-pilot/intake
```

Edit the generated `request.json` using the client's tenant ID, Dataverse origin and intended operator UPN. Optional supplied IDs must refer to the same client. The optional `reader_upns` list helps resolve a known cohort, and `tables` requests validation of specific logical tables and columns. Empty `tables` requests a metadata inventory first. Leave unresolved facts unresolved rather than pasting fictional example GUIDs.

`selections.json` starts with an empty audience and table list. Fill it after discovery. `env.example` documents optional process settings; the application does not automatically load it or any `.env` file.

For a separate local Azure CLI cache, set `AZURE_CONFIG_DIR` to a protected directory before sign-in. This is useful when your ordinary CLI session belongs to a different tenant. Then authenticate interactively with the intended operator:

```powershell
# Windows PowerShell, from the repository root
$env:AZURE_CONFIG_DIR = Join-Path $PWD 'clients/bank-pilot/azure-operator'
```

```bash
# macOS/Linux shell, from the repository root
export AZURE_CONFIG_DIR="$PWD/clients/bank-pilot/azure-operator"
```

```text
az login --tenant <CLIENT_TENANT_GUID> --allow-no-subscriptions
az account show --query "{tenant:tenantId,account:user.name,type:user.type}" --output json
```

Use the real GUID in place of the angle-bracket placeholder. The interactive browser/device sign-in handles MFA and conditional access. Never pass a password or print access tokens. The CLI's current subscription is not a Dataverse environment or Fabric permission grant; discovery verifies the actual token tenant and operator identity independently.

That operator check applies to discovery only. The adapter runtime's Azure CLI credential is tenant-bound and does not pin the UPN/object ID recorded in the plan. Keep using the isolated operator cache, run the safe `az account show` check before operations, and compare the account/tenant with the intended operator. Reader acceptance uses separate caches. If an account changed or the immutable binding is uncertain, repeat scoped read-only discovery to a new evidence file before proceeding. Do not interpret `plan.operator` as an enforced runtime account restriction.

## 4. Discover and select

```text
python -m policyweaver.onboarding discover --request clients/bank-pilot/intake/request.json --output clients/bank-pilot/intake/inventory.json
```

This phase reads source identity/metadata and accessible Fabric inventory. It does not create a plug-in, edit roles, read business values for publication, or publish OneLake policies. Keep the resulting administrative inventory private. If access is insufficient, preserve that failure as unresolved; do not infer that an inaccessible workspace, reader or table does not exist.

Review the inventory with the client and populate `selections.json`:

- Choose the destination workspace by GUID. Prefer a dedicated serving workspace with an approved owner and capacity.
- Select explicit reader Entra object IDs from valid Dataverse bindings. A license or Entra account alone does not establish source eligibility.
- Select logical table names and supported scalar columns from metadata. Start with a representative pilot covering the client's actual security cases.
- Set a client-specific `deployment_name` beginning `pw_` and choose `required_access_paths` from `onelake`, `spark`, `sql` and `direct_lake`.
- The onboarding renderer creates a configuration with empty `serving_items` for new isolated app-created items. Existing deployment reuse is an advanced operating workflow, not an onboarding shortcut.
- Retain timed retention and the default quota unless the client has evidence for a different selection. A quota above the default needs the actual support/approval reference for this destination. The renderer sets readable names and one source worker.

Discovery supports progressive detail. With `tables: []`, it lists the table catalog. To inspect column candidates for a chosen table, add an entry such as `{"name":"account","columns":[]}` to the request and discover into a new file. Candidate columns are not yet qualified for projection. Then select explicit scalar columns in both the request and selections, set the same destination `workspace_id` in both files, and perform final discovery:

```text
python -m policyweaver.onboarding discover --request clients/bank-pilot/intake/request.json --output clients/bank-pilot/intake/inventory-selected.json
```

Use a **new inventory filename for every discovery**; existing evidence is not overwritten. If the exact columns and workspace were known initially, the first discovery can supply this verified selection directly. Configure requires a recent matching inventory, with a 24-hour maximum age; this freshness check is not a publication-boundary inspection. Reconcile current identities and metadata sooner when the source is changing. A cross-client inventory or a stale screenshot is not a source of authoritative identifiers.

For Custom API identity proof, follow [the signed artifact and registration process](READ-CONTEXT-PLUGIN.md). FetchXML mode is the initial configuration path; it is insufficient for a Read-positive reader who cannot query its own `systemuser` context. That reader may need the qualified `pw_ReadContext` API. Do not grant the reader extra privileges to bypass this limitation. Selecting a reviewed DLL hash allows a planned Custom API configuration to be rendered; target registration verification and live identity tests remain mandatory before preparing with that mode.

## 5. Render and review the typed configuration

Use a new output directory to preserve previous plans and prevent accidental replacement:

```text
python -m policyweaver.onboarding configure --request clients/bank-pilot/intake/request.json --inventory clients/bank-pilot/intake/inventory-selected.json --selections clients/bank-pilot/intake/selections.json --output-dir clients/bank-pilot/deployment
python -m policyweaver.onboarding validate --config clients/bank-pilot/deployment/policyweaver.config.json
```

Review `deployment-plan.json`, `policyweaver.config.json` and `NEXT-STEPS.md`. Confirm the source organization ID, destination workspace, exact audience, table/column selections, Azure CLI authentication, namespace, role quota and private state path. The initial renderer uses `discover_readers: false`, an empty serving-item map, a 1,000-reader planner ceiling, one source worker and readable names. Managed identity is a later reviewed migration, not a laptop credential fallback. Validation checks configuration; it does not prove operator permissions, a safe destination or runtime enforcement.

The Power Platform environment ID is retained as intake context when supplied. The adapter's `organization_id` must be the Dataverse organization GUID. Reader values are Entra object IDs. Lakehouse IDs come from provisioning or verified app ownership, never from a name match or another environment's example.

Use the full explicit `--config` path for every command. Relative `state_directory` values resolve against the configuration file's directory, so each deployment has its own protected journal, generations and logs.

## 6. Establish the source and destination

These commands perform source checks and private preparation:

```text
python -m policyweaver.adapter_cli --config clients/bank-pilot/deployment/policyweaver.config.json doctor
python -m policyweaver.adapter_cli --config clients/bank-pilot/deployment/policyweaver.config.json discover
```

`doctor` verifies source identity and selected metadata; it is not a complete impersonation or consumer test. ReadContext installation is a separate, explicit Dataverse customization operation. Reuse deployment authorization already given; if it was not given, review the exact installation plan before requesting it.

Within the client's approved destination scope:

```text
python -m policyweaver.adapter_cli --config clients/bank-pilot/deployment/policyweaver.config.json provision
```

Provisioning creates isolated serving lakehouses, retains creation receipts and records their IDs in the configuration. It does not share them with consumers. It may pause for supported Fabric portal actions such as enabling OneLake security. It does not erase arbitrary pre-existing customer policies. Because provisioning changes the configuration fingerprint, prepare a fresh generation afterward.

Before publishing, establish each serving item's real boundary: actual ownership, workspace inheritance, item grants, alternate paths and required SQL mode. For native SQL, the endpoint must use UserIdentity mode. Switching from delegated mode can remove existing SQL objects and interrupt queries outside the single item; inspect the actual scope and obtain any missing authorization before changing it. [Microsoft access-mode guidance](https://learn.microsoft.com/en-us/fabric/onelake/security/sql-analytics-endpoint-onelake-security).

Readers need direct item Read with the same Entra object ID used in their OneLake role. Keep additional sharing options off unless separately justified; granting broad data read or workspace elevation is not a remedy for a failed test. Confirm supported actual owner type; service-principal ownership currently prevents SQL security synchronization. [Microsoft synchronization guidance](https://learn.microsoft.com/en-us/fabric/onelake/security/troubleshoot-onelake-security-for-sql-analytics-endpoints).

Before the **first timed publication**, establish the independent watchdog using [the deployment runbook](../deploy/README.md). Match its serving-item inventory, namespace, retention mode and tested application version to the publisher. Verify actual identity permissions, withdrawal behavior and a healthy monitored schedule. The default inspect-only deployment is a setup stage and provides no automatic expiry protection. Do not publish timed consumer access while intending to add that protection later. A healthy watchdog still depends on Fabric policy APIs and does not make native roles self-expiring.

## 7. Prepare, publish and observe progress

```text
python -u -m policyweaver.adapter_cli --config clients/bank-pilot/deployment/policyweaver.config.json --progress prepare
python -m policyweaver.adapter_cli --config clients/bank-pilot/deployment/policyweaver.config.json status
```

Preparation writes sensitive source-derived data locally but does not publish permissions. Watch the timestamped aggregate progress and record the successful result's actual generation integer. A `prepared` status means the data is staged; native roles can still be absent.

On PowerShell, the launcher shows progress and saves logs:

```powershell
.\scripts\Run-PolicyWeaver.ps1 -Operation Prepare `
  -Config .\clients\bank-pilot\deployment\policyweaver.config.json `
  -PythonPath .\.venv\Scripts\python.exe
```

It writes terminal, progress, result and execution files under the configured private state directory. A heartbeat means the process is alive; it does not prove successful progress. Inspect exit status and the journal after interruption. Do not clear a live writer lock or replay an uncertain policy mutation.

Replace `ACTUAL_GENERATION` below with the successful preparation's integer:

```text
python -m policyweaver.adapter_cli --config clients/bank-pilot/deployment/policyweaver.config.json dry-run --generation ACTUAL_GENERATION
python -m policyweaver.adapter_cli --config clients/bank-pilot/deployment/policyweaver.config.json boundary-template --generation ACTUAL_GENERATION
```

The boundary template is deliberately unverified. Save it to the deployment's boundary file and complete it only from an actual inspection of the exact readers and serving items. Its timestamp must reflect that inspection and be no more than 15 minutes old at publication; updating only the time is invalid. Every shard needs evidence of no privileged workspace-reader path, no alternate data path and the verified SQL mode. No automatic onboarding step asserts these facts.

With a complete, current generation, successful dry run and fresh inspected boundary:

```text
python -u -m policyweaver.adapter_cli --config clients/bank-pilot/deployment/policyweaver.config.json --progress publish --generation ACTUAL_GENERATION --boundary clients/bank-pilot/deployment/boundary.json
```

Do not use `run`, `worker`, `watchdog` or `withdraw` to obtain a read-only preview: those commands can withdraw policies. Use `prepare` for private staging and `status` for the journal.

## 8. Qualify the client's actual access

Read back the native role set and persisted data, then verify SQL translation separately. A successful policy API response does not establish SQL propagation. Inspect expected `OLS_` roles and current RLS/CLS translation without modifying system-generated SQL policies. A sync failure needs diagnosis of ownership, mode, references, identity match and capacity evidence; do not rerun extraction or buy capacity solely because an HTTP 500 occurred.

Use [actual-reader acceptance](LIVE-ACCEPTANCE.md) to compare real Dataverse and Fabric sessions. At minimum qualify:

- Basic owner access and a known-existing denied record; Local/Deep BU boundaries and sibling denials.
- Direct POA, team/access-team sharing and cumulative grants; last-grant removal and team membership removal.
- Field-profile union, denied-field NULL values, real record-specific POAA and any discovered masking.
- Denied table access and hidden helper columns, raw-data bypasses, historical reads and caches.
- Every required native engine and the client's measured maximum change-to-enforcement time.

An administrator's filtered query is projection evidence, not consumer enforcement. A Global Read persona cannot prove POA-only access. A record that does not exist cannot prove a denied record. A source field that was already NULL cannot prove masking. Keep fixture owners, reader bindings and expected outcomes in protected evidence and obtain explicit scope before mutating client fixture data.

## 9. Operate and hand over

Keep one controlled publisher and an independently hosted, monitored watchdog. Match application versions, retention mode, ownership namespace and serving-item inventory across controllers. Read [the operating reference](ADAPTER-OPERATIONS.md), [watchdog deployment](../deploy/README.md) and [manual-retention implications](MANUAL-RETENTION.md) before scheduling.

A cron schedule starts a full preparation; it does not fetch a complete security delta. Runtime depends on selected reader/table pairs, readable row copies, source throttling and destination propagation. Measure the client's workload. An hourly start plus a lengthy run can exceed a 60-minute change objective. Static native roles do not self-expire when Fabric policy APIs are unavailable, so an independent qualified containment mechanism remains necessary for a hard deadline.

The handover should include the chosen revision, private configuration/plan locations, verified IDs, roles/owners of operational identities, artifacts created, selected coverage, generation and policy receipts, actual-reader test evidence, measured timings, alert/containment ownership and every remaining qualification gap. Report discovered, configured, prepared, published and reader-verified states separately. No clone-and-run success establishes full-catalog or production qualification for another client's environment.
