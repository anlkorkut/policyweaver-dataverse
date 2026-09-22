# Dataverse execution-context proof

Some valid business-table readers cannot read `systemuser`. The adapter's
default FetchXML identity probe therefore cannot qualify those readers without
changing their source privileges. The optional `pw_ReadContext` Custom API
removes that table-read dependency. It is an identity proof only: Dataverse
continues to evaluate all record and field permissions on the subsequent data
requests.

## Contract and scope

The API is an unbound synchronous GET function. Its required `Nonce` input is a
GUID. The plug-in reads its execution context and returns exactly:

| Property | Type | Meaning |
| --- | --- | --- |
| `UserId` | GUID | Effective execution user, from `IPluginExecutionContext.UserId` |
| `OrganizationId` | GUID | Current Dataverse organization |
| `Nonce` | GUID | The supplied challenge, returned unchanged |
| `ProtocolVersion` | String | `1` |

The plug-in must not use `InitiatingUserId` as the effective identity. The
originating user and the user under which the current operation executes can
differ. It does not accept a requested user ID, query an organization service,
read a business record, change records or privileges, or start background work.

The adapter sends the same `CallerObjectId` header used for business reads. It
requires the expected Dataverse user ID, organization ID, protocol and fresh
nonce, then verifies that the user's current administrative Dataverse/Entra
binding remains an enabled human. Unknown or mismatched results stop the
generation. There is no fallback to an administrator data query or an
unverified `WhoAmI` response.

A complete proof of absent table Read still produces zero rows and no native
table permission without invoking this function. The function cannot give an
unroled user business access, override field security, or supply table Read.

## Trust and registration

A nonce alone does not establish that the correct code is installed. Custom API
mode requires a configured SHA-256 of the signed assembly. The source client
verifies the API/type/assembly relationship, reads and hashes the installed DLL,
and checks the exact request/response schema before trusting the function.

The supported registration uses a dedicated `pw` publisher/solution, a signed
`net462` assembly in sandbox/database mode, and the
`PolicyWeaver.ReadContext.ReadContextPlugin` type as the Custom API's main
operation. It has global binding, `IsFunction=true`, no extra processing steps,
no workflow enablement and no additional execute-privilege name. There is no
ordinary SDK message-processing step registered to run as an elevated user.

The installer plans exact component IDs and records ownership before creating
anything. Existing foreign names or a conflicting publisher prefix block the
plan. The first installer does not overwrite, adopt or delete unrelated
customizations. A partial install retains its receipt for investigation; do not
delete receipts or make new plans to disguise uncertain source mutations.

Protect the assembly signing key and installation privileges. The key is kept
outside the source tree's distributable files. The source operator remains a
privileged identity; this proof does not replace control over source plug-in
deployment or other Dataverse customizations.

## Build the signed artifact

Run these commands from the repository root on Windows, using a .NET SDK,
.NET Framework 4.6.2 targeting pack/runtime, and a 64-bit Python 3.11 or later
virtual environment. The example uses `.venv`; use your actual
virtual-environment path. Install the tested dependency versions:

```powershell
.\.venv\Scripts\python.exe -m pip install -c requirements.lock -e ".[adapter,test]"
```

Supply an existing protected strong-name key:

```powershell
& ./plugins/PolicyWeaver.ReadContext/build.ps1 `
  -SignKeyPath 'C:/protected/your-signing-key.snk'
```

The script performs locked dependency restore, builds the signed assembly, runs
the 22 C# tests and writes these artifacts:

- `dist/read-context/PolicyWeaver.ReadContext.dll`
- `dist/read-context/manifest.json`

The manifest records the DLL's SHA-256, public key token, assembly version and
fixed API/type names. Keep the private signing key outside distributable files.
For an isolated development key, follow the guarded key-creation example in
[the plug-in build instructions](../plugins/PolicyWeaver.ReadContext/README.md#build-and-test-locally).
A different key or build can change the DLL digest: review the resulting artifact
and regenerate its deployment plan. Do not copy the demonstration digest into
the configuration of a differently built DLL.

The Python suite is run separately:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## First installation through the reviewed registration CLI

Choose this path for a first development registration in an environment without
these components. The managed-solution import path below is separate. Configure
`bank.config.json` for the actual tenant, Dataverse organization and environment
using [the application configuration runbook](ADAPTER-OPERATIONS.md#configuration).
The installer uses that configuration's Azure CLI or managed-identity credential;
it does not sign in automatically. Its deployment identity needs the appropriate
Dataverse customization rights, including plug-in assembly creation. The
consumer reader identities do not receive those rights.

Keep `identity_verification` at its default `fetchxml` while planning an absent
API. Inspect the artifact manifest and DLL hash, then generate a read-only plan:

```powershell
.\.venv\Scripts\python.exe scripts/manage_read_context.py --config bank.config.json plan `
  --artifact-manifest dist/read-context/manifest.json `
  --receipt .policyweaver/read-context-install.json `
  --output .policyweaver/read-context-install-plan.json
```

Review the plan's target organization, component identities, publisher/solution,
assembly identity, DLL hash and exact metadata creates within the already
authorized deployment scope. The output's `plan_sha256` is the canonical plan
digest used by the installer; it is not `Get-FileHash` of the formatted JSON file.
Set the following placeholder to that **reviewed plan digest** before executing
the explicit installation command:

```powershell
$reviewedPlanSha256 = 'REPLACE_WITH_REVIEWED_PLAN_SHA256'
.\.venv\Scripts\python.exe scripts/manage_read_context.py --config bank.config.json install `
  --artifact-manifest dist/read-context/manifest.json `
  --plan .policyweaver/read-context-install-plan.json `
  --receipt .policyweaver/read-context-install.json `
  --approved-plan-sha256 $reviewedPlanSha256
```

`plan` performs reads. `install` creates the reviewed Dataverse customization
components and retains an ownership receipt; it does not assign reader roles or
change business records. The plan output must be a new file. Keep the original
plan and receipt after a partial failure. The narrowly scoped `repair-plan`
command handles the documented original response-description-length issue; it
is not a general overwrite/retry mechanism. Inspect its `--help` and the original
receipt before using it. Foreign or conflicting components remain blockers.

After installation, verify the actual registration and installed DLL using its
separately reviewed **assembly** digest:

```powershell
$expectedAssemblySha256 = 'REPLACE_WITH_REVIEWED_LOWERCASE_DLL_SHA256'
.\.venv\Scripts\python.exe scripts/manage_read_context.py --config bank.config.json verify `
  --assembly-sha256 $expectedAssemblySha256
```

The `verify` operation is read-only. A plan digest, assembly digest and managed
ZIP digest serve different purposes; never substitute one for another.

## Managed solution for another environment

The portable source repository does not assume a prebuilt managed solution or
signing key. The build procedure above produces a signed DLL and artifact
manifest. For managed delivery, the client's approved build/release pipeline
must package and export a reviewed solution, or supply a separately approved
release artifact with its own evidence. Record the actual managed ZIP digest
and the digest of its embedded DLL; they are different pins.

Inspect the package's managed flag, dependencies and component list. It should
contain the intended identity-proof components and no unrelated role, profile,
business table or organization-setting changes. A prior export or successful
import elsewhere does not qualify the target environment.

To evaluate import in an authorized target environment:

1. Verify the ZIP hash against the release evidence and inspect the solution
   identity and components. Check the intended target environment and any
   existing `pw` publisher or `pw_ReadContext` components before import.
2. In Power Apps, select the target environment, open **Solutions → Import
   solution**, select the managed ZIP, review dependencies and import details,
   and complete the import within the authorized customization scope. Preserve
   the import history and result. This is a metadata-changing operation.
3. Point `bank.config.json` at that target organization and run the same
   `manage_read_context.py ... verify --assembly-sha256` command above using the
   **embedded DLL** digest. Verification must succeed against the imported
   registration before enabling Custom API mode.
4. Repeat the live identity and reader-projection qualification below in that
   environment. An import-success message alone does not establish execution
   identity or authorization parity.

Use the solution import lifecycle for this path. Do not run the first-install
registration planner to adopt or replace imported components; its ownership
receipt is specific to components it created. A locally rebuilt DLL is not
automatically substituted into a separately packaged ZIP. Repackaging, upgrades and
second-environment behavior need their own controlled validation.
[Microsoft's import instructions](https://learn.microsoft.com/en-us/power-apps/maker/data-platform/import-update-export-solutions)
describe the environment selection, dependency checks and import history.

## Enable the verified identity path

After successful registration verification and the source proof checks below,
merge these settings into the actual application configuration:

```json
{
  "identity_verification": "custom_api",
  "identity_api_name": "pw_ReadContext",
  "identity_api_assembly_sha256": "REPLACE_WITH_REVIEWED_LOWERCASE_DLL_SHA256"
}
```

Replace the digest placeholder with the exact 64-character lowercase DLL hash.
This release supports the fixed `pw_ReadContext` API and
`PolicyWeaver.ReadContext.ReadContextPlugin` type. The verifier rejects a different
API name even if it is syntactically valid configuration. Never switch modes in
response to an error without establishing the required proof.

The source client verifies the pinned registration before its first Custom API
challenge and caches successful registration verification only for that source
client. Every reader challenge uses a fresh nonce. A configuration change
invalidates earlier prepared generations; prepare again:

```powershell
.\.venv\Scripts\python.exe -m policyweaver.adapter_cli --config bank.config.json prepare
.\.venv\Scripts\python.exe -m policyweaver.adapter_cli --config bank.config.json status
```

These commands create and inspect a private local generation. Fabric publication
still requires its separate validated serving boundary and current generation.

## Qualification

Before using Custom API mode for publication:

1. Build the signed assembly and run its local tests. Record the DLL hash and
   public assembly identity. Review the read-only installation plan against the
   intended organization.
2. Install only within the authorized Dataverse customization scope, then verify
   the entire registration and installed content hash.
3. Query as the operator and as two different real readers by changing only the
   impersonation header. Every response must identify the correct effective
   user, organization and fresh nonce.
4. Include a reader with business-table Read and no `prvReadUser`. Its context
   proof must work without adding source privileges. Independently compare that
   reader's direct source session with the adapter projection.
5. Test a missing API, changed DLL hash, wrong identity, nonce mismatch, unknown
   protocol and metadata mismatch. All must prevent publication.
6. Prepare a fresh generation after changing the configuration. Existing staged
   data is bound to the previous configuration and must not be reused.

Installing this identity proof does not qualify Fabric RLS/CLS, POAA parity,
engine caches or the 60-minute revocation bound. Those remain the separate live
acceptance tests.

For actual-reader SQL acceptance, the consumer can use the separate
`bound_whoami` mode described in [LIVE-ACCEPTANCE.md](LIVE-ACCEPTANCE.md). That
mode binds a controlled Dataverse/Entra identity pair to the reader's direct
delegated credentials; it requires neither `prvReadUser` nor permission to
inspect plug-in metadata. It does not substitute direct-user WhoAmI for an
impersonated adapter identity proof.

## Record the client's qualification evidence

Retain the exact source revision, signed DLL/public key identity, registration
receipt, actual target verification and operator → reader A → reader B → reader A
challenge results. Include a Read-positive reader without `prvReadUser`, and
compare direct-reader source results with the adapter projection. Keep safe
aggregate metrics and protected identity/value evidence separately.

Record selected reader/table counts, output rows, requests/retries and elapsed
time from that client's run. Those measurements apply to that selected scope;
they do not establish all-table or 1,000-reader throughput. Field NULL counts
alone do not prove negative field-security or record-specific field-sharing
parity.

Run the C# and Python suites for the checked-out revision and retain the actual
results. Consumer qualification still requires real-user Fabric queries on every
enabled engine, positive/negative POA and field-sharing fixtures, BU/team
changes, source/destination failures, historical access, caches and measured
revocation within the client's deadline. Continuous unattended publication also
requires a provider of fresh truthful serving-boundary inspections; the
application consumes those assertions and does not implement that inspector.

## Microsoft references

- [Web API impersonation and CallerObjectId](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/impersonate-another-user-web-api)
- [Custom API implementation and main-operation plug-ins](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/custom-api)
- [Custom API metadata and parameter types](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/custom-api-tables)
- [Creating a Custom API with code](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/create-custom-api-with-code)
- [Building and signing Dataverse plug-ins](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/build-and-package)
