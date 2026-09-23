# Independent native-policy watchdog

Run the watchdog separately from the projection publisher. It reads the current
OneLake policies directly and, by default, withdraws expired app-owned roles without needing
the publisher's disk, journal, Dataverse credentials, or business records.
Generation IDs must be the Unix-microsecond IDs produced by this application's
journal. Do not deploy hand-numbered generations such as `1` into a watched item.

The watchdog validates canonical role ownership, row filters and column
allowlists before acting. It removes only app-owned roles using the ETag of the
exact snapshot it assessed. An intervening fresh publication is preserved. It
reports unresolved policy shapes and unmanaged broad permissions as critical,
continues checking other items, and returns exit code 2 if any critical condition
remains. It never restores an older generation or logs records/tokens/user names.

Fabric requires role names to start with a letter and contain only letters and
digits; names are unique without regard to case. The general limit is 128
characters, but the [SQL analytics endpoint supports at most 124 characters](https://learn.microsoft.com/en-us/fabric/onelake/security/sql-analytics-endpoint-onelake-security#limitations)
because its `OLS_` prefix uses four more. The application caps readable names at
124. The supported ownership encoding depends on the selected naming mode.

New onboarding uses `"role_naming": "user_business_role"` in version 0.3.1:
username + home BU + one prioritized source-role title with action words removed.
There is no added PW prefix, role count or ID suffix. The complete canonical RLS
predicate instead includes `__pw_reader <> 'PolicyWeaverOwnerV1<sha256>'`, binding
the tenant/deployment annotation alongside the existing reader-GUID equality.
The marker is not a GUID, so it excludes no matching authorized reader rows.
It is an ownership annotation, not an access grant, secret, signature or lease.
The watchdog validates exact scope, single-member binding and policy shape;
malformed marked roles block mutation. Unmarked overlapping policies are foreign
and reported as critical rather than automatically removed.

Omitting `role_naming` still means `"legacy"` for compatibility. Legacy
names are `PW<deployment-hash16>R<reader-guid32>`. With `"readable"`, names become
`PW<primary-role>Plus<N><reader-alias>BU<home-BU>N<deployment-hash16>R<reader-guid32>`;
`Plus<N>` appears only when the reader has additional distinct root roles.
Active BNYM, BNY and ECRM titles receive display priority; deprecated labels stay
in the audit mapping. Names are shortened and punctuation is removed; full role
titles, role IDs, assignment origins and BUs remain in the generation manifest.
The displayed home BU is not the scope of every inherited role or row grant.

These two older formats use the first 16 hexadecimal characters of the SHA-256
digest of the ownership prefix in the name. Version 0.3.1 recognizes all three
formats and verifies the reader GUID against the single member and tenant.
Descriptive labels never authorize access or determine ownership. Do
not identify owned roles using the business-role title or literal deployment
name. The complete policy shape and member binding are checked before withdrawal.

**Upgrade every publisher and independent watchdog to version 0.3.1 before
publishing user_business_role names.** An older watchdog cannot recognize the
new ownership encoding and cannot provide its
normal expiry withdrawal for those roles. Deploy the tested image by digest,
wait for old executions to finish, verify a healthy new scheduled inspection,
then set the publisher to `role_naming: "user_business_role"` and prepare a new generation.
The changed configuration fingerprint prevents reuse of a legacy preparation;
the normal ETag-protected role replacement removes old owned names and publishes
the new names together. Renaming an existing generation is prohibited. Explicit
withdrawal in the updated application supports all three formats. Do not roll
back to a controller that cannot identify the published encoding.

```powershell
python -m policyweaver.native_watchdog --config deployment.json --inspect
python -m policyweaver.native_watchdog --config deployment.json --once
```

`--inspect` is read-only. `--once` can withdraw app-owned expired permissions.
The module also accepts the complete configuration in the
`POLICYWEAVER_CONFIG_JSON` environment variable. Include every serving item;
redeploy the watchdog configuration whenever provisioning adds or moves shards.
When retiring or moving an item, explicitly withdraw its published roles and
verify the result before removing that item from the watchdog inventory. Keep
both old and new items monitored throughout migration. Removed source tables
inside an owned item's canonical deployment namespace still expire in timed mode;
removing an entire item from configuration would prevent the watchdog visiting it.
Keep the configuration, deployment permissions and container identity controlled
by the operations team. There is no dependency on an expiring operator boundary
attestation because this component can only remove the app's existing grants.

## Explicit manual retention

`retention_mode` defaults to `"timed"`. An operator can explicitly select
`"manual"` in both the publisher and watchdog configurations to retain valid
published roles until replacement or manual withdrawal. This applies only to
that configuration's tenant, workspace, deployment namespace and enumerated
`serving_items`; it does not disable the watchdog job. In manual mode the job
continues checking canonical policy shape, membership, namespace, generation
integrity and unmanaged overlap. A valid owned generation reports
`manual_retention_active`, with `age_based_withdrawal_enabled: false`.
Malformed policies remain critical; invalid, future or mixed generations retain
their withdrawal behavior. Explicit operator withdrawal remains available.

The generation's finite `publication_deadline_at` still limits how old a prepared
projection may be when it is published. Manual retention does not extend that
deadline or permit publication of a stale preparation. Its
`automatic_withdrawal_at` is null: existing grants and projected data can persist
through later Dataverse changes until a successful refresh or manual withdrawal.
Manual retention therefore gives up automatic age-based stale-grant removal for
this explicitly selected scope; it does not satisfy a security-change deadline
without a separately qualified refresh and containment process.

Retention mode is controller configuration, not a marker embedded in OneLake
roles. Align **every** publisher/local watchdog/cloud watchdog that targets the
same namespace and items. An older timed controller can still withdraw roles
published by a manual-mode publisher. Upgrade the controller image before, or
atomically with, its configuration: older images reject the new field. Deploy
the tested image by digest, preserve identity, scope, schedule and resources,
then verify the exact configuration and image readback. Wait for any old scheduled
execution to finish and confirm a new scheduled heartbeat with
`retention_mode: "manual"` before relying on retained publication. Existing
heartbeat/critical alert queries continue to work because the top-level result
still reports `status`, `critical` and `inspect_only`.

Changing manual mode back to timed can withdraw an already-old generation on the
next watchdog run. Treat image/configuration rollback as one coordinated change;
do not revert to an image that cannot parse its active configuration. An explicit
withdrawal or replacement must precede removing an item from either mode's
inventory.

## Container

The Dockerfile uses Python 3.11, installs the adapter extra with
`requirements.lock` constraints, and runs as UID/GID 10001. The default
command is one watchdog execution. The build-context allowlist excludes local
credentials, configuration, source CSV files, reports, `.policyweaver`, and
virtual environments. No public listener is started.

```powershell
docker build -t policyweaver-watchdog:0.2.0 .
```

For a release, pin the approved base-image digest, generate an SBOM, scan the
image and dependencies, and deploy the resulting image by digest. The supplied
Dockerfile is buildable source, not a signed or vulnerability-certified image.

## Azure Container Apps job

`azure-watchdog.bicep` creates a dedicated user-assigned managed identity,
Container Apps environment, Log Analytics workspace, and a manual job. Set
`location` to the client's approved Azure region; the template default is Sweden
Central. The initial command is read-only inspection. It grants that identity image-pull access to an
existing ACR. It does not create workspaces, assign Fabric permissions, grant
Dataverse access, share items, or deploy an HTTP ingress.

Supply `registryName`, `containerImage` (prefer a digest), and `watchdogConfig`
in a private deployment parameter file. The template overrides authentication
with the new managed identity and stores the configuration as a job secret.
The registry can be in another resource group in the same subscription.
Set `registryUsesAbac=true` for an ABAC-enabled registry: the template selects
Container Registry Repository Reader and limits its condition to
`repositoryName` (default `policyweaver/watchdog`). Otherwise it uses AcrPull.
It never enables registry admin credentials. After identity, alerting and expiry
qualification, set `enableWithdrawal=true` and `enableSchedule=true` to activate
withdrawal every five minutes. Until then, the deployed manual inspection job
provides no automatic revocation protection.

Validate and preview the deployment before creating resources:

```powershell
az bicep build --file deploy/azure-watchdog.bicep
az deployment group what-if --resource-group <resource-group> --template-file deploy/azure-watchdog.bicep --parameters '@<private-parameters.json>'
az deployment group create --resource-group <resource-group> --template-file deploy/azure-watchdog.bicep --parameters '@<private-parameters.json>'
```

An administrator must separately enable the required Fabric service-principal
tenant setting and grant the identity sufficient authority to list and update
OneLake roles on the configured serving items. Fabric workspace Admin/Member
access is powerful; scope the serving deployment appropriately and treat the
watchdog identity as a privileged security controller. Current Microsoft
guidance requires Admin or Member for configuring OneLake roles; it does not
document a role-revocation-only permission. Member is the lower of those two
workspace roles but includes broad workspace data access. Prefer a dedicated
serving workspace; do not automatically assign Member in a workspace containing
unrelated raw data. The code has no need for
Dataverse access. Qualify managed-identity authentication against the actual
tenant before relying on the schedule.

## Operations and the 60-minute requirement

In timed mode, at the default 45-minute generation lifetime, a five-minute watchdog schedule
leaves a nominal ten-minute window for control-plane and engine propagation.
This is a budget, not a platform-enforced guarantee. The watchdog cannot revoke
permissions during a Fabric API outage, cannot terminate every cached query,
and cannot make OneLake roles self-expiring. SQL/Spark/Direct Lake revocation
measurements and an approved outage containment procedure remain release gates.

Configure external Azure Monitor alerts before use:

- Any critical structured result or nonzero/failed execution.
- No healthy withdrawal-mode result within fifteen minutes, including scheduler or identity
  failures that happen before application startup.
- Any unmanaged permission overlap or unrecognized owned-role shape.
- Repeated concurrency conflicts or stale generations after a withdrawal.

The optional alert template below creates portal-only alerts without recipients.
Connect them to the bank's approved incident destination. Test publisher-host
loss while the watchdog continues running, then test watchdog-host/API failure
and the independent containment response. Retain execution and audit evidence.

## References

- [Fabric role replacement and ETags](https://learn.microsoft.com/en-us/rest/api/fabric/core/onelake-data-access-security/create-or-update-data-access-roles)
- [OneLake role and engine propagation](https://learn.microsoft.com/en-us/fabric/onelake/security/data-access-control-model)
- [Azure Container Apps job resource](https://learn.microsoft.com/en-us/azure/templates/microsoft.app/2025-07-01/jobs)
- [Managed environment resource](https://learn.microsoft.com/en-us/azure/templates/microsoft.app/2025-07-01/managedenvironments)
- [Repository-scoped ACR ABAC permissions](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-rbac-abac-repository-permissions)
- [OneLake security management permissions](https://learn.microsoft.com/en-us/fabric/onelake/security/best-practices-secure-data-in-onelake)
# Portal-only watchdog alerts

`watchdog-alerts.bicep` creates two Azure Monitor log alerts: a structured critical
result and no healthy `--once` result within 15 minutes. Both evaluate every five
minutes. They have **no action group or notification recipient**. Connecting an
approved incident destination and testing delivery remains a production gate.

Before deploying, query the actual Log Analytics `ContainerAppConsoleLogs_CL`
schema and values. Its `EnvironmentName_s` is an internal name and can differ
from the ARM Container Apps environment name. Pass the observed value as
`environmentLogName`; do not guess it. The template also filters the exact job
and container. Query validation remains enabled. Supply the client's actual
subscription, resource group and observed environment-log value:

```powershell
az deployment group create --subscription <CLIENT_SUBSCRIPTION_GUID> --resource-group <CLIENT_RESOURCE_GROUP> --name pw-watchdog-monitoring --template-file deploy/watchdog-alerts.bicep --parameters environmentLogName=<OBSERVED_ENVIRONMENT_LOG_NAME>
```

These alerts observe the watchdog control process, not end-user engine access.
An absence of critical results cannot establish a revocation SLA or data-path
parity. See the [scheduled query rule reference](https://learn.microsoft.com/en-us/azure/templates/microsoft.insights/2023-12-01/scheduledqueryrules).
