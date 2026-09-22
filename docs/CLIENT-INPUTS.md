# Client deployment inputs

Use this reference with [client onboarding](CLIENT-ONBOARDING.md). The repository contains no universal client tenant, environment, lakehouse, reader account or signing key. Discovery supplies evidence; the client chooses the deployment scope.

## Identify the target before signing in

| Input | Meaning and source | How it is used |
| --- | --- | --- |
| Entra tenant ID | Directory GUID supplied by the client or confirmed in Entra | Pins authentication and every reader binding |
| Dataverse environment URL | HTTPS organization origin from Power Platform, such as `https://yourorg.crm.dynamics.com` | Web API target; no browser path, query string or trailing API route |
| Intended operator UPN | The client's approved interactive deployment account | Compared with the authenticated identity during onboarding; never a password |
| Operator Entra object ID | Immutable user object ID, if known | Additional discovery-time identity check; discovery can resolve and record it |
| Dataverse organization ID | Organization GUID returned from verified source discovery | Required `organization_id` in the adapter configuration |
| Power Platform environment ID | Separate environment identifier from the admin center | Optional administrative cross-reference; never substituted for organization ID |
| Fabric workspace ID | GUID of the chosen destination workspace | Client selects a discovered workspace; display names alone are insufficient |
| Deployment name | Client-chosen namespace beginning `pw_` followed by lowercase letters, digits or underscores | Stable ownership scope and destination table/name prefix; maximum 38 characters including `pw_` |

The onboarding CLI currently accepts public-cloud Dataverse origins and uses public Fabric service endpoints. It rejects sovereign-cloud origins. The lower-level adapter's broader URL syntax does not qualify sovereign-cloud or cross-cloud authentication, Fabric networking or regional compatibility; that would require separate implementation and validation.

## Select the data and readers explicitly

| Input | Selection rule | Validation required |
| --- | --- | --- |
| Reader Entra object IDs | Explicit immutable IDs for the approved cohort | Each maps to an enabled human Dataverse user with Read-Write or Read access mode; exclude the privileged operator |
| Reader UPN/display name | Review label or login hint | Resolve against current identity evidence; renames do not change the authorization ID |
| Dataverse systemuser ID | Source identity associated with each Entra ID | Discovery/proof and actual-reader qualification use this binding; it is not the `readers` configuration value |
| Logical table names | Explicit approved table list from metadata | Validate entity set, primary key and actual Read privilege mapping; labels such as “Note” are not logical names |
| Logical scalar columns | Explicit allowlist for each selected table | Validate source types, secured/masked metadata and exact output property names; include meaningful test fields |
| Existing serving-item IDs | Empty by default; choose only app-owned, reviewed serving items | Verify workspace, ownership namespace, prior journal/receipts and independent access boundary; never adopt a raw source lakehouse by name |
| Required consumer paths | SQL, OneLake, Spark, Power BI/Direct Lake, or the client's actual subset | Qualify each selected path using real readers; SQL evidence does not qualify every other engine |

Readers do not need separate credentials for the adapter's extraction: the privileged source operator uses verified impersonation. Actual-reader acceptance does require those readers to authenticate themselves. Do not collect their passwords, put credentials in fixtures, or treat administrator-filtered SQL queries as reader tests.

The initial onboarding selection is intentionally empty. Do not turn on `discover_readers` merely to avoid choosing a cohort. A table may be empty or unreadable for a selected user; either outcome must be distinguished from a failed request. Supported lookup selections become scalar Web API properties, for example `primarycontactid` becomes `_primarycontactid_value`. File, image, party-list and complex attribute values require additional implementation and are not silently included.

## Accounts and permissions

| Identity | Where it runs | Required capability and boundary |
| --- | --- | --- |
| Interactive source/publisher operator | Client laptop, Azure CLI | Direct Dataverse impersonation privilege, required security/metadata discovery, Global Read on selected tables and qualified selected-field coverage; authorized Fabric publication rights |
| Dataverse customization installer | Approved deployment workstation or pipeline | Creates/verifies the reviewed `pw_ReadContext` customization components; consumers do not receive customization rights |
| Unattended publisher identity | Managed-identity-enabled Azure host | Dataverse application-user binding plus independently verified source and Fabric capabilities; not the laptop's interactive token cache |
| Independent watchdog identity | Separate monitored host/job | Reads and withdraws app-owned Fabric roles on the enumerated items; no Dataverse data access is needed |
| Lakehouse owner | Fabric ownership metadata | Use an identified user owner with required workspace rights for the initial SQL qualification; verify the supported owner type separately from the publishing identity |
| Consumer readers | Client-supported Fabric engines | Direct item Read using the same object ID as their native role; no raw-data or elevated workspace bypass |

Dataverse impersonation requires `prvActOnBehalfOfAnotherUser`; the effective result depends on both the operator's and reader's permissions. The adapter checks the operator's selected table/field coverage so its own restrictions do not silently reduce the intended reader result. [Microsoft impersonation documentation](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/impersonate-another-user).

Fabric OneLake security management requires powerful workspace permissions. Prefer a dedicated serving workspace; adding an identity as Member to a mixed workspace exposes unrelated items and requires that explicit scope to be understood. Source roles and Fabric workspace roles serve different purposes. Azure subscription Owner alone does not grant Dataverse or Fabric access.

For native SQL, verify UserIdentity mode and a supported actual owner. Microsoft currently states that security synchronization does not work for service-principal lakehouse ownership. A managed identity may perform publication while a separately qualified owner is retained; creation by an automated identity must not leave an unsupported ownership state. Readers also need direct item Read matching their OneLake role's principal. [SQL synchronization requirements](https://learn.microsoft.com/en-us/fabric/onelake/security/troubleshoot-onelake-security-for-sql-analytics-endpoints).

## Environment variables and secrets

The adapter takes its deployment values from typed JSON configuration. It does **not** automatically load `.env`, replace `${VARIABLE}` placeholders, or interpret arbitrary `DATAVERSE_URL`, `TENANT_ID` or `LAKEHOUSE_ID` variables. The onboarding `env.example` explains optional process settings; it is not a secret store.

| Setting | Required? | Actual behavior |
| --- | --- | --- |
| `AZURE_CONFIG_DIR` | Optional for local Azure CLI | Isolates the operator's or test reader's Azure CLI token cache; directory is sensitive and must be private |
| `POLICYWEAVER_CONFIG` | Console use only | The application console reads this configuration path; prefer explicit adapter `--config` arguments |
| `POLICYWEAVER_CONFIG_JSON` | Optional independent watchdog input | Entire secret-free configuration consumed by `policyweaver.native_watchdog`; it does not configure every CLI |
| `managed_identity_client_id` | JSON setting, not a required environment variable | User-assigned identity client ID when `authentication` is `managed_identity`; omit for an applicable system-assigned identity |
| `AZURE_CLIENT_SECRET` or reader passwords | Not used by these supported adapter authentication modes | Do not create or request them for this workflow |
| Strong-name signing key | Required only for building a new signed ReadContext DLL | Protected file supplied to the build script; do not place in client templates, logs or source control |

The current credential factory supports `azure_cli` and `managed_identity`. It does not implement a generic client-secret/certificate/`DefaultAzureCredential` fallback. An Azure managed identity is available from its configured Azure host; selecting that mode on a normal laptop does not create one.

The expected operator UPN/object ID is checked by onboarding discovery, not persistently enforced by the adapter runtime. Runtime Azure CLI credentials are tenant-bound. The generated plan records `operator_binding_scope` to make that limit explicit. Use an isolated operator `AZURE_CONFIG_DIR`, verify the active account before operations and keep consumer test logins in separate caches. Repeat scoped discovery when the account/binding is uncertain; never assume `plan.operator` restricts a later process automatically.

Configuration, inventory and plans contain identities and administrative topology. Prepared generations additionally contain business records and reader-specific field values. Protect the entire client directory with operating-system access controls and encrypted storage. Ignore rules prevent accidental commits but do not encrypt files. Never include token dumps, `.azure` caches, connection strings with secrets, `.snk` files or prepared Delta files in support packets or repository commits.

## Runtime choices that require evidence

| Choice | New-client starting point | Evidence before widening it |
| --- | --- | --- |
| Identity proof | `fetchxml` until the selected path is qualified | Readers with business Read and no `prvReadUser` need the verified signed `pw_ReadContext` API; configure the reviewed DLL hash, not an invented or historical digest |
| Role naming | `readable` | Matching publisher/watchdog version; names capped at 124 characters for SQL compatibility; manifest retains complete role provenance |
| Retention | `timed` | Manual retention is an explicit client choice that waives automatic age withdrawal; it is not a production revocation guarantee |
| Source workers | `1` | Compare parallel source results with sequential results and measure throttling before enabling 2–4 |
| Role quota | `250`, with reserved headroom | Confirm actual per-item quota and foreign-role headroom; an approved exception elsewhere is not inherited |
| Maximum readers | At most `1000` in this planner | Actual client throughput, native policy limits, shard count, materialized data size and propagation tests |
| Change deadline | Client-specified objective recorded in the deployment review | End-to-end detection, preparation, publication and engine/cache enforcement measurement, including failure containment; not an extra unsupported configuration key |

A name summarizes a reader's effective source role set; it is not a one-to-one copy of a business role. Multiple direct and team roles combine at source. Business-unit labels do not describe every access anchor. POA changes which rows are materialized for a reader; POAA and field-security profiles change the values returned for individual fields, including NULL. Those details are verified with paired source/target fixtures, not by expecting a separate native rule for every share.

## Additional inputs for unattended hosting

The local discovery and preparation flow does not require an Azure resource group. Cloud deployment separately needs the client's subscription ID, resource group, region, registry/image digest, managed identities, permitted networking, protected durable state, deployment owner and alert destination. Obtain those when hosting is in scope. Do not infer them from the CLI's default subscription.

The repository includes an independent watchdog deployment template. Before the first timed publication, deploy and monitor that watchdog with the exact scope, compatible version, qualified identity permissions and working withdrawal behavior. An inspect-only or unscheduled job supplies no automatic expiry protection. The repository does not supply a complete production publisher service with a distributed lease, automatic boundary inspector, complete security delta collector or customer-specific incident controls. Review [the watchdog deployment](../deploy/README.md) and [security qualification](ADAPTER-SECURITY.md) before promising unattended service.
