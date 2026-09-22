# Policy Weaver Read Context plug-in

This small, stateless Dataverse plug-in returns the effective execution identity for the `pw_ReadContext` Custom API. It does not query any table, change records, grant privileges, decide record access, obtain an organization service, or write logs. This avoids requiring a reader to have `prvReadUser` merely to prove an impersonated request's execution identity.

The adapter still verifies the operator's immutable Entra-to-Dataverse reader binding, enabled supported user status, complete table Read privileges, and the source operator's required scope. The identity probe does not replace any of those checks or prove the correctness of the subsequent data request by itself.

## Contract

Register an unbound `GET` function named `pw_ReadContext`, with required `Guid` request parameter `Nonce` and these response properties:

| Property | Type | Source |
| --- | --- | --- |
| `UserId` | Guid | `IPluginExecutionContext.UserId` |
| `OrganizationId` | Guid | `IPluginExecutionContext.OrganizationId` |
| `Nonce` | Guid | Exact nonempty request nonce |
| `ProtocolVersion` | String | Constant `1` |

Example request structure, using a freshly generated UUID for each call:

```http
GET /api/data/v9.2/pw_ReadContext(Nonce=<fresh-guid>)
CallerObjectId: <verified-reader-entra-object-id>
Authorization: Bearer <operator-token>
Cache-Control: no-cache
```

The response's user must equal the expected **Dataverse systemuserid**, not the Entra object ID. The organization, nonce and protocol must also match exactly. Missing outputs, default or empty GUIDs, mismatches, errors and stale responses must fail closed. The client must not send headers that bypass business logic. Nonce matching detects stale/misrouted responses; it is not a signature or an independent code-attestation mechanism.

`UserId` is the effective execution identity. `InitiatingUserId` can differ and is never substituted or used as an equality gate. The implementation checks the exact message name and stage 30, following Microsoft's Custom API main-operation example. It does not add an undocumented `Mode`, `Depth`, or parent-context constraint. Extra optional input properties are ignored; caller-supplied `UserId` and `OrganizationId` cannot influence the result. [Custom API documentation](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/custom-api), [plug-in impersonation semantics](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/impersonate-a-user).

## Build and test locally

Use Windows with a .NET SDK and .NET Framework 4.6.2 targeting pack/runtime. The project pins `Microsoft.CrmSdk.CoreAssemblies` to **9.0.2.60** and commits dependency lock files. No extra runtime library is used by the plug-in beyond the framework and Dataverse SDK.

Provide your organization's protected private strong-name key. For isolated development, the following creates a new key without overwriting an existing key; `.policyweaver` is excluded from the repository and release package:

```powershell
$keyPath = Join-Path (Get-Location) '.policyweaver/read-context-signing.snk'
if (Test-Path -LiteralPath $keyPath) { throw 'Key already exists.' }
[System.IO.Directory]::CreateDirectory((Split-Path -Parent $keyPath)) | Out-Null
$keyPair = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
try {
    $keyPair.PersistKeyInCsp = $false
    [System.IO.File]::WriteAllBytes($keyPath, $keyPair.ExportCspBlob($true))
} finally { $keyPair.Dispose() }
& ./plugins/PolicyWeaver.ReadContext/build.ps1 -SignKeyPath $keyPath
```

For an existing protected key:

```powershell
& ./plugins/PolicyWeaver.ReadContext/build.ps1 -SignKeyPath C:/protected/your-signing-key.snk
```

The script restores locked dependencies, compiles with warnings treated as errors, runs the 22 console-harness tests and writes only the plug-in DLL plus a public manifest to `dist/read-context`. No key or SDK DLL is packaged. The manifest contains the artifact hash, strong-name public identity, protocol and fixed plug-in type `PolicyWeaver.ReadContext.ReadContextPlugin`. Strong naming identifies the assembly; review and pin its complete SHA-256 as well. A different signing key changes the artifact hash and identity, so regenerate and review the deployment plan after a rebuild with a different key.

Tests cover exact response types and values, missing/invalid inputs, invalid identity context, zero output mutation on failure, effective versus initiating identity, forged identity inputs, optional extension fields, absence of organization/tracing service requests, minimal context-property access, assembly dependencies, absence of mutable instance state, and 200 concurrent requests against one reused instance. They do not simulate Dataverse's impersonation engine or establish live deployment qualification.

## Deployment trust and live qualification

The registration tooling must verify the artifact hash and exact assembly/type identity, then verify these server properties before trusting any response:

- `PluginTypeId` identifies the reviewed main-operation type and assembly; sandbox isolation is `2` and database source type is `0`.
- `IsFunction=true`, `BindingType=Global`, `AllowedCustomProcessingStepType=None`, and no additional SDK processing steps.
- `ExecutePrivilegeName` is empty. This context-only API requires no new table privilege; Dataverse authentication and its ordinary platform checks remain in force.
- Request/response property names, types and requiredness exactly match the contract.
- Production uses a managed solution with `IsCustomizable=false` on the API and each parameter/response property. `IsPrivate` only affects discoverability; it is not access control.

Do not register an ordinary plug-in step with an elevated run-as account. The Custom API's `PluginTypeId` supplies its main-operation implementation directly. A missing plug-in can return default values, which the client must reject. Assembly content and registration are part of the trusted control plane; a nonce cannot defend against an administrator replacing that code. [Custom API deployment and main-operation guidance](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/custom-api), [Custom API table properties](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/custom-api-tables).

Before qualification, perform live read-only calls using the operator token with no impersonation header, reader A's `CallerObjectId`, reader B's `CallerObjectId`, and then reader A again. Bind every result to its known source identity, organization and fresh nonce, including a reader who has business-table Read but lacks `prvReadUser`. Repeat while switching the same client session's headers to detect stale header state. Also test that malformed, disabled and nonhuman reader identities are rejected by the adapter's binding checks. Only successful live results justify enabling the probe in a particular deployment; the artifact manifest deliberately records `live_qualified=false`. [Web API impersonation requirements and CallerObjectId](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/impersonate-another-user-web-api).

This component makes no outbound call and cannot elevate data privileges. Preserving full row/field security still depends on the authoritative Dataverse read path, trusted publication boundary, revocation lease, and live consumer acceptance tests in the main application.
