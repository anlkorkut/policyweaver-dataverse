# Explicit manual retention

Set `"retention_mode": "manual"` in the deployment configuration **before a new preparation** to retain successfully published roles without age-based automatic withdrawal. The default remains `"timed"`. This option deliberately gives up timed propagation of Dataverse revocations: the published reader projections and permissions remain a snapshot until another generation replaces them or the roles are withdrawn. It does not start an automatic refresh process.

Keep the publisher and every independently hosted watchdog aligned on the same retention mode, tenant, workspace, deployment ownership prefix, and explicit serving-item mapping. A watchdog with the old timed configuration will still withdraw aged roles. The independent watchdog reads its own configuration, not the local generation manifest; its manual setting applies to valid owned roles in those configured items, including previously published generations. Retention is not a field embedded in Fabric's role payload.

Manual mode changes retention only. `generation_lifetime_seconds` still bounds acquisition and publication freshness; the latest publication checkpoint is `expires - publication_budget_seconds`. The adapter continues to enforce the reserve before scans, uploads and policy changes, current identity proofs, complete source reads, manifest checksums, exact destination scope, and a real access inspection no older than 15 minutes. An old or failed generation cannot be republished merely because retention is manual. A retention-mode change changes the configuration fingerprint and requires a new complete preparation.

The immutable generation manifest and durable journal summary record:

- `retention_mode`: `timed` or `manual`.
- `publication_deadline_at`: the finite source freshness deadline minus the publication reserve.
- `automatic_withdrawal_at`: the finite deadline in timed mode; `null` in manual mode.

Existing `expires` / `expires_at` values remain finite source freshness limits. They do **not** schedule age-based withdrawal for a correctly configured manual deployment. Terminal output labels source freshness and role retention separately. Timed configuration fingerprints remain compatible with earlier releases; legacy timed manifests without these additive fields remain readable.

Run the ordinary preparation, dry run, actual boundary inspection, and publication sequence with the selected configuration. No CLI switch silently edits a prepared run:

```powershell
.\scripts\Run-PolicyWeaver.ps1 -Operation Prepare -Config .\manual-demo.config.json
.\scripts\Run-PolicyWeaver.ps1 -Operation DryRun -Config .\manual-demo.config.json -Generation <GENERATION>
.\scripts\Run-PolicyWeaver.ps1 -Operation Publish -Config .\manual-demo.config.json -Generation <GENERATION> -Boundary <FRESH_VERIFIED_BOUNDARY_JSON>
```

Remove this deployment's owned roles explicitly when the test is finished:

```powershell
.\scripts\Run-PolicyWeaver.ps1 -Operation Withdraw -Config .\manual-demo.config.json
# Equivalent adapter command:
python -m policyweaver.adapter_cli --config .\manual-demo.config.json withdraw
```

Withdrawal still works after the source freshness deadline. It uses the protected managed-item registry and invalidates previously prepared generations; unrelated roles are not deliberately removed. Verify actual-reader denial separately because control-plane removal does not prove engine cache propagation.

Manual retention does not disable integrity checks or protective containment. Malformed role shape or ownership and foreign permission overlap raise critical alerts and may require operator remediation; the watchdog does not automatically delete foreign permissions. Mixed or future generations and failed or ambiguous publication retain their existing withdrawal or containment behavior. No infinite date, edited manifest, skipped access inspection, or globally disabled watchdog is required.
