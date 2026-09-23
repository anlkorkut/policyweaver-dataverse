# Migrate from the earlier dvaccess repository

The initial repository revision, [94cbc148](https://github.com/anlkorkut/policyweaver-dataverse/tree/94cbc148d71ad805d3ba0c3d5391f898e22b7845), contains `dvaccess 0.1.0`. It compiled selected Dataverse security topology into static OneLake access profiles. The current `policyweaver 0.3.1` application instead materializes Dataverse's effective Read results per reader, including Basic ownership, POA and record-specific field-security outcomes.

This is a product and configuration migration. The old source remains in Git history. Its `dvaccess` CLI, YAML settings, snapshots, profile hashes, group reconciliation and generated policies are not inputs to the new adapter. Do not rename an old configuration file to make it appear compatible.

## Establish the new deployment separately

1. Preserve the old deployment configuration, controller inventory, role receipts and rollback evidence in the client's private operational storage. Record which process manages each existing Fabric item. Updating Git does not change any deployed permissions or stop an old job.
2. Clone the current revision into a new directory and bootstrap a new virtual environment. Invoke `$policyweaver-dataverse` and follow [client onboarding](CLIENT-ONBOARDING.md). Use the new typed intake and selections; discover the client's current IDs. The installed operational commands are `policyweaver-onboard` and `policyweaver-adapter`. The separate `policyweaver` command is the legacy shadow/inventory interface within this application and cannot publish native authorization.
3. Create new private serving items with a new deployment namespace and their own configuration, state and creation receipts. Do not point the new publisher at the old raw/source lakehouse or copy old role prefixes. Current provisioning refuses name-only adoption and unrelated existing policies.
4. Qualify selected readers and tables across every required engine. Compare Basic/BU/team/POA access and field-profile/POAA values against current Dataverse results, including denied controls and measured revocations. Configure the independent compatible watchdog before timed consumer publication.

## Cut over only after qualification

Document the exact consumer connections and old access paths to retire. Within the client's approved scope, move consumers to the qualified serving items and remove the identified old bypasses. Stop the old controller before retiring the policies it owns so it cannot recreate them. Preserve the old controller's configuration and audit receipts; do not erase journals or indiscriminately clear a lakehouse's roles.

The new publisher only manages its own namespace and verified scope. It does not automatically uninstall the old product, delete old Entra groups, remove old raw-data access, or reconfigure existing Power BI reports. Those are explicit cutover tasks, with client-specific review and evidence.

The new read model still needs source impersonation/field coverage, qualified identity proof, supported scalar selections and a reviewed Fabric boundary. Moving from the old compiler does not establish full-estate throughput or eliminate native policy-API outage and propagation limitations. See [security requirements](ADAPTER-SECURITY.md).
