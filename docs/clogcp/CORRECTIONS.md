# GCP correction scope and remaining limitations

The authoritative baseline is the existing validated CloSec ZIP, source revision
5a90bdf2ce9147f678ed3dd4b5c3ec34efeceb1e, not unrelated unpublished source changes.
This source snapshot is independently modified and uncommitted. Its base checksum
is recorded in VERSION metadata. No real customer assessment was run or reconciled.

Registry: 48 existing GCP criteria plus 29 additional criteria, 77 total. These are
criteria, not 77 complete compliance controls. RULE_INVENTORY identifies every rule
and version; DATASET_RULE_MATRIX accounts for all 118 catalog entries, including
context consumers and unsupported/review-only families. The collector's original
23 EVALUATED / 95 NORMALIZED declarations are preserved; they are not a claim of
actual criterion coverage. Run-specific assurance reports show actual executions,
outcomes, source collection states and findings per project/family.

## Corrected interpretation

- Documented Google APIs service agent Editor on its own project is qualified as an
  expected platform grant. Default Compute/App Engine and legacy Cloud Build workload
  identities do not receive this exception. Unusual agent roles, scopes and credential
  grants remain assessable. Unknown project ownership stays unknown.
- Deleted or malformed principals do not become active excessive-privilege findings.
  Conditional grants, custom-role definitions, federation providers and project-number
  aliases retain effective-authorization limits. Collected disabled parent federation
  pools make active trust criteria inapplicable; conflicting or partial pool snapshots
  remain unknown. Service Account User means attachment
  authority; it is not proof of token creation or an executable escalation path.
- Firewall correlation requires explicit network references and matching targets.
  Running external-IP instances raise configuration exposure context; stopped/unknown
  instances remain latent configuration observations. Same-policy broad deny priority
  is considered; hierarchy, listeners and routing are not invented.
- Instance metadata overrides collected project metadata. Windows SSH applicability
  differs. Missing metadata is not a secure default. Sparse list and rich detail can
  coexist; contradictory decisive snapshots remain unknown.
- Storage public grants respect collected effective PAP, including v2 boolean fields.
  Consistent list/detail records do not create false conflicts. Soft delete is recognized
  as a recovery control without asserting that it satisfies the client's recovery policy.
- Run v1/v2 identity and ingress, disabled invoker IAM checks and project/resource IAM
  are evaluated. Function generation determines the invocation role and underlying Run
  relationship. Internal ingress qualifies public grants. Equivalent time-aligned CAI
  policy observations can support native findings without duplicating them.
- BigQuery metadata roles are not treated as table-data readers. Custom roles require
  observed permission definitions. Explicit SQL engine flags are interpreted by engine;
  unset flags do not imply insecure defaults. SSL policy findings require an observed
  proxy attachment and external forwarding reference.
- Autopilot applicability is specific to the setting; it does not imply private nodes.
  Missing/partial source evidence cannot produce PASS, including supporting evidence.
  Malformed field types produce uncertainty instead of crashes or fabricated findings.

## Additional criteria

GKE: legacy ABAC, node privacy/identity, Shielded Nodes, client certificates, endpoint
restriction, workload identity, network-policy configuration and secrets-encryption review.
Serverless: public invocation and privileged runtime identity for Run and Functions.
Data: BigQuery public data grants and explicit Cloud SQL database flags.
Network/edge: firewall-policy sensitive ingress, attached TLS policy, backend logging,
Cloud Armor review and public-zone DNSSEC.
Governance/detection: effective boolean guardrails, inherited audit coverage review,
disabled alert policies, shared-issuer federation and sensitive public custom roles.
Other collected families: secret lifecycle, artifact tag immutability, build approval
and Pub/Sub push authentication are explicit review criteria where intent or external
controls cannot be established. They do not manufacture vulnerabilities from defaults.

## Unsupported or incomplete effective-control analysis

The matrix is the complete family-by-family register. Remaining scenarios include full
IAM deny/PAB/condition evaluation, arbitrary predefined-role permission expansion,
transitive effective authorization, complete hierarchical firewall/route/peering policy
simulation, packet reachability and listeners, workload/application authorization,
Kubernetes workload/network-policy contents, approved disk/snapshot encryption and
retention requirements, secret payload lifecycle, key-consumer availability, full sink
routing/filter semantics, detection catalog/alert delivery, SCC entitlement and semantic
SCC-to-native equivalence without a recorded canonical relationship. Existing SCC
observations retain source provenance; cross-tool equivalence is not guessed.

New checks do not infer asset relationships or new attack paths. Unsupported families
are visible in the assurance workbook and are never counted as passing. Review-only
criteria and the limitations above remain mandatory assessor work. No claim of complete
GCP security coverage, exploit verification or production validation is made.

## Primary technical references

- https://docs.cloud.google.com/iam/docs/service-agents
- https://docs.cloud.google.com/iam/docs/service-account-types
- https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services
- https://docs.cloud.google.com/run/docs/securing/ingress
- https://docs.cloud.google.com/functions/docs/concepts/iam
- https://docs.cloud.google.com/functions/docs/reference/iam/roles
- https://docs.cloud.google.com/kubernetes-engine/docs/concepts/autopilot-security
- https://docs.cloud.google.com/kubernetes-engine/docs/concepts/network-isolation
- https://docs.cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster
- https://docs.cloud.google.com/bigquery/docs/access-control-basic-roles
- https://docs.cloud.google.com/compute/docs/oslogin/set-up-oslogin
- https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console
- https://docs.cloud.google.com/load-balancing/docs/ssl-policies-concepts
- https://docs.cloud.google.com/load-balancing/docs/use-ssl-policies
- https://docs.cloud.google.com/sql/docs/sqlserver/configure-ssl-instance
- https://docs.cloud.google.com/storage/docs/soft-delete
- https://docs.cloud.google.com/secret-manager/docs/secret-rotation
- https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines

Supplementary scripts were inspected as rule specifications, never executed as cloud
collection and never imported as findings. The methodology mapping specifications and
rule IDs of existing controls are preserved. New criteria remain unmapped observations.
