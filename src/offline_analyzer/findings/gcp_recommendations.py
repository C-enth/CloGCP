"""Offline GCP guidance. Template selection never approves a recommendation."""

from offline_analyzer.findings.recommendations import Recommendation
from offline_analyzer.rules.gcp import BY_ID

GUIDANCE = {
    "API": (
        (
            "Identify each consumer and its browser referrers, source IPs or "
            "application identity. Apply one compatible application restriction "
            "category and explicit apiTargets; test all authorized consumers before "
            "enforcement."
        ),
        (
            "Review usage and billing with the authorized owner. Restrict unused APIs"
            " while validating application dependencies; do not assume a key has "
            "leaked."
        ),
        (
            "Restriction changes can break Maps, mobile and server clients. Use "
            "separate keys for distinct client types and environments; coordinate "
            "quotas and canary rollout."
        ),
        (
            "Recollect key metadata; verify nonempty allowed application values and "
            "intended API targets. Have the owner test authorized and unauthorized "
            "use without exporting key strings."
        ),
        "api-keys/docs/add-restrictions-api-keys",
    ),
    "KEY": (
        (
            "Identify the workload using the key, replace static credentials with "
            "attached service accounts or workload identity federation, and remove "
            "obsolete keys only after successful cutover. For privileged identities "
            "also replace basic roles with narrow permissions."
        ),
        (
            "Reduce unnecessary role bindings and limit credential distribution. If "
            "compromise is independently suspected, use the customer's "
            "incident-response process for controlled revocation."
        ),
        (
            "Key rotation or disabling may stop workloads. Preserve rollback options,"
            " inventory external consumers, and obtain a validated owner-approved "
            "cutover plan."
        ),
        (
            "Recollect user-managed key metadata and IAM policies. Verify migrated "
            "consumers authenticate successfully, obsolete keys are disabled/deleted,"
            " and remaining key ages meet the approved threshold."
        ),
        "iam/docs/best-practices-for-managing-service-account-keys",
    ),
    "IAM": (
        (
            "Review the exact role, principals, policy subject and conditions. "
            "Replace broad basic or impersonation bindings with task-specific roles "
            "on the smallest intended scope. Review public sharing and cross-project "
            "dependency ownership with application owners."
        ),
        (
            "Remove unused grants after dependency validation; prioritize privileged "
            "identities with persistent credentials. Collect inherited allow, deny "
            "and boundary policies before claiming effective-access restrictions."
        ),
        (
            "Changing group, domain, project-level or impersonation bindings can "
            "break deployment, automation and federation. Validate authorized "
            "principals and inherited policies before rollout."
        ),
        (
            "Recollect project/resource and parent IAM policies, custom roles, "
            "conditions, deny policies and boundaries. Have an authorized owner "
            "validate intended access and denial; static allow bindings alone do not "
            "establish effective permissions."
        ),
        "iam/docs/roles-overview",
    ),
    "GOV": (
        (
            "Evaluate keyless workload readiness, establish approved exceptions, then"
            " enforce the applicable effective service-account key creation or upload"
            " constraint at the authorized scope."
        ),
        (
            "Limit unnecessary key creation permissions while assessing inherited "
            "organization policies. Do not change organization-wide policies from a "
            "project-only assessment."
        ),
        (
            "Legacy integrations may require migration before enforcement. Existing "
            "keys are not removed by a creation restriction; review them separately."
        ),
        (
            "Recollect the effective constraint at the project and relevant parents. "
            "Verify enforcement and approved exceptions; validate that existing "
            "workloads continue operating."
        ),
        "iam/docs/service-account-creds",
    ),
    "LOG": (
        (
            "Review explicit audit principal exemptions and logging exclusion filters"
            " against required security events. Retain required events using verified"
            " sinks and log buckets; remove unnecessary exemptions or exclusions with"
            " owner approval."
        ),
        (
            "Preserve existing security telemetry and verify alternate sinks before "
            "changing exclusions. Inventory service defaults and inherited Data "
            "Access settings; Admin Activity defaults must not be reported as "
            "disabled."
        ),
        (
            "Increased Data Access logging can affect cost, retention and privacy "
            "requirements. Validate inherited settings and exported destinations with"
            " detection and data owners."
        ),
        (
            "Recollect IAM auditConfigs, parent policies, sinks, exclusions and "
            "bucket retention. Validate representative required events reach the "
            "intended destination and retention meets the approved policy."
        ),
        "logging/docs/audit/configure-data-access",
    ),
    "SCC": (
        (
            "Validate the detector category, affected resource, event time and state "
            "against current native evidence. Record stale or contradictory "
            "observations; select corrective action for the verified technical "
            "condition."
        ),
        (
            "Prioritize active observations supported by fresh native configuration. "
            "Do not apply detector-specific remediation before confirming its "
            "resource and prerequisites."
        ),
        (
            "SCC subscription, source visibility, detector freshness and project "
            "permissions affect observations. Detector severity is supplementary and "
            "requires independent technical and business review."
        ),
        (
            "Recollect the original SCC finding and native configuration. Verify the "
            "underlying condition is corrected and reconcile the detector update "
            "without automatically approving the finding."
        ),
        "security-command-center/docs/how-to-api-list-findings",
    ),
}


# New configuration families retain per-rule remediation and read-only field guidance.
# References are documentation links only; the offline runtime never fetches them.
CONFIG_GUIDANCE = {
    "NET": (
        "Validate network ownership, policy priority, targets and required traffic. "
        "Review hierarchical and network policies before narrowing public sources.",
        "Changes can interrupt administration, routing and workload connectivity.",
        "firewall/docs/firewalls",
    ),
    "VM": (
        "Validate instance and project metadata, attached identity grants, image support "
        "and application dependencies before applying the rule-specific change.",
        "Some changes require a stopped instance, compatible image or SSH migration. "
        "cloud-platform scope alone does not establish excessive permissions.",
        "compute/docs/instances",
    ),
    "STORAGE": (
        "Review IAM, ACL dependencies, inherited policy and recovery requirements. "
        "Apply the recommended setting after validating consumers and exceptions.",
        "Access changes can disrupt consumers; versioning affects storage cost. "
        "Review soft-delete, retention and separate backups as well.",
        "storage/docs/bucket-metadata",
    ),
    "SQL": (
        "Review private connectivity, authorized networks, client TLS support and "
        "backup objectives with the database owner before applying the specific change.",
        "Connectivity and TLS changes can interrupt database clients. Validate engine, "
        "replica role, recovery requirements and a rollback plan.",
        "sql/docs/introduction",
    ),
    "KMS": (
        "Confirm symmetric-key purpose, approved rotation policy and protected-resource "
        "dependencies; change rotation metadata without retrieving key material.",
        "Rotation does not re-encrypt existing data. Validate decrypt dependencies and "
        "key-version retention before lifecycle changes.",
        "kms/docs/key-rotation",
    ),
    "LOG": (
        "Establish the approved retention objective and scope; compare observed bucket "
        "retention and lock metadata before proposing a retention change.",
        "Retention affects storage cost and privacy. Locking retention can be irreversible; "
        "obtain the owner's retention objective before making that decision.",
        "logging/docs/buckets",
    ),
}


def template_for(rule_id: str) -> Recommendation | None:
    from offline_analyzer.rules.gcp_domains import SPECS

    if rule_id in SPECS:
        spec = SPECS[rule_id]
        return Recommendation(
            expected_posture=spec.title
            + ": applicability and required security posture reviewed with the owner.",
            recommended_action=spec.remediation,
            immediate_mitigation=spec.remediation,
            permanent_remediation=spec.remediation,
            implementation_guidance=(
                "Inspect the named resource and cited configuration before changing it. "
            )
            + spec.remediation,
            operational_considerations=(
                "Validate workload dependencies, authorized public use and rollback "
                "before applying changes."
            ),
            compensating_controls=(
                "Only documented controls supported by the collected related-resource "
                "evidence may compensate; approval remains pending."
            ),
            validation_procedure=(
                "Read-only verification: compare the cited original JSON/API fields, "
                "effective inheritance and related resources with the named criterion. "
                "Reassess a fresh snapshot after an approved change."
            ),
            references=(spec.reference,),
            version="clogcp-remediation-1.0.0",
        )
    r = BY_ID.get(rule_id)
    if not r:
        return None
    family = "IAM" if rule_id == "GCP-STORAGE-PUBLIC" else rule_id.split("-")[1]
    from offline_analyzer.rules.gcp_config import DETAIL

    if rule_id in DETAIL:
        implementation, dependencies, reference = CONFIG_GUIDANCE[family]
        mitigation = (
            "Review the observed condition and dependencies with the owner. " + r.remediation
        )
        validation = (
            "Read-only verification: "
            + DETAIL[rule_id][5]
            + ". Recollect metadata and compare the highlighted fields with the expected values. "
            "Validate the effective policy and workload requirements independently."
        )
    else:
        implementation, mitigation, dependencies, validation, reference = GUIDANCE[family]
    if rule_id == "GCP-STORAGE-PUBLIC":
        implementation = (
            "Validate the exact bucket policy, object access requirements, bucket "
            "public-access prevention setting and effective "
            "storage.publicAccessPrevention constraint. Remove unnecessary public "
            "object-role bindings, then test authorized consumers. Consider private"
            " signed access for intentional distribution."
        )
        dependencies = (
            "Public websites or distribution workflows may depend on anonymous "
            "object access. Public-access prevention can disrupt these consumers; "
            "validate the workload owner and use a staged migration."
        )
        validation = (
            "Recollect bucket IAM and public-access prevention metadata plus the "
            "effective inherited constraint. Validate intended access and anonymous"
            " denial through an authorized owner without exporting customer data."
        )
        reference = "storage/docs/public-access-prevention"
    return Recommendation(
        expected_posture=r.remediation,
        recommended_action=r.remediation,
        immediate_mitigation=mitigation,
        permanent_remediation=r.remediation,
        implementation_guidance=implementation,
        operational_considerations=dependencies,
        compensating_controls=(
            "Validate workload-specific restrictions, monitored exceptions and "
            "least-privilege identities. Compensating controls are not presumed "
            "deployed and require explicit analyst approval."
        ),
        validation_procedure=validation,
        references=("https://docs.cloud.google.com/" + reference,),
        version="gcp-remediation-1.1.0" if rule_id in DETAIL else "gcp-remediation-1.0.0",
    )
