"""Additional technical observations, classified under checklist controls; no effective access."""

from dataclasses import replace

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.iam.policy import parse_policy
from offline_analyzer.rules.configuration import Rule, Verdict
from offline_analyzer.rules.context import EvaluationContext
from offline_analyzer.rules.methodology_links import LINKS


def role_wildcard(obs: Normalized, context: EvaluationContext) -> Verdict:
    inventory = context.iam.inventory
    role = inventory.roles.get((obs.account_id, (obs.native_id or "").rsplit("/", 1)[-1]))
    if role is None:
        return Verdict(Outcome.UNKNOWN, "Role identity unresolved.", ("role ARN",))
    if role.instance_profiles:
        return Verdict(
            Outcome.NOT_APPLICABLE,
            "Instance-profile role is evaluated by R1-IAM-INSTANCE-ROLE-PRIVILEGE.",
        )
    documents, missing = inventory.identity_documents(role)
    matches = [
        s
        for d in documents
        for s in d.statements
        if s.effect == "Allow" and s.actions and {"*", "*:*"} & set(s.actions) and not s.unsupported
    ]
    related = set(role.observations)
    for arn in role.attached or ():
        policy = inventory.policies.get(arn)
        if policy:
            related.update(policy.observations)
    if matches:
        conditions = any(s.conditions for s in matches)
        return Verdict(
            Outcome.FAIL,
            "Resolved role identity policy contains Allow Action:*"
            + (" with conditions." if conditions else "."),
            related=tuple(sorted(related)),
            finding_class="POTENTIAL_EXPOSURE",
            severity="MEDIUM",
            exposure="Broad policy pattern observed; effective permissions and exploitation "
            "are not established. Boundaries, explicit denies, SCP/RCP and request "
            "context can restrict permissions.",
            evidence_needed=tuple(
                sorted(
                    set(missing)
                    | {
                        "Validate intended workload actions and resource scope",
                        "Validate applicable boundary, SCP/RCP, explicit denies "
                        "and request context",
                    }
                )
            ),
            limitations=(
                "No effective-access or privilege-escalation conclusion from Allow alone",
            ),
        )
    if missing or any(d.unsupported or any(s.unsupported for s in d.statements) for d in documents):
        return Verdict(
            Outcome.UNKNOWN,
            "Role identity policy set incomplete or unsupported.",
            tuple(missing) or ("supported policy documents",),
        )
    return Verdict(
        Outcome.PASS,
        "Resolved role policies contain no Allow Action:* pattern.",
        limitations=("Pattern-level result; least privilege is not established",),
    )


def kms_wildcard(obs: Normalized) -> Verdict:
    raw = obs.configuration.get("PolicyDocument")
    if not isinstance(raw, dict):
        return Verdict(Outcome.UNKNOWN, "Key policy unresolved.", ("kms:GetKeyPolicy",))
    document = parse_policy(raw, "collected KMS key policy")
    matches = [
        s
        for s in document.statements
        if s.effect == "Allow"
        and not s.unsupported
        and s.principals
        and "*" in s.principals.get("AWS", ())
        and not s.conditions
        and s.actions
        and any(a.lower().startswith("kms:") or a == "*" for a in s.actions)
        and s.resources == ("*",)
    ]
    if matches:
        return Verdict(
            Outcome.FAIL,
            "KMS key policy has an unconditional Allow to wildcard AWS principals "
            "for KMS actions on this key.",
            finding_class="POTENTIAL_EXPOSURE",
            severity="HIGH",
            exposure="Key-policy access-control weakness observed; cross-account use requires "
            "corresponding source permissions and supported KMS operations. Actual "
            "decryption, data classification and exploitation are not established.",
            evidence_needed=(
                "Source identity permissions and applicable explicit denies/SCP/RCP",
                "KMS grants, operation context and key state",
                "Data classification and actual use of the key",
            ),
            limitations=("Resource:* means this KMS key; it is not evidence of all-key access",),
        )
    if document.unsupported or any(s.unsupported for s in document.statements):
        return Verdict(
            Outcome.UNKNOWN,
            "Key policy contains unsupported statements.",
            ("supported KMS policy statements",),
        )
    return Verdict(
        Outcome.PASS,
        "No unconditional wildcard-principal Allow pattern observed in this key policy.",
        limitations=(
            "Narrow pattern check; key authorization and data security are not established",
        ),
    )


def trail_logging(obs: Normalized) -> Verdict:
    logging = obs.configuration.get("IsLogging")
    if not isinstance(logging, bool) or not str(obs.native_id or "").startswith("arn:"):
        return Verdict(
            Outcome.UNKNOWN,
            "Trail logging state or trail identity unresolved.",
            ("cloudtrail:GetTrailStatus for the trail ARN",),
        )
    if logging:
        return Verdict(
            Outcome.PASS,
            "CloudTrail reports this trail is logging.",
            limitations=("Delivery, selectors and log integrity are evaluated separately",),
        )
    return Verdict(
        Outcome.FAIL,
        "CloudTrail reports this trail is not logging (IsLogging=false).",
        severity="HIGH",
        exposure="API activity covered only by this trail is not being recorded; other "
        "trails or organization trails may still record it.",
        evidence_needed=("Other account or organization trails covering the same events",),
        limitations=("Per-trail result; account-wide audit coverage is not established",),
    )


def management_events(obs: Normalized) -> Verdict:
    basic = obs.configuration.get("EventSelectors")
    advanced = obs.configuration.get("AdvancedEventSelectors")
    if basic is None and advanced is None:
        return Verdict(
            Outcome.UNKNOWN, "Event selectors unresolved.", ("cloudtrail:GetEventSelectors",)
        )
    captured = any(
        isinstance(item, dict)
        and item.get("IncludeManagementEvents") is True
        and item.get("ReadWriteType") in {"All", "WriteOnly"}
        for item in basic or []
    )
    for selector in advanced or []:
        fields = selector.get("FieldSelectors") if isinstance(selector, dict) else None
        for field in fields or []:
            if field.get("Field") == "eventCategory" and "Management" in (
                field.get("Equals") or []
            ):
                captured = True
    if captured:
        return Verdict(
            Outcome.PASS,
            "Trail selectors capture management write events.",
            limitations=("Selector review only; exclusions inside advanced selectors not proven",),
        )
    if advanced:
        return Verdict(
            Outcome.UNKNOWN,
            "Advanced event selectors present without a recognized management-event selector.",
            ("Analyst review of advanced event selectors",),
        )
    return Verdict(
        Outcome.FAIL,
        "Trail event selectors do not capture management write events.",
        severity="MEDIUM",
        exposure="Control-plane changes recorded only through this trail are not captured.",
        evidence_needed=("Other account or organization trails capturing management events",),
        limitations=("Per-trail result; account-wide audit coverage is not established",),
    )


def guardduty_enabled(obs: Normalized, context: EvaluationContext) -> Verdict:
    detectors = obs.configuration.get("DetectorIds")
    if not isinstance(detectors, list):
        return Verdict(Outcome.UNKNOWN, "Detector list unresolved.", ("guardduty:ListDetectors",))
    if not detectors:
        return Verdict(
            Outcome.FAIL,
            "No GuardDuty detector exists in this account and Region.",
            severity="MEDIUM",
            exposure="Threat-detection findings are not generated for this Region.",
            evidence_needed=("Delegated-administrator or organization-wide GuardDuty evidence",),
            limitations=("Regional result; other Regions are evaluated separately",),
        )
    detector_items = context.by_account("AWS::GuardDuty::Detector", obs.region, obs.account_id)
    states = {item.native_id: item.configuration.get("Status") for item in detector_items}
    expected = {f"{obs.account_id}:{obs.region}:detector/{d}" for d in detectors}
    # Expected names carry this account, so only this account's detectors can match.
    related = tuple(sorted(i.observation_id for i in detector_items if i.native_id in expected))
    if any(states.get(name) == "ENABLED" for name in expected):
        return Verdict(Outcome.PASS, "A GuardDuty detector is ENABLED.", related=related)
    if expected - states.keys():
        return Verdict(
            Outcome.UNKNOWN,
            "Detector exists but its status was not collected.",
            ("guardduty:GetDetector",),
            related=related,
        )
    return Verdict(
        Outcome.FAIL,
        "GuardDuty detectors exist but none is ENABLED.",
        related=related,
        severity="MEDIUM",
        exposure="Threat-detection findings are not generated for this Region.",
        limitations=("Regional result; other Regions are evaluated separately",),
    )


def config_recording(obs: Normalized) -> Verdict:
    recorders = obs.configuration.get("ConfigurationRecordersStatus")
    if not isinstance(recorders, list):
        return Verdict(
            Outcome.UNKNOWN,
            "Recorder status unresolved.",
            ("config:DescribeConfigurationRecorderStatus",),
        )
    if not recorders:
        return Verdict(
            Outcome.FAIL,
            "No AWS Config configuration recorder exists in this account and Region.",
            severity="MEDIUM",
            exposure="Resource configuration history and Config rules are unavailable here.",
            limitations=("Regional result; recorded resource types are not evaluated",),
        )
    if any(r.get("recording") is True and r.get("lastStatus") != "FAILURE" for r in recorders):
        return Verdict(
            Outcome.PASS,
            "An AWS Config recorder is recording.",
            limitations=("Recorded resource scope and delivery channel are not evaluated",),
        )
    return Verdict(
        Outcome.FAIL,
        "AWS Config recorders exist but none is recording successfully.",
        severity="MEDIUM",
        exposure="Resource configuration history and Config rules are unavailable here.",
    )


def securityhub_enabled(obs: Normalized) -> Verdict:
    if obs.configuration.get("Enabled") is False:
        return Verdict(
            Outcome.FAIL,
            "Security Hub is not enabled in this account and Region (InvalidAccessException).",
            severity="INFO",
            exposure="Aggregated security findings and standards checks are unavailable here.",
            limitations=("Regional result; cross-Region aggregation is not evaluated",),
        )
    if obs.configuration.get("HubArn"):
        return Verdict(Outcome.PASS, "Security Hub is enabled.")
    return Verdict(Outcome.UNKNOWN, "Hub state unresolved.", ("securityhub:DescribeHub",))


def kms_rotation(obs: Normalized, context: EvaluationContext) -> Verdict:
    metadata = obs.configuration.get("KeyMetadata")
    if not isinstance(metadata, dict):
        return Verdict(Outcome.UNKNOWN, "Key metadata unresolved.", ("kms:DescribeKey",))
    if (
        metadata.get("KeyManager") != "CUSTOMER"
        or metadata.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT"
        or metadata.get("Origin") != "AWS_KMS"
        or metadata.get("KeyState") != "Enabled"
    ):
        return Verdict(
            Outcome.NOT_APPLICABLE,
            "Automatic rotation applies only to enabled customer-managed symmetric AWS_KMS keys.",
        )
    rotation = context.by_native("AWS::KMS::KeyRotation", obs.region, obs.native_id)
    if not rotation:
        return Verdict(
            Outcome.UNKNOWN, "Rotation status not collected.", ("kms:GetKeyRotationStatus",)
        )
    enabled = {item.configuration.get("KeyRotationEnabled") for item in rotation}
    related = tuple(sorted(item.observation_id for item in rotation))
    if enabled == {True}:
        return Verdict(Outcome.PASS, "Automatic key rotation is enabled.", related=related)
    if enabled == {False}:
        return Verdict(
            Outcome.FAIL,
            "Automatic rotation is disabled for this customer-managed key.",
            related=related,
            severity="LOW",
            exposure="Key material is not rotated automatically; impact depends on key use.",
            evidence_needed=("Documented manual rotation or approved exception",),
        )
    return Verdict(Outcome.UNKNOWN, "Rotation status inconsistent.", related=related)


def latent_ingress(obs: Normalized, context: EvaluationContext) -> Verdict:
    from offline_analyzer.rules.network import classify, interface_facts

    group_id = obs.configuration.get("GroupId")
    permissions = obs.configuration.get("IpPermissions")
    if not isinstance(group_id, str) or not isinstance(permissions, list):
        return Verdict(Outcome.UNKNOWN, "Security group ingress unresolved.", ("IpPermissions",))
    found = classify(permissions)
    if found is None:
        return Verdict(
            Outcome.UNKNOWN,
            "An ingress permission has an unrecognized protocol, port range or source.",
            ("well-formed IpPermissions",),
        )
    open_ports = sorted(set(found["v4"]) | set(found["v6"]))
    if not open_ports:
        return Verdict(Outcome.PASS, "No sensitive port is open to 0.0.0.0/0 or ::/0.")
    from offline_analyzer.rules.network import ENI_OPERATION

    interfaces = context.interfaces_for_group(obs.region, group_id)
    facts = [interface_facts(i) for i in interfaces]
    # Any in-use public interface, including service-managed ones, is an exposure question
    # that R1-EC2-SG-SENSITIVE-INGRESS evaluates or sends to analyst validation.
    if any(f["in_use"] and (f["public_v4"] or f["ipv6"]) for f in facts):
        return Verdict(
            Outcome.NOT_APPLICABLE,
            "An in-use public interface uses this group; R1-EC2-SG-SENSITIVE-INGRESS "
            "evaluates that exposure.",
        )
    complete = context.coverage(ENI_OPERATION, obs.account_id, obs.region) == "COMPLETE"
    attachment = (
        "no in-use public interface used it at collection time."
        if complete
        else "interface attachment is unknown because the network-interface inventory for "
        "this account and Region is incomplete."
    )
    return Verdict(
        Outcome.FAIL,
        "Security group permits "
        + ", ".join(open_ports)
        + " from the internet (0.0.0.0/0 or ::/0); "
        + attachment,
        related=tuple(sorted(i.observation_id for i in interfaces)),
        finding_class="BASELINE_DEVIATION",
        severity="MEDIUM",
        exposure="Latent exposure: attaching this group to a public instance or interface "
        "would expose the listed services immediately. Current reachability is not established.",
        evidence_needed=(
            "Intended use of the rule and attachment plans",
            "Complete network-interface inventory for the Region",
        ),
        limitations=(
            "Configuration deviation only; R1-EC2-SG-SENSITIVE-INGRESS remains the "
            "reachability evaluation",
        ),
    )


FOLLOW_UP = ("Additional observation outside the approved methodology; analyst review required",)
SERVICE_RULES = (
    Rule(
        "SEC-EC2-SG-LATENT-EXPOSURE",
        "1.0.0",
        "AWS::EC2::SecurityGroup",
        "ec2:DescribeSecurityGroups",
        "Security group allows sensitive ports from the internet (latent exposure)",
        "Network and exposure",
        ("security group ingress", "network interface attachments"),
        latent_ingress,
        "A rule opening administrative or database ports to the internet becomes an active "
        "exposure as soon as the group is attached to a public resource.",
        "Remove internet-wide sources for sensitive ports; use approved CIDRs, prefix lists, "
        "Session Manager or a bastion.",
        "MEDIUM",
        "Configuration deviation without observed reachability.",
        follow_up=FOLLOW_UP,
        contextual=True,
        family_gated=True,
        context_operations=("ec2:DescribeNetworkInterfaces",),
    ),
    Rule(
        "SEC-CLOUDTRAIL-LOGGING",
        "1.0.0",
        "AWS::CloudTrail::TrailStatus",
        "cloudtrail:GetTrailStatus",
        "CloudTrail trail is not logging",
        "Logging and monitoring",
        ("trail status",),
        trail_logging,
        "A stopped trail does not record API activity it covers, removing audit evidence "
        "for investigations unless another trail records the same events.",
        "Start logging on the trail, or document the trail that supersedes it.",
        "HIGH",
        "Loss of audit evidence for covered API activity.",
        follow_up=FOLLOW_UP,
        family_gated=True,
    ),
    Rule(
        "SEC-CLOUDTRAIL-MANAGEMENT-EVENTS",
        "1.0.0",
        "AWS::CloudTrail::EventSelectors",
        "cloudtrail:GetEventSelectors",
        "CloudTrail trail does not capture management events",
        "Logging and monitoring",
        ("trail event selectors",),
        management_events,
        "Without management write events, control-plane changes covered by this trail are "
        "not recorded.",
        "Include management write events, or document the trail that records them.",
        "MEDIUM",
        "Partial audit coverage for control-plane changes.",
        follow_up=FOLLOW_UP,
        family_gated=True,
    ),
    Rule(
        "SEC-GUARDDUTY-ENABLED",
        "1.0.0",
        "AWS::GuardDuty::RegionalStatus",
        "guardduty:ListDetectors",
        "GuardDuty is not enabled in the Region",
        "Threat detection",
        ("detector list", "detector status"),
        guardduty_enabled,
        "Without an enabled detector, GuardDuty threat findings are not produced for the Region.",
        "Enable GuardDuty, preferably organization-wide through a delegated administrator.",
        "MEDIUM",
        "Reduced threat-detection coverage; compromise is not established.",
        follow_up=FOLLOW_UP,
        contextual=True,
        family_gated=True,
        context_operations=("guardduty:GetDetector",),
    ),
    Rule(
        "SEC-CONFIG-RECORDING",
        "1.0.0",
        "AWS::Config::RegionalStatus",
        "config:DescribeConfigurationRecorderStatus",
        "AWS Config is not recording in the Region",
        "Logging and monitoring",
        ("configuration recorder status",),
        config_recording,
        "Without a recording configuration recorder, configuration history and Config "
        "rule evaluations are unavailable for the Region.",
        "Enable a configuration recorder with a delivery channel, ideally organization-wide.",
        "MEDIUM",
        "Reduced configuration-governance evidence; misconfiguration is not established.",
        follow_up=FOLLOW_UP,
        family_gated=True,
    ),
    Rule(
        "SEC-SECURITYHUB-ENABLED",
        "1.0.0",
        "AWS::SecurityHub::RegionalStatus",
        "securityhub:DescribeHub",
        "Security Hub is not enabled in the Region",
        "Threat detection",
        ("hub subscription state",),
        securityhub_enabled,
        "Without Security Hub, aggregated findings and standards checks are unavailable for "
        "the Region.",
        "Enable Security Hub through the organization's delegated administrator.",
        "INFO",
        "Visibility observation, not a weakness; individual services may still produce findings.",
        follow_up=FOLLOW_UP,
        family_gated=True,
    ),
    Rule(
        "SEC-KMS-ROTATION",
        "1.0.0",
        "AWS::KMS::Key",
        "kms:DescribeKey",
        "Customer-managed KMS key rotation is disabled",
        "Data protection",
        ("key metadata", "rotation status"),
        kms_rotation,
        "Without rotation, the same key material protects data indefinitely; impact depends "
        "on key use and compensating controls.",
        "Enable automatic rotation or document an approved manual rotation process.",
        "LOW",
        "Cryptographic hygiene deviation; data exposure is not established.",
        follow_up=FOLLOW_UP,
        contextual=True,
        family_gated=True,
        context_operations=("kms:GetKeyRotationStatus",),
    ),
)


ADDITIONAL_RULES = (
    Rule(
        "SEC-IAM-ROLE-WILDCARD",
        "1.0.0",
        "AWS::IAM::Role",
        "iam:GetAccountAuthorizationDetails",
        "Role policy contains broad wildcard actions",
        "Identity and access",
        ("resolved identity policies",),
        role_wildcard,
        "A broad action pattern increases the permissions requiring justification. Impact "
        "depends on allowed resources, conditions, boundaries and applicable denies; neither "
        "effective administration nor escalation is established.",
        "Replace wildcard actions with verified workload actions after a tested policy rollout.",
        "MEDIUM",
        "Broad policy scope warrants review; effective privileges remain conditional.",
        follow_up=(
            "Additional observation outside the approved methodology; analyst review required",
        ),
        scope="GLOBAL",
        contextual=True,
        family_gated=True,
        context_operations=(
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:GetRolePolicy",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
        ),
        finding_class="POTENTIAL_EXPOSURE",
    ),
    Rule(
        "SEC-KMS-WILDCARD-PRINCIPAL",
        "1.0.0",
        "AWS::KMS::Key",
        "kms:GetKeyPolicy",
        "KMS key policy permits unconditional wildcard principals",
        "Data protection",
        ("resolved key policy",),
        kms_wildcard,
        "An unrestricted key-policy principal can enable unintended KMS use when the caller "
        "has corresponding permissions. Supported operations, applicable denies, key state "
        "and data classification remain validation dependencies.",
        "Scope key-policy principals and operations to verified consumers; retain tested "
        "key administration and recovery access.",
        "HIGH",
        "Unrestricted principal configuration; decryption and sensitive-data exposure unverified.",
        follow_up=(
            "Additional observation outside the approved methodology; analyst review required",
        ),
        family_gated=True,
        context_operations=("kms:ListGrants",),
        finding_class="POTENTIAL_EXPOSURE",
    ),
) + SERVICE_RULES

# 1.1.0: every additional observation is classified under a checklist control (proposed
# check-area mapping; never control-level coverage).
CLASSIFIED = ("Classified under a checklist control (proposed mapping); analyst review required",)
ADDITIONAL_RULES = tuple(
    replace(
        rule,
        # 1.2.0 for SEC-IAM-ROLE-WILDCARD: role-class and organization-control context
        # (rules/aws_identity.py); predicate unchanged.
        version="1.2.0" if rule.rule_id == "SEC-IAM-ROLE-WILDCARD" else "1.1.0",
        methodology=LINKS[rule.rule_id],
        follow_up=CLASSIFIED,
    )
    for rule in ADDITIONAL_RULES
)
SERVICE_RULES = tuple(
    r for r in ADDITIONAL_RULES if r.rule_id in {s.rule_id for s in SERVICE_RULES}
)
