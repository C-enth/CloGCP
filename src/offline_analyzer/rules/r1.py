"""R1 methodology-mapped rules. Each evaluates named source criteria only."""

import json

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.rules.configuration import Rule, Verdict
from offline_analyzer.rules.iam_trust import trust_conditions
from offline_analyzer.rules.methodology_links import LINKS
from offline_analyzer.rules.network import ENI_OPERATION, port_sources, sensitive_ingress

RDS_ENGINES = {
    "mysql",
    "postgres",
    "mariadb",
    "oracle-ee",
    "oracle-ee-cdb",
    "oracle-se2",
    "oracle-se2-cdb",
    "sqlserver-ee",
    "sqlserver-se",
    "sqlserver-ex",
    "sqlserver-web",
    "db2-ae",
    "db2-se",
    "aurora-mysql",
    "aurora-postgresql",
}
BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def hop_limit(obs: Normalized) -> Verdict:
    state = obs.configuration.get("State")
    name = state.get("Name") if isinstance(state, dict) else None
    if name == "terminated":
        return Verdict(Outcome.NOT_APPLICABLE, "Instance is terminated in the supplied snapshot.")
    if not isinstance(name, str) or name not in {
        "pending",
        "running",
        "stopping",
        "stopped",
        "shutting-down",
    }:
        return Verdict(Outcome.UNKNOWN, "Instance lifecycle state is unresolved.", ("State.Name",))
    options = obs.configuration.get("MetadataOptions")
    options = options if isinstance(options, dict) else {}
    if options.get("State") != "applied":
        return Verdict(
            Outcome.UNKNOWN,
            "Metadata options are missing or not confirmed applied.",
            ("MetadataOptions.State=applied",),
        )
    if options.get("HttpEndpoint") == "disabled":
        return Verdict(Outcome.NOT_APPLICABLE, "Metadata endpoint is disabled.")
    if options.get("HttpEndpoint") != "enabled":
        return Verdict(
            Outcome.UNKNOWN,
            "Metadata endpoint configuration is unresolved.",
            ("MetadataOptions.HttpEndpoint",),
        )
    limit = options.get("HttpPutResponseHopLimit")
    if type(limit) is not int or limit < 1:
        return Verdict(
            Outcome.UNKNOWN,
            "HttpPutResponseHopLimit is missing or not a positive integer.",
            ("MetadataOptions.HttpPutResponseHopLimit",),
        )
    if limit == 1:
        return Verdict(Outcome.PASS, "Applied metadata response hop limit is 1.")
    indicators = obs.configuration.get("ContainerIndicators") or []
    tokens = options.get("HttpTokens")
    return Verdict(
        Outcome.FAIL,
        f"Applied metadata response hop limit is {limit}; the methodology baseline is 1.",
        limitations=("A hop limit above 1 is a baseline deviation, not a credential exposure",),
        finding_class="BASELINE_DEVIATION",
        severity="LOW",
        exposure="Metadata responses can traverse one extra hop (for example into a "
        "container); "
        + ("IMDSv2 tokens are required" if tokens == "required" else "IMDSv1 is also allowed"),
        evidence_needed=("approved exception for container workloads",) if indicators else (),
        compensating=(
            f"Container orchestrator tags present ({', '.join(indicators)}): hop limit 2 may "
            "be a documented workload requirement",
        )
        if indicators
        else (),
    )


def rds_public(obs: Normalized, context) -> Verdict:
    engine = obs.configuration.get("Engine")
    if not isinstance(engine, str):
        return Verdict(Outcome.UNKNOWN, "Database engine is missing.", ("Engine",))
    if engine in {"neptune", "docdb"}:
        return Verdict(Outcome.NOT_APPLICABLE, "Engine is outside the RDS control scope.")
    if engine not in RDS_ENGINES:
        return Verdict(
            Outcome.MANUAL_VALIDATION_REQUIRED,
            "Engine is outside the reviewed applicability list.",
            ("engine applicability review",),
        )
    value = obs.configuration.get("PubliclyAccessible")
    if type(value) is not bool:
        return Verdict(
            Outcome.UNKNOWN,
            "PubliclyAccessible is missing or not a JSON boolean.",
            ("PubliclyAccessible",),
        )
    if not value:
        return Verdict(Outcome.PASS, "RDS reports PubliclyAccessible=false for this instance.")
    return public_database_exposure(obs, context)


def public_database_exposure(obs: Normalized, context) -> Verdict:
    """Source F1 holds; class/severity follow security-group and subnet-route evidence."""
    config = obs.configuration
    reasoning = "RDS reports PubliclyAccessible=true: the endpoint resolves to a public address."
    port = config.get("Port")
    groups = config.get("VpcSecurityGroups")
    needed, related, notes = [], [], []
    internet, restricted = [], []
    if type(port) is not int or not isinstance(groups, list) or not groups:
        needed.append("database port and attached security groups")
    else:
        for group in groups:
            group_id = group.get("GroupId") if isinstance(group, dict) else None
            matches = context.security_groups(obs.region, group_id) if group_id else []
            if len(matches) != 1:
                needed.append(f"security group {group_id or 'unresolved'} configuration")
                continue
            related.append(matches[0].observation_id)
            sources = port_sources(matches[0].configuration.get("IpPermissions") or [], port)
            if sources is None:
                needed.append(f"well-formed rules for security group {group_id}")
            elif sources & {"internet-v4", "internet-v6"}:
                internet.append(group_id)
            elif sources & {"public-restricted", "prefix-list"}:
                restricted.append(group_id)
    if restricted:
        notes.append(
            f"Port {port} allowed from specific public CIDRs/prefix lists via "
            f"{', '.join(restricted)}; approval of those sources not supplied"
        )
    base = dict(related=tuple(related), limitations=tuple(notes))
    later = ("NACL entries for the DB subnets", "database authentication configuration")
    if internet:
        statuses = {
            context.route_status(obs.account_id, obs.region, config.get("VpcId"), subnet)[0]
            for subnet in config.get("SubnetIds") or [None]
        }
        if "INTERNET_ROUTE" in statuses:
            return Verdict(
                Outcome.FAIL, reasoning, **base,
                # Route + open rule are necessary, not sufficient (NACLs, auth unevaluated).
                finding_class="POTENTIAL_EXPOSURE", severity="HIGH",
                exposure=f"Security group(s) {', '.join(internet)} allow port {port} from the "
                "internet and a DB subnet routes to an internet gateway; connection not "
                "demonstrated",
                evidence_needed=later,
            )  # fmt: skip
        if "ROUTE_EVIDENCE_MISSING" in statuses:
            return Verdict(
                Outcome.FAIL, reasoning, **base,
                finding_class="POTENTIAL_EXPOSURE", severity="MEDIUM",
                exposure=f"Security group(s) {', '.join(internet)} allow port {port} from the "
                "internet; DB subnet routing evidence missing",
                evidence_needed=(f"complete ec2:DescribeRouteTables for "
                                 f"{obs.account_id}/{obs.region}",) + later,
            )  # fmt: skip
        return Verdict(
            Outcome.FAIL, reasoning, **base,
            finding_class="BASELINE_DEVIATION", severity="LOW",
            exposure="Internet-sourced security-group rule present, but no DB subnet has a "
            "default route to an internet gateway",
            compensating=("DB subnet routing without internet-gateway default route",),
        )  # fmt: skip
    if needed:
        return Verdict(
            Outcome.FAIL, reasoning, **base,
            finding_class="POTENTIAL_EXPOSURE", severity="MEDIUM",
            exposure="Security-group evidence incomplete; internet reachability unknown",
            evidence_needed=tuple(needed) + later,
        )  # fmt: skip
    return Verdict(
        Outcome.FAIL, reasoning, **base,
        finding_class="BASELINE_DEVIATION", severity="LOW",
        exposure=f"Attached security groups do not admit port {port} from 0.0.0.0/0 or ::/0",
        compensating=("Restrictive security groups on the database port",),
    )  # fmt: skip


BASELINE_ONLY = dict(
    finding_class="BASELINE_DEVIATION",
    severity="MEDIUM",
    exposure="Account-wide preventive guardrail absent; no bucket is shown to be public by "
    "this setting",
    evidence_needed=(
        "bucket inventory with bucket-level Block Public Access, policy status and ACLs",
        "organization-level S3 policy evidence, if used",
    ),
)


def account_bpa(obs: Normalized) -> Verdict:
    config = obs.configuration
    if config.get("configured") is False:
        return Verdict(
            Outcome.FAIL,
            "No account-level S3 Block Public Access configuration exists "
            "(AWS returned NoSuchPublicAccessBlockConfiguration).",
            **BASELINE_ONLY,
        )
    values = {flag: config.get(flag) for flag in BPA_FLAGS}
    if config.get("configured") is not True or any(type(v) is not bool for v in values.values()):
        return Verdict(
            Outcome.UNKNOWN,
            "Account-level Block Public Access flags are missing or not JSON booleans.",
            tuple(f"PublicAccessBlockConfiguration.{flag}" for flag in BPA_FLAGS),
        )
    disabled = [flag for flag, value in values.items() if not value]
    if disabled:
        return Verdict(
            Outcome.FAIL,
            f"Account-level Block Public Access settings disabled: {', '.join(disabled)}.",
            limitations=("Bucket-level settings and policies are evaluated separately",),
            **BASELINE_ONLY,
        )
    return Verdict(
        Outcome.PASS,
        "All four account-level S3 Block Public Access settings are enabled.",
        limitations=("Bucket policies, ACLs and data classification are separate criteria",),
    )


def single(observations) -> Normalized | None | bool:
    """One observation, None if absent, False if conflicting snapshots exist."""
    if not observations:
        return None
    configs = {json.dumps(o.configuration, sort_keys=True) for o in observations}
    return observations[0] if len(configs) == 1 else False


def bpa_flag(observation, flag: str) -> bool | None:
    if not observation:
        return None
    if observation.configuration.get("configured") is False:
        return False
    value = observation.configuration.get(flag)
    return value if type(value) is bool else None


def bucket_public_access(obs: Normalized, context) -> Verdict:
    """Effective anonymous access from AWS policy status, ACL grants and both BPA levels."""
    evidence = context.resource_observations("AWS::S3::Bucket", obs.resource_id)
    bucket_bpa = single([o for o in evidence if o.operation == "s3api:GetPublicAccessBlock"])
    acl = single([o for o in evidence if o.operation == "s3api:GetBucketAcl"])
    account = single(context.account_bpa(obs.account_id))
    if False in (bucket_bpa, acl, account):
        return Verdict(
            Outcome.UNKNOWN,
            "Conflicting Block Public Access or ACL snapshots for this bucket/account.",
            ("consistent configuration snapshot",),
        )
    related = tuple(o.observation_id for o in (bucket_bpa, acl, account) if o)
    missing = []

    def effective(flag):
        values = [bpa_flag(account, flag), bpa_flag(bucket_bpa, flag)]
        if True in values:
            return True
        if None in values:
            for value, name in zip(
                values,
                ("account-level s3control:GetPublicAccessBlock",
                 "bucket-level s3api:GetPublicAccessBlock"),
                strict=True,
            ):  # fmt: skip
                if value is None:
                    missing.append(name)
            return None
        return False

    restrict, ignore = effective("RestrictPublicBuckets"), effective("IgnorePublicAcls")
    policy = obs.configuration
    policy_public = False if policy.get("configured") is False else policy.get("IsPublic")
    public = []
    if restrict is not True:
        if policy_public is True and restrict is False:
            public.append("bucket policy is public per AWS policy status")
        elif type(policy_public) is not bool:
            missing.append("s3api:GetBucketPolicyStatus.IsPublic")
    object_acls = False
    if ignore is not True:
        grants = acl.configuration.get("PublicGrants") if acl else None
        if acl is None or not isinstance(grants, list):
            missing.append("s3api:GetBucketAcl")
        elif grants and ignore is False:
            public.append(f"bucket ACL grants {', '.join(grants)}")
        elif not grants:
            object_acls = True
    if public:
        return Verdict(
            Outcome.FAIL,
            "Anonymous access is permitted: " + "; ".join(public) + ", and no Block Public "
            "Access setting at account or bucket level restricts it.",
            related=related,
            # Public policy status/ACL is a confirmed configuration, not proof of readable
            # data: the grant may cover other actions or prefixes, and objects are unseen.
            finding_class="POTENTIAL_EXPOSURE",
            severity="HIGH",
            exposure="Anonymous access is configured and unrestricted by Block Public Access; "
            "granted actions, object presence and data sensitivity not established",
            evidence_needed=("bucket policy document (granted actions and prefixes)",
                             "data classification of the bucket",
                             "S3 server/CloudTrail data access logs"),
        )  # fmt: skip
    if missing:
        return Verdict(
            Outcome.UNKNOWN,
            "Effective public access cannot be determined without the missing evidence.",
            tuple(sorted(set(missing))),
            related,
        )
    if object_acls:
        return Verdict(
            Outcome.MANUAL_VALIDATION_REQUIRED,
            "Bucket policy and ACL are not public, but IgnorePublicAcls is off at both levels: "
            "object-level ACLs could grant public read and are not assessable offline.",
            ("object ownership controls or object ACL review",),
            related,
        )
    return Verdict(
        Outcome.PASS,
        "Block Public Access settings and AWS policy status leave no anonymous access path.",
        related=related,
        limitations=("Cross-account (non-public) grants are outside this criterion",),
    )


def follow_up(*items: str) -> tuple[str, ...]:
    return items + ("Approve proposed methodology mapping and business severity context",)


R1_RULES = (
    Rule(
        "R1-EC2-SG-SENSITIVE-INGRESS",
        "1.3.0",
        "AWS::EC2::SecurityGroup",
        "ec2:DescribeSecurityGroups",
        "Security group exposes sensitive ports to the internet on a public interface",
        "Network exposure",
        ("IpPermissions", f"complete {ENI_OPERATION} for latent-exposure PASS"),
        sensitive_ingress,
        "A security group admits any IPv4 address to a management or database port on an "
        "interface with a public address. Routing is assessed where evidence exists; NACLs, "
        "host firewalls and service authentication are not, so no access or exploitation is "
        "established.",
        "Restrict ingress to approved administrative CIDRs, a bastion or SSM Session Manager; "
        "remove 0.0.0.0/0 from management/database ports and recollect configuration.",
        "HIGH",
        "Direct internet ingress to management/database ports on a public interface; "
        "service authentication and compensating network controls are unknown.",
        follow_up=follow_up(
            "Confirm interface reachability (NACL/route/host firewall) and service exposure",
            "Identify workload owner and approved access path before remediation",
        ),
        methodology=LINKS["R1-EC2-SG-SENSITIVE-INGRESS"],
        contextual=True,
        context_operations=(ENI_OPERATION, "ec2:DescribeRouteTables"),
        family_gated=True,
        finding_class="POTENTIAL_EXPOSURE",
    ),
    Rule(
        "R1-IAM-ROLE-TRUST-CONDITIONS",
        "1.3.0",
        "AWS::IAM::Role",
        "iam:GetAccountAuthorizationDetails",
        "IAM role trusts another account without binding conditions",
        "Identity and access",
        ("AssumeRolePolicyDocument", "role ARN owner account"),
        trust_conditions,
        "The trust policy lets principals in the trusted account (or any AWS account) request "
        "this role without an organization or external-ID binding. Whether any principal can "
        "actually assume it depends on caller permissions, SCPs/RCPs and boundaries that this "
        "rule does not evaluate.",
        "Add aws:PrincipalOrgID for internal accounts or sts:ExternalId for third parties, or "
        "narrow the principal; review the role's permissions and recollect configuration.",
        "HIGH",
        "Unconditioned cross-account trust removes a primary assume-role guardrail; impact "
        "depends on unevaluated role permissions.",
        follow_up=follow_up(
            "Identify the trusted account owner and business purpose",
            "Evaluate the role's permission policies and applicable SCPs/RCPs",
        ),
        methodology=LINKS["R1-IAM-ROLE-TRUST-CONDITIONS"],
        scope="GLOBAL",
        family_gated=True,
        contextual=True,
        finding_class="POTENTIAL_EXPOSURE",
    ),
    Rule(
        "R1-S3-ACCOUNT-BPA",
        "1.1.0",
        "AWS::S3::AccountPublicAccessBlock",
        "s3control:GetPublicAccessBlock",
        "Account-level S3 Block Public Access is not fully enabled",
        "Data protection",
        ("account-level PublicAccessBlockConfiguration or defined absence",),
        account_bpa,
        "Without all account-level Block Public Access settings, a bucket policy or ACL can "
        "make data public. No bucket is shown to be public by this account setting alone.",
        "Enable all four account-level Block Public Access settings after confirming no "
        "approved public bucket depends on them; recollect configuration.",
        "MEDIUM",
        "Account-wide preventive guardrail is absent; actual bucket exposure is unevaluated.",
        follow_up=follow_up("Enumerate bucket policies/ACLs for public or cross-account grants"),
        methodology=LINKS["R1-S3-ACCOUNT-BPA"],
        scope="GLOBAL",
        family_gated=True,
    ),
    Rule(
        "R1-S3-BUCKET-PUBLIC-ACCESS",
        "1.1.0",
        "AWS::S3::Bucket",
        "s3api:GetBucketPolicyStatus",
        "S3 bucket permits anonymous public access",
        "Data protection",
        ("bucket policy status", "bucket and account Block Public Access", "bucket ACL"),
        bucket_public_access,
        "Anonymous access to the bucket is configured and not restricted by Block Public "
        "Access. Data sensitivity and actual access are not established.",
        "Remove public policy statements/ACL grants or enable Block Public Access after "
        "confirming no approved public use; review the data and access logs.",
        "HIGH",
        "Effective anonymous access configuration on an S3 bucket.",
        follow_up=follow_up("Classify bucket contents and review access logs"),
        methodology=LINKS["R1-S3-BUCKET-PUBLIC-ACCESS"],
        scope="GLOBAL",
        family_gated=True,
        contextual=True,
        context_operations=(
            "s3api:GetPublicAccessBlock",
            "s3api:GetBucketAcl",
            "s3control:GetPublicAccessBlock",
        ),
        finding_class="POTENTIAL_EXPOSURE",
    ),
    Rule(
        "R1-RDS-PUBLIC-ACCESS",
        "1.2.0",
        "AWS::RDS::DBInstance",
        "rds:DescribeDBInstances",
        "RDS instance is publicly accessible",
        "Data protection",
        ("PubliclyAccessible boolean", "reviewed engine"),
        rds_public,
        "The instance endpoint resolves to a public address. Security groups and subnet "
        "routing are assessed where evidence exists; a connection is never demonstrated.",
        "Set PubliclyAccessible=false or move the instance to private subnets after "
        "confirming client connectivity; recollect configuration.",
        "MEDIUM",
        "Public endpoint configuration on a database; network reachability unknown.",
        follow_up=follow_up("Collect subnet route tables and attached security groups"),
        methodology=LINKS["R1-RDS-PUBLIC-ACCESS"],
        family_gated=True,
        contextual=True,
        context_operations=("ec2:DescribeSecurityGroups", "ec2:DescribeRouteTables"),
        finding_class="POTENTIAL_EXPOSURE",
    ),
    Rule(
        "R1-EC2-IMDS-HOP-LIMIT",
        "1.1.0",
        "AWS::EC2::Instance",
        "ec2:DescribeInstances",
        "EC2 metadata response hop limit exceeds 1",
        "Compute security",
        ("applied MetadataOptions.HttpPutResponseHopLimit",),
        hop_limit,
        "A hop limit above 1 lets metadata responses traverse an extra network hop, such as "
        "from a container. This does not establish credential access.",
        "Set HttpPutResponseHopLimit=1 where no container workload requires 2; recollect.",
        "LOW",
        "Defence-in-depth metadata setting; exploitation needs separate SSRF/container access.",
        follow_up=follow_up("Confirm whether container workloads require hop limit 2"),
        methodology=LINKS["R1-EC2-IMDS-HOP-LIMIT"],
        family_gated=True,
    ),
)
