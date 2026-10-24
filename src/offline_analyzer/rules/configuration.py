"""Three provisional configuration checks, independent of source adapters."""

from collections.abc import Callable
from dataclasses import dataclass, field, replace

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.rules.methodology_links import LINKS, MethodologyLink

Answer = tuple[Outcome, str, tuple[str, ...]]


@dataclass(frozen=True)
class Verdict:
    """Rule answer that may cite related resources and add evaluation limitations."""

    outcome: Outcome
    reasoning: str
    missing: tuple[str, ...] = ()
    related: tuple[str, ...] = ()  # observation IDs of related resources used as evidence
    limitations: tuple[str, ...] = ()
    # Risk context for FAIL outcomes; None falls back to the rule defaults.
    finding_class: str | None = None
    severity: str | None = None
    exposure: str | None = None
    evidence_needed: tuple[str, ...] = ()
    compensating: tuple[str, ...] = ()


def as_verdict(answer) -> Verdict:
    return answer if isinstance(answer, Verdict) else Verdict(*answer)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    version: str
    resource_type: str
    operation: str
    title: str
    domain: str
    prerequisites: tuple[str, ...]
    evaluate: Callable[[Normalized], Answer]
    risk: str
    remediation: str
    severity: str
    severity_rationale: str
    methodology_id: str | None = None
    follow_up: tuple[str, ...] = (
        "Approve proposed methodology mapping and business severity context",
    )
    methodology: MethodologyLink | None = field(default=None, compare=False)
    scope: str = "REGIONAL"  # GLOBAL rules are evaluated once per account
    contextual: bool = False  # evaluate(observation, context) with related evidence
    context_operations: tuple[str, ...] = ()
    # Gated rules add per-scope gap rows only when their evidence family was supplied;
    # absent families are reported once per run as not supplied, never as clean.
    family_gated: bool = False
    finding_class: str = "BASELINE_DEVIATION"
    # Adds risk context to a verdict without changing the source-criterion predicate.
    annotate: Callable | None = field(default=None, compare=False)
    provider: str = "AWS"

    def applies(self, observation: Normalized) -> bool:
        return observation.resource_type == self.resource_type


def imdsv2(obs: Normalized) -> Answer:
    config = obs.configuration
    state = config.get("State")
    state = state if isinstance(state, dict) else {}
    if state.get("Name") == "terminated":
        return Outcome.NOT_APPLICABLE, "Instance is terminated in the supplied configuration.", ()
    if not isinstance(state.get("Name"), str) or state["Name"] not in {
        "pending",
        "running",
        "stopping",
        "stopped",
        "shutting-down",
    }:
        return Outcome.UNKNOWN, "Instance lifecycle state is unresolved.", ("State.Name",)
    options = config.get("MetadataOptions")
    options = options if isinstance(options, dict) else {}
    if options.get("State") != "applied":
        return (
            Outcome.UNKNOWN,
            "Metadata options are missing or not confirmed applied.",
            ("MetadataOptions.State=applied",),
        )
    if options.get("HttpEndpoint") == "disabled":
        return (
            Outcome.NOT_APPLICABLE,
            "Metadata endpoint is disabled; token enforcement is not applicable.",
            (),
        )
    if options.get("HttpEndpoint") != "enabled":
        return (
            Outcome.UNKNOWN,
            "Metadata endpoint configuration is unresolved.",
            ("MetadataOptions.HttpEndpoint",),
        )
    tokens = options.get("HttpTokens")
    if tokens == "required":
        return Outcome.PASS, "Applied metadata options require IMDSv2 tokens.", ()
    if tokens == "optional":
        return Outcome.FAIL, "Applied metadata options permit requests without IMDSv2 tokens.", ()
    return Outcome.UNKNOWN, "HttpTokens is absent or unrecognized.", ("MetadataOptions.HttpTokens",)


def instance_state_context(obs: Normalized, verdict: Verdict) -> Verdict:
    state = obs.configuration.get("State")
    name = state.get("Name") if isinstance(state, dict) else None
    if verdict.outcome != Outcome.FAIL or name == "running":
        return verdict
    return replace(
        verdict,
        exposure=f"Instance state {name} at collection; setting applies when it runs",
    )


def rds_encryption(obs: Normalized) -> Answer:
    engine = obs.configuration.get("Engine")
    if not isinstance(engine, str):
        return (
            Outcome.UNKNOWN,
            "Database engine is missing; applicability is unresolved.",
            ("Engine",),
        )
    if engine in {"neptune", "docdb"}:
        return (
            Outcome.NOT_APPLICABLE,
            "Returned database is outside this RDS-instance rule's engine scope.",
            (),
        )
    if engine.startswith("aurora"):
        return (
            Outcome.UNKNOWN,
            "Aurora requires cluster encryption evidence; instance evidence is insufficient.",
            ("rds:DescribeDBClusters.StorageEncrypted",),
        )
    if engine not in {
        "mysql",
        "postgres",
        "mariadb",
        "oracle-ee",
        "oracle-se2",
        "sqlserver-ee",
        "sqlserver-se",
        "sqlserver-ex",
        "sqlserver-web",
        "db2-ae",
        "db2-se",
    }:
        return (
            Outcome.MANUAL_VALIDATION_REQUIRED,
            "Engine is outside the reviewed applicability list.",
            ("engine applicability review",),
        )
    value = obs.configuration.get("StorageEncrypted")
    if type(value) is not bool:
        return (
            Outcome.UNKNOWN,
            "StorageEncrypted is missing or not a JSON boolean.",
            ("StorageEncrypted",),
        )
    return (
        Outcome.PASS if value else Outcome.FAIL,
        f"RDS reports StorageEncrypted={'true' if value else 'false'} for this instance.",
        (),
    )


def log_validation(obs: Normalized) -> Answer:
    home = obs.configuration.get("HomeRegion")
    if not isinstance(home, str) or not home or home != obs.region:
        return (
            Outcome.UNKNOWN,
            "Trail home Region is missing or conflicts with its ARN.",
            ("consistent HomeRegion and TrailARN",),
        )
    value = obs.configuration.get("LogFileValidationEnabled")
    if type(value) is not bool:
        return (
            Outcome.UNKNOWN,
            "LogFileValidationEnabled is missing or not a JSON boolean.",
            ("LogFileValidationEnabled",),
        )
    return (
        Outcome.PASS if value else Outcome.FAIL,
        f"Trail configuration reports LogFileValidationEnabled={'true' if value else 'false'}.",
        (),
    )


RULES = (
    Rule(
        "R0-EC2-IMDSV2",
        "1.3.0",
        "AWS::EC2::Instance",
        "ec2:DescribeInstances",
        "EC2 metadata endpoint permits IMDSv1",
        "Compute security",
        ("applied MetadataOptions", "instance identity and collection time"),
        imdsv2,
        "Token-optional metadata requests lack the additional IMDSv2 session-token requirement. "
        "This evidence does not establish SSRF, credential access or exploitation.",
        "Validate workload compatibility, then set HttpTokens=required and verify State=applied. "
        "Consider disabling the metadata endpoint where it is not needed.",
        "MEDIUM",
        "Configuration weakens metadata request protection; application exposure "
        "and IAM impact are unknown.",
        follow_up=(
            "Validate workload IMDSv2 compatibility and applied settings after change",
            "Collect application/network/IAM evidence before any exposure or exploitation claim",
            "Approve proposed methodology mapping and business severity context",
        ),
    ),
    Rule(
        "R0-RDS-ENCRYPTION",
        "1.3.0",
        "AWS::RDS::DBInstance",
        "rds:DescribeDBInstances",
        "RDS instance storage encryption is disabled",
        "Data protection",
        ("StorageEncrypted boolean", "reviewed engine", "instance identity and collection time"),
        rds_encryption,
        "The supplied instance configuration lacks RDS storage encryption. Data sensitivity, "
        "accessibility and compromise are not established by this configuration.",
        "Plan a tested migration using an encrypted snapshot copy and encrypted "
        "replacement instance; "
        "verify engine support, keys, backup/restore and cutover requirements.",
        "MEDIUM",
        "Encryption-at-rest safeguard is absent; sensitivity and business impact "
        "require analyst input.",
        follow_up=(
            "Validate engine-specific snapshot copy, encrypted restore and cutover plan",
            "Verify encryption keys/backup restore separately from this storage flag",
            "Approve proposed methodology mapping and business severity context",
        ),
    ),
    Rule(
        "R0-CLOUDTRAIL-VALIDATION",
        "1.3.0",
        "AWS::CloudTrail::Trail",
        "cloudtrail:DescribeTrails",
        "CloudTrail log-file validation is disabled",
        "Logging and monitoring",
        ("LogFileValidationEnabled boolean", "trail identity and collection time"),
        log_validation,
        "CloudTrail log-file integrity validation is not enabled for this trail. "
        "This does not demonstrate log modification, missing logging or compromise.",
        "Enable log-file validation on the trail, then recollect configuration. "
        "Verify logging delivery and digest validation separately in the owner "
        "account/home Region.",
        "LOW",
        "Integrity verification capability is absent; logging activity and "
        "retention are outside this check.",
        follow_up=(
            "Collect GetTrailStatus to assess IsLogging and delivery errors separately",
            "Use owner account/home Region for configuration changes and digest verification",
            "Collect authorized digest/object evidence before asserting successful "
            "integrity validation",
            "Approve proposed methodology mapping and business severity context",
        ),
    ),
)
# Mapping metadata and risk-context hooks only; predicates are unchanged from R0 1.1.0.
RULES = tuple(
    replace(
        rule,
        methodology=LINKS[rule.rule_id],
        annotate=instance_state_context if rule.rule_id == "R0-EC2-IMDSV2" else None,
    )
    for rule in RULES
)
BY_ID = {rule.rule_id: rule for rule in RULES}
