"""R0 contracts reuse Phase 0 outcomes; unresolved identity is explicitly nullable."""

import hashlib
import json
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    model_serializer,
    model_validator,
)

from offline_analyzer.contracts.gcp import ProjectId, ProjectNumber
from offline_analyzer.contracts.models import AccountId, Digest, EvidenceRef, Identifier, Outcome
from offline_analyzer.ingestion.safety import validate_relative_path

VERSION = "r0.1"
NORMALIZATION_VERSION = "r0.1.6"
AWS_OPERATIONS = (
    "sts:GetCallerIdentity",
    "ec2:DescribeSubnets",
    "ec2:DescribeNetworkAcls",
    "ec2:DescribeInternetGateways",
    "s3api:GetBucketPolicy",
    "kms:GetKeyPolicy",
    "kms:ListGrants",
    "lambda:ListFunctions",
    "ecs:DescribeTaskDefinition",
    "ec2:DescribeVpcs",
    "ec2:DescribeVpcPeeringConnections",
    "ec2:DescribeTransitGateways",
    "ec2:DescribeTransitGatewayAttachments",
    "ec2:DescribeTransitGatewayRouteTables",
    "ec2:GetTransitGatewayRouteTableAssociations",
    "ec2:GetTransitGatewayRouteTablePropagations",
    "ec2:SearchTransitGatewayRoutes",
    "ram:GetResourceShares",
    "ram:ListResources",
    "ram:ListPrincipals",
    "ec2:DescribeInstances",
    "rds:DescribeDBInstances",
    "cloudtrail:DescribeTrails",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeNetworkInterfaces",
    "iam:GetAccountAuthorizationDetails",
    "iam:ListRoles",
    "s3control:GetPublicAccessBlock",
    "ec2:DescribeRouteTables",
    "s3api:GetPublicAccessBlock",
    "s3api:GetBucketPolicyStatus",
    "s3api:GetBucketAcl",
    "iam:GetRole",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies",
    "iam:GetRolePolicy",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:ListInstanceProfilesForRole",
    "iam:GetInstanceProfile",
    "organizations:DescribeOrganization",
    "organizations:ListRoots",
    "organizations:ListOrganizationalUnitsForParent",
    "organizations:ListAccountsForParent",
    "organizations:ListAccounts",
    "organizations:ListParents",
    "organizations:ListPolicies",
    "organizations:DescribePolicy",
    "organizations:ListTargetsForPolicy",
    "organizations:ListPoliciesForTarget",
    "cloudtrail:GetTrailStatus",
    "cloudtrail:GetEventSelectors",
    "guardduty:ListDetectors",
    "guardduty:GetDetector",
    "config:DescribeConfigurationRecorderStatus",
    "securityhub:DescribeHub",
    "kms:DescribeKey",
    "kms:GetKeyRotationStatus",
)
GLOBAL_OPERATIONS = (
    "sts:GetCallerIdentity",
    "iam:GetAccountAuthorizationDetails",
    "iam:ListRoles",
    "s3control:GetPublicAccessBlock",
    "s3api:GetPublicAccessBlock",
    "s3api:GetBucketPolicyStatus",
    "s3api:GetBucketAcl",
    "iam:GetRole",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies",
    "iam:GetRolePolicy",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "iam:ListInstanceProfilesForRole",
    "iam:GetInstanceProfile",
    "organizations:DescribeOrganization",
    "organizations:ListRoots",
    "organizations:ListOrganizationalUnitsForParent",
    "organizations:ListAccountsForParent",
    "organizations:ListAccounts",
    "organizations:ListParents",
    "organizations:ListPolicies",
    "organizations:DescribePolicy",
    "organizations:ListTargetsForPolicy",
    "organizations:ListPoliciesForTarget",
)
FINDING_CLASSES = ("BASELINE_DEVIATION", "POTENTIAL_EXPOSURE", "SUPPORTED_SECURITY_GAP")


def stable_id(kind: str, value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"{kind}-{hashlib.sha256(payload.encode()).hexdigest()}"


class R0Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["r0.1"] = VERSION


class Scope(R0Contract):
    account_id: AccountId
    region: Identifier


class Source(R0Contract):
    path: Identifier | None = None
    sha256: Digest | None = None
    partition: Literal["aws", "aws-cn", "aws-us-gov"] | None = None
    format: Literal["aws-json-v1", "prowler-ocsf-5.10", "prowler-ocsf-5.26.1", "gcp-json-v1"]
    operation: (
        Literal[
            "sts:GetCallerIdentity",
            "ec2:DescribeSubnets",
            "ec2:DescribeNetworkAcls",
            "ec2:DescribeInternetGateways",
            "s3api:GetBucketPolicy",
            "kms:GetKeyPolicy",
            "kms:ListGrants",
            "lambda:ListFunctions",
            "ecs:DescribeTaskDefinition",
            "ec2:DescribeVpcs",
            "ec2:DescribeVpcPeeringConnections",
            "ec2:DescribeTransitGateways",
            "ec2:DescribeTransitGatewayAttachments",
            "ec2:DescribeTransitGatewayRouteTables",
            "ec2:GetTransitGatewayRouteTableAssociations",
            "ec2:GetTransitGatewayRouteTablePropagations",
            "ec2:SearchTransitGatewayRoutes",
            "ram:GetResourceShares",
            "ram:ListResources",
            "ram:ListPrincipals",
            "ec2:DescribeInstances",
            "rds:DescribeDBInstances",
            "cloudtrail:DescribeTrails",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeNetworkInterfaces",
            "iam:GetAccountAuthorizationDetails",
            "iam:ListRoles",
            "s3control:GetPublicAccessBlock",
            "ec2:DescribeRouteTables",
            "s3api:GetPublicAccessBlock",
            "s3api:GetBucketPolicyStatus",
            "s3api:GetBucketAcl",
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:GetRolePolicy",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:ListInstanceProfilesForRole",
            "iam:GetInstanceProfile",
            "organizations:DescribeOrganization",
            "organizations:ListRoots",
            "organizations:ListOrganizationalUnitsForParent",
            "organizations:ListAccountsForParent",
            "organizations:ListAccounts",
            "organizations:ListParents",
            "organizations:ListPolicies",
            "organizations:DescribePolicy",
            "organizations:ListTargetsForPolicy",
            "organizations:ListPoliciesForTarget",
            "cloudtrail:GetTrailStatus",
            "cloudtrail:GetEventSelectors",
            "guardduty:ListDetectors",
            "guardduty:GetDetector",
            "config:DescribeConfigurationRecorderStatus",
            "securityhub:DescribeHub",
            "kms:DescribeKey",
            "kms:GetKeyRotationStatus",
            "prowler:Scan",
        ]
        | Annotated[str, Field(pattern=r"^gcp:[A-Za-z0-9_.]+$", max_length=200)]
    )
    account_id: AccountId | None = None
    region: Identifier | None = None
    collected_at: AwareDatetime
    coverage: Literal["COMPLETE", "PARTIAL", "ERROR", "NOT_COLLECTED"] = "PARTIAL"
    errors: tuple[Identifier, ...] = ()
    collector_version: Identifier = "unspecified"
    request_parameters: dict[str, JsonValue] | None = None

    project_id: ProjectId | None = None
    project_number: ProjectNumber | None = None
    gcp_metadata: dict[str, JsonValue] | None = None

    @model_serializer(mode="wrap")
    def legacy_partition_shape(self, handler):
        data = handler(self)
        # Preserve historical package bytes and source identity when partition is unspecified.
        if self.partition is None:
            data.pop("partition", None)
        for key in ("project_id", "project_number", "gcp_metadata"):
            if data.get(key) is None:
                data.pop(key, None)
        return data

    @model_validator(mode="after")
    def validate_source(self):
        if (self.format == "gcp-json-v1") != self.operation.startswith("gcp:"):
            raise ValueError("GCP operation/format mismatch")
        if self.format != "gcp-json-v1" and (
            self.project_id or self.project_number or self.gcp_metadata
        ):
            raise ValueError("AWS sources cannot carry GCP metadata")
        if self.format == "gcp-json-v1" and (not self.project_id or self.account_id):
            raise ValueError("GCP project identity required; AWS account forbidden")
        if self.path:
            validate_relative_path(self.path)
            if not self.sha256:
                raise ValueError("artifact checksum required")
        elif self.coverage not in {"ERROR", "NOT_COLLECTED"}:
            raise ValueError("successful source requires artifact")
        if self.coverage == "ERROR" and not self.errors:
            raise ValueError("error coverage needs error identity")
        if self.errors and self.coverage == "COMPLETE":
            raise ValueError("errors cannot establish complete coverage")
        if self.format.startswith("prowler-") != (self.operation == "prowler:Scan"):
            raise ValueError("operation/format mismatch")
        return self


class Package(R0Contract):
    targets: Annotated[tuple[Scope, ...], Field(max_length=4096)] = ()
    sources: Annotated[tuple[Source, ...], Field(min_length=1, max_length=8192)]

    @model_validator(mode="after")
    def unique_sources(self):
        descriptors = [source.model_dump_json() for source in self.sources]
        if len(set(descriptors)) != len(descriptors):
            raise ValueError("duplicate source descriptors")
        return self


class CloudRecord(R0Contract):
    """Additive fields omitted for historical AWS records to retain fingerprints."""

    provider: Literal["AWS", "GCP"] = "AWS"
    project_id: ProjectId | None = None
    project_number: ProjectNumber | None = None
    organization_id: Identifier | None = None
    folder_id: Identifier | None = None

    @model_validator(mode="after")
    def provider_scope_consistent(self):
        if self.provider == "GCP":
            if not self.project_id or getattr(self, "account_id", None) is not None:
                raise ValueError("GCP project required; AWS account must remain null")
            if getattr(self, "resource_id", None) and not self.resource_id.startswith("gcp://"):
                raise ValueError("GCP canonical resource namespace required")
        elif self.project_id or self.project_number or self.organization_id or self.folder_id:
            raise ValueError("AWS records cannot carry GCP hierarchy")
        tool = getattr(self, "source_tool", None)
        if tool and (tool == "gcp") != (self.provider == "GCP"):
            raise ValueError("Provider and source tool disagree")
        return self

    @model_serializer(mode="wrap")
    def historical_aws_shape(self, handler):
        data = handler(self)
        if self.provider == "AWS":
            data.pop("provider", None)
        for key in ("project_id", "project_number", "organization_id", "folder_id"):
            if data.get(key) is None:
                data.pop(key, None)
        return data


class Normalized(CloudRecord):
    observation_id: Identifier
    account_id: AccountId | None
    region: Identifier | None
    resource_id: Identifier | None
    native_id: Identifier | None
    resource_type: Identifier | None
    partition: Identifier | None
    source_tool: Literal["aws", "prowler", "gcp"]
    source_version: Identifier
    source_check_id: Identifier
    source_status: Identifier | None
    source_severity: Identifier | None
    collected_at: AwareDatetime | None
    operation: Identifier
    normalization_version: Literal[
        "r0.1", "r0.1.1", "r0.1.2", "r0.1.3", "r0.1.4", "r0.1.5", "r0.1.6"
    ] = NORMALIZATION_VERSION
    source_finding_id: Identifier | None = None
    source_status_id: Annotated[int, Field(strict=True)] | None = None
    source_status_caption: Identifier | None = None
    collection_account_id: AccountId | None = None
    collection_region: Identifier | None = None
    source_details: dict[str, JsonValue] = Field(default_factory=dict)
    configuration: dict[str, JsonValue]
    evidence: EvidenceRef
    integrity_sha256: Digest
    unresolved: tuple[Identifier, ...] = ()


class MethodologyMapped(CloudRecord):
    """Original control ID and the specific source criteria a rule evaluates.

    PROPOSED means engineering-reviewed against the pinned workbook hash and awaiting
    methodology-owner approval; it is never a claim of full control coverage.
    """

    methodology_id: Identifier | None = None
    mapping_status: Literal["UNRESOLVED", "PROPOSED"] = "UNRESOLVED"
    methodology_criteria: tuple[Identifier, ...] = ()
    methodology_sha256: Digest | None = None

    @model_validator(mode="after")
    def mapping_complete(self):
        if self.mapping_status == "PROPOSED" and not (
            self.methodology_id and self.methodology_criteria and self.methodology_sha256
        ):
            raise ValueError("proposed mapping requires control, criteria and source hash")
        if self.mapping_status == "UNRESOLVED" and self.methodology_id:
            raise ValueError("unresolved mapping cannot carry a methodology ID")
        return self


class Result(MethodologyMapped):
    evaluation_id: Identifier
    rule_id: Identifier
    rule_version: Identifier
    account_id: AccountId | None
    region: Identifier | None
    resource_id: Identifier | None
    native_id: Identifier | None
    outcome: Outcome
    evaluation_scope: Literal["RESOURCE", "COLLECTION_SCOPE"] = "RESOURCE"
    reasoning: str
    evidence: tuple[EvidenceRef, ...] = ()
    supporting_observations: tuple[Identifier, ...] = ()
    contradictory_observations: tuple[Identifier, ...] = ()
    missing_dependencies: tuple[Identifier, ...] = ()
    confidence: Literal["HIGH", "MEDIUM", "LOW", "UNASSESSED"]
    limitations: tuple[Identifier, ...] = ()
    assessed_at: AwareDatetime
    # Risk context derived from evidence, separate from the source-criterion outcome.
    finding_class: Literal[FINDING_CLASSES] | None = None
    exposure_status: Identifier | None = None
    suggested_severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    evidence_needed: tuple[Identifier, ...] = ()
    compensating_controls: tuple[Identifier, ...] = ()

    @model_validator(mode="before")
    @classmethod
    def legacy_scope(cls, data):
        if isinstance(data, dict) and "evaluation_scope" not in data:
            if str(data.get("evaluation_id", "")).startswith(
                ("scope-evaluation-", "unassigned-source-")
            ):
                data = {**data, "evaluation_scope": "COLLECTION_SCOPE"}
        return data

    @model_validator(mode="after")
    def pass_requires_evidence(self):
        if self.outcome == Outcome.PASS and (not self.evidence or self.missing_dependencies):
            raise ValueError("PASS requires complete prerequisites")
        return self


class Candidate(MethodologyMapped):
    finding_id: Identifier
    title: str
    security_domain: Identifier
    rule_id: Identifier
    rule_version: Identifier
    account_id: AccountId | None
    region: Identifier
    resource_id: Identifier
    native_id: Identifier
    technical_observation: str
    security_risk: str
    evidence: tuple[EvidenceRef, ...]
    contradictory_observations: tuple[Identifier, ...]
    missing_evidence: tuple[Identifier, ...]
    suggested_severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_rationale: str
    evidence_confidence: Literal["HIGH", "MEDIUM", "LOW", "UNASSESSED"]
    remediation: str
    review_status: Literal["CANDIDATE"] = "CANDIDATE"
    validation_requirements: tuple[Identifier, ...] = ()
    # Source-linked methodology metadata, kept separate from technical severity.
    attack_paths: tuple[Identifier, ...] = ()
    stride_category: Identifier | None = None
    methodology_inherent_severity: Identifier | None = None
    finding_class: Literal[FINDING_CLASSES] | None = None
    exposure_status: Identifier | None = None
    compensating_controls: tuple[Identifier, ...] = ()


class Decision(R0Contract):
    finding_id: Identifier
    status: Literal["CONFIRMED", "REJECTED", "NEEDS_VALIDATION"]
    analyst: Identifier
    note: Annotated[str, Field(max_length=16000)]
    decided_at: AwareDatetime
    run_id: Identifier
    evidence_fingerprint: Digest
