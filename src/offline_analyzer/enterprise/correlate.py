"""Typed references and evaluated IAM predicates over immutable enterprise evidence.

Resource access and network relationships are configuration references only. A graph
never asserts effective S3/KMS access, reachability, firewall traversal or exploitation.
"""

import json
import re
from collections import defaultdict
from datetime import datetime

from offline_analyzer.contracts.enterprise import Edge
from offline_analyzer.contracts.models import EvidenceRef
from offline_analyzer.contracts.r0 import stable_id
from offline_analyzer.iam.analysis import ORG_KINDS, IamAnalysis
from offline_analyzer.iam.model import KINDS
from offline_analyzer.iam.policy import parse_policy
from offline_analyzer.inventory.accounts import workspace_registry
from offline_analyzer.provenance.execution import checkpoint

ARN = re.compile(r"^arn:([^:]+):([^:]*):([^:]*):([^:]*):(.+)$")
ACCOUNT = re.compile(r"[0-9]{12}")
MAX_EDGES = 100000
CORRELATION_VERSION = "1.0.2"  # 1.0.2: structured truncation records with counts


def parts(value: str, partition=None, account=None):
    match = ARN.fullmatch(value)
    if match:
        return match[1], match[4] if ACCOUNT.fullmatch(match[4]) else None
    if ACCOUNT.fullmatch(value) or value.startswith("account "):
        number = value.removeprefix("account ")
        return partition, number if ACCOUNT.fullmatch(number) else None
    return partition, account


def ec2_ref(partition, account, region, native, kind):
    return f"arn:{partition}:ec2:{region}:{account}:{kind}/{native}"


def correlate(store, run: str) -> dict:
    store.require_run(run)
    sources = list(store.source_data(run))
    registry = workspace_registry(store.workspace)
    registered = registry.fingerprint() if registry else None
    cached = store.db.execute(
        "SELECT data FROM enterprise_projection WHERE run_id=?", [run]
    ).fetchone()
    if (
        cached
        and json.loads(cached[0]).get("registry") == registered
        and json.loads(cached[0]).get("version") == CORRELATION_VERSION
    ):
        return json.loads(cached[0])
    refs_by_oid = defaultdict(set)
    for oid, artifact, locator in store.rows(
        "SELECT observation_id,artifact_id,locator FROM evidence_refs WHERE run_id=?", [run]
    ):
        refs_by_oid[oid].add(EvidenceRef(artifact_id=artifact, locator=locator))
    assessed_at = datetime.fromisoformat(
        store.db.execute("SELECT assessed_at FROM assessments WHERE run_id=?", [run]).fetchone()[0]
    )
    facts = {o.observation_id: o for o in store.observations(run) if o.source_tool == "aws"}
    by_native = defaultdict(list)
    artifact_parts = defaultdict(set)
    for o in facts.values():
        if o.native_id:
            by_native[(o.partition, o.account_id, o.native_id)].append(o)
        artifact_parts[o.evidence.artifact_id].add(o.partition)
    network_owners = defaultdict(set)
    owner_evidence = defaultdict(set)
    for o in facts.values():
        if o.resource_type == "AWS::EC2::TransitGateway" and o.configuration.get("OwnerId"):
            network_owners[(o.partition, o.region, o.native_id)].add(o.configuration["OwnerId"])
        if o.resource_type == "AWS::EC2::TransitGatewayAttachment":
            c = o.configuration
            if c.get("TransitGatewayId") and c.get("TransitGatewayOwnerId"):
                network_owners[(o.partition, o.region, c["TransitGatewayId"])].add(
                    c["TransitGatewayOwnerId"]
                )

    for o in facts.values():
        if o.resource_type == "AWS::EC2::VPC" and o.account_id and o.resource_id:
            key = (o.partition, o.region, o.native_id)
            network_owners[key].add(o.account_id)
            owner_evidence[key].add(o.observation_id)
        if o.resource_type == "AWS::EC2::TransitGateway" and o.configuration.get("OwnerId"):
            owner_evidence[(o.partition, o.region, o.native_id)].add(o.observation_id)
        if o.resource_type == "AWS::EC2::TransitGatewayAttachment":
            owner = o.configuration.get("TransitGatewayOwnerId")
            if owner:
                for native in (o.native_id, o.configuration.get("TransitGatewayId")):
                    key = (o.partition, o.region, native)
                    network_owners[key].add(owner)
                    owner_evidence[key].add(o.observation_id)
    for o in facts.values():
        if o.resource_type == "AWS::EC2::TransitGatewayRouteTable":
            key = (o.partition, o.region, o.configuration.get("TransitGatewayId"))
            table = (o.partition, o.region, o.native_id)
            network_owners[table].update(network_owners[key])
            owner_evidence[table].update(owner_evidence[key] | {o.observation_id})

    def network_proof(o, native):
        return {o.observation_id} | owner_evidence[(o.partition, o.region, native)]

    def network_target(o, native, kind):
        owners = network_owners.get((o.partition, o.region, native), set())
        if len(owners) == 1:
            return ec2_ref(o.partition, next(iter(owners)), o.region, native, kind)
        return f"reference:{o.partition}:ec2:{o.region}:{kind}/{native}"

    findings = defaultdict(list)
    resource_scope = {
        o.resource_id: (o.partition, o.account_id, o.region, o.native_id)
        for o in facts.values()
        if o.resource_id
    }
    for f in store.candidates(run):
        if f.resource_id in resource_scope:
            findings[resource_scope[f.resource_id]].append(f)
    edges: dict[str, Edge] = {}
    truncated = []
    detail: list[dict] = []  # provenance/truncation.py records
    beyond: set[str] = set()  # distinct relationships dropped by MAX_EDGES

    def add(
        source,
        destination,
        kind,
        service,
        domain,
        observations,
        status="DIRECTLY_OBSERVED",
        missing=(),
        blocking=(),
        detail="Configuration reference only",
        authorization=None,
        source_account=None,
        destination_account=None,
        source_partition=None,
        destination_partition=None,
        region=None,
        privilege=None,
        preconditions=(),
    ):
        checkpoint()
        if len(source) > 4096 or len(destination) > 4096:
            truncated.append("Reference identifier exceeds graph contract; inspect source evidence")
            return
        observations = sorted(set(observations))
        used = [facts[oid] for oid in observations if oid in facts]
        if not used:
            return
        sample = used[0]
        sp, sa = parts(source, source_partition or sample.partition, source_account)
        dp, da = parts(destination, destination_partition or sample.partition, destination_account)
        evidence = {o.evidence for o in used}
        # Preserve all original duplicate locators, not only the normalized representative.
        evidence.update(r for oid in observations for r in refs_by_oid[oid])
        timestamps = sorted({o.collected_at for o in used if o.collected_at})
        missing = list(missing)
        if status == "DERIVED_SUPPORTED" and (missing or blocking):
            status, authorization = "POTENTIAL", "POTENTIALLY_ALLOWED"
        if status == "DERIVED_SUPPORTED" and (
            len(timestamps) > 1 or any(o.unresolved for o in used)
        ):
            status, authorization = "POTENTIAL", "POTENTIALLY_ALLOWED"
            missing.append(
                "Reconfirm simultaneous applicability of "
                "collected policies and resolve evidence issues"
            )
        if sp and dp and sp != dp and authorization:
            status, authorization = "UNKNOWN", "UNKNOWN"
            missing.append(
                "Cross-partition authorization is "
                "unsupported; collect principals in the target partition"
            )

        def related(value, part, account):
            parsed = ARN.fullmatch(value)
            native = value
            scope = sample.region
            if parsed:
                scope = parsed[3] or "global"
                if parsed[2] == "ec2" and parsed[5].split("/", 1)[0] in {
                    "instance",
                    "security-group",
                    "network-interface",
                    "route-table",
                }:
                    native = parsed[5].split("/", 1)[-1]
            return findings.get((part, account, scope, native), [])

        linked = related(source, sp, sa) + related(destination, dp, da)
        if (
            kind
            in {
                "INSTANCE_USES_PROFILE",
                "INSTANCE_USES_ROLE",
                "FUNCTION_USES_ROLE",
                "TASK_USES_ROLE",
                "TASK_EXECUTION_ROLE",
            }
            and sa
            and da
            and sa != da
        ):
            status = "UNKNOWN"
            missing.append(
                "Workload-role association ownership conflicts; verify same-account identities"
            )
        source_arn, destination_arn = ARN.fullmatch(source), ARN.fullmatch(destination)
        scope_region = (
            region
            or (source_arn[3] if source_arn and source_arn[3] else None)
            or (destination_arn[3] if destination_arn and destination_arn[3] else None)
            or sample.region
            or "global"
        )
        eid = stable_id("relationship", [sp, sa, source, dp, da, destination, kind, scope_region])
        if len(edges) >= MAX_EDGES and eid not in edges:
            beyond.add(eid)
            return
        previous = edges.get(eid)
        if previous:
            evidence |= set(previous.evidence)
            observations = sorted(set(observations) | set(previous.observation_ids))
            timestamps = sorted(set(timestamps) | set(previous.collected_at))
            if previous.status != status:
                status = "UNKNOWN"
                missing.append("Conflicting relationship conclusions across evidence")
        edges[eid] = Edge(
            relationship_id=eid,
            run_id=run,
            source_account=sa,
            source=source,
            destination_account=da,
            destination=destination,
            source_partition=sp,
            destination_partition=dp,
            relationship_type=kind,
            service=service,
            domain=domain,
            region=scope_region,
            status=status,
            authorization=authorization,
            evidence=tuple(sorted(evidence, key=lambda r: (r.artifact_id, r.locator))),
            observation_ids=tuple(observations),
            collected_at=tuple(timestamps),
            assessed_at=assessed_at,
            missing=tuple(sorted(set(missing))),
            blocking=tuple(sorted(set(blocking))),
            confidence="HIGH"
            if status in {"DIRECTLY_OBSERVED", "DERIVED_SUPPORTED", "BLOCKED"}
            and not any(o.unresolved for o in used)
            else "UNASSESSED",
            limitations=("Configuration or policy predicate does not confirm exploitation",),
            detail=detail,
            related_findings=tuple(sorted({f.finding_id for f in linked})),
            methodology_ids=tuple(sorted({f.methodology_id for f in linked if f.methodology_id})),
            preconditions=tuple(preconditions),
            target_privilege=privilege,
            outside_registry=(sa not in registry.accounts or da not in registry.accounts)
            if registry and sa and da
            else None,
        )

    for partition in sorted(
        {o.partition for o in facts.values() if o.resource_type in KINDS and o.partition}
    ):
        relevant = [
            s for s in sources if partition in artifact_parts.get(s.get("artifact_id"), set())
        ]
        analysis = IamAnalysis(store, run, relevant, registry, partition=partition)
        for role in analysis.inventory.roles.values():
            for statement in role.trust.statements if role.trust else ():
                for principal in (statement.principals or {}).get("AWS", ()):
                    add(
                        principal,
                        role.arn,
                        f"TRUST_POLICY_{statement.effect.upper()}_REFERENCE",
                        "sts",
                        "IAM",
                        role.observations,
                        detail=(
                            "Trust statement references principal; "
                            "effective authorization evaluated separately"
                        ),
                    )
            for arn in role.attached or ():
                policy = analysis.inventory.policies.get(arn)
                add(
                    role.arn,
                    arn,
                    "ROLE_HAS_POLICY",
                    "iam",
                    "IAM",
                    role.observations,
                    missing=()
                    if policy and policy.document
                    else (f"iam:GetPolicy and iam:GetPolicyVersion for {arn}",),
                )
            if role.boundary_arn:
                add(
                    role.arn,
                    role.boundary_arn,
                    "ROLE_HAS_BOUNDARY",
                    "iam",
                    "IAM",
                    role.observations,
                )
            documents, _ = analysis.inventory.identity_documents(role)
            for document in documents:
                for statement in document.statements:
                    for resource in statement.resources or ():
                        if ARN.fullmatch(resource):
                            add(
                                role.arn,
                                resource,
                                f"IDENTITY_POLICY_{statement.effect.upper()}_RESOURCE_REFERENCE",
                                ARN.fullmatch(resource)[2],
                                "RESOURCE_ACCESS",
                                role.observations,
                                status="POTENTIAL",
                                missing=(
                                    (
                                        "Operation-specific resource policy, "
                                        "applicable restrictions and request context"
                                    ),
                                ),
                                detail=(
                                    "Named policy resource; no "
                                    "generic service authorization evaluated"
                                ),
                            )
        for investigation in analysis.transitions() + analysis.passrole():
            target = analysis.inventory.by_arn.get(investigation.target)
            if investigation.kind == "PASS_ROLE" and target is None:
                continue
            principal = analysis.inventory.by_arn.get(investigation.principal)
            oids = set(target.observations if target else ()) | set(
                principal.observations if principal else ()
            )
            # Include resolved policy and Organizations records, not just role attachments.
            for role in (principal, target):
                if role:
                    for arn in (*(role.attached or ()), role.boundary_arn):
                        policy = analysis.inventory.policies.get(arn)
                        if policy:
                            oids.update(policy.observations)
            oids.update(
                o.observation_id
                for o in facts.values()
                if o.resource_type in ORG_KINDS and o.partition == partition
            )
            state = {
                "ALLOWED_WITH_SUPPORTED_CONTEXT": "DERIVED_SUPPORTED",
                "DENIED_BY_EVIDENCE": "BLOCKED",
                "POTENTIALLY_ALLOWED": "POTENTIAL",
                "UNKNOWN": "POTENTIAL",
            }[investigation.state]
            add(
                investigation.principal.removeprefix("account "),
                investigation.target,
                investigation.kind,
                "sts" if investigation.kind == "ASSUME_ROLE" else "iam",
                "IAM",
                oids,
                status=state,
                authorization=investigation.state,
                missing=investigation.missing,
                blocking=investigation.blocking,
                detail=investigation.reasoning,
                privilege=analysis.privilege(target)[0] if target else None,
                preconditions=investigation.preconditions,
            )
        for instance in analysis.instances:
            profile = instance.configuration["InstanceProfileArn"]
            origin = ec2_ref(
                partition, instance.account_id, instance.region, instance.native_id, "instance"
            )
            add(
                origin,
                profile,
                "INSTANCE_USES_PROFILE",
                "ec2",
                "IAM",
                (instance.observation_id,),
                source_account=instance.account_id,
            )
            for arn in analysis.inventory.profiles.get(profile, ()):
                oids = (
                    [instance.observation_id, *analysis.inventory.by_arn[arn].observations]
                    if arn in analysis.inventory.by_arn
                    else [instance.observation_id]
                )
                add(
                    origin,
                    arn,
                    "INSTANCE_USES_ROLE",
                    "ec2",
                    "IAM",
                    oids,
                    source_account=instance.account_id,
                )
        truncated += analysis.truncated
        detail += analysis.truncation

    trust_versions = defaultdict(list)
    for o in facts.values():
        if o.resource_type == "AWS::IAM::Role" and o.native_id:
            trust_versions[(o.partition, o.native_id)].append(o)
    for (_, arn), observations in trust_versions.items():
        documents = {
            json.dumps(o.configuration.get("AssumeRolePolicyDocument"), sort_keys=True)
            for o in observations
        }
        if len(documents) > 1:
            for o in observations:
                policy = parse_policy(
                    o.configuration.get("AssumeRolePolicyDocument"), f"trust:{arn}"
                )
                for statement in policy.statements:
                    for principal in (statement.principals or {}).get("AWS", ()):
                        add(
                            principal,
                            arn,
                            f"TRUST_POLICY_{statement.effect.upper()}_REFERENCE",
                            "sts",
                            "IAM",
                            [v.observation_id for v in observations],
                            status="UNKNOWN",
                            missing=(
                                "Recollect the target trust policy in a coherent assessment window",
                            ),
                            detail=(
                                "Conflicting trust documents; principal reference observed, "
                                "applicable trust unknown"
                            ),
                        )

    for o in facts.values():
        c = o.configuration
        if not o.resource_id or not o.native_id or not o.account_id or not o.partition:
            continue
        own = o.native_id
        if o.resource_type.startswith("AWS::EC2::") and not own.startswith("arn:"):
            ec2_paths = {
                "AWS::EC2::SecurityGroup": "security-group",
                "AWS::EC2::NetworkInterface": "network-interface",
                "AWS::EC2::RouteTable": "route-table",
                "AWS::EC2::TransitGateway": "transit-gateway",
            }
            own = ec2_ref(
                o.partition,
                o.account_id,
                o.region,
                o.native_id,
                ec2_paths.get(o.resource_type, o.resource_type.split("::")[-1].lower()),
            )
        if o.resource_type in {"AWS::S3::Bucket", "AWS::KMS::Key"} and "PolicyDocument" in c:
            policy = parse_policy(c.get("PolicyDocument"), f"resource-policy:{o.native_id}")
            for statement in policy.statements:
                for principal in (statement.principals or {}).get("AWS", ()):
                    add(
                        principal,
                        o.native_id,
                        f"RESOURCE_POLICY_{statement.effect.upper()}_REFERENCE",
                        "s3" if o.resource_type == "AWS::S3::Bucket" else "kms",
                        "RESOURCE_ACCESS",
                        (o.observation_id,),
                        destination_account=o.account_id,
                        missing=(
                            (
                                "Source identity policies, "
                                "boundary/SCP/RCP and service-specific authorization context"
                            ),
                        ),
                        detail="Resource policy principal reference; not effective access",
                    )
                    if statement.effect == "Allow":
                        add(
                            principal,
                            o.native_id,
                            "RESOURCE_ACCESS_CANDIDATE",
                            "s3" if o.resource_type == "AWS::S3::Bucket" else "kms",
                            "RESOURCE_ACCESS",
                            (o.observation_id,),
                            status="POTENTIAL",
                            destination_account=o.account_id,
                            missing=(
                                "Source identity policy, boundary, SCP/RCP and "
                                "service-specific authorization semantics",
                            ),
                            detail="Access candidate; effective S3/KMS authorization unevaluated",
                        )
        if o.resource_type == "AWS::KMS::Grant" and isinstance(c.get("GranteePrincipal"), str):
            add(
                c["GranteePrincipal"],
                c.get("KeyId") or o.native_id,
                "KMS_GRANT_REFERENCE",
                "kms",
                "RESOURCE_ACCESS",
                (o.observation_id,),
                destination_account=o.account_id,
                missing=(
                    "Grant constraints, source identity and KMS operation-specific authorization",
                ),
            )
        for key, typ in (
            ("Role", "FUNCTION_USES_ROLE"),
            ("taskRoleArn", "TASK_USES_ROLE"),
            ("executionRoleArn", "TASK_EXECUTION_ROLE"),
        ):
            if isinstance(c.get(key), str):
                add(
                    own,
                    c[key],
                    typ,
                    "lambda" if key == "Role" else "ecs",
                    "IAM",
                    (o.observation_id,),
                    source_account=o.account_id,
                )
        if (
            isinstance(c.get("VpcId"), str)
            and re.fullmatch(r"vpc-[0-9a-f]{8,17}", c["VpcId"])
            and o.resource_type != "AWS::EC2::VPC"
        ):
            vpc = network_target(o, c["VpcId"], "vpc")
            add(
                own,
                vpc,
                "RESOURCE_IN_VPC",
                "ec2",
                "NETWORK",
                network_proof(o, c["VpcId"]),
                source_account=o.account_id,
                missing=()
                if len(network_owners[(o.partition, o.region, c["VpcId"])]) == 1
                else ("ec2:DescribeVpcs owner evidence for referenced VpcId",),
            )
        if o.resource_type == "AWS::EC2::VPCPeeringConnection":
            a, b = c.get("RequesterVpcInfo") or {}, c.get("AccepterVpcInfo") or {}
            if a.get("OwnerId") and b.get("OwnerId") and a.get("VpcId") and b.get("VpcId"):
                add(
                    ec2_ref(
                        o.partition, a["OwnerId"], a.get("Region", o.region), a["VpcId"], "vpc"
                    ),
                    ec2_ref(
                        o.partition, b["OwnerId"], b.get("Region", o.region), b["VpcId"], "vpc"
                    ),
                    "VPC_PEERING_REFERENCE",
                    "ec2",
                    "NETWORK",
                    (o.observation_id,),
                    detail="Peering state: " + str((c.get("Status") or {}).get("Code", "unknown")),
                    missing=("Bidirectional route tables, SG/NACL and operation/traffic context",),
                )
        if (
            o.resource_type == "AWS::EC2::TransitGatewayAttachment"
            and c.get("ResourceId")
            and c.get("ResourceOwnerId")
            and c.get("TransitGatewayId")
            and c.get("TransitGatewayOwnerId")
        ):
            add(
                ec2_ref(
                    o.partition,
                    c["ResourceOwnerId"],
                    o.region,
                    c["ResourceId"],
                    str(c.get("ResourceType", "resource")),
                ),
                ec2_ref(
                    o.partition,
                    c["TransitGatewayOwnerId"],
                    o.region,
                    c["TransitGatewayId"],
                    "transit-gateway",
                ),
                "TGW_ATTACHMENT_REFERENCE",
                "ec2",
                "NETWORK",
                (o.observation_id,),
                detail=f"Attachment state: {c.get('State')}; reachability unevaluated",
                missing=(
                    (
                        "TGW associations/propagations/routes, "
                        "VPC routes, SG/NACL and inspection policy"
                    ),
                ),
            )
        if o.resource_type in {
            "AWS::EC2::TransitGatewayAssociation",
            "AWS::EC2::TransitGatewayPropagation",
        }:
            table = c.get("TransitGatewayRouteTableId")
            attachment = o.native_id.split("#")[-1]
            if table:
                add(
                    network_target(o, attachment, "transit-gateway-attachment"),
                    network_target(o, table, "transit-gateway-route-table"),
                    "TGW_" + o.resource_type.split("::")[-1].upper() + "_REFERENCE",
                    "ec2",
                    "NETWORK",
                    (o.observation_id,),
                    detail=f"State: {c.get('State')}; ownership resolved only when evidenced",
                )
        if o.resource_type == "AWS::EC2::TransitGatewayRoute":
            for attachment in c.get("TransitGatewayAttachments") or []:
                if attachment.get("TransitGatewayAttachmentId"):
                    add(
                        network_target(
                            o, c["TransitGatewayRouteTableId"], "transit-gateway-route-table"
                        ),
                        network_target(
                            o,
                            attachment["TransitGatewayAttachmentId"],
                            "transit-gateway-attachment",
                        ),
                        "TGW_ROUTE_REFERENCE",
                        "ec2",
                        "NETWORK",
                        (o.observation_id,),
                        detail=(
                            f"Destination {o.native_id.split('#')[-1]}; "
                            f"route state {c.get('State')}; reachability unevaluated"
                        ),
                    )
        if o.resource_type == "AWS::EC2::RouteTable":
            for route in c.get("Routes") or []:
                for key, kind in (
                    ("TransitGatewayId", "transit-gateway"),
                    ("VpcPeeringConnectionId", "vpc-peering-connection"),
                    ("NetworkInterfaceId", "network-interface"),
                ):
                    if route.get(key):
                        add(
                            own,
                            network_target(o, route[key], kind),
                            "VPC_ROUTE_REFERENCE",
                            "ec2",
                            "NETWORK",
                            (o.observation_id,),
                            source_account=o.account_id,
                            detail=(
                                "Route destination "
                                + str(
                                    route.get("DestinationCidrBlock")
                                    or route.get("DestinationIpv6CidrBlock")
                                )
                                + f"; state {route.get('State')}"
                            ),
                            missing=(
                                (
                                    "Next-hop ownership and complete "
                                    "bidirectional traffic/inspection prerequisites"
                                ),
                            ),
                        )
        if o.resource_type in {"AWS::RAM::ResourceReference", "AWS::RAM::PrincipalReference"}:
            value = o.native_id.split("#")[-1]
            add(
                c["resourceShareArn"],
                value,
                "RAM_" + o.resource_type.split("::")[-1].upper(),
                "ram",
                "NETWORK",
                (o.observation_id,),
                detail="Observed RAM reference; sharing does not establish data-plane access",
            )
        if o.resource_type == "AWS::CloudTrail::Trail":
            for key in (
                "CloudWatchLogsRoleArn",
                "CloudWatchLogsLogGroupArn",
                "KmsKeyId",
                "S3BucketName",
            ):
                value = c.get(key)
                if isinstance(value, str):
                    add(
                        own,
                        value,
                        "LOGGING_DESTINATION_REFERENCE",
                        "cloudtrail",
                        "MONITORING",
                        (o.observation_id,),
                        source_account=o.account_id,
                        missing=(
                            (
                                "Destination ownership, delivery status, "
                                "selectors and resource policy validation"
                            ),
                        ),
                    )
        if o.resource_type == "AWS::Organizations::PolicyTargetList":
            policy = (
                f"reference:{o.partition}:organizations:scope-{o.account_id}:policy/{o.native_id}"
            )
            for target in c.get("TargetIds") or []:
                if isinstance(target, str):
                    add(
                        policy,
                        target,
                        "ORGANIZATION_POLICY_ATTACHMENT",
                        "organizations",
                        "ORGANIZATION",
                        (o.observation_id,),
                        detail="Attachment reference; applicability evaluated separately",
                    )
        if o.resource_type == "AWS::Organizations::TargetPolicyList":
            target = o.native_id.split("#", 1)[0]
            for policy_id in c.get("PolicyIds") or []:
                if isinstance(policy_id, str):
                    policy = (
                        f"reference:{o.partition}:organizations:"
                        f"scope-{o.account_id}:policy/{policy_id}"
                    )
                    add(
                        policy,
                        target,
                        "ORGANIZATION_POLICY_ATTACHMENT",
                        "organizations",
                        "ORGANIZATION",
                        (o.observation_id,),
                        detail="Target policy listing; authorization is a separate evaluation",
                    )
        if o.resource_type in {
            "AWS::Organizations::ParentLink",
            "AWS::Organizations::Account",
            "AWS::Organizations::OrganizationalUnit",
        } and c.get("ParentId"):
            add(
                o.native_id,
                c["ParentId"],
                "ORGANIZATION_PARENT_REFERENCE",
                "organizations",
                "ORGANIZATION",
                (o.observation_id,),
                detail="Explicit hierarchy link; names do not establish membership",
            )
    if beyond:
        from offline_analyzer.provenance.truncation import record, text

        entry = record(
            "Enterprise relationship budget",
            "run",
            MAX_EDGES,
            MAX_EDGES + len(beyond),
            "relationships beyond the budget are missing from the graph, the cross-account "
            "sheets and the enterprise security gaps",
            provider="Enterprise",
        )
        detail.append(entry)
        truncated.append(text(entry))
    summary = {
        "version": CORRELATION_VERSION,
        "unresolved_source_identities": sum(not o.resource_id for o in facts.values()),
        "relationships": len(edges),
        "truncation": sorted(set(truncated)),
        "truncation_detail": detail,
        "registry": registered,
    }
    with store.transaction():
        store.db.execute("DELETE FROM enterprise_edges WHERE run_id=?", [run])
        values = list(edges.values())
        for start in range(0, len(values), 128):
            rows = [
                [
                    run,
                    e.relationship_id,
                    e.source_account,
                    e.destination_account,
                    e.relationship_type,
                    e.domain,
                    e.status,
                    e.model_dump_json(),
                ]
                for e in values[start : start + 128]
            ]
            store.db.execute(
                "INSERT INTO enterprise_edges SELECT " + ",".join(["unnest(?)"] * 8),
                list(map(list, zip(*rows, strict=True))),
            )
        consolidate(store, run, values)
        store.db.execute(
            "INSERT INTO enterprise_projection VALUES (?,?) ON CONFLICT(run_id) "
            "DO UPDATE SET data=excluded.data",
            [run, json.dumps(summary)],
        )
    return summary


def consolidate(store, run: str, edges: list[Edge]) -> None:
    """One investigation for an evidenced shared anchor, never a control-ID/text grouping."""
    groups = defaultdict(list)
    for e in edges:
        if e.relationship_type in {
            "TRUST_POLICY_ALLOW_REFERENCE",
            "RESOURCE_POLICY_ALLOW_REFERENCE",
            "TGW_ATTACHMENT_REFERENCE",
            "INSTANCE_USES_ROLE",
            "ORGANIZATION_POLICY_ATTACHMENT",
        }:
            anchor = (
                e.source
                if e.relationship_type == "ORGANIZATION_POLICY_ATTACHMENT"
                else e.destination
            )
            groups[(e.relationship_type, e.destination_partition, anchor)].append(e)
    store.db.execute("DELETE FROM enterprise_issues WHERE run_id=?", [run])
    for (kind, partition, anchor), linked in groups.items():
        accounts = sorted(
            {a for e in linked for a in (e.source_account, e.destination_account) if a}
        )
        if len(accounts) < 2 or len(linked) < 2:
            continue
        evidence = sorted({r.model_dump_json() for e in linked for r in e.evidence})
        findings = sorted({f for e in linked for f in e.related_findings})
        item = {
            "investigation_id": stable_id("enterprise-investigation", [kind, partition, anchor]),
            "anchor": anchor,
            "root_cause_classification": "SHARED_CONFIGURATION_DEPENDENCY",
            "relationship_type": kind,
            "affected_accounts": accounts,
            "affected_account_count": len(accounts),
            "affected_resources": sorted({v for e in linked for v in (e.source, e.destination)}),
            "source_identities": sorted({e.source for e in linked}),
            "destination_identity": anchor,
            "relationships": sorted(e.relationship_id for e in linked),
            "finding_ids": findings,
            "primary_finding": findings[0] if findings else None,
            "evidence": [json.loads(r) for r in evidence],
            "observation_ids": sorted({o for e in linked for o in e.observation_ids}),
            "missing": sorted({m for e in linked for m in e.missing}),
            "confidence": "MEDIUM",
            "suggested_severity": None,
            "remediation_owner": None,
            "technical_observation": (
                "Multiple evidenced references to one shared resource. "
                "Configuration dependency, not a confirmed vulnerability."
            ),
            "limitations": [
                "Internal trusts and shared infrastructure are not automatically vulnerabilities"
            ],
            "methodology_ids": sorted({m for e in linked for m in e.methodology_ids}),
        }
        if findings:
            ranks = {"INFO": -1, "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            marks = ",".join("?" for _ in findings)
            severities = [
                s
                for (s,) in store.rows(
                    "SELECT json_extract_string(data,'$.suggested_severity') FROM findings "
                    f"WHERE run_id=? AND finding_id IN ({marks})",
                    [run, *findings],
                )
            ]
            item["suggested_severity"] = max(severities, key=ranks.get) if severities else None
        store.db.execute(
            "INSERT INTO enterprise_issues VALUES (?,?,?)",
            [run, item["investigation_id"], json.dumps(item)],
        )
