"""CloGCP additional configuration criteria. No effective-access or compliance claims.

Every check is independent of AWS. Unsupported requirements remain manual/unknown.
New criteria are not silently mapped onto the private methodology.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import partial

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.rules.configuration import Rule, Verdict
from offline_analyzer.rules.gcp_config import nested, port_ranges, range_denied, unknown
from offline_analyzer.rules.gcp_context import canonical, complete, of, usable

VERSION = "clogcp-1.0.0"
PUBLIC = {"allUsers", "allAuthenticatedUsers"}
GKE_DOC = "https://docs.cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster"
RUN_DOC = "https://docs.cloud.google.com/run/docs/authenticating/public"
IAM_DOC = "https://docs.cloud.google.com/iam/docs/service-agents"


def verdict(
    failed: bool,
    text: str,
    *,
    severity: str | None = None,
    related: Sequence[Normalized] = (),
    limitations: tuple[str, ...] = (),
    exposure: bool = False,
) -> Verdict:
    return Verdict(
        Outcome.FAIL if failed else Outcome.PASS,
        text,
        related=tuple(o.observation_id for o in related),
        limitations=tuple(limitations),
        severity=severity,
        finding_class="POTENTIAL_EXPOSURE" if exposure else "BASELINE_DEVIATION",
        exposure="Potential exposure; effective access and exploitation unverified"
        if exposure
        else None,
    )


def manual(text: str, *needed: str, related: Sequence[Normalized] = ()) -> Verdict:
    return Verdict(
        Outcome.MANUAL_VALIDATION_REQUIRED,
        text,
        related=tuple(o.observation_id for o in related),
        evidence_needed=needed,
    )


def boolean(
    obs: Normalized,
    context: Sequence[Normalized],
    path: str,
    bad: bool = False,
    autopilot: bool = False,
) -> Verdict:
    c = obs.configuration
    auto = nested(c, "autopilot", "enabled")
    if autopilot and auto is True:
        return Verdict(
            Outcome.NOT_APPLICABLE,
            (
                "Autopilot manages this node/authentication setting; no "
                "Standard-cluster deviation inferred."
            ),
        )
    if autopilot and auto not in (False, None):
        return unknown("Boolean autopilot.enabled")
    value = nested(c, *path.split("."))
    if type(value) is not bool:
        return unknown(path)
    return verdict(
        value == bad, f"Observed {path}={str(value).lower()}; criterion applies to this cluster."
    )


def gke_endpoint(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    c = obs.configuration
    current = nested(c, "controlPlaneEndpointsConfig", "ipEndpointsConfig")
    if isinstance(current, dict):
        public = current.get("enablePublicEndpoint")
        networks = current.get("authorizedNetworksConfig")
        if current.get("enabled") is False:
            return verdict(
                False,
                (
                    "Control-plane IP endpoints explicitly disabled; DNS endpoint "
                    "authorization is separate."
                ),
            )
    else:
        private = nested(c, "privateClusterConfig", "enablePrivateEndpoint")
        public = not private if type(private) is bool else None
        networks = c.get("masterAuthorizedNetworksConfig")
    if public is False:
        return verdict(False, "Public control-plane IP endpoint explicitly disabled.")
    if public is not True or not isinstance(networks, dict):
        return unknown("Public endpoint and authorized-networks configuration")
    enabled = networks.get("enabled")
    cidrs = networks.get("cidrBlocks", [])
    if not isinstance(cidrs, list) or any(
        not isinstance(x, dict) or not isinstance(x.get("cidrBlock"), str) for x in cidrs
    ):
        return unknown("authorizedNetworksConfig.cidrBlocks")
    if enabled is False or any(x["cidrBlock"] in {"0.0.0.0/0", "::/0"} for x in cidrs):
        return verdict(
            True,
            (
                f"Public control-plane IP endpoint; authorized-networks enabled={enabled}, "
                f"CIDRs={cidrs}."
            ),
            severity="HIGH",
            exposure=True,
            limitations=(
                (
                    "Kubernetes authentication, DNS endpoint access and effective network "
                    "reachability not tested"
                ),
            ),
        )
    if enabled is True:
        return verdict(
            False,
            (
                f"Public control-plane IP endpoint restricted by authorized-networks "
                f"configuration: {cidrs}."
            ),
        )
    return unknown("Explicit authorized-networks enabled setting")


def gke_workload(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    c = obs.configuration
    if nested(c, "autopilot", "enabled") is True:
        return Verdict(
            Outcome.NOT_APPLICABLE, "Workload Identity Federation is managed by Autopilot."
        )
    pool = nested(c, "workloadIdentityConfig", "workloadPool")
    if isinstance(pool, str) and pool:
        return verdict(
            False,
            (
                f"Workload identity pool configured: {pool}; individual workload "
                f"bindings are not validated."
            ),
        )
    if "workloadIdentityConfig" in c and isinstance(c["workloadIdentityConfig"], dict):
        return verdict(
            True,
            "Standard cluster has no workload identity pool in its explicit configuration.",
            severity="MEDIUM",
            limitations=("Pod metadata access and node IAM permissions not established",),
        )
    return unknown("workloadIdentityConfig / Standard-cluster workload authentication")


def gke_network(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    if nested(obs.configuration, "networkConfig", "datapathProvider") == "ADVANCED_DATAPATH":
        return verdict(
            False,
            (
                "Dataplane V2 provides network-policy enforcement; actual workload "
                "policies were not collected."
            ),
        )
    return boolean(obs, context, "networkPolicy.enabled", autopilot=True)


def gke_private_nodes(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    c = obs.configuration
    value = nested(c, "privateClusterConfig", "enablePrivateNodes")
    if value is None:
        value = nested(c, "networkConfig", "defaultEnablePrivateNodes")
    if type(value) is not bool:
        return unknown("Explicit private-node default (Standard or Autopilot)")
    return verdict(
        not value,
        (
            f"Cluster default private-node configuration={value}; Autopilot "
            f"does not guarantee private nodes."
        ),
        severity="MEDIUM",
        limitations=(
            (
                "Node-pool/workload overrides and effective node reachability require "
                "separate evidence"
            ),
        ),
    )


def gke_encryption(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    state = nested(obs.configuration, "databaseEncryption", "state")
    if state == "ENCRYPTED":
        return verdict(
            False,
            (
                "Application-layer secrets encryption configured; key access and "
                "workload secret usage remain separate."
            ),
        )
    if state == "DECRYPTED":
        return manual(
            (
                "No application-layer CMEK encryption; Google-managed encryption at "
                "rest is not absence of encryption."
            ),
            "Approved customer-managed encryption requirement",
        )
    return unknown("databaseEncryption.state")


def runtime_identity(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    c = obs.configuration
    emails = (
        [
            nested(c, "template", "serviceAccount"),
            nested(c, "spec", "template", "spec", "serviceAccountName"),
        ]
        if obs.resource_type == "GCP::RunService"
        else [nested(c, "serviceConfig", "serviceAccountEmail"), c.get("serviceAccountEmail")]
        if obs.resource_type == "GCP::Function"
        else [nested(c, "config", "serviceAccount")]
    )
    emails = {x for x in emails if isinstance(x, str) and x}
    if obs.resource_type == "GCP::GKENodePool" and "default" in emails:
        if not obs.project_number:
            return unknown("Project number needed to resolve explicit default GKE node identity")
        emails.remove("default")
        emails.add(obs.project_number + "-compute@developer.gserviceaccount.com")
    if not emails:
        return unknown("Explicit runtime service-account identity; omitted defaults not guessed")
    related = [
        b
        for b in of(context, "GCP::IAMBinding", obs.project_id)
        if usable(b)
        and b.configuration.get("role") in {"roles/owner", "roles/editor"}
        and {"serviceAccount:" + e for e in emails}.intersection(b.configuration.get("members", []))
    ]
    unconditional = [b for b in related if not b.configuration.get("condition")]
    if unconditional:
        return verdict(
            True,
            (
                f"Runtime identity {sorted(emails)} has observed Owner/Editor allow "
                f"bindings; workload purpose does not establish need."
            ),
            severity="HIGH",
            related=unconditional,
            exposure=True,
            limitations=(
                (
                    "IAM Conditions, deny policies, access boundaries and credential "
                    "compromise not resolved"
                ),
            ),
        )
    return manual(
        (
            f"Runtime identity {sorted(emails)} recorded; no unconditional "
            f"basic-role binding established."
        ),
        "Complete inherited IAM, role permissions and workload requirements",
        related=related,
    )


def serverless_public(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    c = obs.configuration
    annotations = nested(c, "metadata", "annotations") or {}
    if not isinstance(annotations, dict):
        return unknown("Service annotations object")
    disabled = c.get(
        "invokerIamDisabled", annotations.get("run.googleapis.com/invoker-iam-disabled")
    )
    if disabled not in (None, True, False, "true", "false"):
        return unknown("Boolean invoker IAM check configuration")
    subject = canonical(obs.native_id)
    allowed_roles = {"roles/run.invoker"}
    if obs.resource_type == "GCP::Function":
        # Cloud Run's IAM-disable flag is not a Cloud Functions property.
        disabled = None
        generation = c.get("environment")
        if generation == "GEN_1":
            allowed_roles = {"roles/cloudfunctions.invoker"}
        elif generation == "GEN_2":
            target = canonical(nested(c, "serviceConfig", "service"))
            if not target:
                return unknown("Gen 2 underlying Cloud Run service and its invoker policy")
            native_run = [
                r
                for r in of(context, "GCP::RunService", obs.project_id)
                if usable(r) and canonical(r.native_id) == target
            ]
            if native_run:
                return manual(
                    (
                        "Gen 2 invocation is evaluated on the explicitly referenced Cloud "
                        "Run service, avoiding a second function finding."
                    ),
                    "Review the corresponding GCP-RUN-PUBLIC result",
                    related=native_run,
                )
            subject = target
        else:
            return unknown("Function generation (GEN_1/GEN_2); invoker permission differs")
    policies = [
        p
        for p in of(context, "GCP::IAMPolicy", obs.project_id)
        if usable(p)
        and (canonical(p.native_id) == subject or p.operation == "gcp:projects.getIamPolicy")
    ]
    public, conditional = [], []
    for p in policies:
        for b in p.configuration.get("bindings", []):
            if (
                isinstance(b, dict)
                and b.get("role") in allowed_roles
                and PUBLIC.intersection(b.get("members", []))
            ):
                (conditional if b.get("condition") else public).append(p)
    if disabled not in (True, "true") and not public:
        if conditional:
            return unknown("Resolve conditional public invoker binding")
        return manual(
            "No unconditional public invoker grant or explicitly disabled IAM check established.",
            "Complete service IAM and inherited bindings; application authentication",
            related=policies,
        )
    ingress = (
        c.get("ingress")
        or nested(c, "serviceConfig", "ingressSettings")
        or c.get("ingressSettings")
        or annotations.get("run.googleapis.com/ingress")
    )
    note = (
        f"invokerIamDisabled={disabled}; public invoker binding={bool(public)}; "
        f"ingress={ingress or 'unrecorded'}."
    )
    internal = {
        "internal",
        "internal-and-cloud-load-balancing",
        "INGRESS_TRAFFIC_INTERNAL_ONLY",
        "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
        "ALLOW_INTERNAL_ONLY",
        "ALLOW_INTERNAL_AND_GCLB",
    }
    if ingress in internal or c.get("iapEnabled") is True:
        return manual(
            note + " Ingress or IAP limits access; public internet invocation is not established.",
            "Approved endpoint audience, load-balancer controls and application authentication",
            related=public,
        )
    return verdict(
        True,
        note
        + (
            " Public invocation configuration requires owner review; intentionally "
            "public APIs may be appropriate."
        ),
        severity="MEDIUM",
        related=public,
        exposure=True,
        limitations=(
            (
                "Application authorization, intentional public purpose and effective "
                "endpoint reachability unverified"
            ),
        ),
    )


def bigquery_public(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    access = obs.configuration.get("access")
    if not isinstance(access, list) or any(not isinstance(a, dict) for a in access):
        return unknown("Dataset detail access grants (list metadata is insufficient)")
    public = [
        a
        for a in access
        if any(
            a.get(k) in PUBLIC for k in ("iamMember", "specialGroup", "userByEmail", "groupByEmail")
        )
    ]
    read_roles = {
        "READER",
        "WRITER",
        "OWNER",
        "roles/bigquery.dataViewer",
        "roles/bigquery.dataEditor",
        "roles/bigquery.dataOwner",
        "roles/bigquery.admin",
    }
    dangerous = [a for a in public if a.get("role") in read_roles]
    custom, unresolved = [], []
    for a in public:
        role = a.get("role")
        if role in read_roles or role == "roles/bigquery.metadataViewer":
            continue
        definitions = [
            r
            for r in of(context, "GCP::CustomRole", obs.project_id)
            if usable(r)
            and canonical(r.native_id) == role
            and isinstance(r.configuration.get("includedPermissions"), list)
        ]
        if not definitions:
            unresolved.append(a)
        elif any(
            "bigquery.tables.getData" in r.configuration["includedPermissions"] for r in definitions
        ):
            dangerous.append(a)
            custom.extend(definitions)
    if dangerous:
        return verdict(
            True,
            f"Public dataset grants with table-data read permission: {dangerous}.",
            severity="HIGH",
            related=custom,
            exposure=True,
            limitations=(
                (
                    "Job execution permission, row/column policies, VPC Service Controls "
                    "and intended public sharing not established"
                ),
            ),
        )
    if unresolved:
        return unknown("Permissions of public dataset role")
    return verdict(
        False,
        (
            "No public table-data read grant in the observed dataset access list; "
            "metadata-only grants do not establish data access."
        ),
    )


def sql_flags(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    c = obs.configuration
    version = c.get("databaseVersion")
    flags = nested(c, "settings", "databaseFlags")
    if (
        not isinstance(version, str)
        or not isinstance(flags, list)
        or any(
            not isinstance(f, dict)
            or not isinstance(f.get("name"), str)
            or not isinstance(f.get("value"), str)
            for f in flags
        )
    ):
        return unknown("Database engine/version and explicit databaseFlags")
    checks = {
        "MYSQL": {"local_infile": {"on", "true", "1"}},
        "POSTGRES": {
            "log_connections": {"off", "false", "0"},
            "log_disconnections": {"off", "false", "0"},
        },
        "SQLSERVER": {
            "cross db ownership chaining": {"on", "true", "1"},
            "external scripts enabled": {"on", "true", "1"},
        },
    }
    configured = {f["name"].lower(): f["value"].lower() for f in flags}
    expected = next((v for k, v in checks.items() if version.startswith(k)), None)
    if expected is None:
        return unknown("Supported database engine/version")
    bad = {k: configured[k] for k, values in expected.items() if configured.get(k) in values}
    if bad:
        return verdict(
            True,
            (
                f"Explicit {version} security-relevant flag values: {bad}; unset "
                f"defaults were not inferred."
            ),
            severity="LOW" if version.startswith("POSTGRES") else "MEDIUM",
            limitations=(
                (
                    "Database user privileges, logging integrations and approved workload "
                    "exceptions not established"
                ),
            ),
        )
    if not all(k in configured for k in expected):
        return manual(
            f"No explicit insecure checked flag in {version}; one or more flags unset.",
            "Version-specific effective defaults and approved database hardening requirements",
        )
    return verdict(
        False, f"Explicit checked {version} flags do not contain the insecure values: {configured}."
    )


def dnssec(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    c = obs.configuration
    if c.get("visibility") == "private":
        return Verdict(
            Outcome.NOT_APPLICABLE,
            "Private DNS zone; public DNSSEC signing criterion does not apply.",
        )
    state = nested(c, "dnssecConfig", "state")
    if c.get("visibility") != "public" or state not in {"on", "off", "transfer"}:
        return unknown("Explicit public-zone visibility and DNSSEC state")
    if state == "transfer":
        return manual(
            "DNSSEC is in transfer state.", "Delegation and signing transition verification"
        )
    return verdict(
        state == "off",
        f"Public DNS zone dnssecConfig.state={state}; registrar DS delegation not verified.",
        severity="MEDIUM",
    )


def asset_configs(
    context: Sequence[Normalized], obs: Normalized, suffix: str
) -> list[tuple[Normalized, dict]]:
    result = []
    for a in of(context, "GCP::AssetResourceSnapshot", obs.project_id):
        if not usable(a):
            continue
        c = a.configuration
        if str(c.get("assetType", "")).endswith("/" + suffix) and isinstance(
            nested(c, "resource", "data"), dict
        ):
            result.append((a, nested(c, "resource", "data")))
    return result


def tls_policy(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    c = obs.configuration
    name = canonical(c.get("selfLink") or obs.native_id)
    proxies = [
        (a, d)
        for kind in ("TargetHttpsProxy", "TargetSslProxy")
        for a, d in asset_configs(context, obs, kind)
        if canonical(d.get("sslPolicy")) == name
    ]
    forwards = of(context, "GCP::ForwardingRule", obs.project_id)
    attached = [
        (a, f)
        for a, d in proxies
        for f in forwards
        if usable(f)
        and f.configuration.get("loadBalancingScheme") in {"EXTERNAL", "EXTERNAL_MANAGED"}
        and canonical(f.configuration.get("target")) == canonical(d.get("selfLink") or a.native_id)
    ]
    if not attached:
        return manual(
            "SSL policy inventory alone does not establish attachment to a live external proxy.",
            "Target proxy sslPolicy and external forwarding-rule attachment",
        )
    minimum = c.get("minTlsVersion")
    if minimum not in {"TLS_1_0", "TLS_1_1", "TLS_1_2", "TLS_1_3"}:
        return unknown("Explicit SSL policy minTlsVersion")
    return verdict(
        minimum in {"TLS_1_0", "TLS_1_1"},
        f"External forwarding rule references a proxy using this policy; minTlsVersion={minimum}.",
        severity="MEDIUM",
        related=[o for pair in attached for o in pair],
        limitations=(
            "Actual TLS handshake, custom cipher configuration and active traffic not tested",
        ),
    )


def backend_control(obs: Normalized, context: Sequence[Normalized], setting: str) -> Verdict:
    c = obs.configuration
    if c.get("loadBalancingScheme") not in {"EXTERNAL", "EXTERNAL_MANAGED"}:
        return Verdict(Outcome.NOT_APPLICABLE, "Not an explicitly external backend service.")
    if c.get("protocol") not in {"HTTP", "HTTPS", "HTTP2", "H2C"}:
        return Verdict(
            Outcome.NOT_APPLICABLE,
            "HTTP application-backend criterion does not apply to this protocol.",
        )
    if setting == "armor":
        value = c.get("securityPolicy") or c.get("edgeSecurityPolicy")
        if value:
            return verdict(
                False, f"Security policy explicitly attached: {value}; rule efficacy not validated."
            )
        return manual(
            (
                "External HTTP backend has no recorded Cloud Armor attachment; active "
                "frontend and intentional protection requirements unverified."
            ),
            "Live frontend → proxy → URL map → backend chain and approved WAF requirement",
        )
    value = nested(c, "logConfig", "enable")
    if type(value) is not bool:
        return unknown("Explicit backend logConfig.enable")
    return verdict(
        not value,
        (
            f"External HTTP backend logConfig.enable={value}; alternative application "
            f"logging not verified."
        ),
        severity="LOW",
    )


def firewall_policy(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    rules = obs.configuration.get("rules")
    if not isinstance(rules, list) or any(not isinstance(r, dict) for r in rules):
        return unknown("Firewall-policy rule details; listing is insufficient")
    candidates = []
    for r in rules:
        if (
            r.get("disabled") is True
            or r.get("direction") != "INGRESS"
            or r.get("action") != "allow"
        ):
            continue
        match = r.get("match")
        if not isinstance(match, dict):
            return unknown("Policy rule match")
        if not {"0.0.0.0/0", "::/0"}.intersection(match.get("srcIpRanges", [])):
            continue
        entries = match.get("layer4Configs")
        if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
            return unknown("Policy rule layer4Configs")
        ports = port_ranges(
            [{"IPProtocol": e.get("ipProtocol"), "ports": e.get("ports", [])} for e in entries]
        )
        if ports is None:
            return unknown("Policy rule ports")
        sensitive = [
            (p, lo, hi)
            for p, lo, hi in ports
            if p == "all"
            or p == "tcp"
            and any(lo <= port <= hi for port in (22, 3389, 3306, 5432, 1433, 6379, 27017))
        ]
        if sensitive:
            blocked = False
            for deny in rules:
                dm = deny.get("match") or {}
                if (
                    deny.get("action") != "deny"
                    or deny.get("direction") != "INGRESS"
                    or deny.get("disabled") is True
                    or type(deny.get("priority")) is not int
                    or type(r.get("priority")) is not int
                    or deny["priority"] > r["priority"]
                    or deny.get("targetResources")
                    or deny.get("targetServiceAccounts")
                    or not set(match.get("srcIpRanges", [])) <= set(dm.get("srcIpRanges", []))
                ):
                    continue
                denied = port_ranges(
                    [
                        {"IPProtocol": e.get("ipProtocol"), "ports": e.get("ports", [])}
                        for e in dm.get("layer4Configs", [])
                    ]
                )
                if denied and all(range_denied(item, denied) for item in sensitive):
                    blocked = True
            if not blocked:
                candidates.append((r, sensitive))
    if not candidates:
        return verdict(
            False,
            "No explicit policy allow from all internet addresses on the checked sensitive ports.",
        )
    return verdict(
        True,
        (
            f"Policy contains {len(candidates)} broad sensitive-port ingress "
            f"allow rule(s); priorities={[(r.get('priority')) for r, _ in candidates]}."
        ),
        severity="MEDIUM",
        limitations=(
            (
                "Policy association, target matching, higher-level denies and effective"
                " reachability unverified"
            ),
        ),
    )


def effective_guardrail(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    from offline_analyzer.rules.gcp import boolean_enforcement, constraint_name

    c = obs.configuration
    name = constraint_name(c)
    allowed = {
        "compute.requireOsLogin",
        "compute.disableSerialPortAccess",
        "storage.publicAccessPrevention",
    }
    if name not in allowed:
        return Verdict(
            Outcome.NOT_APPLICABLE,
            "Constraint outside this explicit effective boolean-guardrail criterion.",
        )
    if c.get("_parameters", {}).get("effective") not in (True, "true"):
        return unknown("Effective inherited organization-policy provenance")
    enforced, reason = boolean_enforcement(c)
    if enforced is None:
        return unknown("Unconditional effective policy: " + reason)
    return verdict(
        not enforced,
        (
            f"Effective {name} enforcement={enforced}; actual resource settings "
            f"are assessed independently."
        ),
        severity="MEDIUM",
    )


def audit_configuration(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    from offline_analyzer.rules.gcp import PARENT_IAM, iam_hierarchy

    if obs.operation != "gcp:projects.getIamPolicy":
        return Verdict(
            Outcome.NOT_APPLICABLE, "Audit aggregation is reported on project IAM policy only."
        )
    policies = [
        p
        for p in of(context, "GCP::IAMPolicy", obs.project_id)
        if usable(p) and p.operation in PARENT_IAM | {obs.operation}
    ]
    types = set()
    for p in policies:
        for config in p.configuration.get("auditConfigs", []):
            if not isinstance(config, dict):
                return unknown("Valid auditConfigs")
            if config.get("service") != "allServices":
                continue
            for log in config.get("auditLogConfigs", []):
                if isinstance(log, dict) and not log.get("exemptedMembers"):
                    types.add(log.get("logType"))
    if {"DATA_READ", "DATA_WRITE"} <= types:
        return verdict(
            False,
            (
                "Project/inherited allServices audit configuration includes non-exempt "
                "DATA_READ and DATA_WRITE entries; service support and delivery not "
                "established."
            ),
            related=policies,
        )
    if hasattr(context, "sources"):
        full, missing = iam_hierarchy(list(context.sources.values()), obs.project_id)
        if not full:
            return unknown(missing)
    return manual(
        f"Observed allServices audit log types: {sorted(t for t in types if t)}.",
        "Required service-specific audit scope and inherited effective audit configuration",
        related=policies,
    )


def alert_enabled(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    value = obs.configuration.get("enabled")
    if type(value) is not bool:
        return unknown("Explicit alert policy enabled setting")
    return verdict(
        not value,
        (
            f"Alert policy enabled={value}; this does not establish overall "
            f"detection coverage or notification delivery."
        ),
        severity="LOW",
    )


def secret_lifecycle(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    rotation = obs.configuration.get("rotation")
    recorded = rotation if isinstance(rotation, dict) else "not recorded"
    return manual(
        (f"Secret rotation schedule: {recorded}; secret payload and purpose were not collected."),
        (
            "Credential versus non-credential purpose, approved lifecycle and "
            "owning-system rotation procedure"
        ),
    )


def artifact_tags(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    c = obs.configuration
    if not isinstance(c.get("format"), str):
        return unknown("Repository format")
    if c.get("format") != "DOCKER":
        return Verdict(
            Outcome.NOT_APPLICABLE,
            "Docker tag-immutability criterion does not apply to other formats.",
        )
    value = nested(c, "dockerConfig", "immutableTags")
    if value is True:
        return verdict(
            False,
            (
                "Docker immutable tags explicitly enabled; deployed image digest "
                "verification remains separate."
            ),
        )
    return manual(
        f"Docker immutableTags={value}; mutable tags can be intentional.",
        "Approved artifact immutability and deployment digest/signature requirements",
    )


def build_approval(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    value = nested(obs.configuration, "approvalConfig", "approvalRequired")
    return manual(
        (
            f"Build trigger approvalRequired={value}; trigger source trust "
            f"and deployment privilege not established."
        ),
        "Approved pipeline trust/approval requirement and runtime IAM",
    )


def push_auth(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    push = obs.configuration.get("pushConfig")
    if not isinstance(push, dict) or not push.get("pushEndpoint"):
        return Verdict(
            Outcome.NOT_APPLICABLE,
            "No explicit push endpoint; pull-subscription criterion differs.",
        )
    identity = nested(push, "oidcToken", "serviceAccountEmail") or "unrecorded"
    return manual(
        f"Push endpoint configured; OIDC service account={identity}.",
        (
            "Destination authentication, intentional unauthenticated push, endpoint"
            " trust and token audience"
        ),
    )


def custom_public(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    c = obs.configuration
    if not isinstance(c.get("members"), list) or not isinstance(c.get("role"), str):
        return unknown("Role and members")
    if not PUBLIC.intersection(c["members"]) or not c["role"].startswith(
        ("projects/", "organizations/")
    ):
        return Verdict(Outcome.NOT_APPLICABLE, "Not a public custom-role binding.")
    if c.get("condition"):
        return unknown("Evaluate IAM Conditions on the public custom role")
    roles = [
        r
        for r in of(context, "GCP::CustomRole", obs.project_id)
        if usable(r) and r.native_id == c["role"]
    ]
    definitions = [r.configuration.get("includedPermissions") for r in roles]
    if roles and all(r.configuration.get("deleted") is True for r in roles):
        return manual(
            "The custom role is explicitly deleted; active privilege is not established.",
            "Role undelete state, stale binding cleanup and effective authorization",
            related=roles,
        )
    if not roles or any(
        not isinstance(p, list) or any(not isinstance(v, str) for v in p) for p in definitions
    ):
        return unknown("Custom-role includedPermissions")
    if len({tuple(sorted(p)) for p in definitions}) != 1:
        return unknown("Consistent custom-role permission snapshots")
    sensitive = {
        "resourcemanager.projects.setIamPolicy",
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccountKeys.create",
        "storage.objects.get",
        "bigquery.tables.getData",
        "secretmanager.versions.access",
        "cloudkms.cryptoKeyVersions.useToDecrypt",
    }
    permissions = sensitive.intersection(definitions[0])
    return verdict(
        bool(permissions),
        (
            "Public custom-role binding; observed sensitive permission "
            f"intersection={sorted(permissions)}."
        ),
        severity="HIGH",
        related=roles,
        exposure=True,
        limitations=(
            (
                "Allow metadata only; resource scope, deny policies, access boundaries "
                "and effective authorization unresolved"
            ),
        ),
    )


def oidc_condition(obs: Normalized, context: Sequence[Normalized]) -> Verdict:
    c = obs.configuration
    if c.get("disabled") is True or c.get("state") == "DELETED":
        return Verdict(Outcome.NOT_APPLICABLE, "Provider disabled/deleted in this snapshot.")
    from offline_analyzer.rules.gcp_context import pool_guard

    parent = canonical(c.get("name") or obs.native_id).rsplit("/providers/", 1)[0]
    parents = {parent}
    parts = parent.split("/", 2)
    if (
        len(parts) == 3
        and parts[0] == "projects"
        and parts[1] in {obs.project_id, obs.project_number}
    ):
        parents.update(
            "projects/" + project + "/" + parts[2]
            for project in {obs.project_id, obs.project_number} - {None}
        )
    pools = [
        p
        for p in of(context, "GCP::WorkloadIdentityPool", obs.project_id)
        if canonical(p.configuration.get("name") or p.native_id) in parents
    ]
    guard = pool_guard(pools, all(complete(context, p) for p in pools))
    if guard:
        return guard
    issuer = nested(c, "oidc", "issuerUri")
    if issuer not in {
        "https://token.actions.githubusercontent.com",
        "https://gitlab.com",
        "https://app.terraform.io",
    }:
        return manual(
            (
                "Provider issuer is not a supported shared CI issuer; trust must be "
                "reviewed against its actual claims."
            ),
            "Issuer-specific attribute mapping and trust requirements",
        )
    condition = c.get("attributeCondition")
    if isinstance(condition, str) and condition.strip():
        return manual(
            (
                "An attribute condition is configured; CEL meaning and issuer-claim "
                "identity restrictions require review."
            ),
            "Evaluate the condition against approved numeric organization/repository claims",
        )
    if c.get("disabled") is not False and not complete(context, obs):
        return unknown("Explicit enabled provider and attributeCondition configuration")
    return verdict(
        True,
        (
            f"Shared CI OIDC issuer {issuer} has no attribute condition restricting "
            f"the issuing organization."
        ),
        severity="HIGH",
        exposure=True,
        related=pools,
        limitations=(
            (
                "Parent pool state, pool bindings, principal access boundaries, "
                "token audience and usable resource permissions not established"
            ),
        ),
    )


@dataclass(frozen=True)
class Spec:
    kind: str
    operation: str
    title: str
    domain: str
    check: Callable[[Normalized, Sequence[Normalized]], Verdict]
    risk: str
    remediation: str
    reference: str
    severity: str = "MEDIUM"


SPECS = {}


def add(
    suffix, kind, operation, title, domain, check, risk, remediation, reference, severity="MEDIUM"
):
    SPECS["GCP-" + suffix] = Spec(
        "GCP::" + kind, operation, title, domain, check, risk, remediation, reference, severity
    )


for suffix, path, bad, title in (
    ("LEGACY-ABAC", "legacyAbac.enabled", True, "Legacy ABAC enabled"),
    (
        "PRIVATE-NODES",
        "privateClusterConfig.enablePrivateNodes",
        False,
        "Standard cluster public-node configuration",
    ),
    ("SHIELDED-NODES", "shieldedNodes.enabled", False, "Shielded GKE Nodes disabled"),
    (
        "CLIENT-CERT",
        "masterAuth.clientCertificateConfig.issueClientCertificate",
        True,
        "Legacy client certificate issuance enabled",
    ),
):
    add(
        "GKE-" + suffix,
        "GKECluster",
        "gcp:expanded.gke_clusters_rest",
        title,
        "Kubernetes",
        partial(boolean, path=path, bad=bad, autopilot=True),
        (
            f"{title} can weaken the cluster boundary when credentials or workloads "
            f"are compromised; exploit prerequisites are unverified."
        ),
        (
            f"Review {path} on the specific cluster, confirm Standard/Autopilot "
            f"applicability, and apply the documented hardening setting with "
            f"the workload owner."
        ),
        GKE_DOC,
    )

SPECS["GCP-GKE-PRIVATE-NODES"] = Spec(
    "GCP::GKECluster",
    "gcp:expanded.gke_clusters_rest",
    "Cluster defaults allow public nodes",
    "Kubernetes",
    gke_private_nodes,
    (
        "Public node addresses expand potential network exposure; "
        "workload/node-pool overrides and firewall policy still determine "
        "reachability."
    ),
    (
        "Review Standard node pools or Autopilot workload node selectors and "
        "enable private nodes where required, preserving tested egress."
    ),
    "https://docs.cloud.google.com/kubernetes-engine/docs/concepts/network-isolation",
)

add(
    "GKE-ENDPOINT",
    "GKECluster",
    "gcp:expanded.gke_clusters_rest",
    "Public control-plane IP endpoint lacks source restrictions",
    "Kubernetes",
    gke_endpoint,
    (
        "Broad control-plane source access permits remote authentication "
        "attempts; cluster credentials and API authorization remain necessary."
    ),
    (
        "Restrict authorized networks or disable public IP endpoints; "
        "separately validate DNS endpoint IAM."
    ),
    GKE_DOC,
    "HIGH",
)
add(
    "GKE-WORKLOAD-IDENTITY",
    "GKECluster",
    "gcp:expanded.gke_clusters_rest",
    "Standard cluster has no workload identity pool",
    "Kubernetes",
    gke_workload,
    (
        "Without workload identity isolation, node credentials may be shared if"
        " metadata access is permitted."
    ),
    (
        "Enable Workload Identity Federation and verify per-workload bindings "
        "and node metadata configuration."
    ),
    GKE_DOC,
)
add(
    "GKE-NETWORK-POLICY",
    "GKECluster",
    "gcp:expanded.gke_clusters_rest",
    "Cluster network-policy enforcement disabled",
    "Kubernetes",
    gke_network,
    (
        "Disabled enforcement removes a workload segmentation mechanism; "
        "lateral reachability requires actual workload and network evidence."
    ),
    "Enable supported enforcement and validate namespace policies and application connectivity.",
    GKE_DOC,
)
add(
    "GKE-SECRETS-ENCRYPTION",
    "GKECluster",
    "gcp:expanded.gke_clusters_rest",
    "Review application-layer secrets encryption",
    "Kubernetes",
    gke_encryption,
    (
        "Customer-managed application-layer encryption has a separate policy "
        "objective from default encryption at rest."
    ),
    (
        "Compare application-layer encryption with the approved key-management "
        "requirement before planning a migration."
    ),
    GKE_DOC,
)
for kind, op in [
    ("RunService", "gcp:run.services.list"),
    ("Function", "gcp:expanded.functions_rest"),
]:
    label = "RUN" if kind == "RunService" else "FUNCTION"
    add(
        label + "-PUBLIC",
        kind,
        op,
        f"{label} public invocation configuration",
        "Serverless",
        serverless_public,
        (
            "Public invocation may allow unintended callers or consume application "
            "capacity; application authorization and intended audience decide the "
            "security gap."
        ),
        (
            "Confirm endpoint audience; restrict invoker access or ingress where "
            "private access is required, and verify application authentication."
        ),
        RUN_DOC,
    )
    add(
        label + "-RUNTIME-PRIVILEGE",
        kind,
        op,
        "Runtime identity has a broad basic-role binding",
        "Serverless",
        runtime_identity,
        (
            "A compromised workload could attempt actions allowed to its runtime "
            "identity; deny policies and effective permissions remain unresolved."
        ),
        (
            "Use a dedicated runtime identity with task-specific grants and verify "
            "inherited permissions before deployment."
        ),
        IAM_DOC,
        "HIGH",
    )
add(
    "GKE-NODE-PRIVILEGE",
    "GKENodePool",
    "gcp:container.nodePools.list",
    "GKE node identity has a broad basic-role binding",
    "Kubernetes",
    runtime_identity,
    (
        "A compromised node may expose a broadly privileged identity; "
        "pod-to-node access and effective permissions are unverified."
    ),
    (
        "Use a dedicated node service account and minimum documented GKE node "
        "roles; verify workload identity isolation."
    ),
    GKE_DOC,
    "HIGH",
)
add(
    "BQ-PUBLIC-DATA",
    "BigQueryDataset",
    "gcp:bigquery.datasets.get",
    "Public BigQuery dataset data-read grant",
    "Data Security",
    bigquery_public,
    (
        "A public principal has a role that permits table-data reads; query/job"
        " permissions and finer-grained controls still apply."
    ),
    (
        "Remove unintended public data grants and verify required sharing "
        "through authorized views or named principals."
    ),
    "https://docs.cloud.google.com/bigquery/docs/access-control-basic-roles",
    "HIGH",
)
add(
    "SQL-EXPLICIT-FLAGS",
    "SQLInstance",
    "gcp:expanded.sql_instances_rest",
    "Explicit database security-relevant flag values",
    "Database Security",
    sql_flags,
    (
        "Explicit engine flags can enable local file import, cross-database "
        "trust, external scripts or reduce connection auditing; the consequence"
        " depends on the engine."
    ),
    (
        "Review the specific engine/version and flagged explicit values; test "
        "the documented safer setting with the DBA before restart."
    ),
    "https://docs.cloud.google.com/sql/docs/mysql/flags",
)
add(
    "DNS-DNSSEC",
    "DNSZone",
    "gcp:expanded.dns_managed_zones",
    "DNSSEC disabled on a public DNS zone",
    "Network and Exposure",
    dnssec,
    (
        "Unsigned public responses lack DNSSEC authenticity protection; "
        "registrar delegation and resolver validation also matter."
    ),
    "Enable supported DNSSEC signing and verify DS delegation with the registrar.",
    "https://docs.cloud.google.com/dns/docs/dnssec-config",
)
add(
    "LB-TLS",
    "SSLPolicy",
    "gcp:expanded.ssl_policies",
    "Attached external proxy policy allows legacy TLS",
    "Edge Security",
    tls_policy,
    (
        "A policy attached through an external forwarding rule permits a legacy"
        " TLS protocol; endpoint handshakes were not tested."
    ),
    "Validate client compatibility and raise the attached policy minimum to TLS 1.2 or newer.",
    "https://docs.cloud.google.com/load-balancing/docs/ssl-policies-concepts",
)
for setting in ("armor", "logging"):
    add(
        "LB-" + setting.upper(),
        "BackendService",
        "gcp:expanded.backend_services",
        f"External HTTP backend {setting} configuration",
        "Edge Security",
        partial(backend_control, setting=setting),
        (
            "Backend protection and request logging support request filtering or "
            "investigation; a complete live frontend chain and application controls"
            " require separate verification."
        ),
        (
            f"Review the specific backend {setting} setting with its actual "
            f"frontend and required protection/telemetry objective."
        ),
        "https://docs.cloud.google.com/armor/docs/security-policy-overview",
    )
add(
    "NET-FIREWALL-POLICY",
    "FirewallPolicy",
    "gcp:expanded.firewall_policies",
    "Firewall policy has broad sensitive-port ingress allow",
    "Network and Exposure",
    firewall_policy,
    (
        "A broad policy allow can expand administrative or database attack "
        "surface if associated with relevant targets and not superseded."
    ),
    (
        "Verify policy association and priority, restrict source ranges and "
        "targets, and validate effective denies before claiming exposure."
    ),
    "https://docs.cloud.google.com/firewall/docs/firewall-policies",
)
add(
    "GOV-GUARDRAIL",
    "OrgPolicy",
    "gcp:orgpolicy.getEffectivePolicy",
    "Effective boolean security guardrail unenforced",
    "Governance",
    effective_guardrail,
    (
        "An unenforced effective guardrail permits resource-level weakening; "
        "actual configured resources remain independently assessable."
    ),
    (
        "Review the named constraint, workload exceptions and effective "
        "inheritance; enforce after compatibility validation."
    ),
    (
        "https://docs.cloud.google.com/resource-manager/docs/organization-polic"
        "y/understanding-constraints"
    ),
)
add(
    "LOG-AUDIT-COVERAGE",
    "IAMPolicy",
    "gcp:projects.getIamPolicy",
    "Review effective Data Access audit configuration",
    "Monitoring and Detection",
    audit_configuration,
    (
        "Audit metadata must be interpreted with inherited service coverage and"
        " exemptions; absence at project level does not establish a logging "
        "gap."
    ),
    (
        "Review effective parent/project audit configurations against required "
        "services and validate downstream delivery."
    ),
    "https://docs.cloud.google.com/logging/docs/audit/configure-data-access",
)
add(
    "MONITOR-ALERT-DISABLED",
    "AlertPolicy",
    "gcp:monitoring.alertPolicies.list",
    "Monitoring alert policy explicitly disabled",
    "Monitoring and Detection",
    alert_enabled,
    (
        "This disabled policy will not evaluate its configured conditions; "
        "redundant policies or intentional maintenance may compensate."
    ),
    (
        "Confirm the policy owner and maintenance intent; enable required "
        "coverage and test notification delivery."
    ),
    "https://docs.cloud.google.com/monitoring/alerts/manage-alerts",
    "LOW",
)
add(
    "SECRET-LIFECYCLE",
    "Secret",
    "gcp:expanded.secrets_rest",
    "Review secret lifecycle and rotation applicability",
    "Cryptography and Secrets",
    secret_lifecycle,
    (
        "Rotation is relevant only to secrets with a defined lifecycle; "
        "scheduler presence does not prove credential rotation."
    ),
    (
        "Identify secret purpose and approved lifecycle, then verify rotation "
        "in the owning system without collecting payloads."
    ),
    "https://docs.cloud.google.com/secret-manager/docs/secret-rotation",
)
add(
    "ARTIFACT-TAGS",
    "ArtifactRepository",
    "gcp:expanded.artifact_repositories_rest",
    "Review Docker artifact tag immutability",
    "Supply Chain",
    artifact_tags,
    (
        "Mutable image tags can change referenced content; digest pinning and "
        "signing may provide the intended control."
    ),
    (
        "Review artifact policy and deployment digest/signature controls before"
        " enabling immutable tags."
    ),
    "https://docs.cloud.google.com/artifact-registry/docs/docker/manage-images",
)
add(
    "BUILD-APPROVAL",
    "BuildTrigger",
    "gcp:expanded.cloudbuild_triggers_rest",
    "Review build trigger approval context",
    "Supply Chain",
    build_approval,
    (
        "Unreviewed build triggers may execute untrusted changes with pipeline "
        "privileges; source controls and IAM decide applicability."
    ),
    "Review trigger source trust, privileged service account grants and required approval policy.",
    "https://docs.cloud.google.com/build/docs/securing-builds/gate-builds-on-approval",
)
add(
    "PUBSUB-PUSH-AUTH",
    "PubSubSubscription",
    "gcp:expanded.pubsub_subscriptions",
    "Review push-subscription authentication",
    "Messaging",
    push_auth,
    (
        "Push authentication must match destination requirements; no OIDC field"
        " alone does not prove a publicly exploitable endpoint."
    ),
    (
        "Verify destination trust, OIDC audience and intended authentication "
        "using configuration evidence."
    ),
    "https://docs.cloud.google.com/pubsub/docs/authenticate-push-subscriptions",
)


add(
    "IAM-CUSTOM-PUBLIC",
    "IAMBinding",
    "gcp:projects.getIamPolicy",
    "Public custom role contains sensitive permissions",
    "Identity and Access",
    custom_public,
    (
        "A public principal is granted an observed sensitive custom permission;"
        " allow metadata does not establish effective access."
    ),
    (
        "Remove unintended public custom-role grants and review exact included "
        "permissions on the recorded policy subject."
    ),
    "https://docs.cloud.google.com/iam/docs/creating-custom-roles",
    "HIGH",
)
add(
    "WIF-SHARED-ISSUER",
    "WorkloadIdentityProvider",
    "gcp:iam.workloadIdentityPoolProviders.list",
    "Shared CI identity issuer lacks attribute restriction",
    "Identity and Access",
    oidc_condition,
    (
        "A shared CI issuer serves multiple organizations; missing "
        "organization-specific attribute restrictions broaden the accepted "
        "token population."
    ),
    (
        "Restrict the provider to approved numeric organization/repository "
        "claims and verify pool IAM grants and token audiences."
    ),
    "https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines",
    "HIGH",
)


def domain_rules() -> tuple[Rule, ...]:
    return tuple(
        Rule(
            rule_id=rid,
            version=VERSION,
            resource_type=s.kind,
            operation=s.operation,
            title=s.title,
            domain=s.domain,
            prerequisites=(s.operation,),
            evaluate=s.check,
            risk=s.risk,
            remediation=s.remediation,
            severity=s.severity,
            severity_rationale=s.risk
            + " Technical proposal; business criticality requires assessor approval.",
            provider="GCP",
            scope="GLOBAL",
            contextual=True,
            methodology=None,
            follow_up=(
                "Validate applicability, compensating controls and current source evidence",
            ),
        )
        for rid, s in SPECS.items()
    )
