"""Evidence-backed GCP configuration criteria; no control-level compliance claims.

Rules consume normalized metadata. Missing and malformed fields remain UNKNOWN. Network
correlation establishes candidate exposure only, never effective reachability.
"""

import ipaddress
import re
from collections.abc import Callable
from decimal import Decimal, InvalidOperation

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.rules.configuration import Rule, Verdict
from offline_analyzer.rules.methodology_links import LINKS

VERSION = "1.1.0"
INTERNET = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP", 23: "Telnet", 5985: "WinRM", 5986: "WinRM-TLS"}
DB_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "SQL Server",
    1521: "Oracle",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5601: "Kibana",
    11211: "Memcached",
    9042: "Cassandra",
    5984: "CouchDB",
}
FULL_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
DEFAULT_SA = re.compile(r"^\d+-compute@developer\.gserviceaccount\.com$")
MAX_ROTATION_SECONDS = 90 * 24 * 3600
Check = Callable[[Normalized, list[Normalized]], Verdict]


def unknown(*fields: str) -> Verdict:
    return Verdict(
        Outcome.UNKNOWN, "Required configuration was not collected or is ambiguous.", fields
    )


def last(value: object) -> str:
    return str(value or "").rstrip("/").rsplit("/", 1)[-1]


def network_id(value: object) -> str | None:
    """Keep project-qualified identity; never correlate network names alone."""
    if not isinstance(value, str):
        return None
    match = re.search(r"(?:^|/)projects/([^/]+)/global/networks/([^/]+)$", value)
    return f"projects/{match[1]}/global/networks/{match[2]}" if match else None


def port_ranges(entries: object) -> list[tuple[str, int, int]] | None:
    """Validate protocols and ports; None means malformed, [] means no rules."""
    if not isinstance(entries, list):
        return None
    out = []
    for entry in entries:
        if not isinstance(entry, dict) or "IPProtocol" not in entry:
            return None
        protocol = str(entry["IPProtocol"]).lower()
        protocol = {"6": "tcp", "17": "udp"}.get(protocol, protocol)
        if not protocol or not (
            protocol.isdigit()
            or protocol
            in {
                "all",
                "tcp",
                "udp",
                "icmp",
                "esp",
                "ah",
                "sctp",
                "ipip",
                "icmpv6",
            }
        ):
            return None
        ports = entry.get("ports", [])
        if not isinstance(ports, list):
            return None
        if not ports:
            out.append((protocol, 0, 65535))
        for port in ports:
            match = re.fullmatch(r"(\d+)(?:-(\d+))?", str(port))
            if not match:
                return None
            lo, hi = int(match[1]), int(match[2] or match[1])
            if not 0 <= lo <= hi <= 65535:
                return None
            out.append((protocol, lo, hi))
    return out


def public_families(config: dict) -> set[int] | None:
    ranges = config.get("sourceRanges")
    if ranges is None or ranges == []:
        if config.get("sourceTags") or config.get("sourceServiceAccounts"):
            return set()
        return {4}  # GCP's documented default ingress source.
    if not isinstance(ranges, list):
        return None
    networks: dict[int, list] = {4: [], 6: []}
    for cidr in ranges:
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            return None
        networks[network.version].append(network)
    return {
        family
        for family, entries in networks.items()
        if any(n.prefixlen == 0 for n in ipaddress.collapse_addresses(entries))
    }


def targets_label(config: dict) -> str:
    tags, accounts_ = config.get("targetTags"), config.get("targetServiceAccounts")
    if tags:
        return "instances tagged " + ", ".join(map(str, tags[:5]))
    if accounts_:
        return "instances running as " + ", ".join(map(str, accounts_[:3]))
    return "all instances in the network"


def instance_matches(rule: dict, instance: dict) -> bool:
    tags, accounts_ = rule.get("targetTags"), rule.get("targetServiceAccounts")
    if tags:
        return bool(set(tags) & set((instance.get("tags") or {}).get("items") or []))
    if accounts_:
        emails = {
            a.get("email") for a in instance.get("serviceAccounts") or [] if isinstance(a, dict)
        }
        return bool(set(accounts_) & emails)
    return True


def external_ip(
    instance: dict, network: str | None = None, families: set[int] | None = None
) -> list[str]:
    ips = []
    for nic in instance.get("networkInterfaces") or []:
        if not isinstance(nic, dict) or (network and network_id(nic.get("network")) != network):
            continue
        for key, family in (("accessConfigs", 4), ("ipv6AccessConfigs", 6)):
            if families is not None and family not in families:
                continue
            for access in nic.get(key) or []:
                if not isinstance(access, dict):
                    continue
                address = access.get("natIP") or access.get("externalIpv6")
                if address:
                    ips.append(str(address))
        if (families is None or 6 in families) and nic.get("externalIpv6"):
            ips.append(str(nic["externalIpv6"]))
    return ips


def priority(config: dict) -> int | None:
    value = config.get("priority", 1000)
    if type(value) is not int or not 0 <= value <= 65535:
        return None
    return value


def range_denied(checked: tuple[str, int, int], denied: list[tuple[str, int, int]]) -> bool:
    protocol, lo, hi = checked
    # Conservative: a single deny must cover the whole tested range/protocol.
    return any((p == "all" or p == protocol) and a <= lo and b >= hi for p, a, b in denied)


def firewall(obs: Normalized, context: list[Normalized], ports: dict[int, str] | None) -> Verdict:
    if hasattr(context, "network"):
        context = context.network(obs.configuration.get("network"))
    c = obs.configuration
    if c.get("direction", "INGRESS") == "EGRESS" or c.get("disabled") is True:
        return Verdict(
            Outcome.NOT_APPLICABLE, "Egress or disabled rule; inbound check does not apply."
        )
    if c.get("direction", "INGRESS") != "INGRESS" or c.get("disabled", False) not in (True, False):
        return unknown("direction / disabled")
    allowed = port_ranges(c.get("allowed", []))
    families = public_families(c)
    if allowed is None or families is None or ("allowed" not in c and "denied" not in c):
        return unknown("allowed / denied protocols and sourceRanges")
    if not allowed or not families:
        return Verdict(Outcome.PASS, "Rule has no unrestricted internet-source allow clause.")
    every_port = any(
        p == "all" or (p in {"tcp", "udp"} and lo == 0 and hi == 65535) for p, lo, hi in allowed
    )
    if ports is not None and every_port:
        return Verdict(
            Outcome.NOT_APPLICABLE, "All-ports exposure is evaluated once by the all-ports check."
        )
    checked = (
        [
            (p, lo, hi)
            for p, lo, hi in allowed
            if p == "all" or (p in {"tcp", "udp"} and lo == 0 and hi == 65535)
        ]
        if ports is None
        else [
            ("tcp", port, port)
            for port in sorted(ports)
            if any(p in {"all", "tcp"} and lo <= port <= hi for p, lo, hi in allowed)
        ]
    )
    if not checked:
        return Verdict(
            Outcome.PASS, "Internet-source rule does not allow the checked protocols/ports."
        )
    network, rank = network_id(c.get("network")), priority(c)
    if network is None or rank is None:
        return unknown("project-qualified network / valid priority")
    blockers, partial = [], []
    for other in context:
        d = other.configuration
        if (
            other.project_id != obs.project_id
            or other.resource_type != "GCP::Firewall"
            or other.observation_id == obs.observation_id
            or other.unresolved
            or other.source_status not in {"SUCCESS", "COMPLETE"}
            or network_id(d.get("network")) != network
            or d.get("direction", "INGRESS") != "INGRESS"
            or d.get("disabled") is True
        ):
            continue
        other_rank, other_families = priority(d), public_families(d)
        denied = port_ranges(d.get("denied", []))
        if (
            other_rank is None
            or other_rank > rank
            or other_families is None
            or not families <= other_families
            or not denied
        ):
            continue
        if all(range_denied(item, denied) for item in checked):
            (partial if d.get("targetTags") or d.get("targetServiceAccounts") else blockers).append(
                other
            )
    if blockers:
        return Verdict(
            Outcome.PASS,
            "Checked traffic is covered by an equal/higher-priority VPC deny.",
            related=tuple(o.observation_id for o in blockers),
            limitations=("Other effective policies and network reachability not evaluated",),
        )
    exposed = [
        o
        for o in context
        if o.resource_type == "GCP::ComputeInstance"
        and not o.unresolved
        and o.source_status in {"SUCCESS", "COMPLETE"}
        and o.configuration.get("status") == "RUNNING"
        and instance_matches(c, o.configuration)
        and external_ip(o.configuration, network, families)
    ]
    exposure = (
        f"POTENTIAL: {len(exposed)} collected matching instance(s) have an external IP."
        if exposed
        else "UNRESOLVED: no matching external endpoint established from collected evidence."
    )
    limits = [
        "Hierarchical/network firewall policies, routes, listeners and reachability not evaluated"
    ]
    if partial:
        limits.append("A deny with narrower targets may block some matching instances")
    return Verdict(
        Outcome.FAIL,
        f"Unrestricted IPv{','.join(map(str, sorted(families)))} ingress permits "
        f"{checked[:6]} on {targets_label(c)} in {network} (priority {rank}). {exposure}",
        related=tuple(o.observation_id for o in exposed + partial),
        limitations=tuple(limits),
        exposure=exposure,
        severity="HIGH" if exposed else "MEDIUM",
        finding_class="POTENTIAL_EXPOSURE" if exposed else "BASELINE_DEVIATION",
    )


def default_network(obs: Normalized, _context: list[Normalized]) -> Verdict:
    name = obs.configuration.get("name")
    if not isinstance(name, str) or not name:
        return unknown("name")
    return Verdict(
        Outcome.FAIL if name == "default" else Outcome.PASS,
        "Network named default exists; review its actual rules and workload use."
        if name == "default"
        else "Network is not named default.",
    )


def regular_subnet(c: dict) -> bool:
    return c.get("purpose") in {None, "", "PRIVATE", "PRIVATE_RFC_1918"}


def boolean_setting(
    value: object, field: str, on_text: str, off_text: str, *, fail_when: bool = False
) -> Verdict:
    if type(value) is not bool:
        return unknown(field)
    failed = value is fail_when
    return Verdict(Outcome.FAIL if failed else Outcome.PASS, on_text if value else off_text)


def flow_logs(obs: Normalized, _context: list[Normalized]) -> Verdict:
    c = obs.configuration
    if not regular_subnet(c):
        return Verdict(Outcome.NOT_APPLICABLE, f"Subnet purpose {c.get('purpose')}.")
    config = c.get("logConfig")
    value = config.get("enable") if isinstance(config, dict) else c.get("enableFlowLogs")
    return boolean_setting(
        value,
        "logConfig.enable / enableFlowLogs",
        "Subnet flow logging is enabled.",
        "Subnet flow logging is disabled.",
    )


def private_access(obs: Normalized, _context: list[Normalized]) -> Verdict:
    c = obs.configuration
    if not regular_subnet(c):
        return Verdict(Outcome.NOT_APPLICABLE, f"Subnet purpose {c.get('purpose')}.")
    return boolean_setting(
        c.get("privateIpGoogleAccess"),
        "privateIpGoogleAccess",
        "Private Google Access enabled.",
        "Private Google Access disabled.",
    )


def metadata(c: dict) -> dict[str, str]:
    return {
        str(i.get("key")): str(i.get("value", "")).strip().lower()
        for i in (c.get("metadata") or {}).get("items") or []
        if isinstance(i, dict)
    }


def vm_external_ip(obs: Normalized, _context: list[Normalized]) -> Verdict:
    ips = external_ip(obs.configuration)
    if ips:
        return Verdict(
            Outcome.FAIL,
            f"Assigned external address(es): {', '.join(ips[:3])}.",
            exposure="External IP assigned; effective reachability unresolved.",
            finding_class="POTENTIAL_EXPOSURE",
        )
    nics = obs.configuration.get("networkInterfaces")
    if not isinstance(nics, list) or any(not isinstance(n, dict) for n in nics):
        return unknown("networkInterfaces")
    for nic in nics:
        if not any(key in nic for key in ("accessConfigs", "ipv6AccessConfigs")):
            return unknown("Explicit network interface external-access configuration")
        for key in ("accessConfigs", "ipv6AccessConfigs"):
            value = nic.get(key, [])
            if not isinstance(value, list) or value:
                return unknown(
                    "Assigned address for configured external access / valid accessConfigs"
                )
    return Verdict(Outcome.PASS, "Collected interfaces explicitly have no external access configs.")


def accounts(c: dict) -> list[dict] | None:
    value = c.get("serviceAccounts")
    if not isinstance(value, list) or any(
        not isinstance(a, dict) or not a.get("email") for a in value
    ):
        return None
    return value


def default_sa(obs: Normalized, _context: list[Normalized]) -> Verdict:
    attached = accounts(obs.configuration)
    if attached is None:
        return unknown("serviceAccounts[].email")
    used = [a["email"] for a in attached if DEFAULT_SA.fullmatch(str(a["email"]))]
    return Verdict(
        Outcome.FAIL if used else Outcome.PASS,
        f"Default Compute service account attached: {used[0]}; privileges unresolved."
        if used
        else "No default Compute service account attached.",
    )


def full_scope(obs: Normalized, _context: list[Normalized]) -> Verdict:
    attached = accounts(obs.configuration)
    if attached is None:
        return unknown("serviceAccounts[].email/scopes")
    defaults = [a for a in attached if DEFAULT_SA.fullmatch(str(a["email"]))]
    if any(not isinstance(a.get("scopes"), list) for a in defaults):
        return unknown("serviceAccounts[].scopes")
    wide = any(FULL_SCOPE in a["scopes"] for a in defaults)
    return Verdict(
        Outcome.FAIL if wide else Outcome.PASS,
        "Default service account uses cloud-platform scope; IAM grants still bound access. "
        "Scope alone establishes no elevated permission."
        if wide
        else "No default account with cloud-platform scope observed.",
    )


def inherited_metadata(obs: Normalized, context: list[Normalized], key: str):
    """Instance override, then collected Compute project metadata; never RM display data."""
    own = metadata(obs.configuration)
    if key in own:
        return own[key], ()
    inherited = []
    for project in context:
        c = project.configuration
        if (
            project.project_id != obs.project_id
            or project.unresolved
            or project.source_status not in {"SUCCESS", "COMPLETE"}
        ):
            continue
        if project.resource_type == "GCP::Project":
            data = c
        elif (
            project.resource_type == "GCP::AssetResourceSnapshot"
            and c.get("assetType") == "compute.googleapis.com/Project"
        ):
            data = nested(c, "resource", "data") or {}
        else:
            continue
        common = data.get("commonInstanceMetadata")
        if isinstance(common, dict):
            values = metadata({"metadata": common})
            if key in values:
                inherited.append((values[key], project.observation_id))
    if inherited and len({v for v, _ in inherited}) == 1:
        return inherited[0][0], tuple(oid for _, oid in inherited)
    return None, ()


def explicit_metadata(key: str, bad: str, good_text: str, bad_text: str) -> Check:
    def check(obs: Normalized, context: list[Normalized]) -> Verdict:
        if key == "enable-oslogin" and windows_vm(obs):
            return Verdict(
                Outcome.NOT_APPLICABLE,
                ("OS Login does not apply to the collected Windows guest license."),
            )
        value, related = inherited_metadata(obs, context, key)
        if value not in {"true", "false", "1", "0"}:
            return unknown(f"instance metadata '{key}' or project-wide metadata")
        failed = value in ({"true", "1"} if bad == "true" else {"false", "0"})
        return Verdict(
            Outcome.FAIL if failed else Outcome.PASS,
            (bad_text if failed else good_text)
            + (" From collected project metadata." if related else " From instance override."),
            related=related,
        )

    return check


def project_ssh_keys(obs: Normalized, context: list[Normalized]) -> Verdict:
    if windows_vm(obs):
        return Verdict(
            Outcome.NOT_APPLICABLE,
            (
                "Linux metadata SSH-key criterion does not apply to the collected "
                "Windows guest license."
            ),
        )
    values = {
        key: inherited_metadata(obs, context, key)
        for key in ("enable-oslogin", "block-project-ssh-keys")
    }
    meta = {key: pair[0] for key, pair in values.items()}
    refs = tuple(dict.fromkeys(oid for _, ids in values.values() for oid in ids))
    if meta.get("block-project-ssh-keys") in {"true", "1"} or meta.get("enable-oslogin") in {
        "true",
        "1",
    }:
        return Verdict(
            Outcome.PASS,
            "Project keys blocked or effective collected OS Login enabled.",
            related=refs,
        )
    if meta.get("block-project-ssh-keys") in {"false", "0"} and meta.get("enable-oslogin") in {
        "false",
        "0",
    }:
        return Verdict(
            Outcome.FAIL,
            (
                "Collected effective metadata disables OS Login and accepts project "
                "keys; actual key use is unverified."
            ),
            related=refs,
        )
    # Project-wide OS Login can still make explicit key acceptance ineffective.
    return unknown("Effective project/instance OS Login and project SSH-key configuration")


def shielded(obs: Normalized, _context: list[Normalized]) -> Verdict:
    config = obs.configuration.get("shieldedInstanceConfig")
    if not isinstance(config, dict):
        return unknown("shieldedInstanceConfig and image support")
    keys = ("enableSecureBoot", "enableVtpm", "enableIntegrityMonitoring")
    off = [k for k in keys if config.get(k) is False]
    if off:
        return Verdict(Outcome.FAIL, "Explicitly disabled Shielded VM settings: " + ", ".join(off))
    if any(config.get(k) is not True for k in keys):
        return unknown("Complete shieldedInstanceConfig")
    return Verdict(Outcome.PASS, "Secure Boot, vTPM and integrity monitoring enabled.")


def ip_forward(obs: Normalized, _context: list[Normalized]) -> Verdict:
    return boolean_setting(
        obs.configuration.get("canIpForward"),
        "canIpForward",
        "IP forwarding enabled; validate appliance exception.",
        "IP forwarding disabled.",
        fail_when=True,
    )


def nested(c: dict, *path: str):
    value = c
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def ubla(obs: Normalized, _context: list[Normalized]) -> Verdict:
    c = obs.configuration
    value = c.get("uniform_bucket_level_access")
    if value is None:
        value = nested(c, "iamConfiguration", "uniformBucketLevelAccess", "enabled")
    if value is None:
        value = nested(c, "iamConfiguration", "bucketPolicyOnly", "enabled")
    return boolean_setting(
        value,
        "uniform bucket-level access",
        "Uniform bucket-level access enabled.",
        "Object ACL access remains enabled.",
    )


def pap(obs: Normalized, context: list[Normalized]) -> Verdict:
    c = obs.configuration
    value = c.get("public_access_prevention") or nested(
        c, "iamConfiguration", "publicAccessPrevention"
    )
    if value == "enforced":
        return Verdict(Outcome.PASS, "Public access prevention enforced on bucket.")
    if value != "inherited":
        return unknown("Recognized bucket public access prevention setting")
    from offline_analyzer.rules.gcp import boolean_enforcement, constraint_name

    # Accept project-effective v1/v2 evidence, never ancestor policy inventory alone.
    policies = [
        o
        for o in context
        if o.project_id == obs.project_id
        and o.resource_type == "GCP::OrgPolicy"
        and not o.unresolved
        and o.source_status in {"SUCCESS", "COMPLETE"}
        and constraint_name(o.configuration) == "storage.publicAccessPrevention"
        and nested(o.configuration, "_parameters", "effective") in (True, "true")
    ]
    values = [boolean_enforcement(o.configuration)[0] for o in policies]
    if not values or any(type(v) is not bool for v in values) or len(set(values)) != 1:
        return unknown(
            "Consistent unconditional effective storage.publicAccessPrevention enforcement"
        )
    enforced = values[0]
    return Verdict(
        Outcome.PASS if enforced else Outcome.FAIL,
        "Effective inherited public access prevention enforced."
        if enforced
        else "Bucket inherits an explicitly unenforced effective public access prevention policy.",
        related=tuple(o.observation_id for o in policies),
    )


def versioning(obs: Normalized, _context: list[Normalized]) -> Verdict:
    c = obs.configuration
    value = c.get("versioning_enabled")
    if value is None:
        value = nested(c, "versioning", "enabled")
    soft_delete = nested(c, "softDeletePolicy", "retentionDurationSeconds")
    if (
        value is False
        and isinstance(soft_delete, (int, str))
        and str(soft_delete).isdigit()
        and int(soft_delete) > 0
    ):
        return Verdict(
            Outcome.MANUAL_VALIDATION_REQUIRED,
            (
                f"Versioning disabled; soft-delete retention={soft_delete}s is "
                f"recorded. Recovery objectives and overwrites require review."
            ),
            evidence_needed=(
                ("Approved recovery objective, soft-delete and overwrite-protection requirements"),
            ),
        )
    return boolean_setting(
        value,
        "versioning.enabled / versioning_enabled",
        "Object versioning enabled.",
        "Object versioning disabled; review recovery controls.",
    )


def windows_vm(obs: Normalized) -> bool:
    disks = obs.configuration.get("disks")
    if not isinstance(disks, list):
        return False
    return any(
        isinstance(d, dict)
        and isinstance(d.get("licenses"), list)
        and any(
            isinstance(v, str) and "/projects/windows-cloud/global/licenses/" in v
            for v in d["licenses"]
        )
        for d in disks
    )


def sql_ip(c: dict) -> dict:
    value = nested(c, "settings", "ipConfiguration")
    return value if isinstance(value, dict) else {}


def sql_open(obs: Normalized, _context: list[Normalized]) -> Verdict:
    ip = sql_ip(obs.configuration)
    if ip.get("ipv4Enabled") is False:
        return Verdict(Outcome.PASS, "Public IPv4 disabled.")
    if ip.get("ipv4Enabled") is not True or not isinstance(ip.get("authorizedNetworks"), list):
        return unknown("settings.ipConfiguration.ipv4Enabled / authorizedNetworks")
    networks = ip["authorizedNetworks"]
    if any(not isinstance(n, dict) or not isinstance(n.get("value"), str) for n in networks):
        return unknown("authorizedNetworks[].value")
    try:
        open_ = any(ipaddress.ip_network(n["value"], strict=False).prefixlen == 0 for n in networks)
    except ValueError:
        return unknown("valid authorizedNetworks[].value")
    return Verdict(
        Outcome.FAIL if open_ else Outcome.PASS,
        "Public IPv4 enabled with unrestricted authorized network; authentication still required."
        if open_
        else "No unrestricted authorized network observed.",
        exposure="Potential public database exposure; reachability unverified." if open_ else None,
    )


def sql_public(obs: Normalized, _context: list[Normalized]) -> Verdict:
    return boolean_setting(
        sql_ip(obs.configuration).get("ipv4Enabled"),
        "ipv4Enabled",
        "Public IPv4 enabled; effective access unresolved.",
        "Public IPv4 disabled.",
        fail_when=True,
    )


def sql_tls(obs: Normalized, _context: list[Normalized]) -> Verdict:
    ip = sql_ip(obs.configuration)
    mode = ip.get("sslMode")
    if mode in {"ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}:
        return Verdict(Outcome.PASS, f"SSL mode {mode}.")
    if mode == "ALLOW_UNENCRYPTED_AND_ENCRYPTED":
        return Verdict(Outcome.FAIL, f"SSL mode {mode}.")
    if mode is not None:
        return unknown("recognized sslMode")
    return boolean_setting(
        ip.get("requireSsl"),
        "sslMode / requireSsl",
        "SSL/TLS required.",
        "Unencrypted connections permitted.",
        fail_when=False,
    )


def sql_backup(obs: Normalized, _context: list[Normalized]) -> Verdict:
    if obs.configuration.get("instanceType") == "READ_REPLICA_INSTANCE":
        return Verdict(
            Outcome.NOT_APPLICABLE, "Read replica; assess backups on primary separately."
        )
    return boolean_setting(
        nested(obs.configuration, "settings", "backupConfiguration", "enabled"),
        "settings.backupConfiguration.enabled",
        "Automated backups enabled.",
        "Automated backups disabled.",
    )


def seconds(value: object) -> Decimal | None:
    try:
        if not re.fullmatch(r"\d+(?:\.\d+)?s", str(value)):
            return None
        return Decimal(str(value)[:-1])
    except InvalidOperation:
        return None


def kms_rotation(obs: Normalized, _context: list[Normalized], complete: bool = False) -> Verdict:
    """`complete`: the key came from a COMPLETE dataset. Only then is an omitted rotation
    schedule read: Cloud KMS disables automatic rotation by clearing both `rotationPeriod` and
    `nextRotationTime` ("Never (manual rotation)"; docs/RULE_SPECIFICATIONS.md)."""
    c = obs.configuration
    purpose = c.get("purpose")
    if purpose in {"ASYMMETRIC_SIGN", "ASYMMETRIC_DECRYPT", "MAC"}:
        return Verdict(Outcome.NOT_APPLICABLE, "Automatic rotation not supported for this purpose.")
    if purpose != "ENCRYPT_DECRYPT":
        return unknown("purpose")
    if complete and "rotationPeriod" not in c and "nextRotationTime" not in c:
        return Verdict(
            Outcome.FAIL,
            "No rotation schedule (rotationPeriod and nextRotationTime absent): automatic "
            "rotation is disabled for this key.",
        )
    period = seconds(c.get("rotationPeriod"))
    if period is None or period <= 0:
        return unknown(
            "positive rotationPeriod; absence does not establish collection completeness"
        )
    failed = period > MAX_ROTATION_SECONDS
    return Verdict(
        Outcome.FAIL if failed else Outcome.PASS,
        f"Rotation period {period}s; engineering baseline is at most 90 days.",
    )


def log_retention(obs: Normalized, _context: list[Normalized]) -> Verdict:
    c = obs.configuration
    if last(c.get("name")) == "_Required":
        return Verdict(Outcome.NOT_APPLICABLE, "_Required bucket has service-managed retention.")
    days = c.get("retentionDays")
    if type(days) is not int or days <= 0:
        return unknown("positive retentionDays")
    return Verdict(
        Outcome.MANUAL_VALIDATION_REQUIRED,
        f"Observed retention: {days} days; compare with the approved retention objective.",
        evidence_needed=("Approved log-retention period and scope",),
    )


# ---------------------------------------------------------------- definitions
# rule id: (resource type, operation, title, domain, risk, remediation, severity, class, evaluate)
DEFINITIONS = {
    "GCP-NET-FW-ADMIN-INTERNET": (
        "GCP::Firewall",
        "gcp:compute.firewalls.list",
        "Firewall rule allows SSH/RDP or other administrative ports from the internet",
        "Network and Exposure",
        (
            "Administrative services reachable from any internet address face password guessing and"
            " exploitation of the service itself."
        ),
        (
            "Restrict source ranges to approved administration networks or use IAP TCP forwarding; "
            "remove 0.0.0.0/0 from the rule."
        ),
        "HIGH",
        "BASELINE_DEVIATION",
        lambda o, c: firewall(o, c, ADMIN_PORTS),
    ),
    "GCP-NET-FW-DB-INTERNET": (
        "GCP::Firewall",
        "gcp:compute.firewalls.list",
        "Firewall rule allows database ports from the internet",
        "Network and Exposure",
        (
            "Database listeners reachable from the internet expose authentication and the database "
            "engine to any attacker."
        ),
        (
            "Remove internet source ranges for database ports; reach databases through private "
            "networks or approved proxies."
        ),
        "HIGH",
        "BASELINE_DEVIATION",
        lambda o, c: firewall(o, c, DB_PORTS),
    ),
    "GCP-NET-FW-ANY-INTERNET": (
        "GCP::Firewall",
        "gcp:compute.firewalls.list",
        "Firewall rule allows all ports from the internet",
        "Network and Exposure",
        (
            "An all-ports rule could expose unintended services if endpoints, effective policies "
            "and routing permit traffic. Reachability is unresolved."
        ),
        "Replace with rules allowing only the required ports from required sources.",
        "HIGH",
        "BASELINE_DEVIATION",
        lambda o, c: firewall(o, c, None),
    ),
    "GCP-NET-DEFAULT-NETWORK": (
        "GCP::Network",
        "gcp:compute.networks.list",
        "Default VPC network exists",
        "Network and Exposure",
        (
            "The default network comes with permissive pre-populated firewall rules and subnets in "
            "every region, weakening segmentation."
        ),
        "Migrate workloads to purpose-built VPCs and delete the default network.",
        "MEDIUM",
        "BASELINE_DEVIATION",
        default_network,
    ),
    "GCP-NET-FLOW-LOGS": (
        "GCP::Subnet",
        "gcp:expanded.subnets",
        "VPC Flow Logs disabled on subnet",
        "Monitoring and Detection",
        (
            "Disabled subnet flow logging reduces connection evidence from this configuration; "
            "other logging mechanisms require separate validation."
        ),
        "Enable VPC Flow Logs on the subnet with an appropriate sampling rate.",
        "LOW",
        "BASELINE_DEVIATION",
        flow_logs,
    ),
    "GCP-NET-PRIVATE-GOOGLE-ACCESS": (
        "GCP::Subnet",
        "gcp:expanded.subnets",
        "Private Google Access disabled on subnet",
        "Network and Exposure",
        (
            "Private Google Access is one private API-connectivity mechanism; validate workload "
            "requirements and alternative private endpoints before assessing exposure."
        ),
        "Enable Private Google Access on subnets whose instances call Google APIs.",
        "LOW",
        "BASELINE_DEVIATION",
        private_access,
    ),
    "GCP-VM-EXTERNAL-IP": (
        "GCP::ComputeInstance",
        "gcp:compute.instances.list",
        "VM instance has an external IP address",
        "Workload Security",
        (
            "An external IP makes the instance directly addressable from the internet whenever a "
            "firewall rule allows it."
        ),
        "Remove external IPs; use Cloud NAT for egress and IAP or load balancers for ingress.",
        "MEDIUM",
        "POTENTIAL_EXPOSURE",
        vm_external_ip,
    ),
    "GCP-VM-DEFAULT-SA": (
        "GCP::ComputeInstance",
        "gcp:compute.instances.list",
        "VM instance uses the default compute service account",
        "Workload Security",
        (
            "A shared default identity can couple workload access. Its effective IAM privileges "
            "require separate evidence; default identity does not imply Editor access."
        ),
        "Attach a dedicated least-privilege service account to the instance.",
        "MEDIUM",
        "BASELINE_DEVIATION",
        default_sa,
    ),
    "GCP-VM-FULL-API-SCOPE": (
        "GCP::ComputeInstance",
        "gcp:compute.instances.list",
        "VM instance uses the default service account with full API access",
        "Workload Security",
        (
            "cloud-platform scope allows token use across API families, subject to effective IAM "
            "grants. It grants no IAM permission by itself."
        ),
        "Use a dedicated service account with only the required roles, or restrict access scopes.",
        "LOW",
        "BASELINE_DEVIATION",
        full_scope,
    ),
    "GCP-VM-SERIAL-PORT": (
        "GCP::ComputeInstance",
        "gcp:compute.instances.list",
        "Interactive serial console enabled on VM instance",
        "Workload Security",
        (
            "The interactive serial console allows connections from any IP address to anyone with "
            "the required IAM permission, bypassing firewall rules."
        ),
        (
            "Set metadata serial-port-enable to false and enforce the "
            "compute.disableSerialPortAccess organization policy."
        ),
        "MEDIUM",
        "BASELINE_DEVIATION",
        explicit_metadata(
            "serial-port-enable",
            "true",
            "Interactive serial console is disabled.",
            "Interactive serial console is enabled on the instance.",
        ),
    ),
    "GCP-VM-OSLOGIN": (
        "GCP::ComputeInstance",
        "gcp:compute.instances.list",
        "OS Login disabled on VM instance",
        "Workload Security",
        (
            "Without OS Login, SSH access is governed by metadata keys rather than IAM, so access "
            "is harder to control and revoke."
        ),
        "Enable OS Login (metadata enable-oslogin=TRUE) at project or instance level.",
        "MEDIUM",
        "BASELINE_DEVIATION",
        explicit_metadata(
            "enable-oslogin",
            "false",
            "OS Login is enabled on the instance.",
            "OS Login is explicitly disabled on the instance.",
        ),
    ),
    "GCP-VM-PROJECT-SSH-KEYS": (
        "GCP::ComputeInstance",
        "gcp:compute.instances.list",
        "Project-wide SSH keys allowed on VM instance",
        "Workload Security",
        "A project-wide SSH key grants access to every instance that accepts project keys.",
        "Set block-project-ssh-keys to true on the instance or use OS Login.",
        "MEDIUM",
        "BASELINE_DEVIATION",
        project_ssh_keys,
    ),
    "GCP-VM-SHIELDED": (
        "GCP::ComputeInstance",
        "gcp:compute.instances.list",
        "Shielded VM protections disabled",
        "Workload Security",
        (
            "Without Secure Boot, vTPM and integrity monitoring, boot-level tampering (rootkits, "
            "bootkits) is neither prevented nor detected."
        ),
        (
            "Enable Secure Boot, vTPM and integrity monitoring (requires a Shielded VM image; stop "
            "the instance to change)."
        ),
        "LOW",
        "BASELINE_DEVIATION",
        shielded,
    ),
    "GCP-VM-IP-FORWARD": (
        "GCP::ComputeInstance",
        "gcp:compute.instances.list",
        "IP forwarding enabled on VM instance",
        "Workload Security",
        (
            "An instance that forwards packets can route or spoof traffic for other addresses if "
            "compromised."
        ),
        (
            "Disable IP forwarding unless the instance is an approved network appliance (recreate "
            "the instance)."
        ),
        "LOW",
        "BASELINE_DEVIATION",
        ip_forward,
    ),
    "GCP-STORAGE-UBLA": (
        "GCP::Bucket",
        "gcp:storage.buckets.list",
        "Uniform bucket-level access disabled",
        "Data Protection",
        (
            "With fine-grained ACLs, individual objects can be shared outside IAM, making access "
            "hard to review."
        ),
        "Enable uniform bucket-level access after migrating any ACL-based grants to IAM.",
        "MEDIUM",
        "BASELINE_DEVIATION",
        ubla,
    ),
    "GCP-STORAGE-PAP": (
        "GCP::Bucket",
        "gcp:storage.buckets.list",
        "Public access prevention not enforced on bucket",
        "Data Protection",
        (
            "Without public access prevention, a single IAM or ACL change can make the bucket's "
            "data public."
        ),
        (
            "Enforce public access prevention on the bucket or via the "
            "storage.publicAccessPrevention organization policy."
        ),
        "LOW",
        "BASELINE_DEVIATION",
        pap,
    ),
    "GCP-STORAGE-VERSIONING": (
        "GCP::Bucket",
        "gcp:storage.buckets.list",
        "Object versioning disabled on bucket",
        "Data Protection",
        (
            "Disabled versioning reduces one recovery mechanism. Soft delete, retention and "
            "independent backup controls require separate validation."
        ),
        (
            "Enable object versioning (with lifecycle rules to bound cost) on buckets holding "
            "important data."
        ),
        "LOW",
        "BASELINE_DEVIATION",
        versioning,
    ),
    "GCP-SQL-OPEN-NETWORK": (
        "GCP::SQLInstance",
        "gcp:expanded.cloud_sql",
        "Cloud SQL instance authorizes all internet addresses",
        "Network and Exposure",
        (
            "An authorized network of 0.0.0.0/0 lets any internet address reach the database "
            "listener and attempt authentication."
        ),
        (
            "Remove 0.0.0.0/0; use private IP or the Cloud SQL Auth Proxy, or authorize specific "
            "networks only."
        ),
        "HIGH",
        "POTENTIAL_EXPOSURE",
        sql_open,
    ),
    "GCP-SQL-PUBLIC-IP": (
        "GCP::SQLInstance",
        "gcp:expanded.cloud_sql",
        "Cloud SQL instance has a public IP address",
        "Network and Exposure",
        (
            "A public IP makes the database reachable from authorized internet networks instead of "
            "only the private network."
        ),
        "Disable public IP after validating private connectivity and connector settings.",
        "MEDIUM",
        "POTENTIAL_EXPOSURE",
        sql_public,
    ),
    "GCP-SQL-TLS": (
        "GCP::SQLInstance",
        "gcp:expanded.cloud_sql",
        "Cloud SQL instance allows unencrypted connections",
        "Data Protection",
        (
            "Unencrypted database connections expose credentials and data to anyone able to observe"
            " the network path."
        ),
        "Set SSL mode to ENCRYPTED_ONLY (or require trusted client certificates).",
        "MEDIUM",
        "BASELINE_DEVIATION",
        sql_tls,
    ),
    "GCP-SQL-BACKUP": (
        "GCP::SQLInstance",
        "gcp:expanded.cloud_sql",
        "Cloud SQL automated backups disabled",
        "Data Protection",
        (
            "Disabled automated backups reduce recovery options; independent backup systems "
            "require analyst validation."
        ),
        "Enable automated backups (and point-in-time recovery where required).",
        "MEDIUM",
        "BASELINE_DEVIATION",
        sql_backup,
    ),
    "GCP-KMS-ROTATION": (
        "GCP::KMSKey",
        "gcp:cloudkms.cryptoKeys.list",
        "KMS rotation period exceeds the 90-day engineering baseline",
        "Data Protection",
        (
            "Without regular rotation, one key version protects data indefinitely, enlarging the "
            "impact of key exposure."
        ),
        "Set an automatic rotation period of 90 days or less on symmetric keys.",
        "MEDIUM",
        "BASELINE_DEVIATION",
        kms_rotation,
    ),
    "GCP-LOG-RETENTION": (
        "GCP::LogBucket",
        "gcp:logging.buckets.list",
        "Log bucket retention requires validation",
        "Monitoring and Detection",
        (
            "Logs deleted before the required retention period cannot support investigations or "
            "compliance evidence."
        ),
        (
            "Set log bucket retention to the organization's required period (and lock it where "
            "required)."
        ),
        "LOW",
        "BASELINE_DEVIATION",
        log_retention,
    ),
}


def bounded_check(check: Check) -> Check:
    def evaluate(obs: Normalized, context: list[Normalized], **options) -> Verdict:
        try:
            return check(obs, context, **options)
        except (TypeError, ValueError, AttributeError, KeyError):
            # Normalized JSON is untrusted metadata, not a typed service response.
            return unknown("Valid service configuration field types")

    return evaluate


EVALUATORS = {rid: bounded_check(d[8]) for rid, d in DEFINITIONS.items()}


# E5 (rules/gcp_principal_context.py): attached service-account privilege context.
VERSIONS = {
    "GCP-KMS-ROTATION": "1.2.0",  # phase 3: omitted rotation schedule from complete evidence
    "GCP-VM-DEFAULT-SA": "1.2.0",
    "GCP-VM-FULL-API-SCOPE": "1.2.0",
    "GCP-NET-FW-ADMIN-INTERNET": "1.2.0",
    "GCP-NET-FW-DB-INTERNET": "1.2.0",
    "GCP-NET-FW-ANY-INTERNET": "1.2.0",
}


def config_rules() -> tuple[Rule, ...]:
    return tuple(
        Rule(
            rid,
            VERSIONS.get(rid, VERSION),
            kind,
            operation,
            title,
            domain,
            (operation,),
            lambda obs, context=None, _rid=rid: EVALUATORS[_rid](obs, context or []),
            risk,
            remediation,
            severity,
            (
                "Severity reflects the observed configuration; exposure and business impact require"
                " analyst validation."
            ),
            scope="GLOBAL",
            contextual=True,
            context_operations=("gcp:compute.instances.list",)
            if kind == "GCP::Firewall"
            else ("gcp:storage.buckets.get", "gcp:orgpolicy.getEffectivePolicy")
            if kind == "GCP::Bucket"
            else (),
            provider="GCP",
            finding_class=finding_class,
            follow_up=(
                "Validate configuration ownership, workload dependencies and business impact",
            ),
            methodology=LINKS[rid],
        )
        for rid, (
            kind,
            operation,
            title,
            domain,
            risk,
            remediation,
            severity,
            finding_class,
            _,
        ) in DEFINITIONS.items()
    )


# Finding-detail guidance: (weakness, principle, highlight fields, expected values,
# remediation command for review, read-only verification command).
NET, LEAST, LOG, DATA = (
    "Minimal exposure / secure defaults",
    "Least privilege",
    "Accountability: complete, tamper-evident audit logging",
    "Data protection at rest",
)
DETAIL = {
    "GCP-NET-FW-ADMIN-INTERNET": (
        "Public exposure (network)",
        NET,
        ("sourceRanges", "allowed", "ports", "targetTags", "priority", "direction"),
        (("sourceRanges", "approved administration networks, not 0.0.0.0/0"),),
        "gcloud compute firewall-rules update <rule> --source-ranges=<approved-cidr>",
        (
            "gcloud compute firewall-rules describe <rule> "
            "--format='json(sourceRanges,allowed,targetTags,priority)'"
        ),
    ),
    "GCP-NET-FW-DB-INTERNET": (
        "Public exposure (database ports)",
        NET,
        ("sourceRanges", "allowed", "ports", "targetTags", "priority", "direction"),
        (("sourceRanges", "private networks only for database ports"),),
        "gcloud compute firewall-rules update <rule> --source-ranges=<approved-cidr>",
        "gcloud compute firewall-rules describe <rule> --format='json(sourceRanges,allowed)'",
    ),
    "GCP-NET-FW-ANY-INTERNET": (
        "Public exposure (all ports)",
        NET,
        ("sourceRanges", "allowed", "IPProtocol", "ports", "targetTags", "priority"),
        (("allowed", "only required protocols and ports"),),
        "",
        "gcloud compute firewall-rules describe <rule> --format='json(sourceRanges,allowed)'",
    ),
    "GCP-NET-DEFAULT-NETWORK": (
        "Insecure default network",
        NET,
        ("name", "autoCreateSubnetworks"),
        (("name", "no network named 'default'"),),
        "gcloud compute networks delete default  # after moving workloads and rules",
        "gcloud compute networks list --format='value(name,autoCreateSubnetworks)'",
    ),
    "GCP-NET-FLOW-LOGS": (
        "Insufficient logging (network)",
        LOG,
        ("logConfig", "enable", "enableFlowLogs"),
        (("enable", "true"),),
        "gcloud compute networks subnets update <subnet> --region=<region> --enable-flow-logs",
        (
            "gcloud compute networks subnets describe <subnet> --region=<region> "
            "--format='json(logConfig)'"
        ),
    ),
    "GCP-NET-PRIVATE-GOOGLE-ACCESS": (
        "Exposure through external egress",
        NET,
        ("privateIpGoogleAccess",),
        (("privateIpGoogleAccess", "true"),),
        (
            "gcloud compute networks subnets update <subnet> --region=<region> "
            "--enable-private-ip-google-access"
        ),
        (
            "gcloud compute networks subnets describe <subnet> --region=<region> "
            "--format='value(privateIpGoogleAccess)'"
        ),
    ),
    "GCP-VM-EXTERNAL-IP": (
        "Public exposure (instance)",
        NET,
        ("accessConfigs", "natIP", "networkInterfaces"),
        (("accessConfigs", "absent (no external IP)"),),
        (
            "gcloud compute instances delete-access-config <instance> --zone=<zone> "
            "--access-config-name='External NAT'"
        ),
        (
            "gcloud compute instances describe <instance> --zone=<zone> "
            "--format='json(networkInterfaces[].accessConfigs)'"
        ),
    ),
    "GCP-VM-DEFAULT-SA": (
        "Excessive permissions (workload identity)",
        LEAST,
        ("serviceAccounts", "email"),
        (("email", "dedicated least-privilege service account"),),
        (
            "gcloud compute instances set-service-account <instance> --zone=<zone> "
            "--service-account=<sa> --scopes=cloud-platform  # instance must be stopped"
        ),
        (
            "gcloud compute instances describe <instance> --zone=<zone> "
            "--format='json(serviceAccounts)'"
        ),
    ),
    "GCP-VM-FULL-API-SCOPE": (
        "Excessive permissions (workload identity)",
        LEAST,
        ("serviceAccounts", "email", "scopes"),
        (("email", "dedicated service account with reviewed least-privilege IAM grants"),),
        (
            "gcloud compute instances set-service-account <instance> --zone=<zone> "
            "--service-account=<sa> --scopes=cloud-platform  # instance must be stopped"
        ),
        (
            "gcloud compute instances describe <instance> --zone=<zone> "
            "--format='json(serviceAccounts)'"
        ),
    ),
    "GCP-VM-SERIAL-PORT": (
        "Weak access restriction (console)",
        NET,
        ("metadata", "items", "serial-port-enable"),
        (("serial-port-enable", "false"),),
        (
            "gcloud compute instances add-metadata <instance> --zone=<zone> "
            "--metadata=serial-port-enable=false"
        ),
        (
            "gcloud compute instances describe <instance> --zone=<zone> "
            "--format='json(metadata.items)'"
        ),
    ),
    "GCP-VM-OSLOGIN": (
        "Weak access restriction (SSH)",
        LEAST,
        ("metadata", "items", "enable-oslogin"),
        (("enable-oslogin", "TRUE"),),
        (
            "gcloud compute instances add-metadata <instance> --zone=<zone> "
            "--metadata=enable-oslogin=TRUE"
        ),
        (
            "gcloud compute instances describe <instance> --zone=<zone> "
            "--format='json(metadata.items)'"
        ),
    ),
    "GCP-VM-PROJECT-SSH-KEYS": (
        "Weak access restriction (SSH keys)",
        LEAST,
        ("metadata", "items", "block-project-ssh-keys", "enable-oslogin"),
        (("block-project-ssh-keys", "true"),),
        (
            "gcloud compute instances add-metadata <instance> --zone=<zone> "
            "--metadata=block-project-ssh-keys=TRUE"
        ),
        (
            "gcloud compute instances describe <instance> --zone=<zone> "
            "--format='json(metadata.items)'"
        ),
    ),
    "GCP-VM-SHIELDED": (
        "Missing boot integrity protection",
        NET,
        ("shieldedInstanceConfig", "enableSecureBoot", "enableVtpm", "enableIntegrityMonitoring"),
        (
            ("enableSecureBoot", "true"),
            ("enableVtpm", "true"),
            ("enableIntegrityMonitoring", "true"),
        ),
        (
            "gcloud compute instances update <instance> --zone=<zone> --shielded-secure-boot "
            "--shielded-vtpm --shielded-integrity-monitoring  # instance must be stopped"
        ),
        (
            "gcloud compute instances describe <instance> --zone=<zone> "
            "--format='json(shieldedInstanceConfig)'"
        ),
    ),
    "GCP-VM-IP-FORWARD": (
        "Network spoofing capability",
        NET,
        ("canIpForward",),
        (("canIpForward", "false"),),
        "",
        "gcloud compute instances describe <instance> --zone=<zone> --format='value(canIpForward)'",
    ),
    "GCP-STORAGE-UBLA": (
        "Weak access restriction (object ACLs)",
        LEAST,
        ("uniform_bucket_level_access", "uniformBucketLevelAccess", "enabled"),
        (("uniform_bucket_level_access", "true"),),
        "gcloud storage buckets update gs://<bucket> --uniform-bucket-level-access",
        (
            "gcloud storage buckets describe gs://<bucket> "
            "--format='value(uniform_bucket_level_access)'"
        ),
    ),
    "GCP-STORAGE-PAP": (
        "Public exposure guardrail missing (data)",
        NET,
        ("public_access_prevention", "publicAccessPrevention"),
        (("public_access_prevention", "enforced"),),
        "gcloud storage buckets update gs://<bucket> --public-access-prevention",
        "gcloud storage buckets describe gs://<bucket> --format='value(public_access_prevention)'",
    ),
    "GCP-STORAGE-VERSIONING": (
        "Missing recoverability",
        DATA,
        ("versioning_enabled", "versioning", "enabled"),
        (("versioning_enabled", "true"),),
        "gcloud storage buckets update gs://<bucket> --versioning",
        "gcloud storage buckets describe gs://<bucket> --format='value(versioning_enabled)'",
    ),
    "GCP-SQL-OPEN-NETWORK": (
        "Public exposure (database)",
        NET,
        ("ipv4Enabled", "authorizedNetworks", "value"),
        (("authorizedNetworks", "no 0.0.0.0/0 entry"),),
        "gcloud sql instances patch <instance> --authorized-networks=<approved-cidr>",
        "gcloud sql instances describe <instance> --format='json(settings.ipConfiguration)'",
    ),
    "GCP-SQL-PUBLIC-IP": (
        "Public exposure (database)",
        NET,
        ("ipv4Enabled", "authorizedNetworks"),
        (("ipv4Enabled", "false"),),
        "gcloud sql instances patch <instance> --no-assign-ip  # requires private IP connectivity",
        (
            "gcloud sql instances describe <instance> "
            "--format='value(settings.ipConfiguration.ipv4Enabled)'"
        ),
    ),
    "GCP-SQL-TLS": (
        "Missing encryption in transit",
        DATA,
        ("sslMode", "requireSsl"),
        (("sslMode", "ENCRYPTED_ONLY"),),
        "gcloud sql instances patch <instance> --ssl-mode=ENCRYPTED_ONLY",
        (
            "gcloud sql instances describe <instance> "
            "--format='value(settings.ipConfiguration.sslMode)'"
        ),
    ),
    "GCP-SQL-BACKUP": (
        "Missing recoverability",
        DATA,
        ("backupConfiguration", "enabled"),
        (("enabled", "true"),),
        "gcloud sql instances patch <instance> --backup-start-time=<HH:MM>",
        "gcloud sql instances describe <instance> --format='json(settings.backupConfiguration)'",
    ),
    "GCP-KMS-ROTATION": (
        "Key management weakness",
        "Credential lifecycle hygiene",
        ("rotationPeriod", "nextRotationTime", "purpose"),
        (("rotationPeriod", "7776000s (90 days) or less"),),
        (
            "gcloud kms keys update <key> --keyring=<ring> --location=<location> "
            "--rotation-period=90d --next-rotation-time=<time>"
        ),
        (
            "gcloud kms keys describe <key> --keyring=<ring> --location=<location> "
            "--format='value(rotationPeriod)'"
        ),
    ),
    "GCP-LOG-RETENTION": (
        "Log retention unverified",
        LOG,
        ("retentionDays", "locked"),
        (("retentionDays", "the organization's required period"),),
        "gcloud logging buckets update <bucket> --location=<location> --retention-days=<days>",
        (
            "gcloud logging buckets describe <bucket> --location=<location> "
            "--format='value(retentionDays,locked)'"
        ),
    ),
}
