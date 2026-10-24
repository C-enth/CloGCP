"""Security-group internet ingress on sensitive ports (methodology AWS-15 clauses P1/F1).

FAIL requires two evidenced facts: the group permits 0.0.0.0/0 to an explicitly listed
sensitive TCP port, and an in-use, customer-managed network interface with a public IPv4
address references the group. NACLs, route tables, host firewalls and service
authentication are not evaluated, so FAIL is a configuration exposure, not reachability.
"""

from ipaddress import IPv4Network, IPv6Network, ip_network

from offline_analyzer.contracts.models import Outcome
from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.rules.configuration import Verdict

# Explicit list from the methodology; its trailing "etc." is a recorded review item.
SENSITIVE_TCP = (22, 3389, 1433, 3306, 5432, 6379, 9200, 27017)
# Treated as non-sensitive per the related exposure template's HTTP carve-out (MR-H03).
WEB_TCP = (80, 443)
PRIVATE = tuple(
    ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)
ICMP = {"icmp", "icmpv6", "1", "58"}
ENI_OPERATION = "ec2:DescribeNetworkInterfaces"
LIMITATIONS = (
    "NACLs, route tables, host firewalls and service authentication are not evaluated",
    "Interfaces in accounts whose interface evidence was not collected are not visible",
)


def ports(permission: dict) -> tuple[str, int, int] | None:
    protocol = permission.get("IpProtocol")
    protocol = str(protocol).lower() if isinstance(protocol, (str, int)) else None
    if protocol in {"-1", "all"}:
        return "all", 0, 65535
    if protocol in ICMP:
        return "icmp", 0, 0
    low, high = permission.get("FromPort"), permission.get("ToPort")
    if protocol in {"tcp", "6", "udp", "17"}:
        if type(low) is not int or type(high) is not int or not 0 <= low <= high <= 65535:
            return None
        return ("tcp" if protocol in {"tcp", "6"} else "udp"), low, high
    return ("other", 0, 65535) if protocol else None


def source_classes(permission: dict) -> set[str] | None:
    classes = set()
    for key, field in (("IpRanges", "CidrIp"), ("Ipv6Ranges", "CidrIpv6")):
        entries = permission.get(key, [])
        if not isinstance(entries, list):
            return None
        for entry in entries:
            value = entry.get(field) if isinstance(entry, dict) else None
            try:
                network = ip_network(value, strict=False)
            except (TypeError, ValueError):
                return None
            if network.prefixlen == 0:
                classes.add("internet-v4" if isinstance(network, IPv4Network) else "internet-v6")
            elif any(
                isinstance(network, type(private)) and network.subnet_of(private)
                for private in PRIVATE
                if isinstance(private, (IPv4Network, IPv6Network))
            ):
                classes.add("private")
            else:
                classes.add("public-restricted")
    prefix_lists = permission.get("PrefixListIds", [])
    if not isinstance(prefix_lists, list):
        return None
    if prefix_lists:
        classes.add("prefix-list")
    return classes


def describe(protocol: str, low: int, high: int) -> str:
    return "all traffic" if protocol == "all" else f"{protocol} {low}-{high}"


def classify(permissions) -> dict[str, list[str]] | None:
    found = {key: [] for key in ("v4", "v6", "restricted", "other")}
    for permission in permissions:
        if not isinstance(permission, dict):
            return None
        span, classes = ports(permission), source_classes(permission)
        if span is None or classes is None:
            return None
        protocol, low, high = span
        if protocol == "icmp":
            continue
        listed = [p for p in SENSITIVE_TCP if low <= p <= high]
        sensitive = protocol == "all" or (protocol == "tcp" and bool(listed))
        known = sum(low <= p <= high for p in SENSITIVE_TCP + WEB_TCP)
        other = protocol in {"all", "udp", "other"} or (high - low + 1) > known
        label = describe(protocol, low, high)
        if sensitive and "internet-v4" in classes:
            found["v4"].append(label)
        if sensitive and "internet-v6" in classes:
            found["v6"].append(label)
        if sensitive and classes & {"public-restricted", "prefix-list"}:
            found["restricted"].append(label)
        if other and classes & {"internet-v4", "internet-v6"}:
            found["other"].append(label)
    return found


def interface_facts(interface: Normalized) -> dict:
    config = interface.configuration
    public = [config.get("PublicIp")] + list(config.get("AddressPublicIps") or [])
    return {
        "in_use": config.get("Status") == "in-use",
        "status_known": isinstance(config.get("Status"), str),
        "public_v4": any(isinstance(ip, str) and ip for ip in public),
        "ipv6": (config.get("Ipv6AddressCount") or 0) > 0,
        # Load balancer/service-managed interfaces expose only their listener ports.
        "managed": config.get("RequesterManaged") is True
        or config.get("InterfaceType") not in (None, "interface"),
    }


def routing(interfaces, context) -> dict[str, list]:
    """Group interfaces by default-route status of their subnet, citing route tables."""
    statuses, tables = {}, []
    for interface in interfaces:
        config = interface.configuration
        status, table = context.route_status(
            interface.account_id, interface.region, config.get("VpcId"), config.get("SubnetId")
        )
        statuses.setdefault(status, []).append(interface)
        if table:
            tables.append(table)
    return {"by_status": statuses, "tables": sorted(set(tables))}


def exposure_verdict(obs, found, exposed, context, notes) -> Verdict:
    """Source F1 holds; finding class and severity follow routing evidence."""
    names = ", ".join(sorted({i.native_id or "unresolved" for i in exposed}))
    route = routing(exposed, context)
    by_status = route["by_status"]
    related = tuple(i.observation_id for i in exposed) + tuple(route["tables"])
    reasoning = (
        f"Ingress from 0.0.0.0/0 on sensitive port range(s) {', '.join(found['v4'])} "
        f"and the group is attached to in-use interface(s) with public IPv4: {names}."
    )
    review = tuple(f"Also requires review: {item}" for item in found["other"])
    later = ("NACL entries for the interface subnets", "host firewall and service exposure")
    if "INTERNET_ROUTE" in by_status:
        return Verdict(
            Outcome.FAIL,
            reasoning,
            related=related,
            limitations=notes + review,
            # An internet-gateway route is necessary, not sufficient: NACLs, host firewalls
            # and the listening service are unevaluated, so exposure stays potential.
            finding_class="POTENTIAL_EXPOSURE",
            severity="HIGH",
            exposure="Subnet default route targets an internet gateway; end-to-end "
            "reachability (NACL, host firewall, listening service) not demonstrated",
            evidence_needed=later,
        )
    if "ROUTE_EVIDENCE_MISSING" in by_status:
        return Verdict(
            Outcome.FAIL,
            reasoning,
            related=related,
            limitations=notes + review,
            finding_class="POTENTIAL_EXPOSURE",
            severity="MEDIUM",
            exposure="Routing evidence missing for the interface subnets; internet "
            "reachability not established",
            evidence_needed=(f"complete ec2:DescribeRouteTables for {obs.account_id}/{obs.region}",)
            + later,
        )
    return Verdict(
        Outcome.FAIL,
        reasoning,
        related=related,
        limitations=notes + review + ("Ingress routing and gateway edge associations not modeled",),
        finding_class="BASELINE_DEVIATION",
        severity="LOW",
        exposure="No default route to an internet gateway for the interface subnets; "
        "routing does not support inbound internet reachability",
        compensating=("Subnet routing without internet-gateway default route",),
    )


def sensitive_ingress(obs: Normalized, context) -> Verdict:
    group_id = obs.configuration.get("GroupId")
    permissions = obs.configuration.get("IpPermissions")
    if not isinstance(group_id, str) or not isinstance(permissions, list):
        return Verdict(
            Outcome.UNKNOWN,
            "Security group ID or ingress permissions are missing.",
            ("GroupId and IpPermissions",),
        )
    found = classify(permissions)
    if found is None:
        return Verdict(
            Outcome.UNKNOWN,
            "An ingress permission has an unrecognized protocol, port range or source.",
            ("well-formed IpPermissions",),
        )
    notes, manual, missing, related = list(LIMITATIONS), [], [], []
    coverage = context.coverage(ENI_OPERATION, obs.account_id, obs.region)
    interfaces = context.interfaces_for_group(obs.region, group_id)
    facts = {i.observation_id: interface_facts(i) for i in interfaces}
    if found["v4"]:
        public = [i for i in interfaces if facts[i.observation_id]["public_v4"]]
        exposed = [
            i
            for i in public
            if facts[i.observation_id]["in_use"] and not facts[i.observation_id]["managed"]
        ]
        if exposed:
            return exposure_verdict(obs, found, exposed, context, tuple(notes))
        if any(facts[i.observation_id]["in_use"] for i in public):
            related += [i.observation_id for i in public]
            manual.append(
                "sensitive ports open to 0.0.0.0/0 on a service-managed public interface; "
                "listener exposure needs load balancer/service evidence"
            )
        if any(not facts[i.observation_id]["status_known"] for i in public):
            missing.append("interface attachment status")
        if coverage != "COMPLETE":
            missing.append(f"complete {ENI_OPERATION} for {obs.account_id}/{obs.region}")
        if not manual and not missing:
            notes.append(
                "Latent exposure: group permits 0.0.0.0/0 to sensitive ports but no in-use "
                "public interface referenced it at collection time"
            )
    if found["v6"]:
        v6 = [
            i
            for i in interfaces
            if facts[i.observation_id]["ipv6"] and facts[i.observation_id]["in_use"]
        ]
        if v6:
            related += [i.observation_id for i in v6]
            statuses = sorted(
                {
                    context.route_status(
                        i.account_id,
                        i.region,
                        i.configuration.get("VpcId"),
                        i.configuration.get("SubnetId"),
                        ipv6=True,
                    )[0]
                    for i in v6
                }
            )
            # Source F1 names 0.0.0.0/0 only; IPv6 exposure is reported, not auto-failed.
            manual.append(
                f"::/0 ingress on {', '.join(found['v6'])} with IPv6-addressed interfaces "
                f"(IPv6 default route: {', '.join(statuses)}); the methodology criterion "
                "names 0.0.0.0/0 only"
            )
        elif coverage != "COMPLETE":
            missing.append(f"complete {ENI_OPERATION} for {obs.account_id}/{obs.region}")
    if found["restricted"]:
        manual.append(
            f"sensitive port range(s) {', '.join(found['restricted'])} open to public CIDRs or "
            "prefix lists; the approved CIDR list was not supplied"
        )
    if found["other"]:
        manual.append(
            f"other internet-exposed ranges {', '.join(found['other'])}; the methodology "
            "sensitive-port list is open-ended"
        )
    if missing:
        return Verdict(
            Outcome.UNKNOWN,
            "Internet-facing exposure cannot be determined: "
            + "; ".join(manual + [f"missing {m}" for m in missing])
            + ".",
            tuple(sorted(set(missing))),
            tuple(related),
            tuple(notes),
        )
    if manual:
        return Verdict(
            Outcome.MANUAL_VALIDATION_REQUIRED,
            "Analyst validation required: " + "; ".join(manual) + ".",
            ("analyst exposure validation",),
            tuple(related),
            tuple(notes),
        )
    return Verdict(
        Outcome.PASS,
        "No listed sensitive port is open to 0.0.0.0/0 or ::/0 on an in-use public interface.",
        related=tuple(related),
        limitations=tuple(notes),
    )


def port_sources(permissions, port: int) -> set[str] | None:
    """Source classes admitted to one TCP port; None if any permission is unreadable."""
    classes = set()
    for permission in permissions:
        if not isinstance(permission, dict):
            return None
        span, sources = ports(permission), source_classes(permission)
        if span is None or sources is None:
            return None
        protocol, low, high = span
        if protocol in {"all", "tcp"} and low <= port <= high:
            classes |= sources
    return classes
