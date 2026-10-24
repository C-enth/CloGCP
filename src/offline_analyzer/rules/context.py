"""Bounded, read-only access to related evidence for relationship-aware rules."""

from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.ingestion.json_input import InputError

MAX_RELATED_PER_SCOPE = 250_000


def scope_coverage(sources, operation: str, account: str | None, region: str | None) -> str:
    """COMPLETE only if every matching source is COMPLETE; errors dominate."""
    matching = [
        s
        for s in sources
        if s["operation"] == operation and s["account_id"] == account and s["region"] == region
    ]
    if not matching:
        return "NOT_COLLECTED"
    if any(s["effective_coverage"] == "ERROR" or s["errors"] for s in matching):
        return "ERROR"
    if all(s["effective_coverage"] == "COMPLETE" for s in matching):
        return "COMPLETE"
    return "PARTIAL"


def internet_route(table: Normalized | None, ipv6: bool = False) -> str:
    """INTERNET_ROUTE only for an active default route to an internet gateway."""
    if table is None:
        return "ROUTE_EVIDENCE_MISSING"
    routes = table.configuration.get("Routes")
    if not isinstance(routes, list):
        return "ROUTE_EVIDENCE_MISSING"
    key, default = (
        ("DestinationIpv6CidrBlock", "::/0") if ipv6 else ("DestinationCidrBlock", "0.0.0.0/0")
    )
    for route in routes:
        if not isinstance(route, dict) or route.get(key) != default:
            continue
        gateway = route.get("GatewayId")
        if route.get("State") not in (None, "active"):
            return "NO_INTERNET_ROUTE"
        if isinstance(gateway, str) and gateway.startswith("igw-"):
            return "INTERNET_ROUTE"
        return "NO_INTERNET_ROUTE"  # default route via NAT, TGW, firewall, peering, etc.
    return "NO_INTERNET_ROUTE"


class RelatedEvidence:
    """Cached per-Region indexes over related resources. Mixed into EvaluationContext."""

    def _index(self, kind: str, region: str) -> list[Normalized]:
        cache = self.__dict__.setdefault("_kinds", {})
        if (kind, region) not in cache:
            items = []
            for (data,) in self.store.rows(
                "SELECT data FROM observations WHERE run_id=? AND tool='aws' AND kind=? "
                "AND region=? ORDER BY observation_id",
                [self.run_id, kind, region],
            ):
                if len(items) >= MAX_RELATED_PER_SCOPE:
                    raise InputError("RELATED_EVIDENCE_LIMIT")
                items.append(Normalized.model_validate_json(data))
            cache[(kind, region)] = items
        return cache[(kind, region)]

    def route_status(self, account, region, vpc, subnet, ipv6=False) -> tuple[str, str | None]:
        """Route status for a subnet plus the route-table observation used.

        An explicit subnet association wins. Falling back to the VPC main table is valid
        only when the route-table listing for the account/Region is complete; otherwise an
        uncollected explicit association could be silently replaced.
        """
        if not subnet or not vpc:
            return "ROUTE_EVIDENCE_MISSING", None
        tables = self._index("AWS::EC2::RouteTable", region)
        for table in tables:
            for association in table.configuration.get("Associations") or []:
                if association.get("SubnetId") == subnet:
                    return internet_route(table, ipv6), table.observation_id
        if self.coverage("ec2:DescribeRouteTables", account, region) != "COMPLETE":
            return "ROUTE_EVIDENCE_MISSING", None
        for table in tables:
            if table.configuration.get("VpcId") == vpc and any(
                a.get("Main") is True for a in table.configuration.get("Associations") or []
            ):
                return internet_route(table, ipv6), table.observation_id
        return "ROUTE_EVIDENCE_MISSING", None

    def _keyed(self, kind: str, region: str, key) -> dict[str, list[Normalized]]:
        cache = self.__dict__.setdefault("_keyed_cache", {})
        name = (kind, region, key.__name__)
        if name not in cache:
            index: dict[str, list[Normalized]] = {}
            for item in self._index(kind, region):
                value = key(item)
                if isinstance(value, str):
                    index.setdefault(value, []).append(item)
            cache[name] = index
        return cache[name]

    def security_groups(self, region: str, group_id: str) -> list[Normalized]:
        return self._keyed("AWS::EC2::SecurityGroup", region, group_key).get(group_id, [])

    def resource_observations(self, kind: str, resource_id: str) -> list[Normalized]:
        return self._keyed(kind, "global", resource_key).get(resource_id, [])

    def account_bpa(self, account: str) -> list[Normalized]:
        return self._keyed("AWS::S3::AccountPublicAccessBlock", "global", account_key).get(
            account, []
        )

    def managed_policy(self, arn: str) -> list[Normalized]:
        return self._keyed("AWS::IAM::ManagedPolicy", "global", native_key).get(arn, [])


def group_key(item):
    return item.configuration.get("GroupId")


def resource_key(item):
    return item.resource_id


def account_key(item):
    return item.account_id


def native_key(item):
    return item.native_id


class EvaluationContext(RelatedEvidence):
    def __init__(self, store, run_id: str, sources: list[dict], registry=None):
        self.store = store
        self.run_id = run_id
        self.sources = sources
        # Approved account registry (may be empty); classification input only.
        self.registry = registry
        self._interfaces: dict[str, dict[str, list[Normalized]]] = {}

    def coverage(self, operation: str, account: str | None, region: str | None) -> str:
        return scope_coverage(self.sources, operation, account, region)

    @property
    def iam(self):
        """Run-wide IAM analysis, built once on first use."""
        if "_iam" not in self.__dict__:
            from offline_analyzer.iam.analysis import IamAnalysis

            self._iam = IamAnalysis(self.store, self.run_id, self.sources, self.registry)
        return self._iam

    def interfaces_for_group(self, region: str, group_id: str) -> list[Normalized]:
        """Network interfaces in the Region whose security-group list contains group_id.

        Security group IDs are Region-unique; interfaces from any collected account are
        considered so shared-VPC participants are included when their evidence exists.
        """
        if region not in self._interfaces:
            index: dict[str, list[Normalized]] = {}
            count = 0
            for (data,) in self.store.rows(
                "SELECT data FROM observations WHERE run_id=? AND tool='aws' AND kind=? "
                "AND region=? ORDER BY observation_id",
                [self.run_id, "AWS::EC2::NetworkInterface", region],
            ):
                count += 1
                if count > MAX_RELATED_PER_SCOPE:
                    raise InputError("RELATED_EVIDENCE_LIMIT")
                interface = Normalized.model_validate_json(data)
                groups = interface.configuration.get("Groups")
                for group in groups if isinstance(groups, list) else ():
                    if isinstance(group, str):
                        index.setdefault(group, []).append(interface)
            self._interfaces[region] = index
        return self._interfaces[region].get(group_id, [])
