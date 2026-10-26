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
            known = self.__dict__.setdefault("_by_id", {})
            for item in items:
                known.setdefault(item.observation_id, item)
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
        by_subnet, main_by_vpc = self._route_tables(region)
        table = by_subnet.get(subnet)
        if table is not None:
            return internet_route(table, ipv6), table.observation_id
        if self.coverage("ec2:DescribeRouteTables", account, region) != "COMPLETE":
            return "ROUTE_EVIDENCE_MISSING", None
        table = main_by_vpc.get(vpc)
        if table is not None:
            return internet_route(table, ipv6), table.observation_id
        return "ROUTE_EVIDENCE_MISSING", None

    def _route_tables(self, region: str):
        """First route table (observation order) per associated subnet and per VPC main
        association: the same answer as scanning the Region's tables in order."""
        cache = self.__dict__.setdefault("_route_cache", {})
        if region not in cache:
            by_subnet, main_by_vpc = {}, {}
            for table in self._index("AWS::EC2::RouteTable", region):
                associations = table.configuration.get("Associations") or []
                for association in associations:
                    subnet = association.get("SubnetId")
                    if isinstance(subnet, str):
                        by_subnet.setdefault(subnet, table)
                vpc = table.configuration.get("VpcId")
                if isinstance(vpc, str) and any(a.get("Main") is True for a in associations):
                    main_by_vpc.setdefault(vpc, table)
            cache[region] = (by_subnet, main_by_vpc)
        return cache[region]

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

    def by_native(self, kind: str, region: str, native) -> list[Normalized]:
        if not isinstance(native, str):  # same as the linear comparison it replaces
            return [i for i in self._index(kind, region) if i.native_id == native]
        return self._keyed(kind, region, native_key).get(native, [])

    def by_account(self, kind: str, region: str, account) -> list[Normalized]:
        if not isinstance(account, str):
            return [i for i in self._index(kind, region) if i.account_id == account]
        return self._keyed(kind, region, account_key).get(account, [])

    def instances(self, region: str) -> dict:
        """(account, instance ID) -> instance observation; the last observation wins, as a
        dict built over the Region's instances in observation order."""
        cache = self.__dict__.setdefault("_instance_cache", {})
        if region not in cache:
            cache[region] = {
                (i.account_id, i.native_id): i for i in self._index("AWS::EC2::Instance", region)
            }
        return cache[region]

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
        """scope_coverage over sources indexed once (same answer, no per-call scan)."""
        index = self.__dict__.get("_coverage_index")
        if index is None:
            index = {}
            for source in self.sources:
                key = (source["operation"], source["account_id"], source["region"])
                index.setdefault(key, []).append(source)
            self._coverage_index = index
        return scope_coverage(
            index.get((operation, account, region), []), operation, account, region
        )

    @property
    def iam(self):
        """Run-wide IAM analysis, built once on first use."""
        if "_iam" not in self.__dict__:
            from offline_analyzer.iam.analysis import IamAnalysis

            self._iam = IamAnalysis(self.store, self.run_id, self.sources, self.registry)
        return self._iam

    def observations_by_id(self, ids) -> list[Normalized]:
        """Observations of this run by ID (related evidence a verdict already cites)."""
        wanted = sorted(set(ids))
        if not wanted:
            return []
        # Observations already loaded by this context are reused; only misses are queried.
        known = self.__dict__.setdefault("_by_id", {})
        missing = [i for i in wanted if i not in known]
        if missing:
            for (data,) in self.store.rows(
                "SELECT data FROM observations WHERE run_id=? AND observation_id IN "
                "(SELECT unnest(?)) ORDER BY observation_id",
                [self.run_id, missing],
            ):
                item = Normalized.model_validate_json(data)
                known[item.observation_id] = item
        return [known[i] for i in wanted if i in known]

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
                self.__dict__.setdefault("_by_id", {})[interface.observation_id] = interface
                groups = interface.configuration.get("Groups")
                for group in groups if isinstance(groups, list) else ():
                    if isinstance(group, str):
                        index.setdefault(group, []).append(interface)
            self._interfaces[region] = index
        return self._interfaces[region].get(group_id, [])
