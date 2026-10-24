"""Bounded indexes of collected GCP facts, never inferred asset relationships."""

from collections import defaultdict
from collections.abc import Iterator, Sequence

from offline_analyzer.contracts.r0 import Normalized
from offline_analyzer.rules.configuration import Verdict


def canonical(value: object) -> str:
    if not isinstance(value, str):
        return ""
    if "/projects/" in value:
        return "projects/" + value.split("/projects/", 1)[1].rstrip("/")
    return value.rstrip("/")


class GCPContext(Sequence[Normalized]):
    """One project view over shared run indexes. No cloud or raw-file access."""

    def __init__(
        self,
        observations: Sequence[Normalized],
        sources: Sequence[dict],
        project: str | None = None,
        *,
        index: tuple | None = None,
    ) -> None:
        if index is None:
            self.by_project = defaultdict(list)
            self.by_kind = defaultdict(list)
            self.by_network = defaultdict(list)
            self.sources = {s["artifact_id"]: s for s in sources if s.get("artifact_id")}
            self.by_id = {o.observation_id: o for o in observations}
            from offline_analyzer.rules.gcp_config import network_id

            for o in observations:
                self.by_project[o.project_id].append(o)
                self.by_kind[(o.project_id, o.resource_type)].append(o)
                networks = [o.configuration.get("network")]
                if o.resource_type == "GCP::ComputeInstance":
                    nics = o.configuration.get("networkInterfaces")
                    nics = nics if isinstance(nics, list) else []
                    networks = [n.get("network") for n in nics if isinstance(n, dict)]
                for n in {network_id(n) for n in networks} - {None}:
                    self.by_network[n].append(o)
        else:
            self.by_project, self.by_kind, self.by_network, self.sources, self.by_id = index
        self.project = project
        self.items = self.by_project.get(project, [])

    def for_project(self, project: str | None) -> "GCPContext":
        return GCPContext(
            [],
            [],
            project,
            index=(self.by_project, self.by_kind, self.by_network, self.sources, self.by_id),
        )

    def __len__(self) -> int:
        return len(self.items)

    def __getitem__(self, item: int | slice) -> Normalized | list[Normalized]:
        return self.items[item]

    def __iter__(self) -> Iterator[Normalized]:
        return iter(self.items)

    def of(self, kind: str) -> Sequence[Normalized]:
        return self.by_kind.get((self.project, kind), [])

    def complete(self, obs: Normalized) -> bool:
        return (
            self.sources.get(obs.evidence.artifact_id, {}).get("effective_coverage") == "COMPLETE"
        )

    def network(self, value: object) -> Sequence[Normalized]:
        from offline_analyzer.rules.gcp_config import network_id

        return self.by_network.get(network_id(value), [])

    def with_policy(self, policy: Normalized) -> "GCPContext":
        """Ephemeral rule-input projection of a collected CAI policy; nothing is persisted."""
        view = self.for_project(self.project)
        view.items = [*self.items, policy]
        view.by_kind = dict(self.by_kind)
        view.by_kind[(self.project, policy.resource_type)] = [
            *self.of(policy.resource_type),
            policy,
        ]
        return view


def of(context: Sequence[Normalized], kind: str, project: str | None) -> Sequence[Normalized]:
    if isinstance(context, GCPContext):
        return context.of(kind)
    return [o for o in context if o.project_id == project and o.resource_type == kind]


def usable(obs: Normalized) -> bool:
    return not obs.unresolved and obs.source_status in {
        "SUCCESS",
        "COMPLETE",
        "PARTIAL",
        "TRUNCATED",
    }


def complete(context: Sequence[Normalized], obs: Normalized) -> bool:
    return isinstance(context, GCPContext) and context.complete(obs)


def pool_guard(pools: Sequence[Normalized], covered: bool) -> Verdict | None:
    """A collected disabled parent pool blocks active federation applicability."""
    from offline_analyzer.contracts.models import Outcome

    if not pools:
        return None
    related = tuple(o.observation_id for o in pools)
    if not covered or any(not usable(o) for o in pools):
        return Verdict(
            Outcome.UNKNOWN,
            "Parent workload identity pool evidence is incomplete or unresolved.",
            ("Complete parent pool configuration",),
            related=related,
        )
    states = {
        True
        if o.configuration.get("state") == "DELETED"
        else o.configuration.get("disabled")
        if type(o.configuration.get("disabled")) is bool
        else None
        for o in pools
    }
    if len(states) > 1:
        return Verdict(
            Outcome.UNKNOWN,
            "Conflicting parent workload identity pool snapshots.",
            ("Consistent parent pool enabled/disabled configuration",),
            related=related,
        )
    if states == {True}:
        return Verdict(
            Outcome.NOT_APPLICABLE,
            (
                "The explicitly linked parent workload identity pool is "
                "disabled/deleted; active federation is not established."
            ),
            related=related,
        )
    return None
