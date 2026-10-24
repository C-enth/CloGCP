"""Render any attack-path record as a left-to-right chain: node -[what allows it]-> node.

Three record shapes exist: GCP transitions (source/destination/relationship), cross-project
and cross-cloud steps (ordered sentences), and AWS prerequisite records (anchor resource plus
specification prerequisites with their evidence status and the rules that evidence them).
The chain only restates the record; it adds no reachability or exploitation claim.
"""

from offline_analyzer.attack_paths.specs import BY_PATH


def diagram(path: dict) -> dict:
    """{"nodes": [{label, status, rules}], "edges": [{label, status}]} with len(edges)=n-1."""
    transitions = path.get("transitions") or []
    if transitions:
        nodes = [{"label": transitions[0]["source"], "status": "", "rules": []}]
        edges = []
        for t in transitions:
            edges.append({"label": t.get("relationship", ""), "status": t.get("status", "")})
            nodes.append({"label": t["destination"], "status": "", "rules": []})
        return {"nodes": nodes, "edges": edges}
    steps = path.get("steps") or []
    if steps:
        return {
            "nodes": [{"label": s, "status": "", "rules": []} for s in steps],
            "edges": [{"label": "", "status": ""} for _ in steps[1:]],
        }
    spec = BY_PATH.get(path.get("attack_path", ""))
    states = path.get("prerequisites") or {}
    nodes = [{"label": path.get("anchor") or path.get("title", ""), "status": "", "rules": []}]
    for prerequisite in spec.prerequisites if spec else ():
        nodes.append(
            {
                "label": prerequisite.summary,
                "status": states.get(prerequisite.key, "NOT_EVALUATED"),
                "rules": list(prerequisite.rules),
            }
        )
    return {"nodes": nodes, "edges": [{"label": "", "status": ""} for _ in nodes[1:]]}


def diagram_text(path: dict) -> str:
    """One line for spreadsheets and Word: A -[relationship]-> B [STATUS; rule R]."""
    chart = diagram(path)

    def node(n: dict) -> str:
        notes = [n["status"]] if n["status"] else []
        if n["rules"]:
            notes.append("rule " + ", ".join(n["rules"]))
        return n["label"] + (f" [{'; '.join(notes)}]" if notes else "")

    text = node(chart["nodes"][0]) if chart["nodes"] else ""
    for edge, target in zip(chart["edges"], chart["nodes"][1:], strict=True):
        label = edge["label"] + (f" ({edge['status']})" if edge["status"] else "")
        text += (f" -[{label}]-> " if label else " -> ") + node(target)
    return text
