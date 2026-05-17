"""Directed attack graph + critical-path discovery, stdlib-only.

We deliberately avoid networkx — the operations we need are small
enough that a few hundred lines of stdlib do the job without a new
dependency footprint. The model:

* **Node** — a string ID. Convenience constructors mint IDs from
  findings (``T:type|U:url``) and assets (``asset:url``).
* **Edge** — directed, weighted. Weight = ``cost`` to traverse;
  lower cost = more attractive path for the attacker.
* **Critical path** — Dijkstra from any ``source`` node to a
  designated ``goal`` (or to every node when ``goal=None``).

A finding's CVSS score becomes its "cost" — high CVSS → low cost
(attractive). Defenders read the report as a heat-map; operators
read it to know where to start exploiting.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Iterable, Optional


# ── Core data shapes ───────────────────────────────────────────────────────


@dataclass
class Node:
    id: str
    label: str = ""
    severity: str = "info"
    cvss: float = 0.0
    asset_url: str = ""
    finding_type: str = ""

    @property
    def cost(self) -> float:
        """Attacker-cost: high-impact nodes are cheap to "use" as steps.

        CVSS 10.0 → cost 0.0; CVSS 0.0 → cost 10.0.
        Tied with severity floor so non-CVSS findings still rank.
        """
        if self.cvss > 0:
            return max(0.0, 10.0 - self.cvss)
        return {
            "critical": 1.0,
            "high": 3.0,
            "medium": 5.0,
            "low": 7.0,
            "info": 9.0,
        }.get(self.severity.lower(), 8.0)


@dataclass
class Edge:
    src: str
    dst: str
    label: str = ""
    weight: float = 1.0


@dataclass
class AttackGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    _adj: dict[str, list[Edge]] = field(default_factory=dict)

    # ── Mutation API ───────────────────────────────────────────────────────

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node
        self._adj.setdefault(node.id, [])

    def add_edge(self, edge: Edge) -> None:
        if edge.src not in self.nodes or edge.dst not in self.nodes:
            return  # silently ignore — caller likely missing a node insert
        self.edges.append(edge)
        self._adj[edge.src].append(edge)

    # ── Convenience builders ───────────────────────────────────────────────

    @staticmethod
    def from_findings(findings: Iterable[dict]) -> "AttackGraph":
        """Materialise findings + their asset edges into a graph."""
        graph = AttackGraph()
        for f in findings:
            url = str(f.get("url") or "unknown")
            f_type = str(f.get("type") or "Finding")
            severity = str(f.get("severity") or "info")
            try:
                cvss = float(f.get("cvss") or 0.0)
            except (TypeError, ValueError):
                cvss = 0.0

            asset_id = f"asset:{url}"
            finding_id = f"finding:{f_type}|{url}"

            if asset_id not in graph.nodes:
                graph.add_node(
                    Node(
                        id=asset_id,
                        label=url,
                        severity="info",
                        asset_url=url,
                    )
                )
            if finding_id not in graph.nodes:
                graph.add_node(
                    Node(
                        id=finding_id,
                        label=f_type,
                        severity=severity,
                        cvss=cvss,
                        asset_url=url,
                        finding_type=f_type,
                    )
                )
            # Edge from asset → finding ("asset is exploitable via …")
            graph.add_edge(
                Edge(
                    src=asset_id,
                    dst=finding_id,
                    label="exploitable_via",
                    weight=graph.nodes[finding_id].cost,
                )
            )
        return graph

    # ── Query ──────────────────────────────────────────────────────────────

    def shortest_path(
        self,
        source: str,
        goal: Optional[str] = None,
    ) -> dict[str, tuple[float, list[str]]]:
        """Dijkstra. Returns ``{node_id: (cost, path)}`` for every node
        reachable from ``source``. When ``goal`` is set, the result only
        contains that node.
        """
        if source not in self.nodes:
            return {}

        distances: dict[str, float] = {source: 0.0}
        predecessors: dict[str, Optional[str]] = {source: None}
        pq: list[tuple[float, str]] = [(0.0, source)]

        while pq:
            cost, current = heapq.heappop(pq)
            if cost > distances.get(current, float("inf")):
                continue
            if goal and current == goal:
                break
            for edge in self._adj.get(current, []):
                new_cost = cost + edge.weight
                if new_cost < distances.get(edge.dst, float("inf")):
                    distances[edge.dst] = new_cost
                    predecessors[edge.dst] = current
                    heapq.heappush(pq, (new_cost, edge.dst))

        def _walk(node: str) -> list[str]:
            path: list[str] = []
            while node is not None:
                path.append(node)
                node = predecessors.get(node)
            return list(reversed(path))

        if goal is not None:
            if goal not in distances:
                return {}
            return {goal: (distances[goal], _walk(goal))}

        return {
            node: (cost, _walk(node))
            for node, cost in distances.items()
        }

    def critical_paths(
        self,
        source: str,
        *,
        top_n: int = 5,
    ) -> list[tuple[str, float, list[str]]]:
        """Top-``top_n`` cheapest paths (most attractive to an attacker)."""
        all_paths = self.shortest_path(source)
        ranked = sorted(
            (
                (node, cost, path)
                for node, (cost, path) in all_paths.items()
                if node != source
            ),
            key=lambda x: x[1],
        )
        return ranked[:top_n]

    # ── Export ─────────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "severity": n.severity,
                    "cvss": n.cvss,
                    "asset_url": n.asset_url,
                    "finding_type": n.finding_type,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "src": e.src,
                    "dst": e.dst,
                    "label": e.label,
                    "weight": e.weight,
                }
                for e in self.edges
            ],
        }
