"""Tests for utils/attack_graph — Node / Edge / Dijkstra critical paths."""

from __future__ import annotations

import pytest

from utils.attack_graph import (
    AttackGraph,
    Edge,
    Node,
)


pytestmark = pytest.mark.unit


# ── Node cost model ─────────────────────────────────────────────────────────


def test_node_cost_high_cvss_is_cheap_to_traverse():
    """High CVSS = high attacker-value = low traversal cost."""
    n = Node(id="x", cvss=9.5)
    assert n.cost <= 1.0


def test_node_cost_zero_cvss_falls_back_to_severity():
    assert Node(id="x", cvss=0, severity="critical").cost < Node(
        id="y", cvss=0, severity="low"
    ).cost


def test_node_cost_unknown_severity_uses_safe_default():
    n = Node(id="x", cvss=0, severity="mystery")
    assert n.cost == pytest.approx(8.0)


# ── Graph construction ─────────────────────────────────────────────────────


def test_add_edge_silently_ignores_missing_nodes():
    g = AttackGraph()
    g.add_node(Node(id="a"))
    g.add_edge(Edge(src="a", dst="missing"))
    assert g.edges == []


def test_from_findings_builds_asset_and_finding_nodes():
    findings = [
        {"type": "XSS_Param", "url": "https://t/a", "severity": "high", "cvss": 6.1},
        {"type": "SQLi_Param", "url": "https://t/b", "severity": "critical", "cvss": 9.8},
    ]
    g = AttackGraph.from_findings(findings)
    # 2 assets + 2 findings = 4 nodes; 2 asset→finding edges.
    assert len(g.nodes) == 4
    assert len(g.edges) == 2


def test_from_findings_dedupes_shared_asset():
    findings = [
        {"type": "XSS_Param", "url": "https://t/a"},
        {"type": "SQLi_Param", "url": "https://t/a"},  # same asset URL
    ]
    g = AttackGraph.from_findings(findings)
    assets = [n for n in g.nodes.values() if n.id.startswith("asset:")]
    assert len(assets) == 1


def test_from_findings_handles_bad_cvss():
    findings = [{"type": "X", "url": "x", "severity": "high", "cvss": "not-a-number"}]
    g = AttackGraph.from_findings(findings)
    assert any(n.cvss == 0.0 for n in g.nodes.values())


# ── Shortest-path / critical-path ──────────────────────────────────────────


def test_shortest_path_basic_chain():
    g = AttackGraph()
    for name in ("a", "b", "c", "d"):
        g.add_node(Node(id=name))
    g.add_edge(Edge(src="a", dst="b", weight=1))
    g.add_edge(Edge(src="b", dst="c", weight=1))
    g.add_edge(Edge(src="a", dst="c", weight=10))  # longer alt path
    g.add_edge(Edge(src="c", dst="d", weight=1))
    out = g.shortest_path("a", goal="d")
    cost, path = out["d"]
    assert cost == 3
    assert path == ["a", "b", "c", "d"]


def test_shortest_path_unreachable_returns_empty():
    g = AttackGraph()
    g.add_node(Node(id="a"))
    g.add_node(Node(id="b"))
    out = g.shortest_path("a", goal="b")
    assert out == {}


def test_shortest_path_invalid_source_returns_empty():
    g = AttackGraph()
    g.add_node(Node(id="a"))
    assert g.shortest_path("does-not-exist") == {}


def test_shortest_path_no_goal_returns_full_table():
    g = AttackGraph()
    for name in ("a", "b", "c"):
        g.add_node(Node(id=name))
    g.add_edge(Edge(src="a", dst="b", weight=2))
    g.add_edge(Edge(src="b", dst="c", weight=3))
    out = g.shortest_path("a")
    assert out["a"][0] == 0.0
    assert out["b"][0] == 2.0
    assert out["c"][0] == 5.0


def test_critical_paths_sorts_by_cost():
    g = AttackGraph()
    for name in ("entry", "low", "med", "high"):
        g.add_node(Node(id=name))
    g.add_edge(Edge(src="entry", dst="low", weight=5))
    g.add_edge(Edge(src="entry", dst="med", weight=2))
    g.add_edge(Edge(src="entry", dst="high", weight=1))
    paths = g.critical_paths("entry", top_n=3)
    costs = [p[1] for p in paths]
    assert costs == sorted(costs)
    # The cheapest path comes first.
    assert paths[0][0] == "high"


def test_critical_paths_respects_top_n():
    g = AttackGraph()
    for name in ["src"] + [f"n{i}" for i in range(10)]:
        g.add_node(Node(id=name))
    for i in range(10):
        g.add_edge(Edge(src="src", dst=f"n{i}", weight=float(i)))
    paths = g.critical_paths("src", top_n=3)
    assert len(paths) == 3


# ── Integration ────────────────────────────────────────────────────────────


def test_findings_to_critical_paths_realistic_scenario():
    findings = [
        {"type": "SSRF", "url": "https://t/api/fetch", "severity": "high", "cvss": 8.6},
        {"type": "Missing_HSTS", "url": "https://t/", "severity": "low", "cvss": 3.0},
        {"type": "SQLi_Param", "url": "https://t/api/users", "severity": "critical", "cvss": 9.8},
    ]
    g = AttackGraph.from_findings(findings)
    # Pick the asset node of the SSRF endpoint as an entry point.
    entry = "asset:https://t/api/fetch"
    paths = g.critical_paths(entry, top_n=5)
    # The SSRF finding itself is the cheapest neighbour (cost ~ 10 - 8.6).
    assert paths
    first_target, first_cost, _ = paths[0]
    assert "SSRF" in first_target


def test_to_dict_round_trips_shape():
    g = AttackGraph()
    g.add_node(Node(id="a", label="A", severity="high", cvss=7.0))
    g.add_node(Node(id="b", label="B", severity="critical", cvss=9.0))
    g.add_edge(Edge(src="a", dst="b", label="leads_to", weight=2.0))
    data = g.to_dict()
    assert {n["id"] for n in data["nodes"]} == {"a", "b"}
    assert data["edges"][0]["src"] == "a"
    assert data["edges"][0]["dst"] == "b"
