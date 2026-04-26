"""
cyberm4fia-scanner — MCP (Model Context Protocol) Tool Surface

Exposes a small, curated set of scanner capabilities as MCP tools so external
agents (Claude Desktop, Cursor, custom Claude Agent SDK clients, …) can drive
the scanner programmatically.

Design split
------------
* ``ToolSpec`` + ``TOOLS`` — pure-Python registry. Each entry has a name,
  description, JSON-schema for inputs, and a handler. This layer has no MCP
  SDK dependency, so it's trivially unit-testable.
* ``dispatch(name, arguments)`` — pure dispatch into the registry. Used by
  tests and by the actual MCP runtime.
* ``serve_stdio()`` — optional. Starts a real MCP server over stdio if the
  official ``mcp`` SDK is installed. Raises ``RuntimeError`` with an install
  hint if the SDK is missing.

Run as a server
---------------
    python -m utils.mcp_server          # stdio mode (requires `mcp` SDK)

Adding a new tool: append a ``ToolSpec`` to ``TOOLS`` and write a unit test
that exercises ``dispatch("...", {...})``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from utils.meta_tools import (
    parse_nmap_xml,
    parse_nuclei_jsonl,
    parse_sqlmap_json,
    summarize_for_ai,
)


# ─── Registry primitives ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict], Any]
    tags: tuple[str, ...] = field(default=())


def _schema(properties: dict, required: list[str]) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


# ─── Handlers ────────────────────────────────────────────────────────────────


def _handle_parse_nmap_xml(args: dict) -> dict:
    xml_text = str(args.get("xml") or "")
    scan = parse_nmap_xml(xml_text)
    return {
        "host_count": len(scan.hosts),
        "open_port_count": scan.open_port_count,
        "summary": summarize_for_ai(scan),
        "hosts": [
            {
                "address": h.address,
                "hostname": h.hostname,
                "open_ports": [
                    {
                        "port": p.port,
                        "protocol": p.protocol,
                        "service": p.service,
                        "product": p.product,
                        "version": p.version,
                    }
                    for p in h.open_ports
                ],
            }
            for h in scan.hosts
        ],
    }


def _handle_parse_nuclei_jsonl(args: dict) -> dict:
    jsonl = str(args.get("jsonl") or "")
    findings = parse_nuclei_jsonl(jsonl)
    return {
        "count": len(findings),
        "critical_count": sum(1 for f in findings if f.is_critical),
        "summary": summarize_for_ai(findings),
        "findings": [
            {
                "template_id": f.template_id,
                "name": f.name,
                "severity": f.severity,
                "matched_at": f.matched_at,
                "host": f.host,
                "cvss": f.cvss,
                "tags": list(f.tags),
            }
            for f in findings
        ],
    }


def _handle_parse_sqlmap_json(args: dict) -> dict:
    payload = args.get("json") or args.get("payload")
    result = parse_sqlmap_json(payload)
    return {
        "vulnerable": result.vulnerable,
        "target": result.target,
        "db_type": result.db_type,
        "injections": [
            {
                "parameter": inj.parameter,
                "place": inj.place,
                "technique": inj.technique,
                "payload": inj.payload,
            }
            for inj in result.injections
        ],
        "summary": summarize_for_ai(result),
    }


def _handle_run_intent_agent(args: dict) -> dict:
    """Run the intent-driven exploit agent. Imports lazily so that tests not
    exercising this tool don't pay the LLM-client init cost."""
    from utils.ai_intent_agent import Intent, get_intent_agent

    agent = get_intent_agent()
    if agent is None:
        return {
            "success": False,
            "summary": "AI client not available; check NVIDIA_API_KEY",
            "iterations": 0,
        }
    intent = Intent(
        goal=str(args.get("goal") or ""),
        target_url=str(args.get("target_url") or ""),
        param=str(args.get("param") or ""),
        vuln_type=str(args.get("vuln_type") or ""),
        http_method=str(args.get("http_method") or "GET"),
        notes=str(args.get("notes") or ""),
        constraints=list(args.get("constraints") or []),
    )
    outcome = agent.run(intent)
    return {
        "success": outcome.success,
        "summary": outcome.summary,
        "iterations": outcome.iterations_used,
        "confidence": outcome.confidence,
        "evidence": outcome.evidence,
        "final_code": outcome.final_code if outcome.success else "",
    }


# ─── Tool catalog ────────────────────────────────────────────────────────────


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="cyberm4fia.parse_nmap_xml",
        description=(
            "Parse Nmap '-oX -' XML output into a structured host/port tree. "
            "Returns host_count, open_port_count, an AI-readable summary, and "
            "a list of hosts with their open ports + service metadata."
        ),
        input_schema=_schema(
            {"xml": {"type": "string", "description": "Raw Nmap XML."}},
            ["xml"],
        ),
        handler=_handle_parse_nmap_xml,
        tags=("recon", "parser"),
    ),
    ToolSpec(
        name="cyberm4fia.parse_nuclei_jsonl",
        description=(
            "Parse Nuclei '-jsonl' output into structured findings with "
            "severity, CVSS, tags, and a high/critical count."
        ),
        input_schema=_schema(
            {"jsonl": {"type": "string", "description": "Raw Nuclei JSONL."}},
            ["jsonl"],
        ),
        handler=_handle_parse_nuclei_jsonl,
        tags=("vuln", "parser"),
    ),
    ToolSpec(
        name="cyberm4fia.parse_sqlmap_json",
        description=(
            "Parse sqlmap API/log JSON into a SqlmapResult-style dict with "
            "the target, DB type, and per-injection details."
        ),
        input_schema=_schema(
            {
                "json": {
                    "type": ["string", "object"],
                    "description": "Raw sqlmap JSON (string) or already-parsed object.",
                },
            },
            ["json"],
        ),
        handler=_handle_parse_sqlmap_json,
        tags=("vuln", "parser"),
    ),
    ToolSpec(
        name="cyberm4fia.run_intent_agent",
        description=(
            "Run the intent-driven AI exploit agent: the LLM writes Python "
            "exploit code, executes it in a sandbox, and self-heals on errors. "
            "Returns confirmed flag, confidence, evidence, and the final script "
            "if the exploit was confirmed."
        ),
        input_schema=_schema(
            {
                "goal": {"type": "string"},
                "target_url": {"type": "string"},
                "param": {"type": "string"},
                "vuln_type": {"type": "string"},
                "http_method": {"type": "string"},
                "notes": {"type": "string"},
                "constraints": {"type": "array", "items": {"type": "string"}},
            },
            ["goal", "target_url"],
        ),
        handler=_handle_run_intent_agent,
        tags=("exploit", "ai"),
    ),
)


_TOOL_INDEX: dict[str, ToolSpec] = {t.name: t for t in TOOLS}


# ─── Public dispatch API ─────────────────────────────────────────────────────


def list_tools() -> list[dict]:
    """Return the tool catalog as a list of MCP-style tool dicts."""
    return [
        {
            "name": t.name,
            "description": t.description,
            "inputSchema": t.input_schema,
        }
        for t in TOOLS
    ]


def dispatch(name: str, arguments: dict | None = None) -> dict:
    """Run a registered tool. Returns ``{"ok": True, "result": ...}`` on
    success and ``{"ok": False, "error": "..."}`` on failure."""
    arguments = arguments or {}
    spec = _TOOL_INDEX.get(name)
    if spec is None:
        return {"ok": False, "error": f"unknown tool: {name}"}
    try:
        result = spec.handler(arguments)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"ok": True, "result": result}


# ─── Optional MCP runtime (stdio) ────────────────────────────────────────────


def serve_stdio() -> None:
    """Run a real MCP server over stdio. Requires the ``mcp`` Python SDK.

    Raises ``RuntimeError`` with an install hint if the SDK isn't available —
    the rest of this module still works (parsers, dispatch) without it.
    """
    try:
        from mcp.server import Server  # type: ignore[import-not-found]
        from mcp.server.stdio import stdio_server  # type: ignore[import-not-found]
        from mcp import types as mcp_types  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "MCP SDK not installed. Install with: pip install mcp"
        ) from exc

    import asyncio

    server = Server("cyberm4fia-scanner")

    @server.list_tools()
    async def _list_tools():
        return [
            mcp_types.Tool(
                name=t.name,
                description=t.description,
                inputSchema=t.input_schema,
            )
            for t in TOOLS
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict):
        out = dispatch(name, arguments)
        return [mcp_types.TextContent(type="text", text=json.dumps(out))]

    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    asyncio.run(_run())


# ─── CLI entry ───────────────────────────────────────────────────────────────


if __name__ == "__main__":
    serve_stdio()
