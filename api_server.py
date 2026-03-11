"""
cyberm4fia-scanner - REST API Server (FastAPI)
Run with: python3 scanner.py --api [--port 8080]

Features:
  - Async endpoints with automatic OpenAPI docs
  - Background task execution for scans
  - Auto-generated Swagger UI at /docs
  - ReDoc at /redoc

Endpoints:
  POST   /api/scan         Start a new scan
  GET    /api/scan/{id}     Get scan status/results
  GET    /api/scans         List all scans
  GET    /api/report/{id}   Download HTML report
  GET    /api/report/{id}/json   Download JSON findings report
  GET    /api/report/{id}/sarif  Download SARIF report
  DELETE /api/scan/{id}     Cancel a scan
"""

import sys
import os
import json
import asyncio
import uuid
import threading
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse, StreamingResponse
    from pydantic import BaseModel, Field
    import uvicorn
except ImportError:
    print("FastAPI not installed. Run: pip install 'fastapi[standard]'")
    sys.exit(1)

from utils.colors import log_info, log_success, set_quiet
from utils.request import (
    ScanCancelled,
    get_default_timeout,
    get_path_blacklist,
    smart_request,
)
from core.scan_context import ScanContext
from core.scan_options import get_scan_mode_runtime


# ─── Pydantic Models ───


class ScanRequest(BaseModel):
    """Request body for starting a new scan."""

    url: str = Field(
        ..., description="Target URL to scan", examples=["http://example.com"]
    )
    modules: list[str] = Field(
        default=["all"],
        description="List of modules to run",
        examples=[["xss", "sqli", "lfi"]],
    )
    mode: str = Field(
        default="normal",
        description="Scan mode: normal | stealth | lab (legacy aliases quick/aggressive still work)",
        examples=["normal"],
    )
    exploit: bool = Field(
        default=False,
        description="Enable exploit follow-up actions after findings are detected",
    )
    max_requests: int = Field(
        default=0,
        description="Optional request budget; 0 disables the limit",
    )
    request_timeout: float = Field(
        default=get_default_timeout(),
        description="Default request timeout for this scan",
    )
    max_host_concurrency: int = Field(
        default=0,
        description="Maximum simultaneous requests per host; 0 disables the limit",
    )
    path_blacklist: str = Field(
        default=",".join(get_path_blacklist()),
        description="Comma-separated risky path patterns to skip",
    )


class ScanSummary(BaseModel):
    """Brief scan info for listing."""

    id: str
    url: str
    status: str
    created_at: str
    total_vulns: int = 0


class ScanResult(BaseModel):
    """Full scan result."""

    id: str
    url: str
    status: str
    created_at: str
    completed_at: Optional[str] = None
    total_vulns: int = 0
    stats: dict = Field(default_factory=dict)
    progress: dict = Field(default_factory=dict)
    vulnerabilities: list = Field(default_factory=list)
    observations: list = Field(default_factory=list)
    findings: list = Field(default_factory=list)
    attack_paths: list = Field(default_factory=list)
    error: Optional[str] = None


# ─── FastAPI App ───

app = FastAPI(
    title="cyberm4fia-scanner API",
    description="Advanced vulnerability scanner REST API with async scan execution, multi-module support, and auto-generated reports.",
    version="5.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# In-memory scan storage
SCANS: dict = {}
_SCAN_LOCK = threading.Lock()


def _update_scan(scan_id: str, **changes):
    with _SCAN_LOCK:
        if scan_id in SCANS:
            SCANS[scan_id].update(changes)


def _set_scan_progress(scan_id: str, phase: str, completed: int, total: int, message: str):
    _update_scan(
        scan_id,
        progress={
            "phase": phase,
            "completed": completed,
            "total": total,
            "message": message,
            "updated_at": str(datetime.now()),
        },
    )


def _check_cancelled(scan: dict):
    cancel_event = scan.get("cancel_event")
    if cancel_event is not None and cancel_event.is_set():
        raise ScanCancelled("Scan cancelled by API request.")


# ─── Background Scan Worker ───


def _run_scan_job(scan_id: str, url: str, options: dict):
    """Background scan worker."""
    from bs4 import BeautifulSoup
    from modules.xss import scan_xss
    from modules.sqli import scan_sqli
    from modules.lfi import scan_lfi
    from modules.rfi import scan_rfi
    from modules.cmdi import scan_cmdi
    from modules.ssrf import scan_ssrf
    from modules.cors import scan_cors
    from modules.header_inject import scan_header_inject
    from modules.report import generate_html_report, generate_json_report
    from core.output import save_findings_json, save_sarif
    from utils.finding import build_scan_artifacts

    scan = SCANS[scan_id]
    _update_scan(scan_id, status="running", started_at=str(datetime.now()))

    mode = options.get("mode", "normal")
    mode, delay, _ = get_scan_mode_runtime(mode)
    modules = options.get("modules", [])
    use_all = "all" in modules
    scan_ctx = ScanContext(
        url,
        mode,
        delay,
        options={
            "json_output": True,
            "exploit": bool(options.get("exploit")),
            "max_requests": int(options.get("max_requests", 0) or 0),
            "request_timeout": float(
                options.get("request_timeout", get_default_timeout())
                or get_default_timeout()
            ),
            "max_host_concurrency": int(
                options.get("max_host_concurrency", 0) or 0
            ),
            "path_blacklist": options.get("path_blacklist", ""),
            "cancel_event": scan.get("cancel_event"),
        },
        scan_suffix=scan_id[:8],
    )

    selected_steps = [
        name
        for name in ("cors", "header_inject", "fetch_forms", "xss", "sqli", "lfi", "rfi", "cmdi", "ssrf")
        if name == "fetch_forms" or use_all or name in modules
    ]
    all_vulns = []

    try:
        with scan_ctx.activate():
            forms = []
            total_steps = len(selected_steps)
            completed_steps = 0

            if use_all or "cors" in modules:
                _check_cancelled(scan)
                _set_scan_progress(scan_id, "cors", completed_steps, total_steps, "Running CORS checks")
                all_vulns.extend(scan_cors(url))
                completed_steps += 1

            if use_all or "header_inject" in modules:
                _check_cancelled(scan)
                _set_scan_progress(scan_id, "header_inject", completed_steps, total_steps, "Running header injection checks")
                all_vulns.extend(scan_header_inject(url, delay))
                completed_steps += 1

            _check_cancelled(scan)
            _set_scan_progress(scan_id, "fetch_forms", completed_steps, total_steps, "Fetching target and extracting forms")
            resp = smart_request(
                "get",
                url,
                timeout=options.get("request_timeout", get_default_timeout()),
            )
            soup = BeautifulSoup(resp.content, "lxml")
            forms = soup.find_all("form")
            completed_steps += 1

            for step_name, runner in (
                ("xss", scan_xss),
                ("sqli", scan_sqli),
                ("lfi", scan_lfi),
                ("rfi", scan_rfi),
                ("cmdi", scan_cmdi),
                ("ssrf", scan_ssrf),
            ):
                if not (use_all or step_name in modules):
                    continue
                _check_cancelled(scan)
                _set_scan_progress(
                    scan_id,
                    step_name,
                    completed_steps,
                    total_steps,
                    f"Running {step_name.upper()} checks",
                )
                all_vulns.extend(runner(url, forms, delay))
                completed_steps += 1

            artifacts = build_scan_artifacts(all_vulns)
            stats = scan_ctx.collect_stats(len(artifacts["findings"]))
            _set_scan_progress(scan_id, "reporting", completed_steps, total_steps, "Generating reports")
            generate_json_report(
                all_vulns,
                url,
                mode,
                stats,
                scan_ctx.scan_dir,
                artifacts=artifacts,
            )
            generate_html_report(all_vulns, url, mode, scan_ctx.scan_dir, stats=stats)
            save_findings_json(
                all_vulns,
                scan_ctx.scan_dir,
                url,
                mode,
                stats,
                artifacts=artifacts,
            )
            save_sarif(all_vulns, scan_ctx.scan_dir)

        _update_scan(
            scan_id,
            status="completed",
            completed_at=str(datetime.now()),
            vulns=all_vulns,
            observations=[obs.to_dict() for obs in artifacts["observations"]],
            findings=[finding.to_dict() for finding in artifacts["findings"]],
            attack_paths=[path.to_dict() for path in artifacts["attack_paths"]],
            stats=stats,
            scan_dir=scan_ctx.scan_dir,
            total_vulns=len(artifacts["findings"]),
        )
        _set_scan_progress(scan_id, "completed", total_steps, total_steps, "Scan completed")

    except ScanCancelled as exc:
        _update_scan(
            scan_id,
            status="cancelled",
            completed_at=str(datetime.now()),
            error=str(exc),
        )
        progress = scan.get("progress", {})
        _set_scan_progress(
            scan_id,
            "cancelled",
            progress.get("completed", 0),
            progress.get("total", 0),
            "Scan cancelled",
        )
    except Exception as e:
        _update_scan(
            scan_id,
            status="failed",
            completed_at=str(datetime.now()),
            error=str(e),
        )


# ─── API Endpoints ───


@app.post(
    "/api/scan",
    response_model=dict,
    status_code=201,
    summary="Start a new scan",
    tags=["Scans"],
)
async def start_scan(scan_req: ScanRequest):
    """Start a new vulnerability scan on the target URL.

    The scan runs in the background. Use `GET /api/scan/{id}` to check progress.
    """
    url = scan_req.url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    scan_id = str(uuid.uuid4())[:12]
    options = {
        "modules": scan_req.modules,
        "mode": scan_req.mode,
        "exploit": scan_req.exploit,
        "max_requests": scan_req.max_requests,
        "request_timeout": scan_req.request_timeout,
        "max_host_concurrency": scan_req.max_host_concurrency,
        "path_blacklist": scan_req.path_blacklist,
    }

    SCANS[scan_id] = {
        "id": scan_id,
        "url": url,
        "options": options,
        "status": "queued",
        "created_at": str(datetime.now()),
        "vulns": [],
        "stats": {},
        "progress": {
            "phase": "queued",
            "completed": 0,
            "total": 0,
            "message": "Queued",
            "updated_at": str(datetime.now()),
        },
        "cancel_event": threading.Event(),
    }

    # Run in background thread
    t = threading.Thread(
        target=_run_scan_job, args=(scan_id, url, options), daemon=True
    )
    t.start()

    return {"scan_id": scan_id, "status": "queued", "url": url}


@app.get(
    "/api/scan/{scan_id}",
    response_model=ScanResult,
    summary="Get scan status and results",
    tags=["Scans"],
)
async def get_scan(scan_id: str):
    """Retrieve detailed scan results including vulnerabilities and stats."""
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResult(
        id=scan["id"],
        url=scan["url"],
        status=scan["status"],
        created_at=scan["created_at"],
        completed_at=scan.get("completed_at"),
        total_vulns=scan.get("total_vulns", 0),
        stats=scan.get("stats", {}),
        progress=scan.get("progress", {}),
        vulnerabilities=scan.get("vulns", []),
        observations=scan.get("observations", []),
        findings=scan.get("findings", []),
        attack_paths=scan.get("attack_paths", []),
        error=scan.get("error"),
    )


@app.get(
    "/api/scans",
    response_model=dict,
    summary="List all scans",
    tags=["Scans"],
)
async def list_scans():
    """List all scans with summary information."""
    scans = []
    for sid, s in SCANS.items():
        scans.append(
            ScanSummary(
                id=sid,
                url=s["url"],
                status=s["status"],
                created_at=s["created_at"],
                total_vulns=s.get("total_vulns", 0),
            ).model_dump()
        )
    return {"scans": scans}


@app.get(
    "/api/report/{scan_id}",
    summary="Download HTML report",
    tags=["Reports"],
)
async def get_report(scan_id: str):
    """Download the generated HTML report for a completed scan."""
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_dir = scan.get("scan_dir")
    if not scan_dir:
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    html_path = os.path.join(scan_dir, "report.html")
    if os.path.exists(html_path):
        return FileResponse(html_path, media_type="text/html")
    raise HTTPException(status_code=404, detail="Report not found")


@app.get(
    "/api/report/{scan_id}/json",
    summary="Download JSON findings report",
    tags=["Reports"],
)
async def get_json_report(scan_id: str):
    """Download the generated JSON findings report for a completed scan."""
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_dir = scan.get("scan_dir")
    if not scan_dir:
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    preferred_paths = [
        os.path.join(scan_dir, "findings.json"),
        os.path.join(scan_dir, "scan.json"),
    ]
    for report_path in preferred_paths:
        if os.path.exists(report_path):
            return FileResponse(report_path, media_type="application/json")
    raise HTTPException(status_code=404, detail="JSON report not found")


@app.get(
    "/api/report/{scan_id}/sarif",
    summary="Download SARIF report",
    tags=["Reports"],
)
async def get_sarif_report(scan_id: str):
    """Download the generated SARIF report for a completed scan."""
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_dir = scan.get("scan_dir")
    if not scan_dir:
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    sarif_path = os.path.join(scan_dir, "results.sarif")
    if os.path.exists(sarif_path):
        return FileResponse(sarif_path, media_type="application/sarif+json")
    raise HTTPException(status_code=404, detail="SARIF report not found")


@app.delete(
    "/api/scan/{scan_id}",
    summary="Cancel/delete a scan",
    tags=["Scans"],
)
async def cancel_scan(scan_id: str):
    """Cancel or delete a scan and its results."""
    scan = SCANS.get(scan_id)
    if scan:
        if scan.get("status") in {"queued", "running", "cancelling"}:
            scan["cancel_event"].set()
            scan["status"] = "cancelling"
            _set_scan_progress(
                scan_id,
                "cancelling",
                scan.get("progress", {}).get("completed", 0),
                scan.get("progress", {}).get("total", 0),
                "Cancellation requested",
            )
            return {"status": "cancelling"}
        del SCANS[scan_id]
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Scan not found")


@app.get(
    "/api/scan/{scan_id}/events",
    summary="Stream scan progress events",
    tags=["Scans"],
)
async def stream_scan_events(scan_id: str):
    """Stream scan status updates using Server-Sent Events (SSE)."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_stream():
        previous_payload = None
        while True:
            scan = SCANS.get(scan_id)
            if not scan:
                break

            payload = json.dumps(
                {
                    "id": scan["id"],
                    "status": scan["status"],
                    "progress": scan.get("progress", {}),
                    "total_vulns": scan.get("total_vulns", 0),
                    "error": scan.get("error"),
                }
            )
            if payload != previous_payload:
                previous_payload = payload
                yield f"event: progress\ndata: {payload}\n\n"

            if scan.get("status") in {"completed", "failed", "cancelled"}:
                break

            await asyncio.sleep(0.25)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/", summary="API info", tags=["Info"])
async def index():
    """API information and available endpoints."""
    return {
        "name": "cyberm4fia-scanner API",
        "version": "5.0",
        "docs": "/docs",
        "redoc": "/redoc",
        "endpoints": {
            "POST /api/scan": "Start scan",
            "GET /api/scan/{id}": "Scan results",
            "GET /api/scan/{id}/events": "Stream progress (SSE)",
            "GET /api/scans": "List all scans",
            "GET /api/report/{id}": "HTML report",
            "GET /api/report/{id}/json": "JSON findings report",
            "GET /api/report/{id}/sarif": "SARIF report",
            "DELETE /api/scan/{id}": "Cancel scan",
        },
    }


# ─── Server Launcher ───


def start_api_server(host="0.0.0.0", port=8080):
    """Start the FastAPI server with Uvicorn."""
    set_quiet(True)
    log_info(f"Starting FastAPI server on {host}:{port}")
    log_success(f"API docs: http://localhost:{port}/docs")
    log_success(f"ReDoc: http://localhost:{port}/redoc")
    uvicorn.run(app, host=host, port=port, log_level="info")
