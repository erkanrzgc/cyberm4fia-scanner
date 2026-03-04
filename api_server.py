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
  DELETE /api/scan/{id}     Cancel a scan
"""

import sys
import os
import uuid
import threading
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse
    from pydantic import BaseModel, Field
    import uvicorn
except ImportError:
    print("FastAPI not installed. Run: pip install 'fastapi[standard]'")
    sys.exit(1)

from utils.colors import log_info, log_success, set_quiet
from utils.request import Config, Stats, smart_request


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
        description="Scan mode: quick | normal | aggressive | stealth",
        examples=["normal"],
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
    stats: dict = {}
    vulnerabilities: list = []
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
    from urllib.parse import urlparse

    scan = SCANS[scan_id]
    scan["status"] = "running"
    scan["started_at"] = str(datetime.now())

    Stats.reset()
    mode = options.get("mode", "normal")
    delay_map = {
        "quick": Config.QUICK_DELAY,
        "normal": Config.REQUEST_DELAY,
        "aggressive": 0.05,
        "stealth": Config.STEALTH_DELAY,
    }
    delay = delay_map.get(mode, Config.REQUEST_DELAY)
    modules = options.get("modules", [])
    use_all = "all" in modules

    all_vulns = []

    try:
        # CORS + Header (target-level)
        if use_all or "cors" in modules:
            all_vulns.extend(scan_cors(url))
        if use_all or "header_inject" in modules:
            all_vulns.extend(scan_header_inject(url, delay))

        # Page-level scans
        resp = smart_request("get", url)
        soup = BeautifulSoup(resp.content, "lxml")
        forms = soup.find_all("form")

        if use_all or "xss" in modules:
            all_vulns.extend(scan_xss(url, forms, delay))
        if use_all or "sqli" in modules:
            all_vulns.extend(scan_sqli(url, forms, delay))
        if use_all or "lfi" in modules:
            all_vulns.extend(scan_lfi(url, forms, delay))
        if use_all or "rfi" in modules:
            all_vulns.extend(scan_rfi(url, forms, delay))
        if use_all or "cmdi" in modules:
            all_vulns.extend(scan_cmdi(url, forms, delay))
        if use_all or "ssrf" in modules:
            all_vulns.extend(scan_ssrf(url, forms, delay))

        # Generate reports
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc.split(":")[0]
        safe = host.replace(".", "_")
        scan_dir = f"scans/{safe}_{scan_id[:8]}"
        os.makedirs(scan_dir, exist_ok=True)

        stats = {
            "total_requests": Stats.total_requests,
            "vulnerabilities": Stats.vulnerabilities_found,
            "waf_blocks": Stats.waf_blocks,
            "errors": Stats.errors,
            "retries": Stats.retries,
        }

        generate_json_report(all_vulns, url, mode, stats, scan_dir)
        generate_html_report(all_vulns, url, mode, scan_dir)

        scan["status"] = "completed"
        scan["completed_at"] = str(datetime.now())
        scan["vulns"] = all_vulns
        scan["stats"] = stats
        scan["scan_dir"] = scan_dir
        scan["total_vulns"] = len(all_vulns)

    except Exception as e:
        scan["status"] = "failed"
        scan["error"] = str(e)


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
    }

    SCANS[scan_id] = {
        "id": scan_id,
        "url": url,
        "options": options,
        "status": "queued",
        "created_at": str(datetime.now()),
        "vulns": [],
        "stats": {},
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
        vulnerabilities=scan.get("vulns", []),
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


@app.delete(
    "/api/scan/{scan_id}",
    summary="Cancel/delete a scan",
    tags=["Scans"],
)
async def cancel_scan(scan_id: str):
    """Cancel or delete a scan and its results."""
    if scan_id in SCANS:
        del SCANS[scan_id]
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Scan not found")


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
            "GET /api/scans": "List all scans",
            "GET /api/report/{id}": "HTML report",
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
