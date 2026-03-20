"""
cyberm4fia-scanner - Scan Comparison Module
Compare two scan results and show differences
"""

import os

import json
from utils.colors import Colors, log_success, log_warning

def _vuln_key(v):
    """Create a unique key for a vulnerability."""
    return (
        v.get("type", ""),
        v.get("param", v.get("field", "")),
        v.get("payload", "")[:50],
    )

def load_scan(scan_dir):
    """Load scan results from a scan directory."""
    json_path = os.path.join(scan_dir, "scan.json")

    if not os.path.exists(json_path):
        return None

    with open(json_path, "r") as f:
        return json.load(f)

def compare_scans(scan_dir_1, scan_dir_2):
    """Compare two scan results.

    Returns dict with:
      - fixed: vulns in scan1 but not in scan2
      - new: vulns in scan2 but not in scan1
      - unchanged: vulns in both scans
      - scan1/scan2: metadata
    """
    scan1 = load_scan(scan_dir_1)
    scan2 = load_scan(scan_dir_2)

    if not scan1:
        return {"error": f"No scan.json in {scan_dir_1}"}
    if not scan2:
        return {"error": f"No scan.json in {scan_dir_2}"}

    vulns1 = scan1.get("vulnerabilities", [])
    vulns2 = scan2.get("vulnerabilities", [])

    keys1 = {_vuln_key(v): v for v in vulns1}
    keys2 = {_vuln_key(v): v for v in vulns2}

    set1 = set(keys1.keys())
    set2 = set(keys2.keys())

    fixed = [keys1[k] for k in (set1 - set2)]
    new = [keys2[k] for k in (set2 - set1)]
    unchanged = [keys2[k] for k in (set1 & set2)]

    return {
        "scan1": {
            "dir": scan_dir_1,
            "date": scan1.get("date", "Unknown"),
            "target": scan1.get("target", "Unknown"),
            "total": len(vulns1),
        },
        "scan2": {
            "dir": scan_dir_2,
            "date": scan2.get("date", "Unknown"),
            "target": scan2.get("target", "Unknown"),
            "total": len(vulns2),
        },
        "fixed": fixed,
        "new": new,
        "unchanged": unchanged,
    }

def print_comparison(result):
    """Pretty-print comparison results."""
    if "error" in result:
        log_warning(result["error"])
        return

    s1 = result["scan1"]
    s2 = result["scan2"]

    print(f"\n{Colors.BOLD}{'═' * 55}{Colors.END}")
    print(f"{Colors.BOLD}📊 SCAN COMPARISON REPORT{Colors.END}")
    print(f"{Colors.BOLD}{'═' * 55}{Colors.END}")

    print(f"\n{Colors.CYAN}Scan 1:{Colors.END} {s1['date']} ({s1['total']} vulns)")
    print(f"  Dir: {s1['dir']}")
    print(f"{Colors.CYAN}Scan 2:{Colors.END} {s2['date']} ({s2['total']} vulns)")
    print(f"  Dir: {s2['dir']}")

    # Fixed vulnerabilities
    fixed = result["fixed"]
    print(f"\n{Colors.GREEN}{Colors.BOLD}✅ FIXED ({len(fixed)}):{Colors.END}")
    if fixed:
        for v in fixed:
            vtype = v.get("type", "Unknown")
            param = v.get("param", v.get("field", "?"))
            payload = str(v.get("payload", ""))[:40]
            print(f"  {Colors.GREEN}- {vtype} on {param} (was: {payload}){Colors.END}")
    else:
        print(f"  {Colors.GREY}None{Colors.END}")

    # New vulnerabilities
    new = result["new"]
    print(f"\n{Colors.RED}{Colors.BOLD}🆕 NEW ({len(new)}):{Colors.END}")
    if new:
        for v in new:
            vtype = v.get("type", "Unknown")
            param = v.get("param", v.get("field", "?"))
            payload = str(v.get("payload", ""))[:40]
            print(
                f"  {Colors.RED}- {vtype} on {param} (payload: {payload}){Colors.END}"
            )
    else:
        print(f"  {Colors.GREY}None{Colors.END}")

    # Unchanged
    unchanged = result["unchanged"]
    print(
        f"\n{Colors.YELLOW}{Colors.BOLD}"
        f"⚠️  STILL PRESENT ({len(unchanged)}):"
        f"{Colors.END}"
    )
    if unchanged:
        for v in unchanged:
            vtype = v.get("type", "Unknown")
            param = v.get("param", v.get("field", "?"))
            print(f"  {Colors.YELLOW}- {vtype} on {param}{Colors.END}")
    else:
        print(f"  {Colors.GREY}None{Colors.END}")

    # Summary
    print(f"\n{Colors.BOLD}{'─' * 55}{Colors.END}")
    delta = s2["total"] - s1["total"]
    if delta < 0:
        print(f"{Colors.GREEN}📉 {abs(delta)} fewer vulnerabilities!{Colors.END}")
    elif delta > 0:
        print(f"{Colors.RED}📈 {delta} more vulnerabilities!{Colors.END}")
    else:
        print("📊 Same number of vulnerabilities")
    print()

def save_comparison_json(result, output_path):
    """Save comparison result as JSON."""
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    log_success(f"Comparison saved: {output_path}")
