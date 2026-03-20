"""
cyberm4fia-scanner - Loot Manager
Structured storage for extracted data: SQLi dumps, stolen cookies,
downloaded files, and credentials.
"""

import json
import os
import time

from utils.colors import log_info, log_success


class LootManager:
    """
    Manages loot collected during exploitation.
    Saves structured JSON files under ``{scan_dir}/loot/``.
    """

    def __init__(self, scan_dir):
        self.loot_dir = os.path.join(scan_dir, "loot")
        os.makedirs(self.loot_dir, exist_ok=True)
        self._manifest = []

    # ── Save helpers ─────────────────────────────────────────────────────

    def save_sqli_dump(self, database, table, columns, rows, *, blind=False):
        """Save SQL injection data dump."""
        filename = f"sqli_{database}_{table}.json"
        data = {
            "type": "sqli_dump",
            "blind": blind,
            "database": database,
            "table": table,
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "timestamp": _ts(),
        }
        self._write(filename, data)
        log_success(f"[LOOT] SQLi dump saved → {filename} ({len(rows)} rows)")
        return os.path.join(self.loot_dir, filename)

    def save_credentials(self, source, credentials):
        """
        Save extracted credentials.
        ``credentials`` is a list of dicts, each with at least 'user' and
        'password' (or 'hash') keys.
        """
        filename = f"creds_{source}.json"
        data = {
            "type": "credentials",
            "source": source,
            "credentials": credentials,
            "count": len(credentials),
            "timestamp": _ts(),
        }
        self._write(filename, data)
        log_success(f"[LOOT] {len(credentials)} credential(s) saved → {filename}")
        return os.path.join(self.loot_dir, filename)

    def save_file_download(self, remote_path, content):
        """Save a file downloaded from the target."""
        basename = os.path.basename(remote_path) or "downloaded_file.txt"
        safe_name = basename.replace("/", "_").replace("\\", "_")
        filepath = os.path.join(self.loot_dir, safe_name)
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(content)

        meta = {
            "type": "file_download",
            "remote_path": remote_path,
            "local_path": filepath,
            "size": len(content),
            "timestamp": _ts(),
        }
        self._manifest.append(meta)
        log_success(f"[LOOT] File saved → {safe_name} ({len(content)} bytes)")
        return filepath

    def save_cookies(self, cookies, source_ip=None):
        """Save stolen cookies from XSS exploitation."""
        filename = "stolen_cookies.json"
        filepath = os.path.join(self.loot_dir, filename)

        # Append to existing file if present
        existing = []
        if os.path.exists(filepath):
            with open(filepath, encoding="utf-8") as fh:
                try:
                    existing = json.load(fh).get("cookies", [])
                except (json.JSONDecodeError, AttributeError):
                    pass

        for c in cookies:
            entry = {
                "cookie": c.get("cookie", str(c)),
                "source_ip": source_ip or c.get("source_ip", "unknown"),
                "timestamp": c.get("timestamp", _ts()),
            }
            existing.append(entry)

        data = {"type": "stolen_cookies", "cookies": existing, "count": len(existing)}
        self._write(filename, data)
        log_success(f"[LOOT] {len(cookies)} cookie(s) saved → {filename}")
        return filepath

    def save_schema_info(self, database, tables, columns_map=None):
        """Save DB schema information (tables, columns)."""
        filename = f"schema_{database}.json"
        data = {
            "type": "schema_info",
            "database": database,
            "tables": tables,
            "columns": columns_map or {},
            "timestamp": _ts(),
        }
        self._write(filename, data)
        log_info(f"[LOOT] Schema info saved → {filename}")
        return os.path.join(self.loot_dir, filename)

    # ── Report ───────────────────────────────────────────────────────────

    def summary(self):
        """Generate a loot summary report."""
        report = {
            "loot_dir": self.loot_dir,
            "files": [],
            "generated_at": _ts(),
        }

        for fname in sorted(os.listdir(self.loot_dir)):
            fpath = os.path.join(self.loot_dir, fname)
            if not os.path.isfile(fpath):
                continue
            entry = {"filename": fname, "size_bytes": os.path.getsize(fpath)}
            if fname.endswith(".json"):
                try:
                    with open(fpath, encoding="utf-8") as fh:
                        meta = json.load(fh)
                    entry["type"] = meta.get("type", "unknown")
                    entry["count"] = meta.get("count") or meta.get("row_count", "?")
                except (json.JSONDecodeError, AttributeError):
                    pass
            report["files"].append(entry)

        report["total_files"] = len(report["files"])

        summary_path = os.path.join(self.loot_dir, "loot_report.json")
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)

        return report

    # ── Internal ─────────────────────────────────────────────────────────

    def _write(self, filename, data):
        filepath = os.path.join(self.loot_dir, filename)
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        self._manifest.append(data)


def _ts():
    return time.strftime("%Y-%m-%dT%H:%M:%S")
