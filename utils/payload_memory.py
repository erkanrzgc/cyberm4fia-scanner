"""
cyberm4fia-scanner — AI Payload Memory
JSON-backed memory of successful payloads and bypass techniques.
Learns from past scans to improve future exploitation.
"""

import json
import os
from datetime import datetime


DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
MEMORY_FILE = os.path.join(DATA_DIR, "payload_memory.json")


class PayloadMemory:
    """Persistent memory of successful payloads and bypass techniques."""

    def __init__(self, db_path=None):
        self.db_path = db_path or MEMORY_FILE
        self._ensure_dir()
        self.data = self._load()

    def _ensure_dir(self):
        parent = os.path.dirname(self.db_path)
        if not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

    def _load(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"entries": [], "stats": {"total_remembered": 0, "total_recalls": 0}}

    def _save(self):
        with open(self.db_path, "w") as f:
            json.dump(self.data, f, indent=2, default=str)

    def remember(self, target, vuln_type, payload, technique="",
                 waf_bypassed="", confidence=0, url="", param=""):
        """
        Store a successful payload in memory.
        
        Args:
            target: Target domain/host.
            vuln_type: Vulnerability type (XSS, SQLi, CMDi, etc.).
            payload: The successful payload string.
            technique: Description of the technique used.
            waf_bypassed: Name of WAF that was bypassed (if any).
            confidence: Confidence score (0-100).
            url: Full URL where the vuln was found.
            param: Parameter name.
        """
        # Deduplicate: don't store exact same payload for same target+type
        for entry in self.data["entries"]:
            if (entry["target"] == target
                    and entry["vuln_type"] == vuln_type
                    and entry["payload"] == payload):
                # Update confidence if higher
                if confidence > entry.get("confidence", 0):
                    entry["confidence"] = confidence
                    entry["last_seen"] = datetime.now().isoformat()
                    self._save()
                return

        entry = {
            "target": target,
            "vuln_type": vuln_type,
            "payload": payload,
            "technique": technique,
            "waf_bypassed": waf_bypassed,
            "confidence": confidence,
            "url": url,
            "param": param,
            "timestamp": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "success_count": 1,
        }
        self.data["entries"].append(entry)
        self.data["stats"]["total_remembered"] += 1
        self._save()

    def recall(self, target=None, vuln_type=None, limit=10):
        """
        Recall successful payloads from memory.
        
        Args:
            target: Filter by target domain (optional).
            vuln_type: Filter by vulnerability type (optional).
            limit: Max results to return.
            
        Returns:
            List of matching memory entries, sorted by confidence desc.
        """
        self.data["stats"]["total_recalls"] += 1
        self._save()

        results = self.data["entries"]

        if target:
            target_lower = target.lower()
            results = [e for e in results if target_lower in e.get("target", "").lower()]

        if vuln_type:
            vt_lower = vuln_type.lower()
            results = [e for e in results if vt_lower in e.get("vuln_type", "").lower()]

        # Sort by confidence descending, then by recency
        results.sort(key=lambda x: (x.get("confidence", 0), x.get("last_seen", "")), reverse=True)

        return results[:limit]

    def get_context_for_ai(self, target=None, vuln_type=None, max_entries=5):
        """
        Generate a prompt context string from memory for AI usage.
        
        Returns a formatted string suitable for injection into AI system prompts.
        """
        entries = self.recall(target=target, vuln_type=vuln_type, limit=max_entries)
        if not entries:
            return ""

        lines = ["Previously successful payloads from memory:"]
        for i, entry in enumerate(entries, 1):
            line = f"{i}. [{entry['vuln_type']}] {entry['payload'][:80]}"
            if entry.get("technique"):
                line += f" (technique: {entry['technique']})"
            if entry.get("waf_bypassed"):
                line += f" [bypassed: {entry['waf_bypassed']}]"
            lines.append(line)

        return "\n".join(lines)

    def remember_from_finding(self, finding_dict):
        """
        Auto-remember from a vulnerability finding dict.
        Extracts relevant fields and stores in memory.
        """
        payload = finding_dict.get("payload", "")
        if not payload:
            return

        from urllib.parse import urlparse
        url = finding_dict.get("url", "")
        parsed = urlparse(url)
        target = parsed.hostname or url

        self.remember(
            target=target,
            vuln_type=finding_dict.get("type", "Unknown"),
            payload=payload,
            technique=finding_dict.get("technique", ""),
            waf_bypassed=finding_dict.get("waf_bypassed", ""),
            confidence=finding_dict.get("confidence_score", 50),
            url=url,
            param=finding_dict.get("param", ""),
        )

    def stats(self):
        """Get memory statistics."""
        entries = self.data["entries"]
        type_counts = {}
        waf_counts = {}

        for e in entries:
            vt = e.get("vuln_type", "Unknown")
            type_counts[vt] = type_counts.get(vt, 0) + 1
            waf = e.get("waf_bypassed", "")
            if waf:
                waf_counts[waf] = waf_counts.get(waf, 0) + 1

        return {
            "total_entries": len(entries),
            "total_remembered": self.data["stats"]["total_remembered"],
            "total_recalls": self.data["stats"]["total_recalls"],
            "by_type": type_counts,
            "waf_bypasses": waf_counts,
        }

    def clear(self, target=None):
        """Clear memory, optionally for a specific target only."""
        if target:
            self.data["entries"] = [
                e for e in self.data["entries"]
                if target.lower() not in e.get("target", "").lower()
            ]
        else:
            self.data["entries"] = []
            self.data["stats"] = {"total_remembered": 0, "total_recalls": 0}
        self._save()


# Singleton accessor
_memory_instance = None


def get_memory(db_path=None):
    """Get or create the global PayloadMemory instance."""
    global _memory_instance
    if _memory_instance is None:
        _memory_instance = PayloadMemory(db_path=db_path)
    return _memory_instance
