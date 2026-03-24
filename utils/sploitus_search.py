"""
cyberm4fia-scanner — Sploitus Exploit Search
Searches sploitus.com for known exploits based on detected technologies.
"""

import httpx

from utils.colors import Colors, log_info, log_success, log_warning
from utils.request import ScanExceptions


SPLOITUS_API = "https://sploitus.com/search"


class SploitusSearch:
    """Search sploitus.com for exploits and vulnerabilities."""

    def __init__(self, timeout=10):
        self.timeout = timeout

    def search(self, query, search_type="exploits", offset=0, limit=5):
        """
        Search sploitus.com.
        
        Args:
            query: Search query string.
            search_type: "exploits" or "tools".
            offset: Pagination offset.
            limit: Max results.
            
        Returns:
            List of exploit dicts.
        """
        try:
            payload = {
                "type": search_type,
                "sort": "default",
                "query": query,
                "title": False,
                "offset": offset,
            }

            with httpx.Client(timeout=self.timeout, verify=False) as client:
                resp = client.post(SPLOITUS_API, json=payload)

                if resp.status_code != 200:
                    log_warning(f"Sploitus API returned {resp.status_code}")
                    return []

                data = resp.json()
                exploits = data.get("exploits", [])

                results = []
                for exp in exploits[:limit]:
                    results.append({
                        "title": exp.get("title", ""),
                        "source": exp.get("source", ""),
                        "href": exp.get("href", ""),
                        "id": exp.get("id", ""),
                        "published": exp.get("published", ""),
                        "score": exp.get("score", 0),
                        "type": exp.get("type", "exploit"),
                    })

                return results

        except ScanExceptions as e:
            log_warning(f"Sploitus search failed: {e}")
            return []

    def search_by_cve(self, cve_id, limit=5):
        """Search for exploits by CVE ID."""
        return self.search(cve_id, limit=limit)

    def search_by_tech(self, tech, version="", limit=5):
        """
        Search for exploits by technology and version.
        
        Args:
            tech: Technology name (e.g., "Apache", "nginx").
            version: Version string (e.g., "2.4.49").
            limit: Max results.
        """
        query = f"{tech} {version}".strip()
        return self.search(query, limit=limit)

    def enrich_findings(self, findings, tech_stack=None):
        """
        Enrich findings and tech stack with known exploits.
        
        Args:
            findings: List of vulnerability finding dicts.
            tech_stack: Dict of detected technologies {name: version}.
            
        Returns:
            List of exploit enrichment dicts.
        """
        enrichments = []

        # Search by CVE from findings
        seen_cves = set()
        for f in findings:
            cve = f.get("cve") or f.get("cwe", "")
            if cve.startswith("CVE-") and cve not in seen_cves:
                seen_cves.add(cve)
                exploits = self.search_by_cve(cve, limit=3)
                if exploits:
                    enrichments.append({
                        "source": "finding",
                        "query": cve,
                        "url": f.get("url", ""),
                        "exploits": exploits,
                    })

        # Search by tech stack
        if tech_stack:
            for tech, version in tech_stack.items():
                if not version or version == "unknown":
                    continue
                exploits = self.search_by_tech(tech, version, limit=3)
                if exploits:
                    enrichments.append({
                        "source": "tech_stack",
                        "query": f"{tech} {version}",
                        "exploits": exploits,
                    })

        return enrichments

    def print_results(self, enrichments):
        """Print formatted exploit search results."""
        if not enrichments:
            log_info("No known exploits found in Sploitus.")
            return

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 55}")
        print(f"  ⚡ Sploitus Exploit Search Results")
        print(f"{'═' * 55}{Colors.END}")

        for enr in enrichments:
            query = enr["query"]
            source = enr["source"]
            exploits = enr["exploits"]

            icon = "🎯" if source == "finding" else "🔧"
            print(f"\n  {icon} {Colors.BOLD}{query}{Colors.END}")

            for exp in exploits:
                title = exp["title"][:60]
                src = exp.get("source", "unknown")
                href = exp.get("href", "")
                score = exp.get("score", 0)

                if score > 7:
                    color = Colors.RED
                elif score > 4:
                    color = Colors.YELLOW
                else:
                    color = Colors.GREEN

                print(f"    {color}⚡ {title}{Colors.END}")
                print(f"      Source: {src} | Score: {score}")
                if href:
                    print(f"      URL: {href}")

        total = sum(len(e["exploits"]) for e in enrichments)
        log_success(f"Found {total} known exploit(s) across {len(enrichments)} queries")
        print()


# Singleton accessor
_search_instance = None


def get_sploitus(timeout=10):
    """Get or create SploitusSearch instance."""
    global _search_instance
    if _search_instance is None:
        _search_instance = SploitusSearch(timeout=timeout)
    return _search_instance
