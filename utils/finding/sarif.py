"""SARIF 2.1.0 report generation."""

from __future__ import annotations


def generate_sarif(findings: list, tool_name: str = "cyberm4fia-scanner") -> dict:
    """Generate a SARIF 2.1.0 report from a list of Finding objects."""
    rules: dict = {}
    results: list = []
    for f in findings:
        if f.cwe not in rules:
            rules[f.cwe] = {
                "id": f.cwe,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html"
                if "-" in f.cwe
                else "",
                "properties": {"cvss": f.cvss, "severity": f.severity},
            }
        results.append(f.to_sarif_result())

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/erkanrzgc/cyberm4fia-scanner",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
