"""
cyberm4fia-scanner - Payload Filter
Dynamically filters payload lists based on the detected technologies
of the target application to reduce noise and WAF detections.
"""

import re
import logging

logger = logging.getLogger(__name__)


class PayloadFilter:
    """
    Filters payload lists based on target context (OS, Language, DB, Web Server).
    Uses regex patterns to identify technology-specific payloads that can be safely
    skipped if the target's technology is known and different.
    """

    # Technology specific indicators in payloads
    TECH_INDICATORS = {
        # Operating Systems
        "os": {
            "windows": {
                "patterns": [
                    r"(?i)\bwindows\b",
                    r"(?i)\bsystem32\b",
                    r"(?i)\bcmd\.exe\b",
                    r"(?i)\bpowershell\b",
                    r"(?i)[c-z]:\\",
                    r"(?i)\bwin\.ini\b",
                    r"(?i)\bboot\.ini\b",
                    r"(?i)\bsystem\.ini\b",
                ],
                "incompatible_with": ["linux", "unix", "macos"],
            },
            "linux": {
                "patterns": [
                    r"(?i)/etc/passwd",
                    r"(?i)/etc/shadow",
                    r"(?i)/bin/bash",
                    r"(?i)/bin/sh",
                    r"(?i)\bcat\s+/",
                ],
                "incompatible_with": ["windows"],
            },
        },
        # Databases
        "db": {
            "mysql": {
                "patterns": [
                    r"(?i)\bsleep\(",
                    r"(?i)\bbenchmark\(",
                    r"(?i)concat\(",
                    r"(?i)information_schema",
                ],
                "incompatible_with": ["mssql", "postgresql", "oracle", "sqlite"],
            },
            "mssql": {
                "patterns": [
                    r"(?i)waitfor\s+delay",
                    r"(?i)\bxtp_.*\b",
                    r"(?i)\bsys\.",
                ],
                "incompatible_with": ["mysql", "postgresql", "oracle", "sqlite"],
            },
            "postgresql": {
                "patterns": [
                    r"(?i)pg_sleep\(",
                    r"(?i)pg_database",
                ],
                "incompatible_with": ["mysql", "mssql", "oracle", "sqlite"],
            },
            "oracle": {
                "patterns": [
                    r"(?i)dbms_pipe\.receive_message",
                    r"(?i)dual\b",
                    r"(?i)v\$version",
                ],
                "incompatible_with": ["mysql", "mssql", "postgresql", "sqlite"],
            },
            "sqlite": {
                "patterns": [
                    r"(?i)sqlite_version\(",
                    r"(?i)sqlite_master",
                ],
                "incompatible_with": ["mysql", "mssql", "postgresql", "oracle"],
            },
        },
        # Languages / Frameworks
        "lang": {
            "php": {
                "patterns": [
                    r"(?i)php://",
                    r"(?i)\.php\b",
                    r"(?i)<\?php",
                    r"(?i)system\(",
                ],
                "incompatible_with": ["asp", "asp.net", "java", "python", "ruby"],
            },
            "java": {
                "patterns": [
                    r"(?i)java\.lang",
                    r"(?i)javax\.",
                    r"(?i)spring",
                    r"(?i)freemarker",
                ],
                "incompatible_with": ["php", "asp", "asp.net", "python", "ruby"],
            },
            "python": {
                "patterns": [
                    r"(?i)__class__",
                    r"(?i)__init__",
                    r"(?i)__subclasses__",
                    r"(?i)request\.application",
                    r"(?i)werkzeug",
                ],
                "incompatible_with": ["php", "asp", "asp.net", "java", "ruby"],
            },
        },
    }

    # Pre-compile ALL regex patterns once at class load for performance
    _COMPILED_PATTERNS = {}
    for category, techs in TECH_INDICATORS.items():
        _COMPILED_PATTERNS[category] = {}
        for tech, data in techs.items():
            _COMPILED_PATTERNS[category][tech] = {
                "patterns": [re.compile(p) for p in data["patterns"]],
                "incompatible_with": data["incompatible_with"],
            }

    @classmethod
    def filter_payloads(cls, payloads, target_context=None):
        """
        Filter a list of payloads based on the known target context.

        Args:
            payloads (list): List of string payloads (from payloads.py).
            target_context (dict): Dictionary defining known tech of the target.
                                   Format: {'os': 'linux', 'db': 'mysql', 'lang': 'php'}

        Returns:
            list: Filtered list of payloads, optimized for the target.
        """
        if not payloads or not target_context:
            return payloads  # No filtering if no context or empty payloads

        # Normalize context to lowercase sets for fast lookup
        known_techs = {
            category: {str(val).lower() for val in (
                [target_context.get(category)] if isinstance(target_context.get(category), str)
                else target_context.get(category, [])
            ) if val}
            for category in cls.TECH_INDICATORS.keys()
        }

        # If we know absolutely nothing about the target, don't filter
        if not any(known_techs.values()):
            return payloads

        filtered_payloads = []
        skipped_count = 0

        for payload in payloads:
            payload_is_compatible = True

            # Check OS incompatibility
            if not cls._is_compatible_with_context(payload, "os", known_techs["os"]):
                payload_is_compatible = False
            
            # Check DB incompatibility
            elif not cls._is_compatible_with_context(payload, "db", known_techs["db"]):
                payload_is_compatible = False
                
            # Check Language incompatibility
            elif not cls._is_compatible_with_context(payload, "lang", known_techs["lang"]):
                payload_is_compatible = False

            if payload_is_compatible:
                filtered_payloads.append(payload)
            else:
                skipped_count += 1

        if skipped_count > 0:
            logger.debug(f"[PayloadFilter] Skipped {skipped_count} payload(s) due to tech mismatch.")

        return filtered_payloads

    @classmethod
    def _is_compatible_with_context(cls, payload, category, target_techs_for_category):
        """
        Check if a payload is compatible with the known technologies for a specific category.
        Returns False if the payload contains indicators for a technology that is explicitly
        incompatible with the known target technologies. Otherwise returns True.
        """
        if not target_techs_for_category:
            return True  # If we don't know the target's tech for this category, assume compatible

        category_data = cls._COMPILED_PATTERNS.get(category, {})
        
        for tech_name, tech_data in category_data.items():
            # If this payload is strongly indicating `tech_name`...
            if any(pattern.search(payload) for pattern in tech_data["patterns"]):
                # ... check if `tech_name` is known to be incompatible with our target's actual tech
                # E.g. payload indicates 'mssql' but target is 'mysql'. Is 'mssql' incompatible with 'mysql'? Yes.
                for target_tech in target_techs_for_category:
                    if target_tech in tech_data["incompatible_with"]:
                        return False # Payload is for something incompatible with target
                        
        return True # Compatible or unknown
