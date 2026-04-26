"""Tests for utils/attack_mapping — MITRE ATT&CK technique mapping."""

from __future__ import annotations

import pytest

from utils.attack_mapping import (
    TECHNIQUE_CATALOG,
    TechniqueRef,
    all_known_vuln_types,
    tactics_for_vuln,
    tag_finding_dict,
    tag_findings,
    techniques_for_vuln,
)


pytestmark = pytest.mark.unit


# ─── Catalog integrity ───────────────────────────────────────────────────────


class TestCatalog:
    def test_all_referenced_techniques_exist_in_catalog(self):
        # Every technique referenced from any vuln_type must resolve.
        for vt in all_known_vuln_types():
            techs = techniques_for_vuln(vt)
            assert techs, f"no techniques for {vt}"
            for t in techs:
                assert t.id in TECHNIQUE_CATALOG, f"{t.id} missing from catalog"

    def test_technique_ids_are_well_formed(self):
        for tid, tref in TECHNIQUE_CATALOG.items():
            assert tid.startswith("T")
            assert tref.tactic, f"{tid} has no tactic"
            assert tref.name, f"{tid} has no name"

    def test_catalog_url_falls_back_to_attack_mitre(self):
        ref = TECHNIQUE_CATALOG["T1190"]
        assert "attack.mitre.org" in ref.to_dict()["url"]


# ─── Vuln-type lookup ────────────────────────────────────────────────────────


class TestTechniqueLookup:
    def test_xss_includes_javascript_execution_and_session_cookie_theft(self):
        techs = techniques_for_vuln("XSS_Param")
        ids = [t.id for t in techs]
        assert "T1059.007" in ids   # JavaScript execution
        assert "T1539" in ids       # Steal Web Session Cookie

    def test_sqli_includes_data_collection_and_initial_access(self):
        techs = techniques_for_vuln("SQLi_Param")
        ids = [t.id for t in techs]
        assert "T1190" in ids
        assert "T1213" in ids

    def test_cmdi_includes_shell_techniques(self):
        techs = techniques_for_vuln("CMDi")
        ids = [t.id for t in techs]
        assert "T1059" in ids

    def test_unknown_vuln_falls_back_to_t1190(self):
        techs = techniques_for_vuln("CompletelyUnknownThing")
        assert len(techs) == 1
        assert techs[0].id == "T1190"

    def test_empty_string_falls_back_to_t1190(self):
        techs = techniques_for_vuln("")
        assert techs[0].id == "T1190"

    def test_case_insensitive_match(self):
        ids_lower = [t.id for t in techniques_for_vuln("xss_param")]
        ids_upper = [t.id for t in techniques_for_vuln("XSS_PARAM")]
        ids_orig = [t.id for t in techniques_for_vuln("XSS_Param")]
        assert ids_lower == ids_upper == ids_orig

    def test_fuzzy_match_for_family_root(self):
        # Made-up but contains "xss" — should hit XSS family fallback.
        techs = techniques_for_vuln("Custom_XSS_Variant_Z")
        ids = [t.id for t in techs]
        assert "T1059.007" in ids


# ─── Tactics aggregation ─────────────────────────────────────────────────────


class TestTactics:
    def test_xss_tactics_include_execution(self):
        tactics = tactics_for_vuln("XSS_Param")
        assert "Execution" in tactics
        assert "Initial Access" in tactics

    def test_brute_force_tactic_is_credential_access(self):
        tactics = tactics_for_vuln("Brute_Force")
        assert tactics == ["Credential Access"]


# ─── Finding tagger ──────────────────────────────────────────────────────────


class TestTagFindingDict:
    def test_adds_attack_fields_without_mutating_input(self):
        finding = {"type": "SQLi_Param", "url": "http://t/?id=1"}
        tagged = tag_finding_dict(finding)
        assert "attack_techniques" not in finding   # original untouched
        assert "attack_techniques" in tagged
        assert "attack_tactics" in tagged
        assert tagged["url"] == finding["url"]

    def test_techniques_have_url_to_attack_mitre(self):
        tagged = tag_finding_dict({"type": "XSS_Param"})
        for tech in tagged["attack_techniques"]:
            assert tech["url"].startswith("https://attack.mitre.org/techniques/")

    def test_falls_back_to_finding_type_field(self):
        finding = {"finding_type": "LFI_Param"}
        tagged = tag_finding_dict(finding)
        ids = [t["id"] for t in tagged["attack_techniques"]]
        assert "T1083" in ids

    def test_non_dict_input_returned_as_is(self):
        assert tag_finding_dict("not a dict") == "not a dict"
        assert tag_finding_dict(None) is None

    def test_tag_findings_bulk(self):
        findings = [
            {"type": "XSS_Param"},
            {"type": "SQLi_Param"},
            {"type": "Subdomain_Takeover"},
        ]
        out = tag_findings(findings)
        assert len(out) == 3
        for f in out:
            assert "attack_techniques" in f
            assert isinstance(f["attack_tactics"], list)
