"""Tests du référentiel ReCyF (20 objectifs, 4 piliers) et de son intégration."""

import pytest

from nis2_analyzer.core.models import MaturityLevel
from nis2_analyzer.core.recyf import (
    load_recyf_framework, filter_by_applicability, coverage_summary,
    MODULE_COVERED_OBJECTIVES,
)
from nis2_analyzer.core.scoring import ScoringEngine
from nis2_analyzer.connectors.cloudsec_bridge import CloudSecBridge


class TestRecyfFrameworkStructure:
    def test_loads_20_objectives(self):
        domains = load_recyf_framework()
        assert sum(d.total_requirements for d in domains) == 20

    def test_loads_4_pillars(self):
        domains = load_recyf_framework()
        assert len(domains) == 4
        assert {d.title for d in domains} == {"Gouvernance", "Protection", "Défense", "Résilience"}

    def test_pillar_objective_counts(self):
        domains = load_recyf_framework()
        counts = {d.title: d.total_requirements for d in domains}
        assert counts == {"Gouvernance": 7, "Protection": 8, "Défense": 2, "Résilience": 3}

    def test_objective_ids_are_unique(self):
        domains = load_recyf_framework()
        ids = [r.id for d in domains for r in d.sub_requirements]
        assert len(ids) == len(set(ids)) == 20

    def test_five_objectives_are_essential_only(self):
        domains = load_recyf_framework()
        essential_only = [r for d in domains for r in d.sub_requirements if r.is_essential_only]
        assert {r.id for r in essential_only} == {
            "RECYF-OS16", "RECYF-OS17", "RECYF-OS18", "RECYF-OS19", "RECYF-OS20",
        }

    def test_every_objective_has_a_question_and_remediation(self):
        domains = load_recyf_framework()
        for d in domains:
            for r in d.sub_requirements:
                assert r.question
                assert r.remediation.quick_win
                assert r.remediation.full_implementation


class TestApplicabilityFiltering:
    def test_important_entity_loses_the_5_essential_only_objectives(self):
        domains = load_recyf_framework()
        filter_by_applicability(domains, "importante")
        assert sum(d.total_requirements for d in domains) == 15
        remaining_ids = {r.id for d in domains for r in d.sub_requirements}
        assert "RECYF-OS16" not in remaining_ids

    def test_essential_entity_keeps_all_20(self):
        domains = load_recyf_framework()
        filter_by_applicability(domains, "essentielle")
        assert sum(d.total_requirements for d in domains) == 20

    def test_unknown_category_defaults_to_the_conservative_15(self):
        domains = load_recyf_framework()
        filter_by_applicability(domains, "hors_champ")
        assert sum(d.total_requirements for d in domains) == 15


class TestCoverageSummary:
    def test_totals_are_consistent(self):
        domains = load_recyf_framework()
        cov = coverage_summary(domains)
        assert cov["total_objectives"] == 20
        assert cov["covered"] + cov["declarative_only"] == 20

    def test_module_covered_objectives_are_flagged(self):
        domains = load_recyf_framework()
        cov = coverage_summary(domains)
        by_id = {d["id"]: d for d in cov["details"]}
        for req_id in MODULE_COVERED_OBJECTIVES:
            assert "module_dedie" in by_id[req_id]["sources"]

    def test_bridge_covered_objectives_are_flagged(self):
        domains = load_recyf_framework()
        cov = coverage_summary(domains)
        by_id = {d["id"]: d for d in cov["details"]}
        assert "preuve_technique" in by_id["RECYF-OS10"]["sources"]  # MFA, IDN-*

    def test_physical_access_objective_is_declarative_only(self):
        # OS6 (accès physiques) n'est couvert ni par le bridge Azure, ni par un module dédié.
        domains = load_recyf_framework()
        cov = coverage_summary(domains)
        by_id = {d["id"]: d for d in cov["details"]}
        assert by_id["RECYF-OS06"]["status"] == "declaratif"


class TestScoringEngineCompatibility:
    def test_scoring_engine_works_on_recyf_domains(self):
        domains = load_recyf_framework()
        for d in domains:
            for r in d.sub_requirements:
                r.maturity = MaturityLevel(3)
        engine = ScoringEngine()
        result = engine.calculate(domains, "TestOrg")
        assert result.overall_score == 100.0

    def test_full_analysis_reports_20_requirements(self):
        domains = load_recyf_framework()
        for d in domains:
            for r in d.sub_requirements:
                r.maturity = MaturityLevel(2)
        engine = ScoringEngine()
        analysis = engine.full_analysis(domains, "TestOrg")
        assert analysis["scores"]["total_requirements"] == 20


class TestCloudSecBridgeOnRecyf:
    def test_apply_to_recyf_framework_fills_technical_objectives(self):
        domains = load_recyf_framework()
        bridge = CloudSecBridge()
        bridge.load_from_dict(CloudSecBridge.demo_report())
        bridge.map_to_nis2()
        result = bridge.apply_to_recyf_framework(domains)

        assert result["auto_filled"] > 0
        req_index = {r.id: r for d in domains for r in d.sub_requirements}
        # OS10 (identités/accès) doit être pré-rempli par les checks MFA (IDN-*)
        assert req_index["RECYF-OS10"].maturity is not None
        assert req_index["RECYF-OS10"].notes.startswith("[AUTO - CloudSec]")

    def test_recyf_and_art21_mappings_are_independent(self):
        """apply_to_framework (Art. 21) et apply_to_recyf_framework (ReCyF) ne se
        marchent pas dessus : appliquer l'un ne doit pas modifier l'autre référentiel."""
        from nis2_analyzer.core.models import load_framework

        art21_domains = load_framework()
        recyf_domains = load_recyf_framework()

        bridge = CloudSecBridge()
        bridge.load_from_dict(CloudSecBridge.demo_report())
        bridge.map_to_nis2()
        bridge.apply_to_framework(art21_domains)

        recyf_req_index = {r.id: r for d in recyf_domains for r in d.sub_requirements}
        assert all(r.maturity is None for r in recyf_req_index.values())
