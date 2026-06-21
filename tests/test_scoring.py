"""Tests du moteur de scoring."""

import pytest
from nis2_analyzer.core.models import load_framework, MaturityLevel
from nis2_analyzer.core.scoring import ScoringEngine


@pytest.fixture
def domains_with_all_maturity_2():
    domains = load_framework()
    for d in domains:
        for r in d.sub_requirements:
            r.maturity = MaturityLevel(2)
    return domains


@pytest.fixture
def domains_with_all_maturity_0():
    domains = load_framework()
    for d in domains:
        for r in d.sub_requirements:
            r.maturity = MaturityLevel(0)
    return domains


class TestScoringEngine:
    def test_perfect_score_when_all_maturity_3(self):
        domains = load_framework()
        for d in domains:
            for r in d.sub_requirements:
                r.maturity = MaturityLevel(3)
        engine = ScoringEngine()
        result = engine.calculate(domains, "Test")
        assert result.overall_score == 100.0

    def test_zero_score_when_all_maturity_0(self, domains_with_all_maturity_0):
        engine = ScoringEngine()
        result = engine.calculate(domains_with_all_maturity_0, "Test")
        assert result.overall_score == 0.0

    def test_grade_a_at_90_percent(self):
        domains = load_framework()
        for d in domains:
            for r in d.sub_requirements:
                r.maturity = MaturityLevel(3)
        engine = ScoringEngine()
        result = engine.calculate(domains, "Test")
        assert result.grade.value == "A"

    def test_grade_f_at_zero(self, domains_with_all_maturity_0):
        engine = ScoringEngine()
        result = engine.calculate(domains_with_all_maturity_0, "Test")
        assert result.grade.value == "F"

    def test_all_gaps_when_maturity_zero(self, domains_with_all_maturity_0):
        engine = ScoringEngine()
        result = engine.calculate(domains_with_all_maturity_0, "Test")
        assert result.total_gaps == 35

    def test_no_gaps_when_maturity_two(self, domains_with_all_maturity_2):
        engine = ScoringEngine()
        result = engine.calculate(domains_with_all_maturity_2, "Test")
        assert result.total_gaps == 0

    def test_org_name_stored_in_result(self):
        domains = load_framework()
        engine = ScoringEngine()
        result = engine.calculate(domains, "TT Corporation")
        assert result.organization_name == "TT Corporation"

    def test_full_analysis_returns_dict(self, domains_with_all_maturity_2):
        engine = ScoringEngine()
        analysis = engine.full_analysis(domains_with_all_maturity_2, "TT Corporation")
        assert isinstance(analysis, dict)
        assert "scores" in analysis
        assert "metadata" in analysis
        assert "domains" in analysis
        assert "gaps" in analysis

    def test_full_analysis_org_in_metadata(self, domains_with_all_maturity_2):
        engine = ScoringEngine()
        analysis = engine.full_analysis(domains_with_all_maturity_2, "TT Corporation")
        assert analysis["metadata"]["organization"] == "TT Corporation"

    def test_domain_scores_sum_makes_sense(self, domains_with_all_maturity_2):
        engine = ScoringEngine()
        analysis = engine.full_analysis(domains_with_all_maturity_2, "Test")
        for d in analysis["domains"]:
            assert 0 <= d["score"] <= 100
