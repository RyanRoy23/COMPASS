"""Tests du module de gouvernance NIS 2 Art. 20."""

import pytest
from nis2_analyzer.core.governance import (
    assess_governance,
    get_questions_schema,
    GovernanceResult,
    GovMaturity,
    GOVERNANCE_QUESTIONS,
)


def full_responses(level: int) -> dict[str, int]:
    """Toutes les questions à un niveau donné."""
    return {q.id: level for q in GOVERNANCE_QUESTIONS}


# ── Score et grade ────────────────────────────────────────────────────────────

class TestScoring:
    def test_all_managed_gives_100(self):
        r = assess_governance(full_responses(3))
        assert r.overall_score == 100.0

    def test_all_absent_gives_0(self):
        r = assess_governance(full_responses(0))
        assert r.overall_score == 0.0

    def test_partial_score_in_range(self):
        responses = {q.id: 2 for q in GOVERNANCE_QUESTIONS}
        r = assess_governance(responses)
        assert 60 < r.overall_score < 70   # niveau 2 = 66.7%

    def test_no_responses_gives_0(self):
        r = assess_governance({})
        assert r.overall_score == 0.0

    def test_grade_a_at_high_score(self):
        r = assess_governance(full_responses(3))
        assert r.grade == "A"

    def test_grade_f_at_zero(self):
        r = assess_governance(full_responses(0))
        assert r.grade == "F"

    def test_weighted_questions_affect_score(self):
        """G01 (weight 1.5) et G03 (weight 1.5) ont plus d'impact."""
        # Toutes à 0 sauf G01 à 3
        responses_g01 = {q.id: 0 for q in GOVERNANCE_QUESTIONS}
        responses_g01["G01"] = 3
        # Toutes à 0 sauf G04 à 3 (weight 1.0)
        responses_g04 = {q.id: 0 for q in GOVERNANCE_QUESTIONS}
        responses_g04["G04"] = 3
        r1 = assess_governance(responses_g01)
        r4 = assess_governance(responses_g04)
        assert r1.overall_score > r4.overall_score


# ── Gaps ─────────────────────────────────────────────────────────────────────

class TestGaps:
    def test_all_absent_all_gaps(self):
        r = assess_governance(full_responses(0))
        assert r.total_gaps == len(GOVERNANCE_QUESTIONS)
        assert r.critical_gaps == len(GOVERNANCE_QUESTIONS)

    def test_all_defined_no_gaps(self):
        r = assess_governance(full_responses(2))
        assert r.total_gaps == 0
        assert r.critical_gaps == 0

    def test_initial_is_gap_not_critical(self):
        r = assess_governance({"G01": 1})
        q = next(q for q in r.questions if q.id == "G01")
        assert q.is_gap is True
        assert q.is_critical_gap is False

    def test_gaps_by_pillar_groups_correctly(self):
        r = assess_governance({"G01": 0, "G03": 0})
        gaps = r.gaps_by_pillar
        assert "Approbation" in gaps
        assert "Formation" in gaps


# ── Responsabilité dirigeants ────────────────────────────────────────────────

class TestLiabilityRisk:
    def test_essential_high_risk_when_governance_missing(self):
        r = assess_governance({"G01": 0, "G02": 0, "G05": 0}, entity_category="essentielle")
        assert r.liability_risk == "ÉLEVÉ"

    def test_essential_low_risk_when_governance_ok(self):
        r = assess_governance({"G01": 3, "G02": 3, "G05": 3}, entity_category="essentielle")
        assert r.liability_risk == "FAIBLE"

    def test_important_moderate_risk(self):
        r = assess_governance({"G01": 0, "G02": 0, "G05": 0}, entity_category="importante")
        assert r.liability_risk == "MODÉRÉ"

    def test_default_category_is_importante(self):
        r = assess_governance({})
        assert r.entity_category == "importante"


# ── Recommandations ──────────────────────────────────────────────────────────

class TestRecommendations:
    def test_critical_gaps_produce_critical_recs(self):
        r = assess_governance({"G01": 0, "G03": 0})
        d = r.to_dict()
        priorities = [rec["priority"] for rec in d["recommendations"]]
        assert "CRITIQUE" in priorities

    def test_recs_sorted_by_priority(self):
        r = assess_governance(full_responses(0))
        d = r.to_dict()
        recs = d["recommendations"]
        order = {"CRITIQUE": 0, "ÉLEVÉE": 1, "MOYENNE": 2, "NORMALE": 3}
        scores = [order.get(rec["priority"], 9) for rec in recs]
        assert scores == sorted(scores)

    def test_no_recs_when_no_gaps(self):
        r = assess_governance(full_responses(3))
        d = r.to_dict()
        assert d["recommendations"] == []


# ── to_dict ──────────────────────────────────────────────────────────────────

class TestToDict:
    def test_required_keys(self):
        r = assess_governance({"G01": 2, "G03": 1})
        d = r.to_dict()
        for key in ("overall_score", "grade", "total_gaps", "critical_gaps",
                    "liability_risk", "questions", "recommendations", "gaps_by_pillar"):
            assert key in d

    def test_question_keys(self):
        r = assess_governance({"G01": 2})
        q = r.to_dict()["questions"][0]
        assert "id" in q
        assert "maturity" in q
        assert "is_gap" in q


# ── Validation des entrées ───────────────────────────────────────────────────

class TestValidation:
    def test_invalid_maturity_raises(self):
        with pytest.raises(ValueError, match="Maturité invalide"):
            assess_governance({"G01": 5})

    def test_unknown_question_id_ignored(self):
        r = assess_governance({"G99": 2})
        # Pas d'erreur, G99 est ignoré
        assert r.overall_score == 0.0


# ── Schema des questions ─────────────────────────────────────────────────────

class TestQuestionsSchema:
    def test_returns_8_questions(self):
        schema = get_questions_schema()
        assert len(schema) == 8

    def test_schema_has_required_keys(self):
        schema = get_questions_schema()
        for q in schema:
            assert "id" in q
            assert "pillar" in q
            assert "question" in q
            assert "article_ref" in q

    def test_all_ids_unique(self):
        schema = get_questions_schema()
        ids = [q["id"] for q in schema]
        assert len(ids) == len(set(ids))
