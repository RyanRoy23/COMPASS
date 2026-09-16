"""Tests du module de résilience ReCyF (OS13-15)."""

import pytest
from nis2_analyzer.core.resilience import (
    assess_resilience,
    get_questions_schema,
    ResilienceMaturity,
    RESILIENCE_QUESTIONS,
)


def full_responses(level: int) -> dict[str, int]:
    """Toutes les questions à un niveau donné."""
    return {q.id: level for q in RESILIENCE_QUESTIONS}


# ── Score et grade ────────────────────────────────────────────────────────────

class TestScoring:
    def test_all_managed_gives_100(self):
        r = assess_resilience(full_responses(3))
        assert r.overall_score == 100.0

    def test_all_absent_gives_0(self):
        r = assess_resilience(full_responses(0))
        assert r.overall_score == 0.0

    def test_no_responses_gives_0(self):
        r = assess_resilience({})
        assert r.overall_score == 0.0

    def test_grade_a_at_high_score(self):
        r = assess_resilience(full_responses(3))
        assert r.grade == "A"

    def test_grade_f_at_zero(self):
        r = assess_resilience(full_responses(0))
        assert r.grade == "F"


# ── Gaps ─────────────────────────────────────────────────────────────────────

class TestGaps:
    def test_all_absent_all_gaps(self):
        r = assess_resilience(full_responses(0))
        assert r.total_gaps == len(RESILIENCE_QUESTIONS)
        assert r.critical_gaps == len(RESILIENCE_QUESTIONS)

    def test_all_defined_no_gaps(self):
        r = assess_resilience(full_responses(2))
        assert r.total_gaps == 0
        assert r.critical_gaps == 0

    def test_initial_is_gap_not_critical(self):
        r = assess_resilience({"RES01": 1})
        q = next(q for q in r.questions if q.id == "RES01")
        assert q.is_gap is True
        assert q.is_critical_gap is False


# ── Maturité par objectif ReCyF (principe de prudence) ────────────────────────

class TestMaturityByObjective:
    def test_covers_the_three_resilience_objectives(self):
        r = assess_resilience(full_responses(2))
        assert set(r.maturity_by_objective.keys()) == {
            "RECYF-OS13", "RECYF-OS14", "RECYF-OS15",
        }

    def test_unanswered_objective_is_none(self):
        r = assess_resilience({})
        assert r.maturity_by_objective["RECYF-OS13"] is None

    def test_takes_the_lowest_level_within_an_objective(self):
        # RES01-03 -> RECYF-OS13 : deux hauts, un bas
        r = assess_resilience({"RES01": 3, "RES02": 3, "RES03": 0})
        assert r.maturity_by_objective["RECYF-OS13"] == 0

    def test_objective_not_answered_stays_none_even_if_others_are(self):
        r = assess_resilience({"RES01": 3})  # RECYF-OS13 seulement
        assert r.maturity_by_objective["RECYF-OS13"] == 3
        assert r.maturity_by_objective["RECYF-OS14"] is None
        assert r.maturity_by_objective["RECYF-OS15"] is None


# ── to_dict ──────────────────────────────────────────────────────────────────

class TestToDict:
    def test_required_keys(self):
        r = assess_resilience({"RES01": 2, "RES04": 1})
        d = r.to_dict()
        for key in ("overall_score", "grade", "total_gaps", "critical_gaps",
                    "maturity_by_objective", "questions"):
            assert key in d

    def test_question_keys(self):
        r = assess_resilience({"RES01": 2})
        q = r.to_dict()["questions"][0]
        assert "id" in q
        assert "recyf_objective" in q
        assert "maturity" in q
        assert "is_gap" in q


# ── Validation des entrées ───────────────────────────────────────────────────

class TestValidation:
    def test_invalid_maturity_raises(self):
        with pytest.raises(ValueError, match="Maturité invalide"):
            assess_resilience({"RES01": 5})

    def test_unknown_question_id_ignored(self):
        r = assess_resilience({"RES99": 2})
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
            assert "recyf_objective" in q
            assert "pillar" in q
            assert "question" in q

    def test_all_ids_unique(self):
        schema = get_questions_schema()
        ids = [q["id"] for q in schema]
        assert len(ids) == len(set(ids))

    def test_three_two_two_split_across_objectives(self):
        schema = get_questions_schema()
        from collections import Counter
        counts = Counter(q["recyf_objective"] for q in schema)
        assert counts == {"RECYF-OS13": 3, "RECYF-OS14": 3, "RECYF-OS15": 2}
