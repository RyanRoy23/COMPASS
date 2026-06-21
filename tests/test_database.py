"""Tests de la couche de persistance SQLite."""

import os
import tempfile
import pytest
from nis2_analyzer.core.database import (
    init_db, save_assessment, list_assessments, get_assessment, compare_assessments
)


def _sample_analysis(org="TT Corporation", score=65.0, grade="C", gaps=8):
    return {
        "metadata": {"organization": org},
        "scores": {
            "overall_score": score,
            "grade": grade,
            "total_requirements": 35,
            "total_gaps": gaps,
            "total_critical_gaps": 3,
        },
        "domains": [
            {"title": "Politiques de securite", "score": 70.0},
            {"title": "Gestion des incidents", "score": 50.0},
        ],
        "gaps": [],
        "action_plan": [],
    }


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "test_history.db")


class TestInitDb:
    def test_creates_db_file(self, tmp_db):
        init_db(tmp_db)
        assert os.path.exists(tmp_db)

    def test_idempotent(self, tmp_db):
        init_db(tmp_db)
        init_db(tmp_db)  # ne doit pas lever d'exception
        assert os.path.exists(tmp_db)


class TestSaveAssessment:
    def test_returns_integer_id(self, tmp_db):
        aid = save_assessment(_sample_analysis(), db_path=tmp_db)
        assert isinstance(aid, int)
        assert aid >= 1

    def test_ids_increment(self, tmp_db):
        id1 = save_assessment(_sample_analysis(), db_path=tmp_db)
        id2 = save_assessment(_sample_analysis(), db_path=tmp_db)
        assert id2 > id1

    def test_stores_correct_metadata(self, tmp_db):
        save_assessment(_sample_analysis(org="TT Corporation", score=72.5, grade="B"), db_path=tmp_db)
        rows = list_assessments(db_path=tmp_db)
        assert rows[0]["org_name"] == "TT Corporation"
        assert rows[0]["score"] == 72.5
        assert rows[0]["grade"] == "B"


class TestListAssessments:
    def test_empty_db_returns_empty_list(self, tmp_db):
        assert list_assessments(db_path=tmp_db) == []

    def test_returns_most_recent_first(self, tmp_db):
        save_assessment(_sample_analysis(score=50.0), db_path=tmp_db)
        save_assessment(_sample_analysis(score=75.0), db_path=tmp_db)
        rows = list_assessments(db_path=tmp_db)
        assert rows[0]["score"] == 75.0

    def test_filter_by_org_name(self, tmp_db):
        save_assessment(_sample_analysis(org="TT Corporation"), db_path=tmp_db)
        save_assessment(_sample_analysis(org="Autre Corp"), db_path=tmp_db)
        rows = list_assessments(org_name="TT", db_path=tmp_db)
        assert len(rows) == 1
        assert rows[0]["org_name"] == "TT Corporation"

    def test_limit_respected(self, tmp_db):
        for _ in range(5):
            save_assessment(_sample_analysis(), db_path=tmp_db)
        rows = list_assessments(limit=3, db_path=tmp_db)
        assert len(rows) == 3


class TestGetAssessment:
    def test_returns_full_payload(self, tmp_db):
        aid = save_assessment(_sample_analysis(), db_path=tmp_db)
        result = get_assessment(aid, db_path=tmp_db)
        assert result is not None
        assert isinstance(result["payload"], dict)
        assert result["payload"]["metadata"]["organization"] == "TT Corporation"

    def test_returns_none_for_unknown_id(self, tmp_db):
        assert get_assessment(9999, db_path=tmp_db) is None


class TestCompareAssessments:
    def test_positive_delta_when_score_improves(self, tmp_db):
        id_a = save_assessment(_sample_analysis(score=50.0, gaps=12), db_path=tmp_db)
        id_b = save_assessment(_sample_analysis(score=70.0, gaps=6), db_path=tmp_db)
        delta = compare_assessments(id_a, id_b, db_path=tmp_db)
        assert delta["score_delta"] == 20.0
        assert delta["gaps_delta"] == -6

    def test_negative_delta_when_score_drops(self, tmp_db):
        id_a = save_assessment(_sample_analysis(score=80.0), db_path=tmp_db)
        id_b = save_assessment(_sample_analysis(score=60.0), db_path=tmp_db)
        delta = compare_assessments(id_a, id_b, db_path=tmp_db)
        assert delta["score_delta"] == -20.0

    def test_raises_on_unknown_id(self, tmp_db):
        aid = save_assessment(_sample_analysis(), db_path=tmp_db)
        with pytest.raises(ValueError, match="introuvable"):
            compare_assessments(aid, 9999, db_path=tmp_db)

    def test_domain_deltas_computed(self, tmp_db):
        id_a = save_assessment(_sample_analysis(score=50.0), db_path=tmp_db)
        id_b = save_assessment(_sample_analysis(score=70.0), db_path=tmp_db)
        delta = compare_assessments(id_a, id_b, db_path=tmp_db)
        assert len(delta["domains"]) == 2
        assert "domain" in delta["domains"][0]
