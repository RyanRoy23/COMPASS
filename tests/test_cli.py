"""Tests des commandes CLI non-interactives."""

import sys
import pytest
from unittest.mock import patch
from io import StringIO

from nis2_analyzer.cli import _cmd_history, _cmd_compare
from nis2_analyzer.core.database import save_assessment


def _sample_analysis(org="TT Corporation", score=65.0, grade="C", gaps=8):
    return {
        "metadata": {"organization": org},
        "scores": {
            "overall_score": score,
            "grade": grade,
            "total_requirements": 35,
            "total_gaps": gaps,
            "total_critical_gaps": 2,
        },
        "domains": [
            {"title": "Politiques de securite", "score": 60.0},
            {"title": "Gestion des incidents", "score": 70.0},
        ],
        "gaps": [],
        "action_plan": [],
    }


# ── Tests _cmd_history ────────────────────────────────────────────────────────

class TestCmdHistory:
    def test_empty_history_prints_message(self, capsys):
        with patch("nis2_analyzer.core.database.list_assessments", return_value=[]):
            _cmd_history()
        out = capsys.readouterr().out
        assert "Aucun" in out or "aucun" in out.lower()

    def test_history_displays_assessments(self, capsys):
        rows = [
            {"id": 1, "org_name": "TT Corporation", "assessed_at": "2026-06-01T10:00:00Z",
             "score": 65.0, "grade": "C", "total_gaps": 8},
            {"id": 2, "org_name": "TT Corporation", "assessed_at": "2026-06-21T10:00:00Z",
             "score": 72.0, "grade": "B", "total_gaps": 5},
        ]
        with patch("nis2_analyzer.core.database.list_assessments", return_value=rows):
            _cmd_history()
        out = capsys.readouterr().out
        assert "TT Corporation" in out
        assert "65.0" in out
        assert "72.0" in out

    def test_history_filter_by_org_name(self, capsys):
        with patch("nis2_analyzer.core.database.list_assessments", return_value=[]) as mock:
            _cmd_history(org_name="TT")
            call_kwargs = mock.call_args.kwargs
            assert call_kwargs.get("org_name") == "TT"


# ── Tests _cmd_compare ────────────────────────────────────────────────────────

class TestCmdCompare:
    def test_compare_shows_delta(self, capsys):
        delta = {
            "org_name": "TT Corporation",
            "date_before": "2026-01-01T00:00:00Z",
            "date_after": "2026-06-21T00:00:00Z",
            "score_before": 40.0,
            "score_after": 65.0,
            "score_delta": 25.0,
            "gaps_before": 20,
            "gaps_after": 8,
            "gaps_delta": -12,
            "grade_before": "D",
            "grade_after": "C",
            "domains": [{"domain": "Politiques", "score_before": 40.0, "score_after": 70.0, "delta": 30.0}],
        }
        with patch("nis2_analyzer.core.database.compare_assessments", return_value=delta):
            _cmd_compare(1, 2)
        out = capsys.readouterr().out
        assert "40.0%" in out
        assert "65.0%" in out
        assert "TT Corporation" in out

    def test_compare_unknown_id_prints_error(self, capsys):
        with patch("nis2_analyzer.core.database.compare_assessments", side_effect=ValueError("Assessment #99 introuvable.")):
            _cmd_compare(1, 99)
        out = capsys.readouterr().out
        assert "introuvable" in out or "Erreur" in out
