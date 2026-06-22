"""Tests du module de notification d'incident NIS 2 Art. 23."""

import pytest
from datetime import datetime, timedelta, timezone

from nis2_analyzer.core.incident_notification import (
    classify_incident,
    compute_deadlines,
    assess_notification_maturity,
    get_notification_questions_schema,
    SignificanceCriteria,
    IncidentSignificance,
    NotificationStatus,
    NOTIFICATION_QUESTIONS,
)


# ── Classification de significativité ────────────────────────────────────────

class TestClassifyIncident:
    def test_critical_system_compromised_is_significant(self):
        c = SignificanceCriteria(critical_system_compromised=True)
        sig, reasons = classify_incident(c)
        assert sig == IncidentSignificance.SIGNIFICANT
        assert any("critique" in r.lower() for r in reasons)

    def test_data_breach_is_significant(self):
        sig, reasons = classify_incident(SignificanceCriteria(data_breach=True))
        assert sig == IncidentSignificance.SIGNIFICANT

    def test_supply_chain_impact_is_significant(self):
        sig, _ = classify_incident(SignificanceCriteria(supply_chain_impact=True))
        assert sig == IncidentSignificance.SIGNIFICANT

    def test_cross_border_is_significant(self):
        sig, _ = classify_incident(SignificanceCriteria(geographic_scope="cross_border"))
        assert sig == IncidentSignificance.SIGNIFICANT

    def test_long_outage_is_significant(self):
        c = SignificanceCriteria(services_unavailable=True, duration_hours=6.0)
        sig, _ = classify_incident(c)
        assert sig == IncidentSignificance.SIGNIFICANT

    def test_short_outage_is_potential(self):
        c = SignificanceCriteria(services_unavailable=True, duration_hours=2.0)
        sig, _ = classify_incident(c)
        assert sig == IncidentSignificance.POTENTIALLY

    def test_large_user_count_is_significant(self):
        sig, _ = classify_incident(SignificanceCriteria(users_affected_count=5000))
        assert sig == IncidentSignificance.SIGNIFICANT

    def test_small_user_count_is_potential(self):
        sig, _ = classify_incident(SignificanceCriteria(users_affected_count=200))
        assert sig == IncidentSignificance.POTENTIALLY

    def test_high_financial_loss_is_significant(self):
        sig, _ = classify_incident(SignificanceCriteria(financial_loss_eur=500_000))
        assert sig == IncidentSignificance.SIGNIFICANT

    def test_low_financial_loss_is_potential(self):
        sig, _ = classify_incident(SignificanceCriteria(financial_loss_eur=50_000))
        assert sig == IncidentSignificance.POTENTIALLY

    def test_no_criteria_is_unknown(self):
        sig, _ = classify_incident(SignificanceCriteria())
        assert sig == IncidentSignificance.UNKNOWN

    def test_third_party_impact_is_significant(self):
        sig, _ = classify_incident(SignificanceCriteria(third_party_impact=True))
        assert sig == IncidentSignificance.SIGNIFICANT

    def test_reasons_not_empty_for_significant(self):
        _, reasons = classify_incident(SignificanceCriteria(data_breach=True))
        assert len(reasons) > 0


# ── Calcul des deadlines ──────────────────────────────────────────────────────

class TestComputeDeadlines:
    def _detection(self, hours_ago=0):
        return datetime.now(timezone.utc) - timedelta(hours=hours_ago)

    def test_returns_three_deadlines(self):
        dl = compute_deadlines(self._detection())
        assert len(dl) == 3

    def test_deadline_names(self):
        dl = compute_deadlines(self._detection())
        names = [d.name for d in dl]
        assert "early_warning" in names
        assert "incident_notification" in names
        assert "final_report" in names

    def test_early_warning_is_24h(self):
        t0 = self._detection(hours_ago=0)
        dl = compute_deadlines(t0)
        ew = next(d for d in dl if d.name == "early_warning")
        expected = t0 + timedelta(hours=24)
        assert abs((ew.deadline_dt - expected).total_seconds()) < 5

    def test_notification_is_72h(self):
        t0 = self._detection(hours_ago=0)
        dl = compute_deadlines(t0)
        notif = next(d for d in dl if d.name == "incident_notification")
        expected = t0 + timedelta(hours=72)
        assert abs((notif.deadline_dt - expected).total_seconds()) < 5

    def test_final_report_is_30_days(self):
        t0 = self._detection(hours_ago=0)
        dl = compute_deadlines(t0)
        final = next(d for d in dl if d.name == "final_report")
        expected = t0 + timedelta(days=30)
        assert abs((final.deadline_dt - expected).total_seconds()) < 5

    def test_overdue_when_past_deadline(self):
        t0 = self._detection(hours_ago=25)  # détecté il y a 25h → early warning overdue
        dl = compute_deadlines(t0)
        ew = next(d for d in dl if d.name == "early_warning")
        assert ew.status == NotificationStatus.OVERDUE

    def test_pending_when_future_deadline(self):
        t0 = self._detection(hours_ago=1)
        dl = compute_deadlines(t0)
        ew = next(d for d in dl if d.name == "early_warning")
        assert ew.status == NotificationStatus.PENDING

    def test_completed_status(self):
        t0 = self._detection(hours_ago=25)
        completed_at = t0 + timedelta(hours=23)
        dl = compute_deadlines(t0, completed={"early_warning": completed_at})
        ew = next(d for d in dl if d.name == "early_warning")
        assert ew.status == NotificationStatus.COMPLETED

    def test_required_info_not_empty(self):
        dl = compute_deadlines(self._detection())
        for d in dl:
            assert len(d.required_info) > 0

    def test_to_dict_has_required_keys(self):
        dl = compute_deadlines(self._detection())
        d = dl[0].to_dict()
        for key in ("name", "article_ref", "deadline_iso", "status", "hours_remaining", "required_info"):
            assert key in d


# ── Maturité du processus ─────────────────────────────────────────────────────

class TestNotificationMaturity:
    def _all(self, level: int) -> dict:
        return {q.id: level for q in NOTIFICATION_QUESTIONS}

    def test_all_managed_gives_100(self):
        r = assess_notification_maturity(self._all(3))
        assert r.overall_score == 100.0

    def test_all_absent_gives_0(self):
        r = assess_notification_maturity(self._all(0))
        assert r.overall_score == 0.0

    def test_grade_a(self):
        assert assess_notification_maturity(self._all(3)).grade == "A"

    def test_grade_f(self):
        assert assess_notification_maturity(self._all(0)).grade == "F"

    def test_gaps_count(self):
        r = assess_notification_maturity(self._all(0))
        assert r.total_gaps == len(NOTIFICATION_QUESTIONS)
        assert r.critical_gaps == len(NOTIFICATION_QUESTIONS)

    def test_no_gaps_at_level_2(self):
        r = assess_notification_maturity(self._all(2))
        assert r.total_gaps == 0

    def test_invalid_maturity_raises(self):
        with pytest.raises(ValueError, match="Maturité invalide"):
            assess_notification_maturity({"N01": 4})

    def test_unknown_id_ignored(self):
        r = assess_notification_maturity({"N99": 2})
        assert r.overall_score == 0.0

    def test_to_dict_keys(self):
        r = assess_notification_maturity({"N01": 2, "N02": 1})
        d = r.to_dict()
        for key in ("overall_score", "grade", "total_gaps", "questions", "priority_actions"):
            assert key in d

    def test_priority_actions_sorted(self):
        r = assess_notification_maturity(self._all(0))
        d = r.to_dict()
        actions = d["priority_actions"]
        # CRITIQUE avant ÉLEVÉE
        priorities = [a["priority"] for a in actions]
        assert priorities == sorted(priorities, key=lambda p: 0 if p == "CRITIQUE" else 1)


# ── Schema des questions ──────────────────────────────────────────────────────

class TestQuestionsSchema:
    def test_returns_6_questions(self):
        schema = get_notification_questions_schema()
        assert len(schema) == 6

    def test_required_keys(self):
        for q in get_notification_questions_schema():
            assert "id" in q
            assert "question" in q
            assert "article_ref" in q

    def test_unique_ids(self):
        ids = [q["id"] for q in get_notification_questions_schema()]
        assert len(ids) == len(set(ids))
