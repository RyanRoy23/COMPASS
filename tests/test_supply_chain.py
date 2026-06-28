"""Tests du module supply chain NIS 2 Art. 21(d)."""

import pytest
from nis2_analyzer.core.supply_chain import (
    assess_supplier,
    assess_supplier_portfolio,
    assess_supply_chain_maturity,
    get_supply_chain_questions_schema,
    SupplierProfile,
    SupplierCriticality,
    AccessLevel,
    DataSensitivity,
    SUPPLY_CHAIN_QUESTIONS,
)


def make_supplier(**kwargs) -> SupplierProfile:
    defaults = dict(
        name="TestSupplier",
        category="SaaS",
        access_level=AccessLevel.NONE,
        data_sensitivity=DataSensitivity.NONE,
        is_single_source=False,
        has_nis2_compliance=None,
        has_iso27001=None,
        has_soc2=None,
        pentest_recent=None,
        incident_history=False,
        contract_has_security_clauses=False,
        subcontracts_to_others=None,
        geographic_risk="eu",
        criticality_override=None,
    )
    defaults.update(kwargs)
    return SupplierProfile(**defaults)


# ── Classification fournisseur ────────────────────────────────────────────────

class TestSupplierClassification:
    def test_privileged_access_is_critical(self):
        r = assess_supplier(make_supplier(access_level=AccessLevel.PRIVILEGED))
        assert r.criticality == SupplierCriticality.CRITICAL

    def test_critical_data_is_critical(self):
        r = assess_supplier(make_supplier(data_sensitivity=DataSensitivity.CRITICAL))
        assert r.criticality == SupplierCriticality.CRITICAL

    def test_no_access_no_data_is_standard(self):
        r = assess_supplier(make_supplier())
        assert r.criticality == SupplierCriticality.STANDARD

    def test_operational_access_is_important(self):
        r = assess_supplier(make_supplier(access_level=AccessLevel.OPERATIONAL))
        assert r.criticality == SupplierCriticality.IMPORTANT

    def test_confidential_data_is_important(self):
        r = assess_supplier(make_supplier(data_sensitivity=DataSensitivity.CONFIDENTIAL))
        assert r.criticality == SupplierCriticality.IMPORTANT

    def test_override_forces_criticality(self):
        r = assess_supplier(make_supplier(
            access_level=AccessLevel.NONE,
            criticality_override=SupplierCriticality.CRITICAL,
        ))
        assert r.criticality == SupplierCriticality.CRITICAL

    def test_high_risk_geo_increases_score(self):
        r_eu = assess_supplier(make_supplier(geographic_risk="eu"))
        r_hr = assess_supplier(make_supplier(geographic_risk="high_risk"))
        assert r_hr.risk_score > r_eu.risk_score

    def test_incident_history_increases_score(self):
        r_no = assess_supplier(make_supplier(incident_history=False))
        r_yes = assess_supplier(make_supplier(incident_history=True))
        assert r_yes.risk_score > r_no.risk_score

    def test_single_source_increases_score(self):
        r_no = assess_supplier(make_supplier(is_single_source=False))
        r_yes = assess_supplier(make_supplier(is_single_source=True))
        assert r_yes.risk_score > r_no.risk_score


# ── Score de risque ───────────────────────────────────────────────────────────

class TestRiskScore:
    def test_score_in_range(self):
        r = assess_supplier(make_supplier(
            access_level=AccessLevel.PRIVILEGED,
            data_sensitivity=DataSensitivity.CRITICAL,
            is_single_source=True,
            incident_history=True,
            geographic_risk="high_risk",
        ))
        assert 0 <= r.risk_score <= 100

    def test_certifications_reduce_score(self):
        r_no_cert = assess_supplier(make_supplier(
            access_level=AccessLevel.OPERATIONAL,
            has_iso27001=False,
            has_soc2=False,
        ))
        r_certified = assess_supplier(make_supplier(
            access_level=AccessLevel.OPERATIONAL,
            has_iso27001=True,
            has_soc2=True,
            has_nis2_compliance=True,
            pentest_recent=True,
            contract_has_security_clauses=True,
        ))
        assert r_certified.risk_score < r_no_cert.risk_score

    def test_risk_factors_not_empty_for_risky_supplier(self):
        r = assess_supplier(make_supplier(
            access_level=AccessLevel.PRIVILEGED,
            incident_history=True,
        ))
        assert len(r.risk_factors) > 0

    def test_mitigating_factors_present_when_certified(self):
        r = assess_supplier(make_supplier(has_iso27001=True, has_soc2=True))
        assert len(r.mitigating_factors) > 0


# ── Clauses contractuelles ────────────────────────────────────────────────────

class TestContractClauses:
    def test_critical_has_more_clauses_than_standard(self):
        r_crit = assess_supplier(make_supplier(access_level=AccessLevel.PRIVILEGED))
        r_std  = assess_supplier(make_supplier())
        assert len(r_crit.required_contract_clauses) > len(r_std.required_contract_clauses)

    def test_all_tiers_have_notification_clause(self):
        for level in [AccessLevel.NONE, AccessLevel.OPERATIONAL, AccessLevel.PRIVILEGED]:
            r = assess_supplier(make_supplier(access_level=level))
            assert any("notification" in c.lower() for c in r.required_contract_clauses)

    def test_critical_requires_audit_clause(self):
        r = assess_supplier(make_supplier(access_level=AccessLevel.PRIVILEGED))
        assert any("audit" in c.lower() for c in r.required_contract_clauses)


# ── Actions prioritaires ──────────────────────────────────────────────────────

class TestActionItems:
    def test_no_clauses_generates_action(self):
        r = assess_supplier(make_supplier(
            access_level=AccessLevel.PRIVILEGED,
            contract_has_security_clauses=False,
        ))
        assert any("contrat" in a["action"].lower() for a in r.action_items)

    def test_single_source_generates_action(self):
        r = assess_supplier(make_supplier(is_single_source=True))
        assert any("alternatif" in a["action"].lower() or "sortie" in a["action"].lower() for a in r.action_items)

    def test_actions_sorted_by_priority(self):
        r = assess_supplier(make_supplier(
            access_level=AccessLevel.PRIVILEGED,
            is_single_source=True,
            contract_has_security_clauses=False,
            has_iso27001=False,
        ))
        order = {"CRITIQUE": 0, "ÉLEVÉE": 1, "MOYENNE": 2}
        priorities = [order.get(a["priority"], 3) for a in r.action_items]
        assert priorities == sorted(priorities)


# ── to_dict ───────────────────────────────────────────────────────────────────

class TestToDict:
    def test_required_keys(self):
        r = assess_supplier(make_supplier(access_level=AccessLevel.OPERATIONAL))
        d = r.to_dict()
        for key in ("name", "criticality", "criticality_label", "risk_score",
                    "risk_factors", "required_contract_clauses", "action_items"):
            assert key in d


# ── Portfolio ─────────────────────────────────────────────────────────────────

class TestPortfolio:
    def test_portfolio_aggregates_correctly(self):
        profiles = [
            make_supplier(name="SupA", access_level=AccessLevel.PRIVILEGED),
            make_supplier(name="SupB", access_level=AccessLevel.NONE),
            make_supplier(name="SupC", access_level=AccessLevel.OPERATIONAL),
        ]
        result = assess_supplier_portfolio(profiles)
        assert result["total_suppliers"] == 3
        assert result["critical_count"] >= 1
        assert "average_risk_score" in result
        assert len(result["suppliers"]) == 3

    def test_empty_portfolio(self):
        result = assess_supplier_portfolio([])
        assert result["total_suppliers"] == 0
        assert result["average_risk_score"] == 0.0


# ── Maturité gouvernance supply chain ────────────────────────────────────────

class TestSupplyChainMaturity:
    def _all(self, level: int) -> dict:
        return {q.id: level for q in SUPPLY_CHAIN_QUESTIONS}

    def test_all_managed_gives_100(self):
        r = assess_supply_chain_maturity(self._all(3))
        assert r.overall_score == 100.0

    def test_all_absent_gives_0(self):
        r = assess_supply_chain_maturity(self._all(0))
        assert r.overall_score == 0.0

    def test_grade_a(self):
        assert assess_supply_chain_maturity(self._all(3)).grade == "A"

    def test_grade_f(self):
        assert assess_supply_chain_maturity(self._all(0)).grade == "F"

    def test_gaps_at_level_0(self):
        r = assess_supply_chain_maturity(self._all(0))
        assert r.total_gaps == len(SUPPLY_CHAIN_QUESTIONS)
        assert r.critical_gaps == len(SUPPLY_CHAIN_QUESTIONS)

    def test_no_gaps_at_level_2(self):
        r = assess_supply_chain_maturity(self._all(2))
        assert r.total_gaps == 0

    def test_invalid_maturity_raises(self):
        with pytest.raises(ValueError, match="Maturité invalide"):
            assess_supply_chain_maturity({"SC01": 5})

    def test_to_dict_keys(self):
        r = assess_supply_chain_maturity({"SC01": 1, "SC03": 0})
        d = r.to_dict()
        for key in ("overall_score", "grade", "total_gaps", "questions", "priority_actions"):
            assert key in d

    def test_priority_actions_sorted(self):
        r = assess_supply_chain_maturity(self._all(0))
        actions = r.to_dict()["priority_actions"]
        order = {"CRITIQUE": 0, "ÉLEVÉE": 1}
        scores = [order.get(a["priority"], 2) for a in actions]
        assert scores == sorted(scores)


# ── Schema des questions ──────────────────────────────────────────────────────

class TestQuestionsSchema:
    def test_returns_7_questions(self):
        assert len(get_supply_chain_questions_schema()) == 7

    def test_required_keys(self):
        for q in get_supply_chain_questions_schema():
            assert "id" in q
            assert "question" in q
            assert "article_ref" in q

    def test_unique_ids(self):
        ids = [q["id"] for q in get_supply_chain_questions_schema()]
        assert len(ids) == len(set(ids))
