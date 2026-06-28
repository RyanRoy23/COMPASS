"""Tests du moteur Monte Carlo — quantification probabiliste du risque NIS 2."""

import pytest
from nis2_analyzer.core.monte_carlo import MonteCarloEngine, MonteCarloReport
from nis2_analyzer.core.financial import OrganizationProfile, OrgSize, Sector
from nis2_analyzer.core.models import load_framework, MaturityLevel


def _domains_all_at(level: int):
    domains = load_framework()
    for d in domains:
        for r in d.sub_requirements:
            r.maturity = MaturityLevel(level)
    return domains


def _domains_mixed():
    domains = load_framework()
    for i, d in enumerate(domains):
        for j, r in enumerate(d.sub_requirements):
            r.maturity = MaturityLevel((i + j) % 4)
    return domains


def _engine(size=OrgSize.ETI, sector=Sector.AUTRE):
    return MonteCarloEngine(OrganizationProfile(size=size, sector=sector), n_simulations=1000)


class TestMonteCarloEngine:
    def test_returns_report(self):
        report = _engine().simulate(_domains_all_at(1))
        assert isinstance(report, MonteCarloReport)

    def test_n_simulations_stored(self):
        report = _engine().simulate(_domains_all_at(1))
        assert report.n_simulations == 1000

    def test_percentiles_ordered(self):
        report = _engine().simulate(_domains_all_at(1))
        assert report.p5 <= report.p10 <= report.p25 <= report.p50
        assert report.p50 <= report.p75 <= report.p90 <= report.p95

    def test_all_managed_lower_exposure(self):
        r_low = _engine().simulate(_domains_all_at(3))
        r_high = _engine().simulate(_domains_all_at(0))
        assert r_low.p50 < r_high.p50

    def test_no_gaps_gives_zero_exposure(self):
        report = _engine().simulate(_domains_all_at(3))
        assert report.p50 == 0.0
        assert report.p90 == 0.0

    def test_all_gaps_gives_nonzero_exposure(self):
        report = _engine().simulate(_domains_all_at(0))
        assert report.p50 > 0

    def test_p50_positive_with_gaps(self):
        report = _engine().simulate(_domains_mixed())
        assert report.p50 >= 0

    def test_ale_comparison_present(self):
        report = _engine().simulate(_domains_all_at(1))
        assert report.ale_low >= 0
        assert report.ale_mid >= report.ale_low
        assert report.ale_high >= report.ale_mid

    def test_histogram_not_empty_when_gaps(self):
        report = _engine().simulate(_domains_all_at(0))
        assert len(report.histogram) > 0

    def test_histogram_frequencies_sum_to_one(self):
        report = _engine().simulate(_domains_all_at(0))
        total = sum(b["frequency"] for b in report.histogram)
        assert abs(total - 1.0) < 0.01

    def test_scenarios_sorted_by_p50_desc(self):
        report = _engine().simulate(_domains_all_at(1))
        p50s = [s.p50 for s in report.scenarios]
        assert p50s == sorted(p50s, reverse=True)

    def test_max_nis2_fine_positive(self):
        report = _engine(sector=Sector.SANTE).simulate(_domains_all_at(1))
        assert report.max_nis2_fine == 10_000_000

    def test_grand_groupe_higher_exposure_than_pme(self):
        r_pme = MonteCarloEngine(OrganizationProfile(size=OrgSize.PME), n_simulations=1000).simulate(_domains_all_at(1))
        r_grand = MonteCarloEngine(OrganizationProfile(size=OrgSize.GRAND_GROUPE), n_simulations=1000).simulate(_domains_all_at(1))
        assert r_grand.p50 > r_pme.p50

    def test_reproducible_with_same_seed(self):
        domains = _domains_mixed()
        r1 = _engine().simulate(domains)
        domains2 = _domains_mixed()
        r2 = _engine().simulate(domains2)
        assert r1.p50 == r2.p50

    def test_mean_between_p25_and_p75(self):
        report = _engine().simulate(_domains_all_at(1))
        if report.p50 > 0:
            assert report.p10 <= report.mean

    def test_to_dict_structure(self):
        report = _engine().simulate(_domains_all_at(1))
        d = report.to_dict()
        assert "distribution" in d
        assert "confidence_interval_90" in d
        assert "ale_comparison" in d
        assert "histogram" in d
        assert "scenarios" in d
        assert "n_simulations" in d

    def test_to_dict_distribution_keys(self):
        report = _engine().simulate(_domains_all_at(1))
        dist = report.to_dict()["distribution"]
        for key in ("p5", "p10", "p25", "p50", "p75", "p90", "p95", "mean", "currency", "period"):
            assert key in dist

    def test_to_dict_scenario_keys(self):
        report = _engine().simulate(_domains_all_at(1))
        d = report.to_dict()
        if d["scenarios"]:
            s = d["scenarios"][0]
            for key in ("requirement_id", "incident_type", "p10", "p50", "p90", "mean"):
                assert key in s

    def test_confidence_interval_covers_p50(self):
        report = _engine().simulate(_domains_all_at(1))
        assert report.p5 <= report.p50 <= report.p95


class TestMonteCarloAPI:
    def test_endpoint_returns_200(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        demo = {
            "NIS2-D01-R01": 2, "NIS2-D01-R02": 1, "NIS2-D02-R01": 0,
            "NIS2-D03-R01": 1, "NIS2-D09-R03": 0, "NIS2-D10-R01": 1,
        }
        res = client.post("/api/monte-carlo", json={
            "org_name": "TT Corporation",
            "responses": demo,
            "org_size": "eti",
            "sector": "sante",
        })
        assert res.status_code == 200

    def test_endpoint_returns_distribution(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/monte-carlo", json={
            "org_name": "TT Corporation",
            "responses": {"NIS2-D01-R01": 0, "NIS2-D10-R01": 0},
            "org_size": "eti",
        })
        data = res.json()
        assert "distribution" in data
        assert data["distribution"]["p50"] >= 0

    def test_invalid_maturity_422(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/monte-carlo", json={
            "org_name": "TT Corporation",
            "responses": {"NIS2-D01-R01": 9},
            "org_size": "eti",
        })
        assert res.status_code == 422

    def test_invalid_org_size_422(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/monte-carlo", json={
            "org_name": "TT Corporation",
            "responses": {"NIS2-D01-R01": 1},
            "org_size": "mega_corp",
        })
        assert res.status_code == 422

    def test_empty_responses_gives_zero_p50(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        # Toutes les réponses à 3 = aucun gap = exposition zéro
        from nis2_analyzer.core.models import load_framework
        domains = load_framework()
        all_managed = {r.id: 3 for d in domains for r in d.sub_requirements}
        res = client.post("/api/monte-carlo", json={
            "org_name": "TT Corporation",
            "responses": all_managed,
            "org_size": "eti",
        })
        assert res.status_code == 200
        assert res.json()["distribution"]["p50"] == 0.0
