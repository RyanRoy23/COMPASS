"""Tests de l'API FastAPI."""

import pytest
from fastapi.testclient import TestClient
from nis2_analyzer.web.app import app

client = TestClient(app)


class TestIndexPage:
    def test_returns_html(self):
        res = client.get("/")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]
        assert "COMPASS" in res.text

    def test_html_contains_form(self):
        res = client.get("/")
        assert "Évaluation" in res.text or "valuation" in res.text


class TestFrameworkEndpoint:
    def test_returns_200(self):
        assert client.get("/api/framework").status_code == 200

    def test_returns_10_domains(self):
        data = client.get("/api/framework").json()
        assert len(data["domains"]) == 10

    def test_returns_35_requirements(self):
        data = client.get("/api/framework").json()
        total = sum(len(d["requirements"]) for d in data["domains"])
        assert total == 35

    def test_domain_has_required_fields(self):
        data = client.get("/api/framework").json()
        domain = data["domains"][0]
        assert "id" in domain
        assert "title" in domain
        assert "weight" in domain
        assert "requirements" in domain

    def test_requirement_has_question(self):
        data = client.get("/api/framework").json()
        req = data["domains"][0]["requirements"][0]
        assert "question" in req
        assert len(req["question"]) > 0


class TestAssessEndpoint:
    _demo_responses = {
        "NIS2-D01-R01": 2, "NIS2-D01-R02": 2, "NIS2-D01-R03": 1,
        "NIS2-D01-R04": 2, "NIS2-D01-R05": 1, "NIS2-D02-R01": 2,
        "NIS2-D02-R02": 1, "NIS2-D02-R03": 0, "NIS2-D02-R04": 1,
        "NIS2-D03-R01": 1, "NIS2-D03-R02": 2, "NIS2-D03-R03": 0,
        "NIS2-D03-R04": 0, "NIS2-D04-R01": 0, "NIS2-D04-R02": 1,
        "NIS2-D04-R03": 0, "NIS2-D05-R01": 1, "NIS2-D05-R02": 2,
        "NIS2-D05-R03": 2, "NIS2-D06-R01": 1, "NIS2-D06-R02": 0,
        "NIS2-D07-R01": 2, "NIS2-D07-R02": 1, "NIS2-D07-R03": 2,
        "NIS2-D07-R04": 0, "NIS2-D07-R05": 1, "NIS2-D08-R01": 2,
        "NIS2-D08-R02": 2, "NIS2-D09-R01": 2, "NIS2-D09-R02": 2,
        "NIS2-D09-R03": 1, "NIS2-D09-R04": 1, "NIS2-D10-R01": 3,
        "NIS2-D10-R02": 2, "NIS2-D10-R03": 1,
    }

    def test_returns_201(self):
        res = client.post("/api/assess", json={
            "org_name": "TT Corporation",
            "responses": self._demo_responses,
        })
        assert res.status_code == 201

    def test_returns_score_and_grade(self):
        res = client.post("/api/assess", json={
            "org_name": "TT Corporation",
            "responses": self._demo_responses,
        })
        data = res.json()
        assert "scores" in data
        assert data["scores"]["overall_score"] > 0
        assert data["scores"]["grade"] in "ABCDEF"

    def test_returns_assessment_id(self):
        res = client.post("/api/assess", json={
            "org_name": "TT Corporation",
            "responses": self._demo_responses,
        })
        assert "assessment_id" in res.json()
        assert isinstance(res.json()["assessment_id"], int)

    def test_xss_in_org_name_is_escaped(self):
        res = client.post("/api/assess", json={
            "org_name": '<script>alert("xss")</script>',
            "responses": {"NIS2-D01-R01": 2},
        })
        assert res.status_code == 201
        data = res.json()
        org = data.get("metadata", {}).get("organization", "")
        assert "<script>" not in org

    def test_invalid_maturity_value_returns_422(self):
        res = client.post("/api/assess", json={
            "org_name": "TT Corporation",
            "responses": {"NIS2-D01-R01": 5},
        })
        assert res.status_code == 422

    def test_empty_responses_returns_422(self):
        res = client.post("/api/assess", json={
            "org_name": "TT Corporation",
            "responses": {},
        })
        assert res.status_code == 422

    def test_empty_org_name_returns_422(self):
        res = client.post("/api/assess", json={
            "org_name": "",
            "responses": {"NIS2-D01-R01": 2},
        })
        assert res.status_code == 422

    def test_unknown_requirement_ids_ignored(self):
        res = client.post("/api/assess", json={
            "org_name": "TT Corporation",
            "responses": {"NIS2-FAKE-R99": 2},
        })
        assert res.status_code == 422


class TestHistoryEndpoint:
    def test_returns_200(self):
        assert client.get("/api/history").status_code == 200

    def test_returns_assessments_list(self):
        data = client.get("/api/history").json()
        assert "assessments" in data
        assert isinstance(data["assessments"], list)

    def test_limit_param_validated(self):
        assert client.get("/api/history?limit=0").status_code == 422
        assert client.get("/api/history?limit=101").status_code == 422

    def test_unknown_assessment_returns_404(self):
        assert client.get("/api/history/999999").status_code == 404


class TestEvidencePackageEndpoint:
    def _payload(self, org="TestOrg"):
        responses = {f"NIS2-D0{d}-R0{r}": 2
                     for d in range(1, 10) for r in range(1, 4)
                     if f"NIS2-D0{d}-R0{r}" in [
                         "NIS2-D01-R01","NIS2-D01-R02","NIS2-D02-R01","NIS2-D02-R02",
                     ]}
        return {"org_name": org, "responses": {"NIS2-D01-R01": 2, "NIS2-D01-R02": 1}}

    def test_returns_zip(self):
        res = client.post("/api/evidence-package", json=self._payload())
        assert res.status_code == 200
        assert "zip" in res.headers["content-type"]

    def test_zip_is_valid(self):
        import io, zipfile
        res = client.post("/api/evidence-package", json=self._payload())
        zf = zipfile.ZipFile(io.BytesIO(res.content))
        assert "manifest.json" in zf.namelist()
        assert "assessment.json" in zf.namelist()

    def test_empty_responses_422(self):
        res = client.post("/api/evidence-package", json={"org_name": "Test", "responses": {}})
        assert res.status_code == 422

    def test_invalid_maturity_422(self):
        res = client.post("/api/evidence-package", json={"org_name": "Test", "responses": {"NIS2-D01-R01": 9}})
        assert res.status_code == 422


class TestGovernanceEndpoint:
    def test_questions_endpoint(self):
        res = client.get("/api/governance/questions")
        assert res.status_code == 200
        data = res.json()
        assert len(data["questions"]) == 8

    def test_full_governance_score(self):
        responses = {f"G0{i}" if i < 10 else f"G{i}": 3
                     for i in range(1, 9)}
        res = client.post("/api/governance", json={"responses": responses, "entity_category": "essentielle"})
        assert res.status_code == 200
        assert res.json()["grade"] == "A"

    def test_empty_responses_zero_score(self):
        res = client.post("/api/governance", json={"responses": {}})
        assert res.status_code == 200
        assert res.json()["overall_score"] == 0.0

    def test_invalid_maturity_422(self):
        res = client.post("/api/governance", json={"responses": {"G01": 5}})
        assert res.status_code == 422

    def test_invalid_category_422(self):
        res = client.post("/api/governance", json={"responses": {}, "entity_category": "inconnu"})
        assert res.status_code == 422

    def test_liability_risk_present(self):
        res = client.post("/api/governance", json={"responses": {"G01": 0, "G02": 0, "G05": 0}, "entity_category": "essentielle"})
        assert "liability_risk" in res.json()
        assert res.json()["liability_risk"] == "ÉLEVÉ"


class TestQualifyEndpoint:
    def _qualify(self, **kwargs):
        defaults = {"sector": "energie", "employees": 300, "annual_revenue_eur": 60_000_000, "org_name": "TestOrg"}
        defaults.update(kwargs)
        return client.post("/api/qualify", json=defaults)

    def test_essential_entity(self):
        res = self._qualify(sector="energie", employees=300, annual_revenue_eur=60_000_000)
        assert res.status_code == 200
        assert res.json()["category"] == "essentielle"

    def test_important_entity_annex_ii(self):
        res = self._qualify(sector="industrie", employees=200, annual_revenue_eur=40_000_000)
        assert res.status_code == 200
        assert res.json()["category"] == "importante"

    def test_out_of_scope(self):
        res = self._qualify(sector="autre", employees=20, annual_revenue_eur=1_000_000)
        assert res.status_code == 200
        assert res.json()["category"] == "hors_champ"

    def test_response_has_obligations(self):
        res = self._qualify(sector="sante", employees=500, annual_revenue_eur=100_000_000)
        data = res.json()
        assert "obligations" in data
        assert "sanction_max_persons_morales" in data["obligations"]

    def test_invalid_sector_returns_422(self):
        res = self._qualify(sector="secteur_inexistant")
        assert res.status_code == 422

    def test_xss_in_org_name(self):
        res = self._qualify(org_name="<script>alert(1)</script>")
        assert res.status_code == 200
        assert "<script>" not in res.json().get("category_label", "")

    def test_administration_always_essential(self):
        res = self._qualify(sector="administration", employees=5, annual_revenue_eur=0)
        assert res.json()["category"] == "essentielle"


class TestCompareEndpoint:
    def test_unknown_ids_return_404(self):
        assert client.get("/api/compare/999998/999999").status_code == 404
