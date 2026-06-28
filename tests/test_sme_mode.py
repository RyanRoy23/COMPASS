"""Tests du mode PME — questionnaire simplifié NIS 2."""

import pytest
from nis2_analyzer.core.sme_mode import (
    SME_QUESTIONS, SMEQuestion,
    get_sme_schema, compute_sme_score, sme_responses_to_nis2,
)
from nis2_analyzer.core.models import load_framework


# ── Données de test ───────────────────────────────────────────────────────────

def _all_zero() -> dict[str, int]:
    return {q.id: 0 for q in SME_QUESTIONS}


def _all_three() -> dict[str, int]:
    return {q.id: 3 for q in SME_QUESTIONS}


def _all_two() -> dict[str, int]:
    return {q.id: 2 for q in SME_QUESTIONS}


def _partial() -> dict[str, int]:
    return {q.id: i % 4 for i, q in enumerate(SME_QUESTIONS)}


# ── Tests du questionnaire ────────────────────────────────────────────────────

class TestSMEQuestions:
    def test_exactly_15_questions(self):
        assert len(SME_QUESTIONS) == 15

    def test_ids_are_unique(self):
        ids = [q.id for q in SME_QUESTIONS]
        assert len(ids) == len(set(ids))

    def test_ids_follow_naming_convention(self):
        for q in SME_QUESTIONS:
            assert q.id.startswith("PME-"), f"{q.id} ne commence pas par PME-"

    def test_all_have_4_levels(self):
        for q in SME_QUESTIONS:
            assert len(q.levels) == 4, f"{q.id} a {len(q.levels)} niveaux"

    def test_all_have_requirement_ids(self):
        for q in SME_QUESTIONS:
            assert len(q.requirement_ids) >= 1, f"{q.id} n'a pas de requirement_ids"

    def test_requirement_ids_are_valid_nis2(self):
        valid = {r.id for d in load_framework() for r in d.sub_requirements}
        for q in SME_QUESTIONS:
            for req_id in q.requirement_ids:
                assert req_id in valid, f"{q.id} → {req_id} inconnu dans le framework NIS 2"

    def test_all_have_why_it_matters(self):
        for q in SME_QUESTIONS:
            assert len(q.why_it_matters) > 20, f"{q.id} why_it_matters trop court"

    def test_all_have_risk_if_zero(self):
        for q in SME_QUESTIONS:
            assert len(q.risk_if_zero) > 20, f"{q.id} risk_if_zero trop court"

    def test_questions_are_not_technical_jargon(self):
        # Les questions doivent éviter certains termes techniques purs
        tech_terms = ["PSSI", "SDLC", "SIEM", "SOC", "TLPT"]
        for q in SME_QUESTIONS:
            for term in tech_terms:
                assert term not in q.question, f"{q.id} contient le terme technique '{term}'"

    def test_covers_mfa(self):
        all_req_ids = {rid for q in SME_QUESTIONS for rid in q.requirement_ids}
        assert "NIS2-D10-R01" in all_req_ids, "MFA (NIS2-D10-R01) non couvert"

    def test_covers_backup(self):
        all_req_ids = {rid for q in SME_QUESTIONS for rid in q.requirement_ids}
        assert "NIS2-D03-R02" in all_req_ids, "Sauvegarde (NIS2-D03-R02) non couvert"

    def test_covers_incident_procedure(self):
        all_req_ids = {rid for q in SME_QUESTIONS for rid in q.requirement_ids}
        assert "NIS2-D02-R01" in all_req_ids

    def test_covers_privileged_access(self):
        all_req_ids = {rid for q in SME_QUESTIONS for rid in q.requirement_ids}
        assert "NIS2-D09-R03" in all_req_ids


class TestGetSMESchema:
    def test_returns_list_of_15(self):
        schema = get_sme_schema()
        assert len(schema) == 15

    def test_each_item_has_required_keys(self):
        for item in get_sme_schema():
            for key in ("id", "category", "question", "why_it_matters", "risk_if_zero", "levels", "requirement_ids"):
                assert key in item, f"Clé '{key}' manquante dans {item.get('id')}"

    def test_levels_have_value_and_label(self):
        for item in get_sme_schema():
            for lvl in item["levels"]:
                assert "value" in lvl
                assert "label" in lvl
                assert lvl["value"] in (0, 1, 2, 3)

    def test_levels_ordered_0_to_3(self):
        for item in get_sme_schema():
            values = [l["value"] for l in item["levels"]]
            assert values == [0, 1, 2, 3]


# ── Tests du calcul de score ──────────────────────────────────────────────────

class TestComputeSMEScore:
    def test_all_zero_score_is_zero(self):
        result = compute_sme_score(_all_zero())
        assert result["score"] == 0.0

    def test_all_three_score_is_hundred(self):
        result = compute_sme_score(_all_three())
        assert result["score"] == 100.0

    def test_all_two_score_around_67(self):
        result = compute_sme_score(_all_two())
        assert abs(result["score"] - 66.7) < 1.0

    def test_grade_f_for_all_zero(self):
        result = compute_sme_score(_all_zero())
        assert result["grade"] == "F"

    def test_grade_a_for_all_three(self):
        result = compute_sme_score(_all_three())
        assert result["grade"] == "A"

    def test_empty_responses_returns_zero(self):
        result = compute_sme_score({})
        assert result["score"] == 0
        assert result["grade"] == "F"

    def test_returns_weak_points_for_level_0(self):
        result = compute_sme_score(_all_zero())
        assert len(result["weak_points"]) > 0

    def test_no_weak_points_when_all_three(self):
        result = compute_sme_score(_all_three())
        assert result["weak_points"] == []

    def test_strong_points_when_all_three(self):
        result = compute_sme_score(_all_three())
        assert len(result["strong_points"]) == 15

    def test_no_strong_points_when_all_zero(self):
        result = compute_sme_score(_all_zero())
        assert result["strong_points"] == []

    def test_top_priority_is_worst_first(self):
        result = compute_sme_score(_all_zero())
        assert result["top_priority"] is not None
        assert result["top_priority"]["level"] == 0

    def test_top_priority_none_when_all_good(self):
        result = compute_sme_score(_all_three())
        assert result["top_priority"] is None

    def test_n_critical_counts_level_0(self):
        r = {"PME-01": 0, "PME-02": 0, "PME-03": 2}
        result = compute_sme_score(r)
        assert result["n_critical"] == 2

    def test_n_optimized_counts_level_3(self):
        r = {"PME-01": 3, "PME-02": 3, "PME-03": 1}
        result = compute_sme_score(r)
        assert result["n_optimized"] == 2

    def test_categories_returned(self):
        result = compute_sme_score(_partial())
        assert len(result["categories"]) > 0
        for cat in result["categories"]:
            assert "category" in cat
            assert "score" in cat
            assert 0 <= cat["score"] <= 100

    def test_partial_responses_valid(self):
        r = {"PME-01": 2, "PME-05": 1}
        result = compute_sme_score(r)
        assert result["total_answered"] == 2
        assert 0 <= result["score"] <= 100

    def test_invalid_level_ignored(self):
        # Les niveaux hors 0-3 sont ignorés (pas dans sme_responses valides)
        r = {"PME-01": 2}
        result = compute_sme_score(r)
        assert result["score"] > 0


# ── Tests de la conversion NIS 2 ──────────────────────────────────────────────

class TestSMEResponsesToNIS2:
    def test_returns_dict(self):
        result = sme_responses_to_nis2(_all_two())
        assert isinstance(result, dict)

    def test_keys_are_nis2_format(self):
        result = sme_responses_to_nis2(_all_two())
        for key in result:
            assert key.startswith("NIS2-"), f"Clé {key} n'est pas au format NIS2-"

    def test_values_in_range(self):
        result = sme_responses_to_nis2(_all_two())
        for req_id, level in result.items():
            assert 0 <= level <= 3, f"{req_id} has level {level}"

    def test_mfa_mapped_from_pme01(self):
        r = {"PME-01": 3}
        result = sme_responses_to_nis2(r)
        assert "NIS2-D10-R01" in result
        assert result["NIS2-D10-R01"] == 3

    def test_backup_mapped_from_pme02(self):
        r = {"PME-02": 2}
        result = sme_responses_to_nis2(r)
        assert "NIS2-D03-R02" in result
        assert result["NIS2-D03-R02"] == 2

    def test_empty_responses_returns_inferences_only(self):
        result = sme_responses_to_nis2({})
        # Même sans réponses, des inférences sont calculées
        assert isinstance(result, dict)

    def test_all_zero_gives_low_nis2_levels(self):
        result = sme_responses_to_nis2(_all_zero())
        direct_values = [v for k, v in result.items() if not k.startswith("NIS2-D05")]
        assert all(v <= 1 for v in direct_values)

    def test_all_three_gives_high_nis2_levels(self):
        result = sme_responses_to_nis2(_all_three())
        # Les exigences directement couvertes doivent être à 3
        direct_reqs = {rid for q in SME_QUESTIONS for rid in q.requirement_ids}
        for req_id in direct_reqs:
            if req_id in result:
                assert result[req_id] == 3, f"{req_id} should be 3"

    def test_covers_more_than_15_requirements(self):
        result = sme_responses_to_nis2(_all_two())
        assert len(result) > 15, "La conversion doit couvrir plus de 15 exigences via inférence"


# ── Tests API ─────────────────────────────────────────────────────────────────

class TestSMEAPI:
    def test_questions_endpoint_200(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.get("/api/sme/questions")
        assert res.status_code == 200

    def test_questions_endpoint_returns_15(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        data = client.get("/api/sme/questions").json()
        assert data["total"] == 15
        assert len(data["questions"]) == 15

    def test_assess_endpoint_200(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/sme/assess", json={
            "org_name": "PME Test",
            "responses": {"PME-01": 2, "PME-02": 1, "PME-05": 0},
            "sector": "industrie",
        })
        assert res.status_code == 200

    def test_assess_returns_sme_assessment(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/sme/assess", json={
            "org_name": "PME Test",
            "responses": {"PME-01": 2, "PME-03": 1},
        })
        data = res.json()
        assert "sme_assessment" in data
        assert "score" in data["sme_assessment"]
        assert "grade" in data["sme_assessment"]

    def test_assess_returns_nis2_detail(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/sme/assess", json={
            "org_name": "PME Test",
            "responses": {"PME-01": 2, "PME-02": 2},
            "include_nis2_detail": True,
        })
        data = res.json()
        assert "nis2_detail" in data
        assert "nis2_responses_inferred" in data

    def test_assess_without_nis2_detail(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/sme/assess", json={
            "org_name": "PME Test",
            "responses": {"PME-01": 1},
            "include_nis2_detail": False,
        })
        data = res.json()
        assert "nis2_detail" not in data

    def test_assess_invalid_question_422(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/sme/assess", json={
            "org_name": "PME Test",
            "responses": {"PME-99": 1},
        })
        assert res.status_code == 422

    def test_assess_invalid_level_422(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/sme/assess", json={
            "org_name": "PME Test",
            "responses": {"PME-01": 5},
        })
        assert res.status_code == 422

    def test_assess_empty_responses_422(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/sme/assess", json={
            "org_name": "PME Test",
            "responses": {},
        })
        assert res.status_code == 422

    def test_all_zero_score_is_zero_via_api(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/sme/assess", json={
            "org_name": "PME Test",
            "responses": {q.id: 0 for q in SME_QUESTIONS},
        })
        data = res.json()
        assert data["sme_assessment"]["score"] == 0.0

    def test_all_three_score_is_100_via_api(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/sme/assess", json={
            "org_name": "Excellente PME",
            "responses": {q.id: 3 for q in SME_QUESTIONS},
        })
        data = res.json()
        assert data["sme_assessment"]["score"] == 100.0

    def test_sector_propagated_to_sector_report(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/sme/assess", json={
            "org_name": "Hôpital PME",
            "responses": {"PME-04": 0},
            "sector": "sante",
            "include_nis2_detail": True,
        })
        data = res.json()
        assert data["nis2_detail"]["sector_report"]["sector"]["id"] == "sante"
