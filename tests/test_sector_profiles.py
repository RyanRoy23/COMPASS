"""Tests des profils sectoriels NIS 2."""

import pytest
from nis2_analyzer.core.sector_profiles import (
    get_sector_profile, apply_sector_weights, get_sector_report,
    SECTOR_PROFILES, SectorProfile,
)
from nis2_analyzer.core.models import load_framework


KNOWN_SECTORS = ["sante", "finance", "energie", "transport", "numerique", "administration", "industrie", "autre"]


class TestSectorProfiles:
    def test_all_sectors_present(self):
        for sector in KNOWN_SECTORS:
            assert sector in SECTOR_PROFILES

    def test_get_sector_profile_returns_profile(self):
        profile = get_sector_profile("sante")
        assert isinstance(profile, SectorProfile)
        assert profile.sector_id == "sante"

    def test_get_sector_profile_fallback_autre(self):
        profile = get_sector_profile("unknown_sector_xyz")
        assert profile.sector_id == "autre"

    def test_all_profiles_have_required_fields(self):
        for sector_id, profile in SECTOR_PROFILES.items():
            assert profile.sector_id == sector_id
            assert profile.sector_label
            assert isinstance(profile.domain_weights, dict)
            assert isinstance(profile.priority_requirements, list)
            assert isinstance(profile.regulatory_context, str)
            assert isinstance(profile.key_threats, list)
            assert isinstance(profile.specific_controls, list)

    def test_domain_weights_reference_valid_ids(self):
        valid_domain_ids = {d.id for d in load_framework()}
        for sector_id, profile in SECTOR_PROFILES.items():
            for domain_id in profile.domain_weights:
                assert domain_id in valid_domain_ids, (
                    f"Secteur {sector_id} référence le domaine inconnu {domain_id}"
                )

    def test_priority_requirements_reference_valid_ids(self):
        valid_req_ids = {
            r.id for d in load_framework() for r in d.sub_requirements
        }
        for sector_id, profile in SECTOR_PROFILES.items():
            for req_id in profile.priority_requirements:
                assert req_id in valid_req_ids, (
                    f"Secteur {sector_id} référence l'exigence inconnue {req_id}"
                )

    def test_specific_controls_have_required_keys(self):
        for sector_id, profile in SECTOR_PROFILES.items():
            for ctrl in profile.specific_controls:
                assert "id" in ctrl, f"{sector_id} control missing 'id'"
                assert "title" in ctrl, f"{sector_id} control missing 'title'"
                assert "description" in ctrl
                assert "requirement_id" in ctrl
                assert "priority" in ctrl

    def test_sector_weights_are_positive(self):
        for sector_id, profile in SECTOR_PROFILES.items():
            for domain_id, weight in profile.domain_weights.items():
                assert weight > 0, f"{sector_id}/{domain_id} has non-positive weight {weight}"

    def test_sante_prioritizes_continuity(self):
        profile = get_sector_profile("sante")
        # NIS2-D03 (continuité) doit avoir le plus fort multiplicateur pour la santé
        d03_weight = profile.domain_weights.get("NIS2-D03", 1.0)
        assert d03_weight >= 1.8

    def test_finance_prioritizes_supply_chain(self):
        profile = get_sector_profile("finance")
        # DORA impose une surveillance forte des TPP (NIS2-D04)
        d04_weight = profile.domain_weights.get("NIS2-D04", 1.0)
        assert d04_weight >= 1.5

    def test_energie_prioritizes_continuity(self):
        profile = get_sector_profile("energie")
        d03_weight = profile.domain_weights.get("NIS2-D03", 1.0)
        assert d03_weight >= 1.5

    def test_autre_has_no_domain_weights(self):
        profile = get_sector_profile("autre")
        assert profile.domain_weights == {}

    def test_all_sectors_have_key_threats(self):
        for sector_id, profile in SECTOR_PROFILES.items():
            assert len(profile.key_threats) >= 2, f"{sector_id} has too few threats"

    def test_all_sectors_have_priority_requirements(self):
        for sector_id, profile in SECTOR_PROFILES.items():
            if sector_id != "autre":
                assert len(profile.priority_requirements) >= 3

    def test_regulatory_context_not_empty(self):
        for sector_id, profile in SECTOR_PROFILES.items():
            assert len(profile.regulatory_context) > 50, f"{sector_id} regulatory_context too short"


class TestApplySectorWeights:
    def test_weights_modified_for_sante(self):
        domains = load_framework()
        original_weights = {d.id: d.weight for d in domains}
        apply_sector_weights(domains, "sante")
        d03 = next(d for d in domains if d.id == "NIS2-D03")
        profile = get_sector_profile("sante")
        factor = profile.domain_weights.get("NIS2-D03", 1.0)
        assert d03.weight == round(original_weights["NIS2-D03"] * factor, 3)

    def test_weights_unchanged_for_autre(self):
        domains = load_framework()
        original_weights = {d.id: d.weight for d in domains}
        apply_sector_weights(domains, "autre")
        for d in domains:
            assert d.weight == original_weights[d.id]

    def test_all_weights_positive_after_apply(self):
        for sector_id in KNOWN_SECTORS:
            domains = load_framework()
            apply_sector_weights(domains, sector_id)
            for d in domains:
                assert d.weight > 0

    def test_unknown_sector_uses_standard_weights(self):
        domains = load_framework()
        original = {d.id: d.weight for d in domains}
        apply_sector_weights(domains, "sector_that_does_not_exist")
        for d in domains:
            assert d.weight == original[d.id]

    def test_returns_domains_list(self):
        domains = load_framework()
        result = apply_sector_weights(domains, "sante")
        assert result is domains  # modifie en place et retourne la liste


class TestGetSectorReport:
    def _fake_assessment(self, gap_ids: list[str]) -> dict:
        return {
            "gaps": [{"id": r} for r in gap_ids],
        }

    def test_returns_dict_with_required_keys(self):
        result = get_sector_report("sante", self._fake_assessment([]))
        assert "sector" in result
        assert "key_threats" in result
        assert "priority_requirements" in result
        assert "priority_gaps" in result
        assert "specific_controls" in result
        assert "sector_alert" in result

    def test_identifies_priority_gaps(self):
        profile = get_sector_profile("sante")
        gap_req = profile.priority_requirements[0]
        result = get_sector_report("sante", self._fake_assessment([gap_req]))
        assert gap_req in result["priority_gaps"]

    def test_no_priority_gaps_when_all_covered(self):
        result = get_sector_report("sante", self._fake_assessment([]))
        assert result["priority_gap_count"] == 0

    def test_sector_alert_positive_when_no_gaps(self):
        result = get_sector_report("finance", self._fake_assessment([]))
        assert "couvertes" in result["sector_alert"]

    def test_sector_alert_negative_when_gaps(self):
        profile = get_sector_profile("finance")
        gap_req = profile.priority_requirements[0]
        result = get_sector_report("finance", self._fake_assessment([gap_req]))
        assert "gap" in result["sector_alert"].lower()

    def test_fallback_for_unknown_sector(self):
        result = get_sector_report("xyz", self._fake_assessment([]))
        assert result["sector"]["id"] == "autre"

    def test_specific_controls_included(self):
        result = get_sector_report("sante", self._fake_assessment([]))
        assert isinstance(result["specific_controls"], list)
        assert len(result["specific_controls"]) > 0


class TestSectorProfilesAPI:
    def test_list_endpoint_returns_200(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.get("/api/sector-profiles")
        assert res.status_code == 200

    def test_list_endpoint_returns_all_sectors(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        data = client.get("/api/sector-profiles").json()
        ids = {s["id"] for s in data["sectors"]}
        for sector in KNOWN_SECTORS:
            assert sector in ids

    def test_assess_with_sector_returns_sector_report(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/assess", json={
            "org_name": "Hôpital Test",
            "responses": {"NIS2-D01-R01": 0, "NIS2-D03-R01": 0, "NIS2-D10-R01": 1},
            "sector": "sante",
        })
        assert res.status_code == 201
        data = res.json()
        assert "sector_report" in data
        assert data["sector_report"]["sector"]["id"] == "sante"

    def test_assess_sector_report_has_priority_gaps(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        # NIS2-D03-R01 est une priorité santé — avec maturity=0 c'est un gap
        res = client.post("/api/assess", json={
            "org_name": "Hôpital Test",
            "responses": {"NIS2-D03-R01": 0},
            "sector": "sante",
        })
        data = res.json()
        assert "NIS2-D03-R01" in data["sector_report"]["priority_gaps"]

    def test_assess_without_sector_uses_autre(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        res = client.post("/api/assess", json={
            "org_name": "Test",
            "responses": {"NIS2-D01-R01": 1},
        })
        assert res.status_code == 201
        data = res.json()
        assert data["sector_report"]["sector"]["id"] == "autre"

    def test_assess_finance_weights_higher_for_supply_chain(self):
        from fastapi.testclient import TestClient
        from nis2_analyzer.web.app import app
        client = TestClient(app)
        # Même gap NIS2-D04 (supply chain) avec secteur finance vs autre
        res_finance = client.post("/api/assess", json={
            "org_name": "Banque Test",
            "responses": {"NIS2-D04-R01": 0},
            "sector": "finance",
        })
        res_autre = client.post("/api/assess", json={
            "org_name": "Org Test",
            "responses": {"NIS2-D04-R01": 0},
            "sector": "autre",
        })
        # Le score finance doit être plus bas (la pondération D04 est plus haute = pénalité plus forte)
        score_finance = res_finance.json()["scores"]["overall_score"]
        score_autre = res_autre.json()["scores"]["overall_score"]
        assert score_finance <= score_autre
