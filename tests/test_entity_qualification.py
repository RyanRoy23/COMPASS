"""Tests for entity_qualification module (NIS 2 Art. 3)."""

import pytest
from nis2_analyzer.core.entity_qualification import (
    qualify_entity,
    EntityProfile,
    EntityCategory,
    ALL_SECTORS,
    ANNEX_I_SECTORS,
    ANNEX_II_SECTORS,
)


def make_profile(**kwargs) -> EntityProfile:
    defaults = dict(
        sector="energie",
        employees=300,
        annual_revenue_eur=60_000_000,
        is_critical_infrastructure=False,
        provides_essential_digital_service=False,
        org_name="TestOrg",
    )
    defaults.update(kwargs)
    return EntityProfile(**defaults)


# ── Entité Essentielle ────────────────────────────────────────────────────────

class TestEssentialEntity:
    def test_large_annex_i_employees(self):
        result = qualify_entity(make_profile(sector="energie", employees=300, annual_revenue_eur=5_000_000))
        assert result.category == EntityCategory.ESSENTIAL

    def test_large_annex_i_revenue(self):
        result = qualify_entity(make_profile(sector="sante", employees=40, annual_revenue_eur=60_000_000))
        assert result.category == EntityCategory.ESSENTIAL

    def test_critical_infrastructure_flag_overrides_size(self):
        result = qualify_entity(make_profile(
            sector="energie", employees=10, annual_revenue_eur=1_000_000,
            is_critical_infrastructure=True,
        ))
        assert result.category == EntityCategory.ESSENTIAL

    def test_essential_digital_service_flag(self):
        result = qualify_entity(make_profile(
            sector="infrastructure_numerique", employees=30, annual_revenue_eur=5_000_000,
            provides_essential_digital_service=True,
        ))
        assert result.category == EntityCategory.ESSENTIAL

    def test_administration_always_essential(self):
        result = qualify_entity(make_profile(sector="administration", employees=10, annual_revenue_eur=0))
        assert result.category == EntityCategory.ESSENTIAL

    def test_espace_always_essential(self):
        result = qualify_entity(make_profile(sector="espace", employees=5, annual_revenue_eur=500_000))
        assert result.category == EntityCategory.ESSENTIAL

    def test_essential_has_obligations(self):
        result = qualify_entity(make_profile(sector="banque", employees=500, annual_revenue_eur=200_000_000))
        assert "10 000 000" in result.obligations["sanction_max_persons_morales"]
        assert result.obligations["audit_obligatoire"] is True
        assert result.obligations["notification_early_warning"] == "24 h après connaissance de l'incident"

    def test_reasons_not_empty(self):
        result = qualify_entity(make_profile(sector="energie", employees=300, annual_revenue_eur=60_000_000))
        assert len(result.reasons) > 0


# ── Entité Importante ─────────────────────────────────────────────────────────

class TestImportantEntity:
    def test_annex_i_small_org(self):
        result = qualify_entity(make_profile(sector="energie", employees=80, annual_revenue_eur=15_000_000))
        assert result.category == EntityCategory.IMPORTANT

    def test_annex_ii_any_size(self):
        result = qualify_entity(make_profile(sector="industrie", employees=600, annual_revenue_eur=300_000_000))
        assert result.category == EntityCategory.IMPORTANT

    def test_annex_ii_medium(self):
        result = qualify_entity(make_profile(sector="numerique", employees=80, annual_revenue_eur=20_000_000))
        assert result.category == EntityCategory.IMPORTANT

    def test_important_obligations(self):
        result = qualify_entity(make_profile(sector="industrie", employees=200, annual_revenue_eur=40_000_000))
        assert "7 000 000" in result.obligations["sanction_max_persons_morales"]
        assert result.obligations["audit_obligatoire"] is False
        assert result.obligations["notification_full_report"] == "72 h après connaissance de l'incident"

    def test_important_has_recommendations(self):
        result = qualify_entity(make_profile(sector="alimentation", employees=100, annual_revenue_eur=25_000_000))
        assert len(result.recommendations) > 0

    def test_annex_i_sme_has_caveat(self):
        result = qualify_entity(make_profile(sector="transport", employees=45, annual_revenue_eur=8_000_000))
        assert result.category == EntityCategory.IMPORTANT
        assert any("autorité nationale" in c for c in result.caveats)


# ── Hors champ ────────────────────────────────────────────────────────────────

class TestOutOfScope:
    def test_unknown_sector_small_org(self):
        result = qualify_entity(make_profile(sector="autre", employees=20, annual_revenue_eur=3_000_000))
        assert result.category == EntityCategory.OUT_OF_SCOPE

    def test_out_of_scope_has_caveats(self):
        result = qualify_entity(make_profile(sector="autre", employees=20, annual_revenue_eur=3_000_000))
        assert len(result.caveats) > 0

    def test_unknown_sector_with_critical_flag(self):
        # Inconnu mais flag critique → EE par exception
        result = qualify_entity(make_profile(
            sector="autre", employees=5, annual_revenue_eur=500_000,
            is_critical_infrastructure=True,
        ))
        assert result.category == EntityCategory.ESSENTIAL


# ── to_dict ──────────────────────────────────────────────────────────────────

class TestToDict:
    def test_keys_present(self):
        result = qualify_entity(make_profile(sector="sante", employees=400, annual_revenue_eur=100_000_000))
        d = result.to_dict()
        assert "category" in d
        assert "category_label" in d
        assert "category_color" in d
        assert "obligations" in d
        assert "sector_annex" in d
        assert d["sector_annex"] == "I"

    def test_annex_ii_in_dict(self):
        result = qualify_entity(make_profile(sector="gestion_dechets", employees=200, annual_revenue_eur=30_000_000))
        d = result.to_dict()
        assert d["sector_annex"] == "II"


# ── Taxonomie ─────────────────────────────────────────────────────────────────

class TestTaxonomy:
    def test_all_annex_i_sectors_in_all_sectors(self):
        for key in ANNEX_I_SECTORS:
            assert key in ALL_SECTORS

    def test_all_annex_ii_sectors_in_all_sectors(self):
        for key in ANNEX_II_SECTORS:
            assert key in ALL_SECTORS

    def test_no_overlap_between_annexes(self):
        overlap = set(ANNEX_I_SECTORS) & set(ANNEX_II_SECTORS)
        assert overlap == set()
