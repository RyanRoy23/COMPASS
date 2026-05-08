"""
Tests unitaires pour nis2_analyzer.core.risk_engine

Couvre les comportements critiques du moteur financier :
- Multiplicateurs de maturité (FAIR-aligned)
- Plafonnement de probabilité à 95%
- Calcul ALE (Annualized Loss Expectancy)
- Cohérence des fourchettes basse/moyenne/haute
- Quick wins et ROI de remédiation
"""

import pytest
from nis2_analyzer.core.risk_engine import RiskEngine, RiskExposure, FinancialReport
from nis2_analyzer.core.financial import OrganizationProfile, OrgSize, Sector
from nis2_analyzer.core.models import (
    Domain, SubRequirement, Remediation,
    MaturityLevel, EffortLevel, load_framework,
)


# ═══════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def eti_profile():
    """Profil ETI standard pour tester les calculs."""
    return OrganizationProfile(
        name="TestCorp",
        size=OrgSize.ETI,
        sector=Sector.INDUSTRIE,
        annual_revenue=50_000_000,
    )


@pytest.fixture
def engine(eti_profile):
    """Engine prêt à analyser."""
    return RiskEngine(profile=eti_profile)


@pytest.fixture
def real_domains_with_demo_answers():
    """
    Charge le vrai référentiel et applique les réponses du mode démo.
    Permet de tester le comportement réel de l'engine sur des données 
    cohérentes avec ce que l'outil produit en mode --demo.
    """
    domains = load_framework()

    demo_answers = {
        "NIS2-D01-R01": 2, "NIS2-D01-R02": 2, "NIS2-D01-R03": 1, "NIS2-D01-R04": 2, "NIS2-D01-R05": 1,
        "NIS2-D02-R01": 2, "NIS2-D02-R02": 1, "NIS2-D02-R03": 0, "NIS2-D02-R04": 1,
        "NIS2-D03-R01": 1, "NIS2-D03-R02": 2, "NIS2-D03-R03": 0, "NIS2-D03-R04": 0,
        "NIS2-D04-R01": 0, "NIS2-D04-R02": 1, "NIS2-D04-R03": 0,
        "NIS2-D05-R01": 1, "NIS2-D05-R02": 2, "NIS2-D05-R03": 2,
        "NIS2-D06-R01": 1, "NIS2-D06-R02": 0,
        "NIS2-D07-R01": 2, "NIS2-D07-R02": 1, "NIS2-D07-R03": 2, "NIS2-D07-R04": 0, "NIS2-D07-R05": 1,
        "NIS2-D08-R01": 2, "NIS2-D08-R02": 2,
        "NIS2-D09-R01": 2, "NIS2-D09-R02": 2, "NIS2-D09-R03": 1, "NIS2-D09-R04": 1,
        "NIS2-D10-R01": 3, "NIS2-D10-R02": 2, "NIS2-D10-R03": 1,
    }

    for domain in domains:
        for req in domain.sub_requirements:
            if req.id in demo_answers:
                req.maturity = MaturityLevel(demo_answers[req.id])

    return domains


# ═══════════════════════════════════════════════════════════════
# TESTS — Multiplicateurs de maturité (cœur méthodologique)
# ═══════════════════════════════════════════════════════════════

class TestMaturityMultipliers:
    """
    Vérifie que les multiplicateurs de maturité sont correctement appliqués.
    
    C'est la défense méthodologique de l'outil : sans ces multiplicateurs,
    la quantification serait identique pour tous les niveaux de maturité,
    ce qui n'aurait aucun sens.
    """

    def test_level_zero_increases_probability(self, engine):
        """Maturité 0 (non implémenté) doit donner probabilité × 1.5."""
        # Probabilité de base 20% × 1.5 = 30%
        assert engine._adjust_probability(0.20, 0) == pytest.approx(0.30, abs=0.001)

    def test_level_one_keeps_base_probability(self, engine):
        """Maturité 1 (partiel) doit donner probabilité × 1.0 = identique."""
        assert engine._adjust_probability(0.20, 1) == pytest.approx(0.20, abs=0.001)

    def test_level_two_reduces_probability_strongly(self, engine):
        """Maturité 2 (implémenté) doit réduire fortement (× 0.3)."""
        # 20% × 0.3 = 6%
        assert engine._adjust_probability(0.20, 2) == pytest.approx(0.06, abs=0.001)

    def test_level_three_minimizes_probability(self, engine):
        """Maturité 3 (géré/mesuré) doit réduire au minimum (× 0.1)."""
        # 20% × 0.1 = 2%
        assert engine._adjust_probability(0.20, 3) == pytest.approx(0.02, abs=0.001)

    def test_unknown_level_uses_base_probability(self, engine):
        """Niveau inconnu (ex: 99) doit utiliser le multiplicateur 1.0."""
        assert engine._adjust_probability(0.20, 99) == pytest.approx(0.20, abs=0.001)


# ═══════════════════════════════════════════════════════════════
# TESTS — Plafonnement à 95%
# ═══════════════════════════════════════════════════════════════

class TestProbabilityCapping:
    """
    Le plafonnement à 95% évite des probabilités absurdes (>100%) 
    quand la probabilité de base est élevée et la maturité à 0.
    """

    def test_high_base_probability_capped_at_95(self, engine):
        """80% × 1.5 = 120% mais doit être plafonné à 95%."""
        result = engine._adjust_probability(0.80, 0)
        assert result == pytest.approx(0.95, abs=0.001)

    def test_low_probability_not_capped(self, engine):
        """30% × 1.5 = 45% ne doit pas être plafonné."""
        result = engine._adjust_probability(0.30, 0)
        assert result == pytest.approx(0.45, abs=0.001)
        assert result < 0.95


# ═══════════════════════════════════════════════════════════════
# TESTS — Cohérence des fourchettes basse/moyenne/haute
# ═══════════════════════════════════════════════════════════════

class TestExposureRangeCoherence:
    """
    Invariant fondamental : exposition_low ≤ exposition_mid ≤ exposition_high.
    Ce test garantit que toutes les expositions calculées respectent l'ordre.
    Si cet invariant casse, le rapport devient incohérent.
    """

    def test_all_exposures_respect_order(self, engine, real_domains_with_demo_answers):
        """Pour chaque exposition, low ≤ mid ≤ high doit toujours être vrai."""
        report = engine.analyze(real_domains_with_demo_answers)

        for exposure in report.exposures:
            assert exposure.exposure_low <= exposure.exposure_mid, (
                f"Incohérence sur {exposure.requirement_id}: "
                f"low={exposure.exposure_low} > mid={exposure.exposure_mid}"
            )
            assert exposure.exposure_mid <= exposure.exposure_high, (
                f"Incohérence sur {exposure.requirement_id}: "
                f"mid={exposure.exposure_mid} > high={exposure.exposure_high}"
            )

    def test_total_exposure_respects_order(self, engine, real_domains_with_demo_answers):
        """Le total cumulé doit aussi respecter l'ordre."""
        report = engine.analyze(real_domains_with_demo_answers)
        assert report.total_exposure_low <= report.total_exposure_mid
        assert report.total_exposure_mid <= report.total_exposure_high


# ═══════════════════════════════════════════════════════════════
# TESTS — Logique d'analyse (gaps uniquement)
# ═══════════════════════════════════════════════════════════════

class TestAnalyzeLogic:
    """
    Vérifie que analyze() ne calcule des expositions QUE pour les gaps,
    pas pour les questions correctement implémentées.
    """

    def test_no_exposure_for_compliant_questions(self, engine, real_domains_with_demo_answers):
        """
        Une question à maturité 2 ou 3 ne doit PAS apparaître dans les expositions.
        Ex: NIS2-D10-R01 (MFA) est à niveau 3 dans le mode démo → aucune exposition.
        """
        report = engine.analyze(real_domains_with_demo_answers)

        compliant_ids = ["NIS2-D10-R01", "NIS2-D08-R01", "NIS2-D08-R02"]
        for compliant_id in compliant_ids:
            exposures_for_id = [e for e in report.exposures if e.requirement_id == compliant_id]
            assert len(exposures_for_id) == 0, (
                f"{compliant_id} est à maturité ≥ 2, ne devrait pas avoir d'exposition"
            )

    def test_top_risks_are_sorted_descending(self, engine, real_domains_with_demo_answers):
        """Les top 5 risques doivent être triés du plus grave au moins grave."""
        report = engine.analyze(real_domains_with_demo_answers)

        for i in range(len(report.top_risks) - 1):
            assert report.top_risks[i].exposure_mid >= report.top_risks[i + 1].exposure_mid, (
                "Les top_risks doivent être triés par exposure_mid décroissante"
            )

    def test_top_risks_max_5_items(self, engine, real_domains_with_demo_answers):
        """Le top doit contenir au maximum 5 risques."""
        report = engine.analyze(real_domains_with_demo_answers)
        assert len(report.top_risks) <= 5


# ═══════════════════════════════════════════════════════════════
# TESTS — Calcul ALE (Annualized Loss Expectancy)
# ═══════════════════════════════════════════════════════════════

class TestALECalculation:
    """
    Vérifie que la formule ALE = Probabilité × Impact est correctement appliquée
    sur les expositions générées.
    """

    def test_exposure_equals_probability_times_impact(self, engine, real_domains_with_demo_answers):
        """exposure_mid doit être égal à probability × impact_mid (à l'arrondi près)."""
        report = engine.analyze(real_domains_with_demo_answers)

        for exposure in report.exposures:
            expected_mid = exposure.probability * exposure.impact_mid
            # On tolère 1 EUR d'écart à cause des arrondis
            assert abs(exposure.exposure_mid - expected_mid) <= 1, (
                f"ALE incorrect pour {exposure.requirement_id}: "
                f"prob={exposure.probability} × impact={exposure.impact_mid} "
                f"≠ exposure_mid={exposure.exposure_mid}"
            )


# ═══════════════════════════════════════════════════════════════
# TESTS — Quick wins
# ═══════════════════════════════════════════════════════════════

class TestQuickWins:
    """
    Les quick wins (effort LOW) sont la valeur la plus actionnable du rapport.
    On vérifie qu'ils sont bien identifiés et chiffrés.
    """

    def test_quick_wins_value_is_positive_when_gaps_exist(self, engine, real_domains_with_demo_answers):
        """Avec les réponses démo, on a des gaps à effort LOW → quick wins > 0."""
        report = engine.analyze(real_domains_with_demo_answers)
        # Le mode démo contient des gaps avec effort "low" (ex: D02-R03, D02-R04)
        assert report.quick_wins_value > 0

    def test_quick_wins_value_below_total_mid_exposure(self, engine, real_domains_with_demo_answers):
        """Les quick wins ne peuvent pas dépasser l'exposition totale moyenne."""
        report = engine.analyze(real_domains_with_demo_answers)
        assert report.quick_wins_value <= report.total_exposure_mid


# ═══════════════════════════════════════════════════════════════
# TESTS — Cas limites
# ═══════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Cas limites pour s'assurer que l'engine ne casse pas."""

    def test_analyze_with_no_gaps(self, engine):
        """Si tous les domaines sont à maturité 3, aucune exposition."""
        domains = load_framework()
        for domain in domains:
            for req in domain.sub_requirements:
                req.maturity = MaturityLevel.MANAGED  # Tous à niveau 3

        report = engine.analyze(domains)
        assert len(report.exposures) == 0
        assert report.total_exposure_mid == 0
        assert report.quick_wins_value == 0

    def test_analyze_with_empty_domains(self, engine):
        """Aucun domaine fourni → rapport vide mais valide, pas d'exception."""
        report = engine.analyze([])
        assert report.total_exposure_low == 0
        assert report.total_exposure_mid == 0
        assert report.total_exposure_high == 0
        assert len(report.exposures) == 0

    def test_default_engine_uses_default_profile(self):
        """RiskEngine() sans profil utilise un profil par défaut, pas une exception."""
        engine = RiskEngine()
        assert engine.profile is not None
        assert engine.profile.size is not None