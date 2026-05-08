"""
Tests unitaires pour nis2_analyzer.core.models

Couvre les comportements critiques du moteur de scoring :
- Calculs de maturité, score domaine, score global pondéré
- Détection des gaps et gaps critiques
- Attribution du grade A-F
- Chargement du référentiel JSON
"""

import pytest
import os
from nis2_analyzer.core.models import (
    MaturityLevel,
    EffortLevel,
    ComplianceGrade,
    Remediation,
    SubRequirement,
    Domain,
    AssessmentResult,
    load_framework,
)


# ═══════════════════════════════════════════════════════════════
# FIXTURES — Données réutilisables par plusieurs tests
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def sample_remediation():
    """Une remédiation type, réutilisable."""
    return Remediation(
        quick_win="Action rapide",
        full_implementation="Implémentation complète",
        effort=EffortLevel.MEDIUM,
    )


@pytest.fixture
def sample_sub_requirement(sample_remediation):
    """Une sous-exigence type, sans maturité initiale."""
    return SubRequirement(
        id="TEST-D01-R01",
        title="Test requirement",
        description="Description test",
        question="Question test ?",
        iso27001_refs=["A.5.1"],
        iso27001_controls=["Control test"],
        evidence_examples=["Evidence test"],
        remediation=sample_remediation,
    )


@pytest.fixture
def sample_domain_4_questions(sample_remediation):
    """Un domaine avec 4 questions, maturités variées (2, 2, 1, 2) → score attendu 58.3%."""
    reqs = []
    for i, mat_value in enumerate([2, 2, 1, 2]):
        req = SubRequirement(
            id=f"TEST-D01-R0{i+1}",
            title=f"Req {i+1}",
            description="Desc",
            question="Q ?",
            iso27001_refs=["A.5.1"],
            iso27001_controls=["C"],
            evidence_examples=["E"],
            remediation=sample_remediation,
        )
        req.maturity = MaturityLevel(mat_value)
        reqs.append(req)

    return Domain(
        id="TEST-D01",
        title="Test domain",
        article_ref="Art. 21(2)(a)",
        weight=1.5,
        description="Test domain description",
        sub_requirements=reqs,
    )


@pytest.fixture
def empty_domain():
    """Un domaine sans aucune question répondue."""
    return Domain(
        id="EMPTY-D01",
        title="Empty domain",
        article_ref="Art. 21(2)(a)",
        weight=1.0,
        description="No questions assessed",
        sub_requirements=[],
    )


# ═══════════════════════════════════════════════════════════════
# TESTS — MaturityLevel
# ═══════════════════════════════════════════════════════════════

class TestMaturityLevel:
    """Vérifie le comportement de l'enum MaturityLevel."""

    def test_score_pct_for_each_level(self):
        """Le score en pourcentage doit être linéaire : 0%, 33%, 67%, 100%."""
        assert MaturityLevel.NOT_IMPLEMENTED.score_pct == 0.0
        assert MaturityLevel.INITIAL.score_pct == pytest.approx(33.33, abs=0.1)
        assert MaturityLevel.DEFINED.score_pct == pytest.approx(66.67, abs=0.1)
        assert MaturityLevel.MANAGED.score_pct == 100.0

    def test_label_for_each_level(self):
        """Chaque niveau doit avoir un label en français."""
        assert MaturityLevel.NOT_IMPLEMENTED.label == "Non implémenté"
        assert MaturityLevel.INITIAL.label == "Initial / Partiel"
        assert MaturityLevel.DEFINED.label == "Défini / Implémenté"
        assert MaturityLevel.MANAGED.label == "Géré / Mesuré"

    def test_color_for_each_level(self):
        """Chaque niveau doit avoir une couleur hexadécimale."""
        for level in MaturityLevel:
            assert level.color.startswith("#")
            assert len(level.color) == 7


# ═══════════════════════════════════════════════════════════════
# TESTS — ComplianceGrade
# ═══════════════════════════════════════════════════════════════

class TestComplianceGrade:
    """Vérifie l'attribution du grade A-F selon le score."""

    def test_grade_A_for_high_score(self):
        """Score ≥ 85 doit donner A."""
        assert ComplianceGrade.from_score(85.0) == ComplianceGrade.A
        assert ComplianceGrade.from_score(95.0) == ComplianceGrade.A
        assert ComplianceGrade.from_score(100.0) == ComplianceGrade.A

    def test_grade_B_for_70_to_84(self):
        """Score entre 70 et 84.99 doit donner B."""
        assert ComplianceGrade.from_score(70.0) == ComplianceGrade.B
        assert ComplianceGrade.from_score(75.0) == ComplianceGrade.B
        assert ComplianceGrade.from_score(84.9) == ComplianceGrade.B

    def test_grade_C_for_50_to_69(self):
        """Score entre 50 et 69.99 doit donner C."""
        assert ComplianceGrade.from_score(50.0) == ComplianceGrade.C
        assert ComplianceGrade.from_score(60.0) == ComplianceGrade.C
        assert ComplianceGrade.from_score(69.9) == ComplianceGrade.C

    def test_grade_D_for_30_to_49(self):
        """Score entre 30 et 49.99 doit donner D."""
        assert ComplianceGrade.from_score(30.0) == ComplianceGrade.D
        assert ComplianceGrade.from_score(40.0) == ComplianceGrade.D
        assert ComplianceGrade.from_score(49.9) == ComplianceGrade.D

    def test_grade_F_for_low_score(self):
        """Score < 30 doit donner F."""
        assert ComplianceGrade.from_score(0.0) == ComplianceGrade.F
        assert ComplianceGrade.from_score(15.0) == ComplianceGrade.F
        assert ComplianceGrade.from_score(29.9) == ComplianceGrade.F


# ═══════════════════════════════════════════════════════════════
# TESTS — SubRequirement
# ═══════════════════════════════════════════════════════════════

class TestSubRequirement:
    """Vérifie la détection de gap et l'évaluation d'une sous-exigence."""

    def test_not_assessed_when_no_maturity(self, sample_sub_requirement):
        """Une question sans maturité n'est pas considérée comme évaluée."""
        assert sample_sub_requirement.is_assessed is False
        assert sample_sub_requirement.is_gap is False

    def test_gap_when_maturity_below_target(self, sample_sub_requirement):
        """Une question avec maturité 0 ou 1 est un gap."""
        sample_sub_requirement.maturity = MaturityLevel.NOT_IMPLEMENTED
        assert sample_sub_requirement.is_gap is True
        assert sample_sub_requirement.is_critical_gap is True

        sample_sub_requirement.maturity = MaturityLevel.INITIAL
        assert sample_sub_requirement.is_gap is True
        assert sample_sub_requirement.is_critical_gap is False

    def test_no_gap_when_maturity_at_or_above_target(self, sample_sub_requirement):
        """Une question avec maturité 2 ou 3 n'est pas un gap."""
        sample_sub_requirement.maturity = MaturityLevel.DEFINED
        assert sample_sub_requirement.is_gap is False

        sample_sub_requirement.maturity = MaturityLevel.MANAGED
        assert sample_sub_requirement.is_gap is False

    def test_critical_gap_only_at_level_zero(self, sample_sub_requirement):
        """Un gap critique est uniquement au niveau 0."""
        sample_sub_requirement.maturity = MaturityLevel.NOT_IMPLEMENTED
        assert sample_sub_requirement.is_critical_gap is True

        for level in [MaturityLevel.INITIAL, MaturityLevel.DEFINED, MaturityLevel.MANAGED]:
            sample_sub_requirement.maturity = level
            assert sample_sub_requirement.is_critical_gap is False


# ═══════════════════════════════════════════════════════════════
# TESTS — Domain
# ═══════════════════════════════════════════════════════════════

class TestDomain:
    """Vérifie le calcul du score d'un domaine et le comptage des gaps."""

    def test_score_with_4_questions(self, sample_domain_4_questions):
        """Score d'un domaine avec maturités 2,2,1,2 doit être 58.3%."""
        # (2+2+1+2)/3*100 / 4 questions = 7/12 * 100 = 58.33%
        assert sample_domain_4_questions.score == pytest.approx(58.33, abs=0.1)

    def test_score_zero_when_no_assessment(self, empty_domain):
        """Un domaine sans questions évaluées retourne 0.0, pas une exception."""
        assert empty_domain.score == 0.0

    def test_total_requirements_count(self, sample_domain_4_questions):
        """Le nombre total de sous-questions doit être correct."""
        assert sample_domain_4_questions.total_requirements == 4

    def test_gap_count(self, sample_domain_4_questions):
        """Compter les gaps : seule la question à maturité 1 est un gap."""
        # Maturités: 2,2,1,2 → 1 gap (la question à niveau 1)
        assert sample_domain_4_questions.gap_count == 1
        assert sample_domain_4_questions.critical_gap_count == 0

    def test_maturity_distribution(self, sample_domain_4_questions):
        """La distribution des maturités doit refléter les réponses."""
        dist = sample_domain_4_questions.maturity_distribution
        # Maturités 2,2,1,2 → {0:0, 1:1, 2:3, 3:0}
        assert dist == {0: 0, 1: 1, 2: 3, 3: 0}


# ═══════════════════════════════════════════════════════════════
# TESTS — AssessmentResult
# ═══════════════════════════════════════════════════════════════

class TestAssessmentResult:
    """Vérifie le score global pondéré et l'agrégation des résultats."""

    def test_overall_score_weighted_average(self, sample_domain_4_questions, sample_remediation):
        """Le score global doit être une moyenne pondérée par le poids des domaines."""
        # Domaine 1 : score 58.33%, poids 1.5
        # Domaine 2 : score 100%, poids 1.0 (toutes réponses au niveau 3)
        d2_reqs = []
        for i in range(2):
            req = SubRequirement(
                id=f"D02-R0{i+1}",
                title="X", description="X", question="X",
                iso27001_refs=[], iso27001_controls=[], evidence_examples=[],
                remediation=sample_remediation,
            )
            req.maturity = MaturityLevel.MANAGED
            d2_reqs.append(req)

        d2 = Domain(
            id="D02", title="D2", article_ref="Art. 21(2)(b)",
            weight=1.0, description="X", sub_requirements=d2_reqs,
        )

        result = AssessmentResult(domains=[sample_domain_4_questions, d2])

        # (58.33 * 1.5 + 100 * 1.0) / (1.5 + 1.0) = (87.5 + 100) / 2.5 = 75%
        assert result.overall_score == pytest.approx(75.0, abs=0.5)

    def test_overall_score_zero_when_empty(self):
        """Un résultat sans domaine retourne 0, pas une division par zéro."""
        result = AssessmentResult(domains=[])
        assert result.overall_score == 0.0

    def test_grade_from_overall_score(self, sample_domain_4_questions):
        """Le grade doit être calculé depuis le score global."""
        result = AssessmentResult(domains=[sample_domain_4_questions])
        # Score 58.33% → C (50-69 = C)
        assert result.grade == ComplianceGrade.C


# ═══════════════════════════════════════════════════════════════
# TESTS — load_framework (intégration avec le vrai JSON)
# ═══════════════════════════════════════════════════════════════

class TestLoadFramework:
    """Vérifie le chargement du référentiel NIS 2 réel."""

    def test_loads_ten_domains(self):
        """Le référentiel NIS 2 doit contenir exactement 10 domaines."""
        domains = load_framework()
        assert len(domains) == 10

    def test_total_requirements_after_mission_a(self):
        """Après la Mission A, le référentiel doit contenir 35 questions."""
        domains = load_framework()
        total = sum(len(d.sub_requirements) for d in domains)
        assert total == 35

# ═══════════════════════════════════════════════════════════════
# TESTS — DORA Mapping (mapping NIS 2 ↔ DORA)
# ═══════════════════════════════════════════════════════════════

class TestDORAMapping:
    """Vérifie le mapping entre les questions NIS 2 et les exigences DORA."""

    def test_dora_fields_loaded_from_json(self):
        """Les champs dora_refs et dora_pillar doivent être chargés depuis le JSON."""
        domains = load_framework()
        
        # NIS2-D01-R01 doit avoir un mapping DORA Art. 9
        for domain in domains:
            for req in domain.sub_requirements:
                if req.id == "NIS2-D01-R01":
                    assert "DORA Art. 9" in req.dora_refs
                    assert req.dora_pillar == "ICT Risk Management"
                    return
        
        pytest.fail("NIS2-D01-R01 introuvable dans le référentiel")

    def test_unmapped_questions_have_empty_dora_fields(self):
        """Les questions sans mapping DORA (ex: D05, D08) doivent avoir des champs vides."""
        domains = load_framework()
        
        for domain in domains:
            for req in domain.sub_requirements:
                if req.id == "NIS2-D05-R01":
                    # D05 n'est pas mappé DORA dans notre matrice
                    assert req.dora_refs == []
                    assert req.dora_pillar == ""
                    return
        
        pytest.fail("NIS2-D05-R01 introuvable dans le référentiel")

    def test_total_questions_with_dora_mapping(self):
        """16 questions doivent avoir un mapping DORA (selon la matrice validée)."""
        domains = load_framework()
        
        mapped_count = sum(
            1 for domain in domains 
            for req in domain.sub_requirements 
            if req.dora_pillar
        )
        
        assert mapped_count == 16, f"Attendu 16 questions mappées DORA, trouvé {mapped_count}"

    def test_dora_coverage_returns_all_pillars(self, sample_remediation):
        """La propriété dora_coverage doit retourner tous les piliers présents."""
        # Créer une assessment avec deux questions sur deux piliers différents
        req1 = SubRequirement(
            id="TEST-R01",
            title="Test 1", description="D", question="Q",
            iso27001_refs=[], iso27001_controls=[], evidence_examples=[],
            remediation=sample_remediation,
            dora_refs=["DORA Art. 5"],
            dora_pillar="ICT Risk Management",
        )
        req1.maturity = MaturityLevel.DEFINED  # Couvert
        
        req2 = SubRequirement(
            id="TEST-R02",
            title="Test 2", description="D", question="Q",
            iso27001_refs=[], iso27001_controls=[], evidence_examples=[],
            remediation=sample_remediation,
            dora_refs=["DORA Art. 17"],
            dora_pillar="ICT-Related Incident Management",
        )
        req2.maturity = MaturityLevel.NOT_IMPLEMENTED  # Pas couvert
        
        domain = Domain(
            id="TEST", title="Test", article_ref="X",
            weight=1.0, description="X",
            sub_requirements=[req1, req2],
        )
        
        result = AssessmentResult(domains=[domain])
        coverage = result.dora_coverage
        
        # Deux piliers doivent apparaître
        assert "ICT Risk Management" in coverage
        assert "ICT-Related Incident Management" in coverage
        
        # ICT Risk Management : 1/1 = 100%
        assert coverage["ICT Risk Management"]["coverage_pct"] == 100.0
        # Incident Management : 0/1 = 0%
        assert coverage["ICT-Related Incident Management"]["coverage_pct"] == 0.0

    def test_dora_coverage_global_with_real_data(self):
        """Avec le référentiel réel et les réponses du mode démo, vérifier la cohérence."""
        domains = load_framework()
        
        demo_answers = {
            "NIS2-D01-R01": 2, "NIS2-D01-R02": 2, "NIS2-D01-R03": 1, "NIS2-D01-R04": 2, "NIS2-D01-R05": 1,
            "NIS2-D02-R01": 2, "NIS2-D02-R02": 1, "NIS2-D02-R03": 0, "NIS2-D02-R04": 1,
            "NIS2-D03-R01": 1, "NIS2-D03-R02": 2, "NIS2-D03-R03": 0, "NIS2-D03-R04": 0,
            "NIS2-D04-R01": 0, "NIS2-D04-R02": 1, "NIS2-D04-R03": 0,
            "NIS2-D06-R01": 1,
        }
        
        for domain in domains:
            for req in domain.sub_requirements:
                if req.id in demo_answers:
                    req.maturity = MaturityLevel(demo_answers[req.id])
        
        result = AssessmentResult(domains=domains)
        coverage = result.dora_coverage
        
        # 4 piliers doivent être présents (Information Sharing n'est pas dans les questions)
        assert len(coverage) == 4
        
        # ICT Risk Management : 3 questions à niveau ≥ 2 sur 5 = 60%
        assert coverage["ICT Risk Management"]["coverage_pct"] == 60.0
        assert coverage["ICT Risk Management"]["covered_questions"] == 3
        assert coverage["ICT Risk Management"]["total_questions"] == 5