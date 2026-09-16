"""
COMPASS — Résilience ReCyF (OS13, OS14, OS15)

Évalue en profondeur les trois objectifs ReCyF du pilier Résilience, que ni
le bridge CloudSec ni aucun autre module ne peuvent prouver techniquement :
ce sont des capacités organisationnelles (un plan existe-t-il ? a-t-il été
testé ?), pas des paramètres de configuration qu'une API peut vérifier.

Sur le même principe que governance.py (Art. 20) ou supply_chain.py
(Art. 21(d)) : ce module transforme une réponse déclarative isolée en
questionnaire structuré, avec preuves attendues et remédiation par item.
Ça ne devient pas une "preuve technique" — ça reste déclaratif par nature —
mais ça cesse d'être une case cochée sans contexte.

  OS13 — Continuité et reprise d'activité      : RES01-RES03
  OS14 — Réaction aux crises d'origine cyber    : RES04-RES06
  OS15 — Exercices, tests et entrainements      : RES07-RES08

Le résultat par objectif (maturité la plus basse parmi ses questions —
principe de prudence, comme le bridge CloudSec) peut ensuite pré-remplir
les questions RECYF-OS13/14/15 du formulaire ReCyF.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Niveaux de maturité ──────────────────────────────────────────────────────

class ResilienceMaturity(Enum):
    ABSENT  = 0   # Inexistant ou non formalisé
    INITIAL = 1   # Informel, ad hoc, jamais testé
    DEFINED = 2   # Formalisé, documenté
    MANAGED = 3   # Formalisé ET testé/exercé régulièrement

    @property
    def label(self) -> str:
        return {0: "Absent", 1: "Informel", 2: "Formalisé", 3: "Testé régulièrement"}[self.value]

    @property
    def score_pct(self) -> float:
        return self.value / 3 * 100


# ── Questions ─────────────────────────────────────────────────────────────────

@dataclass
class ResilienceQuestion:
    id: str
    recyf_objective: str  # "RECYF-OS13" | "RECYF-OS14" | "RECYF-OS15"
    pillar: str           # regroupement lisible : Continuité / Gestion de crise / Exercices
    title: str
    question: str
    evidence_examples: list[str]
    remediation_absent: str
    remediation_managed: str
    weight: float = 1.0
    maturity: Optional[ResilienceMaturity] = None

    @property
    def is_gap(self) -> bool:
        return self.maturity is not None and self.maturity.value < 2

    @property
    def is_critical_gap(self) -> bool:
        return self.maturity is not None and self.maturity.value == 0


RESILIENCE_QUESTIONS: list[ResilienceQuestion] = [
    ResilienceQuestion(
        id="RES01",
        recyf_objective="RECYF-OS13",
        pillar="Continuité",
        title="Plan de continuité et de reprise d'activité formalisé",
        question="Disposez-vous d'un plan de continuité (PCA) et de reprise d'activité (PRA) "
                 "formalisé pour vos systèmes critiques ?",
        weight=1.3,
        evidence_examples=["PCA/PRA documenté et daté", "Liste des systèmes critiques couverts"],
        remediation_absent="Identifier les 3 à 5 systèmes les plus critiques et documenter un "
                            "plan de reprise minimal pour chacun.",
        remediation_managed="Réviser le PCA/PRA à chaque évolution significative du SI, pas "
                             "seulement annuellement.",
    ),
    ResilienceQuestion(
        id="RES02",
        recyf_objective="RECYF-OS13",
        pillar="Continuité",
        title="Objectifs de reprise définis (RTO/RPO)",
        question="Des objectifs de temps de reprise (RTO) et de perte de données maximale (RPO) "
                 "sont-ils définis pour chaque système critique ?",
        weight=1.0,
        evidence_examples=["Tableau RTO/RPO par système", "Validation métier des objectifs"],
        remediation_absent="Fixer un RTO/RPO, même approximatif, pour chaque système identifié "
                            "comme critique dans le PCA.",
        remediation_managed="Valider les RTO/RPO avec les métiers et les confronter aux capacités "
                             "réelles mesurées lors des tests de restauration.",
    ),
    ResilienceQuestion(
        id="RES03",
        recyf_objective="RECYF-OS13",
        pillar="Continuité",
        title="Sauvegardes testées par restauration réelle",
        question="Vos sauvegardes sont-elles testées par une restauration réelle au moins une "
                 "fois par an ?",
        weight=1.2,
        evidence_examples=["Rapport de test de restauration daté", "Durée de restauration mesurée"],
        remediation_absent="Planifier un test de restauration sur un système non critique dans "
                            "les 3 mois.",
        remediation_managed="Automatiser des tests de restauration réguliers et suivre la durée "
                             "réelle par rapport au RTO cible.",
    ),
    ResilienceQuestion(
        id="RES04",
        recyf_objective="RECYF-OS14",
        pillar="Gestion de crise",
        title="Cellule de gestion de crise cyber identifiée",
        question="Une cellule de gestion de crise cyber existe-t-elle, avec des rôles et "
                 "responsabilités définis avant tout incident ?",
        weight=1.3,
        evidence_examples=["Organigramme de crise", "Fiches de rôle par membre de la cellule"],
        remediation_absent="Identifier les membres et rôles d'une cellule de crise minimale "
                            "(direction, DSI/RSSI, communication, juridique).",
        remediation_managed="Former chaque membre à son rôle et désigner des suppléants en cas "
                             "d'indisponibilité.",
    ),
    ResilienceQuestion(
        id="RES05",
        recyf_objective="RECYF-OS14",
        pillar="Gestion de crise",
        title="Procédures de crise accessibles hors SI",
        question="Les procédures de gestion de crise sont-elles documentées et accessibles même "
                 "si le système d'information est indisponible ?",
        weight=1.0,
        evidence_examples=["Copie papier ou hors-ligne des procédures", "Kit de crise physique"],
        remediation_absent="Imprimer ou stocker hors ligne (clé USB, cloud tiers) les procédures "
                            "et coordonnées essentielles.",
        remediation_managed="Tester l'accès aux procédures hors ligne lors de chaque exercice de "
                             "crise.",
    ),
    ResilienceQuestion(
        id="RES06",
        recyf_objective="RECYF-OS14",
        pillar="Gestion de crise",
        title="Contacts d'urgence à jour",
        question="Disposez-vous d'une liste à jour des contacts d'urgence (ANSSI/CSIRT, assureur "
                 "cyber, prestataires clés) mobilisable en cas de crise ?",
        weight=1.0,
        evidence_examples=["Annuaire de crise daté", "Coordonnées CSIRT régional / ANSSI"],
        remediation_absent="Constituer une liste de contacts d'urgence : CSIRT, assureur, "
                            "prestataires d'infogérance, forensics.",
        remediation_managed="Revoir la liste à chaque changement de prestataire et la valider "
                             "annuellement.",
    ),
    ResilienceQuestion(
        id="RES07",
        recyf_objective="RECYF-OS15",
        pillar="Exercices",
        title="Exercice de crise réalisé (12 derniers mois)",
        question="Un exercice de simulation de crise cyber (table-top ou grandeur nature) a-t-il "
                 "été réalisé au cours des 12 derniers mois ?",
        weight=1.2,
        evidence_examples=["Compte-rendu d'exercice daté", "Liste des enseignements tirés"],
        remediation_absent="Organiser un exercice table-top d'une demi-journée sur un scénario "
                            "de ransomware.",
        remediation_managed="Varier les scénarios d'un exercice à l'autre et suivre la mise en "
                             "œuvre effective des enseignements tirés.",
    ),
    ResilienceQuestion(
        id="RES08",
        recyf_objective="RECYF-OS15",
        pillar="Exercices",
        title="Test de restauration documenté (12 derniers mois)",
        question="Un test de restauration de sauvegarde a-t-il été réalisé et documenté au cours "
                 "des 12 derniers mois ?",
        weight=1.0,
        evidence_examples=["Rapport de test", "Écart entre durée mesurée et RTO cible"],
        remediation_absent="Planifier un test de restauration et en documenter le résultat, même "
                            "sommairement.",
        remediation_managed="Intégrer le test de restauration au calendrier récurrent de "
                             "maintenance, pas comme un événement exceptionnel.",
    ),
]


# ── Résultat ──────────────────────────────────────────────────────────────────

@dataclass
class ResilienceResult:
    questions: list[ResilienceQuestion]

    @property
    def overall_score(self) -> float:
        assessed = [q for q in self.questions if q.maturity is not None]
        if not assessed:
            return 0.0
        total_weight = sum(q.weight for q in assessed)
        weighted_sum = sum(q.maturity.score_pct * q.weight for q in assessed)
        return round(weighted_sum / total_weight, 1)

    @property
    def grade(self) -> str:
        s = self.overall_score
        if s >= 85: return "A"
        if s >= 70: return "B"
        if s >= 50: return "C"
        if s >= 30: return "D"
        return "F"

    @property
    def total_gaps(self) -> int:
        return sum(1 for q in self.questions if q.is_gap)

    @property
    def critical_gaps(self) -> int:
        return sum(1 for q in self.questions if q.is_critical_gap)

    @property
    def maturity_by_objective(self) -> dict[str, Optional[int]]:
        """
        Maturité par objectif ReCyF (OS13/14/15) : le niveau le plus bas parmi
        les questions répondues de cet objectif — même principe de prudence
        que le bridge CloudSec ("le maillon faible détermine le niveau").
        Vaut None si aucune question de l'objectif n'a été répondue.
        """
        result: dict[str, Optional[int]] = {}
        for objective in ("RECYF-OS13", "RECYF-OS14", "RECYF-OS15"):
            levels = [
                q.maturity.value for q in self.questions
                if q.recyf_objective == objective and q.maturity is not None
            ]
            result[objective] = min(levels) if levels else None
        return result

    def to_dict(self) -> dict:
        return {
            "overall_score": self.overall_score,
            "grade": self.grade,
            "total_gaps": self.total_gaps,
            "critical_gaps": self.critical_gaps,
            "maturity_by_objective": self.maturity_by_objective,
            "questions": [
                {
                    "id": q.id,
                    "recyf_objective": q.recyf_objective,
                    "pillar": q.pillar,
                    "title": q.title,
                    "maturity": q.maturity.value if q.maturity is not None else None,
                    "maturity_label": q.maturity.label if q.maturity is not None else None,
                    "is_gap": q.is_gap,
                    "is_critical_gap": q.is_critical_gap,
                    "remediation": (
                        q.remediation_absent if q.is_gap else q.remediation_managed
                    ) if q.maturity is not None else None,
                    "evidence_examples": q.evidence_examples,
                }
                for q in self.questions
            ],
        }


# ── Moteur d'évaluation ──────────────────────────────────────────────────────

def assess_resilience(responses: dict[str, int]) -> ResilienceResult:
    """
    Évalue la résilience à partir d'un dict {question_id: maturity (0-3)}.

    Args:
        responses: {"RES01": 2, "RES04": 1, ...}

    Returns:
        ResilienceResult avec score, grade, gaps et maturité par objectif ReCyF.
    """
    import copy
    questions = copy.deepcopy(RESILIENCE_QUESTIONS)

    for q in questions:
        if q.id in responses:
            value = responses[q.id]
            if value not in (0, 1, 2, 3):
                raise ValueError(f"Maturité invalide pour {q.id} : {value}. Valeurs acceptées : 0-3.")
            q.maturity = ResilienceMaturity(value)

    return ResilienceResult(questions=questions)


def get_questions_schema() -> list[dict]:
    """Retourne la liste des questions pour l'UI."""
    return [
        {
            "id": q.id,
            "recyf_objective": q.recyf_objective,
            "pillar": q.pillar,
            "title": q.title,
            "question": q.question,
            "evidence_examples": q.evidence_examples,
            "weight": q.weight,
        }
        for q in RESILIENCE_QUESTIONS
    ]
