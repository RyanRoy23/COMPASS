"""
COMPASS — Gouvernance NIS 2 Art. 20

Évalue la maturité de l'organe de direction sur ses responsabilités NIS 2 :
approbation des mesures de sécurité, supervision, formation, accountability.

Art. 20 NIS 2 impose :
  §1 — L'organe de direction approuve les mesures de gestion des risques (Art. 21)
  §1 — L'organe de direction supervise leur mise en œuvre
  §1 — Les membres peuvent être tenus personnellement responsables
  §2 — Les membres de l'organe de direction suivent des formations
  §2 — L'organe de direction offre des formations similaires aux employés

8 questions couvrent ces 5 piliers :
  G1 — Approbation formelle des mesures de sécurité
  G2 — Supervision de la mise en œuvre
  G3 — Formation des dirigeants (obligatoire Art. 20.2)
  G4 — Reporting cybersécurité régulier au board
  G5 — Responsabilité et accountability
  G6 — Budget cybersécurité approuvé par le board
  G7 — Plan de crise impliquant les dirigeants
  G8 — Désignation d'un responsable sécurité avec accès direct au board
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Niveaux de maturité gouvernance ─────────────────────────────────────────

class GovMaturity(Enum):
    ABSENT   = 0   # Inexistant ou non formalisé
    INITIAL  = 1   # Informel, ad hoc, non documenté
    DEFINED  = 2   # Formalisé, documenté, appliqué
    MANAGED  = 3   # Piloté, mesuré, amélioré en continu

    @property
    def label(self) -> str:
        return {
            0: "Absent",
            1: "Informel",
            2: "Formalisé",
            3: "Piloté",
        }[self.value]

    @property
    def score_pct(self) -> float:
        return self.value / 3 * 100

    @property
    def color(self) -> str:
        return {0: "#EF4444", 1: "#F59E0B", 2: "#3B82F6", 3: "#10B981"}[self.value]


# ── Questions de gouvernance ─────────────────────────────────────────────────

@dataclass
class GovQuestion:
    id: str
    pillar: str
    title: str
    question: str
    article_ref: str
    evidence_examples: list[str]
    remediation_absent: str
    remediation_managed: str
    weight: float = 1.0
    maturity: Optional[GovMaturity] = None
    notes: str = ""

    @property
    def is_gap(self) -> bool:
        return self.maturity is not None and self.maturity.value < 2

    @property
    def is_critical_gap(self) -> bool:
        return self.maturity is not None and self.maturity.value == 0


GOVERNANCE_QUESTIONS: list[GovQuestion] = [
    GovQuestion(
        id="G01",
        pillar="Approbation",
        title="Approbation formelle des mesures de sécurité",
        question="L'organe de direction a-t-il formellement approuvé la politique de sécurité et les mesures NIS 2 Art. 21 ?",
        article_ref="NIS 2 Art. 20.1",
        weight=1.5,
        evidence_examples=[
            "PV de réunion du conseil/comité de direction mentionnant l'approbation de la politique SSI",
            "Résolution du board ou délibération formelle",
            "Politique de sécurité signée par le DG ou PDG",
        ],
        remediation_absent=(
            "Inscrire à l'ordre du jour du prochain conseil la présentation et l'approbation"
            " de la politique de sécurité. Produire un PV de délibération formel."
        ),
        remediation_managed=(
            "Renouveler l'approbation annuellement et après tout incident majeur."
            " Lier l'approbation aux objectifs de conformité NIS 2."
        ),
    ),
    GovQuestion(
        id="G02",
        pillar="Supervision",
        title="Supervision de la mise en œuvre",
        question="L'organe de direction supervise-t-il activement la mise en œuvre des mesures de sécurité ?",
        article_ref="NIS 2 Art. 20.1",
        weight=1.3,
        evidence_examples=[
            "Tableau de bord cybersécurité présenté trimestriellement au board",
            "Comité de sécurité avec représentation au niveau direction",
            "Indicateurs de conformité NIS 2 intégrés aux KPI de l'entreprise",
        ],
        remediation_absent=(
            "Créer un comité de sécurité avec au moins un membre de la direction."
            " Définir un reporting trimestriel minimum vers le board."
        ),
        remediation_managed=(
            "Intégrer les métriques cybersécurité au tableau de bord stratégique"
            " et lier la performance aux objectifs individuels des dirigeants."
        ),
    ),
    GovQuestion(
        id="G03",
        pillar="Formation",
        title="Formation des membres de l'organe de direction",
        question="Les membres de l'organe de direction ont-ils suivi une formation sur les risques et enjeux cybersécurité ?",
        article_ref="NIS 2 Art. 20.2",
        weight=1.5,
        evidence_examples=[
            "Attestations de formation cybersécurité pour dirigeants (ex : ANSSI, CLUSIF, prestataire certifié)",
            "Sensibilisation NIS 2 documentée pour les membres du board",
            "Programme de formation annuel incluant les enjeux de conformité NIS 2",
        ],
        remediation_absent=(
            "Organiser une session de sensibilisation cybersécurité dédiée aux dirigeants (min. 4h)."
            " C'est une obligation explicite Art. 20.2 — ne pas la négliger."
        ),
        remediation_managed=(
            "Mettre en place un programme annuel de montée en compétence"
            " avec certification ou attestation formelle. Étendre aux N-1."
        ),
    ),
    GovQuestion(
        id="G04",
        pillar="Reporting",
        title="Reporting cybersécurité régulier au board",
        question="Un reporting cybersécurité structuré est-il présenté régulièrement à l'organe de direction ?",
        article_ref="NIS 2 Art. 20.1",
        weight=1.0,
        evidence_examples=[
            "Rapport trimestriel de sécurité présenté au COMEX ou CA",
            "Indicateurs : incidents, score de conformité, avancement du plan de remédiation",
            "Revue annuelle de la posture de sécurité avec le board",
        ],
        remediation_absent=(
            "Définir un format standard de rapport cybersécurité (1 page executive)."
            " Planifier 4 présentations annuelles minimum au board."
        ),
        remediation_managed=(
            "Automatiser la production du rapport avec des indicateurs en temps réel."
            " Lier les métriques aux obligations de notification NIS 2 (Art. 23)."
        ),
    ),
    GovQuestion(
        id="G05",
        pillar="Accountability",
        title="Responsabilité et accountability formalisées",
        question="La responsabilité en matière de cybersécurité est-elle explicitement attribuée au niveau de la direction ?",
        article_ref="NIS 2 Art. 20.1",
        weight=1.2,
        evidence_examples=[
            "Fiche de poste DG/PDG mentionnant la responsabilité cybersécurité",
            "Politique de gouvernance SSI avec matrice RACI incluant le niveau direction",
            "Mention explicite dans les statuts ou règlement intérieur",
        ],
        remediation_absent=(
            "Formaliser la responsabilité cybersécurité dans les fiches de poste des dirigeants."
            " Produire une matrice RACI validée par le board."
        ),
        remediation_managed=(
            "Intégrer la performance cybersécurité dans les critères de rémunération variable"
            " et les évaluations annuelles des dirigeants."
        ),
    ),
    GovQuestion(
        id="G06",
        pillar="Budget",
        title="Budget cybersécurité approuvé par le board",
        question="Le budget dédié à la cybersécurité est-il formellement approuvé par l'organe de direction ?",
        article_ref="NIS 2 Art. 20.1",
        weight=1.0,
        evidence_examples=[
            "Ligne budgétaire cybersécurité distincte dans le budget annuel approuvé",
            "PV de validation du budget SSI par le board ou COMEX",
            "Plan pluriannuel d'investissement cybersécurité validé par la direction",
        ],
        remediation_absent=(
            "Créer une ligne budgétaire cybersécurité distincte."
            " La soumettre à approbation formelle du board avec le budget annuel."
        ),
        remediation_managed=(
            "Définir un ratio cible (ex : % du CA ou de l'IT budget) validé par le board."
            " Revoir annuellement en fonction des risques identifiés."
        ),
    ),
    GovQuestion(
        id="G07",
        pillar="Gestion de crise",
        title="Implication des dirigeants dans la gestion de crise",
        question="Les dirigeants sont-ils impliqués dans le plan de gestion de crise cyber et formés à leur rôle ?",
        article_ref="NIS 2 Art. 20.1 + Art. 21.2.c",
        weight=1.0,
        evidence_examples=[
            "Plan de crise cyber avec rôles définis pour la direction",
            "Exercice de crise (simulation, war game) incluant les dirigeants",
            "Protocole de décision en cas d'incident majeur validé par le board",
        ],
        remediation_absent=(
            "Définir le rôle des dirigeants dans le plan de continuité et de réponse aux incidents."
            " Organiser un exercice de crise annuel impliquant le COMEX."
        ),
        remediation_managed=(
            "Intégrer le plan de crise aux obligations de notification NIS 2 Art. 23."
            " Documenter le retour d'expérience de chaque exercice et l'adapter."
        ),
    ),
    GovQuestion(
        id="G08",
        pillar="RSSI / Accès board",
        title="RSSI ou responsable sécurité avec accès direct au board",
        question="Un RSSI ou équivalent dispose-t-il d'un accès direct et régulier à l'organe de direction ?",
        article_ref="NIS 2 Art. 20.1",
        weight=1.2,
        evidence_examples=[
            "RSSI membre permanent ou invité régulier du COMEX/board",
            "Ligne de reporting directe RSSI → DG sans filtre hiérarchique",
            "Droit d'alerte formalisé du RSSI vers le board en cas de risque critique",
        ],
        remediation_absent=(
            "Nommer un RSSI ou responsable sécurité avec un mandat formel."
            " Définir une ligne de reporting directe vers le board."
        ),
        remediation_managed=(
            "Intégrer le RSSI au comité de direction. Formaliser un droit d'alerte"
            " indépendant de la hiérarchie en cas de risque majeur."
        ),
    ),
]


# ── Résultat de l'évaluation de gouvernance ──────────────────────────────────

@dataclass
class GovernanceResult:
    questions: list[GovQuestion]
    entity_category: str = "importante"  # "essentielle" | "importante" | "hors_champ"

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
    def gaps_by_pillar(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for q in self.questions:
            if q.is_gap:
                result.setdefault(q.pillar, []).append(q.title)
        return result

    @property
    def liability_risk(self) -> str:
        """
        Évalue le risque de responsabilité personnelle des dirigeants.
        Basé sur Art. 20.1 (approbation + supervision) et catégorie entité.
        """
        g01 = next((q for q in self.questions if q.id == "G01"), None)
        g02 = next((q for q in self.questions if q.id == "G02"), None)
        g05 = next((q for q in self.questions if q.id == "G05"), None)

        critical_missing = sum(
            1 for q in [g01, g02, g05]
            if q and q.maturity is not None and q.maturity.value < 2
        )

        if self.entity_category == "essentielle":
            if critical_missing >= 2:
                return "ÉLEVÉ"
            if critical_missing == 1:
                return "MODÉRÉ"
            return "FAIBLE"
        else:
            if critical_missing >= 2:
                return "MODÉRÉ"
            return "FAIBLE"

    def to_dict(self) -> dict:
        return {
            "overall_score": self.overall_score,
            "grade": self.grade,
            "total_gaps": self.total_gaps,
            "critical_gaps": self.critical_gaps,
            "liability_risk": self.liability_risk,
            "entity_category": self.entity_category,
            "questions": [
                {
                    "id": q.id,
                    "pillar": q.pillar,
                    "title": q.title,
                    "article_ref": q.article_ref,
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
            "gaps_by_pillar": self.gaps_by_pillar,
            "recommendations": _build_recommendations(self),
        }


# ── Moteur d'évaluation ──────────────────────────────────────────────────────

def assess_governance(
    responses: dict[str, int],
    entity_category: str = "importante",
) -> GovernanceResult:
    """
    Évalue la gouvernance à partir d'un dict {question_id: maturity (0-3)}.

    Args:
        responses: {"G01": 2, "G03": 1, ...}
        entity_category: "essentielle" | "importante" | "hors_champ"

    Returns:
        GovernanceResult avec score, grade, gaps et recommandations.
    """
    import copy
    questions = copy.deepcopy(GOVERNANCE_QUESTIONS)

    for q in questions:
        if q.id in responses:
            value = responses[q.id]
            if value not in (0, 1, 2, 3):
                raise ValueError(f"Maturité invalide pour {q.id} : {value}. Valeurs acceptées : 0-3.")
            q.maturity = GovMaturity(value)

    return GovernanceResult(questions=questions, entity_category=entity_category)


def get_questions_schema() -> list[dict]:
    """Retourne la liste des questions pour l'UI."""
    return [
        {
            "id": q.id,
            "pillar": q.pillar,
            "title": q.title,
            "question": q.question,
            "article_ref": q.article_ref,
            "evidence_examples": q.evidence_examples,
            "weight": q.weight,
        }
        for q in GOVERNANCE_QUESTIONS
    ]


def _build_recommendations(result: GovernanceResult) -> list[dict]:
    """Génère des recommandations priorisées selon les gaps identifiés."""
    recs = []

    priority_map = {
        "G03": {
            "priority": "CRITIQUE",
            "action": "Former les dirigeants à la cybersécurité (Art. 20.2 — obligation légale explicite)",
        },
        "G01": {
            "priority": "CRITIQUE",
            "action": "Obtenir l'approbation formelle de la politique de sécurité par le board (Art. 20.1)",
        },
        "G05": {
            "priority": "ÉLEVÉE",
            "action": "Formaliser la responsabilité cybersécurité dans les fonctions de direction",
        },
        "G08": {
            "priority": "ÉLEVÉE",
            "action": "Nommer un RSSI avec accès direct et régulier à l'organe de direction",
        },
        "G02": {
            "priority": "ÉLEVÉE",
            "action": "Mettre en place un reporting trimestriel cybersécurité vers le board",
        },
        "G07": {
            "priority": "MOYENNE",
            "action": "Impliquer les dirigeants dans le plan de crise et organiser des exercices",
        },
        "G06": {
            "priority": "MOYENNE",
            "action": "Formaliser l'approbation du budget cybersécurité par le board",
        },
        "G04": {
            "priority": "NORMALE",
            "action": "Structurer un reporting cybersécurité régulier (tableau de bord executive)",
        },
    }

    for q in result.questions:
        if q.is_gap and q.id in priority_map:
            rec = priority_map[q.id].copy()
            rec["question_id"] = q.id
            rec["pillar"] = q.pillar
            rec["current_maturity"] = q.maturity.label if q.maturity else "Non évalué"
            rec["remediation"] = q.remediation_absent
            recs.append(rec)

    # Trier : CRITIQUE → ÉLEVÉE → MOYENNE → NORMALE
    order = {"CRITIQUE": 0, "ÉLEVÉE": 1, "MOYENNE": 2, "NORMALE": 3}
    recs.sort(key=lambda r: order.get(r["priority"], 9))
    return recs
