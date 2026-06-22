"""
COMPASS — Workflow de notification d'incident NIS 2 Art. 23

Double rôle :
  1. Évaluation de maturité — 6 questions sur la préparation du processus
     de notification (processus documenté, contacts CSIRT, exercices, etc.)
  2. Aide à la décision en cas d'incident réel — classification de la
     significativité, calcul des deadlines réglementaires, checklist des
     informations requises à chaque étape.

Références :
  NIS 2 Art. 23 — Obligations de notification
  NIS 2 Art. 23.4 — Contenu des notifications
  ENISA Guidelines on incident reporting (2024)

Délais réglementaires (Art. 23.1) :
  T+24h  → Early warning (alerte précoce) au CSIRT / autorité compétente
  T+72h  → Incident notification (notification complète)
  T+1 mois → Final report (rapport final)
  T+24h (après résolution) → Rapport intermédiaire si demandé par autorité

Critères de significativité (Art. 23.3) :
  Un incident est "significatif" s'il a causé ou peut causer :
  a) Perturbation opérationnelle grave des services
  b) Pertes financières importantes pour l'entité
  c) Dommages matériels ou immatériels importants pour d'autres personnes
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional


# ── Enums ─────────────────────────────────────────────────────────────────────

class IncidentSignificance(Enum):
    SIGNIFICANT   = "significant"
    POTENTIALLY   = "potentially_significant"
    NOT_SIGNIFICANT = "not_significant"
    UNKNOWN       = "unknown"

    @property
    def label(self) -> str:
        return {
            "significant":           "Incident significatif — notification obligatoire",
            "potentially_significant": "Potentiellement significatif — évaluation approfondie requise",
            "not_significant":       "Non significatif — pas de notification NIS 2 requise",
            "unknown":               "Indéterminé — collecte d'informations en cours",
        }[self.value]

    @property
    def color(self) -> str:
        return {
            "significant":           "#EF4444",
            "potentially_significant": "#F59E0B",
            "not_significant":       "#10B981",
            "unknown":               "#64748B",
        }[self.value]


class NotificationStatus(Enum):
    PENDING   = "pending"    # deadline pas encore atteinte
    DUE_SOON  = "due_soon"   # < 4h avant deadline
    OVERDUE   = "overdue"    # deadline dépassée
    COMPLETED = "completed"  # notification effectuée


# ── Critères de classification ────────────────────────────────────────────────

@dataclass
class SignificanceCriteria:
    """Critères NIS 2 Art. 23.3 pour qualifier un incident de significatif."""
    # Critères opérationnels
    services_unavailable: Optional[bool] = None      # services indisponibles pour utilisateurs
    users_affected_count: Optional[int] = None       # nombre d'utilisateurs affectés
    duration_hours: Optional[float] = None           # durée de l'impact en heures
    geographic_scope: Optional[str] = None           # "local" | "national" | "cross_border"

    # Critères financiers
    financial_loss_eur: Optional[float] = None       # perte financière estimée

    # Critères de sécurité
    data_breach: Optional[bool] = None               # violation de données personnelles
    critical_system_compromised: Optional[bool] = None  # système critique compromis
    supply_chain_impact: Optional[bool] = None       # impact chaîne d'approvisionnement

    # Réputation / tiers
    third_party_impact: Optional[bool] = None        # impact sur d'autres entités


def classify_incident(criteria: SignificanceCriteria) -> tuple[IncidentSignificance, list[str]]:
    """
    Classifie la significativité d'un incident selon NIS 2 Art. 23.3.

    Returns:
        (significance, reasons) — raisons de la classification.
    """
    significant_reasons = []
    potential_reasons = []

    # Critères entraînant significativité directe
    if criteria.critical_system_compromised:
        significant_reasons.append("Système critique compromis (Art. 23.3.a)")
    if criteria.data_breach:
        significant_reasons.append("Violation de données — notification RGPD Art. 33 également requise")
    if criteria.supply_chain_impact:
        significant_reasons.append("Impact sur la chaîne d'approvisionnement (Art. 23.3.a)")
    if criteria.geographic_scope == "cross_border":
        significant_reasons.append("Impact transfrontalier — notification multi-autorités requise (Art. 23.6)")
    if criteria.services_unavailable and criteria.duration_hours and criteria.duration_hours >= 4:
        significant_reasons.append(
            f"Services indisponibles depuis {criteria.duration_hours:.1f}h (seuil ENISA : 4h)"
        )
    if criteria.users_affected_count and criteria.users_affected_count >= 1000:
        significant_reasons.append(
            f"{criteria.users_affected_count:,} utilisateurs affectés (seuil ENISA : 1 000)"
        )
    if criteria.financial_loss_eur and criteria.financial_loss_eur >= 100_000:
        significant_reasons.append(
            f"Perte financière estimée : {criteria.financial_loss_eur/1000:.0f}K€ (seuil : 100K€)"
        )
    if criteria.third_party_impact:
        significant_reasons.append("Impact significatif sur des tiers (Art. 23.3.b)")

    # Critères entraînant classificiation "potentiellement significatif"
    if not significant_reasons:
        if criteria.services_unavailable and (not criteria.duration_hours or criteria.duration_hours < 4):
            potential_reasons.append("Services affectés mais durée < 4h — à réévaluer si l'incident persiste")
        if criteria.users_affected_count and criteria.users_affected_count < 1000:
            potential_reasons.append(f"{criteria.users_affected_count:,} utilisateurs affectés — sous le seuil de 1 000")
        if criteria.financial_loss_eur and criteria.financial_loss_eur < 100_000:
            potential_reasons.append(f"Perte estimée {criteria.financial_loss_eur/1000:.0f}K€ — sous le seuil de 100K€")

    if significant_reasons:
        return IncidentSignificance.SIGNIFICANT, significant_reasons
    if potential_reasons:
        return IncidentSignificance.POTENTIALLY, potential_reasons
    if any(v is not None for v in [
        criteria.services_unavailable, criteria.data_breach,
        criteria.critical_system_compromised, criteria.users_affected_count,
    ]):
        return IncidentSignificance.NOT_SIGNIFICANT, ["Aucun critère de significativité atteint"]
    return IncidentSignificance.UNKNOWN, ["Informations insuffisantes pour classifier l'incident"]


# ── Deadlines réglementaires ──────────────────────────────────────────────────

@dataclass
class NotificationDeadline:
    name: str
    article_ref: str
    deadline_dt: datetime
    status: NotificationStatus
    required_info: list[str]
    completed_at: Optional[datetime] = None

    @property
    def hours_remaining(self) -> float:
        if self.status == NotificationStatus.COMPLETED:
            return 0.0
        now = datetime.now(timezone.utc)
        delta = self.deadline_dt - now
        return delta.total_seconds() / 3600

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "article_ref": self.article_ref,
            "deadline_iso": self.deadline_dt.isoformat(),
            "status": self.status.value,
            "hours_remaining": round(self.hours_remaining, 1),
            "required_info": self.required_info,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


def compute_deadlines(
    detection_dt: datetime,
    completed: Optional[dict[str, datetime]] = None,
) -> list[NotificationDeadline]:
    """
    Calcule les deadlines NIS 2 Art. 23 à partir du moment de détection.

    Args:
        detection_dt: datetime UTC de la prise de connaissance de l'incident
        completed: dict optionnel {"early_warning": datetime, ...} pour marquer les étapes complétées

    Returns:
        Liste de NotificationDeadline dans l'ordre chronologique.
    """
    completed = completed or {}
    now = datetime.now(timezone.utc)

    def _status(name: str, deadline: datetime) -> NotificationStatus:
        if name in completed:
            return NotificationStatus.COMPLETED
        if now > deadline:
            return NotificationStatus.OVERDUE
        if (deadline - now).total_seconds() < 4 * 3600:
            return NotificationStatus.DUE_SOON
        return NotificationStatus.PENDING

    deadlines = [
        NotificationDeadline(
            name="early_warning",
            article_ref="NIS 2 Art. 23.1.a",
            deadline_dt=detection_dt + timedelta(hours=24),
            status=_status("early_warning", detection_dt + timedelta(hours=24)),
            required_info=[
                "Nature de l'incident (type d'attaque si connue)",
                "Services affectés et périmètre impacté",
                "Indication si l'incident est potentiellement transfrontalier",
                "Mesures préliminaires prises ou envisagées",
            ],
            completed_at=completed.get("early_warning"),
        ),
        NotificationDeadline(
            name="incident_notification",
            article_ref="NIS 2 Art. 23.1.b",
            deadline_dt=detection_dt + timedelta(hours=72),
            status=_status("incident_notification", detection_dt + timedelta(hours=72)),
            required_info=[
                "Description détaillée de l'incident (chronologie, vecteur d'attaque)",
                "Évaluation initiale de l'impact (nombre d'utilisateurs, systèmes)",
                "Cause probable identifiée",
                "Mesures d'atténuation mises en œuvre",
                "Indication si des données à caractère personnel sont concernées (RGPD)",
                "Informations sur les éventuels tiers affectés",
            ],
            completed_at=completed.get("incident_notification"),
        ),
        NotificationDeadline(
            name="final_report",
            article_ref="NIS 2 Art. 23.1.c",
            deadline_dt=detection_dt + timedelta(days=30),
            status=_status("final_report", detection_dt + timedelta(days=30)),
            required_info=[
                "Description complète et chronologie détaillée de l'incident",
                "Cause racine identifiée et confirmée",
                "Impact réel sur les services (durée, nombre d'utilisateurs, perte financière)",
                "Mesures correctives mises en place",
                "Plan d'action pour éviter la récurrence",
                "Leçons apprises",
                "Statut de la résolution (résolu / en cours)",
            ],
            completed_at=completed.get("final_report"),
        ),
    ]
    return deadlines


# ── Évaluation de maturité du processus ──────────────────────────────────────

@dataclass
class NotifQuestion:
    id: str
    title: str
    question: str
    article_ref: str
    evidence_examples: list[str]
    remediation: str
    weight: float = 1.0
    maturity: Optional[int] = None  # 0-3

    @property
    def is_gap(self) -> bool:
        return self.maturity is not None and self.maturity < 2

    @property
    def is_critical_gap(self) -> bool:
        return self.maturity is not None and self.maturity == 0


NOTIFICATION_QUESTIONS: list[NotifQuestion] = [
    NotifQuestion(
        id="N01",
        title="Procédure de notification documentée",
        question="Disposez-vous d'une procédure documentée décrivant le processus de notification NIS 2 Art. 23 (qui notifie, quoi, quand, comment) ?",
        article_ref="NIS 2 Art. 23.1",
        weight=1.5,
        evidence_examples=[
            "Procédure de gestion des incidents avec section NIS 2 dédiée",
            "Runbook de notification CSIRT avec templates",
            "Matrice RACI de la notification (RSSI, DG, DPO, équipe juridique)",
        ],
        remediation=(
            "Rédiger une procédure de notification NIS 2 décrivant : déclencheurs,"
            " responsables, délais (T+24h/T+72h/T+1 mois), canaux de notification CSIRT,"
            " et contenu requis à chaque étape. Faire valider par le COMEX."
        ),
    ),
    NotifQuestion(
        id="N02",
        title="Contacts CSIRT / autorité compétente référencés",
        question="Les coordonnées du CSIRT national et de l'autorité compétente NIS 2 sont-elles référencées et accessibles en cas de crise ?",
        article_ref="NIS 2 Art. 23.1",
        weight=1.3,
        evidence_examples=[
            "Contact ANSSI / CSIRT-FR documenté dans le plan de réponse aux incidents",
            "Fiche de contact urgence incluant numéros 24/7 et portail de notification",
            "Email/formulaire de notification testé au moins une fois",
        ],
        remediation=(
            "Référencer les contacts CSIRT nationaux (ANSSI en France : cert.ssi.gouv.fr)"
            " dans le plan de réponse aux incidents. Vérifier les canaux de notification"
            " disponibles (portail web, email, téléphone) et tester leur accessibilité."
        ),
    ),
    NotifQuestion(
        id="N03",
        title="Critères de significativité définis",
        question="Les critères permettant de qualifier un incident de 'significatif' au sens NIS 2 Art. 23.3 sont-ils documentés et connus des équipes ?",
        article_ref="NIS 2 Art. 23.3",
        weight=1.2,
        evidence_examples=[
            "Grille de qualification d'incident avec seuils (utilisateurs affectés, durée, perte financière)",
            "Arbre de décision 'incident significatif / non significatif'",
            "Formation des équipes SOC sur les critères de significativité NIS 2",
        ],
        remediation=(
            "Documenter les critères de significativité NIS 2 : durée > 4h, > 1 000 utilisateurs"
            " affectés, perte > 100K€, compromission système critique, violation de données,"
            " impact transfrontalier. Intégrer à la procédure de qualification d'incident."
        ),
    ),
    NotifQuestion(
        id="N04",
        title="Templates de notification préparés",
        question="Des modèles de notification (early warning, notification complète, rapport final) sont-ils préparés à l'avance ?",
        article_ref="NIS 2 Art. 23.4",
        weight=1.0,
        evidence_examples=[
            "Template early warning avec champs pré-remplis (Art. 23.4.a)",
            "Template notification complète (Art. 23.4.b) conforme ENISA",
            "Template rapport final avec section 'leçons apprises'",
        ],
        remediation=(
            "Préparer 3 templates conformes NIS 2 Art. 23.4 : alerte précoce T+24h,"
            " notification T+72h, rapport final T+1 mois. Utiliser les modèles ENISA"
            " disponibles sur le portail de l'autorité compétente."
        ),
    ),
    NotifQuestion(
        id="N05",
        title="Exercices de simulation de notification",
        question="Des exercices incluant la simulation du processus de notification NIS 2 ont-ils été réalisés ?",
        article_ref="NIS 2 Art. 20.1 + Art. 23",
        weight=1.2,
        evidence_examples=[
            "Exercice de crise cyber incluant la rédaction d'une early warning T+24h",
            "Test du circuit de notification avec le CSIRT ou en simulation interne",
            "Retour d'expérience (RETEX) documenté sur le processus de notification",
        ],
        remediation=(
            "Organiser au moins un exercice annuel incluant la simulation complète"
            " du processus de notification NIS 2 (T+24h → T+72h → T+1 mois)."
            " Impliquer le RSSI, le DG, le DPO et l'équipe juridique."
        ),
    ),
    NotifQuestion(
        id="N06",
        title="Coordination DPO / RGPD documentée",
        question="Le processus de coordination entre notification NIS 2 (Art. 23) et notification RGPD (Art. 33 RGPD) est-il documenté pour les incidents impliquant des données personnelles ?",
        article_ref="NIS 2 Art. 23 + RGPD Art. 33",
        weight=1.0,
        evidence_examples=[
            "Procédure de double notification NIS 2 + CNIL (si données personnelles concernées)",
            "Rôle du DPO dans le processus de notification NIS 2 défini",
            "Critères de déclenchement RGPD vs NIS 2 documentés pour les équipes",
        ],
        remediation=(
            "Documenter le processus de coordination DPO/RSSI : un même incident peut"
            " déclencher simultanément NIS 2 Art. 23 (CSIRT) et RGPD Art. 33 (CNIL)."
            " Les délais sont identiques (72h) mais les destinataires et contenus diffèrent."
        ),
    ),
]


@dataclass
class NotificationMaturityResult:
    """Résultat de l'évaluation de maturité du processus de notification."""
    questions: list[NotifQuestion]

    @property
    def overall_score(self) -> float:
        assessed = [q for q in self.questions if q.maturity is not None]
        if not assessed:
            return 0.0
        total_w = sum(q.weight for q in assessed)
        weighted = sum((q.maturity / 3 * 100) * q.weight for q in assessed)
        return round(weighted / total_w, 1)

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

    def to_dict(self) -> dict:
        maturity_labels = {0: "Absent", 1: "Informel", 2: "Formalisé", 3: "Piloté"}
        return {
            "overall_score": self.overall_score,
            "grade": self.grade,
            "total_gaps": self.total_gaps,
            "critical_gaps": self.critical_gaps,
            "questions": [
                {
                    "id": q.id,
                    "title": q.title,
                    "article_ref": q.article_ref,
                    "maturity": q.maturity,
                    "maturity_label": maturity_labels.get(q.maturity, "Non évalué") if q.maturity is not None else "Non évalué",
                    "is_gap": q.is_gap,
                    "is_critical_gap": q.is_critical_gap,
                    "remediation": q.remediation if q.is_gap else None,
                    "evidence_examples": q.evidence_examples,
                }
                for q in self.questions
            ],
            "priority_actions": _build_priority_actions(self),
        }


def assess_notification_maturity(responses: dict[str, int]) -> NotificationMaturityResult:
    """
    Évalue la maturité du processus de notification.

    Args:
        responses: {"N01": 2, "N02": 0, ...} — maturité 0-3 par question
    """
    import copy
    questions = copy.deepcopy(NOTIFICATION_QUESTIONS)
    for q in questions:
        if q.id in responses:
            v = responses[q.id]
            if v not in (0, 1, 2, 3):
                raise ValueError(f"Maturité invalide pour {q.id} : {v}. Valeurs acceptées : 0-3.")
            q.maturity = v
    return NotificationMaturityResult(questions=questions)


def get_notification_questions_schema() -> list[dict]:
    return [
        {
            "id": q.id,
            "title": q.title,
            "question": q.question,
            "article_ref": q.article_ref,
            "evidence_examples": q.evidence_examples,
            "weight": q.weight,
        }
        for q in NOTIFICATION_QUESTIONS
    ]


def _build_priority_actions(result: NotificationMaturityResult) -> list[dict]:
    actions = []
    for q in result.questions:
        if q.is_gap:
            actions.append({
                "id": q.id,
                "title": q.title,
                "priority": "CRITIQUE" if q.is_critical_gap else "ÉLEVÉE",
                "remediation": q.remediation,
                "article_ref": q.article_ref,
            })
    # CRITIQUE en premier
    actions.sort(key=lambda a: 0 if a["priority"] == "CRITIQUE" else 1)
    return actions
