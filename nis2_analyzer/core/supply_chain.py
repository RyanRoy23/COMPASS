"""
COMPASS — Supply Chain Security NIS 2 Art. 21(d)

Deux niveaux d'analyse :
  1. Évaluation individuelle d'un fournisseur — score de risque, criticité,
     exigences contractuelles NIS 2, recommandations ciblées.
  2. Évaluation de maturité globale — 7 questions sur la gouvernance de la
     chaîne d'approvisionnement (inventaire, cartographie, clauses contrats,
     audits, surveillance continue, plan de sortie, formation achats).

Références :
  NIS 2 Art. 21.2.d — Sécurité de la chaîne d'approvisionnement
  NIS 2 Art. 21.2.e — Sécurité dans l'acquisition, le développement et
                       la maintenance des systèmes d'information
  ENISA Threat Landscape for Supply Chain Attacks (2021)
  ANSSI — Recommandations pour la sécurité des prestataires (2022)

Critères de criticité fournisseur :
  CRITIQUE  — Accès direct aux SI critiques / données sensibles,
              dépendance forte, peu de substituts disponibles
  IMPORTANT — Accès partiel ou indirect, substitut existant mais coûteux
  STANDARD  — Accès limité ou nul, facilement remplaçable
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Enums ─────────────────────────────────────────────────────────────────────

class SupplierCriticality(Enum):
    CRITICAL  = "critique"
    IMPORTANT = "important"
    STANDARD  = "standard"

    @property
    def label(self) -> str:
        return {
            "critique":  "Critique",
            "important": "Important",
            "standard":  "Standard",
        }[self.value]

    @property
    def color(self) -> str:
        return {
            "critique":  "#EF4444",
            "important": "#F59E0B",
            "standard":  "#10B981",
        }[self.value]

    @property
    def audit_frequency(self) -> str:
        return {
            "critique":  "Annuel minimum — audit documentaire ou sur site",
            "important": "Tous les 2 ans — questionnaire de sécurité + revue contractuelle",
            "standard":  "Tous les 3 ans — auto-déclaration de conformité",
        }[self.value]


class AccessLevel(Enum):
    NONE        = 0   # Pas d'accès aux SI
    READ_ONLY   = 1   # Accès lecture seule à des données non critiques
    OPERATIONAL = 2   # Accès opérationnel aux SI (administration, maintenance)
    PRIVILEGED  = 3   # Accès privilégié / administrateur / données sensibles


class DataSensitivity(Enum):
    NONE        = 0   # Aucune donnée sensible
    INTERNAL    = 1   # Données internes non confidentielles
    CONFIDENTIAL = 2  # Données confidentielles ou personnelles
    CRITICAL    = 3   # Données stratégiques, secrets industriels, données de santé


# ── Profil fournisseur ────────────────────────────────────────────────────────

@dataclass
class SupplierProfile:
    """Profil d'un fournisseur/prestataire à évaluer."""
    name: str
    category: str                          # ex: "MSP", "SaaS", "Consulting", "Matériel"
    access_level: AccessLevel
    data_sensitivity: DataSensitivity
    is_single_source: bool = False         # fournisseur unique sans substitut immédiat
    has_nis2_compliance: Optional[bool] = None   # déjà certifié/déclaré conforme NIS 2
    has_iso27001: Optional[bool] = None          # certifié ISO 27001
    has_soc2: Optional[bool] = None              # certifié SOC 2
    pentest_recent: Optional[bool] = None        # pentest < 12 mois
    incident_history: bool = False         # incident de sécurité connu dans les 3 ans
    contract_has_security_clauses: bool = False  # contrat avec clauses sécurité NIS 2
    subcontracts_to_others: Optional[bool] = None  # fait appel à des sous-traitants
    geographic_risk: str = "eu"            # "eu" | "non_eu_trusted" | "high_risk"
    criticality_override: Optional[SupplierCriticality] = None  # forçage manuel


# ── Scoring et classification ─────────────────────────────────────────────────

@dataclass
class SupplierRiskScore:
    """Résultat de l'évaluation d'un fournisseur."""
    supplier: SupplierProfile
    criticality: SupplierCriticality
    risk_score: float             # 0-100, plus élevé = plus risqué
    risk_factors: list[str]
    mitigating_factors: list[str]
    required_contract_clauses: list[str]
    audit_recommendation: str
    action_items: list[dict]

    def to_dict(self) -> dict:
        return {
            "name": self.supplier.name,
            "category": self.supplier.category,
            "criticality": self.criticality.value,
            "criticality_label": self.criticality.label,
            "criticality_color": self.criticality.color,
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
            "mitigating_factors": self.mitigating_factors,
            "required_contract_clauses": self.required_contract_clauses,
            "audit_recommendation": self.audit_recommendation,
            "action_items": self.action_items,
        }


def assess_supplier(profile: SupplierProfile) -> SupplierRiskScore:
    """
    Évalue le risque d'un fournisseur et retourne son score + classification NIS 2.

    Score de risque (0-100) basé sur :
      - Niveau d'accès aux SI (0-30 pts)
      - Sensibilité des données traitées (0-25 pts)
      - Fournisseur unique / sans substitut (0-15 pts)
      - Historique d'incident (0-10 pts)
      - Risque géographique (0-10 pts)
      - Absence de certifications (0-10 pts)

    Mitigants qui réduisent le score :
      - Certifications (ISO 27001, SOC 2, NIS 2) : -5 pts chacune
      - Pentest récent : -5 pts
      - Clauses contractuelles de sécurité : -5 pts
    """
    risk_factors: list[str] = []
    mitigating_factors: list[str] = []
    score = 0.0

    # ── Facteurs de risque ────────────────────────────────────────────────

    # Accès SI
    access_scores = {
        AccessLevel.NONE: 0,
        AccessLevel.READ_ONLY: 10,
        AccessLevel.OPERATIONAL: 20,
        AccessLevel.PRIVILEGED: 30,
    }
    score += access_scores[profile.access_level]
    if profile.access_level == AccessLevel.PRIVILEGED:
        risk_factors.append("Accès privilégié aux systèmes d'information (administrateur / données sensibles)")
    elif profile.access_level == AccessLevel.OPERATIONAL:
        risk_factors.append("Accès opérationnel aux SI (maintenance, administration)")
    elif profile.access_level == AccessLevel.READ_ONLY:
        risk_factors.append("Accès en lecture à des données internes")

    # Sensibilité des données
    data_scores = {
        DataSensitivity.NONE: 0,
        DataSensitivity.INTERNAL: 5,
        DataSensitivity.CONFIDENTIAL: 15,
        DataSensitivity.CRITICAL: 25,
    }
    score += data_scores[profile.data_sensitivity]
    if profile.data_sensitivity == DataSensitivity.CRITICAL:
        risk_factors.append("Traite des données critiques ou stratégiques (secrets industriels, données de santé)")
    elif profile.data_sensitivity == DataSensitivity.CONFIDENTIAL:
        risk_factors.append("Traite des données confidentielles ou à caractère personnel")

    # Source unique
    if profile.is_single_source:
        score += 15
        risk_factors.append("Fournisseur unique — aucun substitut immédiatement disponible (dépendance forte)")

    # Historique d'incident
    if profile.incident_history:
        score += 10
        risk_factors.append("Incident de sécurité connu dans les 3 dernières années")

    # Risque géographique
    geo_scores = {"eu": 0, "non_eu_trusted": 5, "high_risk": 10}
    score += geo_scores.get(profile.geographic_risk, 0)
    if profile.geographic_risk == "high_risk":
        risk_factors.append("Localisation dans un pays à risque géopolitique élevé")
    elif profile.geographic_risk == "non_eu_trusted":
        risk_factors.append("Localisation hors UE (pays de confiance) — transferts de données à vérifier")

    # Absence de certifications
    cert_missing = 0
    if profile.has_iso27001 is False:
        cert_missing += 1
        risk_factors.append("Pas de certification ISO 27001")
    if profile.has_soc2 is False and profile.has_iso27001 is False:
        cert_missing += 1
    if profile.has_nis2_compliance is False:
        risk_factors.append("Non déclaré conforme NIS 2 (ou statut inconnu)")
    score += min(cert_missing * 5, 10)

    # Sous-traitance
    if profile.subcontracts_to_others:
        score += 5
        risk_factors.append("Fait appel à des sous-traitants — risque de 4e partie non contrôlé")

    # ── Facteurs mitigeants ───────────────────────────────────────────────

    if profile.has_iso27001:
        score = max(0, score - 5)
        mitigating_factors.append("Certifié ISO 27001")
    if profile.has_soc2:
        score = max(0, score - 5)
        mitigating_factors.append("Certifié SOC 2")
    if profile.has_nis2_compliance:
        score = max(0, score - 5)
        mitigating_factors.append("Déclaré conforme NIS 2")
    if profile.pentest_recent:
        score = max(0, score - 5)
        mitigating_factors.append("Pentest réalisé dans les 12 derniers mois")
    if profile.contract_has_security_clauses:
        score = max(0, score - 5)
        mitigating_factors.append("Contrat avec clauses de sécurité NIS 2 en place")

    risk_score = round(min(score, 100), 1)

    # ── Classification ────────────────────────────────────────────────────

    if profile.criticality_override:
        criticality = profile.criticality_override
    elif risk_score >= 50 or profile.access_level == AccessLevel.PRIVILEGED or profile.data_sensitivity == DataSensitivity.CRITICAL:
        criticality = SupplierCriticality.CRITICAL
    elif risk_score >= 25 or profile.access_level == AccessLevel.OPERATIONAL or profile.data_sensitivity == DataSensitivity.CONFIDENTIAL:
        criticality = SupplierCriticality.IMPORTANT
    else:
        criticality = SupplierCriticality.STANDARD

    # ── Clauses contractuelles requises ──────────────────────────────────

    base_clauses = [
        "Droit d'audit et d'accès aux rapports de sécurité",
        "Obligation de notification d'incident dans les 24h",
        "Exigences minimales de sécurité (MFA, chiffrement, patch management)",
        "Clause de continuité de service et plan de sortie",
        "Interdiction de cession du contrat sans accord préalable",
    ]

    important_clauses = base_clauses + [
        "Attestation de conformité NIS 2 ou ISO 27001 annuelle",
        "Obligation de signalement des sous-traitants ayant accès aux données",
        "Tests de pénétration annuels avec partage des résultats",
        "SLA sécurité incluant délais de correction des vulnérabilités critiques",
    ]

    critical_clauses = important_clauses + [
        "Audit de sécurité sur site possible à tout moment (avec préavis raisonnable)",
        "Obligation de certification ISO 27001 ou équivalent sous 12 mois",
        "Plan de réponse aux incidents conjoint (PSSI fournisseur alignée)",
        "Clause de résiliation pour manquement à la sécurité sans pénalité",
        "Inventaire des sous-traitants (4e parties) avec notification de tout changement",
        "Exigence de chiffrement de bout en bout pour les données critiques",
    ]

    clauses_map = {
        SupplierCriticality.CRITICAL:  critical_clauses,
        SupplierCriticality.IMPORTANT: important_clauses,
        SupplierCriticality.STANDARD:  base_clauses,
    }

    # ── Actions prioritaires ──────────────────────────────────────────────

    actions = []

    if not profile.contract_has_security_clauses:
        actions.append({
            "priority": "CRITIQUE" if criticality == SupplierCriticality.CRITICAL else "ÉLEVÉE",
            "action": f"Mettre à jour le contrat avec {profile.name} pour inclure les clauses de sécurité NIS 2",
            "deadline": "3 mois",
        })
    if profile.has_iso27001 is False and criticality == SupplierCriticality.CRITICAL:
        actions.append({
            "priority": "ÉLEVÉE",
            "action": f"Exiger la certification ISO 27001 de {profile.name} ou obtenir une attestation de conformité équivalente",
            "deadline": "12 mois",
        })
    if not profile.pentest_recent and criticality != SupplierCriticality.STANDARD:
        actions.append({
            "priority": "MOYENNE",
            "action": f"Demander le rapport de pentest récent de {profile.name} (< 12 mois)",
            "deadline": "6 mois",
        })
    if profile.is_single_source:
        actions.append({
            "priority": "ÉLEVÉE",
            "action": f"Identifier un fournisseur alternatif à {profile.name} pour réduire la dépendance (plan de sortie)",
            "deadline": "12 mois",
        })
    if profile.subcontracts_to_others and not profile.contract_has_security_clauses:
        actions.append({
            "priority": "MOYENNE",
            "action": f"Exiger de {profile.name} un inventaire de ses sous-traitants et leurs niveaux de sécurité",
            "deadline": "6 mois",
        })

    return SupplierRiskScore(
        supplier=profile,
        criticality=criticality,
        risk_score=risk_score,
        risk_factors=risk_factors,
        mitigating_factors=mitigating_factors,
        required_contract_clauses=clauses_map[criticality],
        audit_recommendation=criticality.audit_frequency,
        action_items=sorted(actions, key=lambda a: {"CRITIQUE": 0, "ÉLEVÉE": 1, "MOYENNE": 2}.get(a["priority"], 3)),
    )


# ── Portfolio supply chain ────────────────────────────────────────────────────

def assess_supplier_portfolio(profiles: list[SupplierProfile]) -> dict:
    """
    Évalue un portefeuille de fournisseurs et retourne une synthèse.
    """
    results = [assess_supplier(p) for p in profiles]

    critical_count   = sum(1 for r in results if r.criticality == SupplierCriticality.CRITICAL)
    important_count  = sum(1 for r in results if r.criticality == SupplierCriticality.IMPORTANT)
    standard_count   = sum(1 for r in results if r.criticality == SupplierCriticality.STANDARD)
    avg_risk         = round(sum(r.risk_score for r in results) / len(results), 1) if results else 0.0
    without_clauses  = sum(1 for r in results if not r.supplier.contract_has_security_clauses)
    single_sources   = sum(1 for r in results if r.supplier.is_single_source)

    return {
        "total_suppliers": len(results),
        "critical_count":  critical_count,
        "important_count": important_count,
        "standard_count":  standard_count,
        "average_risk_score": avg_risk,
        "suppliers_without_security_clauses": without_clauses,
        "single_source_dependencies": single_sources,
        "suppliers": [r.to_dict() for r in results],
    }


# ── Maturité de gouvernance supply chain ─────────────────────────────────────

@dataclass
class SupplyChainQuestion:
    id: str
    title: str
    question: str
    article_ref: str
    evidence_examples: list[str]
    remediation: str
    weight: float = 1.0
    maturity: Optional[int] = None

    @property
    def is_gap(self) -> bool:
        return self.maturity is not None and self.maturity < 2

    @property
    def is_critical_gap(self) -> bool:
        return self.maturity is not None and self.maturity == 0


SUPPLY_CHAIN_QUESTIONS: list[SupplyChainQuestion] = [
    SupplyChainQuestion(
        id="SC01",
        title="Inventaire des fournisseurs critiques",
        question="Disposez-vous d'un inventaire complet et à jour de vos fournisseurs et prestataires ayant accès à vos SI ou données ?",
        article_ref="NIS 2 Art. 21.2.d",
        weight=1.5,
        evidence_examples=[
            "Registre des fournisseurs avec niveau d'accès, données traitées et criticité",
            "Outil TPRM (Third Party Risk Management) ou fichier maintenu à jour",
            "Cartographie des flux de données vers les tiers",
        ],
        remediation=(
            "Construire un inventaire des fournisseurs avec pour chaque tiers : nom, catégorie,"
            " niveau d'accès aux SI, données traitées, criticité NIS 2, statut contractuel."
            " Le maintenir à jour à chaque nouveau contrat ou renouvellement."
        ),
    ),
    SupplyChainQuestion(
        id="SC02",
        title="Évaluation de sécurité avant onboarding",
        question="Réalisez-vous une évaluation de sécurité systématique avant d'engager un nouveau fournisseur critique ?",
        article_ref="NIS 2 Art. 21.2.d",
        weight=1.3,
        evidence_examples=[
            "Questionnaire de sécurité fournisseur (type SIG, CAIQ, ou maison)",
            "Revue des certifications (ISO 27001, SOC 2) avant signature",
            "Validation RSSI ou équipe sécurité dans le processus d'achat",
        ],
        remediation=(
            "Intégrer une étape de validation sécurité dans le processus d'achat/contractualisation."
            " Utiliser un questionnaire standardisé (ex: CAIQ de la CSA, SIG de Shared Assessments)"
            " pour les fournisseurs classifiés Important ou Critique."
        ),
    ),
    SupplyChainQuestion(
        id="SC03",
        title="Clauses de sécurité dans les contrats",
        question="Les contrats avec vos fournisseurs critiques incluent-ils des clauses de sécurité NIS 2 (notification d'incident, droit d'audit, exigences minimales) ?",
        article_ref="NIS 2 Art. 21.2.d",
        weight=1.5,
        evidence_examples=[
            "Clauses type de sécurité dans les modèles de contrat (DPA, annexe sécurité)",
            "Exigence de notification d'incident dans les 24h dans les SLA",
            "Droit d'audit documenté dans les contrats fournisseurs critiques",
        ],
        remediation=(
            "Intégrer des clauses de sécurité dans tous les nouveaux contrats fournisseurs."
            " Pour les contrats existants, planifier des avenants lors du prochain renouvellement."
            " Prioriser les fournisseurs Critique puis Important."
        ),
    ),
    SupplyChainQuestion(
        id="SC04",
        title="Surveillance et audits périodiques",
        question="Réalisez-vous des audits ou revues de sécurité périodiques de vos fournisseurs critiques ?",
        article_ref="NIS 2 Art. 21.2.d",
        weight=1.2,
        evidence_examples=[
            "Programme d'audit annuel fournisseurs critiques (documentaire ou sur site)",
            "Collecte et revue des rapports de pentest ou certifications à renouvellement",
            "Tableau de bord de suivi de la conformité des fournisseurs",
        ],
        remediation=(
            "Établir un programme de surveillance annuel : audit documentaire pour les Important,"
            " audit sur site ou questionnaire approfondi pour les Critique."
            " Documenter les résultats et suivre les plans de remédiation fournisseurs."
        ),
    ),
    SupplyChainQuestion(
        id="SC05",
        title="Gestion des incidents impliquant des fournisseurs",
        question="Avez-vous un processus pour gérer et notifier les incidents de sécurité impliquant un fournisseur ?",
        article_ref="NIS 2 Art. 21.2.d + Art. 23",
        weight=1.2,
        evidence_examples=[
            "Procédure de gestion des incidents incluant la dimension tiers (notification, isolation)",
            "Obligation contractuelle de notification d'incident fournisseur dans les 24h",
            "Exercice de crise incluant un scénario de compromission via fournisseur",
        ],
        remediation=(
            "Ajouter dans la procédure de gestion des incidents un volet 'incident fournisseur' :"
            " qui contacte le fournisseur, comment qualifier l'impact, et si une notification"
            " NIS 2 Art. 23 est déclenchée par l'incident tiers."
        ),
    ),
    SupplyChainQuestion(
        id="SC06",
        title="Plan de sortie et gestion de la dépendance",
        question="Disposez-vous de plans de sortie documentés pour vos fournisseurs critiques (continuité en cas de défaillance ou de rupture de contrat) ?",
        article_ref="NIS 2 Art. 21.2.c + Art. 21.2.d",
        weight=1.0,
        evidence_examples=[
            "Plan de sortie documenté pour chaque fournisseur unique (single source)",
            "Fournisseur de substitution identifié pour les services critiques",
            "Tests de bascule ou de continuité réalisés",
        ],
        remediation=(
            "Documenter un plan de sortie pour chaque fournisseur classifié Critique,"
            " notamment les single-source. Identifier des alternatives et tester la capacité"
            " de bascule au moins une fois par an."
        ),
    ),
    SupplyChainQuestion(
        id="SC07",
        title="Sensibilisation des équipes achat / juridique",
        question="Les équipes responsables des achats et de la contractualisation sont-elles formées aux exigences NIS 2 pour la supply chain ?",
        article_ref="NIS 2 Art. 21.2.d + Art. 20.2",
        weight=1.0,
        evidence_examples=[
            "Formation NIS 2 supply chain pour les acheteurs et juristes",
            "Check-list sécurité intégrée au processus d'achat",
            "RSSI impliqué dans la validation des contrats avec tiers critiques",
        ],
        remediation=(
            "Organiser une session de sensibilisation pour les équipes achats et juridiques"
            " sur les exigences NIS 2 Art. 21.2.d. Fournir une check-list pratique"
            " à utiliser lors de chaque nouvelle contractualisation."
        ),
    ),
]


@dataclass
class SupplyChainMaturityResult:
    questions: list[SupplyChainQuestion]

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
            "priority_actions": self._build_actions(),
        }

    def _build_actions(self) -> list[dict]:
        actions = []
        for q in self.questions:
            if q.is_gap:
                actions.append({
                    "id": q.id,
                    "title": q.title,
                    "priority": "CRITIQUE" if q.is_critical_gap else "ÉLEVÉE",
                    "remediation": q.remediation,
                    "article_ref": q.article_ref,
                })
        actions.sort(key=lambda a: 0 if a["priority"] == "CRITIQUE" else 1)
        return actions


def assess_supply_chain_maturity(responses: dict[str, int]) -> SupplyChainMaturityResult:
    """
    Évalue la maturité de la gouvernance supply chain.

    Args:
        responses: {"SC01": 2, "SC02": 0, ...} — maturité 0-3 par question
    """
    import copy
    questions = copy.deepcopy(SUPPLY_CHAIN_QUESTIONS)
    for q in questions:
        if q.id in responses:
            v = responses[q.id]
            if v not in (0, 1, 2, 3):
                raise ValueError(f"Maturité invalide pour {q.id} : {v}. Valeurs acceptées : 0-3.")
            q.maturity = v
    return SupplyChainMaturityResult(questions=questions)


def get_supply_chain_questions_schema() -> list[dict]:
    return [
        {
            "id": q.id,
            "title": q.title,
            "question": q.question,
            "article_ref": q.article_ref,
            "evidence_examples": q.evidence_examples,
            "weight": q.weight,
        }
        for q in SUPPLY_CHAIN_QUESTIONS
    ]
