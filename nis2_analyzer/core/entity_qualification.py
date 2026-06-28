"""
COMPASS — Qualification d'entité NIS 2 (Art. 3)

Détermine si une organisation est une Entité Essentielle (EE) ou une
Entité Importante (EI) selon les critères de la Directive NIS 2 Art. 3,
et expose les obligations qui en découlent (délais de notification,
sanctions maximales, régime de supervision, etc.).

Logique de qualification :
  EE : secteur hautement critique ET (>250 salariés OU CA >50M€ OU
       infrastructure critique identifiée OU service numérique critique)
  EI : secteur critique OU (secteur hautement critique ET taille PME)
  Hors-champ : secteurs non couverts et taille sous les seuils PME

Références : NIS 2 Art. 3, Annexe I (secteurs hautement critiques),
             Annexe II (secteurs critiques), Art. 34 (sanctions).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── Taxonomie NIS 2 ──────────────────────────────────────────────────────────

class EntityCategory(Enum):
    ESSENTIAL = "essentielle"
    IMPORTANT = "importante"
    OUT_OF_SCOPE = "hors_champ"

    @property
    def label(self) -> str:
        return {
            "essentielle": "Entité Essentielle",
            "importante":  "Entité Importante",
            "hors_champ":  "Hors champ NIS 2",
        }[self.value]

    @property
    def color(self) -> str:
        return {
            "essentielle": "#EF4444",
            "importante":  "#F59E0B",
            "hors_champ":  "#64748B",
        }[self.value]


# Secteurs Annexe I — hautement critiques
ANNEX_I_SECTORS = {
    "energie":          "Énergie (électricité, gaz, pétrole, hydrogène)",
    "transport":        "Transports (aérien, ferroviaire, maritime, routier)",
    "banque":           "Banques et établissements de crédit",
    "finance":          "Infrastructures des marchés financiers",
    "sante":            "Santé (hôpitaux, laboratoires, R&D pharma)",
    "eau":              "Eau potable et eaux usées",
    "infrastructure_numerique": "Infrastructures numériques (DNS, IXP, cloud, CDN, datacenters)",
    "ict_services":     "Services TIC B2B (MSP, MSSP)",
    "administration":   "Administration publique (central et régional)",
    "espace":           "Espace (opérateurs d'infrastructures spatiales)",
}

# Secteurs Annexe II — critiques
ANNEX_II_SECTORS = {
    "services_postaux":      "Services postaux et de messagerie",
    "gestion_dechets":       "Gestion des déchets",
    "industrie":             "Industrie (fabrication critique : chimie, médical, automobile, électronique)",
    "alimentaire":           "Alimentation (production, transformation, distribution à grande échelle)",
    "numerique":             "Services numériques (places de marché, moteurs de recherche, réseaux sociaux)",
    "recherche":             "Recherche (organismes de recherche)",
}

ALL_SECTORS = {**ANNEX_I_SECTORS, **ANNEX_II_SECTORS, "autre": "Autre / Inconnu"}


# ── Obligations par catégorie ────────────────────────────────────────────────

OBLIGATIONS: dict[str, dict] = {
    EntityCategory.ESSENTIAL.value: {
        "supervision": "Proactive (ex ante) — contrôles réguliers sans incident préalable",
        "notification_early_warning": "24 h après connaissance de l'incident",
        "notification_full_report":   "72 h après connaissance de l'incident",
        "notification_final_report":  "1 mois après la notification initiale",
        "sanction_max_persons_morales": "10 000 000 € ou 2 % du CA mondial annuel",
        "sanction_max_dirigeants":      "Responsabilité personnelle des dirigeants possible",
        "audit_obligatoire": True,
        "mesures_art21": [
            "Politiques d'analyse des risques (Art. 21.2.a)",
            "Gestion des incidents (Art. 21.2.b)",
            "Continuité d'activité (Art. 21.2.c)",
            "Sécurité chaîne d'approvisionnement (Art. 21.2.d)",
            "Sécurité acquisition et développement SI (Art. 21.2.e)",
            "Évaluation de l'efficacité (Art. 21.2.f)",
            "Hygiène cyber et formation (Art. 21.2.g)",
            "Cryptographie (Art. 21.2.h)",
            "Sécurité RH, contrôle d'accès, gestion actifs (Art. 21.2.i)",
            "MFA et communications sécurisées (Art. 21.2.j)",
        ],
    },
    EntityCategory.IMPORTANT.value: {
        "supervision": "Réactive (ex post) — contrôles déclenchés après incident ou plainte",
        "notification_early_warning": "24 h après connaissance de l'incident",
        "notification_full_report":   "72 h après connaissance de l'incident",
        "notification_final_report":  "1 mois après la notification initiale",
        "sanction_max_persons_morales": "7 000 000 € ou 1,4 % du CA mondial annuel",
        "sanction_max_dirigeants":      "Non applicable (pas de responsabilité personnelle systématique)",
        "audit_obligatoire": False,
        "mesures_art21": [
            "Politiques d'analyse des risques (Art. 21.2.a)",
            "Gestion des incidents (Art. 21.2.b)",
            "Continuité d'activité (Art. 21.2.c)",
            "Sécurité chaîne d'approvisionnement (Art. 21.2.d)",
            "Sécurité acquisition et développement SI (Art. 21.2.e)",
            "Évaluation de l'efficacité (Art. 21.2.f)",
            "Hygiène cyber et formation (Art. 21.2.g)",
            "Cryptographie (Art. 21.2.h)",
            "Sécurité RH, contrôle d'accès, gestion actifs (Art. 21.2.i)",
            "MFA et communications sécurisées (Art. 21.2.j)",
        ],
    },
    EntityCategory.OUT_OF_SCOPE.value: {
        "supervision": "Non applicable",
        "notification_early_warning": "Non applicable",
        "notification_full_report": "Non applicable",
        "notification_final_report": "Non applicable",
        "sanction_max_persons_morales": "Non applicable",
        "sanction_max_dirigeants": "Non applicable",
        "audit_obligatoire": False,
        "mesures_art21": [],
    },
}


# ── Dataclasses ──────────────────────────────────────────────────────────────

@dataclass
class EntityProfile:
    """Profil organisationnel fourni en entrée."""
    sector: str                     # clé dans ALL_SECTORS
    employees: int                  # nombre de salariés
    annual_revenue_eur: float       # chiffre d'affaires annuel en €
    is_critical_infrastructure: bool = False  # infrastructure critique identifiée par l'État
    provides_essential_digital_service: bool = False  # DNS, IXP, cloud, CDN, DC, MSP/MSSP
    org_name: str = "Organisation"


@dataclass
class QualificationResult:
    """Résultat de la qualification NIS 2."""
    category: EntityCategory
    sector_annex: str               # "I", "II", ou "hors_champ"
    sector_label: str
    reasons: list[str]
    obligations: dict
    recommendations: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "category_label": self.category.label,
            "category_color": self.category.color,
            "sector_annex": self.sector_annex,
            "sector_label": self.sector_label,
            "reasons": self.reasons,
            "obligations": self.obligations,
            "recommendations": self.recommendations,
            "caveats": self.caveats,
        }


# ── Moteur de qualification ──────────────────────────────────────────────────

def qualify_entity(profile: EntityProfile) -> QualificationResult:
    """
    Applique la logique NIS 2 Art. 3 et retourne la catégorie + obligations.

    Règles :
    1. Secteur Annexe I ET (>250 ETP OU CA >50M€ OU infra critique OU service
       numérique essentiel)  → Entité Essentielle
    2. Secteur Annexe I ET taille sous seuils (sans flag critique)  → Entité Importante
    3. Secteur Annexe II → Entité Importante (quelle que soit la taille)
    4. Secteur non couvert ET taille <50 ETP ET CA <10M€  → Hors champ
    5. Exception taille : administrations publiques et quelques secteurs
       spécifiques sont EE indépendamment des seuils (Art. 3.2.b–f).
    """
    sector = profile.sector
    reasons: list[str] = []
    recommendations: list[str] = []
    caveats: list[str] = []

    in_annex_i = sector in ANNEX_I_SECTORS
    in_annex_ii = sector in ANNEX_II_SECTORS
    sector_label = ALL_SECTORS.get(sector, "Secteur inconnu")

    # Seuils de taille (PME = <50 ETP ou CA <10M€ ; grande entreprise = >250 ETP ou CA >50M€)
    is_large = profile.employees > 250 or profile.annual_revenue_eur > 50_000_000
    is_medium = (not is_large) and (profile.employees >= 50 or profile.annual_revenue_eur >= 10_000_000)
    is_micro_sme = not is_large and not is_medium

    # Exceptions automatiques EE (Art. 3.2)
    auto_ee_exceptions = [
        profile.is_critical_infrastructure,
        profile.provides_essential_digital_service,
        sector == "administration",     # administrations publiques → toujours EE
        sector == "espace",             # opérateurs spatiaux → toujours EE
    ]
    has_auto_ee_exception = any(auto_ee_exceptions)

    # ── Classification ────────────────────────────────────────────────────

    if in_annex_i:
        sector_annex = "I"
        if is_large or has_auto_ee_exception:
            category = EntityCategory.ESSENTIAL
            if is_large:
                reasons.append(
                    f"Grande organisation ({profile.employees} ETP / {profile.annual_revenue_eur/1e6:.1f}M€ CA)"
                    " dans un secteur Annexe I (hautement critique)"
                )
            if profile.is_critical_infrastructure:
                reasons.append("Identifié comme infrastructure critique nationale")
            if profile.provides_essential_digital_service:
                reasons.append("Fournit un service numérique essentiel (DNS / IXP / cloud / CDN / datacenter / MSP)")
            if sector == "administration":
                reasons.append("Administration publique — qualification EE automatique (Art. 3.2.b)")
            if sector == "espace":
                reasons.append("Opérateur d'infrastructure spatiale — qualification EE automatique (Art. 3.2.f)")
        else:
            # Secteur Annexe I mais taille PME → Entité Importante
            category = EntityCategory.IMPORTANT
            reasons.append(
                f"Organisation de taille PME ({profile.employees} ETP / {profile.annual_revenue_eur/1e6:.1f}M€ CA)"
                " dans un secteur Annexe I"
            )
            caveats.append(
                "Même en dessous des seuils de taille, une autorité nationale peut vous qualifier"
                " Entité Essentielle si vous êtes identifié comme infrastructure critique (Art. 3.3–3.4)."
            )
            recommendations.append(
                "Vérifiez auprès de votre autorité compétente si une désignation individuelle est applicable."
            )

    elif in_annex_ii:
        sector_annex = "II"
        category = EntityCategory.IMPORTANT
        reasons.append(f"Secteur Annexe II (critique) : {sector_label}")
        if is_micro_sme:
            caveats.append(
                "Les micro-entreprises (<10 ETP / CA <2M€) sont en principe exclues."
                " Vérifiez l'exclusion auprès de votre autorité nationale."
            )
            recommendations.append(
                "Si vous êtes micro-entreprise, consultez votre autorité compétente pour confirmer l'exclusion."
            )

    else:
        sector_annex = "hors_champ"
        if has_auto_ee_exception:
            # Secteur non listé mais flag critique levé
            category = EntityCategory.ESSENTIAL
            reasons.append("Identifié comme infrastructure critique ou fournisseur de service numérique essentiel")
            caveats.append(
                "Votre secteur n'est pas listé en Annexe I ou II, mais les flags critiques"
                " peuvent entraîner une qualification individuelle par votre autorité nationale."
            )
        else:
            category = EntityCategory.OUT_OF_SCOPE
            reasons.append(
                f"Secteur '{sector_label}' non couvert par les Annexes I ou II de la Directive NIS 2"
            )
            caveats.append(
                "La transposition nationale peut élargir le périmètre."
                " Vérifiez la réglementation de votre pays membre."
            )
            recommendations.append(
                "Même hors champ légal, l'application des mesures Art. 21 constitue une bonne"
                " pratique et peut être exigée par vos clients (chaîne d'approvisionnement)."
            )

    # ── Recommandations génériques ────────────────────────────────────────

    if category == EntityCategory.ESSENTIAL:
        recommendations.append(
            "Enregistrez-vous auprès de votre autorité nationale compétente (ANSSI en France)"
            " dans les 3 mois suivant votre prise de conscience du statut EE."
        )
        recommendations.append(
            "Mettez en place un processus de notification d'incident opérationnel sous 24 h."
        )
        recommendations.append(
            "Planifiez un audit de sécurité périodique (Art. 32.4) — c'est une obligation pour les EE."
        )
    elif category == EntityCategory.IMPORTANT:
        recommendations.append(
            "Enregistrez-vous auprès de votre autorité nationale compétente."
        )
        recommendations.append(
            "Documentez vos mesures de sécurité Art. 21 en vue d'un éventuel contrôle ex post."
        )

    obligations = OBLIGATIONS[category.value]

    return QualificationResult(
        category=category,
        sector_annex=sector_annex,
        sector_label=sector_label,
        reasons=reasons,
        obligations=obligations,
        recommendations=recommendations,
        caveats=caveats,
    )
