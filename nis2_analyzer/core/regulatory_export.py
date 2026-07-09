"""
COMPASS — Export réglementaire NIS2
Génère un rapport structuré conforme aux exigences de reporting NIS2 Art. 21.

Le document produit couvre les sections attendues par les autorités compétentes
(ANSSI en France, BSI en Allemagne, ENISA au niveau européen) :
- Identification de l'entité et classification
- Périmètre d'évaluation
- Résultats par domaine (Art. 21 §2 a-j)
- Mesures implémentées vs. gaps
- Plan de remédiation priorisé
- Correspondance ISO/IEC 27001:2022
- Métadonnées d'audit (outil, version, horodatage)
"""

from __future__ import annotations
from datetime import datetime, timezone
from dataclasses import dataclass, field


# ── Mapping NIS2 Article 21 §2 → domaines COMPASS ────────────────────────────

ARTICLE_21_SECTIONS = {
    "NIS2-D01": {
        "article": "Art. 21(2)(a)",
        "label": "Politiques relatives à la sécurité des systèmes d'information",
        "description": (
            "Politiques en matière d'analyse des risques et de sécurité des systèmes d'information."
        ),
    },
    "NIS2-D02": {
        "article": "Art. 21(2)(a)",
        "label": "Gestion des risques",
        "description": (
            "Processus d'identification, d'évaluation et de traitement des risques de cybersécurité."
        ),
    },
    "NIS2-D03": {
        "article": "Art. 21(2)(c)",
        "label": "Continuité des activités",
        "description": (
            "Gestion des sauvegardes, plan de reprise d'activité, gestion des crises."
        ),
    },
    "NIS2-D04": {
        "article": "Art. 21(2)(d)",
        "label": "Sécurité de la chaîne d'approvisionnement",
        "description": (
            "Sécurité relative aux fournisseurs et prestataires de services."
        ),
    },
    "NIS2-D05": {
        "article": "Art. 21(2)(b)",
        "label": "Gestion des incidents",
        "description": (
            "Procédures de détection, gestion, notification et analyse post-incident."
        ),
    },
    "NIS2-D06": {
        "article": "Art. 21(2)(i)",
        "label": "Contrôle d'accès et gestion des identités",
        "description": (
            "Politiques et mesures de contrôle d'accès, authentification, gestion des privilèges."
        ),
    },
    "NIS2-D07": {
        "article": "Art. 21(2)(e)",
        "label": "Sécurité des réseaux et des systèmes d'information",
        "description": (
            "Sécurité dans l'acquisition, le développement et la maintenance des réseaux et systèmes."
        ),
    },
    "NIS2-D08": {
        "article": "Art. 21(2)(e)",
        "label": "Gestion des vulnérabilités",
        "description": (
            "Processus de gestion des correctifs, des vulnérabilités et de l'inventaire des actifs."
        ),
    },
    "NIS2-D09": {
        "article": "Art. 21(2)(g)",
        "label": "Journalisation et surveillance",
        "description": (
            "Mesures de journalisation des événements, surveillance continue et détection d'intrusion."
        ),
    },
    "NIS2-D10": {
        "article": "Art. 21(2)(g)",
        "label": "Sensibilisation et formation",
        "description": (
            "Pratiques de base en matière de cyberhygiène et formation à la cybersécurité."
        ),
    },
}

# Niveaux de maturité — libellés réglementaires
MATURITY_LABELS = {
    0: "Non implémenté",
    1: "Initial / Ad hoc",
    2: "Partiel / En cours",
    3: "Défini et implémenté",
}

MATURITY_COMPLIANCE = {
    0: "Non conforme",
    1: "Non conforme",
    2: "Partiellement conforme",
    3: "Conforme",
}

EFFORT_LABELS = {
    "low": "Court terme (< 1 mois)",
    "medium": "Moyen terme (1-6 mois)",
    "high": "Long terme (> 6 mois)",
}


# ── Structures du rapport ─────────────────────────────────────────────────────

@dataclass
class RegulatoryDomainSection:
    domain_id: str
    domain_title: str
    article_ref: str
    article_label: str
    score: float
    compliance_level: str          # "Conforme" | "Partiellement conforme" | "Non conforme"
    measures_implemented: list[str]
    gaps: list[dict]
    recommendations: list[str]


@dataclass
class RegulatoryReport:
    # En-tête réglementaire
    report_id: str
    generated_at: str
    tool_name: str
    tool_version: str
    framework: str
    reference_standard: str

    # Identification entité
    organization_name: str
    assessment_date: str

    # Synthèse exécutive
    overall_score: float
    grade: str
    total_requirements: int
    conformant_count: int
    partial_count: int
    non_conformant_count: int
    critical_gaps: int
    iso27001_coverage_pct: float

    # Sections par domaine
    sections: list[RegulatoryDomainSection]

    # Plan d'action
    action_plan_summary: dict

    # Correspondances normatives
    iso27001_controls_covered: list[str]
    iso27001_controls_missing: list[str]

    # Déclaration
    declaration: str

    def to_dict(self) -> dict:
        return {
            "report_header": {
                "report_id": self.report_id,
                "generated_at": self.generated_at,
                "tool": self.tool_name,
                "tool_version": self.tool_version,
                "framework": self.framework,
                "reference_standard": self.reference_standard,
            },
            "entity_identification": {
                "organization_name": self.organization_name,
                "assessment_date": self.assessment_date,
            },
            "executive_summary": {
                "overall_score": self.overall_score,
                "grade": self.grade,
                "total_requirements": self.total_requirements,
                "conformant": self.conformant_count,
                "partially_conformant": self.partial_count,
                "non_conformant": self.non_conformant_count,
                "critical_gaps": self.critical_gaps,
                "iso27001_coverage_pct": self.iso27001_coverage_pct,
            },
            "article_21_assessment": [
                {
                    "domain_id": s.domain_id,
                    "domain_title": s.domain_title,
                    "article_reference": s.article_ref,
                    "article_label": s.article_label,
                    "score": s.score,
                    "compliance_level": s.compliance_level,
                    "measures_implemented": s.measures_implemented,
                    "identified_gaps": s.gaps,
                    "recommendations": s.recommendations,
                }
                for s in self.sections
            ],
            "action_plan": self.action_plan_summary,
            "normative_mapping": {
                "iso_iec_27001_2022": {
                    "controls_covered": self.iso27001_controls_covered,
                    "controls_missing": self.iso27001_controls_missing,
                    "coverage_pct": self.iso27001_coverage_pct,
                }
            },
            "declaration": self.declaration,
        }


# ── Moteur d'export ───────────────────────────────────────────────────────────

def build_regulatory_report(
    assessment_payload: dict,
    assessment_id: int,
) -> RegulatoryReport:
    """
    Construit le rapport réglementaire NIS2 à partir du payload d'un assessment.
    """
    import uuid

    metadata = assessment_payload.get("metadata", {})
    scores = assessment_payload.get("scores", {})
    domains_data = assessment_payload.get("domains", [])
    gaps_list = assessment_payload.get("gaps", [])
    iso_map = assessment_payload.get("iso27001_mapping", {})
    action_plan_raw = assessment_payload.get("action_plan", {})

    org_name = metadata.get("organization", "Organisation non renseignée")
    assessment_date = metadata.get("timestamp", datetime.now(timezone.utc).isoformat())
    tool_version = metadata.get("version", "1.x")

    overall_score = scores.get("overall_score", 0.0)
    grade = scores.get("grade", "?")
    total_req = scores.get("total_requirements", 35)

    # Construire un index des gaps par domain_id
    gaps_by_domain: dict[str, list[dict]] = {}
    for gap in gaps_list:
        gap_id = gap.get("id", "")
        domain_id = "-".join(gap_id.split("-")[:2]) if gap_id else ""
        if domain_id:
            gaps_by_domain.setdefault(domain_id, []).append(gap)

    # Comptages conformité
    conformant = 0
    partial = 0
    non_conformant = 0
    critical_gaps = 0
    for gap in gaps_list:
        mv = gap.get("current_maturity_value", 0)
        if mv == 0:
            non_conformant += 1
            if gap.get("is_critical"):
                critical_gaps += 1
        elif mv == 1:
            non_conformant += 1
        else:
            partial += 1
    conformant = total_req - len(gaps_list)

    # Construire index domaines depuis le payload
    domain_scores: dict[str, float] = {}
    for d in domains_data:
        domain_scores[d.get("id", "")] = d.get("score", 0.0)

    # Construire les sections réglementaires
    sections: list[RegulatoryDomainSection] = []
    for domain_id, article_info in ARTICLE_21_SECTIONS.items():
        domain_gaps = gaps_by_domain.get(domain_id, [])
        score = domain_scores.get(domain_id, 0.0)

        # Niveau de conformité du domaine
        gap_maturities = [g.get("current_maturity_value", 0) for g in domain_gaps]
        if not domain_gaps:
            compliance = "Conforme"
        elif all(mv == 0 for mv in gap_maturities):
            compliance = "Non conforme"
        else:
            compliance = "Partiellement conforme"

        # Mesures implémentées = exigences sans gap dans ce domaine
        # On les déduit : si pas de gap pour un requirement, il est conforme
        gap_ids = {g.get("id") for g in domain_gaps}
        implemented_notes = []
        if not domain_gaps:
            implemented_notes.append(
                f"Toutes les exigences du domaine {domain_id} sont satisfaites (score: {score:.1f}/100)."
            )
        else:
            implemented_notes.append(
                f"Score partiel : {score:.1f}/100. "
                f"{len(domain_gaps)} exigence(s) présentent des déficiences."
            )

        # Gaps structurés pour le rapport
        structured_gaps = []
        for gap in domain_gaps:
            structured_gaps.append({
                "requirement_id": gap.get("id"),
                "requirement_title": gap.get("title"),
                "current_status": MATURITY_LABELS.get(
                    gap.get("current_maturity_value", 0), "Non implémenté"
                ),
                "compliance_status": MATURITY_COMPLIANCE.get(
                    gap.get("current_maturity_value", 0), "Non conforme"
                ),
                "is_critical": gap.get("is_critical", False),
                "recommended_action": gap.get("quick_win", ""),
                "effort": EFFORT_LABELS.get(gap.get("effort", "medium"), "Moyen terme"),
                "responsible": gap.get("smart", {}).get("responsible", "RSSI"),
            })

        # Recommandations
        recommendations = [
            g.get("quick_win", "") for g in domain_gaps if g.get("quick_win")
        ]

        sections.append(RegulatoryDomainSection(
            domain_id=domain_id,
            domain_title=article_info["label"],
            article_ref=article_info["article"],
            article_label=article_info["description"],
            score=round(score, 1),
            compliance_level=compliance,
            measures_implemented=implemented_notes,
            gaps=structured_gaps,
            recommendations=recommendations[:5],
        ))

    # ISO 27001 mapping
    iso_details = iso_map.get("details", {})
    covered = [ctrl for ctrl, ok in iso_details.items() if ok]
    missing = [ctrl for ctrl, ok in iso_details.items() if not ok]
    iso_coverage = iso_map.get("coverage_pct", 0.0)

    # Plan d'action
    action_plan_summary = {
        "immediate_actions": action_plan_raw.get("immediate", 0),
        "short_term_actions": action_plan_raw.get("short_term", 0),
        "medium_term_actions": action_plan_raw.get("medium_term", 0),
        "long_term_actions": action_plan_raw.get("long_term", 0),
        "total_actions": sum(action_plan_raw.values()) if action_plan_raw else 0,
    }

    report_id = f"COMPASS-{assessment_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    declaration = (
        f"Ce rapport a été généré automatiquement par COMPASS v{tool_version} "
        f"le {datetime.now(timezone.utc).strftime('%d/%m/%Y à %H:%M UTC')} "
        f"sur la base des réponses fournies par l'organisation \"{org_name}\". "
        "Il constitue une évaluation de la conformité aux exigences de l'article 21 "
        "de la directive NIS2 (2022/2555). Les résultats reflètent l'état déclaratif "
        "au moment de l'évaluation et ne se substituent pas à un audit réalisé par "
        "un organisme qualifié. Toute divergence entre cet état déclaratif et l'état "
        "réel relève de la responsabilité de l'entité évaluée."
    )

    return RegulatoryReport(
        report_id=report_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        tool_name="COMPASS",
        tool_version=tool_version,
        framework="NIS2 Directive 2022/2555",
        reference_standard="Article 21 — Mesures de gestion des risques en matière de cybersécurité",
        organization_name=org_name,
        assessment_date=assessment_date,
        overall_score=round(overall_score, 1),
        grade=grade,
        total_requirements=total_req,
        conformant_count=conformant,
        partial_count=partial,
        non_conformant_count=non_conformant,
        critical_gaps=critical_gaps,
        iso27001_coverage_pct=round(iso_coverage, 1),
        sections=sections,
        action_plan_summary=action_plan_summary,
        iso27001_controls_covered=covered,
        iso27001_controls_missing=missing,
        declaration=declaration,
    )
