"""
COMPASS — Référentiel ReCyF

Glue entre le référentiel générique (core/models.py, data/recyf_framework.json)
et le reste de l'outil : chargement, filtrage par applicabilité EI/EE, et
état des lieux honnête de ce qui est réellement couvert par une preuve
(technique ou processus dédié) par rapport à ce qui reste déclaratif.

Voir docs/recyf-referentiel.md pour la source et la méthodologie du référentiel.
"""

import os

from nis2_analyzer.core.models import Domain, load_framework

_RECYF_DATA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "recyf_framework.json"
)

# Objectifs couverts par un module dédié de COMPASS (autre que le bridge CloudSec).
# Association éditoriale, à revoir si le périmètre d'un module évolue :
# - governance.py          (Art. 20)      -> cadre de gouvernance
# - incident_notification.py (Art. 23)    -> détection/réaction aux incidents
# - supply_chain.py        (Art. 21(d))   -> maîtrise de l'écosystème fournisseurs
# - resilience.py          (OS13-15)      -> continuité, gestion de crise, exercices
#   (questionnaire structuré, PAS une preuve technique — la résilience est une
#   capacité organisationnelle qu'aucune API ne peut vérifier par nature)
MODULE_COVERED_OBJECTIVES: dict[str, str] = {
    "RECYF-OS02": "core/governance.py",
    "RECYF-OS03": "core/supply_chain.py",
    "RECYF-OS12": "core/incident_notification.py",
    "RECYF-OS13": "core/resilience.py",
    "RECYF-OS14": "core/resilience.py",
    "RECYF-OS15": "core/resilience.py",
}


def load_recyf_framework() -> list[Domain]:
    """Charge le référentiel ReCyF (20 objectifs, 4 piliers) depuis data/recyf_framework.json."""
    return load_framework(path=_RECYF_DATA_PATH)


def filter_by_applicability(domains: list[Domain], entity_category: str) -> list[Domain]:
    """
    Retire les objectifs réservés aux Entités Essentielles (OS16-20) quand
    l'entité évaluée est une Entité Importante — sans quoi une EI se verrait
    pénalisée pour ne pas avoir implémenté une exigence qui ne la concerne pas.

    entity_category : "essentielle" -> tous les objectifs (aucun filtrage)
                       toute autre valeur (dont "importante", "hors_champ",
                       ou inconnue) -> objectifs EI_EE uniquement, par prudence.
    """
    if entity_category == "essentielle":
        return domains

    for domain in domains:
        domain.sub_requirements = [
            req for req in domain.sub_requirements if not req.is_essential_only
        ]
    return domains


def coverage_summary(domains: list[Domain]) -> dict:
    """
    État des lieux honnête de la couverture ReCyF par COMPASS : pour chaque
    objectif, quelle est la source de preuve possible (bridge technique,
    module dédié, ou déclaratif uniquement) — indépendamment des réponses
    déjà saisies dans `domains`.

    C'est le chiffre "X objectifs sur 20" à publier au fur et à mesure que
    la couverture progresse, plutôt que de re-promettre une couverture
    complète sans preuve.
    """
    # Import différé pour éviter tout risque de cycle d'import entre
    # connectors/ et core/.
    from nis2_analyzer.connectors.cloudsec_bridge import MAPPING_CLOUDSEC_TO_NIS2

    bridge_covered: set[str] = set()
    for mapping in MAPPING_CLOUDSEC_TO_NIS2.values():
        bridge_covered.update(mapping.get("recyf_objective_ids", []))

    details = []
    for domain in domains:
        for req in domain.sub_requirements:
            sources = []
            if req.id in bridge_covered:
                sources.append("preuve_technique")
            if req.id in MODULE_COVERED_OBJECTIVES:
                sources.append("module_dedie")
            details.append({
                "id": req.id,
                "title": req.title,
                "pillar": domain.title,
                "applicability": req.applicability,
                "sources": sources,
                "status": "couvert" if sources else "declaratif",
            })

    covered = sum(1 for d in details if d["sources"])
    return {
        "total_objectives": len(details),
        "covered": covered,
        "declarative_only": len(details) - covered,
        "coverage_pct": round(covered / len(details) * 100, 1) if details else 0.0,
        "details": details,
    }
