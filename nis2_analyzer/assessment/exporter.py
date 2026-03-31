"""
NIS 2 Compliance Gap Analyzer — Assessment Exporter
Exporte les résultats de l'évaluation en JSON.

Pourquoi un fichier séparé pour l'export ?
Parce que l'évaluation (interactive.py) et le stockage des résultats
sont deux responsabilités distinctes. Si demain on veut exporter en
CSV ou en XML, on ajoute une fonction ici sans toucher au questionnaire.

Le format JSON est choisi parce qu'il est :
- Lisible par un humain (debug facile)
- Parsable par le rapport HTML (Jour 5)
- Compatible avec les outils GRC/SIEM (intégration future)
"""

import json
import os
from datetime import datetime, timezone
from nis2_analyzer.core.models import Domain
from nis2_analyzer.core.scoring import ScoringEngine


def export_to_json(domains: list[Domain], org_name: str, output_path: str) -> str:
    """
    Exporte les résultats complets en JSON.
    
    Ce fichier JSON contient TOUT ce qu'il faut pour générer
    le rapport HTML sans relancer l'évaluation :
    - Métadonnées (date, outil, organisation)
    - Scores globaux et par domaine
    - Liste de tous les gaps avec remédiation
    - Plan d'action priorisé
    - Mapping ISO 27001
    - Réponses brutes (pour audit trail)
    
    Args:
        domains: les domaines avec les maturités renseignées
        org_name: nom de l'organisation évaluée
        output_path: chemin du fichier JSON de sortie
    
    Returns:
        le chemin absolu du fichier créé
    """
    # Utiliser le ScoringEngine du Jour 1 pour tout calculer
    engine = ScoringEngine()
    analysis = engine.full_analysis(domains, org_name)
    
    # Ajouter les réponses brutes pour traçabilité
    # Un auditeur veut pouvoir vérifier chaque réponse
    raw_responses = []
    for domain in domains:
        for req in domain.sub_requirements:
            raw_responses.append({
                "requirement_id": req.id,
                "requirement_title": req.title,
                "domain": domain.title,
                "question": req.question,
                "maturity_value": req.maturity.value if req.maturity else None,
                "maturity_label": req.maturity.label if req.maturity else "Non évalué",
                "is_gap": req.is_gap,
                "is_critical_gap": req.is_critical_gap,
                "iso27001_refs": req.iso27001_refs,
                "evidence_examples": req.evidence_examples,
                "notes": req.notes,
            })
    
    analysis["raw_responses"] = raw_responses
    
    # Créer le répertoire de sortie si nécessaire
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    # Écrire le fichier
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)
    
    abs_path = os.path.abspath(output_path)
    return abs_path


def load_from_json(input_path: str) -> dict:
    """
    Charge un résultat d'évaluation depuis un fichier JSON.
    
    Utile pour :
    - Régénérer un rapport HTML sans relancer l'évaluation
    - Comparer deux évaluations dans le temps
    - Alimenter le bridge CloudSec (Jour 7)
    """
    with open(input_path, "r", encoding="utf-8") as f:
        return json.load(f)
