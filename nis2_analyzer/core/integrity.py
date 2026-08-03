"""
COMPASS — Intégrité des rapports

Calcule une empreinte SHA-256 des réponses d'un assessment, affichée dans
chaque rapport généré (PDF, PSSI, HTML, dossier de preuves). Elle permet à un
lecteur de vérifier que le rapport correspond bien aux données exportées via
/api/assess ou --output, sans avoir à faire confiance au document seul.

Même pattern que le hash de clé API dans core/database.py — hashlib, rien de plus.
"""

import hashlib
import json

from nis2_analyzer.core.models import AssessmentResult, Domain


def compute_domains_hash(domains: list[Domain], org_name: str, timestamp: str) -> str:
    """Empreinte SHA-256 déterministe à partir des domaines évalués."""
    responses = {
        req.id: req.maturity.value
        for domain in domains
        for req in domain.sub_requirements
        if req.is_assessed
    }
    canonical = {
        "organization_name": org_name,
        "timestamp": timestamp,
        "responses": responses,
    }
    payload = json.dumps(canonical, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_assessment_hash(result: AssessmentResult) -> str:
    """Empreinte SHA-256 déterministe des réponses d'un assessment."""
    return compute_domains_hash(result.domains, result.organization_name, result.timestamp)


def short_hash(full_hash: str, length: int = 16) -> str:
    """Version tronquée affichable en pied de page."""
    return full_hash[:length]
