"""
COMPASS — Interface Web (FastAPI)

Expose le moteur d'évaluation via une API REST + une interface HTML.
Conçu pour être minimal : pas de framework JS, pas de build step,
un seul fichier HTML servi par FastAPI.

Endpoints :
  GET  /                   → interface HTML principale
  GET  /api/framework      → liste des domaines et questions
  POST /api/assess         → soumet les réponses, retourne le scoring complet
  POST /api/qualify        → qualification NIS 2 Art. 3 (EE/EI/hors champ)
  GET  /api/history        → historique des assessments
  GET  /api/history/{id}   → détail d'un assessment
  GET  /api/compare/{a}/{b}→ comparaison de deux assessments
"""

import html
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from nis2_analyzer.core.models import load_framework, MaturityLevel
from nis2_analyzer.core.scoring import ScoringEngine
from nis2_analyzer.core.database import (
    save_assessment, list_assessments, get_assessment, compare_assessments
)
from nis2_analyzer.core.entity_qualification import (
    qualify_entity, EntityProfile, ALL_SECTORS
)
from nis2_analyzer.core.governance import (
    assess_governance, get_questions_schema
)

app = FastAPI(
    title="COMPASS",
    description="API d'évaluation de conformité NIS 2 — Article 21",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_TEMPLATE = Path(__file__).parent / "templates" / "index.html"


# ── Modèles Pydantic ──────────────────────────────────────────────────────────

class AssessmentRequest(BaseModel):
    org_name: str = Field(..., min_length=1, max_length=200)
    responses: dict[str, int] = Field(
        ...,
        description="Mapping requirement_id → maturity (0-3)",
    )


class GovernanceRequest(BaseModel):
    responses: dict[str, int] = Field(
        ..., description="Mapping question_id (G01-G08) → maturity (0-3)"
    )
    entity_category: str = Field(
        "importante",
        description="'essentielle' | 'importante' | 'hors_champ'"
    )


class QualifyRequest(BaseModel):
    org_name: str = Field("Organisation", min_length=1, max_length=200)
    sector: str = Field(..., description=f"Clé de secteur parmi : {', '.join(ALL_SECTORS)}")
    employees: int = Field(0, ge=0, description="Nombre de salariés")
    annual_revenue_eur: float = Field(0.0, ge=0, description="CA annuel en euros")
    is_critical_infrastructure: bool = Field(False)
    provides_essential_digital_service: bool = Field(False)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index():
    return HTMLResponse(_TEMPLATE.read_text(encoding="utf-8"))


@app.get("/api/framework")
def get_framework():
    """Retourne la liste des domaines et leurs questions."""
    domains = load_framework()
    return {
        "domains": [
            {
                "id": d.id,
                "title": d.title,
                "weight": d.weight,
                "requirements": [
                    {
                        "id": r.id,
                        "title": r.title,
                        "question": r.question,
                        "iso27001_refs": r.iso27001_refs,
                    }
                    for r in d.sub_requirements
                ],
            }
            for d in domains
        ]
    }


@app.get("/api/governance/questions")
def get_governance_questions():
    """Retourne les 8 questions de gouvernance Art. 20."""
    return {"questions": get_questions_schema()}


@app.post("/api/governance")
def api_governance(body: GovernanceRequest):
    """
    Évalue la gouvernance Art. 20 et retourne score, grade, gaps et recommandations.
    """
    allowed_categories = ("essentielle", "importante", "hors_champ")
    if body.entity_category not in allowed_categories:
        raise HTTPException(
            status_code=422,
            detail=f"entity_category invalide. Valeurs : {allowed_categories}"
        )
    try:
        result = assess_governance(body.responses, entity_category=body.entity_category)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return result.to_dict()


@app.post("/api/qualify")
def api_qualify(body: QualifyRequest):
    """
    Qualifie l'entité selon NIS 2 Art. 3 et retourne la catégorie + obligations.
    """
    if body.sector not in ALL_SECTORS:
        raise HTTPException(
            status_code=422,
            detail=f"Secteur inconnu : '{body.sector}'. Valeurs acceptées : {list(ALL_SECTORS.keys())}"
        )
    profile = EntityProfile(
        sector=body.sector,
        employees=body.employees,
        annual_revenue_eur=body.annual_revenue_eur,
        is_critical_infrastructure=body.is_critical_infrastructure,
        provides_essential_digital_service=body.provides_essential_digital_service,
        org_name=html.escape(body.org_name.strip()),
    )
    result = qualify_entity(profile)
    return result.to_dict()


@app.post("/api/assess", status_code=201)
def run_assessment(body: AssessmentRequest):
    """
    Soumet les réponses au questionnaire et retourne le scoring complet.
    Sauvegarde automatiquement dans l'historique.
    """
    org_name = html.escape(body.org_name.strip())

    # Validation des valeurs de maturité
    for req_id, value in body.responses.items():
        if value not in (0, 1, 2, 3):
            raise HTTPException(
                status_code=422,
                detail=f"Maturité invalide pour {req_id} : {value}. Valeurs acceptées : 0, 1, 2, 3."
            )

    domains = load_framework()
    answered = 0
    for domain in domains:
        for req in domain.sub_requirements:
            if req.id in body.responses:
                req.maturity = MaturityLevel(body.responses[req.id])
                answered += 1

    if answered == 0:
        raise HTTPException(
            status_code=422,
            detail="Aucune réponse valide fournie. Vérifiez les identifiants de requirements."
        )

    engine = ScoringEngine()
    analysis = engine.full_analysis(domains, org_name)
    assessment_id = save_assessment(analysis)
    analysis["assessment_id"] = assessment_id

    return analysis


@app.get("/api/history")
def get_history(org_name: str = None, limit: int = 20):
    """Liste les assessments sauvegardés."""
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=422, detail="limit doit être entre 1 et 100.")
    return {"assessments": list_assessments(org_name=org_name, limit=limit)}


@app.get("/api/history/{assessment_id}")
def get_assessment_detail(assessment_id: int):
    """Retourne le détail complet d'un assessment."""
    result = get_assessment(assessment_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Assessment #{assessment_id} introuvable.")
    return result


@app.get("/api/compare/{id_a}/{id_b}")
def compare(id_a: int, id_b: int):
    """Compare deux assessments et retourne le delta."""
    try:
        return compare_assessments(id_a, id_b)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
