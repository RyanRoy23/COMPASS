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
  POST /api/cloudsec-audit → bridge CloudSec Audit Toolkit (Azure/Entra ID) → preuves NIS 2
                              (Article 21 ET ReCyF)
  GET  /api/recyf/framework → 20 objectifs ReCyF, regroupés par pilier
  POST /api/recyf/assess    → soumet les réponses ReCyF, retourne le scoring +
                              l'état de couverture (preuve technique / déclaratif)
  GET  /api/history        → historique des assessments
  GET  /api/history/{id}   → détail d'un assessment
  GET  /api/compare/{a}/{b}→ comparaison de deux assessments
"""

import collections
import html
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.background import BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from nis2_analyzer import __version__
from nis2_analyzer.core.models import load_framework, MaturityLevel
from nis2_analyzer.core.scoring import ScoringEngine
from nis2_analyzer.core.database import (
    save_assessment, list_assessments, get_assessment, compare_assessments,
    create_tenant, get_tenant_by_key, list_tenants, get_default_tenant_id,
)
from nis2_analyzer.core.entity_qualification import (
    qualify_entity, EntityProfile, ALL_SECTORS
)
from nis2_analyzer.core.governance import (
    assess_governance, get_questions_schema
)
from nis2_analyzer.core.resilience import (
    assess_resilience, get_questions_schema as get_resilience_questions_schema
)
from nis2_analyzer.reporting.evidence_package import build_evidence_package
from nis2_analyzer.core.incident_notification import (
    classify_incident, compute_deadlines,
    assess_notification_maturity, get_notification_questions_schema,
    SignificanceCriteria,
)
from nis2_analyzer.core.supply_chain import (
    assess_supplier,
    assess_supply_chain_maturity, get_supply_chain_questions_schema,
    SupplierProfile, AccessLevel, DataSensitivity,
)
from nis2_analyzer.connectors.cloudsec_bridge import CloudSecBridge
from nis2_analyzer.core.recyf import (
    load_recyf_framework, filter_by_applicability, coverage_summary,
)

app = FastAPI(
    title="COMPASS",
    description="API d'évaluation de conformité NIS 2 — Article 21",
    version=__version__,
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


class RecyfAssessmentRequest(BaseModel):
    org_name: str = Field(..., min_length=1, max_length=200)
    responses: dict[str, int] = Field(
        ...,
        description="Mapping objective_id (RECYF-OS01 à RECYF-OS20) → maturity (0-3)",
    )
    entity_category: str = Field(
        "importante",
        description="'essentielle' (20 objectifs) | 'importante' ou 'hors_champ' (15 objectifs, OS16-20 exclus)",
    )


class SupplierAssessRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    category: str = Field("Autre", max_length=100)
    access_level: int = Field(..., ge=0, le=3, description="0=Aucun 1=Lecture 2=Opérationnel 3=Privilégié")
    data_sensitivity: int = Field(..., ge=0, le=3, description="0=Aucune 1=Interne 2=Confidentielle 3=Critique")
    is_single_source: bool = False
    has_nis2_compliance: Optional[bool] = None
    has_iso27001: Optional[bool] = None
    has_soc2: Optional[bool] = None
    pentest_recent: Optional[bool] = None
    incident_history: bool = False
    contract_has_security_clauses: bool = False
    subcontracts_to_others: Optional[bool] = None
    geographic_risk: str = Field("eu", description="'eu' | 'non_eu_trusted' | 'high_risk'")


class SupplyChainMaturityRequest(BaseModel):
    responses: dict[str, int] = Field(..., description="Mapping question_id (SC01-SC07) → maturity (0-3)")


class NotificationMaturityRequest(BaseModel):
    responses: dict[str, int] = Field(..., description="Mapping question_id (N01-N06) → maturity (0-3)")


class IncidentClassifyRequest(BaseModel):
    services_unavailable: Optional[bool] = None
    users_affected_count: Optional[int] = Field(None, ge=0)
    duration_hours: Optional[float] = Field(None, ge=0)
    geographic_scope: Optional[str] = Field(None, description="'local' | 'national' | 'cross_border'")
    financial_loss_eur: Optional[float] = Field(None, ge=0)
    data_breach: Optional[bool] = None
    critical_system_compromised: Optional[bool] = None
    supply_chain_impact: Optional[bool] = None
    third_party_impact: Optional[bool] = None


class IncidentDeadlinesRequest(BaseModel):
    detection_iso: str = Field(..., description="Datetime UTC de détection (ISO 8601)")
    completed: dict[str, str] = Field(
        default_factory=dict,
        description="Étapes complétées : {'early_warning': '<iso_datetime>', ...}"
    )


class GovernanceRequest(BaseModel):
    responses: dict[str, int] = Field(
        ..., description="Mapping question_id (G01-G08) → maturity (0-3)"
    )
    entity_category: str = Field(
        "importante",
        description="'essentielle' | 'importante' | 'hors_champ'"
    )


class ResilienceRequest(BaseModel):
    responses: dict[str, int] = Field(
        ..., description="Mapping question_id (RES01-RES08) → maturity (0-3)"
    )


class QualifyRequest(BaseModel):
    org_name: str = Field("Organisation", min_length=1, max_length=200)
    sector: str = Field(..., description=f"Clé de secteur parmi : {', '.join(ALL_SECTORS)}")
    employees: int = Field(0, ge=0, description="Nombre de salariés")
    annual_revenue_eur: float = Field(0.0, ge=0, description="CA annuel en euros")
    is_critical_infrastructure: bool = Field(False)
    provides_essential_digital_service: bool = Field(False)


class CloudSecAuditRequest(BaseModel):
    demo_mode: bool = Field(True, description="Mode démonstration — rapport CloudSec réaliste préchargé")
    cloudsec_report: Optional[dict] = Field(
        None, description="Rapport JSON produit par le CloudSec Audit Toolkit (requis si demo_mode=false)"
    )


class TenantCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, description="Nom de l'organisation")
    slug: str = Field(..., min_length=2, max_length=60, pattern=r"^[a-z0-9\-]+$",
                      description="Identifiant unique (lettres minuscules, chiffres, tirets)")
    plan: str = Field("free", description="'free' | 'pro'")


# ── Authentification multi-tenant ─────────────────────────────────────────────

def _require_api_key() -> bool:
    """
    Si COMPASS_REQUIRE_API_KEY=true/1, une clé API valide est obligatoire sur
    tous les endpoints tenant-scoped. Par défaut (variable absente), le fallback
    mono-tenant 'default' reste actif — adapté à un usage local mono-utilisateur.
    À activer dès que l'instance est exposée au-delà d'un poste local.
    """
    return os.environ.get("COMPASS_REQUIRE_API_KEY", "").strip().lower() in ("1", "true", "yes")


def _resolve_tenant(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> dict:
    """
    Dépendance FastAPI : résout la clé API → tenant.
    Sans clé = tenant 'default' (compatibilité mono-tenant), sauf si
    COMPASS_REQUIRE_API_KEY force l'authentification.
    """
    if not x_api_key:
        if _require_api_key():
            raise HTTPException(status_code=401, detail="Clé API requise (COMPASS_REQUIRE_API_KEY activé).")
        return {"id": get_default_tenant_id(), "slug": "default", "name": "Default", "plan": "free"}
    tenant = get_tenant_by_key(x_api_key)
    if tenant is None:
        raise HTTPException(status_code=401, detail="Clé API invalide.")
    return tenant


# ── Rate limiting (in-process, fenêtre glissante) ─────────────────────────────
#
# Pas de dépendance externe (pas de Redis/slowapi) — cohérent avec la philosophie
# self-hosted/zéro-dépendance-superflue du projet. Suffisant pour un déploiement
# mono-instance ; à remplacer par une solution distribuée si un jour multi-worker.

_RATE_LIMIT_WINDOW_SECONDS = 60
_RATE_LIMIT_MAX_REQUESTS = 30
_rate_limit_hits: dict[str, collections.deque] = collections.defaultdict(collections.deque)


def _rate_limit(request: Request) -> None:
    """Dépendance FastAPI : limite chaque IP à _RATE_LIMIT_MAX_REQUESTS / fenêtre."""
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    hits = _rate_limit_hits[client_ip]

    while hits and now - hits[0] > _RATE_LIMIT_WINDOW_SECONDS:
        hits.popleft()

    if len(hits) >= _RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Trop de requêtes — limite de {_RATE_LIMIT_MAX_REQUESTS}/min dépassée. Réessayez plus tard.",
        )

    hits.append(now)


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


@app.get("/api/recyf/framework")
def get_recyf_framework():
    """
    Retourne les 20 objectifs de sécurité ReCyF, regroupés par pilier.

    Chaque objectif porte son applicabilité ("EI_EE" ou "EE") : à l'appelant
    de décider s'il affiche ou masque les objectifs réservés aux entités
    essentielles (OS16-20) selon la catégorie de l'entité évaluée.
    """
    domains = load_recyf_framework()
    return {
        "pillars": [
            {
                "id": d.id,
                "title": d.title,
                "description": d.description,
                "objectives": [
                    {
                        "id": r.id,
                        "title": r.title,
                        "description": r.description,
                        "question": r.question,
                        "applicability": r.applicability,
                    }
                    for r in d.sub_requirements
                ],
            }
            for d in domains
        ]
    }


@app.get("/api/supply-chain/questions")
def get_sc_questions():
    """Retourne les 7 questions de maturité supply chain Art. 21(d)."""
    return {"questions": get_supply_chain_questions_schema()}


@app.post("/api/supply-chain/maturity")
def api_sc_maturity(body: SupplyChainMaturityRequest):
    """Évalue la maturité de la gouvernance supply chain Art. 21(d)."""
    try:
        result = assess_supply_chain_maturity(body.responses)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return result.to_dict()


@app.post("/api/supply-chain/assess-supplier")
def api_assess_supplier(body: SupplierAssessRequest):
    """Évalue le risque d'un fournisseur individuel et retourne sa criticité NIS 2."""
    geo_allowed = ("eu", "non_eu_trusted", "high_risk")
    if body.geographic_risk not in geo_allowed:
        raise HTTPException(status_code=422, detail=f"geographic_risk invalide. Valeurs : {geo_allowed}")
    profile = SupplierProfile(
        name=html.escape(body.name.strip()),
        category=html.escape(body.category.strip()),
        access_level=AccessLevel(body.access_level),
        data_sensitivity=DataSensitivity(body.data_sensitivity),
        is_single_source=body.is_single_source,
        has_nis2_compliance=body.has_nis2_compliance,
        has_iso27001=body.has_iso27001,
        has_soc2=body.has_soc2,
        pentest_recent=body.pentest_recent,
        incident_history=body.incident_history,
        contract_has_security_clauses=body.contract_has_security_clauses,
        subcontracts_to_others=body.subcontracts_to_others,
        geographic_risk=body.geographic_risk,
    )
    return assess_supplier(profile).to_dict()


@app.get("/api/incident/questions")
def get_incident_questions():
    """Retourne les 6 questions de maturité du processus de notification Art. 23."""
    return {"questions": get_notification_questions_schema()}


@app.post("/api/incident/maturity")
def api_incident_maturity(body: NotificationMaturityRequest):
    """Évalue la maturité du processus de notification Art. 23."""
    try:
        result = assess_notification_maturity(body.responses)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return result.to_dict()


@app.post("/api/incident/classify")
def api_incident_classify(body: IncidentClassifyRequest):
    """Classifie la significativité d'un incident selon NIS 2 Art. 23.3."""
    criteria = SignificanceCriteria(
        services_unavailable=body.services_unavailable,
        users_affected_count=body.users_affected_count,
        duration_hours=body.duration_hours,
        geographic_scope=body.geographic_scope,
        financial_loss_eur=body.financial_loss_eur,
        data_breach=body.data_breach,
        critical_system_compromised=body.critical_system_compromised,
        supply_chain_impact=body.supply_chain_impact,
        third_party_impact=body.third_party_impact,
    )
    significance, reasons = classify_incident(criteria)
    return {
        "significance": significance.value,
        "significance_label": significance.label,
        "significance_color": significance.color,
        "reasons": reasons,
        "notification_required": significance.value == "significant",
    }


@app.post("/api/incident/deadlines")
def api_incident_deadlines(body: IncidentDeadlinesRequest):
    """Calcule les deadlines NIS 2 Art. 23 à partir de la détection."""
    try:
        detection_dt = datetime.fromisoformat(body.detection_iso)
        if detection_dt.tzinfo is None:
            detection_dt = detection_dt.replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(status_code=422, detail="Format datetime invalide. Utilisez ISO 8601 (ex: 2026-06-22T10:00:00Z).")

    completed_parsed: dict[str, datetime] = {}
    for name, iso in body.completed.items():
        try:
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            completed_parsed[name] = dt
        except ValueError:
            raise HTTPException(status_code=422, detail=f"Format datetime invalide pour '{name}'.")

    deadlines = compute_deadlines(detection_dt, completed=completed_parsed)
    return {"detection_iso": detection_dt.isoformat(), "deadlines": [d.to_dict() for d in deadlines]}


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


@app.get("/api/resilience/questions")
def get_resilience_questions():
    """Retourne les 8 questions de résilience ReCyF (OS13-15 : continuité, crise, exercices)."""
    return {"questions": get_resilience_questions_schema()}


@app.post("/api/resilience")
def api_resilience(body: ResilienceRequest):
    """
    Évalue la résilience (OS13-15) et retourne score, grade, gaps et la maturité
    par objectif ReCyF — à utiliser pour pré-remplir le formulaire ReCyF.
    """
    try:
        result = assess_resilience(body.responses)
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


@app.post("/api/tenants", status_code=201, dependencies=[Depends(_rate_limit)])
def api_create_tenant(body: TenantCreateRequest):
    """
    Crée un nouveau tenant et retourne sa clé API.
    La clé est affichée UNE SEULE FOIS — conservez-la précieusement.
    """
    if body.plan not in ("free", "pro"):
        raise HTTPException(status_code=422, detail="plan invalide. Valeurs : 'free', 'pro'.")
    try:
        result = create_tenant(
            name=html.escape(body.name.strip()),
            slug=body.slug.strip().lower(),
            plan=body.plan,
        )
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return result


@app.get("/api/tenants")
def api_list_tenants():
    """Liste tous les tenants (sans clés API)."""
    return {"tenants": list_tenants()}


@app.get("/api/tenants/me")
def api_tenant_me(tenant: dict = Depends(_resolve_tenant)):
    """Retourne les informations du tenant authentifié."""
    return tenant


@app.post("/api/assess", status_code=201, dependencies=[Depends(_rate_limit)])
def run_assessment(body: AssessmentRequest, tenant: dict = Depends(_resolve_tenant)):
    """
    Soumet les réponses au questionnaire et retourne le scoring complet.
    Sauvegarde automatiquement dans l'historique du tenant.
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
    assessment_id = save_assessment(analysis, tenant_id=tenant["id"])
    analysis["assessment_id"] = assessment_id

    return analysis


@app.post("/api/recyf/assess", status_code=201, dependencies=[Depends(_rate_limit)])
def run_recyf_assessment(body: RecyfAssessmentRequest, tenant: dict = Depends(_resolve_tenant)):
    """
    Soumet les réponses au référentiel ReCyF et retourne le scoring complet,
    accompagné de l'état de couverture (preuve technique / module dédié /
    déclaratif) pour chacun des objectifs évalués.

    Sauvegarde automatiquement dans l'historique du tenant, au même titre
    qu'un assessment Article 21 (les deux référentiels partagent le même
    historique, distingués par `metadata.framework`).
    """
    allowed_categories = ("essentielle", "importante", "hors_champ")
    if body.entity_category not in allowed_categories:
        raise HTTPException(
            status_code=422,
            detail=f"entity_category invalide. Valeurs : {allowed_categories}",
        )

    org_name = html.escape(body.org_name.strip())

    for req_id, value in body.responses.items():
        if value not in (0, 1, 2, 3):
            raise HTTPException(
                status_code=422,
                detail=f"Maturité invalide pour {req_id} : {value}. Valeurs acceptées : 0, 1, 2, 3."
            )

    domains = load_recyf_framework()
    filter_by_applicability(domains, body.entity_category)

    answered = 0
    for domain in domains:
        for req in domain.sub_requirements:
            if req.id in body.responses:
                req.maturity = MaturityLevel(body.responses[req.id])
                answered += 1

    if answered == 0:
        raise HTTPException(
            status_code=422,
            detail="Aucune réponse valide fournie. Vérifiez les identifiants d'objectifs (RECYF-OS01 à RECYF-OS20)."
        )

    engine = ScoringEngine()
    analysis = engine.full_analysis(
        domains, org_name, framework_label="ReCyF — Référentiel Cyber France v2.5"
    )
    analysis["recyf_coverage"] = coverage_summary(domains)

    assessment_id = save_assessment(analysis, tenant_id=tenant["id"])
    analysis["assessment_id"] = assessment_id

    return analysis


@app.post("/api/cloudsec-audit", status_code=200, dependencies=[Depends(_rate_limit)])
def run_cloudsec_audit(body: CloudSecAuditRequest):
    """
    Traduit un rapport CloudSec Audit Toolkit (Azure/Entra ID) en preuves NIS 2.

    En mode demo_mode=true, utilise un rapport CloudSec réaliste préchargé.
    En mode réel, fournissez le rapport JSON produit par le CloudSec Audit Toolkit
    (`python -m cloudsec.cli --output report.json`) dans `cloudsec_report`.
    """
    if not body.demo_mode and not body.cloudsec_report:
        raise HTTPException(
            status_code=422,
            detail="cloudsec_report est requis pour un audit réel. Utilisez demo_mode=true pour tester.",
        )

    bridge = CloudSecBridge()
    try:
        if body.demo_mode:
            bridge.load_from_dict(CloudSecBridge.demo_report())
        else:
            bridge.load_from_dict(body.cloudsec_report)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    bridge.map_to_nis2()
    evidence = bridge.get_evidence_report()
    passed = sum(1 for e in evidence if e["result"] == "PASS")
    failed = len(evidence) - passed

    domains = load_framework()
    mapping_summary = bridge.apply_to_framework(domains)

    recyf_domains = load_recyf_framework()
    recyf_mapping_summary = bridge.apply_to_recyf_framework(recyf_domains)

    return {
        "summary": {
            "total_controls": bridge.total_mapped,
            "passed": passed,
            "failed": failed,
            "pass_rate": round(passed / max(bridge.total_mapped, 1) * 100, 1),
        },
        "evidence": evidence,
        "mapping_summary": mapping_summary,  # Article 21 — conservé pour compatibilité
        "recyf": {
            "mapping_summary": recyf_mapping_summary,
            "coverage": coverage_summary(recyf_domains),
        },
    }


@app.get("/api/history")
def get_history(org_name: str = None, limit: int = 20,
                tenant: dict = Depends(_resolve_tenant)):
    """Liste les assessments du tenant authentifié."""
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=422, detail="limit doit être entre 1 et 100.")
    return {"assessments": list_assessments(org_name=org_name, limit=limit,
                                            tenant_id=tenant["id"])}


@app.get("/api/history/{assessment_id}")
def get_assessment_detail(assessment_id: int, tenant: dict = Depends(_resolve_tenant)):
    """Retourne le détail complet d'un assessment (vérifié par tenant)."""
    result = get_assessment(assessment_id, tenant_id=tenant["id"])
    if result is None:
        raise HTTPException(status_code=404, detail=f"Assessment #{assessment_id} introuvable.")
    return result


@app.post("/api/evidence-package")
def api_evidence_package(body: AssessmentRequest, background_tasks: BackgroundTasks):
    """
    Génère un dossier de preuves ZIP à partir des réponses au questionnaire.
    Retourne le fichier ZIP en téléchargement direct.
    """
    org_name = html.escape(body.org_name.strip())

    for req_id, value in body.responses.items():
        if value not in (0, 1, 2, 3):
            raise HTTPException(
                status_code=422,
                detail=f"Maturité invalide pour {req_id} : {value}."
            )

    domains = load_framework()
    answered = 0
    for domain in domains:
        for req in domain.sub_requirements:
            if req.id in body.responses:
                req.maturity = MaturityLevel(body.responses[req.id])
                answered += 1

    if answered == 0:
        raise HTTPException(status_code=422, detail="Aucune réponse valide fournie.")

    engine = ScoringEngine()
    analysis = engine.full_analysis(domains, org_name)

    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()
    build_evidence_package(analysis, tmp.name, domains_obj=domains)
    background_tasks.add_task(os.unlink, tmp.name)

    safe_name = org_name.replace(" ", "_").replace("/", "_")[:40]
    return FileResponse(
        tmp.name,
        media_type="application/zip",
        filename=f"compass_evidence_{safe_name}.zip",
    )


@app.get("/api/compare/{id_a}/{id_b}")
def compare(id_a: int, id_b: int, tenant: dict = Depends(_resolve_tenant)):
    """Compare deux assessments du tenant et retourne le delta."""
    try:
        return compare_assessments(id_a, id_b, tenant_id=tenant["id"])
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


