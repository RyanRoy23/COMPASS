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
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.background import BackgroundTasks
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

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
from nis2_analyzer.reporting.evidence_package import build_evidence_package
from nis2_analyzer.core.incident_notification import (
    classify_incident, compute_deadlines,
    assess_notification_maturity, get_notification_questions_schema,
    SignificanceCriteria,
)
from nis2_analyzer.core.supply_chain import (
    assess_supplier, assess_supplier_portfolio,
    assess_supply_chain_maturity, get_supply_chain_questions_schema,
    SupplierProfile, AccessLevel, DataSensitivity, SupplierCriticality,
)
from nis2_analyzer.core.monte_carlo import MonteCarloEngine
from nis2_analyzer.core.aws_connector import AWSConnector
from nis2_analyzer.core.m365_connector import M365Connector
from nis2_analyzer.core.mitre_mapping import compute_mitre_mapping
from nis2_analyzer.core.regulatory_export import build_regulatory_report
from nis2_analyzer.core.financial import OrganizationProfile, OrgSize, Sector
from nis2_analyzer.core.sector_profiles import (
    get_sector_profile, apply_sector_weights, get_sector_report, SECTOR_PROFILES
)
from nis2_analyzer.core.sme_mode import (
    get_sme_schema, compute_sme_score, sme_responses_to_nis2, SME_QUESTIONS
)
from nis2_analyzer.reporting.pdf_report import generate_pdf_report
from nis2_analyzer.reporting.templates import (
    generate_pssi, generate_notification_procedure, generate_asset_register,
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
    sector: str = Field("autre", description="Secteur NIS 2 pour pondération sectorielle")


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


class QualifyRequest(BaseModel):
    org_name: str = Field("Organisation", min_length=1, max_length=200)
    sector: str = Field(..., description=f"Clé de secteur parmi : {', '.join(ALL_SECTORS)}")
    employees: int = Field(0, ge=0, description="Nombre de salariés")
    annual_revenue_eur: float = Field(0.0, ge=0, description="CA annuel en euros")
    is_critical_infrastructure: bool = Field(False)
    provides_essential_digital_service: bool = Field(False)


class MonteCarloRequest(BaseModel):
    org_name: str = Field("Organisation", min_length=1, max_length=200)
    responses: dict[str, int] = Field(..., description="Mapping requirement_id → maturity (0-3)")
    org_size: str = Field("eti", description="'pme' | 'eti' | 'grand'")
    sector: str = Field("autre", description="Secteur de l'organisation")
    annual_revenue_eur: float = Field(0.0, ge=0)
    n_simulations: int = Field(10_000, ge=1_000, le=50_000)


class SMEAssessRequest(BaseModel):
    org_name: str = Field("Mon entreprise", min_length=1, max_length=200)
    responses: dict[str, int] = Field(..., description="Mapping PME-XX → niveau (0-3)")
    sector: str = Field("autre")
    include_nis2_detail: bool = Field(True, description="Inclure la conversion en scoring NIS 2 complet")


class AWSAuditRequest(BaseModel):
    region: str = Field("eu-west-1", description="Région AWS à auditer")
    demo_mode: bool = Field(True, description="Mode démonstration sans credentials AWS")
    # Credentials optionnels (non recommandés — préférer IAM roles)
    aws_access_key_id: Optional[str] = Field(None)
    aws_secret_access_key: Optional[str] = Field(None)
    aws_session_token: Optional[str] = Field(None)


class M365AuditRequest(BaseModel):
    tenant_name: str = Field("Mon Organisation", min_length=1, max_length=200)
    demo_mode: bool = Field(True, description="Mode démonstration sans token Graph API")
    access_token: Optional[str] = Field(None, description="Token OAuth2 Microsoft Graph (scope: Directory.Read.All, Policy.Read.All, AuditLog.Read.All)")
    azure_tenant_id: Optional[str] = Field(None, description="ID du tenant Azure AD")


class TenantCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, description="Nom de l'organisation")
    slug: str = Field(..., min_length=2, max_length=60, pattern=r"^[a-z0-9\-]+$",
                      description="Identifiant unique (lettres minuscules, chiffres, tirets)")
    plan: str = Field("free", description="'free' | 'pro'")


# ── Authentification multi-tenant ─────────────────────────────────────────────

def _resolve_tenant(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> dict:
    """
    Dépendance FastAPI : résout la clé API → tenant.
    Sans clé = tenant 'default' (compatibilité mono-tenant).
    """
    if not x_api_key:
        return {"id": get_default_tenant_id(), "slug": "default", "name": "Default", "plan": "free"}
    tenant = get_tenant_by_key(x_api_key)
    if tenant is None:
        raise HTTPException(status_code=401, detail="Clé API invalide.")
    return tenant


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


@app.get("/api/sector-profiles")
def get_sector_profiles_list():
    """Retourne la liste des profils sectoriels disponibles."""
    return {
        "sectors": [
            {
                "id": p.sector_id,
                "label": p.sector_label,
                "priority_requirements_count": len(p.priority_requirements),
                "specific_controls_count": len(p.specific_controls),
                "regulatory_context": p.regulatory_context,
                "key_threats": p.key_threats,
                "priority_requirements": p.priority_requirements,
                "specific_controls": p.specific_controls,
            }
            for p in SECTOR_PROFILES.values()
        ]
    }


@app.get("/api/sme/questions")
def get_sme_questions():
    """Retourne les 15 questions du mode PME en langage non-technique."""
    return {"questions": get_sme_schema(), "total": len(SME_QUESTIONS)}


@app.post("/api/sme/assess", status_code=200)
def sme_assess(body: SMEAssessRequest):
    """
    Évalue une PME à partir des 15 questions simplifiées.

    Retourne :
    - Score PME simplifié (0-100) avec grade
    - Points faibles et points forts
    - Priorité d'action numéro 1
    - Si include_nis2_detail : scoring NIS 2 complet via conversion automatique
    """
    valid_ids = {q.id for q in SME_QUESTIONS}
    for qid, lvl in body.responses.items():
        if qid not in valid_ids:
            raise HTTPException(status_code=422, detail=f"Question inconnue : {qid}. Utilisez PME-01 à PME-15.")
        if lvl not in (0, 1, 2, 3):
            raise HTTPException(status_code=422, detail=f"Niveau invalide pour {qid} : {lvl}. Valeurs : 0, 1, 2, 3.")

    if not body.responses:
        raise HTTPException(status_code=422, detail="Aucune réponse fournie.")

    # Score PME simplifié
    sme_result = compute_sme_score(body.responses)
    sme_result["org_name"] = html.escape(body.org_name.strip())
    sme_result["sector"] = body.sector

    result = {"sme_assessment": sme_result}

    # Optionnel : scoring NIS 2 complet
    if body.include_nis2_detail:
        nis2_responses = sme_responses_to_nis2(body.responses)
        domains = load_framework()
        sector_id = body.sector if body.sector in SECTOR_PROFILES else "autre"
        apply_sector_weights(domains, sector_id)
        for domain in domains:
            for req in domain.sub_requirements:
                if req.id in nis2_responses:
                    req.maturity = MaturityLevel(nis2_responses[req.id])
        engine = ScoringEngine()
        analysis = engine.full_analysis(domains, html.escape(body.org_name.strip()))
        analysis["sector_report"] = get_sector_report(sector_id, analysis)
        result["nis2_detail"] = analysis
        result["nis2_responses_inferred"] = nis2_responses

    return result


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


@app.post("/api/tenants", status_code=201)
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


@app.post("/api/assess", status_code=201)
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

    # Appliquer les pondérations sectorielles avant le scoring
    sector_id = body.sector if body.sector in SECTOR_PROFILES else "autre"
    apply_sector_weights(domains, sector_id)

    engine = ScoringEngine()
    analysis = engine.full_analysis(domains, org_name)
    assessment_id = save_assessment(analysis, tenant_id=tenant["id"])
    analysis["assessment_id"] = assessment_id

    # Ajouter le rapport sectoriel
    analysis["sector_report"] = get_sector_report(sector_id, analysis)

    return analysis


@app.post("/api/monte-carlo", status_code=200)
def run_monte_carlo(body: MonteCarloRequest):
    """
    Lance une simulation Monte Carlo (10 000 scénarios par défaut).
    Retourne la distribution de la perte annuelle totale avec percentiles.
    """
    _ALLOWED_SIZES = ("pme", "eti", "grand")
    if body.org_size not in _ALLOWED_SIZES:
        raise HTTPException(status_code=422, detail=f"org_size invalide. Valeurs : {_ALLOWED_SIZES}")

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
        raise HTTPException(status_code=422, detail="Aucune réponse valide fournie.")

    size_map = {"pme": OrgSize.PME, "eti": OrgSize.ETI, "grand": OrgSize.GRAND_GROUPE}
    sector_map = {s.value: s for s in Sector}
    sector = sector_map.get(body.sector, Sector.AUTRE)

    profile = OrganizationProfile(
        name=html.escape(body.org_name.strip()),
        size=size_map[body.org_size],
        sector=sector,
        annual_revenue=body.annual_revenue_eur if body.annual_revenue_eur > 0 else None,
    )

    engine = MonteCarloEngine(profile=profile, n_simulations=body.n_simulations)
    report = engine.simulate(domains)
    return report.to_dict()


@app.post("/api/aws-audit", status_code=200)
def run_aws_audit(body: AWSAuditRequest):
    """
    Audite les contrôles de sécurité AWS et les mappe aux exigences NIS 2.

    En mode demo_mode=true, retourne un rapport réaliste sans credentials AWS.
    En mode réel, passe les credentials ou utilise le profil AWS local.
    """
    if body.demo_mode:
        connector = AWSConnector(demo_mode=True)
        return connector.audit(region=body.region).to_dict()

    # Mode réel : credentials optionnels (IAM role recommandé)
    try:
        import boto3
        session_kwargs: dict = {"region_name": body.region}
        if body.aws_access_key_id and body.aws_secret_access_key:
            session_kwargs["aws_access_key_id"] = body.aws_access_key_id
            session_kwargs["aws_secret_access_key"] = body.aws_secret_access_key
            if body.aws_session_token:
                session_kwargs["aws_session_token"] = body.aws_session_token
        session = boto3.Session(**session_kwargs)
        connector = AWSConnector(session=session, demo_mode=False)
        return connector.audit(region=body.region).to_dict()
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="boto3 non installé. Ajoutez boto3 aux dépendances ou utilisez demo_mode=true.",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur AWS : {str(e)}")



@app.post("/api/m365-audit", status_code=200)
def run_m365_audit(body: M365AuditRequest):
    """
    Audite les contrôles de sécurité Microsoft 365 / Azure AD et les mappe aux exigences NIS 2.
    En mode demo_mode=true, retourne un rapport réaliste sans credentials.
    """
    if body.demo_mode:
        connector = M365Connector(demo_mode=True)
        return connector.audit(tenant_name=html.escape(body.tenant_name.strip())).to_dict()
    if not body.access_token:
        raise HTTPException(
            status_code=422,
            detail="Un access_token Microsoft Graph est requis pour le mode réel. Utilisez demo_mode=true pour tester.",
        )
    try:
        connector = M365Connector(
            demo_mode=False,
            access_token=body.access_token,
            tenant_id=body.azure_tenant_id,
        )
        return connector.audit(tenant_name=html.escape(body.tenant_name.strip())).to_dict()
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur Microsoft Graph : {str(e)}")

@app.get("/api/regulatory-export/{assessment_id}")
def get_regulatory_export(assessment_id: int, tenant: dict = Depends(_resolve_tenant)):
    """
    Génère le rapport réglementaire NIS2 Art. 21 structuré (JSON normalisé).
    Utilisable pour soumission ANSSI ou audit externe.
    """
    result = get_assessment(assessment_id, tenant_id=tenant["id"])
    if result is None:
        raise HTTPException(status_code=404, detail=f"Assessment #{assessment_id} introuvable.")
    try:
        report = build_regulatory_report(result["payload"], assessment_id)
        return report.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur export réglementaire : {str(e)}")


@app.get("/api/mitre-mapping/{assessment_id}")
def get_mitre_mapping(assessment_id: int, tenant: dict = Depends(_resolve_tenant)):
    """
    Retourne le mapping MITRE ATT&CK pour un assessment existant.
    Lie chaque gap NIS2 aux techniques d'attaque MITRE correspondantes.
    """
    result = get_assessment(assessment_id, tenant_id=tenant["id"])
    if result is None:
        raise HTTPException(status_code=404, detail=f"Assessment #{assessment_id} introuvable.")
    try:
        report = compute_mitre_mapping(result["payload"], only_gaps=True)
        return report.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur mapping MITRE : {str(e)}")


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


def _build_assessment_from_request(body: AssessmentRequest) -> tuple:
    """Shared helper: load framework, apply responses, return (engine, assessment, org_name)."""
    org_name = html.escape(body.org_name.strip())
    for req_id, value in body.responses.items():
        if value not in (0, 1, 2, 3):
            raise HTTPException(status_code=422, detail=f"Maturité invalide pour {req_id} : {value}.")
    domains = load_framework()
    if body.sector:
        apply_sector_weights(domains, body.sector)
    answered = 0
    for domain in domains:
        for req in domain.sub_requirements:
            if req.id in body.responses:
                req.maturity = MaturityLevel(body.responses[req.id])
                answered += 1
    if answered == 0:
        raise HTTPException(status_code=422, detail="Aucune réponse valide fournie.")
    engine = ScoringEngine()
    return engine, engine.calculate(domains, org_name), org_name


def _template_response(
    buf,
    background_tasks: BackgroundTasks,
    org_name: str,
    slug: str,
) -> FileResponse:
    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    tmp.write(buf.read())
    tmp.close()
    background_tasks.add_task(os.unlink, tmp.name)
    safe = org_name.replace(" ", "_").replace("/", "_")[:40]
    fname = f"compass_{slug}_{safe}.pdf"
    return FileResponse(tmp.name, media_type="application/pdf", filename=fname,
                        headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.post("/api/templates/pssi")
def api_template_pssi(body: AssessmentRequest, background_tasks: BackgroundTasks):
    """Génère une PSSI simplifiée pré-remplie depuis l'évaluation NIS 2."""
    _, assessment, org_name = _build_assessment_from_request(body)
    return _template_response(generate_pssi(assessment), background_tasks, org_name, "pssi")


@app.post("/api/templates/notification")
def api_template_notification(body: AssessmentRequest, background_tasks: BackgroundTasks):
    """Génère la procédure de notification NIS 2 Art. 23 pré-remplie."""
    _, assessment, org_name = _build_assessment_from_request(body)
    return _template_response(generate_notification_procedure(assessment), background_tasks, org_name, "notification")


@app.post("/api/templates/assets")
def api_template_assets(body: AssessmentRequest, background_tasks: BackgroundTasks):
    """Génère le registre des actifs critiques pré-rempli depuis les gaps identifiés."""
    _, assessment, org_name = _build_assessment_from_request(body)
    return _template_response(generate_asset_register(assessment), background_tasks, org_name, "actifs")


@app.get("/api/compare/{id_a}/{id_b}")
def compare(id_a: int, id_b: int, tenant: dict = Depends(_resolve_tenant)):
    """Compare deux assessments du tenant et retourne le delta."""
    try:
        return compare_assessments(id_a, id_b, tenant_id=tenant["id"])
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/pdf-report")
def api_pdf_report(body: AssessmentRequest, background_tasks: BackgroundTasks):
    """
    Génère un rapport PDF professionnel à partir des réponses au questionnaire.
    Retourne le fichier PDF en téléchargement direct.
    """
    org_name = html.escape(body.org_name.strip())

    for req_id, value in body.responses.items():
        if value not in (0, 1, 2, 3):
            raise HTTPException(
                status_code=422,
                detail=f"Maturité invalide pour {req_id} : {value}."
            )

    domains = load_framework()
    if body.sector:
        apply_sector_weights(domains, body.sector)

    answered = 0
    for domain in domains:
        for req in domain.sub_requirements:
            if req.id in body.responses:
                req.maturity = MaturityLevel(body.responses[req.id])
                answered += 1

    if answered == 0:
        raise HTTPException(status_code=422, detail="Aucune réponse valide fournie.")

    engine = ScoringEngine()
    assessment = engine.calculate(domains, org_name)

    # Label lisible du secteur
    sector_label = "Non précisé"
    if body.sector:
        from nis2_analyzer.core.sector_profiles import get_sector_profile
        sector_label = get_sector_profile(body.sector).sector_label

    pdf_buffer = generate_pdf_report(assessment, sector=sector_label)

    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    tmp.write(pdf_buffer.read())
    tmp.close()
    background_tasks.add_task(os.unlink, tmp.name)

    safe_name = org_name.replace(" ", "_").replace("/", "_")[:40]
    return FileResponse(
        tmp.name,
        media_type="application/pdf",
        filename=f"compass_rapport_{safe_name}.pdf",
        headers={"Content-Disposition": f'attachment; filename="compass_rapport_{safe_name}.pdf"'},
    )
