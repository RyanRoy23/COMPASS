"""
COMPASS — Connecteur Microsoft 365 / Azure AD Security Audit

Audite automatiquement les contrôles de sécurité M365 et les mappe
aux exigences NIS 2 Art. 21.

Contrôles couverts :
  Azure AD    → NIS2-D10 (MFA, authentification forte)
                NIS2-D09 (contrôle d'accès, comptes privilégiés)
                NIS2-D07 (formation, sensibilisation)
  Conditional Access → NIS2-D10, NIS2-D09
  PIM         → NIS2-D09 (comptes à privilèges, moindre privilège)
  Audit Logs  → NIS2-D02 (détection, journalisation)
  Defender 365 → NIS2-D02 (capacités de détection), NIS2-D03 (incidents)
  DLP / Info Protection → NIS2-D08 (protection des données)
  External Sharing → NIS2-D04 (supply chain, accès tiers)
  Device Compliance → NIS2-D05 (continuité, gestion des actifs)
  Password Policy → NIS2-D10 (authentification)
  Security Score → NIS2-D06 (évaluation de l'efficacité)

Résultat : un mapping requirement_id → niveau de maturité (0-3)
utilisable directement par l'évaluateur COMPASS.

En mode réel, utilise la Microsoft Graph API (token OAuth2 / Service Principal).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ── Structures de résultat ────────────────────────────────────────────────────

@dataclass
class M365Finding:
    """Un contrôle de sécurité M365 audité avec son résultat."""
    control_id: str           # ex. "AAD-001"
    title: str
    requirement_id: str       # ex. "NIS2-D10-R01"
    category: str             # "Azure AD" | "Defender" | "DLP" | "Device" | ...
    status: str               # "PASS" | "FAIL" | "WARN" | "INFO"
    severity: str             # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    detail: str
    resource: str = ""
    recommended_action: str = ""
    graph_api_endpoint: str = "" # endpoint Graph API correspondant (documentation)


@dataclass
class M365AuditReport:
    """Rapport complet de l'audit Microsoft 365."""
    tenant_id: str
    tenant_name: str
    findings: list[M365Finding]
    maturity_mapping: dict[str, int]  # requirement_id → maturity (0-3)
    security_score: float             # Microsoft Secure Score (0-100)
    total_controls: int
    passed: int
    failed: int
    warnings: int
    critical_findings: list[M365Finding]

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "tenant_name": self.tenant_name,
            "security_score": self.security_score,
            "summary": {
                "total_controls": self.total_controls,
                "passed": self.passed,
                "failed": self.failed,
                "warnings": self.warnings,
                "critical_count": len(self.critical_findings),
            },
            "maturity_mapping": self.maturity_mapping,
            "findings": [
                {
                    "control_id": f.control_id,
                    "title": f.title,
                    "requirement_id": f.requirement_id,
                    "category": f.category,
                    "status": f.status,
                    "severity": f.severity,
                    "detail": f.detail,
                    "resource": f.resource,
                    "recommended_action": f.recommended_action,
                    "graph_api_endpoint": f.graph_api_endpoint,
                }
                for f in self.findings
            ],
            "critical_findings": [
                {
                    "control_id": f.control_id,
                    "title": f.title,
                    "severity": f.severity,
                    "detail": f.detail,
                    "recommended_action": f.recommended_action,
                }
                for f in self.critical_findings
            ],
        }


# ── Moteur d'audit ────────────────────────────────────────────────────────────

class M365Connector:
    """
    Connecteur Microsoft 365 / Azure AD.

    demo_mode=True  → résultats réalistes sans credentials (présentation, tests)
    demo_mode=False → appels réels à Microsoft Graph API
    """

    def __init__(
        self,
        demo_mode: bool = True,
        access_token: str | None = None,
        tenant_id: str | None = None,
    ):
        self.demo_mode = demo_mode
        self.access_token = access_token
        self._tenant_id = tenant_id or "xxxxxxxx-demo-xxxx-xxxx-xxxxxxxxxxxx"

    def audit(self, tenant_name: str = "Contoso Ltd.") -> M365AuditReport:
        if self.demo_mode:
            return self._demo_audit(tenant_name)
        return self._real_audit(tenant_name)

    # ── Mode démonstration ────────────────────────────────────────────────────

    def _demo_audit(self, tenant_name: str) -> M365AuditReport:
        """Rapport réaliste basé sur des données typiques d'un tenant M365 moyen."""
        findings = self._build_demo_findings()
        return self._build_report(self._tenant_id, tenant_name, findings, security_score=54.0)

    def _build_demo_findings(self) -> list[M365Finding]:
        return [
            # ── Azure AD / Authentification ───────────────────────────────────
            M365Finding(
                control_id="AAD-001",
                title="MFA obligatoire pour tous les utilisateurs",
                requirement_id="NIS2-D10-R01",
                category="Azure AD",
                status="FAIL",
                severity="CRITICAL",
                detail="47 % des utilisateurs n'ont pas MFA activé. 12 comptes administrateurs sans MFA détectés.",
                resource="Azure AD Users",
                recommended_action="Activer une politique d'accès conditionnel forçant MFA pour tous les utilisateurs et comptes admin.",
                graph_api_endpoint="GET /reports/authenticationMethods/userRegistrationDetails",
            ),
            M365Finding(
                control_id="AAD-002",
                title="Politique de mots de passe complexe",
                requirement_id="NIS2-D10-R01",
                category="Azure AD",
                status="PASS",
                severity="MEDIUM",
                detail="Politique de mots de passe Azure AD conforme : longueur minimale 12 caractères, complexité activée, historique 10 mots de passe.",
                resource="Azure AD Password Policy",
                recommended_action="",
                graph_api_endpoint="GET /domains/{id}",
            ),
            M365Finding(
                control_id="AAD-003",
                title="Comptes invités (Guest) limités",
                requirement_id="NIS2-D04-R01",
                category="Azure AD",
                status="WARN",
                severity="HIGH",
                detail="234 comptes invités actifs dont 89 sans activité depuis plus de 90 jours.",
                resource="Azure AD Guest Accounts",
                recommended_action="Mettre en place une révision périodique des comptes invités et supprimer les comptes inactifs.",
                graph_api_endpoint="GET /users?$filter=userType eq 'Guest'",
            ),
            M365Finding(
                control_id="AAD-004",
                title="Protection des identités (Identity Protection)",
                requirement_id="NIS2-D02-R01",
                category="Azure AD",
                status="PASS",
                severity="HIGH",
                detail="Azure AD Identity Protection activé. Politique de risque utilisateur configurée pour bloquer à risque élevé.",
                resource="Azure AD Identity Protection",
                recommended_action="",
                graph_api_endpoint="GET /identityProtection/riskDetections",
            ),

            # ── Accès Conditionnel ────────────────────────────────────────────
            M365Finding(
                control_id="CAP-001",
                title="Politiques d'accès conditionnel actives",
                requirement_id="NIS2-D10-R02",
                category="Conditional Access",
                status="WARN",
                severity="HIGH",
                detail="3 politiques d'accès conditionnel actives, mais aucune ne couvre les appareils non conformes (mode audit uniquement).",
                resource="Conditional Access Policies",
                recommended_action="Passer les politiques du mode audit au mode blocage et ajouter une condition de conformité des appareils.",
                graph_api_endpoint="GET /identity/conditionalAccess/policies",
            ),
            M365Finding(
                control_id="CAP-002",
                title="Blocage des protocoles d'authentification hérités (Legacy Auth)",
                requirement_id="NIS2-D10-R01",
                category="Conditional Access",
                status="FAIL",
                severity="CRITICAL",
                detail="Les protocoles d'authentification hérités (Basic Auth, POP, IMAP) ne sont pas bloqués. Ces protocoles contournent MFA.",
                resource="Conditional Access — Legacy Auth Block",
                recommended_action="Créer une politique d'accès conditionnel bloquant tous les protocoles d'authentification hérités.",
                graph_api_endpoint="GET /identity/conditionalAccess/policies",
            ),

            # ── PIM — Privileged Identity Management ──────────────────────────
            M365Finding(
                control_id="PIM-001",
                title="PIM activé pour les rôles privilégiés",
                requirement_id="NIS2-D09-R01",
                category="Privileged Identity Management",
                status="FAIL",
                severity="CRITICAL",
                detail="Privileged Identity Management (PIM) non configuré. 8 comptes avec rôle Global Administrator permanent détectés.",
                resource="Azure AD PIM",
                recommended_action="Activer PIM, convertir les attributions permanentes en attributions éligibles avec approbation et durée limitée.",
                graph_api_endpoint="GET /privilegedAccess/aadRoles/resources",
            ),
            M365Finding(
                control_id="PIM-002",
                title="Révision d'accès (Access Reviews) planifiée",
                requirement_id="NIS2-D09-R02",
                category="Privileged Identity Management",
                status="FAIL",
                severity="HIGH",
                detail="Aucune révision d'accès planifiée pour les rôles privilégiés. Principe du moindre privilège non vérifié périodiquement.",
                resource="Azure AD Access Reviews",
                recommended_action="Configurer des révisions d'accès trimestrielles pour tous les rôles à privilèges élevés.",
                graph_api_endpoint="GET /identityGovernance/accessReviews/definitions",
            ),

            # ── Journalisation / Audit Logs ───────────────────────────────────
            M365Finding(
                control_id="LOG-001",
                title="Journaux d'audit Azure AD activés",
                requirement_id="NIS2-D02-R02",
                category="Audit Logs",
                status="PASS",
                severity="HIGH",
                detail="Journaux d'audit Azure AD activés et configurés pour une rétention de 90 jours (P1/P2).",
                resource="Azure AD Audit Logs",
                recommended_action="",
                graph_api_endpoint="GET /auditLogs/directoryAudits",
            ),
            M365Finding(
                control_id="LOG-002",
                title="Journaux de connexion exportés vers SIEM",
                requirement_id="NIS2-D02-R02",
                category="Audit Logs",
                status="WARN",
                severity="MEDIUM",
                detail="Les journaux de connexion ne sont pas exportés vers un SIEM externe. Analyse centralisée absente.",
                resource="Azure AD Sign-in Logs",
                recommended_action="Configurer les paramètres de diagnostic Azure AD pour exporter vers Log Analytics / Microsoft Sentinel.",
                graph_api_endpoint="GET /auditLogs/signIns",
            ),

            # ── Microsoft Defender for Office 365 ────────────────────────────
            M365Finding(
                control_id="DEF-001",
                title="Defender for Office 365 Plan 2 actif",
                requirement_id="NIS2-D02-R01",
                category="Microsoft Defender",
                status="PASS",
                severity="HIGH",
                detail="Microsoft Defender for Office 365 Plan 2 activé avec Safe Links, Safe Attachments et Anti-phishing configurés.",
                resource="Microsoft Defender for Office 365",
                recommended_action="",
                graph_api_endpoint="GET /security/secureScoreControlProfiles",
            ),
            M365Finding(
                control_id="DEF-002",
                title="Defender for Endpoint connecté (MDI)",
                requirement_id="NIS2-D02-R01",
                category="Microsoft Defender",
                status="WARN",
                severity="MEDIUM",
                detail="Microsoft Defender for Identity (MDI) configuré mais couverture partielle : 60 % des contrôleurs de domaine couverts.",
                resource="Microsoft Defender for Identity",
                recommended_action="Déployer le capteur MDI sur les contrôleurs de domaine manquants.",
                graph_api_endpoint="GET /security/alerts",
            ),

            # ── DLP — Data Loss Prevention ────────────────────────────────────
            M365Finding(
                control_id="DLP-001",
                title="Politiques DLP actives",
                requirement_id="NIS2-D08-R01",
                category="Data Loss Prevention",
                status="WARN",
                severity="HIGH",
                detail="2 politiques DLP configurées en mode audit. Aucune politique en mode blocage actif pour les données sensibles.",
                resource="Microsoft Purview DLP",
                recommended_action="Passer les politiques DLP du mode simulation au mode blocage pour les données classifiées Confidentiel et Secret.",
                graph_api_endpoint="GET /compliance/ediscovery/cases",
            ),
            M365Finding(
                control_id="DLP-002",
                title="Étiquettes de sensibilité (Sensitivity Labels) déployées",
                requirement_id="NIS2-D08-R02",
                category="Data Loss Prevention",
                status="FAIL",
                severity="HIGH",
                detail="Aucune étiquette de sensibilité déployée. La classification des données est manuelle et non cohérente.",
                resource="Microsoft Purview Information Protection",
                recommended_action="Créer et publier des étiquettes de sensibilité (Public, Interne, Confidentiel, Secret) avec chiffrement automatique.",
                graph_api_endpoint="GET /informationProtection/sensitivityLabels",
            ),

            # ── Conformité des appareils ──────────────────────────────────────
            M365Finding(
                control_id="DEV-001",
                title="Politiques de conformité Intune déployées",
                requirement_id="NIS2-D05-R02",
                category="Device Compliance",
                status="PASS",
                severity="MEDIUM",
                detail="Microsoft Intune déployé avec politiques de conformité actives. 78 % des appareils conformes.",
                resource="Microsoft Intune",
                recommended_action="Traiter les 22 % d'appareils non conformes et configurer l'accès conditionnel basé sur la conformité.",
                graph_api_endpoint="GET /deviceManagement/managedDevices",
            ),
            M365Finding(
                control_id="DEV-002",
                title="Chiffrement des appareils (BitLocker) activé",
                requirement_id="NIS2-D08-R01",
                category="Device Compliance",
                status="WARN",
                severity="HIGH",
                detail="BitLocker activé sur 65 % des appareils Windows. 35 % des postes sans chiffrement de disque.",
                resource="BitLocker — Microsoft Intune",
                recommended_action="Déployer une politique Intune forçant l'activation de BitLocker sur tous les appareils Windows gérés.",
                graph_api_endpoint="GET /deviceManagement/managedDevices?$filter=operatingSystem eq 'Windows'",
            ),

            # ── Partage externe ───────────────────────────────────────────────
            M365Finding(
                control_id="EXT-001",
                title="Partage externe SharePoint / Teams restreint",
                requirement_id="NIS2-D04-R02",
                category="External Sharing",
                status="FAIL",
                severity="HIGH",
                detail="Le partage externe dans SharePoint et Teams est configuré sur 'Tout le monde' (Anyone). Aucune restriction sur les liens anonymes.",
                resource="SharePoint / Teams External Sharing",
                recommended_action="Restreindre le partage externe aux domaines autorisés uniquement. Désactiver les liens 'Anyone'.",
                graph_api_endpoint="GET /admin/sharepoint/settings",
            ),

            # ── Secure Score ──────────────────────────────────────────────────
            M365Finding(
                control_id="SEC-001",
                title="Microsoft Secure Score",
                requirement_id="NIS2-D06-R01",
                category="Security Score",
                status="WARN",
                severity="MEDIUM",
                detail="Microsoft Secure Score : 54/100. Score moyen pour un tenant M365. 23 actions d'amélioration disponibles.",
                resource="Microsoft 365 Defender — Secure Score",
                recommended_action="Traiter en priorité les actions à impact élevé : MFA, Legacy Auth, PIM, Sensitivity Labels.",
                graph_api_endpoint="GET /security/secureScores",
            ),
        ]

    # ── Calcul des maturités ──────────────────────────────────────────────────

    def _build_report(
        self,
        tenant_id: str,
        tenant_name: str,
        findings: list[M365Finding],
        security_score: float,
    ) -> M365AuditReport:
        maturity = self._compute_maturity(findings)
        passed = sum(1 for f in findings if f.status == "PASS")
        failed = sum(1 for f in findings if f.status == "FAIL")
        warnings = sum(1 for f in findings if f.status == "WARN")
        critical = [f for f in findings if f.severity == "CRITICAL" and f.status == "FAIL"]

        return M365AuditReport(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            findings=findings,
            maturity_mapping=maturity,
            security_score=security_score,
            total_controls=len(findings),
            passed=passed,
            failed=failed,
            warnings=warnings,
            critical_findings=critical,
        )

    def _compute_maturity(self, findings: list[M365Finding]) -> dict[str, int]:
        """
        Agrège les findings par requirement_id → niveau de maturité (0-3).

        PASS  → contribue positivement
        WARN  → maturité partielle
        FAIL  → bloque la maturité du requirement
        """
        req_findings: dict[str, list[M365Finding]] = {}
        for f in findings:
            req_findings.setdefault(f.requirement_id, []).append(f)

        maturity: dict[str, int] = {}
        for req_id, reqs in req_findings.items():
            has_critical_fail = any(
                f.status == "FAIL" and f.severity == "CRITICAL" for f in reqs
            )
            has_fail = any(f.status == "FAIL" for f in reqs)
            has_warn = any(f.status == "WARN" for f in reqs)
            all_pass = all(f.status == "PASS" for f in reqs)

            if has_critical_fail:
                maturity[req_id] = 0
            elif has_fail:
                maturity[req_id] = 1
            elif has_warn:
                maturity[req_id] = 2
            else:  # all_pass
                maturity[req_id] = 3

        return maturity

    # ── Mode réel (Microsoft Graph API) ──────────────────────────────────────

    def _real_audit(self, tenant_name: str) -> M365AuditReport:
        """
        Audit réel via Microsoft Graph API.
        Nécessite un access_token avec les permissions :
          - Directory.Read.All
          - Policy.Read.All
          - AuditLog.Read.All
          - SecurityEvents.Read.All
          - DeviceManagementManagedDevices.Read.All
        """
        try:
            import requests
        except ImportError:
            raise RuntimeError(
                "Le package 'requests' est requis pour l'audit M365 réel. "
                "Installez-le avec : pip install requests"
            )

        if not self.access_token:
            raise ValueError(
                "Un access_token Microsoft Graph est requis pour l'audit réel. "
                "Utilisez demo_mode=True pour tester sans credentials."
            )

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }
        base = "https://graph.microsoft.com/v1.0"

        def _get(path: str) -> dict:
            r = requests.get(f"{base}{path}", headers=headers, timeout=15)
            r.raise_for_status()
            return r.json()

        findings: list[M365Finding] = []

        # MFA registration
        try:
            reg = _get("/reports/authenticationMethods/userRegistrationDetails")
            users = reg.get("value", [])
            no_mfa = [u for u in users if not u.get("isMfaRegistered", False)]
            mfa_pct = round((1 - len(no_mfa) / max(len(users), 1)) * 100)
            if mfa_pct < 80:
                findings.append(M365Finding(
                    control_id="AAD-001", title="MFA obligatoire pour tous les utilisateurs",
                    requirement_id="NIS2-D10-R01", category="Azure AD",
                    status="FAIL" if mfa_pct < 50 else "WARN",
                    severity="CRITICAL" if mfa_pct < 50 else "HIGH",
                    detail=f"{100 - mfa_pct}% des utilisateurs sans MFA ({len(no_mfa)} comptes).",
                    recommended_action="Activer une politique d'accès conditionnel forçant MFA.",
                    graph_api_endpoint="/reports/authenticationMethods/userRegistrationDetails",
                ))
            else:
                findings.append(M365Finding(
                    control_id="AAD-001", title="MFA obligatoire pour tous les utilisateurs",
                    requirement_id="NIS2-D10-R01", category="Azure AD",
                    status="PASS", severity="MEDIUM",
                    detail=f"MFA activé pour {mfa_pct}% des utilisateurs.",
                    graph_api_endpoint="/reports/authenticationMethods/userRegistrationDetails",
                ))
        except Exception as e:
            findings.append(M365Finding(
                control_id="AAD-001", title="MFA — données non accessibles",
                requirement_id="NIS2-D10-R01", category="Azure AD",
                status="WARN", severity="HIGH",
                detail=f"Impossible de lire les données MFA : {e}. Permission manquante ?",
                recommended_action="Vérifiez les permissions : Reports.Read.All ou Directory.Read.All",
                graph_api_endpoint="/reports/authenticationMethods/userRegistrationDetails",
            ))

        # Conditional Access policies
        try:
            caps = _get("/identity/conditionalAccess/policies")
            policies = caps.get("value", [])
            enabled = [p for p in policies if p.get("state") == "enabled"]
            legacy_block = any(
                "block" in str(p.get("grantControls", {})).lower() and
                "legacyAuthentication" in str(p.get("conditions", {}))
                for p in enabled
            )
            if not legacy_block:
                findings.append(M365Finding(
                    control_id="CAP-002",
                    title="Blocage des protocoles d'authentification hérités",
                    requirement_id="NIS2-D10-R01", category="Conditional Access",
                    status="FAIL", severity="CRITICAL",
                    detail="Aucune politique d'accès conditionnel ne bloque les protocoles hérités.",
                    recommended_action="Créer une politique CA bloquant Basic Auth, POP, IMAP.",
                    graph_api_endpoint="/identity/conditionalAccess/policies",
                ))
            else:
                findings.append(M365Finding(
                    control_id="CAP-002",
                    title="Blocage des protocoles d'authentification hérités",
                    requirement_id="NIS2-D10-R01", category="Conditional Access",
                    status="PASS", severity="CRITICAL",
                    detail=f"{len(enabled)} politiques d'accès conditionnel actives dont le blocage legacy auth.",
                    graph_api_endpoint="/identity/conditionalAccess/policies",
                ))
        except Exception as e:
            findings.append(M365Finding(
                control_id="CAP-002",
                title="Conditional Access — données non accessibles",
                requirement_id="NIS2-D10-R01", category="Conditional Access",
                status="WARN", severity="HIGH",
                detail=f"Impossible de lire les politiques CA : {e}",
                recommended_action="Vérifiez les permissions : Policy.Read.All",
                graph_api_endpoint="/identity/conditionalAccess/policies",
            ))

        # Secure Score
        try:
            ss = _get("/security/secureScores?$top=1")
            scores = ss.get("value", [])
            if scores:
                score_val = scores[0].get("currentScore", 0)
                max_score = scores[0].get("maxScore", 100)
                pct = round(score_val / max_score * 100)
                status = "PASS" if pct >= 70 else ("WARN" if pct >= 40 else "FAIL")
                findings.append(M365Finding(
                    control_id="SEC-001", title="Microsoft Secure Score",
                    requirement_id="NIS2-D06-R01", category="Security Score",
                    status=status, severity="MEDIUM",
                    detail=f"Secure Score : {score_val:.0f}/{max_score:.0f} ({pct}%)",
                    recommended_action="" if pct >= 70 else "Traiter les actions d'amélioration à impact élevé.",
                    graph_api_endpoint="/security/secureScores",
                ))
                security_score = float(pct)
            else:
                security_score = 0.0
        except Exception:
            security_score = 0.0

        return self._build_report(self._tenant_id, tenant_name, findings, security_score)
