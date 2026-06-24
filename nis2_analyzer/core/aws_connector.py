"""
COMPASS — Connecteur AWS CloudSec Audit

Audite automatiquement les contrôles de sécurité AWS et les mappe
aux exigences NIS 2 Art. 21.

Contrôles couverts :
  IAM       → NIS2-D09 (contrôle d'accès, comptes à privilèges)
              NIS2-D10 (MFA, authentification forte)
  CloudTrail → NIS2-D02 (détection, journalisation)
               NIS2-D06 (audit de sécurité)
  Security Groups → NIS2-D01 (analyse des risques), NIS2-D09 (contrôle d'accès)
  S3         → NIS2-D08 (chiffrement), NIS2-D09 (gestion des actifs)
  KMS/Config → NIS2-D08 (cryptographie), NIS2-D06 (évaluation efficacité)
  GuardDuty  → NIS2-D02 (capacités de détection)

Résultat : un mapping requirement_id → niveau de maturité (0-3) basé sur
les configurations réelles, utilisable directement par l'évaluateur COMPASS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ── Structures de résultat ────────────────────────────────────────────────────

@dataclass
class AWSFinding:
    """Un contrôle de sécurité audité avec son résultat."""
    control_id: str          # ex. "IAM-001"
    title: str
    requirement_id: str      # ex. "NIS2-D10-R01"
    status: str              # "PASS" | "FAIL" | "WARN" | "INFO"
    severity: str            # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    detail: str              # Description du problème trouvé
    resource: str = ""       # ARN ou nom de la ressource concernée
    recommended_action: str = ""


@dataclass
class AWSAuditReport:
    """Rapport complet de l'audit AWS."""
    account_id: str
    region: str
    findings: list[AWSFinding]
    # Mapping calculé : requirement_id → maturity (0-3)
    maturity_mapping: dict[str, int]
    # Résumé
    total_controls: int
    passed: int
    failed: int
    warnings: int
    critical_findings: list[AWSFinding]

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "region": self.region,
            "summary": {
                "total_controls": self.total_controls,
                "passed": self.passed,
                "failed": self.failed,
                "warnings": self.warnings,
                "pass_rate": round(self.passed / max(self.total_controls, 1) * 100, 1),
            },
            "maturity_mapping": self.maturity_mapping,
            "critical_findings": [
                {
                    "control_id": f.control_id,
                    "title": f.title,
                    "requirement_id": f.requirement_id,
                    "severity": f.severity,
                    "detail": f.detail,
                    "resource": f.resource,
                    "recommended_action": f.recommended_action,
                }
                for f in self.critical_findings
            ],
            "all_findings": [
                {
                    "control_id": f.control_id,
                    "title": f.title,
                    "requirement_id": f.requirement_id,
                    "status": f.status,
                    "severity": f.severity,
                    "detail": f.detail,
                    "resource": f.resource,
                }
                for f in self.findings
            ],
        }


# ── Moteur d'audit AWS ────────────────────────────────────────────────────────

class AWSConnector:
    """
    Connecteur AWS pour l'audit de sécurité NIS 2.

    Usage :
        connector = AWSConnector(session=boto3.Session(...))
        report = connector.audit(region="eu-west-1")

    En mode démo (sans credentials AWS réels) :
        connector = AWSConnector(demo_mode=True)
        report = connector.audit()
    """

    # Mapping : un ensemble de findings → maturity level
    # Logique : PASS sur tous les contrôles d'un domaine → niveau 2 (implémenté)
    # Des contrôles de surveillance en place → niveau 3
    # Échecs critiques → niveau 0

    def __init__(self, session=None, demo_mode: bool = False):
        self._session = session
        self._demo_mode = demo_mode
        self._findings: list[AWSFinding] = []

    def audit(self, region: str = "eu-west-1") -> AWSAuditReport:
        """Lance l'audit complet et retourne le rapport."""
        self._findings = []

        if self._demo_mode:
            return self._demo_audit(region)

        # Audit réel via boto3
        try:
            import boto3
        except ImportError:
            raise ImportError(
                "boto3 est requis pour l'audit AWS. "
                "Installez-le avec : pip install boto3"
            )

        session = self._session or boto3.Session(region_name=region)
        account_id = self._get_account_id(session)

        self._audit_iam(session)
        self._audit_cloudtrail(session, region)
        self._audit_security_groups(session, region)
        self._audit_s3(session)
        self._audit_kms(session, region)
        self._audit_guardduty(session, region)
        self._audit_config(session, region)
        self._audit_password_policy(session)

        return self._build_report(account_id, region)

    # ── Audit IAM ─────────────────────────────────────────────────────────────

    def _audit_iam(self, session) -> None:
        iam = session.client("iam")

        # IAM-001 : MFA activé pour l'utilisateur root
        try:
            summary = iam.get_account_summary()["SummaryMap"]
            root_mfa = summary.get("AccountMFAEnabled", 0)
            self._findings.append(AWSFinding(
                control_id="IAM-001",
                title="MFA activé sur le compte root",
                requirement_id="NIS2-D10-R01",
                status="PASS" if root_mfa else "FAIL",
                severity="CRITICAL",
                detail="MFA est activé sur le compte root." if root_mfa
                       else "Le compte root n'a pas de MFA activé — risque critique de compromission.",
                resource="arn:aws:iam::root",
                recommended_action="" if root_mfa
                else "Activer MFA (clé physique recommandée) sur le compte root immédiatement.",
            ))
        except Exception as e:
            self._add_error("IAM-001", "NIS2-D10-R01", str(e))

        # IAM-002 : Clés d'accès root non utilisées
        try:
            cred_report = self._get_credential_report(iam)
            if cred_report:
                root_row = next((r for r in cred_report if r.get("user") == "<root_account>"), None)
                if root_row:
                    key1_active = root_row.get("access_key_1_active", "false") == "true"
                    key2_active = root_row.get("access_key_2_active", "false") == "true"
                    has_active_key = key1_active or key2_active
                    self._findings.append(AWSFinding(
                        control_id="IAM-002",
                        title="Clés d'accès root inactives",
                        requirement_id="NIS2-D09-R03",
                        status="FAIL" if has_active_key else "PASS",
                        severity="CRITICAL",
                        detail="Des clés d'accès actives existent sur le compte root." if has_active_key
                               else "Aucune clé d'accès active sur le compte root.",
                        resource="arn:aws:iam::root",
                        recommended_action="Supprimer toutes les clés d'accès root et utiliser des rôles IAM." if has_active_key else "",
                    ))
        except Exception as e:
            self._add_error("IAM-002", "NIS2-D09-R03", str(e))

        # IAM-003 : Utilisateurs IAM avec MFA
        try:
            users = iam.list_users()["Users"]
            users_without_mfa = []
            for user in users:
                mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
                if not mfa_devices:
                    users_without_mfa.append(user["UserName"])

            total_users = len(users)
            no_mfa_count = len(users_without_mfa)
            mfa_rate = (total_users - no_mfa_count) / max(total_users, 1)

            status = "PASS" if mfa_rate >= 0.9 else ("WARN" if mfa_rate >= 0.5 else "FAIL")
            self._findings.append(AWSFinding(
                control_id="IAM-003",
                title="MFA activé sur les utilisateurs IAM",
                requirement_id="NIS2-D10-R01",
                status=status,
                severity="HIGH",
                detail=f"{total_users - no_mfa_count}/{total_users} utilisateurs ont MFA activé ({mfa_rate*100:.0f}%)."
                       + (f" Sans MFA : {', '.join(users_without_mfa[:5])}" if users_without_mfa else ""),
                recommended_action="Enforcer MFA via une politique IAM pour tous les utilisateurs." if status != "PASS" else "",
            ))
        except Exception as e:
            self._add_error("IAM-003", "NIS2-D10-R01", str(e))

        # IAM-004 : Politique de rotation des clés d'accès (90 jours)
        try:
            cred_report = self._get_credential_report(iam)
            if cred_report:
                import datetime
                old_keys = []
                for row in cred_report:
                    if row.get("user") == "<root_account>":
                        continue
                    for key_num in ["1", "2"]:
                        active = row.get(f"access_key_{key_num}_active", "false") == "true"
                        last_rotated = row.get(f"access_key_{key_num}_last_rotated", "N/A")
                        if active and last_rotated != "N/A" and last_rotated != "not_supported":
                            try:
                                rotated_dt = datetime.datetime.fromisoformat(last_rotated.replace("Z", "+00:00"))
                                age_days = (datetime.datetime.now(datetime.timezone.utc) - rotated_dt).days
                                if age_days > 90:
                                    old_keys.append(f"{row['user']} (key{key_num}: {age_days}j)")
                            except Exception:
                                pass

                status = "PASS" if not old_keys else ("WARN" if len(old_keys) <= 2 else "FAIL")
                self._findings.append(AWSFinding(
                    control_id="IAM-004",
                    title="Rotation des clés d'accès IAM (< 90 jours)",
                    requirement_id="NIS2-D09-R03",
                    status=status,
                    severity="MEDIUM",
                    detail=f"{len(old_keys)} clé(s) non rotée(s) depuis plus de 90 jours." if old_keys
                           else "Toutes les clés actives ont été rotées dans les 90 derniers jours.",
                    recommended_action="Définir une politique de rotation automatique des clés IAM." if old_keys else "",
                ))
        except Exception as e:
            self._add_error("IAM-004", "NIS2-D09-R03", str(e))

        # IAM-005 : Politique de mot de passe
        self._audit_password_policy_inline(iam)

        # IAM-006 : Rôles avec permissions admin larges
        try:
            paginator = iam.get_paginator("list_policies")
            admin_policies = []
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    try:
                        version = iam.get_policy_version(
                            PolicyArn=policy["Arn"],
                            VersionId=policy["DefaultVersionId"],
                        )["PolicyVersion"]["Document"]
                        for stmt in version.get("Statement", []):
                            if (stmt.get("Effect") == "Allow"
                                    and stmt.get("Action") in ("*", ["*"])
                                    and stmt.get("Resource") in ("*", ["*"])):
                                admin_policies.append(policy["PolicyName"])
                    except Exception:
                        pass

            self._findings.append(AWSFinding(
                control_id="IAM-006",
                title="Absence de politiques IAM admin-wildcard",
                requirement_id="NIS2-D09-R01",
                status="FAIL" if admin_policies else "PASS",
                severity="HIGH",
                detail=f"{len(admin_policies)} politique(s) avec Action:* Resource:* détectée(s) : {', '.join(admin_policies[:3])}" if admin_policies
                       else "Aucune politique IAM locale avec permissions admin larges (*:*).",
                recommended_action="Remplacer les politiques wildcard par des politiques least-privilege." if admin_policies else "",
            ))
        except Exception as e:
            self._add_error("IAM-006", "NIS2-D09-R01", str(e))

    # ── Audit CloudTrail ──────────────────────────────────────────────────────

    def _audit_cloudtrail(self, session, region: str) -> None:
        ct = session.client("cloudtrail", region_name=region)

        # CT-001 : Trail multi-région actif
        try:
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
            multi_region_trails = [t for t in trails if t.get("IsMultiRegionTrail")]
            active_trails = []
            for trail in multi_region_trails:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                if status.get("IsLogging"):
                    active_trails.append(trail["Name"])

            self._findings.append(AWSFinding(
                control_id="CT-001",
                title="CloudTrail multi-région actif",
                requirement_id="NIS2-D02-R02",
                status="PASS" if active_trails else "FAIL",
                severity="HIGH",
                detail=f"Trail(s) multi-région actif(s) : {', '.join(active_trails)}" if active_trails
                       else "Aucun CloudTrail multi-région actif — journalisation des API manquante.",
                recommended_action="Activer CloudTrail multi-région avec logs vers S3 et intégration CloudWatch." if not active_trails else "",
            ))
        except Exception as e:
            self._add_error("CT-001", "NIS2-D02-R02", str(e))

        # CT-002 : Logs CloudTrail validés (intégrité)
        try:
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
            trails_without_validation = [
                t["Name"] for t in trails
                if not t.get("LogFileValidationEnabled")
            ]
            self._findings.append(AWSFinding(
                control_id="CT-002",
                title="Validation d'intégrité des logs CloudTrail",
                requirement_id="NIS2-D06-R01",
                status="FAIL" if trails_without_validation else "PASS",
                severity="MEDIUM",
                detail=f"Validation désactivée sur : {', '.join(trails_without_validation)}" if trails_without_validation
                       else "Validation d'intégrité activée sur tous les trails.",
                recommended_action="Activer LogFileValidation sur tous les trails CloudTrail." if trails_without_validation else "",
            ))
        except Exception as e:
            self._add_error("CT-002", "NIS2-D06-R01", str(e))

        # CT-003 : CloudWatch Logs activé sur le trail
        try:
            trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
            trails_without_cw = [
                t["Name"] for t in trails
                if not t.get("CloudWatchLogsLogGroupArn")
            ]
            self._findings.append(AWSFinding(
                control_id="CT-003",
                title="CloudTrail intégré à CloudWatch Logs",
                requirement_id="NIS2-D02-R02",
                status="WARN" if trails_without_cw else "PASS",
                severity="MEDIUM",
                detail=f"Trails sans intégration CloudWatch : {', '.join(trails_without_cw)}" if trails_without_cw
                       else "Tous les trails envoient les logs vers CloudWatch.",
                recommended_action="Intégrer CloudTrail à CloudWatch pour la détection d'événements en temps réel." if trails_without_cw else "",
            ))
        except Exception as e:
            self._add_error("CT-003", "NIS2-D02-R02", str(e))

    # ── Audit Security Groups ─────────────────────────────────────────────────

    def _audit_security_groups(self, session, region: str) -> None:
        ec2 = session.client("ec2", region_name=region)

        # SG-001 : Pas de 0.0.0.0/0 sur SSH (port 22)
        try:
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            open_ssh = []
            open_rdp = []
            for sg in sgs:
                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)
                    ranges = [r["CidrIp"] for r in rule.get("IpRanges", [])]
                    ranges += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]
                    if any(r in ("0.0.0.0/0", "::/0") for r in ranges):
                        if from_port <= 22 <= to_port:
                            open_ssh.append(f"{sg['GroupId']} ({sg.get('GroupName', '')})")
                        if from_port <= 3389 <= to_port:
                            open_rdp.append(f"{sg['GroupId']} ({sg.get('GroupName', '')})")

            self._findings.append(AWSFinding(
                control_id="SG-001",
                title="SSH non exposé à Internet (0.0.0.0/0)",
                requirement_id="NIS2-D09-R01",
                status="FAIL" if open_ssh else "PASS",
                severity="CRITICAL" if open_ssh else "LOW",
                detail=f"{len(open_ssh)} Security Group(s) exposent SSH à Internet : {', '.join(open_ssh[:3])}" if open_ssh
                       else "Aucun Security Group n'expose SSH (port 22) à Internet.",
                recommended_action="Restreindre SSH aux adresses IP de gestion ou utiliser AWS Systems Manager Session Manager." if open_ssh else "",
            ))

            self._findings.append(AWSFinding(
                control_id="SG-002",
                title="RDP non exposé à Internet (0.0.0.0/0)",
                requirement_id="NIS2-D09-R01",
                status="FAIL" if open_rdp else "PASS",
                severity="CRITICAL" if open_rdp else "LOW",
                detail=f"{len(open_rdp)} Security Group(s) exposent RDP à Internet : {', '.join(open_rdp[:3])}" if open_rdp
                       else "Aucun Security Group n'expose RDP (port 3389) à Internet.",
                recommended_action="Restreindre RDP aux plages IP de gestion ou utiliser AWS Systems Manager." if open_rdp else "",
            ))
        except Exception as e:
            self._add_error("SG-001", "NIS2-D09-R01", str(e))

    # ── Audit S3 ──────────────────────────────────────────────────────────────

    def _audit_s3(self, session) -> None:
        s3 = session.client("s3")

        try:
            buckets = s3.list_buckets().get("Buckets", [])
            public_buckets = []
            unencrypted_buckets = []
            no_versioning_buckets = []

            for bucket in buckets:
                name = bucket["Name"]

                # Vérifier l'ACL publique
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI", "").endswith(("AllUsers", "AuthenticatedUsers")):
                            public_buckets.append(name)
                            break
                except Exception:
                    pass

                # Vérifier le chiffrement
                try:
                    s3.get_bucket_encryption(Bucket=name)
                except s3.exceptions.ClientError:
                    unencrypted_buckets.append(name)
                except Exception:
                    pass

                # Vérifier le versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=name)
                    if versioning.get("Status") != "Enabled":
                        no_versioning_buckets.append(name)
                except Exception:
                    pass

            self._findings.append(AWSFinding(
                control_id="S3-001",
                title="Buckets S3 non publics",
                requirement_id="NIS2-D09-R04",
                status="FAIL" if public_buckets else "PASS",
                severity="CRITICAL" if public_buckets else "LOW",
                detail=f"{len(public_buckets)} bucket(s) public(s) détecté(s) : {', '.join(public_buckets[:3])}" if public_buckets
                       else f"Aucun des {len(buckets)} buckets n'est public.",
                recommended_action="Activer S3 Block Public Access au niveau du compte et de chaque bucket." if public_buckets else "",
            ))

            self._findings.append(AWSFinding(
                control_id="S3-002",
                title="Chiffrement activé sur les buckets S3",
                requirement_id="NIS2-D08-R02",
                status="FAIL" if unencrypted_buckets else "PASS",
                severity="HIGH" if unencrypted_buckets else "LOW",
                detail=f"{len(unencrypted_buckets)} bucket(s) sans chiffrement activé." if unencrypted_buckets
                       else f"Tous les buckets ont le chiffrement SSE activé.",
                recommended_action="Activer SSE-KMS sur tous les buckets contenant des données sensibles." if unencrypted_buckets else "",
            ))

            self._findings.append(AWSFinding(
                control_id="S3-003",
                title="Versioning activé sur les buckets S3",
                requirement_id="NIS2-D03-R02",
                status="WARN" if no_versioning_buckets else "PASS",
                severity="MEDIUM",
                detail=f"{len(no_versioning_buckets)}/{len(buckets)} bucket(s) sans versioning." if no_versioning_buckets
                       else "Versioning activé sur tous les buckets.",
                recommended_action="Activer le versioning S3 pour les buckets contenant des données critiques (PCA)." if no_versioning_buckets else "",
            ))
        except Exception as e:
            self._add_error("S3-001", "NIS2-D09-R04", str(e))

    # ── Audit KMS ─────────────────────────────────────────────────────────────

    def _audit_kms(self, session, region: str) -> None:
        kms = session.client("kms", region_name=region)

        try:
            keys = kms.list_keys()["Keys"]
            customer_keys = []
            for key in keys:
                try:
                    meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                    if meta.get("KeyManager") == "CUSTOMER" and meta.get("KeyState") == "Enabled":
                        customer_keys.append(key["KeyId"])
                except Exception:
                    pass

            self._findings.append(AWSFinding(
                control_id="KMS-001",
                title="Clés KMS gérées par le client (CMK) présentes",
                requirement_id="NIS2-D08-R01",
                status="PASS" if customer_keys else "WARN",
                severity="MEDIUM",
                detail=f"{len(customer_keys)} clé(s) KMS gérée(s) par le client (CMK) active(s)." if customer_keys
                       else "Aucune CMK KMS détectée — chiffrement possible uniquement avec clés AWS managées.",
                recommended_action="Créer des CMK KMS pour les services critiques avec rotation automatique activée." if not customer_keys else "",
            ))

            # Vérifier la rotation automatique des clés
            keys_without_rotation = []
            for key_id in customer_keys[:20]:  # Limiter pour les grands comptes
                try:
                    rotation = kms.get_key_rotation_status(KeyId=key_id)
                    if not rotation.get("KeyRotationEnabled"):
                        keys_without_rotation.append(key_id[:12] + "...")
                except Exception:
                    pass

            if customer_keys:
                self._findings.append(AWSFinding(
                    control_id="KMS-002",
                    title="Rotation automatique des clés KMS activée",
                    requirement_id="NIS2-D08-R01",
                    status="WARN" if keys_without_rotation else "PASS",
                    severity="MEDIUM",
                    detail=f"{len(keys_without_rotation)} CMK(s) sans rotation automatique." if keys_without_rotation
                           else "Rotation automatique annuelle activée sur toutes les CMK.",
                    recommended_action="Activer la rotation automatique (annuelle) sur toutes les CMK." if keys_without_rotation else "",
                ))
        except Exception as e:
            self._add_error("KMS-001", "NIS2-D08-R01", str(e))

    # ── Audit GuardDuty ───────────────────────────────────────────────────────

    def _audit_guardduty(self, session, region: str) -> None:
        gd = session.client("guardduty", region_name=region)

        try:
            detectors = gd.list_detectors()["DetectorIds"]
            active_detectors = []
            for det_id in detectors:
                det = gd.get_detector(DetectorId=det_id)
                if det.get("Status") == "ENABLED":
                    active_detectors.append(det_id)

            self._findings.append(AWSFinding(
                control_id="GD-001",
                title="AWS GuardDuty activé",
                requirement_id="NIS2-D02-R02",
                status="PASS" if active_detectors else "FAIL",
                severity="HIGH",
                detail=f"GuardDuty actif (détecteur(s) : {', '.join(active_detectors[:2])})." if active_detectors
                       else "GuardDuty n'est pas activé dans cette région — détection des menaces manquante.",
                recommended_action="Activer GuardDuty dans toutes les régions actives. Coût estimé : faible." if not active_detectors else "",
            ))
        except Exception as e:
            self._add_error("GD-001", "NIS2-D02-R02", str(e))

    # ── Audit AWS Config ──────────────────────────────────────────────────────

    def _audit_config(self, session, region: str) -> None:
        cfg = session.client("config", region_name=region)

        try:
            recorders = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
            statuses = cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
            active_recorders = [
                s["name"] for s in statuses if s.get("recording")
            ]

            self._findings.append(AWSFinding(
                control_id="CFG-001",
                title="AWS Config activé (enregistrement continu)",
                requirement_id="NIS2-D06-R01",
                status="PASS" if active_recorders else "FAIL",
                severity="MEDIUM",
                detail=f"AWS Config actif : {', '.join(active_recorders)}." if active_recorders
                       else "AWS Config n'est pas actif — pas de registre de conformité continu.",
                recommended_action="Activer AWS Config avec enregistrement de tous les types de ressources." if not active_recorders else "",
            ))
        except Exception as e:
            self._add_error("CFG-001", "NIS2-D06-R01", str(e))

    # ── Audit politique de mot de passe ──────────────────────────────────────

    def _audit_password_policy(self, session) -> None:
        iam = session.client("iam")
        self._audit_password_policy_inline(iam)

    def _audit_password_policy_inline(self, iam) -> None:
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append(f"longueur minimale {policy.get('MinimumPasswordLength')} < 14")
            if not policy.get("RequireUppercaseCharacters"):
                issues.append("majuscules non requises")
            if not policy.get("RequireLowercaseCharacters"):
                issues.append("minuscules non requises")
            if not policy.get("RequireNumbers"):
                issues.append("chiffres non requis")
            if not policy.get("RequireSymbols"):
                issues.append("symboles non requis")
            if not policy.get("ExpirePasswords"):
                issues.append("expiration des mots de passe désactivée")

            self._findings.append(AWSFinding(
                control_id="IAM-005",
                title="Politique de mot de passe IAM renforcée",
                requirement_id="NIS2-D10-R01",
                status="FAIL" if issues else "PASS",
                severity="MEDIUM",
                detail=f"Problèmes : {', '.join(issues)}." if issues
                       else "Politique de mot de passe conforme (longueur, complexité, expiration).",
                recommended_action="Renforcer la politique de mot de passe IAM (min. 14 caractères, complexité, rotation 90j)." if issues else "",
            ))
        except iam.exceptions.NoSuchEntityException:
            self._findings.append(AWSFinding(
                control_id="IAM-005",
                title="Politique de mot de passe IAM renforcée",
                requirement_id="NIS2-D10-R01",
                status="FAIL",
                severity="HIGH",
                detail="Aucune politique de mot de passe définie pour ce compte AWS.",
                recommended_action="Définir une politique de mot de passe IAM avec complexité et expiration.",
            ))
        except Exception as e:
            self._add_error("IAM-005", "NIS2-D10-R01", str(e))

    # ── Utilitaires ───────────────────────────────────────────────────────────

    def _get_credential_report(self, iam) -> list[dict] | None:
        """Génère et récupère le rapport de credentials IAM."""
        import time
        import csv
        import io

        try:
            # Générer le rapport
            while True:
                resp = iam.generate_credential_report()
                if resp["State"] == "COMPLETE":
                    break
                time.sleep(1)

            report = iam.get_credential_report()
            content = report["Content"].decode("utf-8")
            reader = csv.DictReader(io.StringIO(content))
            return list(reader)
        except Exception:
            return None

    def _add_error(self, control_id: str, requirement_id: str, error: str) -> None:
        self._findings.append(AWSFinding(
            control_id=control_id,
            title=f"Contrôle {control_id}",
            requirement_id=requirement_id,
            status="INFO",
            severity="LOW",
            detail=f"Impossible d'exécuter ce contrôle : {error}",
        ))

    # ── Construction du rapport ───────────────────────────────────────────────

    def _get_account_id(self, session) -> str:
        try:
            return session.client("sts").get_caller_identity()["Account"]
        except Exception:
            return "unknown"

    def _build_report(self, account_id: str, region: str) -> AWSAuditReport:
        findings = self._findings

        passed = sum(1 for f in findings if f.status == "PASS")
        failed = sum(1 for f in findings if f.status == "FAIL")
        warnings = sum(1 for f in findings if f.status == "WARN")
        critical = [f for f in findings if f.severity == "CRITICAL" and f.status == "FAIL"]

        maturity = self._compute_maturity(findings)

        return AWSAuditReport(
            account_id=account_id,
            region=region,
            findings=findings,
            maturity_mapping=maturity,
            total_controls=len([f for f in findings if f.status != "INFO"]),
            passed=passed,
            failed=failed,
            warnings=warnings,
            critical_findings=critical,
        )

    def _compute_maturity(self, findings: list[AWSFinding]) -> dict[str, int]:
        """
        Calcule le niveau de maturité NIS 2 (0-3) pour chaque exigence
        à partir des findings AWS.

        Logique :
        - CRITICAL FAIL → niveau 0 (non implémenté)
        - HIGH FAIL      → niveau 0 ou 1 selon le nombre de passes
        - WARN           → niveau 1 (partiel)
        - Tout PASS      → niveau 2 (implémenté)
        - Tout PASS + contrôles avancés → niveau 3 (géré)
        """
        # Grouper les findings par requirement_id
        by_req: dict[str, list[AWSFinding]] = {}
        for f in findings:
            if f.status == "INFO":
                continue
            by_req.setdefault(f.requirement_id, []).append(f)

        maturity: dict[str, int] = {}
        for req_id, req_findings in by_req.items():
            has_critical_fail = any(f.severity == "CRITICAL" and f.status == "FAIL" for f in req_findings)
            has_high_fail = any(f.severity == "HIGH" and f.status == "FAIL" for f in req_findings)
            has_fail = any(f.status == "FAIL" for f in req_findings)
            has_warn = any(f.status == "WARN" for f in req_findings)
            all_pass = all(f.status == "PASS" for f in req_findings)
            pass_count = sum(1 for f in req_findings if f.status == "PASS")
            total = len(req_findings)

            if has_critical_fail:
                level = 0
            elif has_high_fail:
                level = 0 if pass_count == 0 else 1
            elif has_fail:
                level = 1
            elif has_warn:
                level = 1
            elif all_pass:
                # Niveau 3 si beaucoup de contrôles passent et aucun warn/fail
                level = 3 if total >= 2 else 2
            else:
                level = 1

            maturity[req_id] = level

        return maturity

    # ── Mode démonstration ────────────────────────────────────────────────────

    def _demo_audit(self, region: str) -> AWSAuditReport:
        """
        Génère un rapport d'audit réaliste sans credentials AWS.
        Utile pour les démonstrations, les tests, et l'UI COMPASS.
        """
        demo_findings = [
            # IAM
            AWSFinding("IAM-001", "MFA activé sur le compte root", "NIS2-D10-R01",
                       "PASS", "CRITICAL", "MFA est activé sur le compte root.", "arn:aws:iam::123456789012:root"),
            AWSFinding("IAM-002", "Clés d'accès root inactives", "NIS2-D09-R03",
                       "PASS", "CRITICAL", "Aucune clé d'accès active sur le compte root."),
            AWSFinding("IAM-003", "MFA activé sur les utilisateurs IAM", "NIS2-D10-R01",
                       "WARN", "HIGH", "7/12 utilisateurs ont MFA activé (58%). Sans MFA : dev01, dev02, admin-tmp.",
                       recommended_action="Enforcer MFA via une politique IAM pour tous les utilisateurs."),
            AWSFinding("IAM-004", "Rotation des clés d'accès IAM (< 90 jours)", "NIS2-D09-R03",
                       "FAIL", "MEDIUM", "2 clé(s) non rotée(s) depuis plus de 90 jours. dev01 (key1: 187j), ci-deploy (key1: 143j).",
                       recommended_action="Définir une politique de rotation automatique des clés IAM."),
            AWSFinding("IAM-005", "Politique de mot de passe IAM renforcée", "NIS2-D10-R01",
                       "FAIL", "MEDIUM", "Problèmes : longueur minimale 8 < 14, symboles non requis, expiration des mots de passe désactivée.",
                       recommended_action="Renforcer la politique de mot de passe IAM (min. 14 caractères, complexité, rotation 90j)."),
            AWSFinding("IAM-006", "Absence de politiques IAM admin-wildcard", "NIS2-D09-R01",
                       "FAIL", "HIGH", "1 politique avec Action:* Resource:* détectée : DevFullAccess.",
                       recommended_action="Remplacer les politiques wildcard par des politiques least-privilege."),
            # CloudTrail
            AWSFinding("CT-001", "CloudTrail multi-région actif", "NIS2-D02-R02",
                       "PASS", "HIGH", "Trail multi-région actif : management-trail."),
            AWSFinding("CT-002", "Validation d'intégrité des logs CloudTrail", "NIS2-D06-R01",
                       "PASS", "MEDIUM", "Validation d'intégrité activée sur tous les trails."),
            AWSFinding("CT-003", "CloudTrail intégré à CloudWatch Logs", "NIS2-D02-R02",
                       "WARN", "MEDIUM", "Trail management-trail n'est pas intégré à CloudWatch Logs.",
                       recommended_action="Intégrer CloudTrail à CloudWatch pour la détection d'événements en temps réel."),
            # Security Groups
            AWSFinding("SG-001", "SSH non exposé à Internet (0.0.0.0/0)", "NIS2-D09-R01",
                       "FAIL", "CRITICAL", "1 Security Group expose SSH à Internet : sg-0ab12cd34 (dev-bastion).",
                       "sg-0ab12cd34", "Restreindre SSH aux adresses IP de gestion ou utiliser AWS Systems Manager Session Manager."),
            AWSFinding("SG-002", "RDP non exposé à Internet (0.0.0.0/0)", "NIS2-D09-R01",
                       "PASS", "CRITICAL", "Aucun Security Group n'expose RDP (port 3389) à Internet."),
            # S3
            AWSFinding("S3-001", "Buckets S3 non publics", "NIS2-D09-R04",
                       "PASS", "CRITICAL", "Aucun des 8 buckets n'est public."),
            AWSFinding("S3-002", "Chiffrement activé sur les buckets S3", "NIS2-D08-R02",
                       "WARN", "HIGH", "2 bucket(s) sans chiffrement activé.",
                       recommended_action="Activer SSE-KMS sur tous les buckets contenant des données sensibles."),
            AWSFinding("S3-003", "Versioning activé sur les buckets S3", "NIS2-D03-R02",
                       "WARN", "MEDIUM", "5/8 buckets sans versioning.",
                       recommended_action="Activer le versioning S3 pour les buckets contenant des données critiques (PCA)."),
            # KMS
            AWSFinding("KMS-001", "Clés KMS gérées par le client (CMK) présentes", "NIS2-D08-R01",
                       "PASS", "MEDIUM", "3 clé(s) KMS gérée(s) par le client (CMK) active(s)."),
            AWSFinding("KMS-002", "Rotation automatique des clés KMS activée", "NIS2-D08-R01",
                       "WARN", "MEDIUM", "1 CMK sans rotation automatique.",
                       recommended_action="Activer la rotation automatique (annuelle) sur toutes les CMK."),
            # GuardDuty
            AWSFinding("GD-001", "AWS GuardDuty activé", "NIS2-D02-R02",
                       "PASS", "HIGH", "GuardDuty actif (détecteur : abc123def456)."),
            # AWS Config
            AWSFinding("CFG-001", "AWS Config activé (enregistrement continu)", "NIS2-D06-R01",
                       "FAIL", "MEDIUM", "AWS Config n'est pas actif — pas de registre de conformité continu.",
                       recommended_action="Activer AWS Config avec enregistrement de tous les types de ressources."),
        ]

        self._findings = demo_findings
        return self._build_report("123456789012", region)
