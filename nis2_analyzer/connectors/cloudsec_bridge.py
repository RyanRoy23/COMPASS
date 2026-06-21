"""
COMPASS — CloudSec Bridge
Connecte les résultats du CloudSec Audit Toolkit aux exigences NIS 2.

C'est le fichier clé du projet — celui qui différencie l'outil de tout
ce qui existe sur le marché. Il fait 3 choses :

1. Charge le rapport JSON du CloudSec Audit Toolkit
2. Mappe chaque check CloudSec vers les sous-exigences NIS 2 correspondantes
3. Traduit les résultats en niveaux de maturité avec preuves techniques

Pourquoi c'est important :
- Les outils concurrents demandent "avez-vous le MFA ?" → l'utilisateur dit "oui"
- Notre outil dit "85% de vos comptes ont le MFA, voici la liste de ceux qui ne l'ont pas"
- La différence : preuve technique vs déclaration

Architecture :
- MAPPING_CLOUDSEC_TO_NIS2 : dictionnaire statique qui relie chaque check CloudSec
  à une ou plusieurs sous-exigences NIS 2
- CloudSecBridge : classe qui orchestre l'import et la traduction
- EvidenceItem : structure qui stocke une preuve technique
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from nis2_analyzer.core.models import (
    Domain, SubRequirement, MaturityLevel, load_framework
)


@dataclass
class EvidenceItem:
    """
    Une preuve technique issue de l'audit CloudSec.
    
    Pourquoi structurer les preuves ?
    Parce qu'en audit, une preuve doit avoir :
    - Une source identifiée (quel outil l'a produite)
    - Une date (quand le contrôle a été vérifié)
    - Un résultat factuel (ce qui a été constaté)
    - Un statut (pass/fail)
    
    C'est exactement ce qu'un auditeur ANSSI attend.
    """
    source: str                  # "CloudSec Audit Toolkit v1.0.0"
    check_id: str                # "IDN-001"
    check_title: str             # "Users without MFA enabled"
    timestamp: str               # "2026-03-21T13:19:25Z"
    passed: bool                 # True/False
    finding_count: int           # Nombre de problèmes détectés
    details: str                 # "3/6 users without MFA registered"
    findings_summary: list[str]  # ["Alice - no MFA", "Bob - no MFA"]


# ═══════════════════════════════════════════════════
# MAPPING CLOUDSEC → NIS 2
# ═══════════════════════════════════════════════════
# 
# Ce dictionnaire est le cœur intellectuel du bridge.
# Chaque clé est un check_id du CloudSec Audit Toolkit.
# Chaque valeur contient :
#   - nis2_requirement_ids : les sous-exigences NIS 2 couvertes
#   - maturity_logic : comment traduire le résultat en niveau de maturité
#   - evidence_template : comment formuler la preuve
#
# La logique de maturité est la suivante :
#   - Check PASS → niveau 2 (Défini/Implémenté) minimum
#   - Check PASS + 0 findings → niveau 3 (Géré/Mesuré) car vérifié automatiquement
#   - Check FAIL + findings > seuil → niveau 0 ou 1 selon la gravité
#
# Pourquoi pas toujours niveau 3 en cas de PASS ?
# Parce que le niveau 3 implique une surveillance continue avec KPI.
# Un check ponctuel qui passe prouve l'implémentation (niveau 2),
# la surveillance continue est un processus organisationnel
# qu'un scan technique seul ne peut pas prouver.

MAPPING_CLOUDSEC_TO_NIS2 = {
    
    # ── Identity & MFA Checks → NIS 2 Domaine 10 (MFA) et Domaine 9 (Accès) ──
    
    "IDN-001": {
        "nis2_requirement_ids": ["NIS2-D10-R01"],
        "description": "Vérification du déploiement MFA sur les comptes utilisateurs",
        "maturity_logic": {
            "pass": {
                "level": 3,
                "reason": "MFA vérifié automatiquement sur l'ensemble des comptes — surveillance active"
            },
            "fail_low": {
                "threshold": 0.2,  # Moins de 20% sans MFA
                "level": 1,
                "reason": "MFA partiellement déployé — {finding_count} compte(s) sans MFA détecté(s)"
            },
            "fail_high": {
                "level": 0,
                "reason": "MFA non déployé sur une majorité de comptes — {finding_count} compte(s) sans MFA"
            }
        }
    },
    
    "IDN-002": {
        "nis2_requirement_ids": ["NIS2-D10-R01", "NIS2-D09-R03"],
        "description": "Vérification du MFA sur les comptes administrateurs",
        "maturity_logic": {
            "pass": {
                "level": 3,
                "reason": "MFA actif sur tous les comptes administrateurs — contrôle vérifié"
            },
            "fail_low": {
                "threshold": 0.1,
                "level": 1,
                "reason": "MFA manquant sur {finding_count} compte(s) admin — risque élevé"
            },
            "fail_high": {
                "level": 0,
                "reason": "MFA absent sur les comptes administrateurs — risque critique"
            }
        }
    },
    
    "IDN-003": {
        "nis2_requirement_ids": ["NIS2-D09-R01"],
        "description": "Vérification des privilèges des comptes invités",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Aucun compte invité avec privilèges élevés détecté"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "{finding_count} compte(s) invité(s) avec privilèges élevés"
            },
            "fail_high": {
                "level": 0,
                "reason": "Comptes invités avec accès administrateur — violation du moindre privilège"
            }
        }
    },
    
    "IDN-004": {
        "nis2_requirement_ids": ["NIS2-D09-R02"],
        "description": "Détection des comptes inactifs (>90 jours)",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Aucun compte inactif détecté — gestion des départs effective"
            },
            "fail_low": {
                "threshold": 0.3,
                "level": 1,
                "reason": "{finding_count} compte(s) inactif(s) >90 jours — revue des accès incomplète"
            },
            "fail_high": {
                "level": 0,
                "reason": "Nombreux comptes inactifs — absence de processus de désactivation"
            }
        }
    },
    
    "IDN-005": {
        "nis2_requirement_ids": ["NIS2-D09-R01"],
        "description": "Vérification de la politique de mots de passe",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Aucun compte avec 'password never expires' détecté"
            },
            "fail_low": {
                "threshold": 0.3,
                "level": 1,
                "reason": "{finding_count} compte(s) avec expiration de mot de passe désactivée"
            },
            "fail_high": {
                "level": 0,
                "reason": "Politique de mots de passe non appliquée sur de nombreux comptes"
            }
        }
    },
    
    # ── Privileged Roles Checks → NIS 2 Domaine 9 (Accès & Actifs) ──
    
    "ROL-001": {
        "nis2_requirement_ids": ["NIS2-D09-R03"],
        "description": "Nombre de Global Administrators",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Nombre de Global Admins conforme (≤5)"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "{finding_count} Global Admin(s) — excès de privilèges"
            },
            "fail_high": {
                "level": 0,
                "reason": "Nombre excessif de Global Admins — surface d'attaque critique"
            }
        }
    },
    
    "ROL-002": {
        "nis2_requirement_ids": ["NIS2-D09-R03"],
        "description": "Assignations de rôles privilégiés permanentes",
        "maturity_logic": {
            "pass": {
                "level": 3,
                "reason": "Aucune assignation permanente — PIM/JIT en place"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "{finding_count} assignation(s) permanente(s) — JIT non implémenté"
            },
            "fail_high": {
                "level": 0,
                "reason": "Toutes les assignations sont permanentes — aucun contrôle JIT"
            }
        }
    },
    
    "ROL-003": {
        "nis2_requirement_ids": ["NIS2-D09-R01"],
        "description": "Utilisateurs avec rôles multiples",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Séparation des rôles respectée"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "{finding_count} utilisateur(s) cumulent des rôles privilégiés"
            },
            "fail_high": {
                "level": 0,
                "reason": "Cumul massif de rôles — absence de séparation des tâches"
            }
        }
    },
    
    "ROL-004": {
        "nis2_requirement_ids": ["NIS2-D09-R03"],
        "description": "Service principals avec rôles d'annuaire",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Aucun service principal avec rôles d'annuaire"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "{finding_count} service principal(s) avec privilèges excessifs"
            },
            "fail_high": {
                "level": 0,
                "reason": "Service principals non contrôlés avec accès admin"
            }
        }
    },
    
    # ── Conditional Access → NIS 2 Domaine 1 (Politiques) et Domaine 10 (MFA) ──
    
    "CAP-001": {
        "nis2_requirement_ids": ["NIS2-D01-R01"],
        "description": "Présence de politiques d'accès conditionnel",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Politiques d'accès conditionnel en place"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "Politiques d'accès conditionnel insuffisantes"
            },
            "fail_high": {
                "level": 0,
                "reason": "Aucune politique d'accès conditionnel — pas de contrôle adaptatif"
            }
        }
    },
    
    "CAP-002": {
        "nis2_requirement_ids": ["NIS2-D10-R01"],
        "description": "Blocage de l'authentification legacy",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Authentification legacy bloquée par politique"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "Authentification legacy partiellement bloquée"
            },
            "fail_high": {
                "level": 0,
                "reason": "Authentification legacy non bloquée — contournement MFA possible"
            }
        }
    },
    
    "CAP-003": {
        "nis2_requirement_ids": ["NIS2-D10-R01", "NIS2-D09-R03"],
        "description": "Politique MFA pour les administrateurs",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Politique MFA spécifique aux admins en place"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "Politique MFA admin incomplète"
            },
            "fail_high": {
                "level": 0,
                "reason": "Aucune politique MFA ciblant les administrateurs"
            }
        }
    },
    
    "CAP-004": {
        "nis2_requirement_ids": ["NIS2-D02-R02"],
        "description": "Politique de blocage des connexions à risque",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Politique de détection des connexions à risque active"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "Détection des connexions à risque partielle"
            },
            "fail_high": {
                "level": 0,
                "reason": "Aucune détection des connexions à risque"
            }
        }
    },
    
    # ── Tenant Config → NIS 2 Domaine 1 (Politiques) et Domaine 7 (Hygiène) ──
    
    "TNT-001": {
        "nis2_requirement_ids": ["NIS2-D07-R03"],
        "description": "Configuration du self-service password reset",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "SSPR correctement configuré"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "SSPR partiellement configuré"
            },
            "fail_high": {
                "level": 0,
                "reason": "SSPR non configuré"
            }
        }
    },
    
    "TNT-002": {
        "nis2_requirement_ids": ["NIS2-D09-R01"],
        "description": "Restriction du consentement utilisateur aux applications",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Consentement aux applications restreint"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "Consentement partiellement restreint"
            },
            "fail_high": {
                "level": 0,
                "reason": "Utilisateurs autorisés à consentir à toute application — risque OAuth phishing"
            }
        }
    },
    
    "TNT-003": {
        "nis2_requirement_ids": ["NIS2-D04-R01"],
        "description": "Contrôle de la collaboration externe",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Collaboration externe restreinte aux admins"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "Collaboration externe trop permissive"
            },
            "fail_high": {
                "level": 0,
                "reason": "Tout utilisateur peut inviter des externes — aucun contrôle"
            }
        }
    },
    
    "TNT-004": {
        "nis2_requirement_ids": ["NIS2-D01-R01"],
        "description": "Security Defaults ou Conditional Access actifs",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Protections de base actives (Security Defaults ou CA)"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "Protections de base partielles"
            },
            "fail_high": {
                "level": 0,
                "reason": "Ni Security Defaults ni Conditional Access — tenant non protégé"
            }
        }
    },
    
    # ── Applications → NIS 2 Domaine 5 (Dev & Maintenance) ──
    
    "APP-001": {
        "nis2_requirement_ids": ["NIS2-D05-R02"],
        "description": "Permissions MS Graph excessives des applications",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Aucune application avec permissions excessives"
            },
            "fail_low": {
                "threshold": 0.3,
                "level": 1,
                "reason": "{finding_count} application(s) avec permissions à risque"
            },
            "fail_high": {
                "level": 0,
                "reason": "Applications avec permissions critiques non contrôlées"
            }
        }
    },
    
    "APP-002": {
        "nis2_requirement_ids": ["NIS2-D08-R01"],
        "description": "Credentials d'applications expirant sous 30 jours",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Tous les credentials sont valides >30 jours"
            },
            "fail_low": {
                "threshold": 0.5,
                "level": 1,
                "reason": "{finding_count} credential(s) expirant sous 30 jours"
            },
            "fail_high": {
                "level": 0,
                "reason": "Credentials critiques en voie d'expiration — risque d'interruption"
            }
        }
    },
    
    "APP-003": {
        "nis2_requirement_ids": ["NIS2-D09-R04"],
        "description": "Applications sans propriétaire assigné",
        "maturity_logic": {
            "pass": {
                "level": 2,
                "reason": "Toutes les applications ont un propriétaire identifié"
            },
            "fail_low": {
                "threshold": 0.3,
                "level": 1,
                "reason": "{finding_count} application(s) sans propriétaire — gouvernance incomplète"
            },
            "fail_high": {
                "level": 0,
                "reason": "Applications orphelines — aucune gouvernance des assets applicatifs"
            }
        }
    },
}


class CloudSecBridge:
    """
    Pont entre CloudSec Audit Toolkit et COMPASS.
    
    Workflow :
    1. load_cloudsec_report() → charge le JSON du CloudSec Audit
    2. map_to_nis2() → traduit chaque résultat en maturité NIS 2
    3. apply_to_framework() → injecte les résultats dans les domaines NIS 2
    4. get_evidence_report() → génère le rapport de preuves
    
    L'utilisateur final voit :
    - "12 questions sur 31 ont été pré-remplies par l'audit technique"
    - "Il vous reste 19 questions organisationnelles à répondre"
    - Chaque réponse pré-remplie est accompagnée de la preuve CloudSec
    """
    
    def __init__(self):
        self.cloudsec_data: dict = {}
        self.evidence_items: list[EvidenceItem] = []
        self.auto_filled_count: int = 0
        self.total_mapped: int = 0
    
    def load_cloudsec_report(self, json_path: str) -> dict:
        """
        Charge le rapport JSON du CloudSec Audit Toolkit.

        Ce fichier est généré par : python -m cloudsec.cli --output report.json
        Il contient les résultats des 20 checks avec :
        - metadata (date, version, tenant)
        - results (chaque check avec passed/failed, findings, details)
        - scores (passed, failed, errors)
        """
        # Résolution du chemin absolu pour prévenir le path traversal
        resolved = os.path.realpath(os.path.abspath(json_path))
        if not os.path.exists(resolved):
            raise FileNotFoundError(
                f"Rapport CloudSec non trouvé : {json_path}\n"
                f"Lancez d'abord : python -m cloudsec.cli --output {json_path}"
            )

        if not resolved.endswith(".json"):
            raise ValueError(f"Le fichier bridge doit être un fichier .json : {json_path}")

        with open(resolved, "r", encoding="utf-8") as f:
            try:
                self.cloudsec_data = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Rapport CloudSec invalide — JSON malformé : {e}") from e

        # Validation du schéma minimum attendu
        required_keys = {"results"}
        missing = required_keys - set(self.cloudsec_data.keys())
        if missing:
            raise ValueError(
                f"Format de rapport CloudSec invalide — clés manquantes : {', '.join(missing)}"
            )

        if not isinstance(self.cloudsec_data["results"], dict):
            raise ValueError(
                "Format de rapport CloudSec invalide — 'results' doit être un objet JSON"
            )

        return self.cloudsec_data
    
    def _determine_maturity(self, check_id: str, check_result: dict) -> tuple[MaturityLevel, str]:
        """
        Détermine le niveau de maturité NIS 2 à partir d'un résultat CloudSec.
        
        Logique de décision :
        1. Si le check a une erreur → on ne pré-remplit pas (pas de donnée fiable)
        2. Si le check est PASS → niveau 2 ou 3 selon le mapping
        3. Si le check est FAIL :
           a. On regarde le nombre de findings
           b. Si peu de findings (< seuil) → niveau 1 (partiel)
           c. Si beaucoup de findings (> seuil) → niveau 0 (non implémenté)
        
        Le seuil est défini dans MAPPING_CLOUDSEC_TO_NIS2 pour chaque check,
        parce que "3 comptes sans MFA sur 100" n'a pas le même impact que
        "3 comptes admin sans MFA sur 5".
        """
        if check_id not in MAPPING_CLOUDSEC_TO_NIS2:
            return None, "Check non mappé"
        
        mapping = MAPPING_CLOUDSEC_TO_NIS2[check_id]
        logic = mapping["maturity_logic"]
        
        # Cas erreur : on ne pré-remplit pas
        if check_result.get("error"):
            return None, f"Erreur lors du check : {check_result['error']}"
        
        passed = check_result.get("passed", False)
        finding_count = check_result.get("finding_count", 0)
        
        if passed:
            level_info = logic["pass"]
            return MaturityLevel(level_info["level"]), level_info["reason"]
        else:
            # Déterminer si c'est un fail "léger" ou "grave"
            threshold = logic.get("fail_low", {}).get("threshold", 0.3)
            
            # Heuristique : si le nombre de findings est faible, c'est partiel
            # On utilise finding_count directement car on n'a pas toujours
            # le total pour calculer un ratio
            if finding_count <= 3:
                level_info = logic.get("fail_low", logic.get("fail_high"))
            else:
                level_info = logic.get("fail_high", logic.get("fail_low"))
            
            reason = level_info["reason"].format(finding_count=finding_count)
            return MaturityLevel(level_info["level"]), reason
    
    def map_to_nis2(self) -> list[EvidenceItem]:
        """
        Traduit tous les résultats CloudSec en preuves NIS 2.
        
        Parcourt chaque check du rapport CloudSec, vérifie s'il a un
        mapping NIS 2, et crée un EvidenceItem avec la preuve.
        
        Retourne la liste des preuves collectées.
        """
        if not self.cloudsec_data:
            raise ValueError("Aucun rapport CloudSec chargé. Appelez load_cloudsec_report() d'abord.")
        
        metadata = self.cloudsec_data.get("metadata", {})
        source = f"{metadata.get('tool', 'CloudSec Audit Toolkit')} v{metadata.get('version', '?')}"
        timestamp = metadata.get("timestamp", datetime.utcnow().isoformat())
        
        self.evidence_items = []
        
        for result in self.cloudsec_data.get("results", []):
            check_id = result.get("id", "")
            
            if check_id not in MAPPING_CLOUDSEC_TO_NIS2:
                continue
            
            # Créer la preuve
            findings_summary = []
            for finding in result.get("findings", [])[:5]:  # Max 5 pour lisibilité
                name = finding.get("resource_name", "?")
                detail = finding.get("detail", "")
                findings_summary.append(f"{name} — {detail}")
            
            evidence = EvidenceItem(
                source=source,
                check_id=check_id,
                check_title=result.get("title", ""),
                timestamp=timestamp,
                passed=result.get("passed", False),
                finding_count=result.get("finding_count", 0),
                details=result.get("details", ""),
                findings_summary=findings_summary,
            )
            
            self.evidence_items.append(evidence)
        
        self.total_mapped = len(self.evidence_items)
        return self.evidence_items
    
    def apply_to_framework(self, domains: list[Domain]) -> dict:
        """
        Injecte les résultats mappés dans le framework NIS 2.
        
        Pour chaque preuve CloudSec :
        1. Trouve la sous-exigence NIS 2 correspondante
        2. Calcule le niveau de maturité
        3. Met à jour la sous-exigence avec le niveau et la preuve
        4. Marque la question comme "auto-remplie"
        
        Retourne un résumé de ce qui a été pré-rempli.
        
        Les questions non couvertes par CloudSec restent à remplir
        manuellement par l'utilisateur (questions organisationnelles).
        """
        if not self.evidence_items:
            self.map_to_nis2()
        
        auto_filled = {}       # requirement_id → {level, reason, evidence}
        self.auto_filled_count = 0
        
        # Construire un index requirement_id → SubRequirement
        req_index = {}
        for domain in domains:
            for req in domain.sub_requirements:
                req_index[req.id] = req
        
        # Pour chaque résultat CloudSec, mettre à jour les requirements NIS 2
        for result in self.cloudsec_data.get("results", []):
            check_id = result.get("id", "")
            
            if check_id not in MAPPING_CLOUDSEC_TO_NIS2:
                continue
            
            mapping = MAPPING_CLOUDSEC_TO_NIS2[check_id]
            maturity, reason = self._determine_maturity(check_id, result)
            
            if maturity is None:
                continue
            
            # Appliquer à chaque requirement NIS 2 mappé
            for req_id in mapping["nis2_requirement_ids"]:
                if req_id in req_index:
                    req = req_index[req_id]
                    
                    # Si déjà rempli par un autre check, garder le plus bas
                    # (principe de prudence — le maillon faible détermine le niveau)
                    if req.maturity is None or maturity.value < req.maturity.value:
                        req.maturity = maturity
                        req.notes = f"[AUTO - CloudSec] {reason}"
                        self.auto_filled_count += 1
                        
                        auto_filled[req_id] = {
                            "level": maturity.value,
                            "level_label": maturity.label,
                            "reason": reason,
                            "source_check": check_id,
                            "evidence_details": result.get("details", ""),
                        }
        
        # Compter les questions restantes
        total_reqs = sum(d.total_requirements for d in domains)
        remaining = total_reqs - len(auto_filled)
        
        return {
            "total_requirements": total_reqs,
            "auto_filled": len(auto_filled),
            "remaining_manual": remaining,
            "coverage_pct": round(len(auto_filled) / total_reqs * 100, 1),
            "details": auto_filled,
        }
    
    def get_evidence_report(self) -> list[dict]:
        """
        Génère le rapport de preuves techniques pour l'audit.
        
        Ce rapport est ce qu'un auditeur ANSSI voudrait voir :
        - Quelle vérification a été faite
        - Quand
        - Par quel outil
        - Quel a été le résultat
        - Quels problèmes ont été détectés
        """
        return [
            {
                "source": e.source,
                "check_id": e.check_id,
                "check_title": e.check_title,
                "timestamp": e.timestamp,
                "result": "PASS" if e.passed else "FAIL",
                "finding_count": e.finding_count,
                "details": e.details,
                "findings_sample": e.findings_summary,
            }
            for e in self.evidence_items
        ]
    
    def display_summary(self):
        """Affiche un résumé du bridge dans le terminal."""
        BOLD = "\033[1m"
        RESET = "\033[0m"
        CYAN = "\033[36m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        WHITE = "\033[97m"
        DIM = "\033[2m"
        
        print()
        print(f"  {CYAN}{'═' * 56}{RESET}")
        print(f"  {WHITE}{BOLD}  BRIDGE CLOUDSEC → NIS 2{RESET}")
        print(f"  {CYAN}{'═' * 56}{RESET}")
        print()
        
        meta = self.cloudsec_data.get("metadata", {})
        print(f"  {DIM}Source   : {meta.get('tool', '?')} v{meta.get('version', '?')}{RESET}")
        print(f"  {DIM}Date     : {meta.get('timestamp', '?')[:19]}{RESET}")
        print(f"  {DIM}Checks   : {meta.get('total_checks', '?')} executes{RESET}")
        print()
        
        # Résumé par résultat
        passed = sum(1 for e in self.evidence_items if e.passed)
        failed = sum(1 for e in self.evidence_items if not e.passed)
        
        print(f"  {WHITE}Checks mappes vers NIS 2 :{RESET}  {BOLD}{self.total_mapped}{RESET}")
        print(f"  {GREEN}  Conformes (PASS)       :{RESET}  {GREEN}{passed}{RESET}")
        print(f"  {YELLOW}  Non conformes (FAIL)   :{RESET}  {YELLOW}{failed}{RESET}")
        print()
        
        for evidence in self.evidence_items:
            status = f"{GREEN}PASS{RESET}" if evidence.passed else f"{YELLOW}FAIL{RESET}"
            print(f"  [{evidence.check_id}] {evidence.check_title[:40]}  {status}")
            if not evidence.passed and evidence.findings_summary:
                for finding in evidence.findings_summary[:2]:
                    print(f"    {DIM}→ {finding}{RESET}")
        
        print()
        print(f"  {CYAN}{'─' * 56}{RESET}")
        print(f"  {WHITE}{BOLD}Questions NIS 2 pre-remplies : {self.auto_filled_count}{RESET}")
        print(f"  {CYAN}{'─' * 56}{RESET}")
        print()
