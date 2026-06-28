"""
COMPASS — Profils sectoriels NIS 2

Chaque secteur NIS 2 a des priorités réglementaires différentes.
Un hôpital doit prioriser la continuité d'activité (Art. 21 §c) — une
panne de PACS met des vies en danger. Une banque doit prioriser la
cryptographie et le contrôle d'accès — les données financières sont la cible.

Ce module fournit :
1. Des pondérations sectorielles par domaine NIS 2 (surpondérer ce qui compte)
2. Des questions prioritaires par secteur (celles à ne pas manquer)
3. Des recommandations sectorielles ciblées
4. Un score sectoriel = score global rePondéré selon le profil du secteur

Référence : ENISA Sector-Specific Guidelines, ANSSI Guide sectoriel NIS 2,
EBA Guidelines on ICT Risk, HDS (Hébergeur Données de Santé).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── Profil sectoriel ──────────────────────────────────────────────────────────

@dataclass
class SectorProfile:
    """
    Profil sectoriel NIS 2 : pondérations et priorités spécifiques.

    domain_weights : surcharge des poids de domaine (multiplicateur par rapport
                     aux poids NIS 2 standard). Ex. : D03 × 2.0 pour la santé
                     = la continuité d'activité compte double.
    priority_requirements : IDs des exigences à fort enjeu sectoriel.
    regulatory_context : texte court résumant le contexte réglementaire.
    key_threats : principales menaces sectorielles (pour le rapport).
    """
    sector_id: str
    sector_label: str
    domain_weights: dict[str, float]    # domain_id → multiplicateur
    priority_requirements: list[str]    # requirement_ids à fort enjeu
    regulatory_context: str
    key_threats: list[str]
    specific_controls: list[dict]       # Contrôles supplémentaires recommandés


# ── Définitions sectorielles ──────────────────────────────────────────────────

SECTOR_PROFILES: dict[str, SectorProfile] = {

    "sante": SectorProfile(
        sector_id="sante",
        sector_label="Santé",
        domain_weights={
            "NIS2-D01": 1.3,   # Risques SI : DPI, PACS, équipements biomédicaux
            "NIS2-D02": 1.5,   # Gestion incidents : signalement ASN, arrêt soins critique
            "NIS2-D03": 2.0,   # Continuité : une panne = mise en danger de patients
            "NIS2-D04": 1.4,   # Chaîne appro : DM connectés, SaaS cliniques
            "NIS2-D05": 0.9,   # Dev SI : important mais pas priorité numéro 1
            "NIS2-D06": 1.0,   # Audit sécurité
            "NIS2-D07": 1.2,   # Hygiène : personnel soignant peu sensibilisé
            "NIS2-D08": 1.5,   # Cryptographie : données de santé = données sensibles Art. 9 RGPD
            "NIS2-D09": 1.3,   # Contrôle accès : accès aux DPI limité au besoin de soin
            "NIS2-D10": 1.2,   # MFA : accès distants aux DPI
        },
        priority_requirements=[
            "NIS2-D03-R01",  # Plan de continuité (PCA) — critique pour les soins
            "NIS2-D03-R02",  # Sauvegarde et restauration des DPI
            "NIS2-D02-R03",  # Notification incidents ANSSI / ASN
            "NIS2-D08-R02",  # Chiffrement des données de santé
            "NIS2-D04-R01",  # Évaluation des risques fournisseurs (DM connectés)
            "NIS2-D09-R03",  # Gestion des comptes à privilèges
        ],
        regulatory_context=(
            "Les établissements de santé (ES) et laboratoires sont Entités Essentielles NIS 2. "
            "Ils sont soumis en plus à : HDS (Hébergement Données de Santé), "
            "RGPD Art. 9 (données sensibles), signalement ANSSI + ASN (Agence du Numérique en Santé). "
            "Les cyberattaques ciblant les hôpitaux ont augmenté de 300% depuis 2020 (ANSSI)."
        ),
        key_threats=[
            "Ransomware ciblant les DPI (dossiers patients informatisés)",
            "Compromission des équipements biomédicaux connectés (IoMT)",
            "Interruption du PACS (imagerie médicale)",
            "Phishing sur le personnel soignant",
            "Accès non autorisé aux données de santé",
        ],
        specific_controls=[
            {
                "id": "SANTE-01",
                "title": "Certification HDS",
                "description": "Vérifier que les prestataires hébergeant des données de santé sont certifiés HDS.",
                "requirement_id": "NIS2-D04-R02",
                "priority": "CRITIQUE",
            },
            {
                "id": "SANTE-02",
                "title": "Segmentation réseau biomédicale",
                "description": "Isoler les équipements biomédicaux (IRM, moniteurs) sur un VLAN dédié sans accès Internet direct.",
                "requirement_id": "NIS2-D09-R01",
                "priority": "HAUTE",
            },
            {
                "id": "SANTE-03",
                "title": "Plan de continuité soins (mode dégradé papier)",
                "description": "Documenter et tester le fonctionnement en mode dégradé (DPI inaccessible) sans impact sur la prise en charge.",
                "requirement_id": "NIS2-D03-R01",
                "priority": "CRITIQUE",
            },
            {
                "id": "SANTE-04",
                "title": "Déclaration ASN (incidents significatifs)",
                "description": "Mettre en place la procédure de déclaration d'incidents NIS 2 à l'ASN dans les délais réglementaires (24h/72h).",
                "requirement_id": "NIS2-D02-R03",
                "priority": "CRITIQUE",
            },
        ],
    ),

    "finance": SectorProfile(
        sector_id="finance",
        sector_label="Finance & Assurance",
        domain_weights={
            "NIS2-D01": 1.4,   # Risques SI : DORA exige une cartographie exhaustive
            "NIS2-D02": 1.3,   # Gestion incidents : notification BCE/AMF en 4h
            "NIS2-D03": 1.5,   # Continuité : RTO/RPO stricts (Bâle III)
            "NIS2-D04": 1.6,   # Chaîne appro : DORA Titre V — TPP sous surveillance
            "NIS2-D05": 1.2,   # Dev SI : secure by design, pen tests obligatoires
            "NIS2-D06": 1.4,   # Audit : TLPT (Threat-Led Penetration Testing) DORA
            "NIS2-D07": 0.9,   # Hygiène : important mais équipes IT formées
            "NIS2-D08": 1.6,   # Cryptographie : données financières, PCI-DSS
            "NIS2-D09": 1.5,   # Contrôle accès : PAM, least privilege, SOD
            "NIS2-D10": 1.5,   # MFA : accès aux systèmes de paiement
        },
        priority_requirements=[
            "NIS2-D04-R01",  # Évaluation risques fournisseurs (DORA TPP)
            "NIS2-D04-R03",  # Surveillance continue fournisseurs
            "NIS2-D06-R01",  # Programme d'audit (TLPT)
            "NIS2-D08-R01",  # Politique cryptographie (PCI-DSS)
            "NIS2-D09-R03",  # Comptes à privilèges (PAM)
            "NIS2-D10-R01",  # MFA systèmes de paiement
            "NIS2-D03-R04",  # Tests du PCA
        ],
        regulatory_context=(
            "Les entités financières sont soumises simultanément à NIS 2 et à DORA "
            "(Digital Operational Resilience Act, applicable Jan. 2025). "
            "DORA impose des exigences renforcées sur les tiers prestataires ICT (TPP) "
            "et des tests TLPT (Threat-Led Penetration Testing) tous les 3 ans. "
            "NIS 2 + DORA = double reporting ANSSI + BCE/ACPR."
        ),
        key_threats=[
            "Attaques SWIFT / systèmes de paiement interbancaires",
            "Risque de concentration sur les TPP (cloud, core banking)",
            "Fraude interne via comptes à privilèges",
            "Attaques DDoS ciblant l'accessibilité des services",
            "Compromission de la chaîne d'appro logicielle (SolarWinds-like)",
        ],
        specific_controls=[
            {
                "id": "FINANCE-01",
                "title": "Registre des contrats TPP (DORA Art. 28)",
                "description": "Maintenir un registre de tous les prestataires ICT tiers avec classification criticité et plans de sortie.",
                "requirement_id": "NIS2-D04-R01",
                "priority": "CRITIQUE",
            },
            {
                "id": "FINANCE-02",
                "title": "TLPT (Threat-Led Penetration Testing)",
                "description": "Planifier et exécuter des tests de pénétration avancés guidés par la threat intelligence (TIBER-EU).",
                "requirement_id": "NIS2-D06-R01",
                "priority": "HAUTE",
            },
            {
                "id": "FINANCE-03",
                "title": "PAM (Privileged Access Management)",
                "description": "Déployer une solution PAM pour les accès aux systèmes core banking, SWIFT, et bases de données.",
                "requirement_id": "NIS2-D09-R03",
                "priority": "CRITIQUE",
            },
            {
                "id": "FINANCE-04",
                "title": "RTO/RPO documentés et testés",
                "description": "Définir et tester des objectifs RTO < 4h / RPO < 1h pour les systèmes de paiement critiques.",
                "requirement_id": "NIS2-D03-R04",
                "priority": "HAUTE",
            },
        ],
    ),

    "energie": SectorProfile(
        sector_id="energie",
        sector_label="Énergie",
        domain_weights={
            "NIS2-D01": 1.5,   # Risques SI : OT/IT convergence, risques physiques
            "NIS2-D02": 1.3,   # Gestion incidents : notification ANSSI + régulateurs énergie
            "NIS2-D03": 1.8,   # Continuité : coupures = impact sociétal majeur
            "NIS2-D04": 1.3,   # Chaîne appro : équipements OT souvent legacy
            "NIS2-D05": 1.0,   # Dev SI
            "NIS2-D06": 1.2,   # Audit : conformité ICS/SCADA
            "NIS2-D07": 1.1,   # Hygiène : ingénieurs terrain
            "NIS2-D08": 1.3,   # Cryptographie : communications SCADA
            "NIS2-D09": 1.5,   # Contrôle accès : accès distants OT, jumphost
            "NIS2-D10": 1.4,   # MFA : accès aux systèmes OT
        },
        priority_requirements=[
            "NIS2-D03-R01",  # PCA
            "NIS2-D09-R01",  # Contrôle d'accès OT
            "NIS2-D01-R03",  # Cartographie actifs (OT inclus)
            "NIS2-D10-R01",  # MFA accès distants
            "NIS2-D04-R01",  # Risques fournisseurs OT
        ],
        regulatory_context=(
            "Les opérateurs d'énergie (réseaux électricité, gaz, pétrole) sont Entités Essentielles NIS 2. "
            "Réglementation complémentaire : directive européenne sur la résilience des entités critiques (CER), "
            "règlement ENTSO-E pour les gestionnaires de réseaux. "
            "Enjeu majeur : convergence IT/OT — les systèmes SCADA historiquement isolés "
            "sont désormais connectés, exposant des infrastructures critiques aux cyberattaques."
        ),
        key_threats=[
            "Attaques sur les SCADA / systèmes de contrôle industriel (ICS)",
            "Compromission des accès distants OT (VPN, RDP)",
            "Sabotage physico-cyber (NotPetya, Ukraine 2015/2016)",
            "Ransomware ciblant les systèmes OT (Colonial Pipeline)",
            "Espionnage étatique sur les infrastructures énergétiques",
        ],
        specific_controls=[
            {
                "id": "ENERGIE-01",
                "title": "Segmentation IT/OT (DMZ industrielle)",
                "description": "Implémenter une DMZ entre les réseaux IT et OT avec inspection des flux et interdiction des accès directs.",
                "requirement_id": "NIS2-D09-R01",
                "priority": "CRITIQUE",
            },
            {
                "id": "ENERGIE-02",
                "title": "Inventaire des actifs OT (SCADA, automates)",
                "description": "Cartographier tous les équipements OT/ICS avec versions firmware, connectivité et criticité.",
                "requirement_id": "NIS2-D01-R03",
                "priority": "CRITIQUE",
            },
            {
                "id": "ENERGIE-03",
                "title": "Jumphost dédié pour accès OT",
                "description": "Forcer tous les accès distants OT via un jumphost MFA avec enregistrement des sessions.",
                "requirement_id": "NIS2-D10-R01",
                "priority": "HAUTE",
            },
        ],
    ),

    "transport": SectorProfile(
        sector_id="transport",
        sector_label="Transport & Logistique",
        domain_weights={
            "NIS2-D01": 1.2,
            "NIS2-D02": 1.3,
            "NIS2-D03": 1.6,   # Continuité : retards = impact économique et social
            "NIS2-D04": 1.4,   # Chaîne appro : systèmes embarqués, billettique
            "NIS2-D05": 1.1,
            "NIS2-D06": 1.0,
            "NIS2-D07": 1.1,
            "NIS2-D08": 1.1,
            "NIS2-D09": 1.3,
            "NIS2-D10": 1.2,
        },
        priority_requirements=[
            "NIS2-D03-R01",  # PCA
            "NIS2-D03-R02",  # Sauvegarde
            "NIS2-D04-R01",  # Fournisseurs (systèmes embarqués)
            "NIS2-D02-R02",  # Détection
        ],
        regulatory_context=(
            "Les opérateurs de transport (aérien, ferroviaire, maritime, routier) "
            "sont Entités Essentielles NIS 2. Réglementation complémentaire : "
            "EASA pour l'aviation, règlement maritime EU 2019/473 pour les GMDSS. "
            "Enjeu : systèmes embarqués (SCADA ferroviaire, ATC aviation) et "
            "continuité des opérations (retard = coût réputationnel et financier)."
        ),
        key_threats=[
            "Ransomware sur les systèmes billettiques et logistiques",
            "Attaques sur les systèmes de contrôle ferroviaire (ETCS/ERTMS)",
            "Spoofing GPS sur les flottes maritimes et aériennes",
            "Compromission des systèmes de gestion du trafic",
            "Fuite de données passagers",
        ],
        specific_controls=[
            {
                "id": "TRANSPORT-01",
                "title": "PCA transport : mode dégradé opérationnel",
                "description": "Définir les procédures opérationnelles en cas de cyberattaque (fonctionnement manuel, rerouting).",
                "requirement_id": "NIS2-D03-R01",
                "priority": "CRITIQUE",
            },
            {
                "id": "TRANSPORT-02",
                "title": "Sécurité des systèmes embarqués",
                "description": "Auditer la sécurité des systèmes embarqués (billettique, contrôle) et définir une politique de mise à jour.",
                "requirement_id": "NIS2-D05-R03",
                "priority": "HAUTE",
            },
        ],
    ),

    "numerique": SectorProfile(
        sector_id="numerique",
        sector_label="Numérique & Télécom",
        domain_weights={
            "NIS2-D01": 1.3,
            "NIS2-D02": 1.5,   # Incidents : prestataires num. = impact en cascade
            "NIS2-D03": 1.4,   # Continuité : SLA clients
            "NIS2-D04": 1.2,
            "NIS2-D05": 1.6,   # Dev SI : sécurité du code = produit livré aux clients
            "NIS2-D06": 1.3,
            "NIS2-D07": 1.0,
            "NIS2-D08": 1.3,   # Cryptographie : TLS, chiffrement données clients
            "NIS2-D09": 1.4,
            "NIS2-D10": 1.3,
        },
        priority_requirements=[
            "NIS2-D05-R01",  # Sécurité SDLC
            "NIS2-D05-R02",  # Gestion vulnérabilités
            "NIS2-D02-R02",  # Détection
            "NIS2-D08-R02",  # Chiffrement données clients
            "NIS2-D04-R02",  # Clauses contractuelles (chaîne logicielle)
        ],
        regulatory_context=(
            "Les prestataires numériques (cloud, éditeurs logiciels, opérateurs télécom) "
            "sont Entités Essentielles ou Importantes selon leur taille et leur périmètre. "
            "Enjeu spécifique : la sécurité de leur code et de leur infrastructure "
            "impacte directement leurs clients — une faille chez eux = faille chez N clients. "
            "Réglementation complémentaire : Cyber Resilience Act (CRA) pour les éditeurs logiciels."
        ),
        key_threats=[
            "Attaques supply chain logicielle (SolarWinds, XZ Utils)",
            "Exploitation de vulnérabilités dans les API exposées",
            "Abus d'infrastructure (hébergement C2, cryptomining)",
            "Compromission des pipelines CI/CD",
            "Fuite de données clients hébergées",
        ],
        specific_controls=[
            {
                "id": "NUMERIQUE-01",
                "title": "SAST/DAST dans le pipeline CI/CD",
                "description": "Intégrer l'analyse statique (SAST) et dynamique (DAST) dans le pipeline de déploiement.",
                "requirement_id": "NIS2-D05-R01",
                "priority": "HAUTE",
            },
            {
                "id": "NUMERIQUE-02",
                "title": "Programme de divulgation responsable (VDP)",
                "description": "Mettre en place une politique de divulgation responsable et un programme bug bounty.",
                "requirement_id": "NIS2-D05-R02",
                "priority": "MOYENNE",
            },
            {
                "id": "NUMERIQUE-03",
                "title": "SBOM (Software Bill of Materials)",
                "description": "Générer et maintenir un SBOM pour chaque composant logiciel livré (CRA requirement).",
                "requirement_id": "NIS2-D04-R01",
                "priority": "HAUTE",
            },
        ],
    ),

    "administration": SectorProfile(
        sector_id="administration",
        sector_label="Administration publique",
        domain_weights={
            "NIS2-D01": 1.4,
            "NIS2-D02": 1.2,
            "NIS2-D03": 1.5,
            "NIS2-D04": 1.2,
            "NIS2-D05": 0.9,
            "NIS2-D06": 1.3,   # Audit : obligations SSI administrations
            "NIS2-D07": 1.4,   # Hygiène : nombreux agents, sensibilisation clé
            "NIS2-D08": 1.2,   # Cryptographie : données régaliennes
            "NIS2-D09": 1.4,
            "NIS2-D10": 1.3,
        },
        priority_requirements=[
            "NIS2-D07-R01",  # Sensibilisation (agents publics)
            "NIS2-D09-R03",  # Comptes à privilèges
            "NIS2-D01-R04",  # Gouvernance et responsabilités
            "NIS2-D06-R01",  # Audit (RGSI)
        ],
        regulatory_context=(
            "Les administrations publiques (État, collectivités, établissements publics) "
            "sont Entités Importantes NIS 2. "
            "Réglementation complémentaire : RGSI (Référentiel Général de Sécurité), "
            "circulaires ANSSI, qualification SecNumCloud pour les données sensibles. "
            "Enjeu : ressources limitées, forte exposition aux attaques par phishing, "
            "et obligation de service public (continuité des services aux citoyens)."
        ),
        key_threats=[
            "Phishing ciblant les agents (identifiants, hameçonnage ransomware)",
            "Ransomware sur les SI administratifs (mairies, hôpitaux publics)",
            "Espionnage étatique sur les données régaliennes",
            "Compromission des systèmes de vote ou d'état civil",
            "Attaques DDoS sur les services numériques publics",
        ],
        specific_controls=[
            {
                "id": "ADMIN-01",
                "title": "Référentiel ANSSI / RGSI",
                "description": "Aligner le PSSI sur le RGSI v2 et les guides ANSSI sectoriels.",
                "requirement_id": "NIS2-D01-R01",
                "priority": "HAUTE",
            },
            {
                "id": "ADMIN-02",
                "title": "Formation obligatoire SSI agents",
                "description": "Former 100% des agents aux bonnes pratiques cyber (phishing, mots de passe) — Pix Cyber recommandé.",
                "requirement_id": "NIS2-D07-R01",
                "priority": "HAUTE",
            },
        ],
    ),

    "industrie": SectorProfile(
        sector_id="industrie",
        sector_label="Industrie & Fabrication",
        domain_weights={
            "NIS2-D01": 1.3,
            "NIS2-D02": 1.2,
            "NIS2-D03": 1.7,   # Continuité : arrêt chaîne prod = coût horaire élevé
            "NIS2-D04": 1.5,   # Chaîne appro : fournisseurs OEM, sous-traitants
            "NIS2-D05": 1.0,
            "NIS2-D06": 1.0,
            "NIS2-D07": 1.1,
            "NIS2-D08": 1.0,
            "NIS2-D09": 1.3,
            "NIS2-D10": 1.1,
        },
        priority_requirements=[
            "NIS2-D03-R01",  # PCA
            "NIS2-D04-R01",  # Risques fournisseurs
            "NIS2-D01-R03",  # Cartographie actifs OT
            "NIS2-D03-R02",  # Sauvegarde
        ],
        regulatory_context=(
            "Les industriels (secteurs critiques : automobile, aéronautique, chimie, pharmacie) "
            "peuvent être Entités Importantes NIS 2. "
            "Enjeu majeur : convergence IT/OT — les automates, robots et SCADA "
            "sont de plus en plus connectés aux ERP et à Internet. "
            "Réglementation complémentaire : ISO 27001, IEC 62443 pour les systèmes OT."
        ),
        key_threats=[
            "Ransomware sur les ERP et MES (arrêt de production)",
            "Espionnage industriel (vol de propriété intellectuelle)",
            "Sabotage des systèmes de contrôle (automates, robots)",
            "Attaques via les portails fournisseurs / EDI",
            "Compromission des équipements OT legacy (non patchables)",
        ],
        specific_controls=[
            {
                "id": "INDUSTRIE-01",
                "title": "Segmentation réseau OT/IT",
                "description": "Séparer physiquement ou logiquement les réseaux de production (OT) des réseaux bureautiques (IT).",
                "requirement_id": "NIS2-D09-R01",
                "priority": "CRITIQUE",
            },
            {
                "id": "INDUSTRIE-02",
                "title": "Plan de reprise de production post-incident",
                "description": "Documenter et tester la remise en route de la chaîne de production après une cyberattaque.",
                "requirement_id": "NIS2-D03-R01",
                "priority": "CRITIQUE",
            },
        ],
    ),

    "autre": SectorProfile(
        sector_id="autre",
        sector_label="Autre secteur",
        domain_weights={},  # Pondérations NIS 2 standard, sans surcharge
        priority_requirements=[
            "NIS2-D10-R01",  # MFA
            "NIS2-D02-R01",  # Procédure incidents
            "NIS2-D03-R01",  # PCA
            "NIS2-D09-R03",  # Comptes à privilèges
        ],
        regulatory_context=(
            "Entité soumise à NIS 2 sans secteur spécifique identifié. "
            "Appliquer le référentiel NIS 2 Art. 21 avec les 10 mesures de base. "
            "Contacter l'ANSSI pour vérifier votre qualification (EE ou EI)."
        ),
        key_threats=[
            "Ransomware (menace universelle)",
            "Phishing et compromission des comptes",
            "Vulnérabilités non corrigées",
            "Accès non autorisé via des tiers",
        ],
        specific_controls=[],
    ),
}


# ── Fonctions utilitaires ─────────────────────────────────────────────────────

def get_sector_profile(sector_id: str) -> SectorProfile:
    """Retourne le profil sectoriel, avec fallback sur 'autre'."""
    return SECTOR_PROFILES.get(sector_id, SECTOR_PROFILES["autre"])


def apply_sector_weights(domains: list, sector_id: str) -> list:
    """
    Applique les pondérations sectorielles sur les domaines NIS 2.

    Modifie les poids des domaines en place (multiplie par le facteur sectoriel).
    Retourne les domaines avec leurs nouveaux poids.

    Les pondérations NIS 2 standard sont préservées comme base,
    le facteur sectoriel est appliqué par multiplication.
    """
    profile = get_sector_profile(sector_id)
    if not profile.domain_weights:
        return domains  # secteur "autre" — poids standard

    for domain in domains:
        if domain.id in profile.domain_weights:
            factor = profile.domain_weights[domain.id]
            domain.weight = round(domain.weight * factor, 3)

    return domains


def get_sector_report(sector_id: str, assessment_result: dict) -> dict:
    """
    Génère un rapport sectoriel enrichi à partir d'un résultat d'évaluation.

    Ajoute :
    - Les priorités sectorielles
    - Les gaps sur les exigences prioritaires du secteur
    - Les contrôles spécifiques recommandés
    - Le contexte réglementaire
    """
    profile = get_sector_profile(sector_id)

    # Identifier les gaps sur les exigences prioritaires
    all_gaps = {g.get("requirement_id") or g.get("id") for g in assessment_result.get("gaps", [])}
    priority_gaps = [
        req_id for req_id in profile.priority_requirements
        if req_id in all_gaps
    ]

    return {
        "sector": {
            "id": profile.sector_id,
            "label": profile.sector_label,
            "regulatory_context": profile.regulatory_context,
        },
        "key_threats": profile.key_threats,
        "priority_requirements": profile.priority_requirements,
        "priority_gaps": priority_gaps,
        "priority_gap_count": len(priority_gaps),
        "specific_controls": profile.specific_controls,
        "sector_alert": (
            f"{len(priority_gaps)} gap(s) sur les {len(profile.priority_requirements)} "
            f"exigences prioritaires {profile.sector_label}."
            if priority_gaps else
            f"Toutes les exigences prioritaires {profile.sector_label} sont couvertes."
        ),
    }
