"""
COMPASS — Financial Impact Database
Base de données des coûts d'incidents et scénarios de risque.

Toutes les données sont sourcées publiquement :
- IBM Cost of a Data Breach Report 2024/2025
- Rapports annuels ANSSI (Panorama de la cybermenace)
- Directive NIS 2 (UE 2022/2555) — barème des sanctions
- Coveware Quarterly Ransomware Reports

Pourquoi ces sources ?
Parce qu'un RSSI qui présente des chiffres à sa direction doit
pouvoir les défendre. "Ce chiffre vient du rapport IBM 2024" est
un argument. "L'IA a estimé" n'en est pas un.

Architecture :
- OrganizationProfile : taille, secteur, CA de l'organisation
- RiskScenario : un type d'incident avec sa probabilité et son coût
- SCENARIO_DATABASE : mapping gap NIS 2 → scénarios applicables
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class OrgSize(Enum):
    """
    Taille de l'organisation.
    
    Pourquoi 3 catégories ?
    Parce que l'impact financier d'un ransomware sur une PME de 60 personnes
    n'est pas le même que sur un groupe CAC40. Les sources (IBM, ANSSI)
    segmentent leurs données de la même façon.
    """
    PME = "pme"            # 50-250 salariés
    ETI = "eti"            # 250-5000 salariés
    GRAND_GROUPE = "grand"  # 5000+ salariés

    @property
    def label(self) -> str:
        return {
            "pme": "PME (50-250 salariés)",
            "eti": "ETI (250-5000 salariés)",
            "grand": "Grand groupe (5000+ salariés)",
        }[self.value]


class Sector(Enum):
    """
    Secteur d'activité.
    
    NIS 2 distingue les entités essentielles et importantes.
    Le secteur influence :
    - Le montant des amendes (10M€ vs 7M€)
    - La probabilité de certains incidents (santé = cible ransomware)
    - Le coût par enregistrement (finance > industrie)
    """
    SANTE = "sante"
    FINANCE = "finance"
    ENERGIE = "energie"
    INDUSTRIE = "industrie"
    NUMERIQUE = "numerique"
    TRANSPORT = "transport"
    ADMINISTRATION = "administration"
    AUTRE = "autre"

    @property
    def label(self) -> str:
        labels = {
            "sante": "Santé",
            "finance": "Finance & Assurance",
            "energie": "Énergie",
            "industrie": "Industrie & Fabrication",
            "numerique": "Numérique & Télécom",
            "transport": "Transport & Logistique",
            "administration": "Administration publique",
            "autre": "Autre secteur",
        }
        return labels[self.value]

    @property
    def is_essential(self) -> bool:
        """Les secteurs essentiels ont des sanctions plus élevées (Art. 21)."""
        return self.value in ("sante", "finance", "energie", "numerique", "transport", "administration")


@dataclass
class OrganizationProfile:
    """
    Profil de l'organisation évaluée.
    
    Ces informations permettent de moduler les calculs financiers.
    Sans profil, on utilise des valeurs médianes.
    """
    name: str = "Mon Organisation"
    size: OrgSize = OrgSize.ETI
    sector: Sector = Sector.AUTRE
    annual_revenue: Optional[float] = None  # CA annuel en euros
    employee_count: Optional[int] = None
    data_records: Optional[int] = None      # Nb d'enregistrements de données

    @property
    def max_nis2_fine(self) -> float:
        """
        Amende maximale NIS 2 applicable.
        
        Art. 34 : 
        - Entités essentielles : max(10M€, 2% du CA mondial)
        - Entités importantes : max(7M€, 1.4% du CA mondial)
        
        C'est le texte de la directive — pas une estimation.
        """
        if self.sector.is_essential:
            base = 10_000_000
            pct = 0.02
        else:
            base = 7_000_000
            pct = 0.014

        if self.annual_revenue:
            return max(base, self.annual_revenue * pct)
        return base


class IncidentType(Enum):
    """
    Types d'incidents cyber avec leurs coûts de référence.
    
    Chaque type a un coût moyen par taille d'organisation.
    Ces coûts incluent : réponse à incident, restauration,
    perte d'exploitation, notification, impact réputation.
    """
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    UNAVAILABILITY = "unavailability"
    COMPLIANCE_FINE = "compliance_fine"
    SUPPLY_CHAIN = "supply_chain"
    IDENTITY_COMPROMISE = "identity_compromise"

    @property
    def label(self) -> str:
        return {
            "ransomware": "Ransomware",
            "data_breach": "Fuite de données",
            "unavailability": "Indisponibilité du SI",
            "compliance_fine": "Amende réglementaire NIS 2",
            "supply_chain": "Compromission chaîne d'approvisionnement",
            "identity_compromise": "Compromission de comptes",
        }[self.value]


# ═══════════════════════════════════════════════════════
# COÛTS DE RÉFÉRENCE PAR TYPE D'INCIDENT ET TAILLE
# ═══════════════════════════════════════════════════════
#
# Sources :
# [IBM] IBM Cost of a Data Breach Report 2024
#       - Coût moyen global : 4.88M$ (~4.5M€)
#       - Coût par enregistrement : 165$ (~152€)
#       - France : 4.3M€ en moyenne
#
# [ANSSI] Panorama de la cybermenace 2023-2024
#         - PME : impact moyen ransomware 50K-500K€
#         - ETI : 500K-5M€
#         - Grands groupes : 5M-50M€
#
# [COVEWARE] Quarterly Ransomware Report Q4 2024
#            - Rançon moyenne : 568K$ (~525K€)
#            - Coût total moyen (incluant downtime) : 1.5M$
#
# [NIS2] Directive (UE) 2022/2555, Article 34
#        - Entités essentielles : max(10M€, 2% CA)
#        - Entités importantes : max(7M€, 1.4% CA)

COST_DATABASE = {
    IncidentType.RANSOMWARE: {
        OrgSize.PME: {
            "cost_low": 50_000,
            "cost_mid": 250_000,
            "cost_high": 500_000,
            "source": "ANSSI Panorama 2024 — impact PME",
        },
        OrgSize.ETI: {
            "cost_low": 500_000,
            "cost_mid": 1_500_000,
            "cost_high": 5_000_000,
            "source": "ANSSI + Coveware Q4 2024",
        },
        OrgSize.GRAND_GROUPE: {
            "cost_low": 5_000_000,
            "cost_mid": 15_000_000,
            "cost_high": 50_000_000,
            "source": "IBM Cost of a Data Breach 2024",
        },
    },
    IncidentType.DATA_BREACH: {
        OrgSize.PME: {
            "cost_low": 30_000,
            "cost_mid": 150_000,
            "cost_high": 500_000,
            "source": "IBM 2024 — 152€/enregistrement, ~1000 records PME",
        },
        OrgSize.ETI: {
            "cost_low": 200_000,
            "cost_mid": 1_000_000,
            "cost_high": 4_000_000,
            "source": "IBM 2024 — France 4.3M€ moyen",
        },
        OrgSize.GRAND_GROUPE: {
            "cost_low": 1_000_000,
            "cost_mid": 4_500_000,
            "cost_high": 15_000_000,
            "source": "IBM Cost of a Data Breach 2024 — large enterprises",
        },
    },
    IncidentType.UNAVAILABILITY: {
        OrgSize.PME: {
            "cost_low": 10_000,
            "cost_mid": 50_000,
            "cost_high": 200_000,
            "source": "Estimation — perte exploitation 1-5 jours PME",
        },
        OrgSize.ETI: {
            "cost_low": 100_000,
            "cost_mid": 500_000,
            "cost_high": 2_000_000,
            "source": "Estimation — perte exploitation 1-5 jours ETI",
        },
        OrgSize.GRAND_GROUPE: {
            "cost_low": 500_000,
            "cost_mid": 2_000_000,
            "cost_high": 10_000_000,
            "source": "Gartner — coût moyen downtime 5600$/min",
        },
    },
    IncidentType.COMPLIANCE_FINE: {
        OrgSize.PME: {
            "cost_low": 50_000,
            "cost_mid": 500_000,
            "cost_high": 7_000_000,
            "source": "NIS 2 Art. 34 — entités importantes",
        },
        OrgSize.ETI: {
            "cost_low": 500_000,
            "cost_mid": 2_000_000,
            "cost_high": 10_000_000,
            "source": "NIS 2 Art. 34 — entités essentielles",
        },
        OrgSize.GRAND_GROUPE: {
            "cost_low": 2_000_000,
            "cost_mid": 10_000_000,
            "cost_high": 50_000_000,
            "source": "NIS 2 Art. 34 — max(10M€, 2% CA mondial)",
        },
    },
    IncidentType.SUPPLY_CHAIN: {
        OrgSize.PME: {
            "cost_low": 20_000,
            "cost_mid": 100_000,
            "cost_high": 500_000,
            "source": "ENISA Supply Chain Threat Landscape 2024",
        },
        OrgSize.ETI: {
            "cost_low": 200_000,
            "cost_mid": 1_000_000,
            "cost_high": 5_000_000,
            "source": "ENISA + IBM — supply chain breach premium +12%",
        },
        OrgSize.GRAND_GROUPE: {
            "cost_low": 1_000_000,
            "cost_mid": 5_000_000,
            "cost_high": 20_000_000,
            "source": "IBM 2024 — supply chain attacks cost premium",
        },
    },
    IncidentType.IDENTITY_COMPROMISE: {
        OrgSize.PME: {
            "cost_low": 15_000,
            "cost_mid": 75_000,
            "cost_high": 300_000,
            "source": "IBM 2024 — stolen credentials attack vector",
        },
        OrgSize.ETI: {
            "cost_low": 100_000,
            "cost_mid": 500_000,
            "cost_high": 2_000_000,
            "source": "IBM 2024 — identity-based attacks",
        },
        OrgSize.GRAND_GROUPE: {
            "cost_low": 500_000,
            "cost_mid": 2_500_000,
            "cost_high": 10_000_000,
            "source": "IBM 2024 — compromised credentials avg 4.81M$",
        },
    },
}


# ═══════════════════════════════════════════════════════
# MAPPING GAP NIS 2 → SCÉNARIOS DE RISQUE
# ═══════════════════════════════════════════════════════
#
# Chaque sous-exigence NIS 2, si elle est un gap (niveau 0 ou 1),
# expose l'organisation à des scénarios d'incident spécifiques.
#
# probability_base : probabilité annuelle de l'incident si le gap existe
# Ces probabilités sont des estimations basées sur les statistiques
# d'incidents publiées (ANSSI, IBM, Verizon DBIR).
#
# La probabilité réelle dépend du contexte — ces valeurs sont des
# ordres de grandeur pour le calcul, pas des prédictions exactes.

GAP_TO_RISK_SCENARIOS = {
    # D01 — Risques & PSSI
    "NIS2-D01-R01": {
        "scenarios": [
            {"type": IncidentType.COMPLIANCE_FINE, "probability_base": 0.15,
             "rationale": "Absence de PSSI = non-conformité directe NIS 2, risque de sanction en cas de contrôle"},
            {"type": IncidentType.RANSOMWARE, "probability_base": 0.10,
             "rationale": "Sans politique de sécurité, les mesures de protection sont incohérentes"},
        ]
    },
    "NIS2-D01-R02": {
        "scenarios": [
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.12,
             "rationale": "Sans analyse de risques, les actifs critiques ne sont pas identifiés ni protégés"},
        ]
    },
    "NIS2-D01-R03": {
        "scenarios": [
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.10,
             "rationale": "Sans cartographie, des actifs critiques peuvent être exposés sans le savoir"},
            {"type": IncidentType.RANSOMWARE, "probability_base": 0.08,
             "rationale": "Actifs non inventoriés = surface d'attaque inconnue"},
        ]
    },
    "NIS2-D01-R04": {
        "scenarios": [
            {"type": IncidentType.COMPLIANCE_FINE, "probability_base": 0.10,
             "rationale": "NIS 2 Art. 20 exige que la direction supervise — absence = non-conformité"},
        ]
    },
    "NIS2-D01-R05": {
        "scenarios": [
            {"type": IncidentType.COMPLIANCE_FINE, "probability_base": 0.12,
             "rationale": "Sans engagement budgétaire formalisé, les mesures NIS 2 restent non financées = non-conformité structurelle"},
            {"type": IncidentType.RANSOMWARE, "probability_base": 0.07,
             "rationale": "Sous-investissement chronique en sécurité augmente la probabilité d'incident grave"},
        ]
    },

    # D02 — Gestion des incidents
    "NIS2-D02-R01": {
        "scenarios": [
            {"type": IncidentType.RANSOMWARE, "probability_base": 0.15,
             "rationale": "Sans procédure d'incident, le temps de réponse augmente et l'impact s'aggrave"},
            {"type": IncidentType.UNAVAILABILITY, "probability_base": 0.20,
             "rationale": "Réponse désorganisée = durée d'indisponibilité plus longue"},
        ]
    },
    "NIS2-D02-R02": {
        "scenarios": [
            {"type": IncidentType.RANSOMWARE, "probability_base": 0.12,
             "rationale": "Sans détection (SIEM/EDR), les attaquants opèrent plus longtemps sans être repérés"},
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.15,
             "rationale": "IBM 2024 : les breaches détectées tardivement coûtent 35% de plus"},
        ]
    },
    "NIS2-D02-R03": {
        "scenarios": [
            {"type": IncidentType.COMPLIANCE_FINE, "probability_base": 0.20,
             "rationale": "Non-notification dans les 24h/72h = infraction directe NIS 2 Art. 23"},
        ]
    },
    "NIS2-D02-R04": {
        "scenarios": [
            {"type": IncidentType.RANSOMWARE, "probability_base": 0.05,
             "rationale": "Sans REX, les mêmes erreurs se répètent — probabilité de récidive"},
        ]
    },

    # D03 — Continuité d'activité
    "NIS2-D03-R01": {
        "scenarios": [
            {"type": IncidentType.UNAVAILABILITY, "probability_base": 0.25,
             "rationale": "Sans PCA, un incident majeur entraîne un arrêt prolongé non maîtrisé"},
        ]
    },
    "NIS2-D03-R02": {
        "scenarios": [
            {"type": IncidentType.RANSOMWARE, "probability_base": 0.20,
             "rationale": "Sans sauvegardes testées, un ransomware peut être fatal — pas de restauration possible"},
            {"type": IncidentType.UNAVAILABILITY, "probability_base": 0.15,
             "rationale": "Sauvegardes non testées = RPO/RTO incertains"},
        ]
    },
    "NIS2-D03-R03": {
        "scenarios": [
            {"type": IncidentType.UNAVAILABILITY, "probability_base": 0.10,
             "rationale": "Sans gestion de crise, la coordination est chaotique en situation réelle"},
        ]
    },
    "NIS2-D03-R04": {
        "scenarios": [
            {"type": IncidentType.UNAVAILABILITY, "probability_base": 0.18,
             "rationale": "Un PCA non testé est un PCA non fiable — les exercices révèlent les lacunes avant la crise réelle"},
            {"type": IncidentType.COMPLIANCE_FINE, "probability_base": 0.08,
             "rationale": "NIS 2 exige la validation effective des plans de continuité, pas seulement leur existence"},
        ]
    },

    # D04 — Chaîne d'approvisionnement
    "NIS2-D04-R01": {
        "scenarios": [
            {"type": IncidentType.SUPPLY_CHAIN, "probability_base": 0.12,
             "rationale": "Fournisseurs non évalués = vecteur d'attaque non contrôlé (cf. SolarWinds, Kaseya)"},
        ]
    },
    "NIS2-D04-R02": {
        "scenarios": [
            {"type": IncidentType.SUPPLY_CHAIN, "probability_base": 0.08,
             "rationale": "Sans clauses contractuelles, aucun recours en cas d'incident fournisseur"},
            {"type": IncidentType.COMPLIANCE_FINE, "probability_base": 0.10,
             "rationale": "NIS 2 Art. 21(2)(d) exige explicitement la sécurité supply chain"},
        ]
    },
    "NIS2-D04-R03": {
        "scenarios": [
            {"type": IncidentType.SUPPLY_CHAIN, "probability_base": 0.06,
             "rationale": "Sans surveillance continue, une dégradation chez un fournisseur passe inaperçue"},
        ]
    },

    # D05 — Développement & maintenance
    "NIS2-D05-R01": {
        "scenarios": [
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.12,
             "rationale": "Sans DevSecOps, les vulnérabilités applicatives arrivent en production"},
        ]
    },
    "NIS2-D05-R02": {
        "scenarios": [
            {"type": IncidentType.RANSOMWARE, "probability_base": 0.15,
             "rationale": "Vulnérabilités non patchées = porte d'entrée principale des attaquants (Verizon DBIR)"},
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.12,
             "rationale": "Vulnérabilités exploitées pour exfiltration de données"},
        ]
    },
    "NIS2-D05-R03": {
        "scenarios": [
            {"type": IncidentType.UNAVAILABILITY, "probability_base": 0.08,
             "rationale": "Changements non contrôlés peuvent introduire des régressions ou des failles"},
        ]
    },

    # D06 — Évaluation efficacité
    "NIS2-D06-R01": {
        "scenarios": [
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.10,
             "rationale": "Sans audit/pentest, des vulnérabilités critiques restent non découvertes"},
        ]
    },
    "NIS2-D06-R02": {
        "scenarios": [
            {"type": IncidentType.COMPLIANCE_FINE, "probability_base": 0.08,
             "rationale": "Sans KPI sécurité, impossible de démontrer l'efficacité aux régulateurs"},
        ]
    },

    # D07 — Hygiène cyber & formation
    "NIS2-D07-R01": {
        "scenarios": [
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.15,
             "rationale": "Le phishing est le vecteur n°1 — sans sensibilisation, le taux de clic reste élevé"},
        ]
    },
    "NIS2-D07-R02": {
        "scenarios": [
            {"type": IncidentType.IDENTITY_COMPROMISE, "probability_base": 0.10,
             "rationale": "Admins non formés = erreurs de configuration, exposition accidentelle"},
        ]
    },
    "NIS2-D07-R03": {
        "scenarios": [
            {"type": IncidentType.IDENTITY_COMPROMISE, "probability_base": 0.12,
             "rationale": "Mots de passe faibles, sessions non verrouillées = compromission facilitée"},
        ]
    },
    "NIS2-D07-R04": {
        "scenarios": [
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.08,
             "rationale": "Sans mesure d'efficacité de la sensibilisation, les lacunes persistent invisiblement"},
            {"type": IncidentType.COMPLIANCE_FINE, "probability_base": 0.06,
             "rationale": "NIS 2 Art. 21(2)(g) exige des mesures de cyberhygiène mesurables"},
        ]
    },
    "NIS2-D07-R05": {
        "scenarios": [
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.10,
             "rationale": "Sans filtrage Internet et contrôle des périphériques, les vecteurs d'entrée restent ouverts"},
            {"type": IncidentType.RANSOMWARE, "probability_base": 0.08,
             "rationale": "Périphériques non contrôlés = vecteur de propagation latérale du ransomware"},
        ]
    },

    # D08 — Cryptographie
    "NIS2-D08-R01": {
        "scenarios": [
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.08,
             "rationale": "Sans politique crypto, des données peuvent transiter en clair"},
        ]
    },
    "NIS2-D08-R02": {
        "scenarios": [
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.10,
             "rationale": "Données sensibles non chiffrées = impact maximal en cas d'exfiltration"},
        ]
    },

    # D09 — Contrôle d'accès & actifs
    "NIS2-D09-R01": {
        "scenarios": [
            {"type": IncidentType.IDENTITY_COMPROMISE, "probability_base": 0.15,
             "rationale": "Sans moindre privilège, un compte compromis donne accès à tout"},
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.10,
             "rationale": "Accès excessifs = surface de données exposées plus large"},
        ]
    },
    "NIS2-D09-R02": {
        "scenarios": [
            {"type": IncidentType.IDENTITY_COMPROMISE, "probability_base": 0.12,
             "rationale": "Comptes non révoqués au départ = accès fantômes exploitables"},
        ]
    },
    "NIS2-D09-R03": {
        "scenarios": [
            {"type": IncidentType.IDENTITY_COMPROMISE, "probability_base": 0.18,
             "rationale": "Comptes admin non sécurisés = cible prioritaire des attaquants"},
            {"type": IncidentType.RANSOMWARE, "probability_base": 0.12,
             "rationale": "Compromission d'un admin = déploiement de ransomware sur tout le SI"},
        ]
    },
    "NIS2-D09-R04": {
        "scenarios": [
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.06,
             "rationale": "Actifs non inventoriés = shadow IT non protégé"},
        ]
    },

    # D10 — MFA & communications
    "NIS2-D10-R01": {
        "scenarios": [
            {"type": IncidentType.IDENTITY_COMPROMISE, "probability_base": 0.20,
             "rationale": "Sans MFA, un mot de passe volé suffit — c'est le vecteur n°1 (IBM 2024)"},
            {"type": IncidentType.RANSOMWARE, "probability_base": 0.10,
             "rationale": "Accès initial par credentials volés sans MFA → déploiement ransomware"},
        ]
    },
    "NIS2-D10-R02": {
        "scenarios": [
            {"type": IncidentType.DATA_BREACH, "probability_base": 0.06,
             "rationale": "Communications non chiffrées = interception possible (MITM)"},
        ]
    },
    "NIS2-D10-R03": {
        "scenarios": [
            {"type": IncidentType.UNAVAILABILITY, "probability_base": 0.05,
             "rationale": "Sans canal d'urgence, la coordination de crise est compromise si le SI tombe"},
        ]
    },
}
