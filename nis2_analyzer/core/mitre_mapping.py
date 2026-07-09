"""
COMPASS — Mapping NIS2 / MITRE ATT&CK
Associe chaque exigence NIS2 aux techniques d'attaque MITRE ATT&CK v14
qui deviennent exploitables en cas de non-conformité.

Logique : un gap de conformité (maturity < 3) élargit la surface d'attaque.
Ce module quantifie cette exposition en termes de tactiques et techniques
MITRE, permettant au RSSI de parler le même langage que les équipes SOC/CTI.
"""

from __future__ import annotations
from dataclasses import dataclass, field


# ── Structures de données ─────────────────────────────────────────────────────

@dataclass
class MitreTechnique:
    technique_id: str          # ex: "T1078"
    name: str
    tactic: str                # ex: "Initial Access"
    tactic_id: str             # ex: "TA0001"
    url: str
    description: str           # Contexte NIS2 spécifique


@dataclass
class NIS2MitreLink:
    requirement_id: str
    requirement_title: str
    domain_title: str
    techniques: list[MitreTechnique]
    attack_scenario: str       # Scénario narratif concret
    gap_impact: str            # Ce que le gap permet à l'attaquant
    severity: str              # "CRITICAL" | "HIGH" | "MEDIUM"


@dataclass
class MitreMappingReport:
    org_name: str
    total_gaps: int
    critical_links: int        # Liens NIS2-MITRE de sévérité CRITICAL
    high_links: int
    medium_links: int
    top_tactics: list[dict]    # Tactiques les plus couvertes par les gaps
    top_techniques: list[dict] # Techniques les plus fréquentes
    links: list[NIS2MitreLink]
    coverage_note: str

    def to_dict(self) -> dict:
        return {
            "org_name": self.org_name,
            "total_gaps": self.total_gaps,
            "critical_links": self.critical_links,
            "high_links": self.high_links,
            "medium_links": self.medium_links,
            "top_tactics": self.top_tactics,
            "top_techniques": self.top_techniques,
            "coverage_note": self.coverage_note,
            "links": [
                {
                    "requirement_id": lnk.requirement_id,
                    "requirement_title": lnk.requirement_title,
                    "domain_title": lnk.domain_title,
                    "severity": lnk.severity,
                    "attack_scenario": lnk.attack_scenario,
                    "gap_impact": lnk.gap_impact,
                    "techniques": [
                        {
                            "technique_id": t.technique_id,
                            "name": t.name,
                            "tactic": t.tactic,
                            "tactic_id": t.tactic_id,
                            "url": t.url,
                            "description": t.description,
                        }
                        for t in lnk.techniques
                    ],
                }
                for lnk in self.links
            ],
        }


# ── Base de connaissances NIS2 → MITRE ATT&CK ────────────────────────────────

# Toutes les techniques référencées (MITRE ATT&CK v14)
_T: dict[str, MitreTechnique] = {
    "T1078": MitreTechnique(
        "T1078", "Valid Accounts", "Initial Access", "TA0001",
        "https://attack.mitre.org/techniques/T1078/",
        "Sans MFA, les comptes compromis suffisent pour un accès persistant.",
    ),
    "T1078.004": MitreTechnique(
        "T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access", "TA0001",
        "https://attack.mitre.org/techniques/T1078/004/",
        "Les comptes cloud sans MFA sont la cible principale des campagnes de credential stuffing.",
    ),
    "T1110": MitreTechnique(
        "T1110", "Brute Force", "Credential Access", "TA0006",
        "https://attack.mitre.org/techniques/T1110/",
        "L'absence de politique de verrouillage facilite les attaques par force brute.",
    ),
    "T1110.003": MitreTechnique(
        "T1110.003", "Password Spraying", "Credential Access", "TA0006",
        "https://attack.mitre.org/techniques/T1110/003/",
        "Le password spraying cible les comptes sans politique de mot de passe forte.",
    ),
    "T1566": MitreTechnique(
        "T1566", "Phishing", "Initial Access", "TA0001",
        "https://attack.mitre.org/techniques/T1566/",
        "Sans formation utilisateur, le phishing reste le vecteur d'entrée le plus efficace.",
    ),
    "T1566.001": MitreTechnique(
        "T1566.001", "Spearphishing Attachment", "Initial Access", "TA0001",
        "https://attack.mitre.org/techniques/T1566/001/",
        "Les pièces jointes malveillantes exploitent l'absence de sensibilisation.",
    ),
    "T1566.002": MitreTechnique(
        "T1566.002", "Spearphishing Link", "Initial Access", "TA0001",
        "https://attack.mitre.org/techniques/T1566/002/",
        "Les liens de phishing contournent les filtres sans formation utilisateur.",
    ),
    "T1190": MitreTechnique(
        "T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001",
        "https://attack.mitre.org/techniques/T1190/",
        "Les applications non patchées exposent des vulnérabilités connues exploitables.",
    ),
    "T1203": MitreTechnique(
        "T1203", "Exploitation for Client Execution", "Execution", "TA0002",
        "https://attack.mitre.org/techniques/T1203/",
        "Les postes sans gestion des correctifs sont vulnérables aux exploits clients.",
    ),
    "T1059": MitreTechnique(
        "T1059", "Command and Scripting Interpreter", "Execution", "TA0002",
        "https://attack.mitre.org/techniques/T1059/",
        "L'absence de whitelisting applicatif permet l'exécution de scripts malveillants.",
    ),
    "T1053": MitreTechnique(
        "T1053", "Scheduled Task/Job", "Execution", "TA0002",
        "https://attack.mitre.org/techniques/T1053/",
        "Les tâches planifiées malveillantes persistent sans détection sur des systèmes non surveillés.",
    ),
    "T1543": MitreTechnique(
        "T1543", "Create or Modify System Process", "Persistence", "TA0003",
        "https://attack.mitre.org/techniques/T1543/",
        "Sans contrôle des processus système, la persistance est triviale à établir.",
    ),
    "T1133": MitreTechnique(
        "T1133", "External Remote Services", "Initial Access", "TA0001",
        "https://attack.mitre.org/techniques/T1133/",
        "Les services d'accès distant non sécurisés (VPN, RDP) sont des portes d'entrée directes.",
    ),
    "T1021": MitreTechnique(
        "T1021", "Remote Services", "Lateral Movement", "TA0008",
        "https://attack.mitre.org/techniques/T1021/",
        "La segmentation absente permet le mouvement latéral via les services distants.",
    ),
    "T1021.001": MitreTechnique(
        "T1021.001", "Remote Desktop Protocol", "Lateral Movement", "TA0008",
        "https://attack.mitre.org/techniques/T1021/001/",
        "RDP exposé sans MFA ni segmentation est le vecteur privilégié des ransomwares.",
    ),
    "T1562": MitreTechnique(
        "T1562", "Impair Defenses", "Defense Evasion", "TA0005",
        "https://attack.mitre.org/techniques/T1562/",
        "Sans monitoring, la désactivation des défenses passe inaperçue.",
    ),
    "T1562.001": MitreTechnique(
        "T1562.001", "Disable or Modify Tools", "Defense Evasion", "TA0005",
        "https://attack.mitre.org/techniques/T1562/001/",
        "L'antivirus peut être désactivé sans alerte sur des systèmes sans SIEM.",
    ),
    "T1070": MitreTechnique(
        "T1070", "Indicator Removal", "Defense Evasion", "TA0005",
        "https://attack.mitre.org/techniques/T1070/",
        "Sans conservation des logs, l'attaquant peut effacer ses traces.",
    ),
    "T1070.001": MitreTechnique(
        "T1070.001", "Clear Windows Event Logs", "Defense Evasion", "TA0005",
        "https://attack.mitre.org/techniques/T1070/001/",
        "Les journaux Windows non centralisés peuvent être supprimés par l'attaquant.",
    ),
    "T1485": MitreTechnique(
        "T1485", "Data Destruction", "Impact", "TA0040",
        "https://attack.mitre.org/techniques/T1485/",
        "Sans sauvegardes testées, une destruction de données est irréversible.",
    ),
    "T1486": MitreTechnique(
        "T1486", "Data Encrypted for Impact", "Impact", "TA0040",
        "https://attack.mitre.org/techniques/T1486/",
        "Le ransomware est l'exploitation directe de l'absence de sauvegardes offline.",
    ),
    "T1490": MitreTechnique(
        "T1490", "Inhibit System Recovery", "Impact", "TA0040",
        "https://attack.mitre.org/techniques/T1490/",
        "Les attaquants suppriment les copies shadow pour bloquer la récupération.",
    ),
    "T1489": MitreTechnique(
        "T1489", "Service Stop", "Impact", "TA0040",
        "https://attack.mitre.org/techniques/T1489/",
        "L'arrêt de services critiques sans PCA/PRA entraîne une indisponibilité prolongée.",
    ),
    "T1496": MitreTechnique(
        "T1496", "Resource Hijacking", "Impact", "TA0040",
        "https://attack.mitre.org/techniques/T1496/",
        "Les ressources cloud non surveillées sont détournées pour le cryptominage.",
    ),
    "T1040": MitreTechnique(
        "T1040", "Network Sniffing", "Credential Access", "TA0006",
        "https://attack.mitre.org/techniques/T1040/",
        "Sans chiffrement des communications internes, l'interception est triviale.",
    ),
    "T1557": MitreTechnique(
        "T1557", "Adversary-in-the-Middle", "Credential Access", "TA0006",
        "https://attack.mitre.org/techniques/T1557/",
        "L'absence de chiffrement de transit permet les attaques man-in-the-middle.",
    ),
    "T1005": MitreTechnique(
        "T1005", "Data from Local System", "Collection", "TA0009",
        "https://attack.mitre.org/techniques/T1005/",
        "Sans DLP, l'exfiltration de données locales ne déclenche aucune alerte.",
    ),
    "T1048": MitreTechnique(
        "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "TA0010",
        "https://attack.mitre.org/techniques/T1048/",
        "Sans contrôle des canaux de sortie, l'exfiltration via DNS/ICMP est indétectable.",
    ),
    "T1567": MitreTechnique(
        "T1567", "Exfiltration Over Web Service", "Exfiltration", "TA0010",
        "https://attack.mitre.org/techniques/T1567/",
        "L'exfiltration vers des services cloud légitimes est invisible sans inspection DLP.",
    ),
    "T1195": MitreTechnique(
        "T1195", "Supply Chain Compromise", "Initial Access", "TA0001",
        "https://attack.mitre.org/techniques/T1195/",
        "Un fournisseur non audité est un vecteur d'intrusion indirect dans votre SI.",
    ),
    "T1195.002": MitreTechnique(
        "T1195.002", "Compromise Software Supply Chain", "Initial Access", "TA0001",
        "https://attack.mitre.org/techniques/T1195/002/",
        "Les mises à jour logicielles de fournisseurs non contrôlés peuvent être malveillantes.",
    ),
    "T1072": MitreTechnique(
        "T1072", "Software Deployment Tools", "Execution", "TA0002",
        "https://attack.mitre.org/techniques/T1072/",
        "Les outils de déploiement tiers peuvent être détournés pour propager du code malveillant.",
    ),
    "T1078.001": MitreTechnique(
        "T1078.001", "Default Accounts", "Defense Evasion", "TA0005",
        "https://attack.mitre.org/techniques/T1078/001/",
        "Les comptes par défaut non désactivés sont exploités dans les premières heures d'une intrusion.",
    ),
    "T1068": MitreTechnique(
        "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "TA0004",
        "https://attack.mitre.org/techniques/T1068/",
        "Les vulnérabilités non corrigées permettent l'élévation de privilèges vers SYSTEM/root.",
    ),
    "T1055": MitreTechnique(
        "T1055", "Process Injection", "Defense Evasion", "TA0005",
        "https://attack.mitre.org/techniques/T1055/",
        "L'injection de code dans des processus légitimes contourne les solutions EDR basiques.",
    ),
    "T1027": MitreTechnique(
        "T1027", "Obfuscated Files or Information", "Defense Evasion", "TA0005",
        "https://attack.mitre.org/techniques/T1027/",
        "Sans analyse comportementale, les payloads obfusqués passent les antivirus signature.",
    ),
    "T1136": MitreTechnique(
        "T1136", "Create Account", "Persistence", "TA0003",
        "https://attack.mitre.org/techniques/T1136/",
        "Sans revue des accès, des comptes fantômes peuvent persister indéfiniment.",
    ),
    "T1078.003": MitreTechnique(
        "T1078.003", "Local Accounts", "Defense Evasion", "TA0005",
        "https://attack.mitre.org/techniques/T1078/003/",
        "Les comptes locaux non gérés permettent la persistance après rotation des comptes domaine.",
    ),
    "T1530": MitreTechnique(
        "T1530", "Data from Cloud Storage", "Collection", "TA0009",
        "https://attack.mitre.org/techniques/T1530/",
        "Les buckets/blobs cloud mal configurés exposent les données sensibles publiquement.",
    ),
    "T1537": MitreTechnique(
        "T1537", "Transfer Data to Cloud Account", "Exfiltration", "TA0010",
        "https://attack.mitre.org/techniques/T1537/",
        "Le transfert de données vers un compte cloud attaquant est indétectable sans DLP cloud.",
    ),
}


# ── Mapping NIS2 → MITRE (par requirement_id) ────────────────────────────────

NIS2_MITRE_MAPPING: dict[str, dict] = {
    # Domaine 1 — Gouvernance
    "NIS2-D01-R01": {
        "requirement_title": "Politique de sécurité SI approuvée",
        "domain_title": "Gouvernance",
        "severity": "HIGH",
        "attack_scenario": (
            "Sans politique formelle, les équipes opèrent sans cadre de sécurité. "
            "Un attaquant exploite ce vide organisationnel : absence de règles sur les "
            "mots de passe, les accès distants ou l'installation de logiciels."
        ),
        "gap_impact": "Surface d'attaque non définie, mesures ad hoc inefficaces.",
        "techniques": ["T1078", "T1133", "T1059"],
    },
    "NIS2-D01-R02": {
        "requirement_title": "Roles et responsabilités définis",
        "domain_title": "Gouvernance",
        "severity": "MEDIUM",
        "attack_scenario": (
            "L'ambiguïté des responsabilités retarde la réponse aux incidents. "
            "Pendant qu'on cherche qui doit agir, l'attaquant progresse latéralement."
        ),
        "gap_impact": "Temps de réponse aux incidents multiplié par 3 à 5.",
        "techniques": ["T1021", "T1070"],
    },
    # Domaine 2 — Gestion des risques
    "NIS2-D02-R01": {
        "requirement_title": "Processus d'analyse des risques",
        "domain_title": "Gestion des risques",
        "severity": "HIGH",
        "attack_scenario": (
            "Sans cartographie des risques, les actifs critiques ne sont pas protégés "
            "prioritairement. Les attaquants ciblent exactement ces angles morts."
        ),
        "gap_impact": "Actifs critiques exposés faute de priorisation des contrôles.",
        "techniques": ["T1190", "T1530", "T1005"],
    },
    "NIS2-D02-R02": {
        "requirement_title": "Traitement des risques formalisé",
        "domain_title": "Gestion des risques",
        "severity": "MEDIUM",
        "attack_scenario": (
            "Les risques identifiés mais non traités restent exploitables. "
            "Un audit de surface permet à l'attaquant de cibler les risques acceptés."
        ),
        "gap_impact": "Risques connus non mitigés = vulnérabilités documentées non corrigées.",
        "techniques": ["T1068", "T1190"],
    },
    # Domaine 3 — Continuité d'activité
    "NIS2-D03-R01": {
        "requirement_title": "Plan de continuité d'activité (PCA)",
        "domain_title": "Continuité d'activité",
        "severity": "CRITICAL",
        "attack_scenario": (
            "Un ransomware déployé un vendredi soir trouve une organisation sans PCA. "
            "L'entreprise est incapable de reprendre en mode dégradé. "
            "Le paiement de rançon devient la seule option perçue."
        ),
        "gap_impact": "Indisponibilité prolongée, pression maximale pour payer la rançon.",
        "techniques": ["T1486", "T1490", "T1485", "T1489"],
    },
    "NIS2-D03-R02": {
        "requirement_title": "Plan de reprise après sinistre (PRA/DR)",
        "domain_title": "Continuité d'activité",
        "severity": "CRITICAL",
        "attack_scenario": (
            "Sans sauvegardes offline testées, un ransomware chiffrant les données "
            "et leurs copies cloud rend la récupération impossible sans payer."
        ),
        "gap_impact": "RTO/RPO non maîtrisés, récupération potentiellement impossible.",
        "techniques": ["T1486", "T1490", "T1485"],
    },
    "NIS2-D03-R03": {
        "requirement_title": "Tests de reprise réguliers",
        "domain_title": "Continuité d'activité",
        "severity": "HIGH",
        "attack_scenario": (
            "Des sauvegardes non testées donnent un faux sentiment de sécurité. "
            "En situation réelle, la restauration échoue ou prend 10x plus de temps."
        ),
        "gap_impact": "Temps de reprise réel inconnu, risque d'échec en situation de crise.",
        "techniques": ["T1485", "T1489"],
    },
    # Domaine 4 — Sécurité de la chaîne d'approvisionnement
    "NIS2-D04-R01": {
        "requirement_title": "Evaluation sécurité des fournisseurs",
        "domain_title": "Chaine d'approvisionnement",
        "severity": "CRITICAL",
        "attack_scenario": (
            "Un fournisseur tiers compromis (type SolarWinds) devient le vecteur "
            "d'une attaque supply chain silencieuse sur votre SI. "
            "Aucun contrôle en entrée ne détecte la compromission initiale."
        ),
        "gap_impact": "Vecteur supply chain non contrôlé, accès de confiance exploitable.",
        "techniques": ["T1195", "T1195.002", "T1072"],
    },
    "NIS2-D04-R02": {
        "requirement_title": "Clauses contractuelles sécurité",
        "domain_title": "Chaine d'approvisionnement",
        "severity": "MEDIUM",
        "attack_scenario": (
            "Sans obligations contractuelles, un fournisseur peut accéder à votre SI "
            "avec des credentials partagés, sans journalisation ni révocation possible."
        ),
        "gap_impact": "Accès fournisseurs non tracés, impossibilité de révocation rapide.",
        "techniques": ["T1078", "T1078.001"],
    },
    # Domaine 5 — Gestion des incidents
    "NIS2-D05-R01": {
        "requirement_title": "Processus de détection des incidents",
        "domain_title": "Gestion des incidents",
        "severity": "CRITICAL",
        "attack_scenario": (
            "Le temps moyen de détection (MTTD) sans SOC/SIEM est de 197 jours (IBM 2023). "
            "L'attaquant opère librement pendant 6 mois, exfiltrant les données "
            "et préparant la phase destructive."
        ),
        "gap_impact": "MTTD > 180 jours, exfiltration massive avant détection.",
        "techniques": ["T1562", "T1562.001", "T1070", "T1070.001", "T1048"],
    },
    "NIS2-D05-R02": {
        "requirement_title": "Processus de réponse aux incidents",
        "domain_title": "Gestion des incidents",
        "severity": "HIGH",
        "attack_scenario": (
            "Sans playbook de réponse, chaque incident est géré de zéro. "
            "Le manque de coordination amplifie les dommages et rallonge le temps de confinement."
        ),
        "gap_impact": "MTTR élevé, propagation non contenue, dommages collatéraux.",
        "techniques": ["T1021", "T1486", "T1562"],
    },
    "NIS2-D05-R03": {
        "requirement_title": "Notification réglementaire des incidents",
        "domain_title": "Gestion des incidents",
        "severity": "HIGH",
        "attack_scenario": (
            "Le non-respect du délai de notification NIS2 (24h/72h) expose l'organisation "
            "à des sanctions ANSSI pouvant atteindre 10M€ ou 2% du CA mondial."
        ),
        "gap_impact": "Sanction réglementaire + risque réputationnel en cas d'incident.",
        "techniques": ["T1070", "T1485"],
    },
    # Domaine 6 — Contrôles d'accès
    "NIS2-D06-R01": {
        "requirement_title": "Gestion des identités et des accès",
        "domain_title": "Controles d'acces",
        "severity": "CRITICAL",
        "attack_scenario": (
            "Des comptes avec des privilèges excessifs (violation du principe du moindre privilège) "
            "permettent à un compte compromis d'accéder immédiatement aux données critiques "
            "sans mouvement latéral nécessaire."
        ),
        "gap_impact": "Blast radius maximal sur compromission d'un seul compte.",
        "techniques": ["T1078", "T1078.004", "T1136", "T1078.003"],
    },
    "NIS2-D06-R02": {
        "requirement_title": "Authentification multi-facteur (MFA)",
        "domain_title": "Controles d'acces",
        "severity": "CRITICAL",
        "attack_scenario": (
            "99,9% des attaques sur comptes sont bloquées par le MFA (Microsoft 2023). "
            "Sans MFA, le credential stuffing, le phishing et le password spraying "
            "donnent un accès immédiat après la première compromission de mot de passe."
        ),
        "gap_impact": "Compromission de compte triviale via credential stuffing ou phishing.",
        "techniques": ["T1078", "T1078.004", "T1110", "T1110.003", "T1566"],
    },
    "NIS2-D06-R03": {
        "requirement_title": "Revue periodique des droits d'acces",
        "domain_title": "Controles d'acces",
        "severity": "HIGH",
        "attack_scenario": (
            "Les comptes d'ex-collaborateurs actifs (zombie accounts) sont exploités "
            "6 à 18 mois après le départ. Ces comptes ont souvent des privilèges élevés "
            "et ne font pas l'objet d'une surveillance particulière."
        ),
        "gap_impact": "Comptes orphelins exploitables, accès fantôme indétectable.",
        "techniques": ["T1078", "T1078.003", "T1136"],
    },
    # Domaine 7 — Sécurité des réseaux
    "NIS2-D07-R01": {
        "requirement_title": "Segmentation reseau",
        "domain_title": "Securite des reseaux",
        "severity": "CRITICAL",
        "attack_scenario": (
            "Sur un réseau plat (flat network), un poste utilisateur compromis accède "
            "directement aux serveurs de production, aux sauvegardes et aux contrôleurs "
            "de domaine. Le ransomware se propage en quelques minutes."
        ),
        "gap_impact": "Propagation latérale illimitée depuis n'importe quel point d'entrée.",
        "techniques": ["T1021", "T1021.001", "T1486", "T1040"],
    },
    "NIS2-D07-R02": {
        "requirement_title": "Chiffrement des communications",
        "domain_title": "Securite des reseaux",
        "severity": "HIGH",
        "attack_scenario": (
            "Sans chiffrement des communications internes, un attaquant en position "
            "man-in-the-middle peut capturer des credentials, des données sensibles "
            "et des jetons de session sur le réseau interne."
        ),
        "gap_impact": "Capture de credentials et données sensibles sur le réseau interne.",
        "techniques": ["T1040", "T1557"],
    },
    "NIS2-D07-R03": {
        "requirement_title": "Monitoring reseau et detection d'intrusion",
        "domain_title": "Securite des reseaux",
        "severity": "HIGH",
        "attack_scenario": (
            "Sans IDS/NDR, le scan interne, la reconnaissance et le mouvement latéral "
            "restent invisibles. L'attaquant peut cartographier le réseau cible "
            "sans déclencher la moindre alerte."
        ),
        "gap_impact": "Reconnaissance et mouvement latéral non détectés.",
        "techniques": ["T1021", "T1562", "T1070"],
    },
    # Domaine 8 — Gestion des vulnérabilités
    "NIS2-D08-R01": {
        "requirement_title": "Processus de gestion des correctifs",
        "domain_title": "Gestion des vulnerabilites",
        "severity": "CRITICAL",
        "attack_scenario": (
            "60% des breaches exploitent une vulnérabilité pour laquelle un correctif "
            "existait (Verizon DBIR 2023). Sans processus de patch management, "
            "les CVE critiques restent exposées des mois après leur publication."
        ),
        "gap_impact": "CVE critiques exploitables, fenêtre d'exposition de plusieurs mois.",
        "techniques": ["T1190", "T1203", "T1068"],
    },
    "NIS2-D08-R02": {
        "requirement_title": "Scan de vulnerabilites regulier",
        "domain_title": "Gestion des vulnerabilites",
        "severity": "HIGH",
        "attack_scenario": (
            "Sans scan régulier, les nouvelles vulnérabilités introduites par des "
            "changements de configuration ou des nouvelles installations passent inaperçues. "
            "L'attaquant découvre ces failles via des scanners automatisés publics."
        ),
        "gap_impact": "Surface d'attaque inconnue, failles introduites non détectées.",
        "techniques": ["T1190", "T1068", "T1055"],
    },
    "NIS2-D08-R03": {
        "requirement_title": "Gestion des actifs et inventaire",
        "domain_title": "Gestion des vulnerabilites",
        "severity": "HIGH",
        "attack_scenario": (
            "Les actifs non inventoriés (shadow IT, IoT oubliés) ne reçoivent "
            "ni mise à jour ni surveillance. Ces systèmes fantômes deviennent "
            "les points d'entrée privilégiés des attaquants."
        ),
        "gap_impact": "Shadow IT non géré, actifs non patchés invisibles des équipes sécurité.",
        "techniques": ["T1190", "T1078.001", "T1496"],
    },
    # Domaine 9 — Journalisation et surveillance
    "NIS2-D09-R01": {
        "requirement_title": "Journalisation des evenements de securite",
        "domain_title": "Journalisation et surveillance",
        "severity": "CRITICAL",
        "attack_scenario": (
            "Sans logs, il est impossible de détecter une intrusion en cours "
            "ou de reconstituer a posteriori la séquence d'attaque. "
            "L'investigation forensique devient impossible, la preuve légale inexistante."
        ),
        "gap_impact": "Détection impossible, investigation forensique irréalisable.",
        "techniques": ["T1070", "T1070.001", "T1562.001"],
    },
    "NIS2-D09-R02": {
        "requirement_title": "Conservation et protection des logs",
        "domain_title": "Journalisation et surveillance",
        "severity": "HIGH",
        "attack_scenario": (
            "L'attaquant qui accède au système cible d'abord les logs pour effacer "
            "ses traces. Sans logs centralisés en lecture seule, la suppression "
            "est triviale et l'intrusion devient indétectable rétrospectivement."
        ),
        "gap_impact": "Effacement de traces possible, chronologie d'attaque irreconstruisable.",
        "techniques": ["T1070", "T1070.001", "T1562"],
    },
    "NIS2-D09-R03": {
        "requirement_title": "Surveillance en temps reel (SIEM/SOC)",
        "domain_title": "Journalisation et surveillance",
        "severity": "HIGH",
        "attack_scenario": (
            "Sans corrélation d'événements, les signaux faibles d'une APT passent "
            "inaperçus. La détection d'une attaque multi-étapes nécessite la "
            "corrélation de centaines d'événements sur plusieurs jours."
        ),
        "gap_impact": "APT et attaques multi-étapes non détectées avant impact.",
        "techniques": ["T1562", "T1027", "T1055"],
    },
    # Domaine 10 — Sensibilisation et formation
    "NIS2-D10-R01": {
        "requirement_title": "Formation securite du personnel",
        "domain_title": "Sensibilisation et formation",
        "severity": "HIGH",
        "attack_scenario": (
            "Le phishing reste le vecteur d'entrée n°1 (36% des breaches, Verizon DBIR 2023). "
            "Sans formation régulière, le taux de clic sur les campagnes de phishing "
            "ciblées dépasse 30% selon les études Proofpoint."
        ),
        "gap_impact": "Taux de clic phishing élevé, vecteur humain exploitable à grande échelle.",
        "techniques": ["T1566", "T1566.001", "T1566.002"],
    },
    "NIS2-D10-R02": {
        "requirement_title": "Tests de phishing et sensibilisation pratique",
        "domain_title": "Sensibilisation et formation",
        "severity": "MEDIUM",
        "attack_scenario": (
            "Sans exercices pratiques, la sensibilisation reste théorique. "
            "Les employés qui n'ont jamais vu de vrai phishing en conditions réelles "
            "ne développent pas le réflexe de signalement."
        ),
        "gap_impact": "Réflexes de détection non développés, signalement absent.",
        "techniques": ["T1566", "T1566.002"],
    },
}


# ── Moteur de mapping ─────────────────────────────────────────────────────────

def compute_mitre_mapping(
    analysis: dict,
    only_gaps: bool = True,
) -> MitreMappingReport:
    """
    Génère le rapport MITRE ATT&CK à partir d'un assessment NIS2.

    Paramètres
    ----------
    analysis : dict
        Résultat de `analyze()` ou payload stocké en base.
    only_gaps : bool
        Si True, ne retourne que les exigences avec gaps (maturity < 3).
        Si False, retourne toutes les exigences mappées.
    """
    org_name = analysis.get("metadata", {}).get("organization", "Organisation")
    domains = analysis.get("domains", [])

    # Construire un dict {requirement_id: maturity}
    maturity_map: dict[str, int] = {}
    for domain in domains:
        for req in domain.get("requirements", []):
            req_id = req.get("id", "")
            maturity_map[req_id] = req.get("maturity", 3)

    links: list[NIS2MitreLink] = []
    technique_counter: dict[str, int] = {}
    tactic_counter: dict[str, int] = {}

    for req_id, mapping in NIS2_MITRE_MAPPING.items():
        maturity = maturity_map.get(req_id, 3)
        if only_gaps and maturity >= 3:
            continue

        # Ajuster la sévérité selon la maturité réelle
        base_severity = mapping["severity"]
        if maturity == 0 and base_severity == "HIGH":
            effective_severity = "CRITICAL"
        elif maturity == 2 and base_severity == "CRITICAL":
            effective_severity = "HIGH"
        else:
            effective_severity = base_severity

        technique_ids = mapping["techniques"]
        techniques = []
        for tid in technique_ids:
            tech = _T.get(tid)
            if tech:
                techniques.append(tech)
                technique_counter[tid] = technique_counter.get(tid, 0) + 1
                tactic_id = tech.tactic_id
                tactic_counter[tactic_id] = tactic_counter.get(tactic_id, 0) + 1

        link = NIS2MitreLink(
            requirement_id=req_id,
            requirement_title=mapping["requirement_title"],
            domain_title=mapping["domain_title"],
            techniques=techniques,
            attack_scenario=mapping["attack_scenario"],
            gap_impact=mapping["gap_impact"],
            severity=effective_severity,
        )
        links.append(link)

    # Trier par sévérité
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    links.sort(key=lambda lnk: sev_order.get(lnk.severity, 3))

    # Top tactiques
    tactic_names = {
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0010": "Exfiltration",
        "TA0040": "Impact",
    }
    top_tactics = sorted(
        [{"tactic_id": k, "tactic": tactic_names.get(k, k), "count": v}
         for k, v in tactic_counter.items()],
        key=lambda x: -x["count"],
    )[:8]

    # Top techniques
    top_techniques = sorted(
        [{"technique_id": k, "name": _T[k].name if k in _T else k, "count": v}
         for k, v in technique_counter.items()],
        key=lambda x: -x["count"],
    )[:10]

    critical = sum(1 for lnk in links if lnk.severity == "CRITICAL")
    high = sum(1 for lnk in links if lnk.severity == "HIGH")
    medium = sum(1 for lnk in links if lnk.severity == "MEDIUM")

    total_gaps_input = analysis.get("scores", {}).get("total_gaps", len(links))

    return MitreMappingReport(
        org_name=org_name,
        total_gaps=total_gaps_input,
        critical_links=critical,
        high_links=high,
        medium_links=medium,
        top_tactics=top_tactics,
        top_techniques=top_techniques,
        links=links,
        coverage_note=(
            f"{len(links)} exigences NIS2 en défaut exposent {len(technique_counter)} "
            f"techniques MITRE ATT&CK distinctes couvrant {len(tactic_counter)} tactiques."
        ),
    )
