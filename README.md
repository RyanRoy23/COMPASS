# NIS 2 Risk Analyzer
Évaluation de conformité NIS 2 Article 21 avec mapping DORA et ISO 27001:2022, quantification du risque financier, et **transparence méthodologique** sur le périmètre d'évaluation.

La majorité des outils d'évaluation NIS 2 demandent "avez-vous déployé le MFA ?" et l'utilisateur coche "oui". Personne ne vérifie, et personne ne dit ce qui n'a pas été évalué.

Cet outil propose une approche différente : il distingue explicitement, dans chaque rapport, ce qui est **prouvé** par audit technique, ce qui est **déclaré** par questionnaire, et ce qui n'est **pas couvert** par l'outil et nécessite une vérification externe. L'objectif n'est pas de remplacer un audit professionnel NIS 2, mais d'identifier honnêtement les zones de risque connues sans créer de faux sentiment de complétude.

---

## Ce que fait l'outil

NIS 2 Risk Analyzer évalue la conformité d'une organisation aux 10 mesures de l'Article 21 de la Directive NIS 2 (UE 2022/2555) en combinant **cinq couches** :

**1. Évaluation de conformité structurée**
35 questions couvrant les 10 domaines de l'Article 21, avec scoring pondéré (A-F), identification des gaps, plan de remédiation priorisé, et mapping vers 43 contrôles ISO 27001:2022 Annex A.

**2. Bridge technique — CloudSec Audit Toolkit**
Connexion optionnelle avec le CloudSec Audit Toolkit pour importer les résultats d'un audit Azure/Entra ID (20 contrôles via MS Graph API). Les réponses techniques disponibles sont pré-remplies automatiquement avec des preuves — pas des déclarations. Pour les organisations non-Azure ou les actifs non connectés, la collecte reste manuelle.

**3. Périmètre d'évaluation explicite**
Chaque rapport distingue visuellement les mesures **prouvées** par audit technique, **déclarées** par questionnaire, et **non couvertes** par l'outil. L'objectif est d'éviter le faux sentiment de complétude qui caractérise la plupart des outils GRC : un score NIS 2 partiel mais transparent vaut mieux qu'un score apparemment complet mais aveugle aux zones non évaluées.

**4. Mapping DORA (Digital Operational Resilience Act)**
16 questions NIS 2 sont mappées aux articles DORA pertinents, regroupées par les 5 piliers du règlement : ICT Risk Management, ICT-Related Incident Management, Digital Operational Resilience Testing, ICT Third-Party Risk, Information Sharing. Le rapport affiche la couverture par pilier et signale explicitement les exigences DORA non couvertes (TLPT, registre d'information des prestataires TIC, partage d'information sur les cybermenaces). Utile pour les entités soumises à la fois à NIS 2 et DORA (banques, assurances, sociétés de gestion).

**5. Quantification du risque financier**
Chaque gap est traduit en impact financier estimé selon la méthode ALE (Annualized Loss Expectancy), basée sur des données publiques : IBM Cost of a Data Breach 2024, Panorama de la cybermenace ANSSI, rapports Coveware, barème des sanctions NIS 2 (Article 34). Le rapport indique l'exposition annuelle estimée et la valeur des quick wins en euros.

---
## Quick Start (procédure complète)

Pour relancer l'outil après une première installation :

```powershell
# 1. Activer l'environnement virtuel Python
.\venv\Scripts\Activate.ps1

# 2. Lancer la démo simple
python -m nis2_analyzer --demo

# 3. Lancer la démo complète avec rapport HTML
python -m nis2_analyzer --demo --bridge tests/mock_data/cloudsec_report.json --report reports/rapport.html --size eti --sector industrie --revenue 50000000

# 4. Ouvrir le rapport HTML généré
start reports\rapport.html
```

**Note Windows** : si l'activation du venv échoue, exécuter d'abord :
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

---
## Démonstration rapide

```bash
# Mode démo — résultats en 5 secondes
python -m nis2_analyzer --demo

# Démo complète avec bridge CloudSec + analyse financière + rapport HTML
python -m nis2_analyzer --demo \
  --bridge tests/mock_data/cloudsec_report.json \
  --report reports/rapport.html \
  --size eti --sector industrie --revenue 50000000
```

**Résultat de la démo :**

```
Score global :  37.3%  |  Grade :  D
Gaps totaux  :  21     |  Critiques :  6

Exposition financière annuelle estimée :
  Hypothèse basse  :  970K EUR
  Hypothèse moyenne :  3.9M EUR
  Hypothèse haute   :  16.3M EUR

Valeur des quick wins : 750K EUR/an
(réduction de risque réalisable en moins d'un mois)
```

---

## Installation

```bash
git clone https://github.com/RyanRoy23/nis2-risk-analyzer.git
cd nis2-risk-analyzer
```

Python 3.10+ requis. Aucune dépendance externe — uniquement la bibliothèque standard Python.

---

## Utilisation

### Mode interactif

```bash
python -m nis2_analyzer
```

L'outil guide l'utilisateur à travers les 31 questions, domaine par domaine. Chaque réponse est notée de 0 (non implémenté) à 3 (géré/mesuré). Le score se calcule en temps réel.

### Mode bridge + interactif

```bash
python -m nis2_analyzer \
  --bridge chemin/vers/rapport_cloudsec.json \
  --report reports/rapport.html \
  --size pme --sector sante
```

Le bridge charge le rapport JSON du [CloudSec Audit Toolkit](https://github.com/RyanRoy23/cloudsec-audit-toolkit) et pré-remplit automatiquement les questions techniques (11/31). L'utilisateur ne répond qu'aux 20 questions organisationnelles restantes.

Pour chaque question pré-remplie, l'outil affiche le constat technique et permet de l'accepter ou de le corriger.

### Mode démo

```bash
python -m nis2_analyzer --demo
```

Simule une évaluation complète avec des réponses prédéfinies. Utile pour tester l'outil ou le présenter.

### Options complètes

| Option | Description |
|--------|-------------|
| `--demo` | Mode démonstration avec réponses simulées |
| `--bridge`, `-b` | Chemin du rapport CloudSec Audit Toolkit (JSON) |
| `--report`, `-r` | Chemin du rapport HTML de sortie |
| `--output`, `-o` | Chemin du fichier JSON de sortie |
| `--size` | Taille de l'organisation : `pme`, `eti`, `grand` |
| `--sector` | Secteur : `sante`, `finance`, `energie`, `industrie`, `numerique`, `transport`, `administration`, `autre` |
| `--revenue` | Chiffre d'affaires annuel en euros |
| `--org-name` | Nom de l'organisation |

---

## Architecture

```
nis2-risk-analyzer/
├── nis2_analyzer/
│   ├── core/
│   │   ├── models.py          # Classes de base (Domain, MaturityLevel, ComplianceGrade)
│   │   ├── scoring.py         # Moteur de scoring pondéré + gap analysis
│   │   ├── financial.py       # Base de données d'impact financier (IBM, ANSSI, NIS 2)
│   │   └── risk_engine.py     # Moteur de quantification ALE
│   ├── assessment/
│   │   ├── interactive.py     # Questionnaire CLI interactif
│   │   └── exporter.py        # Export JSON des résultats
│   ├── connectors/
│   │   └── cloudsec_bridge.py # Bridge CloudSec Audit Toolkit → NIS 2
│   ├── reporting/
│   │   └── html_report.py     # Générateur de rapport HTML unifié
│   ├── data/
│   │   └── nis2_framework.json # Référentiel NIS 2 Article 21
│   └── cli.py                 # Point d'entrée CLI
├── tests/
│   └── mock_data/
│       └── cloudsec_report.json # Rapport CloudSec simulé pour les tests
├── reports/                   # Rapports générés
└── docs/                      # Documentation
```

---

## Le référentiel NIS 2

L'outil couvre les 10 domaines de l'Article 21(2) :

| # | Domaine | Art. | Sous-exigences | Poids |
|---|---------|------|:--------------:|:-----:|
| 1 | Politiques d'analyse des risques et de sécurité des SI | (a) | 4 | 1.5x |
| 2 | Gestion des incidents | (b) | 4 | 1.5x |
| 3 | Continuité d'activité et gestion de crise | (c) | 3 | 1.3x |
| 4 | Sécurité de la chaîne d'approvisionnement | (d) | 3 | 1.2x |
| 5 | Sécurité dans l'acquisition, le développement et la maintenance des SI | (e) | 3 | 1.0x |
| 6 | Évaluation de l'efficacité des mesures | (f) | 2 | 1.0x |
| 7 | Pratiques d'hygiène cyber et formation | (g) | 3 | 1.0x |
| 8 | Politiques d'utilisation de la cryptographie | (h) | 2 | 0.8x |
| 9 | Sécurité des RH, contrôle d'accès et gestion des actifs | (i) | 4 | 1.2x |
| 10 | Authentification multifacteur et communications sécurisées | (j) | 3 | 1.0x |

**Total : 31 sous-exigences mappées vers 41 contrôles ISO 27001:2022 Annex A.**

---

## Bridge CloudSec — Comment ça marche

Le bridge connecte les résultats du [CloudSec Audit Toolkit](https://github.com/RyanRoy23/cloudsec-audit-toolkit) aux exigences NIS 2.

**Flux :**
1. Le CloudSec Audit Toolkit audite un tenant Azure/Entra ID via MS Graph API (20 checks)
2. Le bridge charge le rapport JSON et traduit chaque résultat en niveau de maturité NIS 2
3. Les questions techniques sont pré-remplies avec la preuve (compte détecté, configuration vérifiée)
4. L'utilisateur ne répond qu'aux questions organisationnelles

**Mapping des checks :**

| Check CloudSec | Exigence NIS 2 | Logique |
|----------------|----------------|---------|
| IDN-001 : Users without MFA | D10-R01 : MFA | PASS → N3, FAIL → N0-1 selon le nombre |
| IDN-002 : Admin MFA | D10-R01 + D09-R03 | PASS → N3, FAIL → N0 (critique) |
| IDN-004 : Inactive accounts | D09-R02 : Arrivées/départs | PASS → N2, FAIL → N0-1 |
| ROL-001 : Global Admins | D09-R03 : Comptes à privilèges | ≤5 → N2, >5 → N0-1 |
| ROL-002 : Permanent roles | D09-R03 : Comptes à privilèges | PIM/JIT → N3, permanent → N0 |
| CAP-001 : Conditional Access | D01-R01 : PSSI | Policies actives → N2 |
| CAP-004 : Risky sign-in | D02-R02 : Détection | Blocking policy → N2 |
| TNT-003 : External collab | D04-R01 : Supply chain | Restreint → N2 |
| APP-001 : Excessive perms | D05-R02 : Vulnérabilités | 0 findings → N2 |
| APP-003 : No owner | D09-R04 : Gestion des actifs | Owners assignés → N2 |

**Principe de prudence :** quand deux checks couvrent la même exigence, le niveau le plus bas l'emporte.

---

## Quantification financière

Chaque gap est relié à des scénarios d'incident avec un coût estimé.

**Méthodologie :** ALE (Annualized Loss Expectancy) = Probabilité annuelle × Impact financier.

**Sources des données de coût :**
- IBM Cost of a Data Breach Report 2024 — coût moyen France : 4.3M€
- ANSSI Panorama de la cybermenace — impact ransomware PME : 50K-500K€
- Coveware Quarterly Reports — rançon moyenne : 525K€
- Directive NIS 2 Art. 34 — amendes : max(10M€, 2% CA) entités essentielles

**Ajustement par maturité :**
| Niveau | Multiplicateur | Logique |
|--------|:--------------:|---------|
| 0 — Non implémenté | ×1.5 | Aucune protection |
| 1 — Partiel | ×1.0 | Protection incohérente |
| 2 — Implémenté | ×0.3 | Risque résiduel |
| 3 — Géré | ×0.1 | Surveillance active |

**Note :** ces estimations sont indicatives et basées sur des données publiques agrégées. Elles ne remplacent pas une analyse de risques contextualisée (FAIR, ISO 27005).

---

## Rapport HTML

Le rapport HTML unifié consolide les cinq couches en un seul document autonome (aucune dépendance externe requise pour l'ouverture) :

- Score global + grade (A-F)
- **Périmètre d'évaluation : distinction visuelle prouvé / déclaré / non couvert**
- Scores par domaine avec barres de progression
- Bridge CloudSec : questions pré-remplies et constats techniques
- Exposition financière : hypothèses basse/moyenne/haute, amende NIS 2
- Top risques par exposition et top remédiations par ROI
- Plan de remédiation en 4 phases (immédiat, court, moyen, long terme)
- Couverture ISO 27001:2022 Annex A (contrôles couverts/non couverts)
- **Couverture DORA par pilier (mapping NIS 2 ↔ DORA, 5 piliers)**

---

## Roadmap

### Récemment livré
- Section "Périmètre d'évaluation" dans le rapport HTML : distinction visuelle prouvé/déclaré/non couvert
- Couverture étendue des dimensions organisationnelles : engagement direction (article 20 NIS 2), tests effectifs PCA, mesure d'efficacité de la sensibilisation, filtrage Internet et contrôle des périphériques (passage de 31 à 35 questions)
- Suite de tests unitaires automatisés (45 tests, couverture 86% sur le moteur de scoring) et CI/CD GitHub Actions
- Mapping DORA via les 16 questions NIS 2 pertinentes : couverture des 5 piliers (ICT Risk Management, Incident Management, Resilience Testing, Third-Party Risk, Information Sharing) avec transparence sur les zones non couvertes (TLPT, registre TIC, partage d'information)

### En cours (priorité 1)
- Documentation détaillée du compte de service Azure (permissions minimales, durcissement, audit)
- Quantification financière étendue aux gaps organisationnels

### Court terme (3-6 mois)
- Persistance locale des évaluations (JSON ou SQLite) pour reprise et historisation
- Élargissement du bridge CloudSec (40+ checks Azure)
- Multi-framework : mapping vers DORA et le référentiel ANSSI
- Dossier de preuves structuré exportable pour audit externe

### Moyen terme (6-12 mois)
- Connecteur AWS (boto3 + AWS Config)
- Webapp avec interface graphique (Flask ou FastAPI + frontend léger)
- Suivi temporel : comparaison d'évaluations successives, courbes de progression
- Modèle financier Monte Carlo (distributions FAIR)

### Long terme
- Benchmark sectoriel anonymisé
- Connecteurs additionnels (GCP, on-premise AD, EDR, SIEM)
- Mode collaboratif multi-utilisateurs avec rôles (RSSI, DPO, auditeur)

---

## Limitations

L'outil est un prototype démonstratif, pas un produit industriel. Les limites suivantes sont assumées et explicites :

**Périmètre technique partiel**
Le bridge technique ne couvre actuellement qu'Azure/Entra ID. Les environnements AWS, GCP, on-premise ou OT/ICS ne sont pas évalués automatiquement et restent en mode déclaratif via questionnaire.

**Couverture organisationnelle limitée**
NIS 2 est à environ 60-70% un cadre organisationnel : qualité de la gouvernance, engagement effectif de la direction, gestion de crise, supervision des fournisseurs, formation et sensibilisation. Ces dimensions sont actuellement évaluées par questionnaire déclaratif uniquement, sans mécanisme de validation. La transparence du rapport (section "Périmètre d'évaluation") signale explicitement ces zones, mais elles nécessitent un audit externe pour être réellement vérifiées.

**Mapping DORA partiel**
Le mapping DORA ne constitue pas une évaluation DORA complète. Trois exigences DORA spécifiques ne sont pas couvertes par l'outil : le TLPT (Threat-Led Penetration Testing, article 26), le registre d'information des prestataires TIC (article 28(3)), et le partage d'information sur les cybermenaces (article 45). Une évaluation DORA complète nécessite un référentiel dédié et un audit complémentaire, en particulier pour les entités financières significatives soumises au régime de supervision directe.

**Risque du compte de service Azure**
Le bridge CloudSec nécessite un compte Azure avec des permissions de lecture (Global Reader, Security Reader). Ce compte devient une cible potentielle s'il est compromis. La documentation détaille les permissions minimales à accorder et les bonnes pratiques de protection (Conditional Access, MFA, audit du compte). L'outil ne dispose d'aucune permission d'écriture.

**Quantification financière indicative**
La méthode ALE (Annualized Loss Expectancy) utilisée est linéaire et basée sur des données publiques agrégées. Ce n'est pas un modèle actuariel comme FAIR ou ISO 27005 quantitative. Les fourchettes basse/moyenne/haute structurent la décision, elles ne la remplacent pas.

**Pas de substitution à un audit professionnel**
L'outil ne remplace ni un audit NIS 2 mené par un cabinet qualifié, ni un avis juridique sur la conformité. Il fournit une auto-évaluation outillée et un dossier de préparation pour un audit externe.

**Données non persistées**
Cette version (v1.0) ne stocke pas les évaluations entre les sessions. Chaque évaluation produit un rapport ponctuel. La persistance et l'historisation sont prévues dans la roadmap.

---

## Auteur

**Ryan Roy TASSEH TAGNY**
Cybersécurité & Cloud | Certifié ISO/IEC 27001:2022 | CC ISC2

- LinkedIn : [linkedin.com/in/ryan-roy-tasseh-tagny-237554231](https://linkedin.com/in/ryan-roy-tasseh-tagny-237554231)
- GitHub : [github.com/RyanRoy23](https://github.com/RyanRoy23)

---

## Licence

MIT — Libre d'utilisation, de modification et de distribution.
