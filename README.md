# NIS 2 Risk Analyzer

**Évaluation de conformité NIS 2 Article 21 connectée à un audit technique réel, avec quantification du risque financier.**

Les outils d'évaluation NIS 2 existants demandent "avez-vous déployé le MFA ?" et l'utilisateur coche "oui". Personne ne vérifie. Cet outil fait la différence entre déclarer et prouver.

---

## Ce que fait l'outil

NIS 2 Risk Analyzer évalue la conformité d'une organisation aux 10 mesures de l'Article 21 de la Directive NIS 2 (UE 2022/2555) en combinant trois approches :

**1. Évaluation de conformité structurée**
31 questions couvrant les 10 domaines de l'Article 21, avec scoring pondéré (A-F), identification des gaps, plan de remédiation priorisé, et mapping vers 41 contrôles ISO 27001:2022 Annex A.

**2. Bridge technique — CloudSec Audit Toolkit**
Connexion directe avec [CloudSec Audit Toolkit](https://github.com/RyanRoy23/cloudsec-audit-toolkit) pour importer les résultats d'un audit Azure/Entra ID (20 contrôles via MS Graph API). Les réponses techniques sont pré-remplies automatiquement avec des preuves — pas des déclarations.

**3. Quantification du risque financier**
Chaque gap est traduit en impact financier estimé (méthode ALE) basé sur des données publiques : IBM Cost of a Data Breach, rapports ANSSI, barème des sanctions NIS 2 (Art. 34). Le rapport indique l'exposition annuelle et la valeur des quick wins en euros.

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

Le rapport HTML unifié consolide les trois couches en un seul document autonome (aucune dépendance externe requise pour l'ouverture) :

- Score global + grade (A-F)
- Scores par domaine avec barres de progression
- Bridge CloudSec : questions pré-remplies et constats techniques
- Exposition financière : hypothèses basse/moyenne/haute, amende NIS 2
- Top risques par exposition et top remédiations par ROI
- Plan de remédiation en 4 phases (immédiat, court, moyen, long terme)
- Couverture ISO 27001:2022 Annex A (contrôles couverts/non couverts)

---

## Roadmap

- [ ] Élargissement du bridge (40+ checks Azure)
- [ ] Connecteur AWS (boto3 + AWS Config)
- [ ] Modèle financier Monte Carlo (distributions FAIR)
- [ ] Webapp avec persistance (Flask/FastAPI + React)
- [ ] Suivi temporel (comparaison d'évaluations successives)
- [ ] Multi-framework (DORA, RGPD, référentiel ANSSI)
- [ ] Dossier de preuves structuré pour audit
- [ ] Benchmark sectoriel anonymisé

---

## Limitations

- Le bridge technique ne couvre actuellement qu'Azure/Entra ID
- La quantification financière est une estimation indicative (ALE linéaire), pas un modèle actuariel
- L'outil ne se substitue pas à un audit professionnel ni à un avis juridique
- Les probabilités d'incidents sont des ordres de grandeur basés sur des statistiques publiques

---

## Auteur

**Ryan Roy TASSEH TAGNY**
Cybersécurité & Cloud | Certifié ISO/IEC 27001:2022 | CC ISC2

- LinkedIn : [linkedin.com/in/ryan-roy-tasseh-tagny-237554231](https://linkedin.com/in/ryan-roy-tasseh-tagny-237554231)
- GitHub : [github.com/RyanRoy23](https://github.com/RyanRoy23)

---

## Licence

MIT — Libre d'utilisation, de modification et de distribution.
