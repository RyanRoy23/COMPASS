# NIS 2 Risk Analyzer

Évaluation de conformité NIS 2 Article 21 avec audit technique Azure, quantification du risque financier, interface web et suivi de progression dans le temps.

La majorité des outils d'évaluation NIS 2 demandent "avez-vous déployé le MFA ?" et l'utilisateur coche "oui". Personne ne vérifie, et personne ne dit ce qui n'a pas été évalué.

Cet outil propose une approche différente : il distingue explicitement ce qui est **prouvé** par audit technique, ce qui est **déclaré** par questionnaire, et ce qui n'est **pas couvert** et nécessite une vérification externe.

---

## Ce que fait l'outil

NIS 2 Risk Analyzer évalue la conformité aux 10 mesures de l'Article 21 (UE 2022/2555) en combinant **cinq couches** :

| Couche | Description |
|--------|-------------|
| **Conformité structurée** | 35 questions, 10 domaines, scoring pondéré A-F, plan de remédiation priorisé |
| **Bridge technique** | Audit Azure/Entra ID via CloudSec Toolkit — pré-remplit les réponses avec des preuves réelles |
| **Transparence du périmètre** | Chaque rapport distingue prouvé / déclaré / non couvert |
| **Mapping DORA** | 16 questions NIS 2 mappées aux 5 piliers DORA |
| **Quantification financière** | Exposition ALE en euros, scénarios basse/moyenne/haute, valeur des quick wins |

---

## Démarrage rapide

### Option 1 — Interface web (recommandée)

```bash
git clone https://github.com/RyanRoy23/nis2-risk-analyzer.git
cd nis2-risk-analyzer
pip install -r requirements-web.txt
python serve.py
```

Ouvrez **http://localhost:8000** dans votre navigateur. Remplissez le questionnaire, cliquez sur "Lancer l'évaluation", consultez les résultats.

### Option 2 — Docker (zéro configuration)

```bash
git clone https://github.com/RyanRoy23/nis2-risk-analyzer.git
cd nis2-risk-analyzer
make build
make demo        # démonstration
make run         # évaluation interactive
```

### Option 3 — CLI Python

```bash
git clone https://github.com/RyanRoy23/nis2-risk-analyzer.git
cd nis2-risk-analyzer

# Démonstration rapide
python -m nis2_analyzer --demo

# Démo complète : bridge Azure + analyse financière + rapport HTML
python -m nis2_analyzer --demo \
  --bridge tests/mock_data/cloudsec_report.json \
  --report reports/rapport.html \
  --size eti --sector industrie --revenue 50000000
```

> **Aucune dépendance externe** pour le mode CLI — uniquement la bibliothèque standard Python 3.10+.  
> Les dépendances web (`fastapi`, `uvicorn`) ne sont requises que pour l'interface web.

---

## Interface web

L'interface web donne accès à toutes les fonctionnalités sans ligne de commande.

**Lancement :**
```bash
pip install -r requirements-web.txt
python serve.py
# → http://localhost:8000
```

**Fonctionnalités :**
- Formulaire d'évaluation avec curseurs de maturité (0-3) par exigence
- Bouton **Mode démo** pour pré-remplir en un clic et voir un exemple de résultat
- Vue résultats : score global, grade, barres par domaine, liste des gaps
- Vue historique : tableau de tous les assessments avec badges de grade colorés

**API REST disponible :**

| Endpoint | Description |
|----------|-------------|
| `GET /api/framework` | Liste des 10 domaines et 35 questions |
| `POST /api/assess` | Soumet les réponses, retourne le scoring + sauvegarde |
| `GET /api/history` | Historique des assessments |
| `GET /api/history/{id}` | Détail d'un assessment |
| `GET /api/compare/{a}/{b}` | Delta entre deux assessments |

---

## Historique et suivi de progression

Chaque évaluation est automatiquement sauvegardée dans `~/.nis2_analyzer/history.db`.

```bash
# Consulter l'historique
python -m nis2_analyzer --history

# Filtrer par organisation
python -m nis2_analyzer --history --org-name "TT Corporation"

# Comparer deux assessments
python -m nis2_analyzer --compare 1 3

# Ne pas sauvegarder un run
python -m nis2_analyzer --demo --no-save
```

Exemple de sortie `--compare` :
```
Comparaison d'assessments — TT Corporation
#1 (2026-01-15) → #3 (2026-06-21)
──────────────────────────────────────────
Score global : 40.7% → 67.2%  ▲ +26.5%
Grade        : D → C
Gaps ouverts : 20 → 11        ▼ -9
──────────────────────────────────────────
Evolution par domaine :
  Gestion des incidents        ▲ +35.0%
  Authentification MFA         ▲ +20.0%
  Continuité d'activité        = stable
```

---

## CLI — Toutes les options

| Option | Description |
|--------|-------------|
| `--demo` | Mode démonstration avec réponses simulées |
| `--bridge`, `-b` | Rapport CloudSec Audit Toolkit (JSON) |
| `--report`, `-r` | Rapport HTML de sortie |
| `--output`, `-o` | Export JSON des résultats |
| `--size` | Taille : `pme`, `eti`, `grand` |
| `--sector` | Secteur : `sante`, `finance`, `energie`, `industrie`, `numerique`, `transport`, `administration`, `autre` |
| `--revenue` | Chiffre d'affaires annuel en euros |
| `--org-name` | Nom de l'organisation |
| `--history` | Affiche l'historique des assessments |
| `--compare ID_A ID_B` | Compare deux assessments |
| `--no-save` | Ne pas sauvegarder cet assessment |

---

## Docker

```bash
make build    # construire l'image
make run      # évaluation interactive
make demo     # mode démonstration
make history  # consulter l'historique
make test     # tests dans le conteneur
make shell    # shell interactif
make clean    # tout supprimer
```

L'historique est persisté dans un volume Docker nommé `nis2_history`.  
Les rapports HTML générés sont disponibles dans `./reports/`.

---

## Architecture

```
nis2-risk-analyzer/
├── nis2_analyzer/
│   ├── core/
│   │   ├── models.py           # Domain, MaturityLevel, ComplianceGrade
│   │   ├── scoring.py          # Moteur de scoring pondéré + gap analysis
│   │   ├── financial.py        # Base de données d'impact financier
│   │   ├── risk_engine.py      # Quantification ALE
│   │   └── database.py         # Persistance SQLite (historique)
│   ├── assessment/
│   │   ├── interactive.py      # Questionnaire CLI interactif
│   │   └── exporter.py         # Export JSON
│   ├── connectors/
│   │   └── cloudsec_bridge.py  # Bridge CloudSec → NIS 2
│   ├── reporting/
│   │   └── html_report.py      # Générateur de rapport HTML autonome
│   ├── web/
│   │   ├── app.py              # API FastAPI
│   │   └── templates/
│   │       └── index.html      # Interface web (vanilla JS)
│   ├── data/
│   │   └── nis2_framework.json # Référentiel NIS 2 Article 21
│   └── cli.py                  # Orchestration CLI
├── tests/                      # 114 tests unitaires
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── serve.py                    # Lancement interface web
├── requirements-web.txt        # Dépendances web uniquement
└── docs/
    └── azure-service-account.md
```

---

## Le référentiel NIS 2

| # | Domaine | Sous-exigences | Poids |
|---|---------|:--------------:|:-----:|
| 1 | Politiques d'analyse des risques et de sécurité des SI | 5 | 1.5× |
| 2 | Gestion des incidents | 4 | 1.5× |
| 3 | Continuité d'activité et gestion de crise | 4 | 1.3× |
| 4 | Sécurité de la chaîne d'approvisionnement | 3 | 1.2× |
| 5 | Sécurité dans l'acquisition, le développement et la maintenance des SI | 3 | 1.0× |
| 6 | Évaluation de l'efficacité des mesures | 2 | 1.0× |
| 7 | Pratiques d'hygiène cyber et formation | 5 | 1.0× |
| 8 | Politiques d'utilisation de la cryptographie | 2 | 0.8× |
| 9 | Sécurité des RH, contrôle d'accès et gestion des actifs | 4 | 1.2× |
| 10 | Authentification multifacteur et communications sécurisées | 3 | 1.0× |

**Total : 35 sous-exigences, 43 contrôles ISO 27001:2022 Annex A mappés.**

---

## Bridge CloudSec

Le bridge connecte les résultats du [CloudSec Audit Toolkit](https://github.com/RyanRoy23/cloudsec-audit-toolkit) aux exigences NIS 2.

**Flux :**
1. CloudSec audite le tenant Azure/Entra ID via MS Graph API (20 checks)
2. Le bridge traduit chaque résultat en niveau de maturité NIS 2 avec preuve
3. Les questions techniques sont pré-remplies automatiquement
4. L'utilisateur ne répond qu'aux questions organisationnelles restantes

**Exemples de mapping :**

| Check CloudSec | Exigence NIS 2 | Logique |
|----------------|----------------|---------|
| IDN-001 : Users without MFA | D10-R01 | PASS → N3, FAIL → N0-1 selon le nombre |
| IDN-002 : Admin MFA | D10-R01 + D09-R03 | PASS → N3, FAIL → N0 (critique) |
| ROL-001 : Global Admins | D09-R03 | ≤5 → N2, >5 → N0-1 |
| CAP-001 : Conditional Access | D01-R01 | Policies actives → N2 |
| CAP-004 : Risky sign-in | D02-R02 | Blocking policy → N2 |

---

## Quantification financière

**Méthode :** ALE (Annualized Loss Expectancy) = Probabilité annuelle × Impact financier

**Sources :** IBM Cost of a Data Breach 2024 · ANSSI Panorama 2024 · Coveware Q4 2024 · NIS 2 Article 34

**Ajustement par maturité :**

| Niveau | Multiplicateur |
|--------|:--------------:|
| 0 — Non implémenté | ×1.5 |
| 1 — Partiel | ×1.0 |
| 2 — Implémenté | ×0.3 |
| 3 — Géré/Mesuré | ×0.1 |

> Ces estimations sont indicatives. Elles ne remplacent pas une analyse FAIR ou ISO 27005.

---

## Tests

```bash
# Lancer les tests
pip install pytest pytest-cov
python -m pytest tests/ -v

# Avec couverture
python -m pytest tests/ --cov=nis2_analyzer --cov-report=term-missing
```

**État actuel : 114 tests, CI GitHub Actions vert.**

Modules couverts : `core/scoring` (100%), `core/database` (100%), `web/app` (98%), `reporting/html_report` (71%).

---

## Limitations

**Périmètre technique partiel** — Le bridge ne couvre qu'Azure/Entra ID. Les environnements AWS, GCP et on-premise restent en mode déclaratif.

**Couverture organisationnelle** — NIS 2 est à 60-70% un cadre organisationnel. Ces dimensions sont évaluées par questionnaire déclaratif uniquement et nécessitent un audit externe pour être vraiment vérifiées.

**Mapping DORA partiel** — Trois exigences DORA ne sont pas couvertes : TLPT (art. 26), registre TIC (art. 28(3)), partage de cybermenaces (art. 45).

**Quantification indicative** — L'ALE linéaire n'est pas un modèle actuariel. Les fourchettes structurent la décision, elles ne la remplacent pas.

**Pas de substitution à un audit** — L'outil produit une auto-évaluation outillée, pas un rapport d'audit certifié.

---

## Roadmap

### Livré (v1.1)
- Interface web FastAPI — évaluation depuis le navigateur, sans CLI
- Persistance SQLite — historique des assessments, comparaison dans le temps
- Docker + Makefile — déploiement en une commande
- 114 tests unitaires, CI/CD GitHub Actions
- Sécurité renforcée : protection XSS, validation des entrées, sécurisation du bridge

### Prochaines étapes
- Élargissement du bridge CloudSec (40+ checks Azure)
- Connecteur AWS (boto3)
- Rapport HTML généré depuis l'interface web
- Suivi temporel visuel dans l'interface web (courbes de progression)
- Modèle financier Monte Carlo (distributions FAIR)

---

## Auteur

**Ryan Roy TASSEH TAGNY**  
Cybersécurité & Cloud | Certifié ISO/IEC 27001:2022 | CC ISC2

- LinkedIn : [linkedin.com/in/ryan-roy-tasseh-tagny-237554231](https://linkedin.com/in/ryan-roy-tasseh-tagny-237554231)
- GitHub : [github.com/RyanRoy23](https://github.com/RyanRoy23)

---

## Licence

MIT — Libre d'utilisation, de modification et de distribution.
