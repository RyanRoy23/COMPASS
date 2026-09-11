# COMPASS — Compliance Posture Assessment System

Évaluation de conformité NIS 2 qui distingue explicitement ce qui est **prouvé** par audit
technique (bridge Entra ID / Azure), ce qui est **déclaré** par questionnaire, et ce qui n'est
**pas couvert**. La plupart des outils demandent « avez-vous le MFA ? » et l'utilisateur coche
« oui » — personne ne vérifie, personne ne dit ce qui n'a pas été évalué.

> ** Refonte en cours (v2.0-dev).** Le référentiel bascule de l'Article 21 + ISO 27001 vers
> **ReCyF** (Référentiel Cyber France, ANSSI). Le périmètre technique se recentre sur **Entra
> ID / Azure**. Les modules quantification financière, Monte Carlo, connecteurs AWS/M365 et
> mode PME ont été retirés — récupérables au tag `archive/v1.2-full`. Le questionnaire et le
> rapport HTML reflètent encore la grille Article 21 en attendant la modélisation ReCyF.

---

## Ce que fait l'outil

COMPASS évalue la conformité NIS 2 en combinant :

| Couche | Description |
|--------|-------------|
| **Conformité structurée** | 35 questions, 10 domaines, scoring pondéré A-F, plan de remédiation priorisé (bascule ReCyF en cours) |
| **Bridge technique** | Audit Entra ID / Azure via CloudSec Toolkit — pré-remplit les réponses avec des preuves techniques horodatées |
| **Transparence du périmètre** | Chaque rapport distingue **prouvé** / **déclaré** / **non couvert** |
| **Volets réglementaires** | Qualification Art. 3, gouvernance Art. 20, notification Art. 23, supply chain Art. 21(d) |
| **Dossier de preuves** | Export ZIP horodaté et intègre (hash SHA-256) pour un contrôle ANSSI |

---

## Démarrage rapide

### Option 1 — Interface web (recommandée)

```bash
git clone https://github.com/RyanRoy23/COMPASS.git
cd COMPASS
pip install -r requirements-web.txt
python serve.py
```

Ouvrez **http://localhost:8000** dans votre navigateur. Remplissez le questionnaire, cliquez sur "Lancer l'évaluation", consultez les résultats.

### Option 2 — Docker (zéro configuration)

```bash
git clone https://github.com/RyanRoy23/COMPASS.git
cd COMPASS
make build
make up           # interface web → http://localhost:8000
```

### Option 3 — CLI Python

```bash
git clone https://github.com/RyanRoy23/COMPASS.git
cd COMPASS

# Démonstration rapide
python -m nis2_analyzer --demo

# Démo complète : bridge Azure + rapport HTML
python -m nis2_analyzer --demo \
  --bridge tests/mock_data/cloudsec_report.json \
  --report reports/rapport.html
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
| `POST /api/cloudsec-audit` | Traduit un rapport CloudSec (Entra ID) en preuves NIS 2 |
| `POST /api/qualify` | Qualification NIS 2 Art. 3 (essentielle / importante / hors champ) |
| `POST /api/governance` | Gouvernance Art. 20 |
| `POST /api/incident/*` | Notification d'incident Art. 23 (classification, deadlines, maturité) |
| `POST /api/supply-chain/*` | Fournisseurs et maturité supply chain Art. 21(d) |
| `POST /api/evidence-package` | Dossier de preuves ZIP |
| `GET /api/history` · `GET /api/compare/{a}/{b}` | Historique et delta entre assessments |

> L'ensemble des routes est documenté sur `http://localhost:8000/docs` (OpenAPI).

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
| `--evidence`, `-e` | Dossier de preuves ZIP de sortie |
| `--org-name` | Nom de l'organisation |
| `--qualify` | Qualification NIS 2 Art. 3 (avec `--sector`, `--employees`, `--revenue`) |
| `--governance` | Questionnaire de gouvernance Art. 20 |
| `--history` | Affiche l'historique des assessments |
| `--compare ID_A ID_B` | Compare deux assessments |
| `--no-save` | Ne pas sauvegarder cet assessment |

---

## Docker

```bash
make build    # construire l'image
make up        # interface web → http://localhost:8000
make demo      # démonstration CLI ponctuelle
make history   # consulter l'historique
make shell     # shell interactif dans le conteneur
make clean     # supprimer conteneurs, volumes et image
```

L'historique SQLite est persisté dans le volume Docker `compass_history`.
Les rapports HTML générés par le CLI sont disponibles dans `./reports/`.
`make test` lance la suite dans l'environnement local (venv), pas dans l'image runtime.

---

## Architecture

```
COMPASS/
├── nis2_analyzer/
│   ├── __init__.py                  # __version__ (source unique)
│   ├── core/
│   │   ├── models.py                # Domain, MaturityLevel, ComplianceGrade
│   │   ├── scoring.py               # Scoring pondéré + gap analysis + plan SMART
│   │   ├── database.py              # Persistance SQLite (historique, multi-tenant)
│   │   ├── integrity.py             # Empreinte SHA-256 des rapports
│   │   ├── entity_qualification.py  # Qualification Art. 3
│   │   ├── governance.py            # Gouvernance Art. 20
│   │   ├── incident_notification.py # Notification Art. 23
│   │   └── supply_chain.py          # Supply chain Art. 21(d)
│   ├── assessment/                  # Questionnaire CLI interactif + export JSON
│   ├── connectors/
│   │   └── cloudsec_bridge.py       # Bridge CloudSec (Entra ID) → preuves NIS 2
│   ├── reporting/
│   │   ├── html_report.py           # Rapport HTML autonome
│   │   └── evidence_package.py      # Dossier de preuves ZIP
│   ├── web/
│   │   ├── app.py                   # API FastAPI
│   │   └── templates/index.html     # Interface web (vanilla JS)
│   ├── data/nis2_framework.json     # Référentiel (bascule ReCyF en cours)
│   └── cli.py                       # Orchestration CLI
├── tests/                           # 260 tests unitaires
├── Dockerfile · docker-compose.yml · Makefile
├── serve.py                         # Lancement interface web
└── requirements-web.txt             # Dépendances web uniquement
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

## Tests

```bash
pip install pytest pytest-cov
python -m pytest tests/ -q

# Avec couverture
python -m pytest tests/ --cov=nis2_analyzer --cov-report=term-missing
```

**État actuel : 260 tests, CI GitHub Actions verte (Python 3.11 et 3.12).**

---

## Limitations

**Périmètre technique** — Le bridge ne couvre qu'Entra ID / Azure. Le reste (AWS, GCP, on-premise) est évalué en mode déclaratif.

**Couverture organisationnelle** — NIS 2 est à 60-70% un cadre organisationnel. Ces dimensions sont évaluées par questionnaire déclaratif et nécessitent un audit externe pour être vraiment vérifiées.

**Pas de substitution à un audit** — L'outil produit une auto-évaluation outillée, pas un rapport d'audit certifié.

---

## Roadmap

### En cours (v2.0)
- **Bascule vers ReCyF** (Référentiel Cyber France, ANSSI) : 20 objectifs / 4 piliers, en remplacement de la grille Article 21 + ISO 27001
- Gradation de chaque objectif ReCyF par type de preuve : prouvé (audit Entra) / déclaré / non couvert
- Élargissement du bridge CloudSec côté identité

### Fait
- Interface web FastAPI, persistance SQLite multi-tenant, Docker
- Volets Art. 3 / 20 / 23 / 21(d), dossier de preuves ZIP intègre
- 260 tests, CI GitHub Actions (Python 3.11 + 3.12)
- Sécurité : échappement XSS, validation Pydantic, hash des clés API, rate limiting

---

## Auteur

**Ryan Roy TASSEH TAGNY**  
Cybersécurité & Cloud | Certifié ISO/IEC 27001:2022 | CC ISC2

- LinkedIn : [linkedin.com/in/ryan-roy-tasseh-tagny-237554231](https://linkedin.com/in/ryan-roy-tasseh-tagny-237554231)
- GitHub : [github.com/RyanRoy23](https://github.com/RyanRoy23)

---

## Licence

MIT — Libre d'utilisation, de modification et de distribution.
