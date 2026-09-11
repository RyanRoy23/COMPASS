# ReCyF — Référentiel Cyber France (ANSSI)

Notes de travail extraites du document source officiel, pour cadrer la bascule de
COMPASS de l'Article 21 brut vers ReCyF.

**Source :** ANSSI, *RECYF : RÉFÉRENTIEL DE CYBERSÉCURITÉ FRANCE — Version 2.5 du
17/03/2026*, document de travail, 47 pages.
`https://messervices.cyber.gouv.fr/documents-ressources/20260317_NIS_V2_ReCyF_v2.5.pdf`

Statut : **document de travail**, non contraignant. Deviendra opposable à la
publication des décrets techniques de la loi résilience (attendus fin 2026).
À revérifier à chaque nouvelle version (la v2.5 succède à la v2.4 ; suivi des
modifications disponible sur MesServicesCyber).

---

## 20 objectifs de sécurité (OS1-OS20)

OS1 à OS15 : applicables aux **Entités Importantes et Essentielles**.
OS16 à OS20 : exigences avancées, applicables aux **Entités Essentielles uniquement**.

| # | Titre | Pilier |
|---|-------|--------|
| OS1 | Recensement des systèmes d'information | Gouvernance |
| OS2 | Mise en œuvre d'un cadre de gouvernance de la sécurité numérique | Gouvernance |
| OS3 | Maîtrise de l'écosystème | Gouvernance |
| OS4 | Intégration de la sécurité numérique dans la gestion des ressources humaines | Gouvernance |
| OS5 | Maîtrise des systèmes d'information | Gouvernance |
| OS6 | Maîtrise des accès physiques aux locaux | Protection |
| OS7 | Sécurisation de l'architecture des systèmes d'information | Protection |
| OS8 | Sécurisation des accès distants aux systèmes d'information | Protection |
| OS9 | Protection des systèmes d'information contre les codes malveillants | Protection |
| OS10 | Gestion des identités et des accès des utilisateurs aux systèmes d'information | Protection |
| OS11 | Maîtrise de l'administration des systèmes d'information | Protection |
| OS12 | Identification et réaction aux incidents de sécurité | Défense |
| OS13 | Continuité et reprise d'activité | Résilience |
| OS14 | Réaction aux crises d'origine cyber | Résilience |
| OS15 | Exercices, tests et entraînements | Résilience |
| OS16 *(EE)* | Mise en œuvre d'une approche par les risques | Gouvernance |
| OS17 *(EE)* | Audit de la sécurité des systèmes d'information | Gouvernance |
| OS18 *(EE)* | Sécurisation de la configuration des ressources des systèmes d'information | Protection |
| OS19 *(EE)* | Administration des systèmes d'information depuis des ressources dédiées | Protection |
| OS20 *(EE)* | Supervision de la sécurité des systèmes d'information | Défense |

Répartition par pilier : Gouvernance 7 (OS1-5, 16-17) · Protection 8 (OS6-11, 18-19) ·
Défense 2 (OS12, OS20) · Résilience 3 (OS13-15).

Chaque objectif est décliné en **moyens acceptables de conformité (MAC)** — 152 au
total dans le document — non extraits ici (à consulter par objectif au moment de
modéliser chacun, pas tous d'un coup).

## Correspondance avec l'Article 21 / Article 20 NIS 2

Table officielle "CORRESPONDANCE MESURES NIS 2 – MESURES NATIONALES" — quelle(s)
mesure(s) NIS 2 chaque objectif traduit :

| Mesure NIS 2 | Objectifs ReCyF |
|---|---|
| Art. 20 (responsabilité de l'organe de direction) | OS2 |
| Art. 21.2 (approche tous risques) | OS6 |
| Art. 21.2.a (analyse des risques, politiques sécurité SI) | OS2, OS16 |
| Art. 21.2.b (gestion des incidents) | OS12, OS15, OS20 |
| Art. 21.2.c (continuité, sauvegardes, gestion de crise) | OS13, OS14, OS15 |
| Art. 21.2.d (sécurité chaîne d'approvisionnement) | OS3 |
| Art. 21.2.e (acquisition/dév/maintenance SI, vulnérabilités) | OS5, OS7, OS8, OS9, OS10, OS11, OS17, OS19 |
| Art. 21.2.f (évaluation de l'efficacité des mesures) | OS2, OS17 |
| Art. 21.2.g (cyberhygiène, formation) | OS4, OS15 |
| Art. 21.2.h (cryptographie / chiffrement) | OS2, OS7, OS8 |
| Art. 21.2.i (RH, contrôle d'accès, gestion des actifs) | OS1, OS2, OS3, OS5, OS10, OS11 |
| Art. 21.2.j (MFA, authentification continue, communications sécurisées) | OS8, OS10, OS14 |

Cette table permet de **conserver le mapping DORA/ISO 27001 déjà construit sur les
35 sous-exigences Art. 21 actuelles** en le faisant transiter par cette
correspondance, plutôt que de le refaire de zéro.

## Implication pour COMPASS

- Le référentiel natif de COMPASS doit devenir les 20 objectifs ReCyF (avec leur
  pilier et leur périmètre EI/EE), pas les 35 sous-exigences Art. 21.
- Les modules déjà en place (`governance.py` → largement OS2/OS16 ; `incident_notification.py`
  → OS12/OS15/OS20 ; `supply_chain.py` → OS3 ; `entity_qualification.py` → qualification
  Art. 3, en amont du référentiel) se rattachent chacun à un ou plusieurs objectifs —
  à vérifier objectif par objectif plutôt qu'en bloc.
- Le bridge CloudSec (`cloudsec_bridge.py`) couvre aujourd'hui des contrôles Entra ID/Azure
  qui relèvent principalement du pilier **Protection** (OS7-11) et d'une partie de
  **Gouvernance** (OS2, MFA/CA policies) — à remapper objectif par objectif plutôt que
  domaine Art. 21 par domaine Art. 21.
