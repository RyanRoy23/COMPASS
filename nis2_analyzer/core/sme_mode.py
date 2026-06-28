"""
COMPASS — Mode PME (questionnaire simplifié)

Le mode PME propose 15 questions essentielles en langage non-technique,
destinées aux dirigeants, DG ou responsables IT de PME sans RSSI dédié.

Chaque question est rédigée en français courant ("Est-ce que…" plutôt que
"Avez-vous implémenté une politique de…") et mappée à une ou plusieurs
exigences NIS 2, afin que les réponses puissent alimenter le scoring complet.

Sélection des 15 questions :
Les questions couvrent les contrôles qui réduisent le plus le risque cyber
pour une PME, selon les statistiques ANSSI et ENISA :
  1. Mots de passe forts + MFA            → plus grand vecteur d'intrusion
  2. Sauvegardes                          → seule défense efficace vs ransomware
  3. Mises à jour                         → 60% des attaques exploitent des CVE patchées
  4. Accès tiers / fournisseurs           → surface d'attaque supply chain
  5. Procédure en cas de cyberattaque     → résilience opérationnelle
  6. Formation du personnel               → vecteur phishing n°1

Chaque niveau (0-3) est formulé en termes compréhensibles par un non-expert.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SMEQuestion:
    """Une question du mode PME, rédigée en langage dirigeant."""
    id: str
    category: str           # Thème (non-technique)
    question: str           # Question en français courant
    why_it_matters: str     # Explication courte de l'enjeu
    levels: list[str]       # Libellés des 4 niveaux (0→3) en langage simple
    requirement_ids: list[str]  # Exigences NIS 2 associées
    risk_if_zero: str       # Conséquence concrète si niveau 0


# ── Les 15 questions du mode PME ─────────────────────────────────────────────

SME_QUESTIONS: list[SMEQuestion] = [

    SMEQuestion(
        id="PME-01",
        category="🔐 Mots de passe & accès",
        question="Est-ce que vos collaborateurs utilisent des mots de passe forts et une double authentification (code SMS ou application) pour accéder aux outils professionnels ?",
        why_it_matters="80% des piratages commencent par un mot de passe volé. La double authentification bloque les intrusions même si le mot de passe est connu.",
        levels=[
            "Non — les mots de passe sont simples et pas de vérification en deux étapes.",
            "Partiellement — certains outils ont la double auth mais pas tous.",
            "Oui — la plupart des outils exigent un mot de passe fort et une double auth.",
            "Oui, systématiquement — toute connexion est protégée, avec vérification régulière.",
        ],
        requirement_ids=["NIS2-D10-R01", "NIS2-D09-R01"],
        risk_if_zero="Un seul compte piraté peut donner accès à toute votre messagerie, vos fichiers et vos clients.",
    ),

    SMEQuestion(
        id="PME-02",
        category="💾 Sauvegardes",
        question="Est-ce que vos données importantes sont sauvegardées régulièrement, et avez-vous déjà testé leur restauration ?",
        why_it_matters="En cas de ransomware (virus qui chiffre vos fichiers), une sauvegarde récente est votre seule issue sans payer la rançon.",
        levels=[
            "Non — pas de sauvegarde régulière ou sauvegarde jamais testée.",
            "Partiellement — sauvegarde occasionnelle mais jamais testée en restauration.",
            "Oui — sauvegarde automatique quotidienne sur un support séparé.",
            "Oui, et testé — sauvegarde quotidienne, restauration testée au moins une fois par an.",
        ],
        requirement_ids=["NIS2-D03-R02"],
        risk_if_zero="En cas d'attaque ransomware, vous perdez toutes vos données ou devez payer une rançon (en moyenne 50 000 € pour une PME).",
    ),

    SMEQuestion(
        id="PME-03",
        category="🔄 Mises à jour",
        question="Est-ce que les logiciels et systèmes de votre entreprise sont mis à jour régulièrement (ordinateurs, serveurs, applications métier) ?",
        why_it_matters="La majorité des cyberattaques exploitent des failles dans des logiciels non mis à jour. Une mise à jour peut bloquer une attaque connue.",
        levels=[
            "Non — les mises à jour sont ignorées ou très rares.",
            "Partiellement — les PC sont mis à jour mais pas les serveurs ni les applications métier.",
            "Oui — mises à jour automatiques activées sur la plupart des systèmes.",
            "Oui, avec suivi — mises à jour gérées et vérifiées, délai maximum de 30 jours.",
        ],
        requirement_ids=["NIS2-D05-R03", "NIS2-D05-R02"],
        risk_if_zero="Un logiciel non mis à jour peut être piraté en quelques minutes par des outils automatisés disponibles sur Internet.",
    ),

    SMEQuestion(
        id="PME-04",
        category="📋 Plan en cas d'attaque",
        question="Est-ce que votre entreprise sait quoi faire si elle est victime d'une cyberattaque (qui appeler, comment réagir, que déconnecter) ?",
        why_it_matters="Les premières heures d'une cyberattaque sont décisives. Sans procédure, on panique, on efface des preuves, et les dégâts s'amplifient.",
        levels=[
            "Non — aucune procédure, on improviserait en cas d'attaque.",
            "Partiellement — quelques réflexes connus mais rien de formalisé par écrit.",
            "Oui — une procédure existe et les contacts clés (IT, ANSSI, assurance) sont identifiés.",
            "Oui, et testé — la procédure a été simulée ou testée avec l'équipe au cours des 12 derniers mois.",
        ],
        requirement_ids=["NIS2-D02-R01", "NIS2-D03-R01"],
        risk_if_zero="Sans procédure, une cyberattaque dure en moyenne 3× plus longtemps et coûte 2× plus cher.",
    ),

    SMEQuestion(
        id="PME-05",
        category="👥 Formation du personnel",
        question="Est-ce que vos collaborateurs ont été formés ou sensibilisés aux risques cyber (emails frauduleux, arnaques, mots de passe) ?",
        why_it_matters="9 attaques sur 10 commencent par un email frauduleux (phishing). Un collaborateur averti est votre meilleure défense.",
        levels=[
            "Non — aucune formation ni sensibilisation.",
            "Ponctuellement — une communication ou réunion a eu lieu mais sans suivi.",
            "Oui — une formation ou sensibilisation par an pour tous les collaborateurs.",
            "Oui, régulièrement — formation annuelle + tests de phishing simulés + rappels réguliers.",
        ],
        requirement_ids=["NIS2-D07-R01", "NIS2-D07-R03"],
        risk_if_zero="Un collaborateur non formé clique en moyenne sur 1 email frauduleux sur 5, ouvrant la porte à une intrusion.",
    ),

    SMEQuestion(
        id="PME-06",
        category="🔌 Accès des prestataires",
        question="Est-ce que vous contrôlez les accès de vos prestataires informatiques et logiciels à vos systèmes (accès limités, traçés, résiliés à la fin du contrat) ?",
        why_it_matters="De nombreuses attaques passent par un prestataire compromis. Un accès non supprimé après fin de contrat est une porte ouverte.",
        levels=[
            "Non — les prestataires ont accès complet et les accès ne sont pas suivis.",
            "Partiellement — les accès sont donnés mais rarement revus ni supprimés en fin de mission.",
            "Oui — accès limités au nécessaire et supprimés à la fin du contrat.",
            "Oui, avec traçabilité — accès documentés, audités et clôturés avec procédure formelle.",
        ],
        requirement_ids=["NIS2-D04-R01", "NIS2-D09-R02"],
        risk_if_zero="Un accès prestataire non résilié est l'une des premières causes d'intrusion dans les PME.",
    ),

    SMEQuestion(
        id="PME-07",
        category="🔐 Comptes administrateurs",
        question="Est-ce que les accès \"administrateur\" (accès total aux systèmes) sont limités à quelques personnes identifiées et utilisés uniquement quand nécessaire ?",
        why_it_matters="Un compte admin piraté donne un contrôle total sur votre informatique. Moins il y en a, mieux c'est.",
        levels=[
            "Non — plusieurs personnes ont des droits admin sans nécessité réelle.",
            "Partiellement — quelques admins identifiés mais pas de suivi des usages.",
            "Oui — les droits admin sont limités et documentés.",
            "Oui, avec contrôle — droits admin audités, usage journalisé, revue trimestrielle.",
        ],
        requirement_ids=["NIS2-D09-R03"],
        risk_if_zero="Un compte admin volé permet de chiffrer ou supprimer toutes vos données en quelques minutes.",
    ),

    SMEQuestion(
        id="PME-08",
        category="📦 Inventaire informatique",
        question="Est-ce que vous avez une liste à jour de tous vos équipements informatiques (ordinateurs, serveurs, téléphones professionnels, accès cloud) ?",
        why_it_matters="On ne peut pas protéger ce qu'on ne connaît pas. Un équipement oublié non mis à jour est une faille.",
        levels=[
            "Non — pas de liste, on ne sait pas exactement ce qui existe.",
            "Partiellement — une liste existe mais elle est incomplète ou rarement mise à jour.",
            "Oui — un inventaire à jour des équipements principaux est maintenu.",
            "Oui, complet — inventaire détaillé de tous les actifs, mis à jour en continu.",
        ],
        requirement_ids=["NIS2-D09-R04", "NIS2-D01-R03"],
        risk_if_zero="Un appareil inconnu non protégé peut devenir le point d'entrée d'une attaque.",
    ),

    SMEQuestion(
        id="PME-09",
        category="📧 Communications sécurisées",
        question="Est-ce que vos communications sensibles (contrats, données clients, RH) passent par des canaux sécurisés (messagerie chiffrée, HTTPS, VPN pour le télétravail) ?",
        why_it_matters="Des échanges non chiffrés peuvent être interceptés. Les données clients et financières sont particulièrement ciblées.",
        levels=[
            "Non — les communications se font sans protection particulière.",
            "Partiellement — le site web est en HTTPS mais pas les échanges internes.",
            "Oui — messagerie pro sécurisée, VPN pour les accès distants.",
            "Oui, systématiquement — toutes les communications sensibles sont chiffrées et auditées.",
        ],
        requirement_ids=["NIS2-D10-R02", "NIS2-D08-R02"],
        risk_if_zero="Des données clients ou financières interceptées peuvent engager votre responsabilité RGPD et ternir votre réputation.",
    ),

    SMEQuestion(
        id="PME-10",
        category="🛡️ Antivirus & protection",
        question="Est-ce que tous vos postes de travail et serveurs ont un antivirus ou une solution de protection active et à jour ?",
        why_it_matters="Un antivirus à jour bloque la majorité des virus, ransomwares et logiciels malveillants connus.",
        levels=[
            "Non — pas de protection ou antivirus expiré.",
            "Partiellement — antivirus sur les PC mais pas sur tous les serveurs.",
            "Oui — solution de protection active sur tous les postes et serveurs.",
            "Oui, avancé — EDR (protection avancée) avec surveillance des comportements anormaux.",
        ],
        requirement_ids=["NIS2-D02-R02", "NIS2-D05-R02"],
        risk_if_zero="Sans antivirus, un fichier malveillant reçu par email peut infecter tout votre réseau en quelques secondes.",
    ),

    SMEQuestion(
        id="PME-11",
        category="👋 Départs de collaborateurs",
        question="Est-ce que lorsqu'un collaborateur quitte l'entreprise, ses accès informatiques sont supprimés immédiatement (email, applications, VPN) ?",
        why_it_matters="Un ancien employé avec des accès actifs est un risque réel, surtout en cas de départ conflictuel.",
        levels=[
            "Non — les accès restent actifs après le départ.",
            "Partiellement — l'email est supprimé mais d'autres accès restent ouverts.",
            "Oui — une checklist de départ couvre la suppression des accès principaux.",
            "Oui, systématiquement — procédure formelle avec vérification et trace écrite.",
        ],
        requirement_ids=["NIS2-D09-R02"],
        risk_if_zero="Un accès non révoqué peut être utilisé pour voler des données ou perturber vos systèmes.",
    ),

    SMEQuestion(
        id="PME-12",
        category="☁️ Cloud & logiciels SaaS",
        question="Est-ce que vous connaissez et gérez les logiciels en ligne (cloud, SaaS) utilisés par vos équipes, et vérifiez-vous leur niveau de sécurité ?",
        why_it_matters="Le \"shadow IT\" (outils cloud utilisés sans autorisation) multiplie les surfaces d'attaque non maîtrisées.",
        levels=[
            "Non — les équipes utilisent des outils cloud sans centralisation ni contrôle.",
            "Partiellement — les principaux outils sont connus mais pas tous vérifiés.",
            "Oui — liste des outils SaaS approuvés, contrats avec clauses de sécurité.",
            "Oui, avec audit — évaluation de sécurité des fournisseurs cloud et surveillance continue.",
        ],
        requirement_ids=["NIS2-D04-R01", "NIS2-D04-R02"],
        risk_if_zero="Un outil SaaS non sécurisé peut exposer vos données clients sans que vous en soyez informé.",
    ),

    SMEQuestion(
        id="PME-13",
        category="📞 Qui appeler en cas d'incident ?",
        question="Est-ce que vous savez à qui signaler une cyberattaque (ANSSI, prestataire IT, assurance cyber) et dans quels délais NIS 2 l'impose ?",
        why_it_matters="NIS 2 impose de signaler les incidents significatifs à l'ANSSI sous 24h. Ignorer cette obligation expose à des amendes.",
        levels=[
            "Non — personne ne sait quoi faire ni qui appeler.",
            "Partiellement — le prestataire IT est connu mais pas l'obligation de notification ANSSI.",
            "Oui — procédure de notification connue avec contacts ANSSI et délais identifiés.",
            "Oui, testé — la procédure a été exercée ou simulée, avec contacts à jour.",
        ],
        requirement_ids=["NIS2-D02-R03", "NIS2-D02-R01"],
        risk_if_zero="Ne pas notifier un incident NIS 2 dans les délais peut entraîner une amende jusqu'à 10 M€ ou 2% du CA mondial.",
    ),

    SMEQuestion(
        id="PME-14",
        category="🏠 Télétravail sécurisé",
        question="Est-ce que vos collaborateurs en télétravail accèdent aux ressources de l'entreprise de façon sécurisée (VPN, ordinateur professionnel, réseau WiFi maîtrisé) ?",
        why_it_matters="Le télétravail sans VPN expose les communications aux écoutes. Un WiFi public non sécurisé peut servir de point d'interception.",
        levels=[
            "Non — accès en télétravail sans VPN ni contraintes de sécurité.",
            "Partiellement — VPN disponible mais non obligatoire.",
            "Oui — VPN obligatoire pour les accès distants, ordinateur professionnel fourni.",
            "Oui, renforcé — VPN + MFA + vérification de l'état du poste avant connexion.",
        ],
        requirement_ids=["NIS2-D10-R02", "NIS2-D09-R01"],
        risk_if_zero="Une connexion sans VPN depuis un café ou aéroport peut exposer vos mots de passe et données professionnelles.",
    ),

    SMEQuestion(
        id="PME-15",
        category="📊 Responsable de la sécurité",
        question="Est-ce que quelqu'un dans votre organisation est clairement responsable de la sécurité informatique, même sans être un expert dédié ?",
        why_it_matters="Sans responsable identifié, les sujets de sécurité ne sont gérés par personne. NIS 2 Art. 20 responsabilise la direction.",
        levels=[
            "Non — personne n'est clairement en charge de la sécurité informatique.",
            "Partiellement — le sujet revient à l'IT mais sans mandat ni budget formalisé.",
            "Oui — un référent sécurité est désigné avec un rôle et des responsabilités claires.",
            "Oui, avec gouvernance — référent sécurité + reporting régulier à la direction + budget dédié.",
        ],
        requirement_ids=["NIS2-D01-R04", "NIS2-D01-R05"],
        risk_if_zero="Sans responsable identifié, aucune décision de sécurité n'est prise — jusqu'au jour de l'incident.",
    ),
]


# ── Mapping PME → NIS 2 complet ───────────────────────────────────────────────

def sme_responses_to_nis2(sme_responses: dict[str, int]) -> dict[str, int]:
    """
    Convertit les réponses PME (PME-01 → 0..3) en réponses NIS 2 complètes.

    Pour les exigences couvertes par une question PME, on utilise la réponse.
    Pour les exigences non couvertes (questions expertes), on infère
    un niveau de maturité depuis les réponses PME voisines ou on applique
    un niveau neutre (1 = partiel) afin de ne pas pénaliser les PME
    sur des questions qu'elles n'ont pas pu répondre.

    Cette inférence est transparente dans le rapport.
    """
    # Construire le mapping direct depuis les questions PME
    direct: dict[str, list[int]] = {}
    for q in SME_QUESTIONS:
        level = sme_responses.get(q.id)
        if level is None:
            continue
        for req_id in q.requirement_ids:
            direct.setdefault(req_id, []).append(level)

    # Agréger : moyenne arrondie des niveaux pour les exigences avec plusieurs questions
    nis2_responses: dict[str, int] = {}
    for req_id, levels in direct.items():
        nis2_responses[req_id] = round(sum(levels) / len(levels))

    # Inférer les exigences non couvertes directement
    # Règles d'inférence basées sur les corrélations NIS 2 :
    inferences = {
        # Si MFA OK (D10-R01) → communications sécurisées probablement aussi
        "NIS2-D10-R03": nis2_responses.get("NIS2-D10-R02", 1),
        # Si sauvegarde OK (D03-R02) → PCA probablement partiel
        "NIS2-D03-R03": max(0, nis2_responses.get("NIS2-D03-R02", 1) - 1),
        "NIS2-D03-R04": max(0, nis2_responses.get("NIS2-D03-R02", 1) - 1),
        # Si formation OK (D07-R01) → hygiène et pratiques suivent
        "NIS2-D07-R02": nis2_responses.get("NIS2-D07-R01", 1),
        "NIS2-D07-R04": max(0, nis2_responses.get("NIS2-D07-R01", 1) - 1),
        "NIS2-D07-R05": nis2_responses.get("NIS2-D07-R01", 1),
        # Si cryptographie partielle → politique de crypto déduite
        "NIS2-D08-R01": nis2_responses.get("NIS2-D08-R02", 1),
        # Audit et indicateurs → niveau prudent par défaut pour PME
        "NIS2-D06-R01": min(nis2_responses.get("NIS2-D09-R03", 1), 1),
        "NIS2-D06-R02": 0,
        # Incidents : retour d'expérience déduit de la procédure
        "NIS2-D02-R04": max(0, nis2_responses.get("NIS2-D02-R01", 1) - 1),
        # Supply chain : surveillance continue rarement faite en PME
        "NIS2-D04-R03": max(0, nis2_responses.get("NIS2-D04-R01", 1) - 1),
        # Dev SI : SDLC peu pertinent pour les PME non-tech
        "NIS2-D05-R01": 1,
        # Gouvernance
        "NIS2-D01-R01": nis2_responses.get("NIS2-D01-R04", 1),
        "NIS2-D01-R02": max(0, nis2_responses.get("NIS2-D01-R03", 1) - 1),
    }

    for req_id, level in inferences.items():
        if req_id not in nis2_responses:
            nis2_responses[req_id] = min(max(level, 0), 3)

    return nis2_responses


def get_sme_schema() -> list[dict]:
    """Retourne le schéma des questions PME pour l'API."""
    return [
        {
            "id": q.id,
            "category": q.category,
            "question": q.question,
            "why_it_matters": q.why_it_matters,
            "risk_if_zero": q.risk_if_zero,
            "requirement_ids": q.requirement_ids,
            "levels": [
                {"value": i, "label": q.levels[i]}
                for i in range(4)
            ],
        }
        for q in SME_QUESTIONS
    ]


def compute_sme_score(sme_responses: dict[str, int]) -> dict:
    """
    Calcule un score PME simplifié directement depuis les réponses PME.

    Retourne :
    - score global (0-100)
    - score par catégorie
    - liste des points faibles (niveau 0)
    - liste des points forts (niveau 3)
    - priorité d'action (question PME à traiter en premier)
    """
    if not sme_responses:
        return {"score": 0, "grade": "F", "categories": [], "weak_points": [], "strong_points": [], "top_priority": None}

    questions_map = {q.id: q for q in SME_QUESTIONS}
    answered = [(qid, lvl) for qid, lvl in sme_responses.items() if qid in questions_map and lvl in (0, 1, 2, 3)]

    if not answered:
        return {"score": 0, "grade": "F", "categories": [], "weak_points": [], "strong_points": [], "top_priority": None}

    total_score = sum(lvl for _, lvl in answered)
    max_score = len(answered) * 3
    pct = round(total_score / max_score * 100, 1)

    grade = "A" if pct >= 85 else "B" if pct >= 70 else "C" if pct >= 55 else "D" if pct >= 40 else "F"

    # Par catégorie
    categories: dict[str, list[int]] = {}
    for qid, lvl in answered:
        cat = questions_map[qid].category
        categories.setdefault(cat, []).append(lvl)
    cat_scores = [
        {"category": cat, "score": round(sum(lvls) / (len(lvls) * 3) * 100, 0)}
        for cat, lvls in categories.items()
    ]

    weak_points = [
        {
            "id": qid,
            "category": questions_map[qid].category,
            "question": questions_map[qid].question,
            "level": lvl,
            "risk": questions_map[qid].risk_if_zero,
            "levels": questions_map[qid].levels,
        }
        for qid, lvl in answered if lvl <= 1
    ]
    # Trier par criticité : niveau 0 d'abord
    weak_points.sort(key=lambda x: x["level"])

    strong_points = [
        {
            "id": qid,
            "category": questions_map[qid].category,
            "question": questions_map[qid].question,
        }
        for qid, lvl in answered if lvl == 3
    ]

    top_priority = weak_points[0] if weak_points else None

    return {
        "score": pct,
        "grade": grade,
        "total_answered": len(answered),
        "categories": cat_scores,
        "weak_points": weak_points,
        "strong_points": strong_points,
        "top_priority": top_priority,
        "n_critical": sum(1 for _, l in answered if l == 0),
        "n_partial": sum(1 for _, l in answered if l == 1),
        "n_implemented": sum(1 for _, l in answered if l == 2),
        "n_optimized": sum(1 for _, l in answered if l == 3),
    }
