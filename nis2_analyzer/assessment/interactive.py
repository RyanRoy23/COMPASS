"""
COMPASS — Interactive Assessment
Module qui guide l'utilisateur à travers les 31 questions du référentiel NIS 2.

Architecture :
- display_* : fonctions d'affichage (ce que l'utilisateur voit)
- prompt_* : fonctions d'interaction (ce que l'utilisateur saisit)
- run_assessment : fonction principale qui orchestre le tout

Pourquoi séparer affichage et logique ?
Parce qu'on pourra réutiliser la logique avec une interface web plus tard
sans toucher au code métier.
"""

import os
import sys
from typing import Optional
from nis2_analyzer.core.models import (
    Domain, SubRequirement, MaturityLevel, load_framework
)


# ═══════════════════════════════════════════════
# CONSTANTES D'AFFICHAGE
# ═══════════════════════════════════════════════
# Ces caractères spéciaux créent les encadrés et barres dans le terminal.
# On utilise des caractères Unicode "box drawing" — ils fonctionnent
# sur Windows Terminal, macOS Terminal, et tout terminal Linux moderne.

BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
WHITE = "\033[97m"


def clear_screen():
    """Efface le terminal. os.name == 'nt' détecte Windows."""
    os.system('cls' if os.name == 'nt' else 'clear')


def display_banner():
    """
    Affiche la bannière de l'outil au lancement.
    C'est la première chose que l'utilisateur voit.
    L'objectif : identifier immédiatement l'outil et donner confiance.
    """
    print()
    print(f"  {CYAN}{'=' * 56}{RESET}")
    print(f"  {CYAN}||{RESET}  {WHITE}{BOLD}COMPASS{RESET}             {CYAN}||{RESET}")
    print(f"  {CYAN}||{RESET}  {DIM}Article 21 — Assessment interactif{RESET}        {CYAN}||{RESET}")
    print(f"  {CYAN}{'=' * 56}{RESET}")
    print()


def display_welcome():
    """
    Message d'accueil qui explique ce que l'outil va faire.
    Important : l'utilisateur doit comprendre en 10 secondes
    ce qu'on attend de lui et combien de temps ça va prendre.
    """
    print(f"  {WHITE}Cet outil evalue votre niveau de conformite NIS 2{RESET}")
    print(f"  {WHITE}en vous posant {BOLD}31 questions{RESET}{WHITE} sur les 10 domaines{RESET}")
    print(f"  {WHITE}de l'Article 21.{RESET}")
    print()
    print(f"  {DIM}Pour chaque question, indiquez votre niveau de maturite :{RESET}")
    print()
    print(f"    {RED}0{RESET} — Non implemente    (aucune mesure en place)")
    print(f"    {YELLOW}1{RESET} — Initial / Partiel  (mesure ad hoc, non formalisee)")
    print(f"    {CYAN}2{RESET} — Defini / Implemente (mesure formalisee et appliquee)")
    print(f"    {GREEN}3{RESET} — Gere / Mesure      (mesure surveillee via KPI)")
    print()
    print(f"  {DIM}Duree estimee : 5 a 10 minutes.{RESET}")
    print(f"  {DIM}Cible NIS 2 minimum : niveau 2 sur chaque exigence.{RESET}")
    print()


def display_domain_header(domain: Domain, domain_index: int, total_domains: int):
    """
    Affiche l'en-tête d'un nouveau domaine.
    
    Pourquoi un en-tête par domaine ?
    - Ça structure l'évaluation visuellement
    - L'utilisateur sait où il en est (progression)
    - L'article de référence NIS 2 est visible (crédibilité)
    - Le poids indique l'importance relative du domaine
    """
    print()
    print(f"  {CYAN}{'━' * 56}{RESET}")
    print(f"  {WHITE}{BOLD}Domaine {domain_index}/{total_domains} : {domain.title}{RESET}")
    print(f"  {DIM}{domain.article_ref} | Poids : {domain.weight}x{RESET}")
    print(f"  {CYAN}{'━' * 56}{RESET}")
    print()


def display_question(req: SubRequirement, question_index: int, total_questions: int):
    """
    Affiche une question individuelle.
    
    Structure de chaque question :
    1. Numéro (progression globale)
    2. La question elle-même (claire, actionnable)
    3. Les 4 niveaux de réponse (toujours visibles pour rappel)
    
    Pourquoi afficher les niveaux à chaque question ?
    Parce que l'utilisateur ne doit jamais avoir à scroller
    pour se rappeler ce que signifie "2". Ça ralentit l'évaluation
    et introduit des erreurs.
    """
    print(f"  {BLUE}[{question_index}/{total_questions}]{RESET} {WHITE}{req.question}{RESET}")
    print()
    print(f"    {RED}0{RESET} — Non implemente")
    print(f"    {YELLOW}1{RESET} — Initial / Partiel")
    print(f"    {CYAN}2{RESET} — Defini / Implemente")
    print(f"    {GREEN}3{RESET} — Gere / Mesure")
    print()


def display_domain_result(domain: Domain, domain_index: int):
    """
    Affiche le score d'un domaine une fois toutes ses questions répondues.
    
    C'est un moment clé de l'expérience utilisateur :
    - Le score donne un feedback immédiat
    - La barre de progression visuelle rend le score tangible
    - Les gaps sont comptés pour alerter l'utilisateur
    
    La barre utilise des caractères bloc Unicode (█ et ░) pour
    créer une jauge visuelle directement dans le terminal.
    """
    score = domain.score
    gaps = domain.gap_count
    critical = domain.critical_gap_count
    
    # Choisir la couleur selon le score
    if score >= 66:
        color = GREEN
    elif score >= 33:
        color = YELLOW
    else:
        color = RED
    
    # Construire la barre de progression
    # On utilise 20 caractères pour la barre (chaque = 5%)
    filled = int(score / 5)
    empty = 20 - filled
    bar = f"{color}{'█' * filled}{DIM}{'░' * empty}{RESET}"
    
    print()
    print(f"  {DIM}{'─' * 40}{RESET}")
    print(f"  {WHITE}{BOLD}Score domaine {domain_index} :{RESET} {color}{BOLD}{score:.0f}%{RESET}  {bar}")
    
    if gaps > 0:
        gap_text = f"{gaps} gap(s)"
        if critical > 0:
            gap_text += f" dont {RED}{BOLD}{critical} critique(s){RESET}"
        print(f"  {DIM}Gaps identifies : {RESET}{gap_text}")
    else:
        print(f"  {GREEN}Aucun gap identifie sur ce domaine.{RESET}")
    
    print(f"  {DIM}{'─' * 40}{RESET}")
    print()


def display_final_result(domains: list[Domain], org_name: str):
    """
    Affiche le résultat final de l'évaluation complète.
    
    C'est l'écran le plus important — ce que l'utilisateur retient.
    
    Structure :
    1. Score global + Grade (le chiffre clé)
    2. Résumé par domaine (vue d'ensemble)
    3. Compteurs de gaps (urgence)
    4. Message d'orientation (next steps)
    
    Le grade (A-F) est plus mémorable qu'un pourcentage seul.
    "On a un C" est plus actionnable que "on est à 54%".
    """
    from nis2_analyzer.core.models import ComplianceGrade
    
    # Calcul du score global pondéré
    total_weight = sum(d.weight for d in domains)
    weighted_sum = sum(d.score * d.weight for d in domains)
    overall_score = weighted_sum / total_weight if total_weight > 0 else 0
    grade = ComplianceGrade.from_score(overall_score)
    
    # Compteurs globaux
    total_reqs = sum(d.total_requirements for d in domains)
    total_gaps = sum(d.gap_count for d in domains)
    total_critical = sum(d.critical_gap_count for d in domains)
    compliant = total_reqs - total_gaps
    
    # Couleur du grade
    grade_colors = {"A": GREEN, "B": BLUE, "C": YELLOW, "D": RED, "F": RED}
    gc = grade_colors.get(grade.value, WHITE)
    
    print()
    print()
    print(f"  {CYAN}{'═' * 56}{RESET}")
    print(f"  {WHITE}{BOLD}  RESULTAT DE L'EVALUATION NIS 2{RESET}")
    print(f"  {DIM}  Organisation : {org_name}{RESET}")
    print(f"  {CYAN}{'═' * 56}{RESET}")
    print()
    
    # Score global
    print(f"  {WHITE}Score global :{RESET}   {gc}{BOLD}{overall_score:.0f}%{RESET}")
    print(f"  {WHITE}Grade        :{RESET}   {gc}{BOLD}{grade.value}{RESET}")
    print(f"  {DIM}{grade.description}{RESET}")
    print()
    
    # Barre globale
    filled = int(overall_score / 5)
    empty = 20 - filled
    bar = f"{gc}{'█' * filled}{DIM}{'░' * empty}{RESET}"
    print(f"  {bar}  {gc}{overall_score:.0f}%{RESET}")
    print()
    
    # Résumé par domaine
    print(f"  {WHITE}{BOLD}Scores par domaine :{RESET}")
    print()
    
    for i, domain in enumerate(domains, 1):
        ds = domain.score
        if ds >= 66:
            dc = GREEN
        elif ds >= 33:
            dc = YELLOW
        else:
            dc = RED
        
        # Barre mini (10 caractères)
        df = int(ds / 10)
        de = 10 - df
        dbar = f"{dc}{'█' * df}{'░' * de}{RESET}"
        
        # Nom du domaine tronqué pour l'alignement
        name = domain.title[:38].ljust(38)
        print(f"  {DIM}{i:2d}.{RESET} {name}  {dbar}  {dc}{ds:5.1f}%{RESET}")
    
    print()
    
    # Compteurs
    print(f"  {CYAN}{'─' * 56}{RESET}")
    print(f"  {WHITE}Exigences evaluees  :{RESET}  {BOLD}{total_reqs}{RESET}")
    print(f"  {GREEN}Conformes (>=N2)    :{RESET}  {GREEN}{BOLD}{compliant}{RESET}")
    print(f"  {YELLOW}Gaps identifies     :{RESET}  {YELLOW}{BOLD}{total_gaps}{RESET}")
    print(f"  {RED}Gaps critiques (N0) :{RESET}  {RED}{BOLD}{total_critical}{RESET}")
    print(f"  {CYAN}{'─' * 56}{RESET}")
    print()
    
    # Message d'orientation selon le grade
    if grade.value == "A":
        print(f"  {GREEN}Votre organisation presente une posture de securite robuste.{RESET}")
        print(f"  {GREEN}Maintenez le cap et poursuivez l'amelioration continue.{RESET}")
    elif grade.value == "B":
        print(f"  {BLUE}Bonne posture globale. Concentrez-vous sur les gaps restants{RESET}")
        print(f"  {BLUE}pour atteindre la pleine conformite.{RESET}")
    elif grade.value == "C":
        print(f"  {YELLOW}Fondations en place mais gaps significatifs a combler.{RESET}")
        print(f"  {YELLOW}Priorisez les quick wins et les domaines critiques.{RESET}")
    elif grade.value == "D":
        print(f"  {RED}Mesures partielles. Un plan de remediation structure est{RESET}")
        print(f"  {RED}necessaire avec priorisation par criticite.{RESET}")
    else:
        print(f"  {RED}{BOLD}Lacunes critiques identifiees. Un plan de remediation{RESET}")
        print(f"  {RED}{BOLD}urgent est necessaire. Commencez par les quick wins.{RESET}")
    
    print()


def prompt_org_name() -> str:
    """
    Demande le nom de l'organisation.
    
    Pourquoi demander le nom ?
    - Personnalise le rapport
    - L'utilisateur s'engage psychologiquement dans l'évaluation
    - Le nom apparaîtra dans le rapport HTML exporté
    
    Si l'utilisateur appuie juste sur Entrée, on met "Mon Organisation"
    par défaut — on ne bloque pas sur un champ optionnel.
    """
    print(f"  {WHITE}Nom de l'organisation :{RESET} ", end="")
    name = input().strip()
    if not name:
        name = "Mon Organisation"
    return name


def prompt_maturity() -> Optional[MaturityLevel]:
    """
    Capture la réponse de l'utilisateur pour une question.
    
    Gestion des cas :
    - 0, 1, 2, 3 : réponses valides → retourne le MaturityLevel
    - 's' ou 'skip' : passer la question → retourne None
    - 'q' ou 'quit' : quitter l'évaluation → lève KeyboardInterrupt
    - Autre chose : message d'erreur et on re-demande
    
    Pourquoi permettre de skipper ?
    Parce qu'un RSSI peut ne pas avoir l'information pour
    certaines questions. Mieux vaut un "je ne sais pas" honnête
    qu'une réponse inventée qui fausse le score.
    """
    while True:
        print(f"  {WHITE}Votre reponse (0-3, s=passer, q=quitter) :{RESET} ", end="")
        try:
            answer = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            raise KeyboardInterrupt()
        
        if answer in ('q', 'quit', 'quitter'):
            raise KeyboardInterrupt()
        
        if answer in ('s', 'skip', 'passer'):
            print(f"  {DIM}Question passee.{RESET}")
            print()
            return None
        
        if answer in ('0', '1', '2', '3'):
            level = MaturityLevel(int(answer))
            
            # Feedback visuel immédiat
            feedback_colors = {
                0: RED,
                1: YELLOW,
                2: CYAN,
                3: GREEN,
            }
            color = feedback_colors[level.value]
            print(f"  {color}→ {level.label}{RESET}")
            print()
            return level
        
        print(f"  {RED}Reponse invalide. Tapez 0, 1, 2, 3, s ou q.{RESET}")
        print()


def prompt_continue() -> bool:
    """
    Demande à l'utilisateur s'il veut continuer après le résultat d'un domaine.
    Permet de faire une pause entre les domaines.
    """
    print(f"  {DIM}Appuyez sur Entree pour continuer (q pour quitter)...{RESET}", end="")
    try:
        answer = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer not in ('q', 'quit', 'quitter')


def prompt_export(default_path: str = "reports/assessment_result.json") -> Optional[str]:
    """
    Demande si l'utilisateur veut exporter les résultats.
    
    Pourquoi demander ?
    Un utilisateur qui fait un test rapide n'a peut-être pas besoin
    d'un fichier JSON. Mais un RSSI qui fait une vraie évaluation
    voudra garder les résultats pour son rapport.
    """
    print(f"  {WHITE}Exporter les resultats ? (o/n) :{RESET} ", end="")
    try:
        answer = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return None
    
    if answer in ('o', 'oui', 'y', 'yes'):
        print(f"  {WHITE}Chemin du fichier [{default_path}] :{RESET} ", end="")
        path = input().strip()
        if not path:
            path = default_path
        return path
    
    return None


# ═══════════════════════════════════════════════
# FONCTION PRINCIPALE
# ═══════════════════════════════════════════════

def run_assessment(framework_path: str = None) -> tuple[list[Domain], str]:
    """
    Orchestre l'évaluation complète.
    
    C'est la fonction principale du Jour 2. Voici son déroulement :
    
    1. Charger le référentiel NIS 2 (Jour 1)
    2. Afficher la bannière et les instructions
    3. Demander le nom de l'organisation
    4. Pour chaque domaine :
       a. Afficher l'en-tête du domaine
       b. Pour chaque sous-exigence :
          - Afficher la question
          - Capturer la réponse (0-3 ou skip)
          - Mettre à jour le niveau de maturité
       c. Afficher le score du domaine
       d. Pause entre les domaines
    5. Afficher le résultat final
    6. Proposer l'export JSON
    
    Retourne :
    - La liste des domaines avec les maturités renseignées
    - Le nom de l'organisation
    
    Ces données seront passées au ScoringEngine (Jour 1) et
    au ReportGenerator (Jour 5) pour produire les livrables.
    """
    # Étape 1 : Charger le référentiel
    domains = load_framework(framework_path)
    
    # Étape 2 : Affichage initial
    clear_screen()
    display_banner()
    display_welcome()
    
    # Étape 3 : Nom de l'organisation
    org_name = prompt_org_name()
    
    # Compteur global de questions
    total_questions = sum(d.total_requirements for d in domains)
    current_question = 0
    
    try:
        # Étape 4 : Parcourir les domaines
        for domain_idx, domain in enumerate(domains, 1):
            display_domain_header(domain, domain_idx, len(domains))
            
            # Parcourir les sous-exigences du domaine
            for req in domain.sub_requirements:
                current_question += 1
                display_question(req, current_question, total_questions)
                
                # Capturer la réponse
                maturity = prompt_maturity()
                
                # Mettre à jour le niveau de maturité
                # Si l'utilisateur a skippé (None), on ne touche pas
                if maturity is not None:
                    req.maturity = maturity
            
            # Score du domaine
            display_domain_result(domain, domain_idx)
            
            # Pause entre les domaines (sauf le dernier)
            if domain_idx < len(domains):
                if not prompt_continue():
                    # L'utilisateur veut quitter — on affiche quand même
                    # le résultat partiel
                    print(f"\n  {YELLOW}Evaluation interrompue. Resultats partiels :{RESET}")
                    break
        
        # Étape 5 : Résultat final
        clear_screen()
        display_banner()
        display_final_result(domains, org_name)
        
    except KeyboardInterrupt:
        # Ctrl+C ou 'q' — on affiche le résultat partiel
        print(f"\n\n  {YELLOW}Evaluation interrompue. Resultats partiels :{RESET}\n")
        display_final_result(domains, org_name)
    
    return domains, org_name
