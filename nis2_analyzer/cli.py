"""
COMPASS — CLI Entry Point
Usage : python -m nis2_analyzer [options]

Modes disponibles :
1. Interactif     : python -m nis2_analyzer
2. Demo           : python -m nis2_analyzer --demo
3. Bridge + Inter : python -m nis2_analyzer --bridge rapport_cloudsec.json
4. Complet        : python -m nis2_analyzer --demo --bridge rapport.json --report reports/rapport.html --size eti --sector industrie --revenue 50000000
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nis2_analyzer.core.models import load_framework, MaturityLevel
from nis2_analyzer.core.scoring import ScoringEngine
from nis2_analyzer.assessment.exporter import export_to_json

BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
WHITE = "\033[97m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"


def run_demo_mode(with_bridge=False, with_financial=False, profile=None, report_path=None, no_save=False):
    """Mode demo avec toutes les couches."""
    from nis2_analyzer.assessment.interactive import display_banner

    display_banner()
    print(f"  {YELLOW}{BOLD}MODE DEMO{RESET}")
    print(f"  {DIM}Simulation d'une evaluation avec reponses predefinies.{RESET}")
    print()

    domains = load_framework()
    org_name = profile.name if profile else "IndustrieCorp SA"
    bridge_result = None

    if with_bridge:
        from nis2_analyzer.connectors.cloudsec_bridge import CloudSecBridge
        bridge = CloudSecBridge()
        try:
            bridge.load_cloudsec_report(with_bridge)
            bridge.map_to_nis2()
            bridge_result = bridge.apply_to_framework(domains)
            bridge.display_summary()
            print(f"  {GREEN}{BOLD}{bridge_result['auto_filled']}{RESET}{GREEN} questions pre-remplies par l'audit technique.{RESET}")
            print(f"  {DIM}{bridge_result['remaining_manual']} questions restantes a remplir.{RESET}")
            print()
        except FileNotFoundError as e:
            print(f"  {RED}Erreur : {e}{RESET}")
            print()
            with_bridge = False

    demo_answers = {
        "NIS2-D01-R01": 2, "NIS2-D01-R02": 2, "NIS2-D01-R03": 1, "NIS2-D01-R04": 2, "NIS2-D01-R05": 1,
        "NIS2-D02-R01": 2, "NIS2-D02-R02": 1, "NIS2-D02-R03": 0, "NIS2-D02-R04": 1,
        "NIS2-D03-R01": 1, "NIS2-D03-R02": 2, "NIS2-D03-R03": 0, "NIS2-D03-R04": 0,
        "NIS2-D04-R01": 0, "NIS2-D04-R02": 1, "NIS2-D04-R03": 0,
        "NIS2-D05-R01": 1, "NIS2-D05-R02": 2, "NIS2-D05-R03": 2,
        "NIS2-D06-R01": 1, "NIS2-D06-R02": 0,
        "NIS2-D07-R01": 2, "NIS2-D07-R02": 1, "NIS2-D07-R03": 2, "NIS2-D07-R04": 0, "NIS2-D07-R05": 1,
        "NIS2-D08-R01": 2, "NIS2-D08-R02": 2,
        "NIS2-D09-R01": 2, "NIS2-D09-R02": 2, "NIS2-D09-R03": 1, "NIS2-D09-R04": 1,
        "NIS2-D10-R01": 3, "NIS2-D10-R02": 2, "NIS2-D10-R03": 1,
    }

    for domain in domains:
        for req in domain.sub_requirements:
            if req.maturity is None and req.id in demo_answers:
                req.maturity = MaturityLevel(demo_answers[req.id])

    _display_results(domains, org_name)

    financial_dict = None
    if with_financial and profile:
        financial_dict = _run_financial(domains, profile)

    if report_path:
        _generate_report(domains, org_name, financial_dict, bridge_result, report_path)

    _save_assessment(domains, org_name, skip=no_save)
    return domains, org_name


def run_bridge_interactive(bridge_path, profile=None, report_path=None, no_save=False):
    """
    Mode bridge + interactif.
    Le bridge pre-remplit les questions techniques.
    L'utilisateur repond aux questions organisationnelles restantes.
    """
    from nis2_analyzer.assessment.interactive import (
        display_banner, display_domain_header,
        display_question, display_domain_result, display_final_result,
        prompt_org_name, prompt_maturity, prompt_continue, clear_screen,
    )
    from nis2_analyzer.connectors.cloudsec_bridge import CloudSecBridge

    domains = load_framework()

    clear_screen()
    display_banner()

    print(f"  {CYAN}{BOLD}MODE BRIDGE + INTERACTIF{RESET}")
    print(f"  {DIM}Chargement de l'audit technique...{RESET}")
    print()

    bridge = CloudSecBridge()
    bridge_result = None
    try:
        bridge.load_cloudsec_report(bridge_path)
        bridge.map_to_nis2()
        bridge_result = bridge.apply_to_framework(domains)
        bridge.display_summary()
    except (FileNotFoundError, ValueError) as e:
        print(f"  {RED}Erreur : {e}{RESET}")
        print(f"  {DIM}Passage en mode interactif standard.{RESET}")
        print()

    auto_filled = sum(1 for d in domains for r in d.sub_requirements if r.maturity is not None)
    remaining = sum(1 for d in domains for r in d.sub_requirements if r.maturity is None)

    if bridge_result:
        print(f"  {GREEN}{BOLD}{auto_filled}{RESET}{GREEN} questions pre-remplies par l'audit Azure.{RESET}")
        print(f"  {WHITE}{BOLD}{remaining}{RESET}{WHITE} questions organisationnelles restantes.{RESET}")
        print()
        print(f"  {DIM}Les reponses pre-remplies seront affichees.{RESET}")
        print(f"  {DIM}Vous pourrez les corriger si necessaire.{RESET}")
        print()

    input(f"  {DIM}Appuyez sur Entree pour commencer...{RESET}")

    clear_screen()
    display_banner()
    org_name = prompt_org_name()

    total_questions = sum(d.total_requirements for d in domains)
    current_question = 0

    try:
        for domain_idx, domain in enumerate(domains, 1):
            display_domain_header(domain, domain_idx, len(domains))

            for req in domain.sub_requirements:
                current_question += 1

                if req.maturity is not None and req.notes.startswith("[AUTO"):
                    _display_auto_filled(req, current_question, total_questions)
                else:
                    display_question(req, current_question, total_questions)
                    maturity = prompt_maturity()
                    if maturity is not None:
                        req.maturity = maturity

            display_domain_result(domain, domain_idx)

            if domain_idx < len(domains):
                if not prompt_continue():
                    print(f"\n  {YELLOW}Evaluation interrompue. Resultats partiels :{RESET}")
                    break

        clear_screen()
        display_banner()
        display_final_result(domains, org_name)

    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}Evaluation interrompue. Resultats partiels :{RESET}\n")
        display_final_result(domains, org_name)

    financial_dict = None
    if profile:
        financial_dict = _run_financial(domains, profile)

    if report_path:
        _generate_report(domains, org_name, financial_dict, bridge_result, report_path)

    _save_assessment(domains, org_name, skip=no_save)
    return domains, org_name


def _display_auto_filled(req, question_index, total_questions):
    """Affiche une question pre-remplie par le bridge avec option de correction."""
    level = req.maturity
    colors = {0: RED, 1: YELLOW, 2: CYAN, 3: GREEN}
    color = colors.get(level.value, WHITE)

    print(f"  {BLUE}[{question_index}/{total_questions}]{RESET} {WHITE}{req.question}{RESET}")
    print()
    print(f"  {MAGENTA}  PRE-REMPLI PAR AUDIT TECHNIQUE{RESET}")
    print(f"    {color}Niveau {level.value} — {level.label}{RESET}")

    note = req.notes.replace("[AUTO - CloudSec] ", "")
    print(f"    {DIM}{note}{RESET}")
    print()
    print(f"    {DIM}(Entree = accepter, 0-3 = corriger){RESET}")

    try:
        answer = input(f"    {WHITE}>{RESET} ").strip()
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt()

    if answer in ('0', '1', '2', '3'):
        old_label = level.label
        req.maturity = MaturityLevel(int(answer))
        req.notes = f"[CORRIGE] Reponse manuelle (etait: {old_label})"
        new_color = colors.get(req.maturity.value, WHITE)
        print(f"    {new_color}Corrige : {req.maturity.label}{RESET}")
    else:
        print(f"    {GREEN}Accepte{RESET}")
    print()


def _display_results(domains, org_name):
    """Affiche les resultats de scoring dans le terminal."""
    print(f"  {WHITE}{BOLD}Resultats de l'evaluation :{RESET}")
    print()

    for i, domain in enumerate(domains, 1):
        ds = domain.score
        gaps = domain.gap_count
        dc = GREEN if ds >= 66 else YELLOW if ds >= 33 else RED
        filled = int(ds / 10)
        empty = 10 - filled
        bar = f"{dc}{'█' * filled}{'░' * empty}{RESET}"
        name = domain.title[:38].ljust(38)
        gap_info = f"  {DIM}({gaps} gap{'s' if gaps != 1 else ''}){RESET}" if gaps > 0 else ""
        print(f"  {DIM}{i:2d}.{RESET} {name}  {bar}  {dc}{ds:5.1f}%{RESET}{gap_info}")

    print()

    engine = ScoringEngine()
    analysis = engine.full_analysis(domains, org_name)
    overall = analysis["scores"]["overall_score"]
    grade = analysis["scores"]["grade"]
    total_gaps = analysis["scores"]["total_gaps"]
    critical = analysis["scores"]["total_critical_gaps"]
    gc = {
        "A": GREEN, "B": BLUE, "C": YELLOW, "D": RED, "F": RED
    }.get(grade, WHITE)

    print(f"  {CYAN}{'═' * 56}{RESET}")
    print(f"  {WHITE}Score global :{RESET}  {gc}{BOLD}{overall}%{RESET}  |  {WHITE}Grade :{RESET}  {gc}{BOLD}{grade}{RESET}")
    print(f"  {WHITE}Gaps totaux  :{RESET}  {YELLOW}{BOLD}{total_gaps}{RESET}  |  {WHITE}Critiques :{RESET}  {RED}{BOLD}{critical}{RESET}")
    print(f"  {CYAN}{'═' * 56}{RESET}")
    print()

    print(f"  {WHITE}{BOLD}Plan d'action :{RESET}")
    print(f"    Actions immediates  : {RED}{BOLD}{analysis['action_plan']['immediate']}{RESET}")
    print(f"    Court terme         : {YELLOW}{BOLD}{analysis['action_plan']['short_term']}{RESET}")
    print(f"    Moyen terme         : {analysis['action_plan']['medium_term']}")
    print(f"    Long terme          : {analysis['action_plan']['long_term']}")
    print()

    iso = analysis["iso27001_mapping"]
    print(f"  {WHITE}{BOLD}Couverture ISO 27001 :{RESET}  {iso['coverage_pct']}%")
    print(f"    Controles references : {iso['total_controls_referenced']}")
    print(f"    Controles couverts   : {iso['controls_covered']}")
    print()


def _run_financial(domains, profile):
    """Lance l'analyse financiere."""
    from nis2_analyzer.core.risk_engine import RiskEngine
    engine = RiskEngine(profile)
    report = engine.analyze(domains)
    engine.display_summary(report)
    return engine.to_dict(report)


def _generate_report(domains, org_name, financial_dict, bridge_result, report_path):
    """Genere le rapport HTML unifie."""
    from nis2_analyzer.reporting.html_report import generate_report
    path = generate_report(
        domains=domains,
        org_name=org_name,
        financial_report=financial_dict,
        bridge_summary=bridge_result,
        output_path=report_path,
    )
    print(f"  {GREEN}{BOLD}Rapport HTML genere : {path}{RESET}")
    print(f"  {DIM}Ouvrez ce fichier dans votre navigateur.{RESET}")
    print()


def _save_assessment(domains, org_name, skip=False):
    """Sauvegarde un assessment dans l'historique SQLite."""
    if skip:
        return None
    try:
        from nis2_analyzer.core.database import save_assessment
        from nis2_analyzer.core.scoring import ScoringEngine
        engine = ScoringEngine()
        analysis = engine.full_analysis(domains, org_name)
        assessment_id = save_assessment(analysis)
        print(f"  {DIM}Assessment #{assessment_id} sauvegarde dans l'historique.{RESET}")
        print(f"  {DIM}Consultez avec : python -m nis2_analyzer --history{RESET}")
        print()
        return assessment_id
    except Exception as e:
        print(f"  {YELLOW}Avertissement : impossible de sauvegarder l'historique ({e}){RESET}")
        return None


def _cmd_history(org_name=None):
    """Affiche l'historique des assessments."""
    from nis2_analyzer.core.database import list_assessments
    rows = list_assessments(org_name=org_name)
    if not rows:
        print(f"\n  {DIM}Aucun assessment enregistre.{RESET}")
        print(f"  {DIM}Lancez une evaluation pour commencer a construire votre historique.{RESET}\n")
        return
    print(f"\n  {BOLD}Historique des assessments{RESET}")
    if org_name:
        print(f"  {DIM}Filtre : \"{org_name}\"{RESET}")
    print(f"  {'─' * 62}")
    print(f"  {'ID':<5} {'Organisation':<22} {'Date':<12} {'Score':>6} {'Grade':>6} {'Gaps':>5}")
    print(f"  {'─' * 62}")
    for r in rows:
        date = r["assessed_at"][:10]
        print(f"  {r['id']:<5} {r['org_name'][:21]:<22} {date:<12} {r['score']:>5.1f}% {r['grade']:>6} {r['total_gaps']:>5}")
    print(f"  {'─' * 62}")
    print(f"  {DIM}Comparez deux assessments : python -m nis2_analyzer --compare ID_A ID_B{RESET}\n")


def _cmd_compare(id_a, id_b):
    """Compare deux assessments et affiche le delta."""
    from nis2_analyzer.core.database import compare_assessments
    try:
        delta = compare_assessments(id_a, id_b)
    except ValueError as e:
        print(f"\n  {RED}Erreur : {e}{RESET}\n")
        return

    score_delta = delta["score_delta"]
    gaps_delta = delta["gaps_delta"]
    arrow_score = f"{GREEN}▲ +{score_delta}%{RESET}" if score_delta > 0 else (f"{RED}▼ {score_delta}%{RESET}" if score_delta < 0 else f"{DIM}= stable{RESET}")
    arrow_gaps = f"{GREEN}▼ {gaps_delta}{RESET}" if gaps_delta < 0 else (f"{RED}▲ +{gaps_delta}{RESET}" if gaps_delta > 0 else f"{DIM}= stable{RESET}")

    print(f"\n  {BOLD}Comparaison d'assessments — {delta['org_name']}{RESET}")
    print(f"  {DIM}#{id_a} ({delta['date_before'][:10]}) → #{id_b} ({delta['date_after'][:10]}){RESET}")
    print(f"  {'─' * 50}")
    print(f"  Score global : {delta['score_before']}% → {delta['score_after']}%  {arrow_score}")
    print(f"  Grade        : {delta['grade_before']} → {delta['grade_after']}")
    print(f"  Gaps ouverts : {delta['gaps_before']} → {delta['gaps_after']}  {arrow_gaps}")
    print(f"  {'─' * 50}")
    print(f"  {BOLD}Evolution par domaine :{RESET}")
    for d in delta["domains"]:
        if d["delta"] is None:
            continue
        if d["delta"] > 0:
            indicator = f"{GREEN}▲ +{d['delta']}%{RESET}"
        elif d["delta"] < 0:
            indicator = f"{RED}▼ {d['delta']}%{RESET}"
        else:
            indicator = f"{DIM}={RESET}"
        print(f"    {d['domain'][:38]:<38} {indicator}")
    print()


def _parse_profile(args):
    """Construit le profil d'organisation a partir des arguments CLI."""
    from nis2_analyzer.core.financial import OrganizationProfile, OrgSize, Sector

    size_map = {"pme": OrgSize.PME, "eti": OrgSize.ETI, "grand": OrgSize.GRAND_GROUPE}
    sector_map = {
        "sante": Sector.SANTE, "finance": Sector.FINANCE, "energie": Sector.ENERGIE,
        "industrie": Sector.INDUSTRIE, "numerique": Sector.NUMERIQUE,
        "transport": Sector.TRANSPORT, "administration": Sector.ADMINISTRATION,
        "autre": Sector.AUTRE,
    }

    return OrganizationProfile(
        name=args.org_name or "Mon Organisation",
        size=size_map.get(args.size, OrgSize.ETI),
        sector=sector_map.get(args.sector, Sector.AUTRE),
        annual_revenue=args.revenue,
    )


def _cmd_qualify(args):
    """Qualification NIS 2 Art. 3 — affiche la categorie et les obligations."""
    from nis2_analyzer.core.entity_qualification import qualify_entity, EntityProfile, EntityCategory, ALL_SECTORS

    sector = getattr(args, "sector", "autre") or "autre"
    employees = getattr(args, "employees", 0) or 0
    revenue = getattr(args, "revenue", 0.0) or 0.0
    org_name = getattr(args, "org_name", None) or "Organisation"

    profile = EntityProfile(
        sector=sector,
        employees=employees,
        annual_revenue_eur=revenue,
        is_critical_infrastructure=getattr(args, "critical_infra", False),
        provides_essential_digital_service=getattr(args, "essential_digital", False),
        org_name=org_name,
    )

    result = qualify_entity(profile)
    cat = result.category

    color_map = {
        EntityCategory.ESSENTIAL:   RED,
        EntityCategory.IMPORTANT:   YELLOW,
        EntityCategory.OUT_OF_SCOPE: DIM,
    }
    cat_color = color_map.get(cat, WHITE)

    sector_label = ALL_SECTORS.get(sector, sector)
    print()
    print(f"  {BOLD}{CYAN}Qualification NIS 2 — Article 3{RESET}")
    print(f"  {DIM}Organisation : {org_name}{RESET}")
    print(f"  {DIM}Secteur      : {sector_label} (Annexe {result.sector_annex}){RESET}")
    print(f"  {DIM}Taille       : {employees} ETP | {revenue/1e6:.1f}M€ CA{RESET}")
    print()
    print(f"  Categorie : {cat_color}{BOLD}{result.category.label.upper()}{RESET}")
    print()

    print(f"  {WHITE}{BOLD}Motifs de qualification :{RESET}")
    for r in result.reasons:
        print(f"    {DIM}•{RESET} {r}")
    print()

    print(f"  {WHITE}{BOLD}Obligations principales :{RESET}")
    o = result.obligations
    print(f"    Supervision           : {o['supervision']}")
    print(f"    Early warning         : {o['notification_early_warning']}")
    print(f"    Rapport complet       : {o['notification_full_report']}")
    print(f"    Rapport final         : {o['notification_final_report']}")
    print(f"    Sanction max (entite) : {cat_color}{o['sanction_max_persons_morales']}{RESET}")
    print(f"    Audit obligatoire     : {'Oui' if o['audit_obligatoire'] else 'Non'}")
    print()

    if result.recommendations:
        print(f"  {WHITE}{BOLD}Recommandations :{RESET}")
        for rec in result.recommendations:
            print(f"    {GREEN}→{RESET} {rec}")
        print()

    if result.caveats:
        print(f"  {WHITE}{BOLD}Points d'attention :{RESET}")
        for c in result.caveats:
            print(f"    {YELLOW}⚠{RESET}  {c}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="COMPASS — Compliance Posture Assessment System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :

  Evaluation interactive :
    python -m nis2_analyzer

  Mode demonstration :
    python -m nis2_analyzer --demo

  Demo complete (bridge + financier + rapport HTML) :
    python -m nis2_analyzer --demo --bridge tests/mock_data/cloudsec_report.json --report reports/rapport.html --size eti --sector industrie --revenue 50000000

  Bridge + interactif + rapport :
    python -m nis2_analyzer --bridge rapport_cloudsec.json --report reports/rapport.html --size pme --sector sante
        """
    )

    parser.add_argument("--demo", action="store_true",
                        help="Mode demonstration avec reponses simulees")
    parser.add_argument("--bridge", "-b", default=None,
                        help="Chemin du rapport CloudSec Audit Toolkit (JSON)")
    parser.add_argument("--report", "-r", default=None,
                        help="Chemin du rapport HTML de sortie")
    parser.add_argument("--output", "-o", default=None,
                        help="Chemin du fichier JSON de sortie")
    parser.add_argument("--size", default="eti", choices=["pme", "eti", "grand"],
                        help="Taille de l'organisation")
    parser.add_argument("--sector", default="autre",
                        choices=["sante", "finance", "energie", "industrie",
                                 "numerique", "transport", "administration", "autre"],
                        help="Secteur d'activite")
    parser.add_argument("--revenue", type=float, default=None,
                        help="Chiffre d'affaires annuel en euros")
    parser.add_argument("--org-name", default=None,
                        help="Nom de l'organisation")
    parser.add_argument("--history", action="store_true",
                        help="Affiche l'historique des assessments enregistres")
    parser.add_argument("--compare", nargs=2, type=int, metavar=("ID_A", "ID_B"),
                        help="Compare deux assessments par leur ID (ex: --compare 1 3)")
    parser.add_argument("--no-save", action="store_true",
                        help="Ne pas sauvegarder cet assessment dans l'historique")
    parser.add_argument("--qualify", action="store_true",
                        help="Qualification NIS 2 Art. 3 : determine si l'entite est Essentielle ou Importante")
    parser.add_argument("--employees", type=int, default=0,
                        help="Nombre de salaries (pour --qualify)")
    parser.add_argument("--critical-infra", action="store_true",
                        help="Entite identifiee comme infrastructure critique nationale (pour --qualify)")
    parser.add_argument("--essential-digital", action="store_true",
                        help="Fournit un service numerique essentiel DNS/IXP/cloud/CDN/MSP (pour --qualify)")

    args = parser.parse_args()

    # ── Qualification NIS 2 Art. 3 ──
    if args.qualify:
        _cmd_qualify(args)
        return

    # ── Commandes d'historique (pas d'assessment) ──
    if args.history:
        _cmd_history(org_name=args.org_name)
        return

    if args.compare:
        _cmd_compare(args.compare[0], args.compare[1])
        return

    profile = None
    if args.size or args.sector or args.revenue or args.report:
        profile = _parse_profile(args)

    try:
        if args.demo:
            run_demo_mode(
                with_bridge=args.bridge,
                with_financial=(profile is not None),
                profile=profile,
                report_path=args.report,
                no_save=args.no_save,
            )

        elif args.bridge:
            run_bridge_interactive(
                bridge_path=args.bridge,
                profile=profile,
                report_path=args.report,
                no_save=args.no_save,
            )

        else:
            from nis2_analyzer.assessment.interactive import run_assessment, prompt_export

            domains, org_name = run_assessment()

            financial_dict = None
            if profile:
                financial_dict = _run_financial(domains, profile)

            if args.report:
                _generate_report(domains, org_name, financial_dict, None, args.report)

            _save_assessment(domains, org_name, skip=args.no_save)

            export_path = args.output
            if export_path is None:
                export_path = prompt_export()
            if export_path:
                path = export_to_json(domains, org_name, export_path)
                print(f"  {GREEN}Resultats exportes : {path}{RESET}")
                print()

            print(f"  {DIM}Merci d'avoir utilise COMPASS.{RESET}")
            print(f"  {DIM}github.com/RyanRoy23{RESET}")
            print()

    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}Evaluation annulee.{RESET}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
