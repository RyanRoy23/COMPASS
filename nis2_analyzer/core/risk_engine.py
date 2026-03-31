"""
NIS 2 Risk Analyzer — Risk Quantification Engine
Traduit chaque gap de conformité en impact financier estimé.

Méthodologie de calcul :
1. Pour chaque gap, on identifie les scénarios de risque applicables
2. Pour chaque scénario, on calcule :
   - Probabilité annuelle (ajustée selon le niveau de maturité)
   - Impact financier (selon la taille de l'organisation)
   - Exposition = Probabilité × Impact (formule ALE classique)
3. L'exposition totale est la somme de toutes les expositions
4. Le ROI de remédiation = exposition éliminée / effort estimé

ALE (Annualized Loss Expectancy) est la méthode standard
utilisée par les risk managers (ISO 27005, FAIR, NIST SP 800-30).
Ce n'est pas une invention — c'est la pratique de l'industrie.
"""

from dataclasses import dataclass, field
from nis2_analyzer.core.models import Domain, SubRequirement, MaturityLevel
from nis2_analyzer.core.financial import (
    OrganizationProfile, OrgSize, Sector,
    IncidentType, COST_DATABASE, GAP_TO_RISK_SCENARIOS,
)


@dataclass
class RiskExposure:
    """
    Exposition financière pour un gap spécifique.
    
    C'est ce qui apparaîtra dans le rapport :
    "Gap NIS2-D10-R01 (MFA) → exposition estimée : 75K€ - 300K€/an"
    """
    requirement_id: str
    requirement_title: str
    domain_title: str
    current_maturity: int
    incident_type: str
    incident_label: str
    probability: float           # Probabilité annuelle (0-1)
    impact_low: float            # Impact bas en euros
    impact_mid: float            # Impact moyen en euros
    impact_high: float           # Impact haut en euros
    exposure_low: float          # ALE bas = probabilité × impact_low
    exposure_mid: float          # ALE moyen = probabilité × impact_mid
    exposure_high: float         # ALE haut = probabilité × impact_high
    rationale: str               # Justification du scénario
    source: str                  # Source des données de coût


@dataclass
class RemediationROI:
    """
    Retour sur investissement d'une action de remédiation.
    
    Le RSSI présente ça à sa direction :
    "En activant le MFA (effort : 5 jours), on réduit notre
    exposition annuelle de 225K€. ROI = 45K€ par jour d'effort."
    """
    requirement_id: str
    requirement_title: str
    action: str                  # Quick win ou implémentation complète
    effort_label: str            # "Rapide (< 1 mois)", etc.
    exposure_eliminated_low: float
    exposure_eliminated_mid: float
    exposure_eliminated_high: float
    priority_score: float        # Plus élevé = plus urgent


@dataclass
class FinancialReport:
    """Rapport financier complet."""
    organization: OrganizationProfile
    total_exposure_low: float
    total_exposure_mid: float
    total_exposure_high: float
    max_nis2_fine: float
    exposures: list[RiskExposure]
    remediation_roi: list[RemediationROI]
    top_risks: list[RiskExposure]        # Top 5 risques par exposition
    quick_wins_value: float              # Valeur €€ des quick wins


class RiskEngine:
    """
    Moteur de quantification du risque financier.
    
    Usage :
        engine = RiskEngine(profile)
        report = engine.analyze(domains)
        engine.display_summary(report)
    """

    def __init__(self, profile: OrganizationProfile = None):
        if profile is None:
            profile = OrganizationProfile()
        self.profile = profile

    def _adjust_probability(self, base_probability: float, maturity: int) -> float:
        """
        Ajuste la probabilité selon le niveau de maturité.
        
        Logique :
        - Niveau 0 (non implémenté) : probabilité × 1.5 (pire que la base)
        - Niveau 1 (partiel) : probabilité × 1.0 (base = partiellement exposé)
        - Niveau 2 (implémenté) : probabilité × 0.3 (mesure en place, risque résiduel)
        - Niveau 3 (géré) : probabilité × 0.1 (surveillance active, risque minimal)
        
        Pourquoi ces multiplicateurs ?
        Un contrôle complètement absent (N0) est pire qu'un contrôle partiel (N1).
        Un contrôle en place (N2) réduit fortement le risque mais ne l'élimine pas.
        Un contrôle surveillé (N3) représente le risque résiduel incompressible.
        
        Ces facteurs sont alignés avec la méthodologie FAIR (Factor Analysis
        of Information Risk) utilisée dans l'industrie.
        """
        multipliers = {
            0: 1.5,   # Pire que la base — aucune protection
            1: 1.0,   # Base — protection incohérente
            2: 0.3,   # Mesure en place — risque résiduel
            3: 0.1,   # Surveillance active — risque minimal
        }
        adjusted = base_probability * multipliers.get(maturity, 1.0)
        return min(adjusted, 0.95)  # Plafonner à 95%

    def _get_cost(self, incident_type: IncidentType) -> dict:
        """Récupère les coûts pour un type d'incident selon la taille de l'organisation."""
        size = self.profile.size
        if incident_type in COST_DATABASE and size in COST_DATABASE[incident_type]:
            return COST_DATABASE[incident_type][size]
        # Fallback sur ETI si la taille n'est pas trouvée
        return COST_DATABASE.get(incident_type, {}).get(OrgSize.ETI, {
            "cost_low": 100_000,
            "cost_mid": 500_000,
            "cost_high": 2_000_000,
            "source": "Estimation par défaut",
        })

    def analyze(self, domains: list[Domain]) -> FinancialReport:
        """
        Analyse financière complète.
        
        Pour chaque gap identifié :
        1. Trouver les scénarios de risque applicables
        2. Calculer la probabilité ajustée
        3. Calculer l'exposition (ALE = probabilité × impact)
        4. Calculer le ROI de remédiation
        """
        all_exposures = []
        all_roi = []
        total_low = 0
        total_mid = 0
        total_high = 0
        quick_wins_value = 0

        for domain in domains:
            for req in domain.sub_requirements:
                # On ne calcule que pour les gaps (niveau 0 ou 1)
                if not req.is_gap:
                    continue

                maturity_value = req.maturity.value if req.maturity else 0

                # Trouver les scénarios pour ce gap
                scenarios = GAP_TO_RISK_SCENARIOS.get(req.id, {}).get("scenarios", [])

                req_exposure_mid = 0

                for scenario in scenarios:
                    incident_type = scenario["type"]
                    base_prob = scenario["probability_base"]
                    rationale = scenario["rationale"]

                    # Ajuster la probabilité
                    adjusted_prob = self._adjust_probability(base_prob, maturity_value)

                    # Récupérer les coûts
                    costs = self._get_cost(incident_type)

                    # Calculer l'exposition (ALE)
                    exp_low = adjusted_prob * costs["cost_low"]
                    exp_mid = adjusted_prob * costs["cost_mid"]
                    exp_high = adjusted_prob * costs["cost_high"]

                    exposure = RiskExposure(
                        requirement_id=req.id,
                        requirement_title=req.title,
                        domain_title=domain.title,
                        current_maturity=maturity_value,
                        incident_type=incident_type.value,
                        incident_label=incident_type.label,
                        probability=round(adjusted_prob, 3),
                        impact_low=costs["cost_low"],
                        impact_mid=costs["cost_mid"],
                        impact_high=costs["cost_high"],
                        exposure_low=round(exp_low, 0),
                        exposure_mid=round(exp_mid, 0),
                        exposure_high=round(exp_high, 0),
                        rationale=rationale,
                        source=costs["source"],
                    )

                    all_exposures.append(exposure)
                    total_low += exp_low
                    total_mid += exp_mid
                    total_high += exp_high
                    req_exposure_mid += exp_mid

                # Calculer le ROI de remédiation pour ce gap
                if req_exposure_mid > 0:
                    roi = RemediationROI(
                        requirement_id=req.id,
                        requirement_title=req.title,
                        action=req.remediation.quick_win,
                        effort_label=req.remediation.effort.label,
                        exposure_eliminated_low=sum(
                            e.exposure_low for e in all_exposures
                            if e.requirement_id == req.id
                        ),
                        exposure_eliminated_mid=req_exposure_mid,
                        exposure_eliminated_high=sum(
                            e.exposure_high for e in all_exposures
                            if e.requirement_id == req.id
                        ),
                        priority_score=req_exposure_mid * (
                            3 if req.remediation.effort.value == "low"
                            else 2 if req.remediation.effort.value == "medium"
                            else 1
                        ),
                    )
                    all_roi.append(roi)

                    if req.remediation.effort.value == "low":
                        quick_wins_value += req_exposure_mid

        # Trier les expositions par impact décroissant
        all_exposures.sort(key=lambda e: e.exposure_mid, reverse=True)
        all_roi.sort(key=lambda r: r.priority_score, reverse=True)

        # Top 5 risques
        top_risks = all_exposures[:5]

        return FinancialReport(
            organization=self.profile,
            total_exposure_low=round(total_low, 0),
            total_exposure_mid=round(total_mid, 0),
            total_exposure_high=round(total_high, 0),
            max_nis2_fine=self.profile.max_nis2_fine,
            exposures=all_exposures,
            remediation_roi=all_roi,
            top_risks=top_risks,
            quick_wins_value=round(quick_wins_value, 0),
        )

    def display_summary(self, report: FinancialReport):
        """Affiche le résumé financier dans le terminal."""
        BOLD = "\033[1m"
        DIM = "\033[2m"
        RESET = "\033[0m"
        CYAN = "\033[36m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        RED = "\033[31m"
        WHITE = "\033[97m"
        MAGENTA = "\033[35m"

        def fmt_eur(amount: float) -> str:
            """Formate un montant en euros lisible."""
            if amount >= 1_000_000:
                return f"{amount/1_000_000:.1f}M EUR"
            elif amount >= 1_000:
                return f"{amount/1_000:.0f}K EUR"
            else:
                return f"{amount:.0f} EUR"

        print()
        print(f"  {CYAN}{'═' * 56}{RESET}")
        print(f"  {WHITE}{BOLD}  QUANTIFICATION DU RISQUE FINANCIER{RESET}")
        print(f"  {DIM}  {report.organization.name} — {report.organization.size.label}{RESET}")
        print(f"  {CYAN}{'═' * 56}{RESET}")
        print()

        # Exposition totale
        print(f"  {WHITE}{BOLD}Exposition financiere annuelle estimee :{RESET}")
        print()
        print(f"    {YELLOW}Hypothese basse  :{RESET}  {YELLOW}{BOLD}{fmt_eur(report.total_exposure_low)}{RESET}")
        print(f"    {RED}Hypothese moyenne :{RESET}  {RED}{BOLD}{fmt_eur(report.total_exposure_mid)}{RESET}")
        print(f"    {RED}Hypothese haute   :{RESET}  {RED}{BOLD}{fmt_eur(report.total_exposure_high)}{RESET}")
        print()
        print(f"  {DIM}Amende NIS 2 maximale applicable : {fmt_eur(report.max_nis2_fine)}{RESET}")
        print()

        # Top 5 risques
        print(f"  {CYAN}{'─' * 56}{RESET}")
        print(f"  {WHITE}{BOLD}Top 5 des risques par exposition :{RESET}")
        print()

        for i, risk in enumerate(report.top_risks[:5], 1):
            color = RED if risk.exposure_mid > 200_000 else YELLOW
            print(f"  {BOLD}{i}.{RESET} {risk.requirement_title[:40]}")
            print(f"     {DIM}Scenario : {risk.incident_label}{RESET}")
            print(f"     {DIM}Probabilite : {risk.probability*100:.0f}%/an{RESET}")
            print(f"     {color}Exposition : {fmt_eur(risk.exposure_low)} — {fmt_eur(risk.exposure_high)}/an{RESET}")
            print(f"     {DIM}{risk.rationale[:70]}{RESET}")
            print()

        # ROI des remédiations
        print(f"  {CYAN}{'─' * 56}{RESET}")
        print(f"  {WHITE}{BOLD}Top 5 remediations par ROI :{RESET}")
        print()

        for i, roi in enumerate(report.remediation_roi[:5], 1):
            print(f"  {BOLD}{i}.{RESET} {roi.requirement_title[:40]}")
            print(f"     {DIM}Action : {roi.action[:65]}{RESET}")
            print(f"     {DIM}Effort : {roi.effort_label}{RESET}")
            print(f"     {GREEN}Risque elimine : {fmt_eur(roi.exposure_eliminated_low)} — {fmt_eur(roi.exposure_eliminated_high)}/an{RESET}")
            print()

        # Quick wins value
        print(f"  {CYAN}{'─' * 56}{RESET}")
        print(f"  {WHITE}{BOLD}Valeur des quick wins :{RESET}")
        print(f"  {GREEN}En implementant les actions rapides (< 1 mois),{RESET}")
        print(f"  {GREEN}vous reduisez votre exposition de {BOLD}{fmt_eur(report.quick_wins_value)}/an{RESET}")
        print(f"  {CYAN}{'─' * 56}{RESET}")
        print()

    def to_dict(self, report: FinancialReport) -> dict:
        """Exporte le rapport financier en dictionnaire pour le JSON."""
        return {
            "organization": {
                "name": report.organization.name,
                "size": report.organization.size.value,
                "sector": report.organization.sector.value,
                "annual_revenue": report.organization.annual_revenue,
                "max_nis2_fine": report.max_nis2_fine,
            },
            "total_exposure": {
                "low": report.total_exposure_low,
                "mid": report.total_exposure_mid,
                "high": report.total_exposure_high,
                "currency": "EUR",
                "period": "annuel",
            },
            "exposures": [
                {
                    "requirement_id": e.requirement_id,
                    "requirement_title": e.requirement_title,
                    "domain": e.domain_title,
                    "maturity": e.current_maturity,
                    "incident_type": e.incident_type,
                    "incident_label": e.incident_label,
                    "probability_pct": round(e.probability * 100, 1),
                    "impact_low": e.impact_low,
                    "impact_mid": e.impact_mid,
                    "impact_high": e.impact_high,
                    "exposure_low": e.exposure_low,
                    "exposure_mid": e.exposure_mid,
                    "exposure_high": e.exposure_high,
                    "rationale": e.rationale,
                    "source": e.source,
                }
                for e in report.exposures
            ],
            "remediation_roi": [
                {
                    "requirement_id": r.requirement_id,
                    "requirement_title": r.requirement_title,
                    "action": r.action,
                    "effort": r.effort_label,
                    "exposure_eliminated_low": r.exposure_eliminated_low,
                    "exposure_eliminated_mid": r.exposure_eliminated_mid,
                    "exposure_eliminated_high": r.exposure_eliminated_high,
                    "priority_score": r.priority_score,
                }
                for r in report.remediation_roi
            ],
            "quick_wins_total_value": report.quick_wins_value,
        }
