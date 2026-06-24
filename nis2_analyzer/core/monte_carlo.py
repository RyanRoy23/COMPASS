"""
COMPASS — Monte Carlo Risk Simulation Engine

Remplace le calcul ALE déterministe (probabilité × coût = chiffre unique)
par 10 000 simulations où probabilité et coût varient selon des distributions
statistiques réalistes.

Résultat : une distribution de pertes annuelles avec intervalles de confiance.
  - P10 : dans 90% des scénarios, la perte dépassera ce montant
  - P50 : perte médiane (valeur centrale de référence)
  - P90 : dans 90% des scénarios, la perte sera inférieure à ce montant
  - Intervalle de confiance à 90% : [P5, P95]

Pourquoi Monte Carlo ?
L'ALE classique (probabilité × impact) est déterministe : il suppose que
la probabilité et le coût sont des valeurs fixes connues. En réalité, ce sont
des distributions. Monte Carlo modélise cette incertitude et produit une
fourchette honnête plutôt qu'un faux chiffre précis.

Méthodologie :
- Probabilité : distribution Beta(α, β) calée sur [p_low, p_mid, p_high]
- Coût par incident : distribution LogNormale calée sur [cost_low, cost_mid, cost_high]
- N_SIMULATIONS = 10 000 (convergence suffisante, temps < 1s)
- Seed fixe pour reproductibilité des rapports
"""

import math
import random
from dataclasses import dataclass, field

from nis2_analyzer.core.models import Domain
from nis2_analyzer.core.financial import (
    OrganizationProfile, OrgSize, IncidentType,
    COST_DATABASE, GAP_TO_RISK_SCENARIOS,
)

N_SIMULATIONS = 10_000
RANDOM_SEED = 42


# ── Distributions statistiques ────────────────────────────────────────────────

def _lognormal_params(low: float, mid: float, high: float) -> tuple[float, float]:
    """
    Calcule μ et σ d'une lognormale à partir de percentiles empiriques.
    On suppose : low ≈ P10, mid ≈ P50, high ≈ P90.
    """
    if mid <= 0:
        mid = max(low, 1.0)
    mu = math.log(mid)
    # σ estimé depuis l'écart P90-P10
    if high > low > 0:
        sigma = (math.log(high) - math.log(low)) / (2 * 1.28)
    else:
        sigma = 0.5
    return mu, max(sigma, 0.05)


def _beta_params(p_low: float, p_mid: float, p_high: float) -> tuple[float, float]:
    """
    Estime α et β d'une distribution Beta depuis trois percentiles de probabilité.
    On utilise la méthode des moments sur la moyenne et variance estimées.
    """
    mean = p_mid
    variance = ((p_high - p_low) / 4) ** 2
    variance = max(variance, 1e-6)
    mean = min(max(mean, 0.001), 0.999)
    common = mean * (1 - mean) / variance - 1
    alpha = mean * common
    beta = (1 - mean) * common
    return max(alpha, 0.5), max(beta, 0.5)


def _sample_beta(alpha: float, beta_param: float, rng: random.Random) -> float:
    """Échantillonne une distribution Beta via deux distributions Gamma."""
    x = rng.gammavariate(alpha, 1.0)
    y = rng.gammavariate(beta_param, 1.0)
    total = x + y
    if total == 0:
        return 0.5
    return min(max(x / total, 0.0), 1.0)


def _sample_lognormal(mu: float, sigma: float, rng: random.Random) -> float:
    """Échantillonne une lognormale."""
    return math.exp(rng.gauss(mu, sigma))


# ── Résultats ─────────────────────────────────────────────────────────────────

@dataclass
class ScenarioMC:
    """Résultat Monte Carlo pour un gap + scénario de risque."""
    requirement_id: str
    requirement_title: str
    domain_title: str
    incident_type: str
    incident_label: str
    maturity: int
    p10: float
    p50: float
    p90: float
    p5: float
    p95: float
    mean: float
    probability_p50: float


@dataclass
class MonteCarloReport:
    """Rapport complet de la simulation Monte Carlo."""
    organization: OrganizationProfile
    n_simulations: int
    # Distribution agrégée de la perte annuelle totale
    p5: float
    p10: float
    p25: float
    p50: float
    p75: float
    p90: float
    p95: float
    mean: float
    # Comparaison avec l'ALE classique
    ale_low: float
    ale_mid: float
    ale_high: float
    # Détail par scénario
    scenarios: list[ScenarioMC]
    # Histogramme : 20 bins pour la visualisation
    histogram: list[dict]
    # Amende maximale NIS 2
    max_nis2_fine: float

    def to_dict(self) -> dict:
        return {
            "organization": {
                "name": self.organization.name,
                "size": self.organization.size.value,
                "sector": self.organization.sector.value,
            },
            "n_simulations": self.n_simulations,
            "distribution": {
                "p5": self.p5,
                "p10": self.p10,
                "p25": self.p25,
                "p50": self.p50,
                "p75": self.p75,
                "p90": self.p90,
                "p95": self.p95,
                "mean": self.mean,
                "currency": "EUR",
                "period": "annuel",
            },
            "confidence_interval_90": {
                "lower": self.p5,
                "upper": self.p95,
                "label": "Intervalle de confiance à 90%",
            },
            "ale_comparison": {
                "ale_low": self.ale_low,
                "ale_mid": self.ale_mid,
                "ale_high": self.ale_high,
                "label": "ALE classique (probabilité × coût fixe)",
            },
            "max_nis2_fine": self.max_nis2_fine,
            "histogram": self.histogram,
            "scenarios": [
                {
                    "requirement_id": s.requirement_id,
                    "requirement_title": s.requirement_title,
                    "domain": s.domain_title,
                    "incident_type": s.incident_type,
                    "incident_label": s.incident_label,
                    "maturity": s.maturity,
                    "p10": s.p10,
                    "p50": s.p50,
                    "p90": s.p90,
                    "mean": s.mean,
                }
                for s in self.scenarios
            ],
        }


# ── Moteur de simulation ──────────────────────────────────────────────────────

class MonteCarloEngine:
    """
    Moteur de simulation Monte Carlo pour la quantification du risque NIS 2.

    Usage :
        engine = MonteCarloEngine(profile)
        report = engine.simulate(domains)
    """

    MATURITY_PROB_FACTOR = {0: 1.5, 1: 1.0, 2: 0.3, 3: 0.1}

    def __init__(self, profile: OrganizationProfile = None, n_simulations: int = N_SIMULATIONS):
        self.profile = profile or OrganizationProfile()
        self.n_simulations = n_simulations
        self._rng = random.Random(RANDOM_SEED)

    def _get_cost_range(self, incident_type: IncidentType) -> tuple[float, float, float]:
        size = self.profile.size
        db = COST_DATABASE.get(incident_type, {}).get(size)
        if db is None:
            db = COST_DATABASE.get(incident_type, {}).get(OrgSize.ETI, {
                "cost_low": 100_000, "cost_mid": 500_000, "cost_high": 2_000_000,
            })
        return db["cost_low"], db["cost_mid"], db["cost_high"]

    def _simulate_scenario(
        self,
        base_probability: float,
        maturity: int,
        cost_low: float,
        cost_mid: float,
        cost_high: float,
    ) -> list[float]:
        """
        Simule N_SIMULATIONS réalisations de la perte annuelle pour un scénario.

        Pour chaque simulation :
        1. Tire une probabilité d'occurrence depuis une Beta
        2. Tire un coût depuis une LogNormale
        3. Calcule si l'incident se produit (Bernoulli) et la perte associée
        """
        factor = self.MATURITY_PROB_FACTOR.get(maturity, 1.0)
        p_mid = min(base_probability * factor, 0.95)
        p_low = max(p_mid * 0.5, 0.001)
        p_high = min(p_mid * 2.0, 0.98)

        alpha, beta_p = _beta_params(p_low, p_mid, p_high)
        mu, sigma = _lognormal_params(cost_low, cost_mid, cost_high)

        losses = []
        for _ in range(self.n_simulations):
            p = _sample_beta(alpha, beta_p, self._rng)
            if self._rng.random() < p:
                cost = _sample_lognormal(mu, sigma, self._rng)
                losses.append(cost)
            else:
                losses.append(0.0)
        return losses

    @staticmethod
    def _percentile(sorted_values: list[float], pct: float) -> float:
        if not sorted_values:
            return 0.0
        idx = (pct / 100) * (len(sorted_values) - 1)
        lo = int(idx)
        hi = min(lo + 1, len(sorted_values) - 1)
        frac = idx - lo
        return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac

    @staticmethod
    def _build_histogram(sorted_values: list[float], n_bins: int = 20) -> list[dict]:
        """Construit un histogramme normalisé pour la visualisation."""
        if not sorted_values or sorted_values[-1] == 0:
            return []
        min_val = sorted_values[0]
        max_val = sorted_values[-1]
        if max_val == min_val:
            return [{"bin_min": min_val, "bin_max": max_val, "count": len(sorted_values), "frequency": 1.0}]

        bin_width = (max_val - min_val) / n_bins
        bins = [0] * n_bins
        for v in sorted_values:
            idx = min(int((v - min_val) / bin_width), n_bins - 1)
            bins[idx] += 1

        total = len(sorted_values)
        return [
            {
                "bin_min": round(min_val + i * bin_width, 0),
                "bin_max": round(min_val + (i + 1) * bin_width, 0),
                "count": bins[i],
                "frequency": round(bins[i] / total, 4),
            }
            for i in range(n_bins)
        ]

    def simulate(self, domains: list[Domain]) -> MonteCarloReport:
        """
        Lance la simulation Monte Carlo sur tous les gaps identifiés.
        Retourne la distribution agrégée de la perte annuelle totale.
        """
        # Réinitialise le RNG pour reproductibilité
        self._rng = random.Random(RANDOM_SEED)

        # Perte annuelle totale par simulation : tableau de N_SIMULATIONS valeurs
        total_losses = [0.0] * self.n_simulations
        scenario_results: list[ScenarioMC] = []

        # ALE classique pour comparaison
        ale_low = ale_mid = ale_high = 0.0

        for domain in domains:
            for req in domain.sub_requirements:
                if not req.is_gap:
                    continue

                maturity = req.maturity.value if req.maturity else 0
                scenarios = GAP_TO_RISK_SCENARIOS.get(req.id, {}).get("scenarios", [])

                for scenario in scenarios:
                    incident_type: IncidentType = scenario["type"]
                    base_prob: float = scenario["probability_base"]

                    cost_low, cost_mid, cost_high = self._get_cost_range(incident_type)

                    # Simulation Monte Carlo
                    losses = self._simulate_scenario(
                        base_prob, maturity, cost_low, cost_mid, cost_high
                    )

                    # Agrégation dans le total
                    for i, loss in enumerate(losses):
                        total_losses[i] += loss

                    # ALE classique
                    factor = self.MATURITY_PROB_FACTOR.get(maturity, 1.0)
                    adj_prob = min(base_prob * factor, 0.95)
                    ale_low += adj_prob * cost_low
                    ale_mid += adj_prob * cost_mid
                    ale_high += adj_prob * cost_high

                    # Statistiques du scénario
                    sorted_losses = sorted(losses)
                    scenario_results.append(ScenarioMC(
                        requirement_id=req.id,
                        requirement_title=req.title,
                        domain_title=domain.title,
                        incident_type=incident_type.value,
                        incident_label=incident_type.label,
                        maturity=maturity,
                        p10=round(self._percentile(sorted_losses, 10), 0),
                        p50=round(self._percentile(sorted_losses, 50), 0),
                        p90=round(self._percentile(sorted_losses, 90), 0),
                        p5=round(self._percentile(sorted_losses, 5), 0),
                        p95=round(self._percentile(sorted_losses, 95), 0),
                        mean=round(sum(losses) / len(losses), 0),
                        probability_p50=round(min(base_prob * factor, 0.95), 3),
                    ))

        # Distribution agrégée
        total_losses.sort()

        # L'histogramme ne montre que les simulations avec perte > 0
        # (les zéros représentent "pas d'incident cette année" et écraseraient la visualisation)
        nonzero_losses = [v for v in total_losses if v > 0]
        histogram = self._build_histogram(nonzero_losses)

        return MonteCarloReport(
            organization=self.profile,
            n_simulations=self.n_simulations,
            p5=round(self._percentile(total_losses, 5), 0),
            p10=round(self._percentile(total_losses, 10), 0),
            p25=round(self._percentile(total_losses, 25), 0),
            p50=round(self._percentile(total_losses, 50), 0),
            p75=round(self._percentile(total_losses, 75), 0),
            p90=round(self._percentile(total_losses, 90), 0),
            p95=round(self._percentile(total_losses, 95), 0),
            mean=round(sum(total_losses) / max(len(total_losses), 1), 0),
            ale_low=round(ale_low, 0),
            ale_mid=round(ale_mid, 0),
            ale_high=round(ale_high, 0),
            scenarios=sorted(scenario_results, key=lambda s: s.p50, reverse=True),
            histogram=histogram,
            max_nis2_fine=self.profile.max_nis2_fine,
        )
