"""
NIS 2 Compliance Gap Analyzer — Core Models
Data structures for the assessment framework, scoring, and gap analysis.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import json
import os


class MaturityLevel(Enum):
    """Assessment maturity levels aligned with NIS 2 expectations."""
    NOT_IMPLEMENTED = 0
    INITIAL = 1
    DEFINED = 2
    MANAGED = 3

    @property
    def label(self) -> str:
        return {
            0: "Non implémenté",
            1: "Initial / Partiel",
            2: "Défini / Implémenté",
            3: "Géré / Mesuré",
        }[self.value]

    @property
    def color(self) -> str:
        return {0: "#DC2626", 1: "#EA580C", 2: "#CA8A04", 3: "#10B981"}[self.value]

    @property
    def score_pct(self) -> float:
        """Percentage score contribution."""
        return self.value / 3 * 100


class EffortLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def label(self) -> str:
        return {"low": "Rapide (< 1 mois)", "medium": "Moyen (1-3 mois)", "high": "Long (> 3 mois)"}[self.value]

    @property
    def color(self) -> str:
        return {"low": "#10B981", "medium": "#CA8A04", "high": "#DC2626"}[self.value]

    @property
    def sort_order(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


class ComplianceGrade(Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"

    @property
    def color(self) -> str:
        return {"A": "#10B981", "B": "#3B82F6", "C": "#F59E0B", "D": "#EF4444", "F": "#DC2626"}[self.value]

    @property
    def description(self) -> str:
        return {
            "A": "Conforme — Posture de sécurité robuste, couverture NIS 2 quasi-complète.",
            "B": "Avancé — Majorité des mesures en place, quelques améliorations nécessaires.",
            "C": "Intermédiaire — Fondations en place mais gaps significatifs à combler.",
            "D": "Initial — Mesures partielles, efforts importants requis pour la conformité.",
            "F": "Non conforme — Lacunes critiques, plan de remédiation urgent nécessaire.",
        }[self.value]

    @staticmethod
    def from_score(score: float) -> "ComplianceGrade":
        if score >= 85:
            return ComplianceGrade.A
        elif score >= 70:
            return ComplianceGrade.B
        elif score >= 50:
            return ComplianceGrade.C
        elif score >= 30:
            return ComplianceGrade.D
        else:
            return ComplianceGrade.F


@dataclass
class Remediation:
    quick_win: str
    full_implementation: str
    effort: EffortLevel


@dataclass
class SubRequirement:
    id: str
    title: str
    description: str
    question: str
    iso27001_refs: list[str]
    iso27001_controls: list[str]
    evidence_examples: list[str]
    remediation: Remediation
    dora_refs: list[str] = field(default_factory=list)
    dora_pillar: str = ""
    maturity: Optional[MaturityLevel] = None
    notes: str = ""

    @property
    def is_assessed(self) -> bool:
        return self.maturity is not None

    @property
    def is_gap(self) -> bool:
        return self.maturity is not None and self.maturity.value < 2

    @property
    def is_critical_gap(self) -> bool:
        return self.maturity is not None and self.maturity.value == 0


@dataclass
class Domain:
    id: str
    title: str
    article_ref: str
    weight: float
    description: str
    sub_requirements: list[SubRequirement]

    @property
    def total_requirements(self) -> int:
        return len(self.sub_requirements)

    @property
    def assessed_count(self) -> int:
        return sum(1 for r in self.sub_requirements if r.is_assessed)

    @property
    def gap_count(self) -> int:
        return sum(1 for r in self.sub_requirements if r.is_gap)

    @property
    def critical_gap_count(self) -> int:
        return sum(1 for r in self.sub_requirements if r.is_critical_gap)

    @property
    def score(self) -> float:
        """Weighted domain score (0-100)."""
        assessed = [r for r in self.sub_requirements if r.is_assessed]
        if not assessed:
            return 0.0
        return sum(r.maturity.score_pct for r in assessed) / len(assessed)

    @property
    def maturity_distribution(self) -> dict[int, int]:
        dist = {0: 0, 1: 0, 2: 0, 3: 0}
        for r in self.sub_requirements:
            if r.is_assessed:
                dist[r.maturity.value] += 1
        return dist


@dataclass
class AssessmentResult:
    """Complete assessment result with scoring and gap analysis."""
    domains: list[Domain]
    organization_name: str = "Organisation"
    assessor: str = "NIS 2 Compliance Gap Analyzer"
    timestamp: str = ""

    @property
    def total_requirements(self) -> int:
        return sum(d.total_requirements for d in self.domains)

    @property
    def total_assessed(self) -> int:
        return sum(d.assessed_count for d in self.domains)

    @property
    def total_gaps(self) -> int:
        return sum(d.gap_count for d in self.domains)

    @property
    def total_critical_gaps(self) -> int:
        return sum(d.critical_gap_count for d in self.domains)

    @property
    def overall_score(self) -> float:
        """Global weighted score (0-100)."""
        total_weight = sum(d.weight for d in self.domains)
        if total_weight == 0:
            return 0.0
        weighted_sum = sum(d.score * d.weight for d in self.domains)
        return weighted_sum / total_weight

    @property
    def grade(self) -> ComplianceGrade:
        return ComplianceGrade.from_score(self.overall_score)

    @property
    def gaps_by_effort(self) -> dict[str, list[SubRequirement]]:
        """Group all gaps by remediation effort for prioritized action plan."""
        result = {"low": [], "medium": [], "high": []}
        for domain in self.domains:
            for req in domain.sub_requirements:
                if req.is_gap:
                    result[req.remediation.effort.value].append(req)
        return result

    @property
    def iso27001_coverage(self) -> dict[str, bool]:
        """Map of ISO 27001 controls and their coverage status."""
        coverage = {}
        for domain in self.domains:
            for req in domain.sub_requirements:
                for ref in req.iso27001_refs:
                    if ref not in coverage:
                        coverage[ref] = False
                    if req.is_assessed and req.maturity.value >= 2:
                        coverage[ref] = True
        return coverage
     
    @property
    def dora_coverage(self) -> dict[str, dict]:
        """
        Couverture DORA par pilier.
        
        Retourne un dictionnaire structuré par pilier :
        {
            "ICT Risk Management": {
                "total_questions": 5,
                "covered_questions": 3,
                "coverage_pct": 60.0,
                "questions": ["NIS2-D01-R01", ...],
                "dora_articles": ["DORA Art. 5", "DORA Art. 6", ...]
            },
            ...
        }
        
        Une question est "couverte" si elle est évaluée à maturité ≥ 2.
        """
        pillars = {}
        for domain in self.domains:
            for req in domain.sub_requirements:
                if not req.dora_pillar:
                    continue
                
                pillar = req.dora_pillar
                if pillar not in pillars:
                    pillars[pillar] = {
                        "total_questions": 0,
                        "covered_questions": 0,
                        "questions": [],
                        "dora_articles": set(),
                    }
                
                pillars[pillar]["total_questions"] += 1
                pillars[pillar]["questions"].append(req.id)
                for art in req.dora_refs:
                    pillars[pillar]["dora_articles"].add(art)
                
                if req.is_assessed and req.maturity.value >= 2:
                    pillars[pillar]["covered_questions"] += 1
        
        # Calculer les pourcentages et convertir les sets en listes
        for pillar in pillars:
            total = pillars[pillar]["total_questions"]
            covered = pillars[pillar]["covered_questions"]
            pillars[pillar]["coverage_pct"] = round(covered / total * 100, 1) if total > 0 else 0
            pillars[pillar]["dora_articles"] = sorted(list(pillars[pillar]["dora_articles"]))
        
        return pillars

def load_framework(path: str = None) -> list[Domain]:
    """Load the NIS 2 framework from JSON and return Domain objects."""
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "..", "data", "nis2_framework.json")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    domains = []
    for d in data["domains"]:
        sub_reqs = []
        for r in d["sub_requirements"]:
            rem = r["remediation"]
            sub_reqs.append(SubRequirement(
                id=r["id"],
                title=r["title"],
                description=r["description"],
                question=r["question"],
                iso27001_refs=r["iso27001_refs"],
                iso27001_controls=r["iso27001_controls"],
                evidence_examples=r["evidence_examples"],
                remediation=Remediation(
                    quick_win=rem["quick_win"],
                    full_implementation=rem["full_implementation"],
                    effort=EffortLevel(rem["effort"]),
                ),
                dora_refs=r.get("dora_refs", []),
                dora_pillar=r.get("dora_pillar", ""),
            ))
        domains.append(Domain(
            id=d["id"],
            title=d["title"],
            article_ref=d["article_ref"],
            weight=d["weight"],
            description=d["description"],
            sub_requirements=sub_reqs,
        ))

    return domains
