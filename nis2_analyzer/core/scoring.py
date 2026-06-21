"""
COMPASS — Scoring Engine
Calculates compliance scores, identifies gaps, and generates prioritized action plans.
"""

from dataclasses import dataclass
from nis2_analyzer.core.models import (
    Domain, SubRequirement, AssessmentResult,
    MaturityLevel, EffortLevel, ComplianceGrade
)
from datetime import datetime, timezone


@dataclass
class GapItem:
    """A single identified compliance gap with context."""
    requirement_id: str
    requirement_title: str
    domain_id: str
    domain_title: str
    current_maturity: MaturityLevel
    target_maturity: MaturityLevel
    quick_win: str
    full_remediation: str
    effort: EffortLevel
    iso27001_refs: list[str]
    priority_score: float  # Higher = more urgent


@dataclass
class ActionPlan:
    """Prioritized remediation action plan."""
    immediate_actions: list[GapItem]    # Effort LOW + maturity 0
    short_term_actions: list[GapItem]   # Effort LOW/MEDIUM + maturity 0-1
    medium_term_actions: list[GapItem]  # Effort MEDIUM + maturity 1
    long_term_actions: list[GapItem]    # Effort HIGH


class ScoringEngine:
    """
    Calculates NIS 2 compliance scores from assessment responses.
    
    Scoring methodology:
    - Each sub-requirement is scored 0-3 (maturity level)
    - Domain score = average of sub-requirement scores (0-100%)
    - Global score = weighted average of domain scores
    - Weights reflect NIS 2 criticality (incidents & risk analysis > crypto)
    """

    TARGET_MATURITY = MaturityLevel.DEFINED  # Level 2 = minimum NIS 2 compliance

    def calculate(self, domains: list[Domain], org_name: str = "Organisation") -> AssessmentResult:
        """Run the full scoring and gap analysis."""
        result = AssessmentResult(
            domains=domains,
            organization_name=org_name,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        return result

    def generate_gap_analysis(self, result: AssessmentResult) -> list[GapItem]:
        """Extract all gaps and compute priority scores."""
        gaps = []

        for domain in result.domains:
            for req in domain.sub_requirements:
                if not req.is_gap:
                    continue

                # Priority score: combines domain weight, maturity gap, and effort
                maturity_gap = self.TARGET_MATURITY.value - (req.maturity.value if req.maturity else 0)
                effort_factor = {EffortLevel.LOW: 3, EffortLevel.MEDIUM: 2, EffortLevel.HIGH: 1}
                priority = domain.weight * maturity_gap * effort_factor.get(req.remediation.effort, 1)

                gaps.append(GapItem(
                    requirement_id=req.id,
                    requirement_title=req.title,
                    domain_id=domain.id,
                    domain_title=domain.title,
                    current_maturity=req.maturity or MaturityLevel.NOT_IMPLEMENTED,
                    target_maturity=self.TARGET_MATURITY,
                    quick_win=req.remediation.quick_win,
                    full_remediation=req.remediation.full_implementation,
                    effort=req.remediation.effort,
                    iso27001_refs=req.iso27001_refs,
                    priority_score=priority,
                ))

        # Sort by priority (highest first)
        gaps.sort(key=lambda g: g.priority_score, reverse=True)
        return gaps

    def generate_action_plan(self, gaps: list[GapItem]) -> ActionPlan:
        """Organize gaps into a prioritized action plan."""
        immediate = []
        short_term = []
        medium_term = []
        long_term = []

        for gap in gaps:
            is_critical = gap.current_maturity == MaturityLevel.NOT_IMPLEMENTED

            if gap.effort == EffortLevel.LOW and is_critical:
                immediate.append(gap)
            elif gap.effort == EffortLevel.LOW or (gap.effort == EffortLevel.MEDIUM and is_critical):
                short_term.append(gap)
            elif gap.effort == EffortLevel.MEDIUM:
                medium_term.append(gap)
            else:
                long_term.append(gap)

        return ActionPlan(
            immediate_actions=immediate,
            short_term_actions=short_term,
            medium_term_actions=medium_term,
            long_term_actions=long_term,
        )

    def compute_iso27001_mapping(self, result: AssessmentResult) -> dict:
        """Generate ISO 27001 coverage analysis."""
        coverage = result.iso27001_coverage
        total = len(coverage)
        covered = sum(1 for v in coverage.values() if v)
        return {
            "total_controls_referenced": total,
            "controls_covered": covered,
            "controls_not_covered": total - covered,
            "coverage_pct": round(covered / total * 100, 1) if total > 0 else 0,
            "details": coverage,
        }

    def compute_domain_summary(self, result: AssessmentResult) -> list[dict]:
        """Generate per-domain summary for reporting."""
        summary = []
        for domain in result.domains:
            summary.append({
                "id": domain.id,
                "title": domain.title,
                "article_ref": domain.article_ref,
                "weight": domain.weight,
                "score": round(domain.score, 1),
                "total_requirements": domain.total_requirements,
                "gaps": domain.gap_count,
                "critical_gaps": domain.critical_gap_count,
                "maturity_distribution": domain.maturity_distribution,
            })
        return summary

    def full_analysis(self, domains: list[Domain], org_name: str = "Organisation") -> dict:
        """Run complete analysis and return all results as a dict."""
        result = self.calculate(domains, org_name)
        gaps = self.generate_gap_analysis(result)
        action_plan = self.generate_action_plan(gaps)
        iso_mapping = self.compute_iso27001_mapping(result)
        domain_summary = self.compute_domain_summary(result)

        return {
            "metadata": {
                "tool": "COMPASS",
                "version": "1.1.0",
                "timestamp": result.timestamp,
                "organization": org_name,
                "framework": "NIS 2 Directive — Article 21",
            },
            "scores": {
                "overall_score": round(result.overall_score, 1),
                "grade": result.grade.value,
                "grade_color": result.grade.color,
                "grade_description": result.grade.description,
                "total_requirements": result.total_requirements,
                "total_assessed": result.total_assessed,
                "total_gaps": result.total_gaps,
                "total_critical_gaps": result.total_critical_gaps,
            },
            "domains": domain_summary,
            "gaps": [
                {
                    "id": g.requirement_id,
                    "title": g.requirement_title,
                    "domain": g.domain_title,
                    "current_maturity": g.current_maturity.label,
                    "current_maturity_value": g.current_maturity.value,
                    "target_maturity": g.target_maturity.label,
                    "quick_win": g.quick_win,
                    "full_remediation": g.full_remediation,
                    "effort": g.effort.value,
                    "effort_label": g.effort.label,
                    "iso27001_refs": g.iso27001_refs,
                    "priority_score": round(g.priority_score, 2),
                }
                for g in gaps
            ],
            "action_plan": {
                "immediate": len(action_plan.immediate_actions),
                "short_term": len(action_plan.short_term_actions),
                "medium_term": len(action_plan.medium_term_actions),
                "long_term": len(action_plan.long_term_actions),
            },
            "iso27001_mapping": iso_mapping,
        }
