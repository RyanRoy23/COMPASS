"""
NIS 2 Risk Analyzer — HTML Report Generator
Génère un rapport HTML unifié consolidant les 3 couches :
1. Score de conformité NIS 2
2. Preuves techniques (bridge CloudSec)
3. Quantification du risque financier

Le rapport est un fichier HTML autonome — pas de dépendance externe,
pas de serveur, pas de JavaScript framework. On ouvre le fichier
dans un navigateur et tout est là.

Pourquoi HTML et pas PDF ?
- Un PDF est statique. Un HTML permet des interactions (sections
  dépliables, hover sur les barres, tooltips).
- Un HTML s'ouvre sur n'importe quel appareil sans logiciel.
- Un HTML est plus facile à intégrer dans un intranet ou un wiki.
- Le RSSI peut l'envoyer par email et le DG l'ouvre en 1 clic.
"""

import json
import os
from datetime import datetime, timezone
from nis2_analyzer.core.models import Domain, ComplianceGrade, MaturityLevel
from nis2_analyzer.core.scoring import ScoringEngine


def _fmt_eur(amount: float) -> str:
    """Formate un montant en euros."""
    if amount >= 1_000_000:
        return f"{amount/1_000_000:.1f}M €"
    elif amount >= 1_000:
        return f"{amount/1_000:.0f}K €"
    else:
        return f"{amount:.0f} €"


def _grade_color(grade: str) -> str:
    return {"A": "#10B981", "B": "#3B82F6", "C": "#E5A100", "D": "#EF4444", "F": "#DC2626"}.get(grade, "#94A3B8")


def _maturity_color(level: int) -> str:
    return {0: "#EF4444", 1: "#F59E0B", 2: "#3B82F6", 3: "#10B981"}.get(level, "#94A3B8")


def _maturity_label(level: int) -> str:
    return {0: "Non implémenté", 1: "Initial / Partiel", 2: "Défini / Implémenté", 3: "Géré / Mesuré"}.get(level, "—")


def _score_color(score: float) -> str:
    if score >= 66:
        return "#10B981"
    elif score >= 33:
        return "#E5A100"
    else:
        return "#EF4444"


def generate_report(
    domains: list[Domain],
    org_name: str,
    financial_report: dict = None,
    bridge_summary: dict = None,
    output_path: str = "reports/nis2_report.html",
) -> str:
    """
    Génère le rapport HTML complet.
    
    Args:
        domains: domaines avec maturités renseignées
        org_name: nom de l'organisation
        financial_report: résultats du RiskEngine.to_dict() (optionnel)
        bridge_summary: résumé du bridge CloudSec (optionnel)
        output_path: chemin du fichier HTML de sortie
    """
    
    # Calculer les scores
    engine = ScoringEngine()
    analysis = engine.full_analysis(domains, org_name)
    
    timestamp = datetime.now(timezone.utc).strftime("%d/%m/%Y à %H:%M UTC")
    grade = analysis["scores"]["grade"]
    overall_score = analysis["scores"]["overall_score"]
    total_reqs = analysis["scores"]["total_requirements"]
    total_gaps = analysis["scores"]["total_gaps"]
    total_critical = analysis["scores"]["total_critical_gaps"]
    compliant = total_reqs - total_gaps
    
    # Préparer les données financières
    has_financial = financial_report is not None
    has_bridge = bridge_summary is not None
    
    # ── Construire le HTML ──
    
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NIS 2 Risk Analyzer — Rapport {org_name}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
        
        :root {{
            --bg-primary: #0A0E1A;
            --bg-secondary: #111827;
            --bg-card: #1A2035;
            --bg-card-hover: #1E2642;
            --border: #2A3352;
            --text-primary: #F1F5F9;
            --text-secondary: #94A3B8;
            --text-muted: #64748B;
            --accent: #38BDF8;
            --accent-dim: #0C4A6E;
            --green: #10B981;
            --green-dim: #064E3B;
            --red: #EF4444;
            --red-dim: #7F1D1D;
            --orange: #F59E0B;
            --orange-dim: #78350F;
            --blue: #3B82F6;
            --blue-dim: #1E3A5F;
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'DM Sans', -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1100px;
            margin: 0 auto;
            padding: 40px 24px;
        }}
        
        /* ── HEADER ── */
        .header {{
            text-align: center;
            margin-bottom: 48px;
            padding-bottom: 32px;
            border-bottom: 1px solid var(--border);
        }}
        
        .header-badge {{
            display: inline-block;
            background: var(--accent-dim);
            color: var(--accent);
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-bottom: 16px;
        }}
        
        .header h1 {{
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 8px;
            color: var(--text-primary);
        }}
        
        .header .subtitle {{
            font-size: 15px;
            color: var(--text-secondary);
        }}
        
        .header .meta {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 12px;
        }}
        
        /* ── SCORE HERO ── */
        .score-hero {{
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .score-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 28px;
            text-align: center;
        }}
        
        .score-card.main {{
            border-color: {_grade_color(grade)}40;
            background: linear-gradient(135deg, var(--bg-card) 0%, {_grade_color(grade)}10 100%);
        }}
        
        .score-card .label {{
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }}
        
        .score-card .value {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 42px;
            font-weight: 700;
            line-height: 1;
        }}
        
        .score-card .detail {{
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 8px;
        }}
        
        /* ── SECTIONS ── */
        .section {{
            margin-bottom: 40px;
        }}
        
        .section-title {{
            font-size: 18px;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--accent);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .section-title .icon {{
            width: 24px;
            height: 24px;
            background: var(--accent-dim);
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
        }}
        
        /* ── DOMAIN BARS ── */
        .domain-grid {{
            display: grid;
            gap: 12px;
        }}
        
        .domain-row {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px 20px;
            display: grid;
            grid-template-columns: 2fr 1fr 80px;
            align-items: center;
            gap: 16px;
            transition: background 0.2s;
        }}
        
        .domain-row:hover {{
            background: var(--bg-card-hover);
        }}
        
        .domain-name {{
            font-size: 14px;
            font-weight: 500;
        }}
        
        .domain-ref {{
            font-size: 11px;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }}
        
        .bar-container {{
            height: 8px;
            background: var(--bg-primary);
            border-radius: 4px;
            overflow: hidden;
        }}
        
        .bar-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.8s ease-out;
        }}
        
        .domain-score {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            font-weight: 600;
            text-align: right;
        }}
        
        /* ── GAP TABLE ── */
        .gap-table {{
            width: 100%;
            border-collapse: separate;
            border-spacing: 0 6px;
        }}
        
        .gap-table th {{
            text-align: left;
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 8px 12px;
            font-weight: 600;
        }}
        
        .gap-table td {{
            background: var(--bg-card);
            padding: 12px;
            font-size: 13px;
            color: var(--text-secondary);
        }}
        
        .gap-table tr td:first-child {{
            border-radius: 8px 0 0 8px;
        }}
        
        .gap-table tr td:last-child {{
            border-radius: 0 8px 8px 0;
        }}
        
        .maturity-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }}
        
        .effort-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 500;
        }}
        
        /* ── FINANCIAL CARDS ── */
        .financial-hero {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }}
        
        .financial-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
        }}
        
        .financial-card.exposure {{
            border-color: var(--red)40;
            background: linear-gradient(135deg, var(--bg-card) 0%, var(--red-dim)30 100%);
        }}
        
        .financial-card.savings {{
            border-color: var(--green)40;
            background: linear-gradient(135deg, var(--bg-card) 0%, var(--green-dim)30 100%);
        }}
        
        .financial-card .label {{
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }}
        
        .financial-card .amount {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 32px;
            font-weight: 700;
        }}
        
        .financial-card .range {{
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 4px;
        }}
        
        /* ── RISK LIST ── */
        .risk-item {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 10px;
            display: grid;
            grid-template-columns: 3fr 1fr 1fr;
            align-items: center;
            gap: 12px;
        }}
        
        .risk-item .risk-name {{
            font-size: 14px;
            font-weight: 500;
        }}
        
        .risk-item .risk-type {{
            font-size: 11px;
            color: var(--text-muted);
        }}
        
        .risk-item .risk-prob {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            text-align: center;
        }}
        
        .risk-item .risk-cost {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            font-weight: 600;
            text-align: right;
        }}
        
        /* ── BRIDGE SECTION ── */
        .bridge-stat {{
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 16px;
            margin-bottom: 20px;
        }}
        
        .bridge-stat .stat-box {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px;
            text-align: center;
        }}
        
        .bridge-stat .stat-value {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 28px;
            font-weight: 700;
            color: var(--accent);
        }}
        
        .bridge-stat .stat-label {{
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 4px;
        }}
        
        /* ── ISO MAPPING ── */
        .iso-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(70px, 1fr));
            gap: 6px;
        }}
        
        .iso-pill {{
            padding: 6px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
            text-align: center;
            font-weight: 500;
        }}
        
        .iso-pill.covered {{
            background: var(--green-dim);
            color: var(--green);
        }}
        
        .iso-pill.not-covered {{
            background: var(--red-dim);
            color: var(--red);
        }}
        
        /* ── FOOTER ── */
        .footer {{
            text-align: center;
            padding-top: 32px;
            margin-top: 48px;
            border-top: 1px solid var(--border);
            font-size: 12px;
            color: var(--text-muted);
        }}
        
        .footer a {{
            color: var(--accent);
            text-decoration: none;
        }}
        
        /* ── ACTION PLAN ── */
        .action-phases {{
            display: grid;
            grid-template-columns: 1fr 1fr 1fr 1fr;
            gap: 12px;
            margin-bottom: 24px;
        }}
        
        .phase-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 16px;
            text-align: center;
        }}
        
        .phase-card .phase-count {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 28px;
            font-weight: 700;
        }}
        
        .phase-card .phase-label {{
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 4px;
        }}
        
        @media print {{
            body {{ background: #fff; color: #1a1a1a; }}
            .score-card, .domain-row, .gap-table td, .financial-card, 
            .risk-item, .phase-card, .bridge-stat .stat-box {{
                background: #f8f9fa;
                border-color: #dee2e6;
                color: #1a1a1a;
            }}
            .section-title {{ color: #1a1a1a; border-color: #0C4A6E; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER -->
        <div class="header">
            <div class="header-badge">NIS 2 — Article 21</div>
            <h1>Rapport de Conformité & Analyse de Risque</h1>
            <div class="subtitle">{org_name}</div>
            <div class="meta">Généré le {timestamp} — NIS 2 Risk Analyzer v1.0.0</div>
        </div>
        
        <!-- SCORE HERO -->
        <div class="score-hero">
            <div class="score-card main">
                <div class="label">Score Global</div>
                <div class="value" style="color: {_grade_color(grade)}">{overall_score}%</div>
                <div class="detail">Grade {grade}</div>
            </div>
            <div class="score-card">
                <div class="label">Gaps Identifiés</div>
                <div class="value" style="color: var(--orange)">{total_gaps}</div>
                <div class="detail">dont {total_critical} critique(s)</div>
            </div>
            <div class="score-card">
                <div class="label">Exigences Conformes</div>
                <div class="value" style="color: var(--green)">{compliant}</div>
                <div class="detail">sur {total_reqs} évaluées</div>
            </div>
        </div>
"""

    # ── SECTION : Scores par domaine ──
    html += """
        <div class="section">
            <div class="section-title">
                <div class="icon">◉</div>
                Scores par domaine
            </div>
            <div class="domain-grid">
"""
    
    for domain in domains:
        score = domain.score
        color = _score_color(score)
        gaps = domain.gap_count
        gap_text = f" — {gaps} gap{'s' if gaps > 1 else ''}" if gaps > 0 else ""
        
        html += f"""
                <div class="domain-row">
                    <div>
                        <div class="domain-name">{domain.title}</div>
                        <div class="domain-ref">{domain.article_ref} | Poids {domain.weight}x{gap_text}</div>
                    </div>
                    <div class="bar-container">
                        <div class="bar-fill" style="width: {score}%; background: {color};"></div>
                    </div>
                    <div class="domain-score" style="color: {color}">{score:.0f}%</div>
                </div>
"""
    
    html += """
            </div>
        </div>
"""

    # ── SECTION : Bridge CloudSec (si disponible) ──
    if has_bridge:
        auto = bridge_summary.get("auto_filled", 0)
        remaining = bridge_summary.get("remaining_manual", 0)
        coverage = bridge_summary.get("coverage_pct", 0)
        
        html += f"""
        <div class="section">
            <div class="section-title">
                <div class="icon">⚡</div>
                Bridge Technique — CloudSec Audit Toolkit
            </div>
            <div class="bridge-stat">
                <div class="stat-box">
                    <div class="stat-value">{auto}</div>
                    <div class="stat-label">Questions pré-remplies</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{remaining}</div>
                    <div class="stat-label">Questions manuelles</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{coverage}%</div>
                    <div class="stat-label">Couverture technique</div>
                </div>
            </div>
"""
        
        # Détails des auto-fills
        details = bridge_summary.get("details", {})
        if details:
            html += """
            <table class="gap-table">
                <tr>
                    <th>Exigence</th>
                    <th>Source</th>
                    <th>Niveau</th>
                    <th>Constat</th>
                </tr>
"""
            for req_id, info in details.items():
                level = info["level"]
                color = _maturity_color(level)
                html += f"""
                <tr>
                    <td style="font-weight: 500; color: var(--text-primary)">{req_id}</td>
                    <td><span style="font-family: 'JetBrains Mono', monospace; font-size: 11px;">{info.get('source_check', '')}</span></td>
                    <td><span class="maturity-badge" style="background: {color}20; color: {color}">N{level}</span></td>
                    <td style="font-size: 12px;">{info['reason'][:80]}</td>
                </tr>
"""
            html += """
            </table>
"""
        html += """
        </div>
"""

    # ── SECTION : Quantification financière (si disponible) ──
    if has_financial:
        exp = financial_report.get("total_exposure", {})
        exp_low = exp.get("low", 0)
        exp_mid = exp.get("mid", 0)
        exp_high = exp.get("high", 0)
        fine = financial_report.get("organization", {}).get("max_nis2_fine", 0)
        qw_value = financial_report.get("quick_wins_total_value", 0)
        
        html += f"""
        <div class="section">
            <div class="section-title">
                <div class="icon">€</div>
                Quantification du Risque Financier
            </div>
            <div class="financial-hero">
                <div class="financial-card exposure">
                    <div class="label">Exposition annuelle estimée</div>
                    <div class="amount" style="color: var(--red)">{_fmt_eur(exp_mid)}</div>
                    <div class="range">De {_fmt_eur(exp_low)} à {_fmt_eur(exp_high)} — Amende NIS 2 max : {_fmt_eur(fine)}</div>
                </div>
                <div class="financial-card savings">
                    <div class="label">Réduction possible (Quick Wins)</div>
                    <div class="amount" style="color: var(--green)">{_fmt_eur(qw_value)}</div>
                    <div class="range">Actions réalisables en moins d'un mois</div>
                </div>
            </div>
"""
        
        # Top risques
        exposures = financial_report.get("exposures", [])
        top_risks = sorted(exposures, key=lambda e: e.get("exposure_mid", 0), reverse=True)[:7]
        
        if top_risks:
            html += """
            <div style="margin-top: 16px;">
"""
            for risk in top_risks:
                exp_mid_r = risk.get("exposure_mid", 0)
                color = "var(--red)" if exp_mid_r > 200000 else "var(--orange)"
                prob = risk.get("probability_pct", 0)
                
                html += f"""
                <div class="risk-item">
                    <div>
                        <div class="risk-name">{risk['requirement_title']}</div>
                        <div class="risk-type">{risk['incident_label']} — {risk.get('rationale', '')[:60]}</div>
                    </div>
                    <div class="risk-prob" style="color: var(--text-secondary)">{prob}%/an</div>
                    <div class="risk-cost" style="color: {color}">{_fmt_eur(exp_mid_r)}/an</div>
                </div>
"""
            html += """
            </div>
"""
        html += """
        </div>
"""

    # ── SECTION : Plan de remédiation ──
    action_plan = analysis.get("action_plan", {})
    html += f"""
        <div class="section">
            <div class="section-title">
                <div class="icon">▶</div>
                Plan de Remédiation Priorisé
            </div>
            <div class="action-phases">
                <div class="phase-card">
                    <div class="phase-count" style="color: var(--red)">{action_plan.get('immediate', 0)}</div>
                    <div class="phase-label">Immédiat</div>
                </div>
                <div class="phase-card">
                    <div class="phase-count" style="color: var(--orange)">{action_plan.get('short_term', 0)}</div>
                    <div class="phase-label">Court terme</div>
                </div>
                <div class="phase-card">
                    <div class="phase-count" style="color: var(--blue)">{action_plan.get('medium_term', 0)}</div>
                    <div class="phase-label">Moyen terme</div>
                </div>
                <div class="phase-card">
                    <div class="phase-count" style="color: var(--text-muted)">{action_plan.get('long_term', 0)}</div>
                    <div class="phase-label">Long terme</div>
                </div>
            </div>
"""
    
    # Table des gaps
    gaps = analysis.get("gaps", [])
    if gaps:
        html += """
            <table class="gap-table">
                <tr>
                    <th>Exigence</th>
                    <th>Domaine</th>
                    <th>Niveau</th>
                    <th>Effort</th>
                    <th>Quick Win</th>
                </tr>
"""
        for gap in gaps[:15]:
            level = gap.get("current_maturity_value", 0)
            m_color = _maturity_color(level)
            effort = gap.get("effort", "medium")
            e_colors = {"low": "var(--green)", "medium": "var(--orange)", "high": "var(--red)"}
            e_color = e_colors.get(effort, "var(--text-muted)")
            
            html += f"""
                <tr>
                    <td style="font-weight: 500; color: var(--text-primary); font-size: 12px;">{gap['title'][:45]}</td>
                    <td style="font-size: 11px;">{gap['domain'][:30]}</td>
                    <td><span class="maturity-badge" style="background: {m_color}20; color: {m_color}">N{level}</span></td>
                    <td><span class="effort-badge" style="background: {e_color}15; color: {e_color}">{gap.get('effort_label', '')}</span></td>
                    <td style="font-size: 11px;">{gap['quick_win'][:60]}</td>
                </tr>
"""
        html += """
            </table>
"""
    html += """
        </div>
"""

    # ── SECTION : Couverture ISO 27001 ──
    iso_mapping = analysis.get("iso27001_mapping", {})
    iso_details = iso_mapping.get("details", {})
    iso_covered = iso_mapping.get("controls_covered", 0)
    iso_total = iso_mapping.get("total_controls_referenced", 0)
    iso_pct = iso_mapping.get("coverage_pct", 0)
    
    html += f"""
        <div class="section">
            <div class="section-title">
                <div class="icon">✓</div>
                Couverture ISO 27001:2022 — {iso_pct}%
            </div>
            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 16px;">
                {iso_covered} contrôles couverts sur {iso_total} référencés dans le mapping NIS 2 ↔ ISO 27001 Annex A.
            </p>
            <div class="iso-grid">
"""
    
    for control, covered in sorted(iso_details.items()):
        css_class = "covered" if covered else "not-covered"
        html += f'                <div class="iso-pill {css_class}">{control}</div>\n'
    
    html += """
            </div>
        </div>
"""

    # ── FOOTER ──
    html += f"""
        <div class="footer">
            <p>NIS 2 Risk Analyzer v1.0.0 — Généré le {timestamp}</p>
            <p style="margin-top: 4px;">Développé par Ryan Roy TASSEH TAGNY — 
                <a href="https://github.com/RyanRoy23">github.com/RyanRoy23</a></p>
            <p style="margin-top: 8px; font-size: 11px;">
                Ce rapport est un outil d'aide à la décision. Il ne constitue pas un audit officiel ni un avis juridique.
            </p>
        </div>
    </div>
</body>
</html>
"""
    
    # Écrire le fichier
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    
    return os.path.abspath(output_path)
