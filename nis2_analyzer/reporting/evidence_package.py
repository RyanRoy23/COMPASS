"""
COMPASS — Dossier de preuves exportable (Art. 21 + Art. 20)

Génère un package ZIP structuré contenant l'ensemble des éléments
nécessaires à un audit NIS 2 ou à une transmission à l'autorité
compétente (ANSSI en France).

Contenu du package :
  manifest.json          — métadonnées, checksums SHA-256, horodatage
  assessment.json        — évaluation NIS 2 Art. 21 complète
  governance.json        — évaluation Art. 20 (si fournie)
  qualification.json     — qualification Art. 3 EE/EI (si fournie)
  gaps_action_plan.csv   — plan de remédiation (import Excel)
  evidence_summary.html  — synthèse lisible pour un auditeur

Pourquoi un ZIP ?
  Un auditeur ou régulateur reçoit un seul fichier auto-suffisant,
  horodaté et intègre (checksums). Chaque composant est versionné
  et peut être validé indépendamment.
"""

import csv
import hashlib
import html
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _h(value: str) -> str:
    return html.escape(str(value), quote=True)


# ── Générateurs de contenu ───────────────────────────────────────────────────

def _build_gaps_csv(domains_obj) -> bytes:
    """
    Génère le CSV du plan de remédiation.
    Accepte une liste d'objets Domain (pour accéder à toutes les sous-exigences).
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)

    writer.writerow([
        "ID", "Domaine", "Titre", "Maturité actuelle",
        "Est un gap", "Gap critique",
        "Action rapide", "Implémentation complète", "Effort",
        "Refs ISO 27001", "Refs DORA",
    ])

    for domain in domains_obj:
        domain_title = domain.title
        for req in domain.sub_requirements:
            maturity_label = req.maturity.label if req.maturity is not None else "Non évalué"
            rem = req.remediation
            writer.writerow([
                req.id,
                domain_title,
                req.title,
                maturity_label,
                "Oui" if req.is_gap else "Non",
                "Oui" if req.is_critical_gap else "Non",
                rem.quick_win,
                rem.full_implementation,
                rem.effort.value,
                "; ".join(req.iso27001_refs),
                "; ".join(req.dora_refs),
            ])

    return output.getvalue().encode("utf-8-sig")  # BOM pour Excel


def _build_evidence_html(
    assessment: dict,
    governance: Optional[dict],
    qualification: Optional[dict],
    org_name: str,
    generated_at: str,
) -> bytes:
    """Génère la synthèse HTML lisible pour un auditeur."""

    scores = assessment.get("scores", {})
    overall = scores.get("overall_score", 0)
    grade = scores.get("grade", "?")
    total_gaps = scores.get("total_gaps", 0)
    critical_gaps = scores.get("total_critical_gaps", 0)

    grade_color = {"A": "#10B981", "B": "#3B82F6", "C": "#F59E0B", "D": "#EF4444", "F": "#DC2626"}.get(grade, "#94A3B8")

    # Section qualification
    qual_html = ""
    if qualification:
        cat_label = qualification.get("category_label", "—")
        cat_color = qualification.get("category_color", "#94A3B8")
        annex = qualification.get("sector_annex", "—")
        qual_html = f"""
        <section>
          <h2>Qualification NIS 2 — Article 3</h2>
          <table>
            <tr><th>Catégorie</th><td style="color:{_h(cat_color)};font-weight:700">{_h(cat_label)}</td></tr>
            <tr><th>Secteur</th><td>{_h(qualification.get('sector_label', '—'))} (Annexe {_h(annex)})</td></tr>
            <tr><th>Supervision</th><td>{_h(qualification.get('obligations', {}).get('supervision', '—'))}</td></tr>
            <tr><th>Notification early warning</th><td>{_h(qualification.get('obligations', {}).get('notification_early_warning', '—'))}</td></tr>
            <tr><th>Sanction max</th><td>{_h(qualification.get('obligations', {}).get('sanction_max_persons_morales', '—'))}</td></tr>
            <tr><th>Audit obligatoire</th><td>{'Oui' if qualification.get('obligations', {}).get('audit_obligatoire') else 'Non'}</td></tr>
          </table>
        </section>"""

    # Section gouvernance
    gov_html = ""
    if governance:
        gov_score = governance.get("overall_score", 0)
        gov_grade = governance.get("grade", "?")
        gov_grade_color = {"A": "#10B981", "B": "#3B82F6", "C": "#F59E0B", "D": "#EF4444", "F": "#DC2626"}.get(gov_grade, "#94A3B8")
        liability = governance.get("liability_risk", "—")
        liability_color = {"ÉLEVÉ": "#EF4444", "MODÉRÉ": "#F59E0B", "FAIBLE": "#10B981"}.get(liability, "#94A3B8")

        gov_rows = ""
        for q in governance.get("questions", []):
            if q.get("maturity") is None:
                continue
            gap_mark = " ⚠" if q.get("is_gap") else ""
            critical_mark = " 🔴" if q.get("is_critical_gap") else ""
            gov_rows += f"<tr><td>{_h(q['id'])}</td><td>{_h(q['pillar'])}</td><td>{_h(q['title'])}</td><td>{_h(q.get('maturity_label','—'))}{gap_mark}{critical_mark}</td></tr>"

        gov_html = f"""
        <section>
          <h2>Gouvernance — Article 20</h2>
          <table>
            <tr><th>Score gouvernance</th><td style="color:{gov_grade_color};font-weight:700">{gov_score}% (Grade {_h(gov_grade)})</td></tr>
            <tr><th>Gaps gouvernance</th><td>{governance.get('total_gaps', 0)} dont {governance.get('critical_gaps', 0)} critiques</td></tr>
            <tr><th>Risque responsabilité dirigeants</th><td style="color:{liability_color};font-weight:700">{_h(liability)}</td></tr>
          </table>
          <h3>Détail par question</h3>
          <table>
            <tr><th>ID</th><th>Pilier</th><th>Question</th><th>Maturité</th></tr>
            {gov_rows}
          </table>
        </section>"""

    # Domaines
    domain_rows = ""
    for d in assessment.get("domains", []):
        sc = d.get("score", 0)
        dcolor = "#10B981" if sc >= 66 else "#F59E0B" if sc >= 33 else "#EF4444"
        domain_rows += f"<tr><td>{_h(d['title'])}</td><td style='color:{dcolor};font-weight:700'>{sc:.1f}%</td><td>{d.get('gap_count',0)}</td><td>{d.get('critical_gap_count',0)}</td></tr>"

    # Gaps critiques
    gap_rows = ""
    for gap in assessment.get("gaps", []):
        if gap.get("is_critical_gap"):
            rem = gap.get("remediation", {})
            gap_rows += f"<tr><td>{_h(gap['id'])}</td><td>{_h(gap['title'])}</td><td>{_h(rem.get('quick_win','—'))}</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>COMPASS — Dossier de preuves NIS 2 — {_h(org_name)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; color: #1e293b; line-height: 1.6; }}
    h1 {{ color: #0f172a; border-bottom: 3px solid #38bdf8; padding-bottom: 8px; }}
    h2 {{ color: #0f172a; margin-top: 32px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }}
    h3 {{ color: #334155; margin-top: 20px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
    th {{ background: #f1f5f9; text-align: left; padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600; }}
    td {{ padding: 8px 12px; border: 1px solid #e2e8f0; }}
    tr:nth-child(even) {{ background: #f8fafc; }}
    .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-weight: 700; font-size: 14px; }}
    .meta {{ color: #64748b; font-size: 13px; margin-top: 4px; }}
    section {{ margin-bottom: 40px; }}
    .notice {{ background: #fefce8; border: 1px solid #fde68a; padding: 12px 16px; border-radius: 6px; margin-top: 24px; font-size: 13px; color: #78350f; }}
  </style>
</head>
<body>
  <h1>COMPASS — Dossier de preuves NIS 2</h1>
  <p class="meta">Organisation : <strong>{_h(org_name)}</strong></p>
  <p class="meta">Généré le : {_h(generated_at)}</p>
  <p class="meta">Référentiel : NIS 2 Directive (UE) 2022/2555 — Article 21</p>

  <section>
    <h2>Résumé exécutif</h2>
    <table>
      <tr><th>Score de conformité global</th><td style="color:{grade_color};font-weight:700">{overall}% (Grade {_h(grade)})</td></tr>
      <tr><th>Exigences totales</th><td>{scores.get('total_requirements', '—')}</td></tr>
      <tr><th>Exigences évaluées</th><td>{scores.get('total_assessed', '—')}</td></tr>
      <tr><th>Gaps identifiés</th><td>{total_gaps}</td></tr>
      <tr><th>Gaps critiques (maturité 0)</th><td style="color:#EF4444;font-weight:700">{critical_gaps}</td></tr>
    </table>
  </section>

  {qual_html}

  <section>
    <h2>Conformité par domaine NIS 2 Art. 21</h2>
    <table>
      <tr><th>Domaine</th><th>Score</th><th>Gaps</th><th>Critiques</th></tr>
      {domain_rows}
    </table>
  </section>

  {gov_html}

  {'<section><h2>Gaps critiques prioritaires</h2><table><tr><th>ID</th><th>Exigence</th><th>Action rapide recommandée</th></tr>' + gap_rows + '</table></section>' if gap_rows else ''}

  <div class="notice">
    <strong>Avertissement :</strong> Ce dossier est une auto-évaluation outillée. Il ne remplace pas un audit
    de conformité certifié. Les évaluations déclaratives doivent être vérifiées par un auditeur externe.
    Les preuves techniques (bridge CloudSec) portent uniquement sur l'environnement Azure/Entra ID audité.
  </div>
</body>
</html>"""

    return html_content.encode("utf-8")


# ── Point d'entrée principal ──────────────────────────────────────────────────

def build_evidence_package(
    assessment: dict,
    output_path: str,
    domains_obj=None,
    governance: Optional[dict] = None,
    qualification: Optional[dict] = None,
    org_name: Optional[str] = None,
) -> str:
    """
    Génère le dossier de preuves ZIP et le sauvegarde dans output_path.

    Args:
        assessment:    dict produit par ScoringEngine.full_analysis()
        output_path:   chemin du fichier ZIP de sortie
        domains_obj:   liste d'objets Domain (pour le CSV détaillé — optionnel)
        governance:    dict produit par GovernanceResult.to_dict() (optionnel)
        qualification: dict produit par QualificationResult.to_dict() (optionnel)
        org_name:      nom de l'organisation (extrait de assessment si absent)

    Returns:
        Chemin absolu du ZIP généré.
    """
    if org_name is None:
        org_name = assessment.get("metadata", {}).get("organization", "Organisation")

    generated_at = _now_iso()

    # ── Construire les fichiers du package ────────────────────────────────

    files: dict[str, bytes] = {}

    # 1. assessment.json
    files["assessment.json"] = json.dumps(assessment, ensure_ascii=False, indent=2).encode("utf-8")

    # 2. governance.json (optionnel)
    if governance:
        files["governance.json"] = json.dumps(governance, ensure_ascii=False, indent=2).encode("utf-8")

    # 3. qualification.json (optionnel)
    if qualification:
        files["qualification.json"] = json.dumps(qualification, ensure_ascii=False, indent=2).encode("utf-8")

    # 4. gaps_action_plan.csv
    files["gaps_action_plan.csv"] = _build_gaps_csv(domains_obj) if domains_obj else b""

    # 5. evidence_summary.html
    files["evidence_summary.html"] = _build_evidence_html(
        assessment, governance, qualification, org_name, generated_at
    )

    # 6. manifest.json — checksums + métadonnées
    manifest = {
        "compass_version": "1.1.0",
        "generated_at": generated_at,
        "organization": org_name,
        "framework": "NIS 2 Directive (UE) 2022/2555 — Article 21",
        "files": {
            name: {
                "size_bytes": len(content),
                "sha256": _sha256(content),
            }
            for name, content in files.items()
        },
        "includes_governance": governance is not None,
        "includes_qualification": qualification is not None,
        "scores": {
            "overall_score": assessment.get("scores", {}).get("overall_score"),
            "grade": assessment.get("scores", {}).get("grade"),
            "total_gaps": assessment.get("scores", {}).get("total_gaps"),
        },
    }
    files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")

    # ── Écrire le ZIP ─────────────────────────────────────────────────────

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)

    return str(output.resolve())


def list_package_contents(zip_path: str) -> list[dict]:
    """
    Liste le contenu d'un package ZIP avec tailles et checksums.
    Utile pour vérifier l'intégrité avant transmission.
    """
    result = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            content = zf.read(info.filename)
            result.append({
                "filename": info.filename,
                "size_bytes": info.file_size,
                "sha256": _sha256(content),
            })
    return result
