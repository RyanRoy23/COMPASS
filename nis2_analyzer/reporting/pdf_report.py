"""
COMPASS — Générateur de rapport PDF professionnel

Produit un rapport PDF complet à partir d'un AssessmentResult :
  - Page de garde avec score global, grade et métadonnées
  - Scores par domaine avec barres visuelles colorées
  - Gaps prioritaires classés par criticité
  - Plan de remédiation rapide (quick wins)
  - Pied de page COMPASS / NIS 2 Art. 21
"""

import io
from datetime import datetime
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)
from reportlab.platypus.flowables import Flowable

from nis2_analyzer.core.models import AssessmentResult, Domain
from nis2_analyzer.core.scoring import ScoringEngine

# ── Palette COMPASS ───────────────────────────────────────────────────────────

C_BG        = colors.HexColor("#0A0E1A")
C_SURFACE   = colors.HexColor("#111827")
C_ACCENT    = colors.HexColor("#3B82F6")
C_GREEN     = colors.HexColor("#10B981")
C_YELLOW    = colors.HexColor("#F59E0B")
C_RED       = colors.HexColor("#EF4444")
C_MUTED     = colors.HexColor("#6B7280")
C_TEXT      = colors.HexColor("#1F2937")
C_WHITE     = colors.white
C_LIGHT_BG  = colors.HexColor("#F8FAFC")
C_BORDER    = colors.HexColor("#E2E8F0")

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


def _grade_color(grade: str) -> colors.Color:
    return {
        "A": C_GREEN,
        "B": C_ACCENT,
        "C": C_YELLOW,
        "D": C_RED,
        "F": colors.HexColor("#DC2626"),
    }.get(grade, C_MUTED)


def _score_color(score: float) -> colors.Color:
    if score >= 70:
        return C_GREEN
    if score >= 50:
        return C_YELLOW
    return C_RED


# ── Flowable personnalisé : barre de score ────────────────────────────────────

class ScoreBar(Flowable):
    """Barre de progression colorée pour représenter un score de domaine."""

    def __init__(self, score: float, width: float = 120 * mm, height: float = 6):
        super().__init__()
        self.score = score
        self.width = width
        self.height = height

    def draw(self):
        filled = self.width * (self.score / 100)
        # fond gris
        self.canv.setFillColor(C_BORDER)
        self.canv.roundRect(0, 0, self.width, self.height, 2, fill=1, stroke=0)
        # barre colorée
        if filled > 0:
            self.canv.setFillColor(_score_color(self.score))
            self.canv.roundRect(0, 0, min(filled, self.width), self.height, 2, fill=1, stroke=0)

    def wrap(self, *args):
        return self.width, self.height


# ── Styles typographiques ─────────────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", fontSize=26, fontName="Helvetica-Bold",
            textColor=C_WHITE, leading=32, alignment=TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", fontSize=12, fontName="Helvetica",
            textColor=colors.HexColor("#93C5FD"), leading=18, alignment=TA_LEFT,
        ),
        "meta": ParagraphStyle(
            "meta", fontSize=9, fontName="Helvetica",
            textColor=colors.HexColor("#CBD5E1"), leading=14, alignment=TA_LEFT,
        ),
        "section": ParagraphStyle(
            "section", fontSize=13, fontName="Helvetica-Bold",
            textColor=C_ACCENT, leading=18, spaceBefore=6,
        ),
        "body": ParagraphStyle(
            "body", fontSize=9, fontName="Helvetica",
            textColor=C_TEXT, leading=14,
        ),
        "body_bold": ParagraphStyle(
            "body_bold", fontSize=9, fontName="Helvetica-Bold",
            textColor=C_TEXT, leading=14,
        ),
        "small": ParagraphStyle(
            "small", fontSize=8, fontName="Helvetica",
            textColor=C_MUTED, leading=12,
        ),
        "footer": ParagraphStyle(
            "footer", fontSize=7.5, fontName="Helvetica",
            textColor=C_MUTED, alignment=TA_CENTER,
        ),
        "gap_title": ParagraphStyle(
            "gap_title", fontSize=9, fontName="Helvetica-Bold",
            textColor=C_TEXT, leading=13,
        ),
        "gap_action": ParagraphStyle(
            "gap_action", fontSize=8.5, fontName="Helvetica",
            textColor=colors.HexColor("#374151"), leading=13,
        ),
    }


# ── Template de page ──────────────────────────────────────────────────────────

class _CoverPageTemplate(PageTemplate):
    """Page de garde avec fond sombre."""

    def __init__(self):
        frame = Frame(MARGIN, MARGIN, PAGE_W - 2 * MARGIN, PAGE_H - 2 * MARGIN,
                      id="cover", showBoundary=0)
        super().__init__("cover", [frame])

    def beforeDrawPage(self, canvas, doc):
        canvas.saveState()
        # fond sombre
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        # bande accent en haut
        canvas.setFillColor(C_ACCENT)
        canvas.rect(0, PAGE_H - 6, PAGE_W, 6, fill=1, stroke=0)
        canvas.restoreState()


class _ContentPageTemplate(PageTemplate):
    """Pages de contenu avec header et footer."""

    def __init__(self, org_name: str, timestamp: str):
        self.org_name = org_name
        self.timestamp = timestamp
        frame = Frame(MARGIN, MARGIN + 10 * mm, PAGE_W - 2 * MARGIN,
                      PAGE_H - 2 * MARGIN - 22 * mm, id="content", showBoundary=0)
        super().__init__("content", [frame])

    def beforeDrawPage(self, canvas, doc):
        canvas.saveState()
        # Header
        canvas.setFillColor(C_SURFACE)
        canvas.rect(0, PAGE_H - 14 * mm, PAGE_W, 14 * mm, fill=1, stroke=0)
        canvas.setFillColor(C_ACCENT)
        canvas.rect(0, PAGE_H - 14 * mm, 4, 14 * mm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(C_WHITE)
        canvas.drawString(MARGIN, PAGE_H - 9 * mm, "COMPASS")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#94A3B8"))
        canvas.drawString(MARGIN + 22 * mm, PAGE_H - 9 * mm,
                          f"Rapport NIS 2 — {self.org_name}")
        canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 9 * mm, self.timestamp)

        # Footer
        canvas.setFillColor(C_BORDER)
        canvas.rect(MARGIN, 10 * mm, PAGE_W - 2 * MARGIN, 0.5, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(MARGIN, 7 * mm,
                          "COMPASS — Compliance Posture Assessment System")
        canvas.drawRightString(PAGE_W - MARGIN, 7 * mm,
                               f"Page {doc.page}")
        canvas.restoreState()


# ── Contenu de la page de garde ───────────────────────────────────────────────

def _cover_content(result: AssessmentResult, sector: str, styles: dict) -> list:
    story = []
    story.append(Spacer(1, 40 * mm))

    # Badge NIS 2
    badge_data = [["  NIS 2 — Art. 21  "]]
    badge_table = Table(badge_data, colWidths=[45 * mm])
    badge_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, -1), C_WHITE),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(badge_table)
    story.append(Spacer(1, 8 * mm))

    # Titre
    story.append(Paragraph("Rapport de conformité", styles["subtitle"]))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph("COMPASS", styles["title"]))
    story.append(Spacer(1, 10 * mm))

    # Ligne de séparation accent
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=8 * mm))

    # Métadonnées organisation
    ts = result.timestamp or datetime.now().strftime("%d/%m/%Y")
    meta_lines = [
        f"<b>Organisation :</b>  {result.organization_name}",
        f"<b>Secteur :</b>  {sector}",
        f"<b>Date :</b>  {ts}",
        f"<b>Exigences évaluées :</b>  {result.total_assessed} / {result.total_requirements}",
    ]
    for line in meta_lines:
        story.append(Paragraph(line, styles["meta"]))
        story.append(Spacer(1, 2 * mm))

    story.append(Spacer(1, 12 * mm))

    # Score et grade en grand
    grade = result.grade.value
    score = round(result.overall_score, 1)
    grade_col = _grade_color(grade)

    kpi_data = [[
        Paragraph(f"<font size='42'><b>{score}%</b></font>",
                  ParagraphStyle("kpi_score", fontSize=42, fontName="Helvetica-Bold",
                                 textColor=_score_color(score), alignment=TA_CENTER)),
        Paragraph(f"<font size='56'><b>{grade}</b></font>",
                  ParagraphStyle("kpi_grade", fontSize=56, fontName="Helvetica-Bold",
                                 textColor=grade_col, alignment=TA_CENTER)),
        Paragraph(
            f"<font size='9' color='#94A3B8'>Gaps identifiés</font><br/>"
            f"<font size='32'><b>{result.total_gaps}</b></font><br/>"
            f"<font size='8' color='#94A3B8'>dont {result.total_critical_gaps} critiques</font>",
            ParagraphStyle("kpi_gaps", fontSize=9, fontName="Helvetica",
                           textColor=C_RED, alignment=TA_CENTER, leading=20)),
    ]]
    kpi_table = Table(kpi_data, colWidths=[(PAGE_W - 2 * MARGIN) / 3] * 3)
    kpi_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#111827")),
        ("ROUNDEDCORNERS", [8, 8, 8, 8]),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LINEAFTER", (0, 0), (1, 0), 0.5, colors.HexColor("#1F2937")),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 8 * mm))

    # Description du grade
    story.append(Paragraph(result.grade.description,
                            ParagraphStyle("grade_desc", fontSize=9, fontName="Helvetica",
                                           textColor=colors.HexColor("#94A3B8"),
                                           alignment=TA_CENTER, leading=14)))
    return story


# ── Section : scores par domaine ──────────────────────────────────────────────

def _domain_scores_content(domains: list[Domain], styles: dict) -> list:
    story = []
    story.append(Paragraph("Scores par domaine NIS 2", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=4 * mm))

    col_w = PAGE_W - 2 * MARGIN
    bar_w = col_w * 0.35

    rows = []
    for d in domains:
        score = round(d.score, 1)
        assessed = d.assessed_count
        total = d.total_requirements
        coverage = f"{assessed}/{total}"
        gap_count = d.gap_count

        gap_label = ""
        if gap_count > 0:
            gap_label = f"{gap_count} gap{'s' if gap_count > 1 else ''}"

        rows.append([
            Paragraph(f"<b>{d.title}</b><br/>"
                      f"<font color='#6B7280' size='7.5'>{d.article_ref} · couverture {coverage}</font>",
                      styles["body"]),
            ScoreBar(score, width=bar_w, height=7),
            Paragraph(f"<b>{score}%</b>",
                      ParagraphStyle("pct", fontSize=9, fontName="Helvetica-Bold",
                                     textColor=_score_color(score), alignment=TA_RIGHT)),
            Paragraph(gap_label,
                      ParagraphStyle("gaps_lbl", fontSize=8, fontName="Helvetica",
                                     textColor=C_RED if gap_count > 0 else C_MUTED,
                                     alignment=TA_RIGHT)),
        ])

    col_widths = [col_w - bar_w - 22 * mm - 20 * mm, bar_w, 22 * mm, 20 * mm]
    t = Table(rows, colWidths=col_widths, repeatRows=0)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, C_BORDER),
        ("BACKGROUND", (0, 0), (-1, -1), C_WHITE),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_WHITE, C_LIGHT_BG]),
    ]))
    story.append(t)
    return story


# ── Section : gaps prioritaires ───────────────────────────────────────────────

def _gaps_content(result: AssessmentResult, styles: dict, max_gaps: int = 12) -> list:
    story = []
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Gaps prioritaires à traiter", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=4 * mm))

    # Collecte tous les gaps triés : critiques d'abord, puis par poids de domaine
    all_gaps = []
    for d in result.domains:
        for r in d.sub_requirements:
            if r.is_gap:
                all_gaps.append((d, r))

    all_gaps.sort(key=lambda x: (x[1].maturity.value, -x[0].weight))

    col_w = PAGE_W - 2 * MARGIN
    rows = []
    header = [
        Paragraph("<b>Exigence</b>", styles["body_bold"]),
        Paragraph("<b>Domaine</b>", styles["body_bold"]),
        Paragraph("<b>Maturité</b>", styles["body_bold"]),
        Paragraph("<b>Action rapide</b>", styles["body_bold"]),
    ]
    rows.append(header)

    for domain, req in all_gaps[:max_gaps]:
        mat = req.maturity.value
        mat_label = req.maturity.label
        mat_color = {0: C_RED, 1: C_YELLOW}.get(mat, C_MUTED)

        rows.append([
            Paragraph(f"<b>{req.id}</b><br/>{req.title}", styles["gap_title"]),
            Paragraph(domain.title, styles["small"]),
            Paragraph(f"<font color='{mat_color.hexval()}'><b>{mat}/3</b></font><br/>"
                      f"<font size='7.5'>{mat_label}</font>", styles["small"]),
            Paragraph(req.remediation.quick_win, styles["gap_action"]),
        ])

    col_widths = [35 * mm, 38 * mm, 22 * mm, col_w - 35 * mm - 38 * mm - 22 * mm]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EFF6FF")),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_ACCENT),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LIGHT_BG]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))

    # Mettre en rouge les lignes critiques (maturité 0)
    for i, (_, req) in enumerate(all_gaps[:max_gaps], start=1):
        if req.maturity.value == 0:
            t.setStyle(TableStyle([
                ("LEFTPADDING", (0, i), (0, i), 4),
                ("LINEBEFORE", (0, i), (0, i), 3, C_RED),
            ]))
        elif req.maturity.value == 1:
            t.setStyle(TableStyle([
                ("LEFTPADDING", (0, i), (0, i), 4),
                ("LINEBEFORE", (0, i), (0, i), 3, C_YELLOW),
            ]))

    story.append(t)

    if len(all_gaps) > max_gaps:
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(
            f"… et {len(all_gaps) - max_gaps} autres gaps identifiés. "
            "Consultez l'interface COMPASS pour le détail complet.",
            styles["small"]))

    return story


# ── Section : quick wins ──────────────────────────────────────────────────────

def _quickwins_content(result: AssessmentResult, styles: dict) -> list:
    story = []
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Quick wins — Actions prioritaires (effort faible)", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=4 * mm))

    quick_wins = result.gaps_by_effort.get("low", [])
    if not quick_wins:
        story.append(Paragraph("Aucun quick win identifié.", styles["small"]))
        return story

    col_w = PAGE_W - 2 * MARGIN
    rows = []
    for i, req in enumerate(quick_wins[:8], 1):
        rows.append([
            Paragraph(f"<b>{i}.</b>", styles["body_bold"]),
            Paragraph(f"<b>{req.title}</b>", styles["body_bold"]),
            Paragraph(req.remediation.quick_win, styles["body"]),
            Paragraph(f"<font color='#10B981'>{'  '.join(req.iso27001_refs[:2])}</font>",
                      styles["small"]),
        ])

    t = Table(rows, colWidths=[8 * mm, 45 * mm, col_w - 8 * mm - 45 * mm - 28 * mm, 28 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, C_BORDER),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_WHITE, C_LIGHT_BG]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    return story


# ── Section : plan SMART ─────────────────────────────────────────────────────

def _smart_plan_content(result: AssessmentResult, styles: dict) -> list:
    story = []
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Plan d'action SMART", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=3 * mm))
    story.append(Paragraph(
        "Priorisé par délai recommandé — effort, coût estimé et responsable par gap.",
        styles["small"]))
    story.append(Spacer(1, 3 * mm))

    engine = ScoringEngine()
    gaps = engine.generate_gap_analysis(result)
    if not gaps:
        story.append(Paragraph("Aucun gap identifié — posture conforme.", styles["small"]))
        return story

    PHASE_COLORS = {0: C_RED, 1: colors.HexColor("#F97316"), 2: C_YELLOW, 3: C_MUTED}
    PHASE_LABELS = {0: "Immédiat", 1: "Court terme", 2: "Moyen terme", 3: "Long terme"}

    def _phase(g) -> int:
        w = g.deadline_weeks
        return 0 if w <= 4 else 1 if w <= 12 else 2 if w <= 24 else 3

    def _fmt_cost(v: int) -> str:
        return f"{v // 1000}k€" if v >= 1000 else f"{v}€"

    col_w = PAGE_W - 2 * MARGIN
    header = [
        Paragraph("<b>Phase</b>", styles["body_bold"]),
        Paragraph("<b>Gap / Domaine</b>", styles["body_bold"]),
        Paragraph("<b>Effort</b>", styles["body_bold"]),
        Paragraph("<b>Coût estimé</b>", styles["body_bold"]),
        Paragraph("<b>Responsable</b>", styles["body_bold"]),
    ]
    rows = [header]
    phase_row_indices = {}

    sorted_gaps = sorted(gaps, key=_phase)
    for i, g in enumerate(sorted_gaps[:15], start=1):
        phase = _phase(g)
        pc = PHASE_COLORS[phase]
        label = PHASE_LABELS[phase]
        effort_str = f"{g.effort_days[0]}–{g.effort_days[1]} j"
        cost_str = f"{_fmt_cost(g.cost_range[0])} – {_fmt_cost(g.cost_range[1])}"
        rows.append([
            Paragraph(f"<font color='{pc.hexval()}'><b>{label}</b></font>", styles["small"]),
            Paragraph(f"<b>{g.requirement_id}</b><br/>"
                      f"<font size='7.5'>{g.requirement_title}</font><br/>"
                      f"<font color='#6B7280' size='7'>{g.domain_title}</font>", styles["small"]),
            Paragraph(effort_str, styles["small"]),
            Paragraph(cost_str, styles["small"]),
            Paragraph(g.responsible, styles["small"]),
        ])
        phase_row_indices[i] = phase

    col_widths = [22 * mm, col_w - 22 * mm - 18 * mm - 28 * mm - 35 * mm, 18 * mm, 28 * mm, 35 * mm]
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EFF6FF")),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_ACCENT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_LIGHT_BG]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))

    for row_i, phase in phase_row_indices.items():
        pc = PHASE_COLORS[phase]
        t.setStyle(TableStyle([("LINEBEFORE", (0, row_i), (0, row_i), 3, pc)]))

    story.append(t)

    if len(gaps) > 15:
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(
            f"… et {len(gaps) - 15} autres gaps. Consultez l'interface COMPASS pour le plan complet.",
            styles["small"]))
    return story


# ── Point d'entrée principal ──────────────────────────────────────────────────

def generate_pdf_report(
    result: AssessmentResult,
    sector: str = "Non précisé",
    output: Optional[io.BytesIO] = None,
) -> io.BytesIO:
    """
    Génère le rapport PDF COMPASS et retourne un BytesIO prêt à l'envoi HTTP.

    Args:
        result: AssessmentResult complet issu de ScoringEngine.full_analysis()
        sector: Secteur d'activité (label lisible)
        output: Buffer optionnel ; si None, un nouveau BytesIO est créé.
    """
    if output is None:
        output = io.BytesIO()

    styles = _styles()
    ts = result.timestamp or datetime.now().strftime("%d/%m/%Y à %H:%M")

    # Templates de page
    cover_tpl = _CoverPageTemplate()
    content_tpl = _ContentPageTemplate(result.organization_name, ts)

    doc = BaseDocTemplate(
        output,
        pagesize=A4,
        pageTemplates=[cover_tpl, content_tpl],
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN + 10 * mm,
        title=f"Rapport COMPASS — {result.organization_name}",
        author="COMPASS — Compliance Posture Assessment System",
        subject="Évaluation de conformité NIS 2",
    )

    story = []

    # ── Page 1 : couverture ──
    story += _cover_content(result, sector, styles)
    story.append(_PageBreak("content"))

    # ── Page 2+ : scores domaines ──
    story += _domain_scores_content(result.domains, styles)

    # ── Gaps prioritaires ──
    story += _gaps_content(result, styles)

    # ── Quick wins ──
    story += _quickwins_content(result, styles)

    # ── Plan SMART ──
    story += _smart_plan_content(result, styles)

    # ── Note de bas de rapport ──
    story.append(Spacer(1, 8 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "Ce rapport a été généré automatiquement par COMPASS. Il constitue une aide à la décision "
        "et ne remplace pas une évaluation réalisée par un expert certifié. "
        "Référentiel : Directive NIS 2 (UE 2022/2555), Article 21 — Mesures de gestion des risques.",
        styles["footer"],
    ))

    doc.build(story)
    output.seek(0)
    return output


# ── Flowable interne : saut de page avec changement de template ───────────────

from reportlab.platypus import PageBreak as _RL_PageBreak

class _PageBreak(_RL_PageBreak):
    """Saut de page qui switche vers le template 'content'."""
    def __init__(self, next_template: str = "content"):
        super().__init__(nextTemplate=next_template)
