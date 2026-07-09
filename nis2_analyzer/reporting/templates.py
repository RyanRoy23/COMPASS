"""
COMPASS — Générateur de templates réglementaires NIS 2

Produit des documents PDF pré-remplis à partir des données d'un assessment :
  - PSSI simplifiée (Politique de Sécurité des Systèmes d'Information)
  - Procédure de notification d'incident NIS 2 Art. 23
  - Registre des actifs critiques NIS 2 Art. 21
"""

import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, PageTemplate,
    Paragraph, Spacer, Table, TableStyle, KeepTogether,
)

from nis2_analyzer.core.models import AssessmentResult
from nis2_analyzer.core.scoring import ScoringEngine

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm

C_ACCENT  = colors.HexColor("#3B82F6")
C_GREEN   = colors.HexColor("#10B981")
C_YELLOW  = colors.HexColor("#F59E0B")
C_RED     = colors.HexColor("#EF4444")
C_MUTED   = colors.HexColor("#6B7280")
C_BORDER  = colors.HexColor("#E2E8F0")
C_LIGHT   = colors.HexColor("#F8FAFC")
C_BG_HEAD = colors.HexColor("#EFF6FF")


def _styles() -> dict:
    return {
        "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=18,
                                 textColor=C_ACCENT, spaceAfter=4),
        "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=11,
                                    textColor=C_MUTED, spaceAfter=8),
        "section": ParagraphStyle("section", fontName="Helvetica-Bold", fontSize=12,
                                   textColor=colors.HexColor("#1E3A5F"), spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9,
                                leading=14, spaceAfter=4),
        "body_bold": ParagraphStyle("body_bold", fontName="Helvetica-Bold", fontSize=9,
                                     leading=14),
        "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8,
                                 textColor=C_MUTED, leading=12),
        "field_label": ParagraphStyle("field_label", fontName="Helvetica-Bold", fontSize=8,
                                       textColor=C_MUTED),
        "center": ParagraphStyle("center", fontName="Helvetica", fontSize=9,
                                  alignment=TA_CENTER),
    }


def _simple_page(canvas, doc, title: str, org: str, date: str):
    canvas.saveState()
    # Bande bleue en haut
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, PAGE_H - 14 * mm, PAGE_W, 14 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(MARGIN, PAGE_H - 9 * mm, f"COMPASS — {title}")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 9 * mm, org)
    # Pied de page
    canvas.setFillColor(C_MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(MARGIN, 8 * mm, f"Généré le {date} par COMPASS — NIS 2 Art. 21 | Document confidentiel")
    canvas.drawRightString(PAGE_W - MARGIN, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _field_row(label: str, value: str, styles: dict) -> list:
    """Ligne label / valeur pour les formulaires."""
    return [
        Paragraph(label, styles["field_label"]),
        Paragraph(value or "___________________________", styles["body"]),
    ]


# ── Template 1 : PSSI Simplifiée ─────────────────────────────────────────────

def generate_pssi(result: AssessmentResult) -> io.BytesIO:
    """Génère une PSSI simplifiée pré-remplie à partir de l'assessment."""
    buf = io.BytesIO()
    styles = _styles()
    org = result.organization_name
    date = datetime.now().strftime("%d/%m/%Y")
    engine = ScoringEngine()
    gaps = engine.generate_gap_analysis(result)

    def on_page(canvas, doc):
        _simple_page(canvas, doc, "Politique de Sécurité des Systèmes d'Information", org, date)

    frame = Frame(MARGIN, MARGIN + 10 * mm, PAGE_W - 2 * MARGIN, PAGE_H - 2 * MARGIN - 24 * mm)
    tpl = PageTemplate(id="main", frames=[frame], onPage=on_page)
    doc = BaseDocTemplate(buf, pagesize=A4, pageTemplates=[tpl],
                          title=f"PSSI — {org}", author="COMPASS")

    story = []

    # En-tête
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Politique de Sécurité des Systèmes d'Information", styles["title"]))
    story.append(Paragraph(f"NIS 2 Art. 21 — Version 1.0 — {date}", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=6 * mm))

    # Identification
    story.append(Paragraph("1. Identification du document", styles["section"]))
    col_w = PAGE_W - 2 * MARGIN
    id_rows = [
        _field_row("Organisation", org, styles),
        _field_row("Responsable PSSI (RSSI)", "", styles),
        _field_row("Date d'approbation", "", styles),
        _field_row("Prochaine révision", "", styles),
        _field_row("Catégorie NIS 2", "Entité Essentielle / Importante (à préciser)", styles),
        _field_row("Score de conformité actuel", f"{round(result.overall_score, 1)}% — Grade {result.grade.value}", styles),
    ]
    t = Table(id_rows, colWidths=[55 * mm, col_w - 55 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("BACKGROUND", (0, 0), (0, -1), C_LIGHT),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 4 * mm))

    # Périmètre
    story.append(Paragraph("2. Périmètre et objectifs", styles["section"]))
    story.append(Paragraph(
        f"La présente PSSI s'applique à l'ensemble des systèmes d'information de <b>{org}</b>. "
        "Elle définit les orientations stratégiques en matière de sécurité conformément aux "
        "exigences de la directive NIS 2 (UE 2022/2555) et des guides de l'ANSSI.",
        styles["body"]))
    story.append(Spacer(1, 3 * mm))

    # Domaines NIS 2
    story.append(Paragraph("3. Couverture des domaines NIS 2 — Art. 21", styles["section"]))
    domain_rows = [[
        Paragraph("<b>Domaine</b>", styles["body_bold"]),
        Paragraph("<b>Réf.</b>", styles["body_bold"]),
        Paragraph("<b>Score</b>", styles["body_bold"]),
        Paragraph("<b>Statut</b>", styles["body_bold"]),
    ]]
    for d in result.domains:
        score = round(d.score, 1)
        status = "Conforme" if score >= 70 else "En cours" if score >= 40 else "À traiter"
        sc = C_GREEN if score >= 70 else C_YELLOW if score >= 40 else C_RED
        domain_rows.append([
            Paragraph(d.title, styles["body"]),
            Paragraph(d.article_ref, styles["small"]),
            Paragraph(f"{score}%", styles["body"]),
            Paragraph(f"<font color='{sc.hexval()}'>{status}</font>", styles["body"]),
        ])
    t2 = Table(domain_rows, colWidths=[80 * mm, 25 * mm, 20 * mm, col_w - 125 * mm], repeatRows=1)
    t2.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_BG_HEAD),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_ACCENT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_LIGHT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t2)
    story.append(Spacer(1, 4 * mm))

    # Gaps prioritaires
    if gaps:
        story.append(Paragraph("4. Axes d'amélioration prioritaires", styles["section"]))
        gap_rows = [[
            Paragraph("<b>Exigence</b>", styles["body_bold"]),
            Paragraph("<b>Priorité</b>", styles["body_bold"]),
            Paragraph("<b>Action immédiate</b>", styles["body_bold"]),
            Paragraph("<b>Responsable</b>", styles["body_bold"]),
        ]]
        for g in gaps[:10]:
            prio_color = C_RED if g.is_critical else C_YELLOW
            prio_label = "Critique" if g.is_critical else "Modérée"
            gap_rows.append([
                Paragraph(f"<b>{g.requirement_id}</b><br/><font size='7.5'>{g.requirement_title}</font>",
                           styles["small"]),
                Paragraph(f"<font color='{prio_color.hexval()}'><b>{prio_label}</b></font>", styles["small"]),
                Paragraph(g.quick_win, styles["small"]),
                Paragraph(g.responsible, styles["small"]),
            ])
        t3 = Table(gap_rows, colWidths=[38 * mm, 18 * mm, col_w - 38 * mm - 18 * mm - 35 * mm, 35 * mm],
                   repeatRows=1)
        t3.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_BG_HEAD),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_ACCENT),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_LIGHT]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t3)
        story.append(Spacer(1, 4 * mm))

    # Signatures
    story.append(Paragraph("5. Approbation", styles["section"]))
    sig_rows = [
        [Paragraph("Rôle", styles["field_label"]), Paragraph("Nom", styles["field_label"]),
         Paragraph("Date", styles["field_label"]), Paragraph("Signature", styles["field_label"])],
        [Paragraph("Directeur Général", styles["body"]), Paragraph("", styles["body"]),
         Paragraph("", styles["body"]), Paragraph("", styles["body"])],
        [Paragraph("RSSI", styles["body"]), Paragraph("", styles["body"]),
         Paragraph("", styles["body"]), Paragraph("", styles["body"])],
        [Paragraph("DSI", styles["body"]), Paragraph("", styles["body"]),
         Paragraph("", styles["body"]), Paragraph("", styles["body"])],
    ]
    t4 = Table(sig_rows, colWidths=[40 * mm, 50 * mm, 30 * mm, col_w - 120 * mm])
    t4.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_BG_HEAD),
        ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t4)

    doc.build(story)
    buf.seek(0)
    return buf


# ── Template 2 : Procédure de notification d'incident ────────────────────────

def generate_notification_procedure(result: AssessmentResult) -> io.BytesIO:
    """Génère la procédure de notification d'incident NIS 2 Art. 23."""
    buf = io.BytesIO()
    styles = _styles()
    org = result.organization_name
    date = datetime.now().strftime("%d/%m/%Y")

    def on_page(canvas, doc):
        _simple_page(canvas, doc, "Procédure de Notification d'Incident NIS 2", org, date)

    frame = Frame(MARGIN, MARGIN + 10 * mm, PAGE_W - 2 * MARGIN, PAGE_H - 2 * MARGIN - 24 * mm)
    tpl = PageTemplate(id="main", frames=[frame], onPage=on_page)
    doc = BaseDocTemplate(buf, pagesize=A4, pageTemplates=[tpl],
                          title=f"Notification d'incident NIS 2 — {org}", author="COMPASS")

    story = []
    col_w = PAGE_W - 2 * MARGIN
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Procédure de Notification d'Incident NIS 2", styles["title"]))
    story.append(Paragraph(f"Directive (UE) 2022/2555 — Art. 23 | {org} | {date}", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=6 * mm))

    # Objet
    story.append(Paragraph("1. Objet et champ d'application", styles["section"]))
    story.append(Paragraph(
        "Cette procédure définit le processus de détection, qualification et notification "
        "des incidents de cybersécurité significatifs conformément à l'Art. 23 de la directive NIS 2. "
        "Elle est applicable à tous les collaborateurs et prestataires de <b>" + org + "</b>.",
        styles["body"]))
    story.append(Spacer(1, 3 * mm))

    # Critères de significativité
    story.append(Paragraph("2. Critères de significativité d'un incident", styles["section"]))
    criteria = [
        ["Critère", "Seuil NIS 2", "Applicable ?"],
        ["Nombre d'utilisateurs affectés", "> 500 utilisateurs actifs", "☐ Oui  ☐ Non"],
        ["Indisponibilité des services", "> 6 heures consécutives", "☐ Oui  ☐ Non"],
        ["Perte financière", "> 500 000 €", "☐ Oui  ☐ Non"],
        ["Violation de données personnelles", "Toute violation significative", "☐ Oui  ☐ Non"],
        ["Systèmes critiques compromis", "Infrastructure essentielle", "☐ Oui  ☐ Non"],
        ["Impact supply chain", "Fournisseurs tiers affectés", "☐ Oui  ☐ Non"],
        ["Portée géographique", "Nationale ou transfrontalière", "☐ Oui  ☐ Non"],
    ]
    crit_rows = [[Paragraph(f"<b>{c}</b>" if i == 0 else c, styles["body_bold"] if i == 0 else styles["body"])
                  for c in row] for i, row in enumerate(criteria)]
    t = Table(crit_rows, colWidths=[65 * mm, 65 * mm, col_w - 130 * mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_BG_HEAD),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_ACCENT),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_LIGHT]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t)
    story.append(Spacer(1, 4 * mm))

    # Délais et obligations
    story.append(Paragraph("3. Délais réglementaires NIS 2 Art. 23", styles["section"]))
    deadlines = [
        ["Étape", "Délai", "Destinataire", "Contenu minimum"],
        ["Alerte initiale", "< 24h après détection", "ANSSI (CSIRT national)",
         "Nature de l'incident, impact estimé, mesures prises"],
        ["Rapport intermédiaire", "< 72h après détection", "ANSSI",
         "Évaluation initiale, indicateurs de compromission, statut"],
        ["Rapport final", "< 1 mois après résolution", "ANSSI",
         "Description complète, cause racine, mesures correctives"],
    ]
    dl_rows = [[Paragraph(f"<b>{c}</b>" if i == 0 else c,
                           styles["body_bold"] if i == 0 else styles["body"])
                for c in row] for i, row in enumerate(deadlines)]
    dl_colors = [None, C_RED, colors.HexColor("#F97316"), C_YELLOW]
    t2 = Table(dl_rows, colWidths=[30 * mm, 28 * mm, 35 * mm, col_w - 93 * mm], repeatRows=1)
    t2.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_BG_HEAD),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_ACCENT),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_LIGHT]),
    ]))
    for i, c in enumerate(dl_colors[1:], 1):
        if c:
            t2.setStyle(TableStyle([("LINEBEFORE", (0, i), (0, i), 3, c)]))
    story.append(t2)
    story.append(Spacer(1, 4 * mm))

    # Contacts
    story.append(Paragraph("4. Contacts et escalade", styles["section"]))
    contact_rows = [
        [Paragraph("<b>Rôle</b>", styles["body_bold"]), Paragraph("<b>Nom</b>", styles["body_bold"]),
         Paragraph("<b>Tél.</b>", styles["body_bold"]), Paragraph("<b>Email</b>", styles["body_bold"])],
        *[[Paragraph(r, styles["body"]), Paragraph("", styles["body"]),
           Paragraph("", styles["body"]), Paragraph("", styles["body"])]
          for r in ["RSSI", "DSI", "Direction Générale", "Juriste / DPO", "ANSSI CERT-FR"]],
    ]
    t3 = Table(contact_rows, colWidths=[38 * mm, 45 * mm, 30 * mm, col_w - 113 * mm])
    t3.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_BG_HEAD),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_LIGHT]),
    ]))
    story.append(t3)
    story.append(Spacer(1, 4 * mm))

    # Fiche de signalement
    story.append(Paragraph("5. Fiche de signalement d'incident (à compléter)", styles["section"]))
    fields = [
        ("Date/heure de détection", ""), ("Date/heure de notification ANSSI", ""),
        ("Référence interne de l'incident", ""), ("Systèmes affectés", ""),
        ("Impact estimé (utilisateurs, services)", ""), ("Cause supposée", ""),
        ("Mesures de containment prises", ""), ("Contact ANSSI (numéro de suivi)", ""),
    ]
    f_rows = [[Paragraph(label, styles["field_label"]),
               Paragraph(val or "________________________________________", styles["body"])]
              for label, val in fields]
    t4 = Table(f_rows, colWidths=[65 * mm, col_w - 65 * mm])
    t4.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BACKGROUND", (0, 0), (0, -1), C_LIGHT),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t4)

    doc.build(story)
    buf.seek(0)
    return buf


# ── Template 3 : Registre des actifs critiques ────────────────────────────────

def generate_asset_register(result: AssessmentResult) -> io.BytesIO:
    """Génère un registre des actifs critiques NIS 2 Art. 21."""
    buf = io.BytesIO()
    styles = _styles()
    org = result.organization_name
    date = datetime.now().strftime("%d/%m/%Y")

    def on_page(canvas, doc):
        _simple_page(canvas, doc, "Registre des Actifs Critiques NIS 2", org, date)

    frame = Frame(MARGIN, MARGIN + 10 * mm, PAGE_W - 2 * MARGIN, PAGE_H - 2 * MARGIN - 24 * mm)
    tpl = PageTemplate(id="main", frames=[frame], onPage=on_page)
    doc = BaseDocTemplate(buf, pagesize=A4, pageTemplates=[tpl],
                          title=f"Registre des actifs — {org}", author="COMPASS")

    story = []
    col_w = PAGE_W - 2 * MARGIN
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Registre des Actifs Critiques", styles["title"]))
    story.append(Paragraph(f"NIS 2 Art. 21 — Inventaire et classification | {org} | {date}", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=6 * mm))

    story.append(Paragraph("1. Objet", styles["section"]))
    story.append(Paragraph(
        "Ce registre recense les actifs informatiques critiques de <b>" + org + "</b> "
        "conformément aux exigences de l'Art. 21(2)(a) de NIS 2 (gestion des risques liés aux actifs). "
        "Il doit être maintenu à jour et révisé au minimum annuellement.",
        styles["body"]))
    story.append(Spacer(1, 3 * mm))

    # Grille de classification
    story.append(Paragraph("2. Grille de classification de la criticité", styles["section"]))
    class_rows = [
        ["Niveau", "Définition", "Exemples"],
        ["🔴 CRITIQUE", "Arrêt immédiat de l'activité si compromis", "Active Directory, ERP, SI de production"],
        ["🟠 ÉLEVÉ", "Impact majeur sur l'activité", "Messagerie, VPN, outils métier clés"],
        ["🟡 MODÉRÉ", "Impact limité, continuité possible", "Serveurs de développement, outils annexes"],
        ["🟢 FAIBLE", "Impact négligeable", "Postes non connectés aux SI critiques"],
    ]
    c_rows = [[Paragraph(c, styles["body_bold"] if i == 0 else styles["body"]) for c in row]
              for i, row in enumerate(class_rows)]
    t = Table(c_rows, colWidths=[28 * mm, 75 * mm, col_w - 103 * mm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_BG_HEAD),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_ACCENT),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_LIGHT]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)
    story.append(Spacer(1, 4 * mm))

    # Registre principal (lignes vides à remplir)
    story.append(Paragraph("3. Registre des actifs (à compléter)", styles["section"]))
    reg_header = ["Nom de l'actif", "Type", "Propriétaire", "Criticité", "Localisation",
                  "Date dernière revue", "NIS 2 applicable"]
    reg_rows = [[Paragraph(h, styles["body_bold"]) for h in reg_header]]
    # 15 lignes vides pré-formatées
    for _ in range(15):
        reg_rows.append([Paragraph("", styles["body"]) for _ in reg_header])

    col_ws = [38 * mm, 22 * mm, 28 * mm, 18 * mm, 26 * mm, 22 * mm, col_w - 154 * mm]
    t2 = Table(reg_rows, colWidths=col_ws, repeatRows=1)
    t2.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_BG_HEAD),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_ACCENT),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_LIGHT]),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(t2)
    story.append(Spacer(1, 4 * mm))

    # Domaines NIS 2 en lien avec les actifs
    story.append(Paragraph("4. Domaines NIS 2 à adresser selon les gaps identifiés", styles["section"]))
    engine = ScoringEngine()
    gaps = engine.generate_gap_analysis(result)
    if gaps:
        link_rows = [[Paragraph("<b>Actif concerné (à préciser)</b>", styles["body_bold"]),
                      Paragraph("<b>Gap NIS 2</b>", styles["body_bold"]),
                      Paragraph("<b>Action recommandée</b>", styles["body_bold"])]]
        for g in gaps[:8]:
            link_rows.append([
                Paragraph("", styles["body"]),
                Paragraph(f"<b>{g.requirement_id}</b> — {g.requirement_title}", styles["small"]),
                Paragraph(g.quick_win, styles["small"]),
            ])
        t3 = Table(link_rows, colWidths=[45 * mm, 60 * mm, col_w - 105 * mm], repeatRows=1)
        t3.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_BG_HEAD),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_ACCENT),
            ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_LIGHT]),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t3)

    doc.build(story)
    buf.seek(0)
    return buf
