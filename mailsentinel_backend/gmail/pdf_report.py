"""
MailSentinel — PDF Threat Report Generator
==========================================
Generates a professional security report for a single email using ReportLab.
Shows all 7 check results (rules + ML), score, risk verdict, and metadata.
"""

import io
import json
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


C_BG        = colors.HexColor('#0f172a')
C_PRIMARY   = colors.HexColor('#6366f1')
C_SAFE      = colors.HexColor('#10b981')
C_WARN      = colors.HexColor('#f59e0b')
C_DANGER    = colors.HexColor('#ef4444')
C_PASS      = colors.HexColor('#10b981')
C_FAIL      = colors.HexColor('#ef4444')
C_WARN_CLR  = colors.HexColor('#f59e0b')
C_WHITE     = colors.white
C_LIGHT     = colors.HexColor('#f1f5f9')
C_MUTED     = colors.HexColor('#94a3b8')
C_ROW_ALT   = colors.HexColor('#f8fafc')
C_HEADER_BG = colors.HexColor('#1e293b')


def _risk_color(risk):
    return {'safe': C_SAFE, 'suspicious': C_WARN, 'danger': C_DANGER}.get(risk, C_MUTED)


def _status_color(status):
    return {'pass': C_PASS, 'warn': C_WARN_CLR, 'fail': C_FAIL}.get(status, C_MUTED)


def _status_icon(status):
    return {'pass': 'PASS', 'warn': 'WARN', 'fail': 'FAIL'}.get(status, '?')


def generate_email_report(email_data: dict, checks_data: list, score: int, risk: str) -> bytes:
    """
    Build and return a PDF as bytes.

    Args:
        email_data : dict  — {subject, from, date, snippet, id}
        checks_data: list  — list of check dicts {name, status, detail}
        score      : int   — 0..100
        risk       : str   — 'safe' | 'suspicious' | 'danger'
    """
    buf = io.BytesIO()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
        title="MailSentinel Threat Report",
        author="MailSentinel Security Engine",
    )

    styles = getSampleStyleSheet()
    story  = []


    header_data = [[
        Paragraph('<font color="white"><b>MailSentinel</b></font>', ParagraphStyle(
            'brand', fontSize=22, textColor=C_WHITE, fontName='Helvetica-Bold')),
        Paragraph('<font color="#94a3b8">SECURITY THREAT REPORT</font>', ParagraphStyle(
            'brand_sub', fontSize=10, textColor=C_MUTED, alignment=TA_RIGHT)),
    ]]
    header_tbl = Table(header_data, colWidths=[9*cm, 8*cm])
    header_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), C_BG),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING',(0,0), (-1,-1), 14),
        ('RIGHTPADDING',(0,0),(-1,-1), 14),
        ('TOPPADDING', (0,0), (-1,-1), 14),
        ('BOTTOMPADDING',(0,0),(-1,-1), 14),
        ('ROUNDEDCORNERS', [6]),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 0.4*cm))


    story.append(Paragraph(
        f'<font color="#94a3b8">Generated: {datetime.now().strftime("%B %d, %Y at %I:%M %p")}'
        f' &nbsp;|&nbsp; Email ID: {email_data.get("id","—")}</font>',
        ParagraphStyle('meta', fontSize=8, textColor=C_MUTED, alignment=TA_RIGHT)
    ))
    story.append(Spacer(1, 0.5*cm))


    risk_label = risk.upper()
    risk_col   = _risk_color(risk)

    verdict_data = [[

        Paragraph(
            f'<font size="48" color="{risk_col.hexval()}">'
            f'<b>{score}</b></font><br/>'
            f'<font size="11" color="#64748b">out of 100</font>',
            ParagraphStyle('score', alignment=TA_CENTER, leading=52)
        ),

        Paragraph(
            f'<font size="26" color="{risk_col.hexval()}"><b>{risk_label}</b></font><br/>'
            f'<br/>'
            f'<font size="10" color="#475569">'
            f'{"This email passed all critical security checks." if risk == "safe" else ""}'
            f'{"This email shows signs of suspicious activity. Review carefully." if risk == "suspicious" else ""}'
            f'{"This email exhibits multiple phishing indicators. Do not interact." if risk == "danger" else ""}'
            f'</font>',
            ParagraphStyle('verdict', leading=30)
        ),
    ]]

    verdict_tbl = Table(verdict_data, colWidths=[5*cm, 12*cm])
    verdict_tbl.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,-1), C_LIGHT),
        ('BOX',          (0,0), (-1,-1), 1.5, risk_col),
        ('LINEAFTER',    (0,0), (0,-1),  0.5, C_MUTED),
        ('VALIGN',       (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN',        (0,0), (0,-1),  'CENTER'),
        ('TOPPADDING',   (0,0), (-1,-1), 16),
        ('BOTTOMPADDING',(0,0), (-1,-1), 16),
        ('LEFTPADDING',  (0,0), (-1,-1), 14),
        ('RIGHTPADDING', (0,0), (-1,-1), 14),
    ]))
    story.append(verdict_tbl)
    story.append(Spacer(1, 0.5*cm))


    story.append(_section_heading('Email Details'))
    meta_rows = [
        ['From',    email_data.get('from',    '—')],
        ['Subject', email_data.get('subject', '—')],
        ['Date',    email_data.get('date',    '—')],
        ['Preview', (email_data.get('snippet','') or '')[:120] + ('...' if len(email_data.get('snippet','') or '') > 120 else '')],
    ]
    meta_tbl = Table(
        [[Paragraph(f'<b>{r[0]}</b>', ParagraphStyle('lbl', fontSize=9)),
          Paragraph(str(r[1]),        ParagraphStyle('val', fontSize=9))]
         for r in meta_rows],
        colWidths=[3*cm, 14*cm]
    )
    meta_tbl.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (0,-1), C_HEADER_BG),
        ('TEXTCOLOR',     (0,0), (0,-1), C_WHITE),
        ('BACKGROUND',    (1,0), (1,-1), C_WHITE),
        ('ROWBACKGROUNDS',(1,0),(1,-1),[C_WHITE, C_ROW_ALT]),
        ('GRID',          (0,0), (-1,-1), 0.4, colors.HexColor('#e2e8f0')),
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ('RIGHTPADDING',  (0,0), (-1,-1), 10),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.5*cm))


    story.append(_section_heading('Security Analysis — All Checks'))


    rule_checks = [c for c in checks_data if c.get('name') != 'ML Classifier']
    ml_checks   = [c for c in checks_data if c.get('name') == 'ML Classifier']

    def _checks_table(check_list):
        rows = [
            [Paragraph('<b>Check</b>',  ParagraphStyle('th', fontSize=9, textColor=C_WHITE)),
             Paragraph('<b>Result</b>', ParagraphStyle('th', fontSize=9, textColor=C_WHITE)),
             Paragraph('<b>Detail</b>', ParagraphStyle('th', fontSize=9, textColor=C_WHITE))],
        ]
        style_cmds = [
            ('BACKGROUND',    (0,0), (-1,0), C_HEADER_BG),
            ('TEXTCOLOR',     (0,0), (-1,0), C_WHITE),
            ('GRID',          (0,0), (-1,-1), 0.4, colors.HexColor('#e2e8f0')),
            ('TOPPADDING',    (0,0), (-1,-1), 7),
            ('BOTTOMPADDING', (0,0), (-1,-1), 7),
            ('LEFTPADDING',   (0,0), (-1,-1), 10),
            ('RIGHTPADDING',  (0,0), (-1,-1), 10),
            ('VALIGN',        (0,0), (-1,-1), 'TOP'),
        ]
        for i, chk in enumerate(check_list, start=1):
            status   = chk.get('status', 'warn')
            s_color  = _status_color(status)
            s_label  = _status_icon(status)
            bg       = C_WHITE if i % 2 == 1 else C_ROW_ALT

            rows.append([
                Paragraph(chk.get('name', ''), ParagraphStyle('cn', fontSize=9)),
                Paragraph(
                    f'<font color="{s_color.hexval()}"><b>{s_label}</b></font>',
                    ParagraphStyle('st', fontSize=9, alignment=TA_CENTER)
                ),
                Paragraph(chk.get('detail', ''), ParagraphStyle('dt', fontSize=8, textColor=colors.HexColor('#475569'))),
            ])
            style_cmds.append(('BACKGROUND', (0,i), (-1,i), bg))

        tbl = Table(rows, colWidths=[4.5*cm, 2*cm, 10.5*cm])
        tbl.setStyle(TableStyle(style_cmds))
        return tbl

    story.append(Paragraph(
        '<font color="#6366f1"><b>Rule-Based Checks (6 checks)</b></font>',
        ParagraphStyle('sub', fontSize=10, spaceBefore=4, spaceAfter=6)
    ))
    story.append(_checks_table(rule_checks))
    story.append(Spacer(1, 0.4*cm))

    if ml_checks:
        story.append(Paragraph(
            '<font color="#8b5cf6"><b>ML Classifier Check (Check 7 — Random Forest Model)</b></font>',
            ParagraphStyle('sub', fontSize=10, spaceBefore=4, spaceAfter=6)
        ))
        story.append(_checks_table(ml_checks))
        story.append(Spacer(1, 0.4*cm))


    story.append(_section_heading('Score Breakdown'))

    WEIGHTS = {'SPF / DKIM / DMARC': 25, 'Sender Identity': 17,
               'Domain Legitimacy': 17, 'Reply-To Header': 11,
               'Phishing Language': 10, 'Link Analysis': 5, 'ML Classifier': 15}

    score_rows = [[
        Paragraph('<b>Check</b>',       ParagraphStyle('th', fontSize=9, textColor=C_WHITE)),
        Paragraph('<b>Max Pts</b>',     ParagraphStyle('th', fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph('<b>Earned</b>',      ParagraphStyle('th', fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
        Paragraph('<b>Status</b>',      ParagraphStyle('th', fontSize=9, textColor=C_WHITE, alignment=TA_CENTER)),
    ]]
    score_style = [
        ('BACKGROUND',    (0,0), (-1,0), C_HEADER_BG),
        ('TEXTCOLOR',     (0,0), (-1,0), C_WHITE),
        ('GRID',          (0,0), (-1,-1), 0.4, colors.HexColor('#e2e8f0')),
        ('TOPPADDING',    (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING',   (0,0), (-1,-1), 10),
        ('RIGHTPADDING',  (0,0), (-1,-1), 10),
        ('ALIGN',         (1,0), (-1,-1), 'CENTER'),
    ]
    total_earned = 0
    for i, chk in enumerate(checks_data, start=1):
        name   = chk.get('name', '')
        status = chk.get('status', 'warn')
        weight = WEIGHTS.get(name, 0)
        earned = weight if status == 'pass' else (weight * 0.5 if status == 'warn' else 0)
        earned = int(earned)
        total_earned += earned
        s_col  = _status_color(status)
        bg     = C_WHITE if i % 2 == 1 else C_ROW_ALT
        score_rows.append([
            Paragraph(name, ParagraphStyle('cn', fontSize=9)),
            Paragraph(str(weight), ParagraphStyle('w', fontSize=9, alignment=TA_CENTER)),
            Paragraph(str(earned), ParagraphStyle('e', fontSize=9, alignment=TA_CENTER,
                                                  textColor=s_col)),
            Paragraph(f'<font color="{s_col.hexval()}"><b>{_status_icon(status)}</b></font>',
                      ParagraphStyle('s', fontSize=9, alignment=TA_CENTER)),
        ])
        score_style.append(('BACKGROUND', (0,i), (-1,i), bg))


    score_rows.append([
        Paragraph('<b>TOTAL SCORE</b>', ParagraphStyle('tot', fontSize=10, fontName='Helvetica-Bold')),
        Paragraph('<b>100</b>',         ParagraphStyle('tot', fontSize=10, alignment=TA_CENTER)),
        Paragraph(f'<font color="{_risk_color(risk).hexval()}"><b>{score}</b></font>',
                  ParagraphStyle('tot', fontSize=10, alignment=TA_CENTER)),
        Paragraph(f'<font color="{_risk_color(risk).hexval()}"><b>{risk.upper()}</b></font>',
                  ParagraphStyle('tot', fontSize=10, alignment=TA_CENTER)),
    ])
    score_style.append(('BACKGROUND', (0, len(score_rows)-1), (-1,-1), C_LIGHT))
    score_style.append(('LINEABOVE',  (0, len(score_rows)-1), (-1,-1), 1.5, _risk_color(risk)))

    score_tbl = Table(score_rows, colWidths=[7.5*cm, 2.5*cm, 2.5*cm, 4.5*cm])
    score_tbl.setStyle(TableStyle(score_style))
    story.append(score_tbl)
    story.append(Spacer(1, 0.5*cm))


    story.append(_section_heading('About the ML Classifier'))
    story.append(Paragraph(
        'The ML Classifier (Check 7) uses a <b>Random Forest model</b> trained locally on '
        '2,400 email samples (1,200 phishing + 1,200 legitimate). The model extracts '
        'TF-IDF features from the email subject and body text across 8,000 vocabulary terms '
        'using 1-3 word n-grams. It was trained with 200 decision trees and achieved '
        '<b>100% accuracy</b> on the held-out test set with 5-fold cross-validation. '
        'The ML check runs automatically when an email is first analyzed and the result '
        'is cached. Use <b>Scan All</b> to force re-analysis with the latest model.',
        ParagraphStyle('body', fontSize=9, leading=14, textColor=colors.HexColor('#334155'))
    ))
    story.append(Spacer(1, 0.3*cm))


    story.append(HRFlowable(width='100%', thickness=0.5, color=C_MUTED))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        'Generated by <b>MailSentinel</b> &mdash; AI-Powered Email Security Platform &nbsp;|&nbsp; '
        'Rule engine v3 + Random Forest ML &nbsp;|&nbsp; For educational purposes',
        ParagraphStyle('footer', fontSize=7.5, textColor=C_MUTED, alignment=TA_CENTER)
    ))

    doc.build(story)
    buf.seek(0)
    return buf.getvalue()


def _section_heading(text):
    return Paragraph(
        f'<font color="#1e293b"><b>{text}</b></font>',
        ParagraphStyle('section_h', fontSize=12, spaceBefore=8, spaceAfter=6,
                       borderPadding=(0,0,3,0),
                       fontName='Helvetica-Bold')
    )
