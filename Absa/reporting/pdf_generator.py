"""
ABSA PDF Report Generator
Takes the structured dict from ReportBuilder and produces a professional
multi-page PDF using ReportLab. Includes vector bar charts, colored severity
badges, monospace code blocks, evidence panels, page headers/footers,
table of contents, and a cover page.

Supports two calling conventions:
  1. generate(data=report_dict)                             -- full pipeline mode
  2. generate(findings=..., context=..., output_path=...)    -- main menu shortcut

Works with dataclass-based models from core.models where Severity enum
values are lowercase ("critical", "high", etc.).
"""

import os
from datetime import datetime
from typing import Dict, Any, List, Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, HRFlowable,
)
from reportlab.platypus.flowables import Flowable

from utils.logger import get_logger

logger = get_logger("reporting.pdf")

try:
    import config as _cfg
    REPORT_DIR = getattr(_cfg, "REPORT_DIR", "reports")
except ImportError:
    REPORT_DIR = "reports"

PAGE_W, PAGE_H = A4
MARGIN_L = 20 * mm
MARGIN_R = 20 * mm
MARGIN_T = 25 * mm
MARGIN_B = 25 * mm
CONTENT_W = PAGE_W - MARGIN_L - MARGIN_R

SEVERITY_COLORS = {
    "Critical": HexColor("#CC0000"),
    "High": HexColor("#E67E22"),
    "Medium": HexColor("#F1C40F"),
    "Low": HexColor("#3498DB"),
    "Info": HexColor("#95A5A6"),
}
SEVERITY_BG = {
    "Critical": HexColor("#FDECEA"),
    "High": HexColor("#FDF2E9"),
    "Medium": HexColor("#FEF9E7"),
    "Low": HexColor("#EBF5FB"),
    "Info": HexColor("#F2F3F4"),
}
RISK_COLORS = {
    "CRITICAL": HexColor("#CC0000"),
    "HIGH": HexColor("#E67E22"),
    "MEDIUM": HexColor("#F1C40F"),
    "LOW": HexColor("#3498DB"),
    "INFORMATIONAL": HexColor("#95A5A6"),
}

_C = {
    "primary": HexColor("#006633"),
    "text": HexColor("#2C3E50"),
    "text_light": HexColor("#7F8C8D"),
}


class ColoredBox(Flowable):
    def __init__(self, text, width, height, bg_color, text_color=white,
                 font_name="Helvetica-Bold", font_size=11):
        Flowable.__init__(self)
        self.text = text
        self.bw = width
        self.bh = height
        self.bg = bg_color
        self.tc = text_color
        self.fn = font_name
        self.fs = font_size

    def wrap(self, aW, aH):
        return self.bw, self.bh

    def draw(self):
        self.canv.setFillColor(self.bg)
        self.canv.roundRect(0, 0, self.bw, self.bh, 3, fill=1, stroke=0)
        self.canv.setFillColor(self.tc)
        self.canv.setFont(self.fn, self.fs)
        self.canv.drawCentredString(self.bw / 2, (self.bh - self.fs) / 2 + 1, self.text)


class CodeBlock(Flowable):
    def __init__(self, code, width, font_size=7):
        Flowable.__init__(self)
        self.code = code
        self.bw = width
        self.fs = font_size
        self._lines = code.split("\n")
        self.lh = font_size * 1.5
        self.pad = 8

    def wrap(self, aW, aH):
        return self.bw, len(self._lines) * self.lh + self.pad * 2

    def draw(self):
        h = len(self._lines) * self.lh + self.pad * 2
        self.canv.setFillColor(HexColor("#F4F6F7"))
        self.canv.roundRect(0, 0, self.bw, h, 4, fill=1, stroke=0)
        self.canv.setFillColor(HexColor("#BDC3C7"))
        self.canv.rect(0, 0, 3, h, fill=1, stroke=0)
        self.canv.setFillColor(HexColor("#2C3E50"))
        self.canv.setFont("Courier", self.fs)
        y = h - self.pad - self.fs
        for line in self._lines:
            if y < 0:
                break
            self.canv.drawString(self.pad + 6, y, line[:110])
            y -= self.lh


class EvidenceBlock(Flowable):
    def __init__(self, text, width, font_size=7):
        Flowable.__init__(self)
        self.text = text
        self.bw = width
        self.fs = font_size
        self._lines = text.split("\n")
        self.lh = font_size * 1.5
        self.pad = 8

    def wrap(self, aW, aH):
        return self.bw, min(len(self._lines) * self.lh + self.pad * 2, 280)

    def draw(self):
        h = self.wrap(self.bw, 1000)[1]
        self.canv.setFillColor(HexColor("#EBF5FB"))
        self.canv.roundRect(0, 0, self.bw, h, 4, fill=1, stroke=0)
        self.canv.setFillColor(HexColor("#1A5276"))
        self.canv.rect(0, 0, 3, h, fill=1, stroke=0)
        self.canv.setFont("Courier", self.fs)
        y = h - self.pad - self.fs
        for line in self._lines:
            if y < 4:
                self.canv.drawString(self.pad + 6, y, "... [truncated]")
                break
            self.canv.drawString(self.pad + 6, y, line[:110])
            y -= self.lh


class SeverityChart(Flowable):
    def __init__(self, data, width, height=120):
        Flowable.__init__(self)
        self.data = data
        self.cw = width
        self.ch = height

    def wrap(self, aW, aH):
        return self.cw, self.ch + 10

    def draw(self):
        c = self.canv
        cats = ["Critical", "High", "Medium", "Low", "Info"]
        vals = [self.data.get(cat, 0) for cat in cats]
        mx = max(vals) if max(vals) > 0 else 1
        bw = self.cw - 85
        bh, gap = 16, 7
        sy = self.ch
        for i, (cat, val) in enumerate(zip(cats, vals)):
            y = sy - i * (bh + gap)
            c.setFillColor(HexColor("#2C3E50"))
            c.setFont("Helvetica-Bold", 8)
            c.drawRightString(78, y + 3, cat)
            c.setFillColor(HexColor("#ECF0F1"))
            c.roundRect(83, y, bw, bh, 3, fill=1, stroke=0)
            w = (val / mx) * bw
            if w > 0:
                c.setFillColor(SEVERITY_COLORS.get(cat, HexColor("#95A5A6")))
                c.roundRect(83, y, max(w, 5), bh, 3, fill=1, stroke=0)
            c.setFillColor(HexColor("#2C3E50"))
            c.setFont("Helvetica-Bold", 9)
            c.drawString(88 + w + 5, y + 3, str(val))


class CategoryChart(Flowable):
    def __init__(self, data, width, height=140):
        Flowable.__init__(self)
        self.data = data
        self.cw = width
        self.ch = height

    def wrap(self, aW, aH):
        return self.cw, self.ch + 10

    def draw(self):
        c = self.canv
        cats = list(self.data.keys())[:8]
        vals = [self.data.get(cat, 0) for cat in cats]
        mx = max(vals) if max(vals) > 0 else 1
        bw = self.cw - 115
        bh, gap = 13, 4
        sy = self.ch
        colors = [
            HexColor("#E74C3C"), HexColor("#E67E22"), HexColor("#F39C12"),
            HexColor("#27AE60"), HexColor("#2980B9"), HexColor("#8E44AD"),
            HexColor("#1ABC9C"), HexColor("#95A5A6"),
        ]
        for i, (cat, val) in enumerate(zip(cats, vals)):
            y = sy - i * (bh + gap)
            c.setFillColor(HexColor("#2C3E50"))
            c.setFont("Helvetica", 7)
            lbl = cat[:20] + ("..." if len(cat) > 20 else "")
            c.drawRightString(108, y + 2, lbl)
            c.setFillColor(HexColor("#ECF0F1"))
            c.roundRect(113, y, bw, bh, 2, fill=1, stroke=0)
            w = (val / mx) * bw
            if w > 0:
                c.setFillColor(colors[i % len(colors)])
                c.roundRect(113, y, max(w, 4), bh, 2, fill=1, stroke=0)
            c.setFillColor(HexColor("#2C3E50"))
            c.setFont("Helvetica-Bold", 8)
            c.drawString(118 + w + 4, y + 2, str(val))


def _styles():
    s = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "T1", parent=s["Title"], fontName="Helvetica-Bold",
            fontSize=22, textColor=_C["text"], alignment=TA_CENTER,
            spaceAfter=4 * mm,
        ),
        "subtitle": ParagraphStyle(
            "T2", parent=s["Normal"], fontName="Helvetica",
            fontSize=11, textColor=_C["text_light"], alignment=TA_CENTER,
            spaceAfter=2 * mm,
        ),
        "h1": ParagraphStyle(
            "H1", parent=s["Heading1"], fontName="Helvetica-Bold",
            fontSize=16, textColor=_C["primary"], spaceBefore=6 * mm,
            spaceAfter=3 * mm,
        ),
        "h2": ParagraphStyle(
            "H2", parent=s["Heading2"], fontName="Helvetica-Bold",
            fontSize=13, textColor=_C["text"], spaceBefore=4 * mm,
            spaceAfter=2 * mm,
        ),
        "h3": ParagraphStyle(
            "H3", parent=s["Heading3"], fontName="Helvetica-Bold",
            fontSize=10, textColor=_C["text"], spaceBefore=3 * mm,
            spaceAfter=1.5 * mm,
        ),
        "body": ParagraphStyle(
            "B1", parent=s["Normal"], fontName="Helvetica", fontSize=9,
            textColor=_C["text"], leading=13, spaceAfter=2 * mm,
            alignment=TA_JUSTIFY,
        ),
        "mono": ParagraphStyle(
            "M1", parent=s["Normal"], fontName="Courier", fontSize=7.5,
            textColor=_C["text"], leading=10, spaceAfter=1 * mm,
        ),
        "label": ParagraphStyle(
            "L1", parent=s["Normal"], fontName="Helvetica-Bold",
            fontSize=8, textColor=_C["text_light"], spaceAfter=1 * mm,
        ),
        "center": ParagraphStyle(
            "C1", parent=s["Normal"], fontName="Helvetica", fontSize=9,
            textColor=_C["text"], alignment=TA_CENTER, spaceAfter=2 * mm,
        ),
        "disclaimer": ParagraphStyle(
            "D1", parent=s["Normal"], fontName="Helvetica",
            fontSize=7.5, textColor=_C["text_light"], leading=10,
            spaceAfter=1.5 * mm, alignment=TA_JUSTIFY,
        ),
        "toc": ParagraphStyle(
            "TOC1", parent=s["Normal"], fontName="Helvetica", fontSize=10,
            textColor=_C["text"], leading=18,
        ),
        "toc_sub": ParagraphStyle(
            "TOC2", parent=s["Normal"], fontName="Helvetica",
            fontSize=9, textColor=_C["text_light"], leading=16,
            leftIndent=15,
        ),
    }


def _header_footer(canvas_obj, doc):
    canvas_obj.saveState()
    canvas_obj.setStrokeColor(HexColor("#006633"))
    canvas_obj.setLineWidth(1.5)
    canvas_obj.line(MARGIN_L, PAGE_H - 15 * mm, PAGE_W - MARGIN_R, PAGE_H - 15 * mm)
    canvas_obj.setFont("Helvetica-Bold", 7)
    canvas_obj.setFillColor(HexColor("#006633"))
    canvas_obj.drawString(MARGIN_L, PAGE_H - 13 * mm, "ABSA - Security Assessment Report")
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.setFillColor(HexColor("#7F8C8D"))
    canvas_obj.drawRightString(PAGE_W - MARGIN_R, PAGE_H - 13 * mm, "CONFIDENTIAL")
    canvas_obj.setStrokeColor(HexColor("#BDC3C7"))
    canvas_obj.setLineWidth(0.5)
    canvas_obj.line(MARGIN_L, 15 * mm, PAGE_W - MARGIN_R, 15 * mm)
    canvas_obj.setFont("Helvetica", 7)
    canvas_obj.setFillColor(HexColor("#95A5A6"))
    session_id = getattr(doc, "session_id", "")
    canvas_obj.drawString(MARGIN_L, 10 * mm, session_id)
    canvas_obj.drawRightString(PAGE_W - MARGIN_R, 10 * mm, f"Page {doc.page}")
    canvas_obj.restoreState()


def _cover_page(canvas_obj, doc):
    canvas_obj.saveState()
    canvas_obj.setFillColor(HexColor("#006633"))
    canvas_obj.rect(0, PAGE_H - 60 * mm, PAGE_W, 60 * mm, fill=1, stroke=0)
    canvas_obj.setFont("Helvetica-Bold", 24)
    canvas_obj.setFillColor(white)
    canvas_obj.drawCentredString(PAGE_W / 2, PAGE_H - 25 * mm, "Automated Banking")
    canvas_obj.drawCentredString(PAGE_W / 2, PAGE_H - 33 * mm, "Security Auditor")
    canvas_obj.setFont("Helvetica", 12)
    canvas_obj.setFillColor(HexColor("#A9DFBF"))
    canvas_obj.drawCentredString(PAGE_W / 2, PAGE_H - 42 * mm,
                                  "A Zero-Day-Aware Testing Framework")
    canvas_obj.setFont("Helvetica-Bold", 10)
    canvas_obj.setFillColor(HexColor("#2C3E50"))
    canvas_obj.drawCentredString(PAGE_W / 2, 100 * mm,
                                  getattr(doc, "report_title", "Security Assessment Report"))
    canvas_obj.setFont("Helvetica", 9)
    canvas_obj.setFillColor(HexColor("#7F8C8D"))
    meta = getattr(doc, "cover_meta", {})
    canvas_obj.drawCentredString(PAGE_W / 2, 88 * mm,
                                  f"Target: {meta.get('target_url', 'N/A')}")
    canvas_obj.drawCentredString(PAGE_W / 2, 83 * mm,
                                  f"Date: {meta.get('date', 'N/A')}")
    canvas_obj.drawCentredString(PAGE_W / 2, 78 * mm,
                                  f"Session: {meta.get('session_id', 'N/A')}")
    canvas_obj.setFillColor(HexColor("#CC0000"))
    canvas_obj.roundRect(PAGE_W / 2 - 50 * mm, 60 * mm, 100 * mm, 10 * mm,
                          3, fill=1, stroke=0)
    canvas_obj.setFont("Helvetica-Bold", 11)
    canvas_obj.setFillColor(white)
    canvas_obj.drawCentredString(PAGE_W / 2, 62.5 * mm,
                                  "CONFIDENTIAL - Authorized Distribution Only")
    canvas_obj.restoreState()


class PDFGenerator:
    """Generates the multi-page PDF assessment report."""

    def __init__(self, context=None):
        self.ctx = context
        self.styles = _styles()
        self.output_path = ""

    def generate(self, data=None, findings=None, context=None,
                 output_path=None) -> str:
        if data is None and findings is not None:
            ctx = context or self.ctx

            if ctx is None:
                logger.error("generate() called with findings but no context")
                raise ValueError("Either data dict or context+findings required")

            try:
                from reporting.report_builder import ReportBuilder
                builder = ReportBuilder(ctx)
                original_findings = list(ctx.findings) if hasattr(ctx, "findings") else []
                ctx.findings = list(findings)
                data = builder.build()
                ctx.findings = original_findings
                logger.info("Report data built from %d findings", len(findings))
            except Exception as exc:
                logger.error("ReportBuilder failed: %s", exc, exc_info=True)
                raise

            if output_path is None:
                output_path = self._default_path(ctx)

        elif data is not None:
            if output_path is None:
                ctx_for_path = self.ctx
                if ctx_for_path is None:
                    try:
                        from core.models import ScanContext
                        target = data.get("metadata", {}).get("target_url", "unknown")
                        ctx_for_path = ScanContext(target_url=target)
                    except Exception:
                        ctx_for_path = None
                output_path = self._default_path(ctx_for_path)

        else:
            raise ValueError("Either data dict or findings list required")

        if not isinstance(data, dict):
            logger.error("data is not a dict: %s", type(data))
            raise ValueError("Report data must be a dictionary")

        data.setdefault("metadata", {})
        data.setdefault("executive_summary", "No summary available.")
        data.setdefault("severity_distribution", {})
        data.setdefault("category_breakdown", {})
        data.setdefault("risk_rating", "INFORMATIONAL")
        data.setdefault("phase_results", [])
        data.setdefault("findings", [])
        data.setdefault("zeroday_findings", [])
        data.setdefault("compliance_summary", {})
        data.setdefault("stealth_info", "Not configured.")
        data.setdefault("disclaimer", "")
        data.setdefault("title", "ABSA Security Report")
        data.setdefault("generated_at", datetime.utcnow().isoformat() + "Z")

        out_dir = os.path.dirname(output_path)
        if out_dir and not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)

        logger.info("Building PDF: %s", output_path)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=MARGIN_L,
            rightMargin=MARGIN_R,
            topMargin=MARGIN_T,
            bottomMargin=MARGIN_B,
            title=data.get("title", "ABSA Report"),
            author="Automated Banking Security Auditor",
        )

        doc.session_id = data.get("metadata", {}).get("session_id", "")
        doc.report_title = data.get("title", "")
        doc.cover_meta = {
            "target_url": data.get("metadata", {}).get("target_url", ""),
            "date": data.get("generated_at", "")[:10],
            "session_id": doc.session_id,
        }

        elements = []

        elements.append(Spacer(1, 140 * mm))
        elements.append(PageBreak())

        elements.extend(self._build_toc(data))
        elements.append(PageBreak())

        elements.extend(self._build_exec_summary(data))
        elements.extend(self._build_charts(data))
        elements.append(PageBreak())

        elements.extend(self._build_phases(data))
        elements.append(PageBreak())

        elements.extend(self._build_findings(data))

        if data.get("zeroday_findings"):
            elements.append(PageBreak())
            elements.extend(self._build_zeroday(data))

        if data.get("compliance_summary"):
            elements.append(PageBreak())
            elements.extend(self._build_compliance(data))

        elements.append(PageBreak())
        elements.extend(self._build_stealth(data))

        elements.append(Spacer(1, 10 * mm))
        elements.extend(self._build_disclaimer(data))

        try:
            doc.build(
                elements,
                onFirstPage=_cover_page,
                onLaterPages=_header_footer,
            )
            self.output_path = output_path
            logger.info("PDF saved successfully: %s", output_path)
            return output_path
        except Exception as exc:
            logger.error("PDF build failed: %s", exc, exc_info=True)
            raise

    def _default_path(self, ctx) -> str:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        if ctx is not None:
            domain = getattr(ctx, "target_domain", "target") or "target"
        else:
            domain = "target"
        filename = f"ABSA_Report_{domain}_{ts}.pdf"
        return os.path.join(REPORT_DIR, filename)

    def _build_toc(self, data):
        s = self.styles
        has_zd = bool(data.get("zeroday_findings"))
        has_comp = bool(data.get("compliance_summary"))
        return [
            Paragraph("Table of Contents", s["h1"]),
            Spacer(1, 3 * mm),
            Paragraph("1.  Executive Summary", s["toc"]),
            Paragraph("2.  Risk & Severity Charts", s["toc"]),
            Paragraph("3.  Phase Results", s["toc"]),
            Paragraph("4.  Detailed Findings", s["toc"]),
            Paragraph("5.  Zero-Day Appendix",
                      s["toc"] if has_zd else s["toc_sub"]),
            Paragraph("6.  Compliance Mapping",
                      s["toc"] if has_comp else s["toc_sub"]),
            Paragraph("7.  Stealth Methodology", s["toc"]),
            Paragraph("8.  Disclaimer", s["toc"]),
        ]

    def _build_exec_summary(self, data):
        s = self.styles
        text = data.get("executive_summary", "")
        text = text.replace("{", "").replace("}", "")
        text = text.replace("\n\n\n", "\n\n")

        risk = data.get("risk_rating", "INFORMATIONAL")
        rc = RISK_COLORS.get(risk, HexColor("#95A5A6"))

        elems = [
            Paragraph("1. Executive Summary", s["h1"]),
            Spacer(1, 2 * mm),
            ColoredBox(f"Overall Risk Rating: {risk}", CONTENT_W, 12 * mm, rc),
            Spacer(1, 4 * mm),
        ]
        for para in text.split("\n\n"):
            if para.strip():
                safe = self._esc(para.strip())
                safe = safe.replace("\n", "<br/>")
                elems.append(Paragraph(safe, s["body"]))
                elems.append(Spacer(1, 1 * mm))
        return elems

    def _build_charts(self, data):
        s = self.styles
        return [
            Paragraph("2. Risk & Severity Analysis", s["h1"]),
            Spacer(1, 2 * mm),
            Paragraph("Severity Distribution", s["h2"]),
            SeverityChart(data.get("severity_distribution", {}), CONTENT_W),
            Spacer(1, 5 * mm),
            Paragraph("Category Breakdown", s["h2"]),
            CategoryChart(data.get("category_breakdown", {}), CONTENT_W),
        ]

    def _build_phases(self, data):
        s = self.styles
        phases = data.get("phase_results", [])
        table_data = [["Phase", "Status", "Duration", "Findings", "Details"]]
        for p in phases:
            status = p.get("status", "UNKNOWN")
            if status == "COMPLETE":
                status_color = "#27AE60"
            elif status == "SKIPPED":
                status_color = "#E67E22"
            else:
                status_color = "#CC0000"
            status_cell = f'<font color="{status_color}"><b>{status}</b></font>'
            table_data.append([
                p.get("name", ""),
                status_cell,
                p.get("duration", "N/A"),
                str(p.get("finding_count", 0)),
                (p.get("stats_str") or "N/A")[:50],
            ])

        t = Table(table_data, colWidths=[55*mm, 20*mm, 18*mm, 16*mm, 55*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#006633")),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#BDC3C7")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, HexColor("#F8F9F9")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return [
            Paragraph("3. Phase Results", s["h1"]),
            Spacer(1, 2 * mm),
            t,
        ]

    def _build_findings(self, data):
        s = self.styles
        findings = data.get("findings", [])
        if not findings:
            return [
                Paragraph("4. Detailed Findings", s["h1"]),
                Paragraph("No vulnerabilities were identified during this assessment.", s["body"]),
            ]

        elems = [
            Paragraph(f"4. Detailed Findings ({len(findings)} total)", s["h1"]),
            Spacer(1, 2 * mm),
        ]

        for f in findings:
            sev = f.get("severity", "Info")
            badge_w = max(len(sev) * 6 + 10, 45)
            sev_bg = SEVERITY_BG.get(sev, HexColor("#F2F3F4"))
            sev_fg = SEVERITY_COLORS.get(sev, HexColor("#95A5A6"))
            if sev == "Medium":
                sev_fg = HexColor("#7D6608")

            block = [
                ColoredBox(sev, badge_w, 7*mm, sev_bg, sev_fg, "Helvetica-Bold", 8),
            ]

            title_data = [[
                Paragraph(f'<b>{self._esc(f.get("title", ""))}</b>', s["h3"]),
                Paragraph(
                    f'CVSS: <b>{f.get("cvss_score", 0)}</b>  |  '
                    f'CWE: {self._esc(f.get("cwe_id", "N/A"))}  |  '
                    f'{self._esc(f.get("finding_type", ""))}',
                    s["label"]
                ),
            ]]
            tt = Table(title_data, colWidths=[CONTENT_W - badge_w - 5*mm, 55*mm])
            tt.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ]))
            block.append(tt)
            block.append(Spacer(1, 2 * mm))

            rendered = f.get("rendered_text", "")
            for part in rendered.split("\n\n"):
                part = part.strip()
                if not part:
                    continue
                if part.startswith("EVIDENCE:"):
                    block.append(Paragraph("Evidence:", s["label"]))
                    block.append(EvidenceBlock(
                        self._esc(part.replace("EVIDENCE:", "").strip()), CONTENT_W
                    ))
                elif part.startswith("REMEDIATION CODE:"):
                    code = part.replace("REMEDIATION CODE:", "").strip()
                    if code and code != "No additional findings in this category.":
                        block.append(Paragraph("Remediation Code:", s["label"]))
                        block.append(CodeBlock(self._esc(code), CONTENT_W))
                elif part.startswith("REPRODUCTION STEPS:"):
                    safe_text = self._esc(part.replace("\n", "<br/>"))
                    block.append(Paragraph(safe_text, s["body"]))
                elif part.startswith("KNOWN CVE") or part.startswith("COMPLIANCE"):
                    safe_text = self._esc(part.replace("\n", "<br/>"))
                    block.append(Paragraph(safe_text, s["body"]))
                else:
                    safe_text = self._esc(part.replace("\n", "<br/>"))
                    block.append(Paragraph(safe_text, s["body"]))

            block.append(Spacer(1, 2 * mm))
            block.append(HRFlowable(
                width=CONTENT_W, color=HexColor("#BDC3C7"), thickness=0.5
            ))
            elems.append(KeepTogether(block))

        return elems

    def _build_zeroday(self, data):
        s = self.styles
        zds = data.get("zeroday_findings", [])
        elems = [
            Paragraph("5. Zero-Day Appendix", s["h1"]),
            Spacer(1, 2 * mm),
            ColoredBox(
                f"{len(zds)} Potential Zero-Day Vulnerability(ies)",
                CONTENT_W, 12 * mm,
                HexColor("#CC0000"), white, "Helvetica-Bold", 10,
            ),
            Spacer(1, 4 * mm),
        ]
        for zd in zds:
            text = zd.get("rendered_text", "")
            for part in text.split("\n\n"):
                part = part.strip()
                if not part:
                    continue
                if part.startswith("PROOF-OF-CONCEPT:"):
                    elems.append(Paragraph("Proof-of-Concept:", s["label"]))
                    elems.append(EvidenceBlock(
                        self._esc(part.replace("PROOF-OF-CONCEPT:", "").strip()),
                        CONTENT_W
                    ))
                elif part.startswith("PROPOSED CODE FIX:"):
                    code = part.replace("PROPOSED CODE FIX:", "").strip()
                    if code and code != "No additional findings in this category.":
                        elems.append(Paragraph("Proposed Code Fix:", s["label"]))
                        elems.append(CodeBlock(self._esc(code), CONTENT_W))
                elif part.startswith("DISCLOSURE"):
                    safe = self._esc(part.replace("\n", "<br/>"))
                    elems.append(Paragraph(safe, s["disclaimer"]))
                else:
                    safe = self._esc(part.replace("\n", "<br/>"))
                    elems.append(Paragraph(safe, s["body"]))
            elems.append(Spacer(1, 3 * mm))
        return elems

    def _build_compliance(self, data):
        s = self.styles
        comp = data.get("compliance_summary", {})
        if not comp:
            return [
                Paragraph("6. Compliance Mapping", s["h1"]),
                Paragraph("No compliance mappings were identified.", s["body"]),
            ]
        elems = [
            Paragraph("6. Compliance Mapping", s["h1"]),
            Spacer(1, 2 * mm),
        ]
        for fw, clauses in comp.items():
            elems.append(Paragraph(f"<b>{self._esc(fw)}</b>", s["h2"]))
            table_data = [["Clause", "Title", "Finding", "Severity", "CVSS"]]
            for cl in clauses:
                table_data.append([
                    self._esc(cl.get("clause_id", "")),
                    self._esc(cl.get("clause_title", "")),
                    self._esc(cl.get("finding_title", "")[:40]),
                    self._esc(cl.get("severity", "")),
                    str(cl.get("cvss", 0)),
                ])
            t = Table(table_data, colWidths=[18*mm, 30*mm, 50*mm, 18*mm, 14*mm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2C3E50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#BDC3C7")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, HexColor("#F8F9F9")]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            elems.append(t)
            elems.append(Spacer(1, 3 * mm))
        return elems

    def _build_stealth(self, data):
        s = self.styles
        text = data.get("stealth_info", "Stealth was not enabled.")
        if isinstance(text, dict):
            text = text.get("rendered_text", str(text))
        safe = self._esc(str(text).replace("\n", "<br/>"))
        return [
            Paragraph("7. Stealth Methodology", s["h1"]),
            Spacer(1, 2 * mm),
            Paragraph(safe, s["body"]),
        ]

    def _build_disclaimer(self, data):
        s = self.styles
        text = data.get("disclaimer", "")
        safe = self._esc(text.replace("\n", "<br/>"))
        return [
            HRFlowable(width=CONTENT_W, color=HexColor("#CC0000"), thickness=1),
            Spacer(1, 3 * mm),
            Paragraph("8. Disclaimer & Responsible Disclosure", s["h1"]),
            Spacer(1, 2 * mm),
            Paragraph(safe, s["disclaimer"]),
        ]

    @staticmethod
    def _esc(text: str) -> str:
        """Escape XML-special characters for ReportLab Paragraph."""
        if not text:
            return ""
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")
        return text