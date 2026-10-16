"""Generate a downloadable PDF from the canonical Markdown report."""

from __future__ import annotations

import html
import io
from pathlib import Path
from urllib.parse import urlsplit

from markdown_it import MarkdownIt
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import HRFlowable, LongTable, Paragraph, Preformatted, SimpleDocTemplate, Spacer, TableStyle


GREEN = colors.HexColor("#2e654c")
INK = colors.HexColor("#222b26")
MUTED = colors.HexColor("#647068")
LINE = colors.HexColor("#dfe4de")
SOFT = colors.HexColor("#f4f6f3")


def _register_fonts() -> None:
    import reportlab

    font_dir = Path(reportlab.__file__).parent / "fonts"
    for name, filename in (("MoshVera", "Vera.ttf"), ("MoshVeraBold", "VeraBd.ttf"),
                           ("MoshVeraItalic", "VeraIt.ttf"), ("MoshVeraBoldItalic", "VeraBI.ttf")):
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(font_dir / filename)))
    pdfmetrics.registerFontFamily("MoshVera", normal="MoshVera", bold="MoshVeraBold",
                                  italic="MoshVeraItalic", boldItalic="MoshVeraBoldItalic")


def _inline_markup(children: list) -> str:
    parts = []
    links = []
    for token in children:
        if token.type == "text":
            parts.append(html.escape(token.content))
        elif token.type in {"softbreak", "hardbreak"}:
            parts.append("<br/>" if token.type == "hardbreak" else " ")
        elif token.type == "code_inline":
            parts.append(f'<font color="#315d48">{html.escape(token.content)}</font>')
        elif token.type == "image":
            parts.append(f'[Image: {html.escape(token.content or "image")}]')
        elif token.type in {"strong_open", "em_open", "s_open"}:
            parts.append({"strong_open": "<b>", "em_open": "<i>", "s_open": "<strike>"}[token.type])
        elif token.type in {"strong_close", "em_close", "s_close"}:
            parts.append({"strong_close": "</b>", "em_close": "</i>", "s_close": "</strike>"}[token.type])
        elif token.type == "link_open":
            href = token.attrGet("href") or ""
            parsed = urlsplit(href)
            allowed = parsed.scheme in {"http", "https", "mailto"} or (not parsed.scheme and href.startswith("#"))
            links.append(allowed)
            parts.append(f'<link href="{html.escape(href, quote=True)}" color="#2e654c">' if allowed else "")
        elif token.type == "link_close" and links:
            if links.pop():
                parts.append("</link>")
    return "".join(parts)


def _table(tokens: list, start: int, cell_style: ParagraphStyle, width: float) -> tuple[LongTable | None, int]:
    rows = []
    row = []
    cell = ""
    index = start + 1
    while index < len(tokens) and tokens[index].type != "table_close":
        token = tokens[index]
        if token.type == "tr_open":
            row = []
        elif token.type in {"th_open", "td_open"}:
            cell = ""
        elif token.type == "inline":
            cell += _inline_markup(token.children or [])
        elif token.type in {"th_close", "td_close"}:
            row.append(Paragraph(cell or " ", cell_style))
        elif token.type == "tr_close" and row:
            rows.append(row)
        index += 1
    if not rows:
        return None, index
    columns = max(map(len, rows))
    normalized = [row + [Paragraph(" ", cell_style) for _ in range(columns - len(row))] for row in rows]
    table = LongTable(normalized, colWidths=[width / columns] * columns, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("BACKGROUND", (0, 0), (-1, 0), SOFT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table, index


def render_markdown_pdf(source: str, title: str) -> bytes:
    """Render Markdown to PDF bytes without fetching linked assets or saving a second report."""
    _register_fonts()
    buffer = io.BytesIO()
    margin = 48
    page_width, _ = A4
    document = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=margin, rightMargin=margin,
                                 topMargin=54, bottomMargin=52, title=title, author="mosh")
    body = ParagraphStyle("body", fontName="MoshVera", fontSize=9.3, leading=14.5,
                          textColor=INK, spaceAfter=9, allowWidows=0, allowOrphans=0,
                          splitLongWords=1)
    styles = {
        "p": body,
        "h1": ParagraphStyle("h1", parent=body, fontName="MoshVeraBold", fontSize=18, leading=23,
                              spaceBefore=4, spaceAfter=13, keepWithNext=True),
        "h2": ParagraphStyle("h2", parent=body, fontName="MoshVeraBold", fontSize=13.5, leading=18,
                              spaceBefore=16, spaceAfter=8, keepWithNext=True),
        "h3": ParagraphStyle("h3", parent=body, fontName="MoshVeraBold", fontSize=11, leading=15,
                              spaceBefore=12, spaceAfter=6, keepWithNext=True),
        "h4": ParagraphStyle("h4", parent=body, fontName="MoshVeraBold", fontSize=9.8, leading=14,
                              spaceBefore=10, spaceAfter=5, keepWithNext=True),
        "quote": ParagraphStyle("quote", parent=body, leftIndent=13, textColor=MUTED,
                                 borderColor=LINE, borderWidth=1, borderPadding=7),
        "cell": ParagraphStyle("cell", parent=body, fontSize=8, leading=11, spaceAfter=0),
        "code": ParagraphStyle("code", parent=body, fontSize=8, leading=11, leftIndent=10,
                                rightIndent=10, backColor=SOFT, borderPadding=8),
    }
    story = []
    tokens = MarkdownIt("default", {"html": False, "linkify": False}).parse(source)
    heading = ""
    quote_depth = 0
    list_stack: list[dict[str, int | str]] = []
    item_prefix = ""
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.type == "table_open":
            table, index = _table(tokens, index, styles["cell"], page_width - 2 * margin)
            if table:
                story.extend((table, Spacer(1, 12)))
        elif token.type == "heading_open":
            heading = token.tag if token.tag in styles else "h4"
        elif token.type == "heading_close":
            heading = ""
        elif token.type == "blockquote_open":
            quote_depth += 1
        elif token.type == "blockquote_close":
            quote_depth -= 1
        elif token.type in {"bullet_list_open", "ordered_list_open"}:
            list_stack.append({"kind": token.type, "count": int(token.attrGet("start") or 1) - 1})
        elif token.type in {"bullet_list_close", "ordered_list_close"}:
            list_stack.pop()
        elif token.type == "list_item_open":
            current = list_stack[-1]
            current["count"] = int(current["count"]) + 1
            item_prefix = "• " if current["kind"] == "bullet_list_open" else f'{current["count"]}. '
        elif token.type == "inline":
            markup = _inline_markup(token.children or [])
            if item_prefix:
                markup = html.escape(item_prefix) + markup
                item_prefix = ""
            style = styles[heading] if heading else styles["quote"] if quote_depth else body
            if list_stack:
                style = ParagraphStyle("list", parent=style, leftIndent=len(list_stack) * 15,
                                       firstLineIndent=-9, spaceAfter=4)
            story.append(Paragraph(markup or " ", style))
        elif token.type in {"fence", "code_block"}:
            story.append(Spacer(1, 5))
            story.append(Preformatted(token.content.rstrip("\n"), styles["code"],
                                      maxLineLength=95, splitChars=" /._-"))
            story.append(Spacer(1, 7))
        elif token.type == "hr":
            story.append(HRFlowable(width="100%", thickness=.5, color=LINE, spaceBefore=7, spaceAfter=12))
        index += 1
    if not story:
        story.append(Paragraph("No report content.", body))

    def page_decoration(canvas, doc) -> None:
        canvas.saveState()
        canvas.setStrokeColor(LINE)
        canvas.line(margin, 39, page_width - margin, 39)
        canvas.setFont("MoshVera", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(margin, 27, "mosh")
        canvas.drawRightString(page_width - margin, 27, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=page_decoration, onLaterPages=page_decoration)
    return buffer.getvalue()
