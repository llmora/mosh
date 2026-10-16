"""Generate Word downloads directly from canonical Markdown reports."""

from __future__ import annotations

import io
import zipfile
from xml.etree import ElementTree as ET

from markdown_it import MarkdownIt


W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG = "http://schemas.openxmlformats.org/package/2006/relationships"
CP = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
DC = "http://purl.org/dc/elements/1.1/"
XML = "http://www.w3.org/XML/1998/namespace"

ET.register_namespace("w", W)
ET.register_namespace("r", R)


def _el(parent: ET.Element, name: str, **attrs: str) -> ET.Element:
    return ET.SubElement(parent, f"{{{W}}}{name}", {f"{{{W}}}{key}": value for key, value in attrs.items()})


def _paragraph(parent: ET.Element, style: str = "Normal") -> ET.Element:
    paragraph = _el(parent, "p")
    properties = _el(paragraph, "pPr")
    _el(properties, "pStyle", val=style)
    return paragraph


def _run(parent: ET.Element, value: str, *, bold: bool = False, italic: bool = False,
         strike: bool = False, code: bool = False, link: bool = False) -> None:
    if not value:
        return
    run = _el(parent, "r")
    if bold or italic or strike or code or link:
        properties = _el(run, "rPr")
        if bold:
            _el(properties, "b")
        if italic:
            _el(properties, "i")
        if strike:
            _el(properties, "strike")
        if code:
            _el(properties, "rFonts", ascii="Courier New", hAnsi="Courier New")
            _el(properties, "color", val="315D48")
        if link:
            _el(properties, "color", val="2E654C")
            _el(properties, "u", val="single")
    value_parts = value.split("\n")
    for index, part in enumerate(value_parts):
        if index:
            _el(run, "br")
        if part:
            node = _el(run, "t")
            node.set(f"{{{XML}}}space", "preserve")
            node.text = part


def _inline(paragraph: ET.Element, tokens: list, hyperlinks: list[tuple[str, str]], *, bold: bool = False) -> None:
    emphasis = 0
    strong = 0
    strike = 0
    link_id = ""
    for token in tokens:
        kind = token.type
        if kind == "strong_open":
            strong += 1
        elif kind == "strong_close":
            strong -= 1
        elif kind == "em_open":
            emphasis += 1
        elif kind == "em_close":
            emphasis -= 1
        elif kind == "s_open":
            strike += 1
        elif kind == "s_close":
            strike -= 1
        elif kind == "link_open":
            href = token.attrGet("href") or ""
            if href.startswith(("https://", "http://", "mailto:")):
                link_id = f"rId{len(hyperlinks) + 1}"
                hyperlinks.append((link_id, href))
        elif kind == "link_close":
            link_id = ""
        elif kind in {"text", "code_inline", "image", "softbreak", "hardbreak"}:
            value = (" " if kind == "softbreak" else "\n" if kind == "hardbreak" else
                     f"[Image: {token.content or 'image'}]" if kind == "image" else token.content)
            parent = paragraph
            if link_id:
                parent = ET.SubElement(paragraph, f"{{{W}}}hyperlink", {f"{{{R}}}id": link_id})
            _run(parent, value, bold=bold or strong > 0, italic=emphasis > 0,
                 strike=strike > 0, code=kind == "code_inline", link=bool(link_id))


def _styles() -> bytes:
    root = ET.Element(f"{{{W}}}styles")
    definitions = (
        ("Normal", 22, "222B26", False, 120),
        ("Heading1", 34, "222B26", True, 260),
        ("Heading2", 27, "222B26", True, 220),
        ("Heading3", 23, "222B26", True, 180),
        ("Heading4", 22, "222B26", True, 160),
        ("List", 22, "222B26", False, 80),
        ("Quote", 21, "647068", False, 160),
        ("Code", 18, "315D48", False, 100),
    )
    for style_id, size, color, bold, after in definitions:
        style = _el(root, "style", type="paragraph", styleId=style_id)
        _el(style, "name", val=style_id)
        ppr = _el(style, "pPr")
        _el(ppr, "spacing", before="180" if style_id.startswith("Heading") and style_id != "Heading1" else "0",
            after=str(after), line="300", lineRule="auto")
        if style_id.startswith("Heading"):
            _el(ppr, "keepNext")
        if style_id == "List":
            _el(ppr, "ind", left="360", hanging="240")
        if style_id == "Quote":
            _el(ppr, "ind", left="360")
        rpr = _el(style, "rPr")
        font = "Courier New" if style_id == "Code" else "Arial"
        _el(rpr, "rFonts", ascii=font, hAnsi=font)
        _el(rpr, "color", val=color)
        _el(rpr, "sz", val=str(size))
        if bold:
            _el(rpr, "b")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def render_markdown_docx(source: str, title: str) -> bytes:
    """Return a portable DOCX without saving another report artifact."""
    root = ET.Element(f"{{{W}}}document")
    body = _el(root, "body")
    hyperlinks: list[tuple[str, str]] = []
    paragraph: ET.Element | None = None
    table: ET.Element | None = None
    row: ET.Element | None = None
    cell: ET.Element | None = None
    header_cell = False
    list_stack: list[tuple[str, int]] = []
    quote_depth = 0
    tokens = MarkdownIt("default", {"html": False, "linkify": False}).parse(source)
    for token in tokens:
        kind = token.type
        if kind == "heading_open":
            paragraph = _paragraph(body, "Heading" + str(min(int(token.tag[1:]), 4)))
        elif kind == "paragraph_open":
            if cell is not None:
                paragraph = _paragraph(cell)
            elif list_stack:
                paragraph = _paragraph(body, "List")
                marker, number = list_stack[-1]
                _run(paragraph, f"{number}. " if marker == "ordered" else "• ")
                if marker == "ordered":
                    list_stack[-1] = (marker, number + 1)
            else:
                paragraph = _paragraph(body, "Quote" if quote_depth else "Normal")
        elif kind == "inline" and paragraph is not None:
            _inline(paragraph, token.children or [], hyperlinks, bold=header_cell)
        elif kind in {"paragraph_close", "heading_close"}:
            paragraph = None
        elif kind in {"bullet_list_open", "ordered_list_open"}:
            list_stack.append(("ordered" if kind == "ordered_list_open" else "bullet", int(token.attrGet("start") or 1)))
        elif kind in {"bullet_list_close", "ordered_list_close"}:
            list_stack.pop()
        elif kind == "blockquote_open":
            quote_depth += 1
        elif kind == "blockquote_close":
            quote_depth -= 1
        elif kind in {"fence", "code_block"}:
            for line in token.content.rstrip("\n").split("\n"):
                _run(_paragraph(body, "Code"), line or " ")
        elif kind == "hr":
            _run(_paragraph(body), "────────────────────────")
        elif kind == "table_open":
            table = _el(body, "tbl")
            properties = _el(table, "tblPr")
            _el(properties, "tblW", w="0", type="auto")
            borders = _el(properties, "tblBorders")
            for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
                _el(borders, side, val="single", sz="4", color="DFE4DE")
            margins = _el(properties, "tblCellMar")
            for side in ("top", "left", "bottom", "right"):
                _el(margins, side, w="100", type="dxa")
        elif kind == "tr_open" and table is not None:
            row = _el(table, "tr")
        elif kind in {"th_open", "td_open"} and row is not None:
            cell = _el(row, "tc")
            header_cell = kind == "th_open"
            if header_cell:
                _el(_el(cell, "tcPr"), "shd", fill="F4F6F3")
            paragraph = _paragraph(cell)
        elif kind in {"th_close", "td_close"}:
            cell = None
            header_cell = False
            paragraph = None
        elif kind == "table_close":
            table = None
    section = _el(body, "sectPr")
    _el(section, "pgSz", w="12240", h="15840")
    _el(section, "pgMar", top="1152", right="1152", bottom="1152", left="1152",
        header="720", footer="720", gutter="0")

    relationships = ET.Element("Relationships", xmlns=PKG)
    ET.SubElement(relationships, "Relationship", Id="rIdStyles",
                  Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles",
                  Target="styles.xml")
    for relationship_id, href in hyperlinks:
        ET.SubElement(relationships, "Relationship", Id=relationship_id,
                      Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                      Target=href, TargetMode="External")
    core = ET.Element(f"{{{CP}}}coreProperties")
    ET.SubElement(core, f"{{{DC}}}title").text = title
    ET.SubElement(core, f"{{{DC}}}creator").text = "mosh"
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '</Types>'
    )
    package_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
        '</Relationships>'
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", package_rels)
        archive.writestr("word/document.xml", ET.tostring(root, encoding="utf-8", xml_declaration=True))
        archive.writestr("word/styles.xml", _styles())
        archive.writestr("word/_rels/document.xml.rels", ET.tostring(relationships, encoding="utf-8", xml_declaration=True))
        archive.writestr("docProps/core.xml", ET.tostring(core, encoding="utf-8", xml_declaration=True))
    return output.getvalue()
