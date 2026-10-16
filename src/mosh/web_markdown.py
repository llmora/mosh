"""Render report Markdown for the localhost interface."""

import html

from markdown_it import MarkdownIt


def render_markdown_document(source: str, *, download_url: str = "") -> str:
    """Return a safe Markdown document with linked headings and download choices."""
    parser = MarkdownIt("default", {"html": False, "linkify": False})
    parser.add_render_rule("table_open", lambda *_: '<div class="markdown-table-wrap"><table>\n')
    parser.add_render_rule("table_close", lambda *_: '</table></div>\n')
    tokens = parser.parse(source)
    headings = []
    for index, token in enumerate(tokens):
        if token.type != "heading_open":
            continue
        heading_id = f"section-{len(headings) + 1}"
        token.attrSet("id", heading_id)
        inline = tokens[index + 1]
        label = "".join(
            child.content if child.type in {"text", "code_inline", "image"} else " " if child.type in {"softbreak", "hardbreak"} else ""
            for child in inline.children or []
        ).strip() or "Untitled section"
        headings.append((heading_id, token.tag, label))
    article = f'<article class="markdown-document">{parser.renderer.render(tokens, parser.options, {})}</article>'
    if not headings and not download_url:
        return article
    download = ""
    if download_url:
        base_url = download_url
        options = "".join(
            f'<a href="{html.escape(base_url, quote=True)}?format={format_name}" download>{label}</a>'
            for format_name, label in (("pdf", "PDF"), ("docx", "Word (DOCX)"), ("md", "Markdown"))
        )
        download = (
            '<details class="markdown-download-menu"><summary class="secondary">Download</summary>'
            f'<div class="markdown-download-options">{options}</div></details>'
        )
    contents = ""
    if headings:
        links = "".join(
            f'<li class="depth-{tag[1:]}"><a href="#{heading_id}">{html.escape(label)}</a></li>'
            for heading_id, tag, label in headings
        )
        contents = f'<nav class="markdown-toc" aria-label="Contents"><h2>Contents</h2><ol>{links}</ol></nav>'
    return f'<div class="markdown-view"><aside class="markdown-side">{download}{contents}</aside>{article}</div>'
