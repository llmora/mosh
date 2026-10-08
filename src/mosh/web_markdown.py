"""Render report Markdown for the localhost interface."""

from markdown_it import MarkdownIt


def render_markdown_document(source: str) -> str:
    """Return a styled, HTML-safe Markdown document fragment."""
    parser = MarkdownIt("default", {"html": False, "linkify": False})
    parser.add_render_rule("table_open", lambda *_: '<div class="markdown-table-wrap"><table>\n')
    parser.add_render_rule("table_close", lambda *_: '</table></div>\n')
    return f'<article class="markdown-document">{parser.render(source)}</article>'
