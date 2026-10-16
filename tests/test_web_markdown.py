import unittest

from mosh.web_markdown import render_markdown_document


class MarkdownDocumentTests(unittest.TestCase):
    def test_report_structure_and_tables_render_as_html(self) -> None:
        source = (
            "# Discovery report\n\n"
            "A **confirmed** [reference](https://example.test/reference).\n\n"
            "- First area\n- Second area\n\n"
            "| Area | Status |\n| --- | --- |\n| Login | Found |\n\n"
            "```python\nprint('safe')\n```\n"
        )
        rendered = render_markdown_document(source)
        self.assertIn('<article class="markdown-document">', rendered)
        self.assertIn('<h1 id="section-1">Discovery report</h1>', rendered)
        self.assertIn("<strong>confirmed</strong>", rendered)
        self.assertIn('<a href="https://example.test/reference">reference</a>', rendered)
        self.assertIn("<li>First area</li>", rendered)
        self.assertIn('<div class="markdown-table-wrap"><table>', rendered)
        self.assertIn("<td>Login</td>", rendered)
        self.assertIn('<pre><code class="language-python">', rendered)

    def test_raw_html_and_unsafe_link_protocols_do_not_execute(self) -> None:
        rendered = render_markdown_document(
            "<script>alert(1)</script>\n\n"
            "[open](javascript:alert(1))\n\n"
            "![image](data:image/svg+xml;base64,PHN2Zz4=)\n"
        )
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn('href="javascript:', rendered)
        self.assertNotIn('src="data:', rendered)

    def test_contents_links_match_unique_heading_ids_and_escape_labels(self) -> None:
        rendered = render_markdown_document(
            "# Overview\n\n## A **test** & result\n\n## A **test** & result\n",
            download_url="/report/view",
        )
        self.assertIn('aria-label="Contents"', rendered)
        self.assertIn('<a href="#section-1">Overview</a>', rendered)
        self.assertIn('<a href="#section-2">A test &amp; result</a>', rendered)
        self.assertIn('<a href="#section-3">A test &amp; result</a>', rendered)
        self.assertIn('<h2 id="section-2">A <strong>test</strong> &amp; result</h2>', rendered)
        self.assertIn('<summary class="secondary">Download</summary>', rendered)
        for format_name, label in (("pdf", "PDF"), ("docx", "Word (DOCX)"), ("md", "Markdown")):
            self.assertIn(f'href="/report/view?format={format_name}" download>{label}</a>', rendered)

    def test_no_heading_still_offers_download_menu(self) -> None:
        rendered = render_markdown_document("Only a paragraph.", download_url="/plan/report")
        self.assertIn('<summary class="secondary">Download</summary>', rendered)
        self.assertNotIn('aria-label="Contents"', rendered)


if __name__ == "__main__":
    unittest.main()
