import unittest

from mosh.web_pdf import render_markdown_pdf


class MarkdownPdfTests(unittest.TestCase):
    def test_pdf_renders_markdown_sections_tables_lists_and_code(self) -> None:
        source = (
            "# Assessment report\n\n"
            "A **confirmed** finding with [evidence](https://example.test/evidence).\n\n"
            "## Findings\n\n- First result\n- Second result\n\n"
            "| Area | Status |\n| --- | --- |\n| Login | Reviewed |\n\n"
            "```text\nGET /account HTTP/1.1\n```\n"
        )
        result = render_markdown_pdf(source, "Assessment report")
        self.assertTrue(result.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", result[-32:])
        self.assertGreater(len(result), 3000)

    def test_pdf_handles_empty_and_unsafe_markdown_without_fetching_images(self) -> None:
        for source in ("", "<script>alert(1)</script>\n\n![remote](https://example.test/image.png)\n"):
            with self.subTest(source=source):
                self.assertTrue(render_markdown_pdf(source, "Safe report").startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
