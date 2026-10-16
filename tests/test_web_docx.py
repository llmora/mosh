import io
import unittest
import zipfile
from xml.etree import ElementTree as ET

from mosh.web_docx import render_markdown_docx


W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


class WordExportTests(unittest.TestCase):
    def test_report_structure_and_links_survive_export(self) -> None:
        source = (
            "# Discovery report\n\n"
            "A **confirmed** [reference](https://example.test/reference).\n\n"
            "- First area\n- Second area\n\n"
            "| Area | Status |\n| --- | --- |\n| Login | Found |\n\n"
            "```python\nprint('safe')\n```\n"
        )
        data = render_markdown_docx(source, "Discovery report")
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(archive.testzip(), None)
            root = ET.fromstring(archive.read("word/document.xml"))
            styles = ET.fromstring(archive.read("word/styles.xml"))
            relationships = archive.read("word/_rels/document.xml.rels").decode()
            core = archive.read("docProps/core.xml").decode()
        text = "".join(node.text or "" for node in root.iter(f"{{{W}}}t"))
        for phrase in ("Discovery report", "A ", "confirmed", "reference", "First area", "Second area", "Login", "Found", "print('safe')"):
            self.assertIn(phrase, text)
        self.assertEqual(len(root.findall(f".//{{{W}}}tbl")), 1)
        self.assertEqual(len(root.findall(f".//{{{W}}}tr")), 2)
        self.assertIsNotNone(styles.find(f".//{{{W}}}style[@{{{W}}}styleId='Heading1']"))
        self.assertIn("https://example.test/reference", relationships)
        self.assertIn("Discovery report", core)

    def test_untrusted_html_is_text_and_link_is_not_active(self) -> None:
        data = render_markdown_docx("<script>bad()</script>\n\n[bad](javascript:bad())", "Test")
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            document = archive.read("word/document.xml").decode()
            relationships = archive.read("word/_rels/document.xml.rels").decode()
        self.assertIn("&lt;script&gt;bad()&lt;/script&gt;", document)
        self.assertNotIn("javascript:bad()", relationships)


if __name__ == "__main__":
    unittest.main()
