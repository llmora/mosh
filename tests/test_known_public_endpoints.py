import tempfile
import unittest
from pathlib import Path

from mosh.engagement import (
    build_engagement_template,
    load_engagement_file,
    resolve_known_public_endpoints,
    write_engagement_template_mapping,
)


SAMPLE_ENDPOINTS = [
    "/auth/login",
    "/auth/register",
    "/auth/token/refresh",
    "/quiz/themes",
    "/quiz/questions",
]


def _base_template() -> dict:
    """A minimal valid engagement template for regeneration tests."""
    return build_engagement_template("https://example.com", {})


class KnownPublicEndpointsLoadTests(unittest.TestCase):
    def test_loads_known_public_endpoints_from_engagement_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "engagement.yaml"
            yaml = "known_public_endpoints:\n" + "".join(
                f"  - {endpoint}\n" for endpoint in SAMPLE_ENDPOINTS
            )
            path.write_text(yaml, encoding="utf-8")

            engagement = load_engagement_file(path)

            self.assertEqual(engagement["known_public_endpoints"], SAMPLE_ENDPOINTS)
            self.assertEqual(resolve_known_public_endpoints(engagement), SAMPLE_ENDPOINTS)

    def test_empty_list_is_handled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "engagement.yaml"
            path.write_text("known_public_endpoints: []\n", encoding="utf-8")

            engagement = load_engagement_file(path)

            self.assertEqual(engagement["known_public_endpoints"], [])
            self.assertEqual(resolve_known_public_endpoints(engagement), [])

    def test_missing_key_defaults_to_empty_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "engagement.yaml"
            path.write_text("engagement:\n  notes: nothing public here\n", encoding="utf-8")

            engagement = load_engagement_file(path)

            self.assertNotIn("known_public_endpoints", engagement)
            self.assertEqual(resolve_known_public_endpoints(engagement), [])

    def test_resolver_ignores_non_list_value(self) -> None:
        self.assertEqual(
            resolve_known_public_endpoints({"known_public_endpoints": "/auth/login"}),
            [],
        )


class KnownPublicEndpointsPreservationTests(unittest.TestCase):
    def test_field_preserved_on_template_regeneration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            # Initial write seeds the engagement file with public endpoints.
            initial = _base_template()
            initial["known_public_endpoints"] = list(SAMPLE_ENDPOINTS)
            write_engagement_template_mapping(report_dir, initial)

            path = report_dir / "engagement_template.yaml"
            self.assertEqual(
                resolve_known_public_endpoints(load_engagement_file(path)),
                SAMPLE_ENDPOINTS,
            )

            # Regenerate from a freshly built template that has no endpoints set.
            regenerated = _base_template()
            self.assertEqual(regenerated["known_public_endpoints"], [])
            write_engagement_template_mapping(report_dir, regenerated)

            preserved = resolve_known_public_endpoints(load_engagement_file(path))
            self.assertEqual(preserved, SAMPLE_ENDPOINTS)

    def test_regeneration_merges_new_and_existing_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)

            initial = _base_template()
            initial["known_public_endpoints"] = ["/auth/login", "/auth/register"]
            write_engagement_template_mapping(report_dir, initial)

            regenerated = _base_template()
            regenerated["known_public_endpoints"] = ["/quiz/themes"]
            write_engagement_template_mapping(report_dir, regenerated)

            path = report_dir / "engagement_template.yaml"
            preserved = resolve_known_public_endpoints(load_engagement_file(path))
            self.assertIn("/auth/login", preserved)
            self.assertIn("/auth/register", preserved)
            self.assertIn("/quiz/themes", preserved)


if __name__ == "__main__":
    unittest.main()
