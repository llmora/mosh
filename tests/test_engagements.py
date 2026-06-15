from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from mosh.engagements import (
    attach_asset,
    asset_dir,
    create_engagement,
    infer_asset_type,
    load_asset,
    load_engagement,
    record_asset_discovery,
    save_engagement,
)


class EngagementTests(unittest.TestCase):
    def test_create_engagement_writes_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"

            engagement = create_engagement(output_root, title="Example App")

            self.assertRegex(engagement.id, r"^eng_[a-z0-9]{8}$")
            manifest = output_root / engagement.id / "engagement.json"
            self.assertTrue(manifest.exists())
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "mosh.engagement.v1")
            self.assertEqual(payload["title"], "Example App")
            self.assertEqual(payload["assets"], [])

    def test_attach_asset_infers_types_and_writes_asset_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            source = Path(directory) / "example-source"
            source.mkdir()
            engagement = create_engagement(output_root)

            live_result = attach_asset(output_root, engagement.id, "https://App.Example.test/")
            source_result = attach_asset(output_root, engagement.id, str(source), label="API source")

            self.assertTrue(live_result.created)
            self.assertEqual(live_result.asset.id, "asset_live_1")
            self.assertEqual(live_result.asset.type, "live_url")
            self.assertEqual(live_result.asset.locator, "https://app.example.test")
            self.assertEqual(source_result.asset.id, "asset_source_1")
            self.assertEqual(source_result.asset.type, "source_tree")
            self.assertEqual(source_result.asset.label, "API source")
            live_asset_path = asset_dir(output_root, engagement.id, "asset_live_1") / "asset.json"
            source_asset_path = asset_dir(output_root, engagement.id, "asset_source_1") / "asset.json"
            self.assertTrue(live_asset_path.exists())
            self.assertTrue(source_asset_path.exists())
            manifest = json.loads((output_root / engagement.id / "engagement.json").read_text(encoding="utf-8"))
            self.assertEqual(
                manifest["assets"],
                [
                    {"id": "asset_live_1", "created_at": live_result.asset.created_at},
                    {"id": "asset_source_1", "created_at": source_result.asset.created_at},
                ],
            )
            self.assertNotIn("type", manifest["assets"][0])
            self.assertNotIn("locator", manifest["assets"][0])
            self.assertNotIn("label", manifest["assets"][0])
            self.assertNotIn("metadata", manifest["assets"][0])
            source_asset_payload = json.loads(source_asset_path.read_text(encoding="utf-8"))
            self.assertEqual(source_asset_payload["label"], "API source")
            self.assertEqual(source_asset_payload["type"], "source_tree")

            reloaded = load_engagement(output_root, engagement.id)
            self.assertEqual([asset.id for asset in reloaded.assets], ["asset_live_1", "asset_source_1"])

    def test_attach_asset_is_idempotent_for_same_locator_and_type(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)

            first = attach_asset(output_root, engagement.id, "https://example.test")
            second = attach_asset(output_root, engagement.id, "https://example.test/")

            self.assertTrue(first.created)
            self.assertFalse(second.created)
            self.assertEqual(first.asset.id, second.asset.id)
            self.assertEqual(len(load_engagement(output_root, engagement.id).assets), 1)

    def test_legacy_embedded_asset_manifest_loads_and_rewrites_as_asset_refs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root, title="Legacy")
            asset = attach_asset(output_root, engagement.id, "https://example.test").asset
            manifest_path = output_root / engagement.id / "engagement.json"
            legacy_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            legacy_payload["assets"] = [asset.to_dict()]
            manifest_path.write_text(json.dumps(legacy_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            loaded = load_engagement(output_root, engagement.id)
            save_engagement(output_root, loaded)

            self.assertEqual(load_asset(output_root, engagement.id, asset.id).locator, "https://example.test")
            rewritten = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(rewritten["assets"], [{"id": asset.id, "created_at": asset.created_at}])
            self.assertNotIn("type", rewritten["assets"][0])
            self.assertNotIn("locator", rewritten["assets"][0])

    def test_record_asset_discovery_keeps_only_non_derived_discovery_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            asset = attach_asset(output_root, engagement.id, "https://example.test").asset
            report_dir = output_root / engagement.id / "assets" / asset.id / "discovery"

            updated = record_asset_discovery(output_root, engagement.id, asset.id, report_dir)

            discovery = updated.metadata["discovery"]
            self.assertIn("last_discovered_at", discovery)
            self.assertNotIn("report_dir", discovery)
            self.assertNotIn("report_path", discovery)
            payload = json.loads((asset_dir(output_root, engagement.id, asset.id) / "asset.json").read_text(encoding="utf-8"))
            self.assertEqual(set(payload["metadata"]["discovery"]), {"last_discovered_at"})

    def test_legacy_asset_discovery_paths_are_removed_when_asset_is_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            asset = attach_asset(output_root, engagement.id, "https://example.test").asset
            asset_path = asset_dir(output_root, engagement.id, asset.id) / "asset.json"
            payload = json.loads(asset_path.read_text(encoding="utf-8"))
            payload["metadata"] = {
                "discovery": {
                    "last_discovered_at": "2026-01-01T00:00:00+00:00",
                    "report_dir": "report/old/discovery",
                    "report_path": "report/old/discovery/report.md",
                }
            }
            asset_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            loaded = load_asset(output_root, engagement.id, asset.id)
            save_engagement(output_root, load_engagement(output_root, engagement.id))

            self.assertEqual(set(loaded.metadata["discovery"]), {"last_discovered_at"})
            rewritten = json.loads(asset_path.read_text(encoding="utf-8"))
            self.assertEqual(set(rewritten["metadata"]["discovery"]), {"last_discovered_at"})

    def test_infer_asset_type_recognizes_repositories_and_mobile_app_urls(self) -> None:
        self.assertEqual(infer_asset_type("https://github.com/example/app"), "source_repo")
        self.assertEqual(infer_asset_type("git@gitlab.com:example/app.git"), "source_repo")
        self.assertEqual(infer_asset_type("https://apps.apple.com/us/app/example/id123"), "mobile_app")
        self.assertEqual(infer_asset_type("https://play.google.com/store/apps/details?id=example"), "mobile_app")
        self.assertEqual(infer_asset_type("https://app.example.test"), "live_url")

    def test_created_engagement_id_is_path_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            engagement = create_engagement(Path(directory) / "report")

            self.assertIsNotNone(re.fullmatch(r"eng_[a-z0-9]{8}", engagement.id))


if __name__ == "__main__":
    unittest.main()
