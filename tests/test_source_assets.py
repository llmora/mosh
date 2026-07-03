from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mosh.engagements import EngagementAsset, create_engagement
from mosh.source_assets import ensure_source_root, readable_source_root, source_checkout_dir


class SourceAssetTests(unittest.TestCase):
    def test_source_tree_resolves_to_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            source = Path(directory) / "source"
            source.mkdir()
            engagement = create_engagement(output_root)
            asset = EngagementAsset(id="asset_source_1", type="source_tree", locator=str(source))

            self.assertEqual(ensure_source_root(output_root, engagement.id, asset), source.resolve())
            self.assertEqual(readable_source_root(output_root, engagement.id, asset), source.resolve())

    def test_source_repo_clones_to_engagement_asset_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            asset = EngagementAsset(
                id="asset_repo_1",
                type="source_repo",
                locator="https://github.com/example/app",
            )
            checkout = source_checkout_dir(output_root, engagement.id, asset)

            def fake_run(args, **kwargs):
                if args[:3] == ["git", "clone", "--depth"]:
                    Path(args[-1]).mkdir(parents=True)
                    return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
                if args[:3] == ["git", "-C", str(checkout)]:
                    return subprocess.CompletedProcess(args, 0, stdout="true\n", stderr="")
                return subprocess.CompletedProcess(args, 1, stdout="", stderr="unexpected git command")

            with patch("mosh.source_assets.subprocess.run", side_effect=fake_run) as run:
                source_root = ensure_source_root(output_root, engagement.id, asset)

            self.assertEqual(source_root, checkout.resolve())
            self.assertEqual(readable_source_root(output_root, engagement.id, asset), checkout.resolve())
            clone_calls = [call for call in run.call_args_list if call.args[0][:3] == ["git", "clone", "--depth"]]
            self.assertEqual(len(clone_calls), 1)

    def test_source_repo_rejects_non_git_checkout_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            engagement = create_engagement(output_root)
            asset = EngagementAsset(
                id="asset_repo_1",
                type="source_repo",
                locator="https://github.com/example/app",
            )
            checkout = source_checkout_dir(output_root, engagement.id, asset)
            checkout.mkdir(parents=True)
            (checkout / "README.md").write_text("not a checkout\n", encoding="utf-8")

            with patch(
                "mosh.source_assets.subprocess.run",
                return_value=subprocess.CompletedProcess(["git"], 1, stdout="", stderr=""),
            ):
                with self.assertRaisesRegex(ValueError, "not a Git checkout"):
                    ensure_source_root(output_root, engagement.id, asset)


if __name__ == "__main__":
    unittest.main()
