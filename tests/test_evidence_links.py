from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mosh.engagements import attach_asset, asset_discovery_dir, create_engagement
from mosh.evidence_links import (
    EVIDENCE_LINKS_SCHEMA,
    build_evidence_links,
    discovery_fingerprint,
    links_path,
    load_evidence_links_if_current,
)


class EvidenceLinksTests(unittest.TestCase):
    def test_build_evidence_links_writes_engagement_plan_links_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            source = Path(directory) / "source"
            source.mkdir()
            engagement = create_engagement(output_root)
            live_asset = attach_asset(output_root, engagement.id, "https://app.example.test").asset
            source_asset = attach_asset(output_root, engagement.id, str(source)).asset
            _write_memory(
                asset_discovery_dir(output_root, engagement.id, live_asset.id),
                [
                    {
                        "kind": "crawled_page",
                        "content": {
                            "url": "https://app.example.test/api/users/123",
                            "status": 200,
                            "links": ["https://app.example.test/api/status"],
                            "references": [],
                            "forms": [],
                        },
                    }
                ],
            )
            _write_memory(
                asset_discovery_dir(output_root, engagement.id, source_asset.id),
                [
                    {
                        "kind": "source_index",
                        "content": {
                            "inventory": {
                                "routes": [
                                    {
                                        "method": "GET",
                                        "full_route": "/api/users/:userId",
                                        "path": "api/users.py",
                                        "line": 12,
                                        "handler": "get_user",
                                        "framework": "python",
                                        "snippet_hash": "sha256:user",
                                    },
                                    {
                                        "method": "GET",
                                        "full_route": "/api/status",
                                        "path": "api/status.py",
                                        "line": 3,
                                        "framework": "python",
                                    },
                                ]
                            }
                        },
                    }
                ],
            )

            result = build_evidence_links(output_root, engagement.id)

            self.assertEqual(result.links_path, links_path(output_root, engagement.id))
            self.assertTrue(result.links_path.exists())
            self.assertEqual(result.links_path, output_root / engagement.id / "plan" / "links.json")
            self.assertFalse((output_root / engagement.id / "evidence-links").exists())
            self.assertFalse((output_root / engagement.id / "links.json").exists())
            payload = json.loads(result.links_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], EVIDENCE_LINKS_SCHEMA)
            self.assertTrue(payload["discovery_fingerprint"].startswith("sha256:"))
            self.assertNotIn("engagement_id", payload)
            self.assertNotIn("assets", payload)
            self.assertNotIn("discovered_at", json.dumps(payload))
            self.assertEqual(len(payload["links"]), 2)
            bases = {link["basis"] for link in payload["links"]}
            self.assertEqual(bases, {"exact_path", "parameterized_path"})
            parameterized = next(link for link in payload["links"] if link["basis"] == "parameterized_path")
            self.assertEqual(parameterized["asset_refs"], [source_asset.id, live_asset.id])
            self.assertEqual(parameterized["refs"][0]["path"], "api/users.py")
            self.assertEqual(parameterized["refs"][1]["path"], "/api/users/123")

    def test_build_evidence_links_adds_validated_model_assisted_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            source = Path(directory) / "source"
            source.mkdir()
            engagement = create_engagement(output_root)
            live_asset = attach_asset(output_root, engagement.id, "https://app.example.test").asset
            source_asset = attach_asset(output_root, engagement.id, str(source)).asset
            _write_memory(
                asset_discovery_dir(output_root, engagement.id, live_asset.id),
                [
                    {
                        "kind": "crawled_page",
                        "content": {
                            "url": "https://app.example.test/api/v1/sales/leads",
                            "status": 200,
                            "links": [],
                            "references": [],
                            "forms": [],
                        },
                    }
                ],
            )
            _write_memory(
                asset_discovery_dir(output_root, engagement.id, source_asset.id),
                [
                    {
                        "kind": "source_index",
                        "content": {
                            "inventory": {
                                "routes": [
                                    {
                                        "method": "POST",
                                        "full_route": "/sales/leads",
                                        "path": "api/sales.py",
                                        "line": 20,
                                        "handler": "create_lead",
                                        "framework": "python",
                                    }
                                ]
                            }
                        },
                    }
                ],
            )
            fake_linker = FakeModelAssistedLinker()

            result = build_evidence_links(output_root, engagement.id, model_assisted_linker=fake_linker)

            self.assertEqual(len(fake_linker.contexts), 1)
            context = fake_linker.contexts[0]
            self.assertEqual(context["schema"], "mosh.evidence-link-candidate-input.v1")
            self.assertEqual(context["pairs"][0]["deterministic_links"], [])
            self.assertEqual(len(result.payload["links"]), 1)
            link = result.payload["links"][0]
            self.assertEqual(link["type"], "source_route_to_live_endpoint_candidate")
            self.assertEqual(link["basis"], "model_assisted_candidate")
            self.assertEqual(link["confidence"], "high")
            self.assertEqual(link["score"], 0.74)
            self.assertEqual(link["asset_refs"], [source_asset.id, live_asset.id])
            self.assertEqual(link["refs"][0]["path"], "api/sales.py")
            self.assertEqual(link["refs"][1]["path"], "/api/v1/sales/leads")
            self.assertEqual(result.payload["pairs"][0]["deterministic_links"], 0)
            self.assertEqual(result.payload["pairs"][0]["model_candidate_links"], 1)
            self.assertEqual(result.payload["model_assisted"]["model"], "fake-linker")

    def test_load_evidence_links_if_current_invalidates_when_discovery_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            source = Path(directory) / "source"
            source.mkdir()
            engagement = create_engagement(output_root)
            live_asset = attach_asset(output_root, engagement.id, "https://app.example.test").asset
            source_asset = attach_asset(output_root, engagement.id, str(source)).asset
            live_dir = asset_discovery_dir(output_root, engagement.id, live_asset.id)
            _write_memory(
                live_dir,
                [
                    {
                        "kind": "crawled_page",
                        "content": {
                            "url": "https://app.example.test/api/status",
                            "status": 200,
                            "links": [],
                            "references": [],
                            "forms": [],
                        },
                    }
                ],
            )
            _write_memory(
                asset_discovery_dir(output_root, engagement.id, source_asset.id),
                [
                    {
                        "kind": "source_index",
                        "content": {
                            "inventory": {
                                "routes": [
                                    {
                                        "method": "GET",
                                        "full_route": "/api/status",
                                        "path": "api/status.py",
                                    }
                                ]
                            }
                        },
                    }
                ],
            )

            result = build_evidence_links(output_root, engagement.id)
            original_fingerprint = result.payload["discovery_fingerprint"]

            current = load_evidence_links_if_current(output_root, engagement.id)
            self.assertIsNotNone(current)
            self.assertEqual(current.payload["discovery_fingerprint"], original_fingerprint)

            _write_memory(
                live_dir,
                [
                    {
                        "kind": "crawled_page",
                        "content": {
                            "url": "https://app.example.test/api/status",
                            "status": 200,
                            "links": ["https://app.example.test/api/users"],
                            "references": [],
                            "forms": [],
                        },
                    }
                ],
            )

            self.assertNotEqual(discovery_fingerprint(output_root, engagement.id), original_fingerprint)
            self.assertIsNone(load_evidence_links_if_current(output_root, engagement.id))

    def test_build_evidence_links_links_every_live_source_pair_and_caps_each_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            source_one = Path(directory) / "source-one"
            source_two = Path(directory) / "source-two"
            source_one.mkdir()
            source_two.mkdir()
            engagement = create_engagement(output_root)
            live_one = attach_asset(output_root, engagement.id, "https://one.example.test").asset
            live_two = attach_asset(output_root, engagement.id, "https://two.example.test").asset
            source_asset_one = attach_asset(output_root, engagement.id, str(source_one)).asset
            source_asset_two = attach_asset(output_root, engagement.id, str(source_two)).asset
            for live_asset, host in ((live_one, "one.example.test"), (live_two, "two.example.test")):
                _write_memory(
                    asset_discovery_dir(output_root, engagement.id, live_asset.id),
                    [
                        {
                            "kind": "crawled_page",
                            "content": {
                                "url": f"https://{host}/api/shared",
                                "status": 200,
                                "links": [],
                                "references": [],
                                "forms": [],
                            },
                        }
                    ],
                )
            for source_asset in (source_asset_one, source_asset_two):
                _write_memory(
                    asset_discovery_dir(output_root, engagement.id, source_asset.id),
                    [
                        {
                            "kind": "source_index",
                            "content": {
                                "inventory": {
                                    "routes": [
                                        {
                                            "method": "GET",
                                            "full_route": "/api/shared",
                                            "path": f"{source_asset.id}/api.py",
                                            "line": 1,
                                        }
                                    ]
                                }
                            },
                        }
                    ],
                )

            result = build_evidence_links(output_root, engagement.id, max_links_per_asset_pair=1)

            self.assertEqual(len(result.payload["links"]), 4)
            self.assertEqual(
                {(pair["live_asset_id"], pair["source_asset_id"], pair["links"]) for pair in result.payload["pairs"]},
                {
                    (live_one.id, source_asset_one.id, 1),
                    (live_one.id, source_asset_two.id, 1),
                    (live_two.id, source_asset_one.id, 1),
                    (live_two.id, source_asset_two.id, 1),
                },
            )

    def test_build_evidence_links_records_skipped_assets_without_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory) / "report"
            source = Path(directory) / "source"
            source.mkdir()
            engagement = create_engagement(output_root)
            live_asset = attach_asset(output_root, engagement.id, "https://app.example.test").asset
            source_asset = attach_asset(output_root, engagement.id, str(source)).asset

            result = build_evidence_links(output_root, engagement.id)

            self.assertEqual(result.payload["links"], [])
            self.assertEqual(
                result.payload["skipped_assets"],
                [
                    {"id": live_asset.id, "reason": "no live discovery endpoints"},
                    {"id": source_asset.id, "reason": "no source discovery routes"},
                ],
            )


def _write_memory(report_dir: Path, items: list[dict[str, object]]) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "memory.json").write_text(json.dumps(items), encoding="utf-8")


class FakeModelAssistedLinker:
    model_metadata = {"crew": "planning", "agent": "evidence_linker", "model": "fake-linker"}

    def __init__(self) -> None:
        self.contexts: list[dict[str, object]] = []

    def suggest_links(self, context: dict[str, object], tool_context: object | None = None) -> dict[str, object]:
        self.contexts.append(context)
        pair = context["pairs"][0]  # type: ignore[index]
        return {
            "links": [
                {
                    "source_ref_id": pair["source_routes"][0]["ref_id"],
                    "live_ref_id": pair["live_endpoints"][0]["ref_id"],
                    "confidence": "high",
                    "reason": "Live deployment appears to add an /api/v1 prefix to the source sales route.",
                },
                {
                    "source_ref_id": "src_invented",
                    "live_ref_id": pair["live_endpoints"][0]["ref_id"],
                    "confidence": "high",
                    "reason": "Invalid source ref must be ignored.",
                },
            ]
        }


if __name__ == "__main__":
    unittest.main()
