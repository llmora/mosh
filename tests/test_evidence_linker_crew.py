from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mosh.config import AppConfig
from mosh.crews.discovery.crew import _load_crewai
from mosh.crews.security_planning.evidence_linker import (
    EvidenceLinkerState,
    _build_evidence_linker_crew,
    _build_live_endpoint_metadata_tool,
    _build_load_evidence_ref_tool,
    _build_source_read_slice_tool,
    _build_source_search_tool,
)
from mosh.engagements import EngagementAsset
from mosh.evidence_links import EvidenceLinkerToolContext, LiveEndpoint, SourceRoute


class EvidenceLinkerCrewTests(unittest.TestCase):
    def test_evidence_linker_crew_uses_discovery_style_verbose_output(self) -> None:
        crewai = _load_crewai()
        crew_def = _build_evidence_linker_crew(
            crewai,
            AppConfig(openrouter_api_key="test-key"),
            EvidenceLinkerState(),
        )

        crew = crew_def.crew()

        self.assertTrue(crew.verbose)

    def test_evidence_linker_agent_has_bounded_linkage_tools(self) -> None:
        crewai = _load_crewai()
        crew_def = _build_evidence_linker_crew(
            crewai,
            AppConfig(openrouter_api_key="test-key"),
            EvidenceLinkerState(),
        )

        agent = crew_def.evidence_linker()
        tool_names = {tool.name for tool in agent.tools}

        self.assertEqual(
            tool_names,
            {
                "load_evidence_ref",
                "source_search",
                "source_read_slice",
                "live_endpoint_metadata",
                "submit_evidence_link_candidates",
            },
        )

    def test_linkage_tools_load_search_and_read_only_existing_source_refs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source_root = Path(directory) / "source"
            source_root.mkdir()
            (source_root / "app.py").write_text(
                "\n".join(
                    [
                        "from fastapi import FastAPI",
                        "app = FastAPI()",
                        "@app.post('/sales/leads')",
                        "def create_lead(payload):",
                        "    return {'ok': True}",
                    ]
                ),
                encoding="utf-8",
            )
            crewai = _load_crewai()
            state = _tool_state(source_root)

            load_tool = _build_load_evidence_ref_tool(crewai, state)
            search_tool = _build_source_search_tool(crewai, state)
            read_tool = _build_source_read_slice_tool(crewai, state)

            loaded = json.loads(load_tool._run("src_sales"))
            search = json.loads(search_tool._run("src_sales", "create_lead"))
            read = json.loads(read_tool._run("src_sales", start_line=3, end_line=5))
            unknown = json.loads(search_tool._run("src_unknown", "create_lead"))
            escaped = json.loads(read_tool._run("src_sales", relative_path="../outside.py"))

        self.assertEqual(loaded["path"], "app.py")
        self.assertEqual(search["matches"][0]["path"], "app.py")
        self.assertEqual(search["matches"][0]["line"], 4)
        self.assertIn("@app.post('/sales/leads')", read["content"])
        self.assertEqual(unknown["error"], "source ref has no readable local source root")
        self.assertEqual(escaped["error"], "source slice path escapes source root")

    def test_live_endpoint_metadata_tool_rejects_unknown_refs_and_unsafe_methods(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            crewai = _load_crewai()
            state = _tool_state(Path(directory))
            out_of_scope_asset = EngagementAsset(id="asset_live_1", type="live_url", locator="https://app.example.test")
            state.tool_context.live_refs["live_external"] = LiveEndpoint(
                asset=out_of_scope_asset,
                method="ANY",
                url="https://other.invalid/api",
                path="/api",
                status=200,
                source_kind="crawled_page",
            )
            tool = _build_live_endpoint_metadata_tool(crewai, state)

            unknown = json.loads(tool._run("live_unknown"))
            unsafe = json.loads(tool._run("live_sales", method="POST"))
            blocked = json.loads(tool._run("live_external", method="HEAD"))

        self.assertEqual(unknown["error"], "unknown live endpoint ref")
        self.assertEqual(unsafe["error"], "live_endpoint_metadata only allows HEAD, GET, or OPTIONS")
        self.assertTrue(blocked["blocked"])
        self.assertEqual(blocked["error"], "endpoint URL is outside asset scope")


def _tool_state(source_root: Path) -> EvidenceLinkerState:
    source_asset = EngagementAsset(id="asset_source_1", type="source_tree", locator=str(source_root))
    live_asset = EngagementAsset(id="asset_live_1", type="live_url", locator="https://app.example.test")
    source_route = SourceRoute(
        asset=source_asset,
        method="POST",
        route="/sales/leads",
        source_path="app.py",
        line=3,
        handler="create_lead",
        framework="python",
        snippet_hash=None,
        route_resolution_confidence="high",
    )
    live_endpoint = LiveEndpoint(
        asset=live_asset,
        method="ANY",
        url="https://app.example.test/api/v1/sales/leads",
        path="/api/v1/sales/leads",
        status=200,
        source_kind="crawled_page",
    )
    return EvidenceLinkerState(
        tool_context=EvidenceLinkerToolContext(
            source_refs={"src_sales": source_route},
            live_refs={"live_sales": live_endpoint},
        )
    )


if __name__ == "__main__":
    unittest.main()
