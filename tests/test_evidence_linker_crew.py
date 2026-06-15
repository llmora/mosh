from __future__ import annotations

import unittest

from mosh.config import AppConfig
from mosh.crews.discovery.crew import _load_crewai
from mosh.crews.security_planning.evidence_linker import EvidenceLinkerState, _build_evidence_linker_crew


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


if __name__ == "__main__":
    unittest.main()
