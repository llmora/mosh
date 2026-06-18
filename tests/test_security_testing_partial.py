import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mosh.memory import FileMemory
from mosh.crews.testing.crew import _run_one_security_test, _safe_test_id


class _FakeCrew:
    """Minimal stand-in for a CrewAI crew wrapper.

    Calling ``.crew().kickoff(inputs=...)`` either does nothing (so the
    surrounding fallback logic runs) or raises, depending on ``raise_on_kickoff``.
    """

    def __init__(self, *, raise_on_kickoff: bool = False) -> None:
        self._raise_on_kickoff = raise_on_kickoff
        self.kickoff_count = 0

    def crew(self) -> "_FakeCrew":
        return self

    def kickoff(self, *, inputs):  # noqa: ARG002 - inputs unused by the fake
        self.kickoff_count += 1
        if self._raise_on_kickoff:
            raise RuntimeError("Reviewer LLM unavailable")
        return None


class PartialTestResultsTest(unittest.TestCase):
    def test_report_written_when_reviewer_crew_raises(self) -> None:
        hypothesis = {
            "id": "API-001",
            "title": "Unauthenticated private API access is rejected",
            "surface": "api",
            "priority": "critical",
        }
        config = SimpleNamespace(security_execution_max_revisions=0)

        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            memory = FileMemory(report_dir)

            # Executor and reporter crews are no-ops so the executor evidence
            # and reporter report both take their fallback paths. The reviewer
            # crew raises to simulate an LLM/crew failure with no captured review.
            with (
                patch(
                    "mosh.crews.testing.crew._build_executor_crew",
                    return_value=_FakeCrew(),
                ),
                patch(
                    "mosh.crews.testing.crew._build_reviewer_crew",
                    return_value=_FakeCrew(raise_on_kickoff=True),
                ),
                patch(
                    "mosh.crews.testing.crew._build_reporter_crew",
                    return_value=_FakeCrew(),
                ),
            ):
                _run_one_security_test(
                    crewai=object(),
                    config=config,
                    target_url="https://example.test",
                    source=None,
                    source_root=None,
                    source_context={},
                    evidence_links={},
                    report_dir=report_dir,
                    memory=memory,
                    hypothesis=hypothesis,
                    engagement={},
                    targets={},
                    plan_revision_id="rev-1",
                )

            report_path = (
                report_dir / "executed_tests" / f"{_safe_test_id('API-001')}.md"
            )
            self.assertTrue(
                report_path.exists(),
                "A report file must be written even when the reviewer crew fails.",
            )
            contents = report_path.read_text(encoding="utf-8")
            self.assertIn("Reviewer unavailable due to crew failure.", contents)

    def test_reviewer_crew_failure_does_not_retry_executor(self) -> None:
        hypothesis = {
            "id": "API-001",
            "title": "Unauthenticated private API access is rejected",
            "surface": "api",
            "priority": "critical",
        }
        config = SimpleNamespace(security_execution_max_revisions=2)

        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp)
            memory = FileMemory(report_dir)
            executor_crew = _FakeCrew()
            reviewer_crew = _FakeCrew(raise_on_kickoff=True)

            with (
                patch(
                    "mosh.crews.testing.crew._build_executor_crew",
                    return_value=executor_crew,
                ),
                patch(
                    "mosh.crews.testing.crew._build_reviewer_crew",
                    return_value=reviewer_crew,
                ),
                patch(
                    "mosh.crews.testing.crew._build_reporter_crew",
                    return_value=_FakeCrew(),
                ),
            ):
                _run_one_security_test(
                    crewai=object(),
                    config=config,
                    target_url="https://example.test",
                    source=None,
                    source_root=None,
                    source_context={},
                    evidence_links={},
                    report_dir=report_dir,
                    memory=memory,
                    hypothesis=hypothesis,
                    engagement={},
                    targets={},
                    plan_revision_id="rev-1",
                )

            report_path = (
                report_dir / "executed_tests" / f"{_safe_test_id('API-001')}.md"
            )
            self.assertEqual(1, executor_crew.kickoff_count)
            self.assertTrue(report_path.exists())
            contents = report_path.read_text(encoding="utf-8")
            self.assertIn("Reviewer unavailable due to crew failure.", contents)


if __name__ == "__main__":
    unittest.main()
