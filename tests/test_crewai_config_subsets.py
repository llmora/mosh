from __future__ import annotations

import unittest
from importlib import resources

from mosh.crews.discovery.crew import CREW_CONFIG_PACKAGE


class CrewAIConfigSubsetTests(unittest.TestCase):
    def test_security_planning_subcrew_configs_match_full_yaml_blocks(self) -> None:
        self._assert_subset_matches("security_planning", "agents.yaml", "planner_agents.yaml", ["planner"])
        self._assert_subset_matches("security_planning", "tasks.yaml", "planner_tasks.yaml", ["draft_security_test_plan_task"])
        self._assert_subset_matches("security_planning", "agents.yaml", "critic_agents.yaml", ["reviewer"])
        self._assert_subset_matches(
            "security_planning",
            "tasks.yaml",
            "critic_tasks.yaml",
            ["critique_security_test_plan_task"],
        )
        self._assert_subset_matches("security_planning", "agents.yaml", "reporter_agents.yaml", ["reporter"])
        self._assert_subset_matches(
            "security_planning",
            "tasks.yaml",
            "reporter_tasks.yaml",
            ["write_security_test_plan_task"],
        )
        self._assert_subset_matches(
            "security_planning",
            "agents.yaml",
            "engagement_refiner_agents.yaml",
            ["engagement_refiner"],
        )
        self._assert_subset_matches(
            "security_planning",
            "tasks.yaml",
            "engagement_refiner_tasks.yaml",
            ["refine_engagement_template_task"],
        )

    def test_security_testing_subcrew_configs_match_full_yaml_blocks(self) -> None:
        self._assert_subset_matches("security_testing", "agents.yaml", "executor_agents.yaml", ["executor"])
        self._assert_subset_matches("security_testing", "tasks.yaml", "executor_tasks.yaml", ["execute_security_test_task"])
        self._assert_subset_matches("security_testing", "agents.yaml", "reviewer_agents.yaml", ["reviewer"])
        self._assert_subset_matches(
            "security_testing",
            "tasks.yaml",
            "reviewer_tasks.yaml",
            ["review_security_test_evidence_task"],
        )
        self._assert_subset_matches("security_testing", "agents.yaml", "reporter_agents.yaml", ["reporter"])
        self._assert_subset_matches(
            "security_testing",
            "tasks.yaml",
            "reporter_tasks.yaml",
            ["write_executed_security_test_report_task"],
        )

    def test_final_reporting_subcrew_configs_match_full_yaml_blocks(self) -> None:
        self._assert_subset_matches("reporting", "agents.yaml", "writer_agents.yaml", ["writer"])
        self._assert_subset_matches("reporting", "tasks.yaml", "writer_tasks.yaml", ["write_final_report_task"])
        self._assert_subset_matches("reporting", "agents.yaml", "reviewer_agents.yaml", ["reviewer"])
        self._assert_subset_matches("reporting", "tasks.yaml", "reviewer_tasks.yaml", ["review_final_report_task"])

    def _assert_subset_matches(self, crew: str, full_file: str, subset_file: str, keys: list[str]) -> None:
        full_text = resources.files(CREW_CONFIG_PACKAGE).joinpath(f"{crew}/{full_file}").read_text(encoding="utf-8")
        subset_text = resources.files(CREW_CONFIG_PACKAGE).joinpath(f"{crew}/{subset_file}").read_text(
            encoding="utf-8"
        )

        self.assertEqual(_select_blocks(full_text, keys), subset_text)


def _select_blocks(source: str, keys: list[str]) -> str:
    blocks: dict[str, list[str]] = {}
    current_key: str | None = None
    current_block: list[str] = []
    for line in source.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            if current_key is not None:
                blocks[current_key] = current_block
            current_key = line.rstrip()[:-1]
            current_block = [line]
        elif current_key is not None:
            current_block.append(line)
    if current_key is not None:
        blocks[current_key] = current_block
    missing = [key for key in keys if key not in blocks]
    if missing:
        raise KeyError(f"Missing YAML config block(s): {', '.join(missing)}")
    return "\n\n".join("\n".join(blocks[key]).rstrip() for key in keys) + "\n"


if __name__ == "__main__":
    unittest.main()
