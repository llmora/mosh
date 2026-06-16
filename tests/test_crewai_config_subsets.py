from __future__ import annotations

import unittest
from importlib import resources

from mosh.crews.discovery.crew import CREW_CONFIG_PACKAGE


class CrewAIConfigSubsetTests(unittest.TestCase):
    def test_security_planning_subcrew_configs_are_canonical(self) -> None:
        self._assert_yaml_blocks_exactly("security_planning", "evidence_linker_agents.yaml", ["evidence_linker"])
        self._assert_yaml_blocks_exactly(
            "security_planning",
            "evidence_linker_tasks.yaml",
            ["suggest_evidence_link_candidates_task"],
        )
        self._assert_yaml_blocks_exactly("security_planning", "planner_agents.yaml", ["planner"])
        self._assert_yaml_blocks_exactly("security_planning", "planner_tasks.yaml", ["draft_security_test_plan_task"])
        self._assert_yaml_blocks_exactly("security_planning", "critic_agents.yaml", ["reviewer"])
        self._assert_yaml_blocks_exactly(
            "security_planning",
            "critic_tasks.yaml",
            ["critique_security_test_plan_task"],
        )
        self._assert_yaml_blocks_exactly("security_planning", "reporter_agents.yaml", ["reporter"])
        self._assert_yaml_blocks_exactly(
            "security_planning",
            "reporter_tasks.yaml",
            ["write_security_test_plan_task"],
        )
        self._assert_yaml_blocks_exactly(
            "security_planning",
            "engagement_refiner_agents.yaml",
            ["engagement_refiner"],
        )
        self._assert_yaml_blocks_exactly(
            "security_planning",
            "engagement_refiner_tasks.yaml",
            ["refine_engagement_template_task"],
        )

    def test_security_testing_subcrew_configs_are_canonical(self) -> None:
        self._assert_yaml_blocks_exactly("security_testing", "executor_agents.yaml", ["executor"])
        self._assert_yaml_blocks_exactly("security_testing", "executor_tasks.yaml", ["execute_security_test_task"])
        self._assert_yaml_blocks_exactly("security_testing", "reviewer_agents.yaml", ["reviewer"])
        self._assert_yaml_blocks_exactly(
            "security_testing",
            "reviewer_tasks.yaml",
            ["review_security_test_evidence_task"],
        )
        self._assert_yaml_blocks_exactly("security_testing", "reporter_agents.yaml", ["reporter"])
        self._assert_yaml_blocks_exactly(
            "security_testing",
            "reporter_tasks.yaml",
            ["write_executed_security_test_report_task"],
        )

    def test_final_reporting_subcrew_configs_are_canonical(self) -> None:
        self._assert_yaml_blocks_exactly("reporting", "writer_agents.yaml", ["writer"])
        self._assert_yaml_blocks_exactly("reporting", "writer_tasks.yaml", ["write_final_report_task"])
        self._assert_yaml_blocks_exactly("reporting", "reviewer_agents.yaml", ["reviewer"])
        self._assert_yaml_blocks_exactly("reporting", "reviewer_tasks.yaml", ["review_final_report_task"])

    def _assert_yaml_blocks_exactly(self, crew: str, config_file: str, keys: list[str]) -> None:
        text = resources.files(CREW_CONFIG_PACKAGE).joinpath(f"{crew}/{config_file}").read_text(encoding="utf-8")
        self.assertEqual(_select_blocks(text, keys), text)


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
