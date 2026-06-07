from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Callable, Protocol

from appsec_harness.agents import AgentDefinition
from appsec_harness.config import AppConfig
from appsec_harness.discovery_crew import (
    CREW_CONFIG_PACKAGE,
    CrewAIUnavailable,
    _build_task_with_output_event,
    _llm,
    _load_crewai,
)
from appsec_harness.engagement import build_engagement_template, write_engagement_template_mapping
from appsec_harness.memory import FileMemory
from appsec_harness.models import Event
from appsec_harness.scope import report_dir_name
from appsec_harness.security_test_planning_reporting import write_security_test_plan


@dataclass
class SecurityTestPlanningState:
    target_url: str
    discovery_dir: Path
    report_dir: Path
    memory: FileMemory
    discovery_context: dict[str, Any]
    current_plan: dict[str, Any] | None = None
    current_review: dict[str, Any] | None = None
    accepted: bool = False
    iterations: int = 0


@dataclass(frozen=True)
class SecurityTestPlanningResult:
    plan: dict[str, Any]
    critic_review: dict[str, Any] | None
    accepted: bool
    iterations: int


class SecurityTestPlanningCrewRunner(Protocol):
    def run(
        self,
        target_url: str,
        discovery_dir: Path,
        report_dir: Path,
        memory: FileMemory,
    ) -> SecurityTestPlanningResult:
        pass


def security_test_planning_agent_definitions(config: AppConfig) -> list[AgentDefinition]:
    return [
        AgentDefinition(
            name="orchestrator",
            role="Security test planning coordinator",
            goal="Coordinate security test planning work and persist planner/critic/finalizer outputs.",
            model=config.models.orchestrator,
        ),
        AgentDefinition(
            name="security_test_planner",
            role="Security test hypothesis planner",
            goal="Turn discovery findings into detailed, evidence-backed security test hypotheses.",
            model=config.models.security_test_planner,
        ),
        AgentDefinition(
            name="security_test_critic",
            role="Security test plan critic",
            goal="Review test hypotheses for clarity, evidence, scope, safety, and missing requirements.",
            model=config.models.security_test_critic,
        ),
        AgentDefinition(
            name="security_test_finalizer",
            role="Security test plan finalizer",
            goal="Persist the agreed planning output as a stable Markdown security test plan.",
            model=config.models.security_test_finalizer,
        ),
        AgentDefinition(
            name="engagement_template_refiner",
            role="Engagement template refiner",
            goal="Refine the generated engagement template for security test execution.",
            model=config.models.engagement_template_refiner,
        ),
    ]


class CrewAISecurityTestPlanningCrewRunner:
    def __init__(self, config: AppConfig) -> None:
        self.config = config

    def run(
        self,
        target_url: str,
        discovery_dir: Path,
        report_dir: Path,
        memory: FileMemory,
    ) -> SecurityTestPlanningResult:
        if not self.config.openrouter_api_key:
            raise CrewAIUnavailable("OPENROUTER_API_KEY is not set.")

        discovery_context = load_discovery_context(discovery_dir)
        crewai = _load_crewai()
        state = SecurityTestPlanningState(
            target_url=target_url,
            discovery_dir=discovery_dir,
            report_dir=report_dir,
            memory=memory,
            discovery_context=discovery_context,
        )

        memory.record_event(
            "orchestrator",
            "crew_start",
            "Starting CrewAI security test planning crew",
            {"target": target_url, "discovery_dir": str(discovery_dir)},
        )

        max_attempts = self.config.planning_max_revisions + 1
        previous_plan: dict[str, Any] | None = None
        previous_review: dict[str, Any] | None = None
        for iteration in range(1, max_attempts + 1):
            state.current_plan = None
            state.current_review = None
            state.iterations = iteration
            planner_crew = _build_planning_planner_crew(crewai, self.config, state)
            planner_crew.crew().kickoff(
                inputs={
                    "target_url": target_url,
                    "iteration": iteration,
                    "max_attempts": max_attempts,
                    "discovery_context": json.dumps(discovery_context, sort_keys=True),
                    "previous_plan": json.dumps(previous_plan or {}, sort_keys=True),
                    "previous_critique": json.dumps(previous_review or {}, sort_keys=True),
                }
            )
            if state.current_plan is None:
                raise RuntimeError("Security test planner did not submit a plan.")

            critic_crew = _build_planning_critic_crew(crewai, self.config, state)
            critic_crew.crew().kickoff(
                inputs={
                    "target_url": target_url,
                    "iteration": iteration,
                    "max_attempts": max_attempts,
                    "security_test_plan": json.dumps(state.current_plan, sort_keys=True),
                }
            )
            if state.current_review is None:
                raise RuntimeError("Security test critic did not submit a review.")
            previous_plan = state.current_plan
            previous_review = state.current_review
            state.accepted = bool(state.current_review.get("accepted"))
            if state.accepted:
                break

        if state.current_plan is None:
            raise RuntimeError("Security test planner did not produce a plan.")

        deterministic_engagement_template = build_engagement_template(target_url, state.current_plan)
        engagement_template = write_engagement_template_mapping(report_dir, deterministic_engagement_template)
        memory.record_event(
            "orchestrator",
            "engagement_template_written",
            "Wrote deterministic engagement template before finalization",
            {"bytes": len(engagement_template.encode("utf-8"))},
        )

        final_crew = _build_planning_finalizer_crew(crewai, self.config, state)
        final_crew.crew().kickoff(
            inputs={
                "target_url": target_url,
                "accepted": state.accepted,
                "iterations": state.iterations,
                "security_test_plan": json.dumps(state.current_plan, sort_keys=True),
                "critic_review": json.dumps(state.current_review or {}, sort_keys=True),
            }
        )

        if self.config.refine_engagement_template_with_llm:
            try:
                refinement_crew = _build_engagement_template_refinement_crew(
                    crewai,
                    self.config,
                    state,
                    deterministic_engagement_template,
                )
                refinement_crew.crew().kickoff(
                    inputs={
                        "target_url": target_url,
                        "security_test_plan": json.dumps(state.current_plan, sort_keys=True),
                        "engagement_template": json.dumps(deterministic_engagement_template, sort_keys=True),
                    }
                )
                if not (report_dir / "engagement_template.yaml").exists():
                    engagement_template = write_engagement_template_mapping(report_dir, deterministic_engagement_template)
                    memory.record_event(
                        "engagement_template_refiner",
                        "refinement_missing",
                        "Engagement template refiner did not write a template; wrote deterministic fallback",
                        {"bytes": len(engagement_template.encode("utf-8"))},
                    )
            except Exception as exc:
                engagement_template = write_engagement_template_mapping(report_dir, deterministic_engagement_template)
                memory.record_event(
                    "engagement_template_refiner",
                    "refinement_failed",
                    "Engagement template refinement failed; wrote deterministic fallback",
                    {"error": str(exc), "bytes": len(engagement_template.encode("utf-8"))},
                )
        else:
            memory.record_event(
                "orchestrator",
                "engagement_template_refinement_skipped",
                "Skipped LLM engagement template refinement",
                {"reason": "disabled"},
            )

        memory.record_event(
            "orchestrator",
            "crew_complete",
            "CrewAI security test planning crew completed",
            {"target": target_url, "accepted": state.accepted, "iterations": state.iterations},
        )
        return SecurityTestPlanningResult(
            plan=state.current_plan,
            critic_review=state.current_review,
            accepted=state.accepted,
            iterations=state.iterations,
        )


def build_security_test_planning_crew_runner(config: AppConfig) -> SecurityTestPlanningCrewRunner:
    return CrewAISecurityTestPlanningCrewRunner(config)


class SecurityTestPlanningOrchestrator:
    def __init__(
        self,
        config: AppConfig,
        output_root: Path = Path("report"),
        event_sink: Callable[[Event], None] | None = None,
        crew_runner: SecurityTestPlanningCrewRunner | None = None,
    ) -> None:
        self.config = config
        self.output_root = output_root
        self.event_sink = event_sink
        self.crew_runner = crew_runner or build_security_test_planning_crew_runner(config)

    def run(self, url: str) -> Path:
        domain_dir = self.output_root / report_dir_name(url)
        discovery_dir = domain_dir / "discovery"
        report_dir = domain_dir / "security-test-planning"
        memory = FileMemory(report_dir, event_sink=self.event_sink)
        agent_definitions = security_test_planning_agent_definitions(self.config)
        memory.record_event(
            "orchestrator",
            "start",
            "Starting security test planning crew",
            {
                "target": url,
                "discovery_dir": str(discovery_dir),
                "agents": [agent.to_dict() for agent in agent_definitions],
            },
        )
        result = self.crew_runner.run(url, discovery_dir, report_dir, memory)
        engagement_path = report_dir / "engagement_template.yaml"
        if not engagement_path.exists():
            engagement_template = write_engagement_template_mapping(report_dir, build_engagement_template(url, result.plan))
            memory.record_event(
                "orchestrator",
                "engagement_template_written",
                "Wrote deterministic engagement template",
                {"bytes": len(engagement_template.encode("utf-8"))},
            )
        memory.add_item(
            "engagement_template",
            {
                "path": str(engagement_path),
                "bytes": engagement_path.stat().st_size,
            },
            "orchestrator",
        )
        memory.record_event(
            "orchestrator",
            "complete",
            "Security test planning crew completed",
            {"report_dir": str(report_dir)},
        )
        return report_dir


def load_discovery_context(discovery_dir: Path) -> dict[str, Any]:
    if not discovery_dir.exists():
        raise FileNotFoundError(f"Discovery output not found: {discovery_dir}")
    return {
        "report_markdown": _read_text(discovery_dir / "report.md"),
        "memory": _read_json(discovery_dir / "memory.json", []),
        "events": _read_json(discovery_dir / "events.json", []),
    }


def _build_planning_planner_crew(crewai: Any, config: AppConfig, state: SecurityTestPlanningState):
    plan_tool = _build_submit_plan_tool(crewai, state)
    agents_path, tasks_path = _write_security_planning_subset_configs(
        state.report_dir,
        "planner",
        agent_keys=["security_test_planner"],
        task_keys=["draft_security_test_plan_task"],
    )

    @crewai.CrewBase
    class SecurityTestPlanningPlannerCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def security_test_planner(self):
            return crewai.Agent(
                config=self.agents_config["security_test_planner"],
                llm=_llm(crewai, config.models.security_test_planner, config.openrouter_api_key),
                tools=[plan_tool],
                allow_delegation=False,
            )

        @crewai.task
        def draft_security_test_plan_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["draft_security_test_plan_task"],
                agent=self.security_test_planner(),
                agent_name="security_test_planner",
                task_name="draft_security_test_plan_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.security_test_planner()],
                tasks=[self.draft_security_test_plan_task()],
                process=crewai.Process.sequential,
                verbose=True,
            )

    return SecurityTestPlanningPlannerCrew()


def _build_planning_critic_crew(crewai: Any, config: AppConfig, state: SecurityTestPlanningState):
    critique_tool = _build_submit_critique_tool(crewai, state)
    agents_path, tasks_path = _write_security_planning_subset_configs(
        state.report_dir,
        "critic",
        agent_keys=["security_test_critic"],
        task_keys=["critique_security_test_plan_task"],
    )

    @crewai.CrewBase
    class SecurityTestPlanningCriticCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def security_test_critic(self):
            return crewai.Agent(
                config=self.agents_config["security_test_critic"],
                llm=_llm(crewai, config.models.security_test_critic, config.openrouter_api_key),
                tools=[critique_tool],
                allow_delegation=False,
            )

        @crewai.task
        def critique_security_test_plan_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["critique_security_test_plan_task"],
                agent=self.security_test_critic(),
                agent_name="security_test_critic",
                task_name="critique_security_test_plan_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.security_test_critic()],
                tasks=[self.critique_security_test_plan_task()],
                process=crewai.Process.sequential,
                verbose=True,
            )

    return SecurityTestPlanningCriticCrew()


def _build_planning_finalizer_crew(crewai: Any, config: AppConfig, state: SecurityTestPlanningState):
    write_tool = _build_write_security_test_plan_tool(crewai, state)
    agents_path, tasks_path = _write_security_planning_subset_configs(
        state.report_dir,
        "finalizer",
        agent_keys=["security_test_finalizer"],
        task_keys=["write_security_test_plan_task"],
    )

    @crewai.CrewBase
    class SecurityTestPlanningFinalizerCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def security_test_finalizer(self):
            return crewai.Agent(
                config=self.agents_config["security_test_finalizer"],
                llm=_llm(crewai, config.models.security_test_finalizer, config.openrouter_api_key),
                tools=[write_tool],
                allow_delegation=False,
            )

        @crewai.task
        def write_security_test_plan_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["write_security_test_plan_task"],
                agent=self.security_test_finalizer(),
                agent_name="security_test_finalizer",
                task_name="write_security_test_plan_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.security_test_finalizer()],
                tasks=[self.write_security_test_plan_task()],
                process=crewai.Process.sequential,
                verbose=True,
            )

    return SecurityTestPlanningFinalizerCrew()


def _build_engagement_template_refinement_crew(
    crewai: Any,
    config: AppConfig,
    state: SecurityTestPlanningState,
    deterministic_template: dict[str, Any],
):
    write_tool = _build_write_refined_engagement_template_tool(crewai, state, deterministic_template)
    agents_path, tasks_path = _write_security_planning_subset_configs(
        state.report_dir,
        "engagement_refiner",
        agent_keys=["engagement_template_refiner"],
        task_keys=["refine_engagement_template_task"],
    )

    @crewai.CrewBase
    class EngagementTemplateRefinementCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def engagement_template_refiner(self):
            return crewai.Agent(
                config=self.agents_config["engagement_template_refiner"],
                llm=_llm(crewai, config.models.engagement_template_refiner, config.openrouter_api_key),
                tools=[write_tool],
                allow_delegation=False,
            )

        @crewai.task
        def refine_engagement_template_task(self):
            return _build_task_with_output_event(
                crewai,
                state,
                config=self.tasks_config["refine_engagement_template_task"],
                agent=self.engagement_template_refiner(),
                agent_name="engagement_template_refiner",
                task_name="refine_engagement_template_task",
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.engagement_template_refiner()],
                tasks=[self.refine_engagement_template_task()],
                process=crewai.Process.sequential,
                verbose=True,
            )

    return EngagementTemplateRefinementCrew()


def _write_security_planning_subset_configs(
    report_dir: Path,
    name: str,
    agent_keys: list[str],
    task_keys: list[str],
) -> tuple[str, str]:
    config_dir = report_dir / ".crew_config"
    config_dir.mkdir(parents=True, exist_ok=True)
    source_agents = resources.files(CREW_CONFIG_PACKAGE).joinpath("security_planning/agents.yaml").read_text(
        encoding="utf-8"
    )
    source_tasks = resources.files(CREW_CONFIG_PACKAGE).joinpath("security_planning/tasks.yaml").read_text(
        encoding="utf-8"
    )
    agents_path = config_dir / f"{name}_agents.yaml"
    tasks_path = config_dir / f"{name}_tasks.yaml"
    agents_path.write_text(_select_yaml_top_level_blocks(source_agents, agent_keys), encoding="utf-8")
    tasks_path.write_text(_select_yaml_top_level_blocks(source_tasks, task_keys), encoding="utf-8")
    return str(agents_path.resolve()), str(tasks_path.resolve())


def _select_yaml_top_level_blocks(source: str, keys: list[str]) -> str:
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
        raise KeyError(f"Missing security planning YAML config block(s): {', '.join(missing)}")
    return "\n\n".join("\n".join(blocks[key]).rstrip() for key in keys) + "\n"


def _build_submit_plan_tool(crewai: Any, state: SecurityTestPlanningState):
    class SubmitPlanInput(crewai.BaseModel):
        plan: dict[str, Any] | str = crewai.Field(
            ...,
            description="Structured security test plan. Prefer a JSON object; a JSON string is accepted.",
        )

    class SubmitSecurityTestPlanTool(crewai.BaseTool):
        name: str = "submit_security_test_plan"
        description: str = "Submit the planner's structured security test hypotheses for critic review."
        args_schema: type[crewai.BaseModel] = SubmitPlanInput

        def _run(self, plan: Any) -> str:
            plan_content = _coerce_mapping(plan)
            state.current_plan = plan_content
            state.memory.add_item(
                "security_test_plan_draft",
                {"iteration": state.iterations, "structured": plan_content},
                "security_test_planner",
            )
            state.memory.record_event(
                "security_test_planner",
                "plan_submitted",
                "Security test planner submitted draft plan",
                {
                    "iteration": state.iterations,
                    "hypotheses": len(_list(plan_content.get("test_hypotheses"))),
                    "keys": sorted(plan_content.keys()),
                },
            )
            return json.dumps(
                {
                    "accepted": True,
                    "iteration": state.iterations,
                    "hypotheses": len(_list(plan_content.get("test_hypotheses"))),
                },
                sort_keys=True,
            )

    return SubmitSecurityTestPlanTool()


def _build_submit_critique_tool(crewai: Any, state: SecurityTestPlanningState):
    class SubmitCritiqueInput(crewai.BaseModel):
        review: dict[str, Any] | str = crewai.Field(
            ...,
            description="Structured critic review with accepted, summary, blocking_findings, and suggestions.",
        )

    class SubmitSecurityTestPlanCritiqueTool(crewai.BaseTool):
        name: str = "submit_security_test_plan_critique"
        description: str = "Submit the critic's structured review of the current security test plan."
        args_schema: type[crewai.BaseModel] = SubmitCritiqueInput

        def _run(self, review: Any) -> str:
            review_content = _coerce_mapping(review)
            review_content.setdefault("accepted", False)
            state.current_review = review_content
            state.memory.add_item(
                "security_test_plan_critique",
                {"iteration": state.iterations, "structured": review_content},
                "security_test_critic",
            )
            state.memory.record_event(
                "security_test_critic",
                "critique_submitted",
                "Security test critic submitted plan review",
                {
                    "iteration": state.iterations,
                    "accepted": bool(review_content.get("accepted")),
                    "blocking_findings": len(_list(review_content.get("blocking_findings"))),
                },
            )
            return json.dumps(
                {
                    "accepted": bool(review_content.get("accepted")),
                    "iteration": state.iterations,
                    "blocking_findings": len(_list(review_content.get("blocking_findings"))),
                },
                sort_keys=True,
            )

    return SubmitSecurityTestPlanCritiqueTool()


def _build_write_security_test_plan_tool(crewai: Any, state: SecurityTestPlanningState):
    class WritePlanInput(crewai.BaseModel):
        plan: dict[str, Any] | str = crewai.Field(..., description="Final structured security test plan.")
        critic_review: dict[str, Any] | str | None = crewai.Field(default=None, description="Final critic review.")

    class WriteSecurityTestPlanTool(crewai.BaseTool):
        name: str = "write_security_test_plan"
        description: str = "Persist the final security test plan as stable Markdown."
        args_schema: type[crewai.BaseModel] = WritePlanInput

        def _run(self, plan: Any, critic_review: Any = None) -> str:
            plan_content = _prefer_structured_mapping(_coerce_mapping(plan), state.current_plan)
            review_content = (
                _prefer_structured_mapping(_coerce_mapping(critic_review), state.current_review)
                if critic_review is not None
                else state.current_review
            )
            state.current_plan = plan_content
            state.current_review = review_content
            markdown = write_security_test_plan(
                state.report_dir,
                state.target_url,
                plan_content,
                review_content,
                accepted=state.accepted,
                iterations=state.iterations,
            )
            state.memory.add_item(
                "security_test_plan_final",
                {
                    "accepted": state.accepted,
                    "iterations": state.iterations,
                    "structured": plan_content,
                    "critic_review": review_content,
                },
                "security_test_finalizer",
            )
            state.memory.record_event(
                "security_test_finalizer",
                "plan_written",
                "Security test finalizer wrote Markdown plan",
                {
                    "report_dir": str(state.report_dir),
                    "accepted": state.accepted,
                    "iterations": state.iterations,
                    "markdown_bytes": len(markdown.encode("utf-8")),
                },
            )
            return json.dumps(
                {
                    "report_dir": str(state.report_dir),
                    "accepted": state.accepted,
                    "iterations": state.iterations,
                    "markdown_bytes": len(markdown.encode("utf-8")),
                },
                sort_keys=True,
            )

    return WriteSecurityTestPlanTool()


def _build_write_refined_engagement_template_tool(
    crewai: Any,
    state: SecurityTestPlanningState,
    deterministic_template: dict[str, Any],
):
    class WriteEngagementTemplateInput(crewai.BaseModel):
        template: dict[str, Any] | str = crewai.Field(
            ...,
            description="Refined engagement template. Prefer a JSON object; a JSON string is accepted.",
        )

    class WriteRefinedEngagementTemplateTool(crewai.BaseTool):
        name: str = "write_refined_engagement_template"
        description: str = "Persist a validated engagement_template.yaml for security test execution."
        args_schema: type[crewai.BaseModel] = WriteEngagementTemplateInput

        def _run(self, template: Any) -> str:
            candidate = _coerce_mapping(template)
            fallback_used = False
            try:
                engagement_template = write_engagement_template_mapping(state.report_dir, candidate)
            except ValueError as exc:
                fallback_used = True
                engagement_template = write_engagement_template_mapping(state.report_dir, deterministic_template)
                state.memory.record_event(
                    "engagement_template_refiner",
                    "refinement_rejected",
                    "Refined engagement template was invalid; wrote deterministic fallback",
                    {"error": str(exc)},
                )
            state.memory.add_item(
                "engagement_template_refinement",
                {
                    "path": str(state.report_dir / "engagement_template.yaml"),
                    "bytes": len(engagement_template.encode("utf-8")),
                    "fallback_used": fallback_used,
                },
                "engagement_template_refiner",
            )
            state.memory.record_event(
                "engagement_template_refiner",
                "engagement_template_written",
                "Engagement template refiner wrote engagement_template.yaml",
                {
                    "bytes": len(engagement_template.encode("utf-8")),
                    "fallback_used": fallback_used,
                },
            )
            return json.dumps(
                {
                    "path": str(state.report_dir / "engagement_template.yaml"),
                    "bytes": len(engagement_template.encode("utf-8")),
                    "fallback_used": fallback_used,
                },
                sort_keys=True,
            )

    return WriteRefinedEngagementTemplateTool()


def _read_json(path: Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    return json.loads(path.read_text(encoding="utf-8"))


def _read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _coerce_mapping(value: Any | None) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(mode="json")
        return dumped if isinstance(dumped, dict) else {"content": dumped}
    if hasattr(value, "dict"):
        dumped = value.dict()
        return dumped if isinstance(dumped, dict) else {"content": dumped}
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return {}
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"content": value}
        return parsed if isinstance(parsed, dict) else {"content": parsed}
    return {"content": value}


def _prefer_structured_mapping(candidate: dict[str, Any], fallback: dict[str, Any] | None) -> dict[str, Any]:
    if candidate and not _is_content_only_mapping(candidate):
        return candidate
    return fallback or candidate or {}


def _is_content_only_mapping(value: dict[str, Any]) -> bool:
    return set(value.keys()) == {"content"}


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
