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
            cycle_crew = _build_planning_cycle_crew(crewai, self.config, state)
            cycle_crew.crew().kickoff(
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
            if state.current_review is None:
                raise RuntimeError("Security test critic did not submit a review.")
            previous_plan = state.current_plan
            previous_review = state.current_review
            state.accepted = bool(state.current_review.get("accepted"))
            if state.accepted:
                break

        if state.current_plan is None:
            raise RuntimeError("Security test planner did not produce a plan.")

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
        self.crew_runner.run(url, discovery_dir, report_dir, memory)
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


def _build_planning_cycle_crew(crewai: Any, config: AppConfig, state: SecurityTestPlanningState):
    plan_tool = _build_submit_plan_tool(crewai, state)
    critique_tool = _build_submit_critique_tool(crewai, state)
    write_tool = _build_write_security_test_plan_tool(crewai, state)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("security_planning/agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("security_planning/tasks.yaml"))

    @crewai.CrewBase
    class SecurityTestPlanningCycleCrew:
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

        @crewai.agent
        def security_test_critic(self):
            return crewai.Agent(
                config=self.agents_config["security_test_critic"],
                llm=_llm(crewai, config.models.security_test_critic, config.openrouter_api_key),
                tools=[critique_tool],
                allow_delegation=False,
            )

        @crewai.agent
        def security_test_finalizer(self):
            return crewai.Agent(
                config=self.agents_config["security_test_finalizer"],
                llm=_llm(crewai, config.models.security_test_finalizer, config.openrouter_api_key),
                tools=[write_tool],
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
                agents=[self.security_test_planner(), self.security_test_critic()],
                tasks=[self.draft_security_test_plan_task(), self.critique_security_test_plan_task()],
                process=crewai.Process.sequential,
                verbose=True,
            )

    return SecurityTestPlanningCycleCrew()


def _build_planning_finalizer_crew(crewai: Any, config: AppConfig, state: SecurityTestPlanningState):
    plan_tool = _build_submit_plan_tool(crewai, state)
    critique_tool = _build_submit_critique_tool(crewai, state)
    write_tool = _build_write_security_test_plan_tool(crewai, state)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("security_planning/agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("security_planning/tasks.yaml"))

    @crewai.CrewBase
    class SecurityTestPlanningFinalizerCrew:
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

        @crewai.agent
        def security_test_critic(self):
            return crewai.Agent(
                config=self.agents_config["security_test_critic"],
                llm=_llm(crewai, config.models.security_test_critic, config.openrouter_api_key),
                tools=[critique_tool],
                allow_delegation=False,
            )

        @crewai.agent
        def security_test_finalizer(self):
            return crewai.Agent(
                config=self.agents_config["security_test_finalizer"],
                llm=_llm(crewai, config.models.security_test_finalizer, config.openrouter_api_key),
                tools=[write_tool],
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
