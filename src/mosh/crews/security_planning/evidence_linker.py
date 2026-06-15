from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Any

from mosh.config import AppConfig
from mosh.crews.discovery.crew import CREW_CONFIG_PACKAGE, CrewAIUnavailable, _llm, _load_crewai


@dataclass
class EvidenceLinkerState:
    candidates: dict[str, Any] | None = None


class CrewAIModelAssistedEvidenceLinker:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        model = config.models.security_planning.evidence_linker
        self.model_metadata = {
            "crew": "security_planning",
            "agent": "evidence_linker",
            "model": config.llm_model_name(model),
            "provider": config.llm_provider_for_model(model),
        }

    def suggest_links(self, context: dict[str, Any]) -> dict[str, Any]:
        if not context.get("pairs"):
            return {"links": []}
        model = self.config.models.security_planning.evidence_linker
        missing_keys = self.config.missing_llm_api_keys_for_models([model])
        if missing_keys:
            raise CrewAIUnavailable(f"Missing LLM API key(s): {', '.join(missing_keys)}.")

        crewai = _load_crewai()
        state = EvidenceLinkerState()
        crew = _build_evidence_linker_crew(crewai, self.config, state)
        crew.crew().kickoff(inputs={"link_context": json.dumps(context, sort_keys=True)})
        if state.candidates is None:
            raise RuntimeError("Evidence linker did not submit candidate links.")
        return state.candidates


def build_model_assisted_linker(config: AppConfig) -> CrewAIModelAssistedEvidenceLinker:
    return CrewAIModelAssistedEvidenceLinker(config)


def _build_evidence_linker_crew(crewai: Any, config: AppConfig, state: EvidenceLinkerState):
    submit_tool = _build_submit_evidence_link_candidates_tool(crewai, state)
    agents_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("security_planning/evidence_linker_agents.yaml"))
    tasks_path = str(resources.files(CREW_CONFIG_PACKAGE).joinpath("security_planning/evidence_linker_tasks.yaml"))

    @crewai.CrewBase
    class EvidenceLinkerCrew:
        agents_config = agents_path
        tasks_config = tasks_path

        @crewai.agent
        def evidence_linker(self):
            return crewai.Agent(
                config=self.agents_config["evidence_linker"],
                llm=_llm(crewai, config, config.models.security_planning.evidence_linker),
                tools=[submit_tool],
                allow_delegation=False,
            )

        @crewai.task
        def suggest_evidence_link_candidates_task(self):
            return crewai.Task(
                config=self.tasks_config["suggest_evidence_link_candidates_task"],
                agent=self.evidence_linker(),
            )

        @crewai.crew
        def crew(self):
            return crewai.Crew(
                agents=[self.evidence_linker()],
                tasks=[self.suggest_evidence_link_candidates_task()],
                process=crewai.Process.sequential,
                verbose=True,
            )

    return EvidenceLinkerCrew()


def _build_submit_evidence_link_candidates_tool(crewai: Any, state: EvidenceLinkerState):
    class SubmitEvidenceLinkCandidatesInput(crewai.BaseModel):
        candidates: dict[str, Any] | str = crewai.Field(
            ...,
            description="Candidate source/live evidence links using only source_ref_id and live_ref_id values from the input.",
        )

    class SubmitEvidenceLinkCandidatesTool(crewai.BaseTool):
        name: str = "submit_evidence_link_candidates"
        description: str = "Submit model-assisted source/live evidence link candidates."
        args_schema: type[crewai.BaseModel] = SubmitEvidenceLinkCandidatesInput

        def _run(self, candidates: Any) -> str:
            normalized = _normalize_candidate_payload(_coerce_mapping(candidates))
            state.candidates = normalized
            return json.dumps({"candidate_links": len(normalized.get("links") or [])}, sort_keys=True)

    return SubmitEvidenceLinkCandidatesTool()


def _normalize_candidate_payload(value: dict[str, Any]) -> dict[str, Any]:
    links = value.get("links") if isinstance(value.get("links"), list) else []
    normalized_links = []
    for item in links:
        if not isinstance(item, dict):
            continue
        source_ref_id = _text(item.get("source_ref_id"))
        live_ref_id = _text(item.get("live_ref_id"))
        if not source_ref_id or not live_ref_id:
            continue
        normalized_links.append(
            {
                "source_ref_id": source_ref_id,
                "live_ref_id": live_ref_id,
                "confidence": _normalize_confidence(item.get("confidence")),
                "reason": _text(item.get("reason"))[:600],
            }
        )
    return {"links": normalized_links[:100]}


def _normalize_confidence(value: Any) -> str:
    confidence = _text(value).lower()
    if confidence in {"low", "medium", "high"}:
        return confidence
    return "low"


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
        text = value.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {"content": text}
        return parsed if isinstance(parsed, dict) else {"content": parsed}
    return {"content": value}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""
