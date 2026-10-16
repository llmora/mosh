# Model-driven Open Security Harness Specification

## Goal

Build an application security testing harness that uses coordinated agents to perform appsec work and produce a final report.

The system should be built in small, testable steps. Do not over-engineer early versions, but keep the core architecture clear enough to support future crews.

## Core Architecture

The application must follow this pattern across all crews:

```text
orchestrator -> agent -> tools
```

This is an important architectural rule.

The orchestrator coordinates work between agents. It does not directly perform specialist work and must not directly call low-level tools such as crawlers, scanners, or component detectors.

Each agent owns the tools it can use. If a crawler is needed, the crawler agent invokes its crawler tool. If component inventory is needed, the SBOM/component agent invokes its own inventory tools.

This pattern applies to the current and future crews.

## Orchestrator Responsibilities

The orchestrator should:

- start and coordinate crews
- assign work to agents
- pass relevant discoveries between agents
- receive agent outputs
- coordinate shared memory updates
- trigger final report generation
- record observable workflow events

The orchestrator should not:

- directly crawl the target
- directly run scanner tools
- directly inspect application components
- bypass an agent to call one of that agent's tools

## Agent Responsibilities

Agents perform specialist work. Each agent should have:

- a clear role
- a clear goal
- its own model configuration
- a defined set of tools it is allowed to invoke
- access to shared file-backed memory

Agents may discover information that the orchestrator passes to other agents that can contribute further.

Agents execute on the host for now.

## Tools

Tools are capabilities owned and invoked by agents.

Tools may be:

- implemented inside the application
- wrappers around external tools running in Docker containers

External tools must not be installed on the host. They should run in Docker containers.

The discovery tool image pins Katana at v1.7.0 and builds it with Go 1.26, the minimum version required by that Katana release. Pinning the tool release keeps later upstream Go requirements from breaking rebuilds unexpectedly.

Tool image source should stay grouped by crew/tooling domain:

- discovery tool image assets live under `tools/discovery/`
- security testing tool image assets live under `tools/security/`

The intended Docker interaction is:

- execute a container with the tool
- pass input to it
- read structured output from it

## Implementation Stack

Use CrewAI for the agent implementation.

Use OpenRouter, optional direct DeepSeek API access, and optional user-provided OpenAI-compatible endpoints for LLM calls.

Runtime settings are read from exported environment variables and from an optional `.env` file in the directory where the CLI is run. Exported environment variables take precedence over `.env` values. The `.env` file is local-only and must not be committed. The optional `mosh.yaml` file remains the place for model selection.

OpenRouter is the default and is always used for non-DeepSeek models. Its API key is provided through:

```text
OPENROUTER_API_KEY
```

Users can connect their own OpenAI-compatible endpoint with `MOSH_LLM_BASE_URL`; `MOSH_LLM_API_KEY` is optional:

```text
MOSH_LLM_BASE_URL
MOSH_LLM_API_KEY
```

Existing custom-only configurations with `MOSH_LLM_BASE_URL` and no `custom/` model IDs retain their route-all behavior. Once any configured agent uses a `custom/` model ID, routing is per model: only `custom/` IDs use the custom endpoint, and other IDs use direct DeepSeek or OpenRouter as selected. This preserves older configurations while allowing a gradual migration through `mosh.yaml` without a second routing-state file. Custom calls use CrewAI's OpenAI-compatible integration with provider `openai`, `base_url` set to `MOSH_LLM_BASE_URL`, and `api_key` set to `MOSH_LLM_API_KEY` when provided. The API key is optional; when absent, the runtime supplies a placeholder only to the client library and does not persist it.

When a selected model is a DeepSeek model and `DEEPSEEK_API_KEY` is present, the application should call the DeepSeek API directly through CrewAI's LiteLLM-backed LLM integration rather than using raw HTTP calls:

```text
DEEPSEEK_API_KEY
```

Configured model names may use provider-style names such as `deepseek/deepseek-v4-flash` or `openrouter/deepseek/deepseek-v4-flash`. An `openrouter/` prefix explicitly chooses OpenRouter, even when a direct DeepSeek key exists. When direct DeepSeek is selected, the runtime must normalize the model name to the bare DeepSeek API model name, such as `deepseek-v4-flash` or `deepseek-v4-pro`, before passing it to CrewAI's LiteLLM-backed LLM integration. The default package provider configuration should be used.

When OpenRouter is selected, the runtime should pass the OpenRouter model ID without an extra routing prefix, such as `openai/gpt-5.2` or `deepseek/deepseek-v4-flash`. A leading `openrouter/` in local configuration is allowed as a convenience but must be stripped before the LLM call.

When a custom endpoint is selected, the runtime passes the model ID exactly as configured except for a leading `custom/` prefix, which is stripped before the LLM call. `custom/` is required for custom models when providers are mixed; legacy route-all setups may still use bare IDs. This allows local model names such as `custom/llama3.1` to be sent as `llama3.1`.

If a selected model is a DeepSeek model but `DEEPSEEK_API_KEY` is not present, the application should use OpenRouter for that model. If a crew uses any non-DeepSeek model `OPENROUTER_API_KEY` is required for that model.

Each agent can be configured to use a specific LLM model through an optional `mosh.yaml` file in the directory where the CLI is run. The file supports a single `models` mapping grouped by crew:

```yaml
models:
  discovery_live:
    crawler: openai/gpt-5.2-mini
    technology_mapper: openai/gpt-5.2-mini
    reporter: openai/gpt-5.2-mini

  discovery_source:
    intake: openai/gpt-5.2-mini
    mapper: openai/gpt-5.2-mini
    route_resolver: openai/gpt-5.2-mini
    dependency_config: openai/gpt-5.2-mini
    component_mapper: openai/gpt-5.2-mini
    gap_analyst: openai/gpt-5.2-mini
    reporter: openai/gpt-5.2-mini

  planning:
    planner: openai/gpt-5.2-mini
    evidence_linker: openai/gpt-5.2-mini
    reviewer: openai/gpt-5.2
    reporter: openai/gpt-5.2-mini
    engagement_refiner: openai/gpt-5.2-mini

  testing:
    executor: openai/gpt-5.2-mini
    reviewer: openai/gpt-5.2
    reporter: openai/gpt-5.2-mini

  reporting:
    writer: openai/gpt-5.2-mini
    reviewer: openai/gpt-5.2

  chat:
    assistant: openai/gpt-5.2-mini
```

Omitted model keys keep their built-in defaults. Unknown model keys should fail clearly so misspelled crew or agent names do not silently select the wrong model. The user-facing model configuration should not expose a generic `orchestrator` model unless a crew has an explicit LLM-backed coordinator role.

CrewAI agent and task definitions should use CrewAI's built-in YAML configuration pattern. Configuration is grouped by crew, so each crew's agents and tasks are kept together for future reference. Python should bind live tool implementations to the YAML-defined agents, but agent roles, goals, backstories, task descriptions, and expected outputs should live in YAML.

Crew-specific Python code should also live with the crew. For example, the live discovery crew owns its `crew.py`, `agents.py`, `crawler.py`, `tools.py`, and `reporting.py` modules under `src/mosh/crews/discovery_live/`. Shared application primitives such as configuration, Docker execution, engagement files, file-backed memory, shared models, and scope helpers stay at the `mosh` package root.

## Shared Memory

Shared memory must be file-backed. Agents can read from and add to shared memory. Memory writes must be recorded as observable events.

## Engagements And Assets

An engagement is the durable top-level assessment container. It is created with a random path-safe ID and persisted under:

```text
report/<engagement-id>/engagement.json
```

Assets are the attached things under assessment. Current asset types are:

- `live_url`
- `source_tree`
- `source_repo`

Asset attachment through `mosh engagement attach` is registration only. It must not automatically run discovery or testing. Asset type is inferred from the locator when possible, and callers may pass an explicit type for ambiguous URLs.

The top-level shortcut command accepts a single asset locator:

```text
mosh <url>
mosh <source-tree-path>
mosh <https-source-repo-url>
```

This shortcut must create a new engagement, attach the asset, run discovery for
that asset, and print the next planning command. It is equivalent to the first
three explicit steps for a one-asset engagement, but normal `engagement attach`
remains registration-only.

Source repositories are accepted only as HTTPS URLs. HTTPS URLs ending in `.git`
and canonical repository root URLs on known Git hosts (`github.com`,
`gitlab.com`, and `bitbucket.org`) are inferred as `source_repo`; Git host URLs
that point inside repository web UI paths must be rejected as ambiguous and the
user should pass the repository root. Git Pages hosts such as `*.github.io` are
live URLs. SSH, SCP-style Git, and `git://` repository locators are unsupported.

Each asset is persisted under:

```text
report/<engagement-id>/assets/<asset-id>/asset.json
```

`engagement.json` stores only asset references: `id` and `created_at`. Asset type, locator, label, and non-derived metadata are stored only in the asset's `asset.json` to avoid duplicated state. Asset discovery paths must not be stored in `asset.json`; they are derived from `report/<engagement-id>/assets/<asset-id>/discovery/`. For `source_repo` assets, the repository URL remains the canonical locator and the local checkout path is derived as `report/<engagement-id>/assets/<asset-id>/checkout/`; this checkout path must not be duplicated into `engagement.json` or `asset.json`.

Engagement discovery dispatches by asset and writes:

```text
report/<engagement-id>/assets/<asset-id>/discovery/
```

By default `mosh discover <engagement-id>` runs discovery only for assets that do not already have discovery output. `--asset <asset-id>` narrows discovery to one or more assets, and `--refresh` forces a rerun for the selected assets.

Planning runs evidence linking as its first stage. It reads asset discovery outputs
and writes source/live evidence relationships to:

```text
report/<engagement-id>/plan/links.json
```

## Harness Improvement Suggestions

Every engagement-backed stage may record internal suggestions for improving the
`mosh` harness itself. These suggestions are for human maintainers and must stay
separate from security findings, discovery gaps, preflight blockers, customer
inputs, and final customer report content.

Canonical suggestions are persisted once per engagement under:

```text
report/<engagement-id>/harness_improvements.json
```

The file uses schema `mosh.harness-improvements.v1`:

```json
{
  "schema": "mosh.harness-improvements.v1",
  "engagement_id": "eng_a1b2c3d4",
  "suggestions": [
    {
      "id": "hi_ab12cd34ef56",
      "fingerprint": "sha256:...",
      "status": "proposed",
      "category": "tooling",
      "impact": "medium",
      "title": "Add JWT claim diff tool",
      "problem": "JWT claims had to be decoded and compared manually.",
      "suggestion": "Add a bounded JWT decode and claim diff helper.",
      "evidence": ["AUTH-001"],
      "first_seen_at": "2026-06-21T00:00:00+00:00",
      "last_seen_at": "2026-06-21T00:00:00+00:00",
      "occurrences": [
        {
          "stage": "testing",
          "agent": "executor",
          "source_ref": "AUTH-001",
          "recorded_at": "2026-06-21T00:00:00+00:00"
        }
      ]
    }
  ]
}
```

Suggestions are upserted by a stable fingerprint derived from category, title,
problem, and suggestion. Repeated observations update `last_seen_at`, merge
evidence, and append an occurrence instead of creating duplicate canonical
suggestion records. Stage-local `memory.json` files may record only lightweight
`harness_improvement_ref` entries containing the suggestion ID, fingerprint, and
path. They must not duplicate canonical suggestion text.

The CLI surfaces suggestions with:

```text
mosh improvements list <engagement-id>
mosh improvements list
```

The engagement-specific form reads a single engagement. Omitting the engagement
ID scans `report/eng_*/harness_improvements.json`, groups suggestions by
fingerprint, and prints a human-readable cross-engagement view.

## Real-Time Visibility

The CLI should show real-time observable activity from the crew.

After each major stage completes successfully, the CLI should print a concise
next-step hint. Discovery should point to `mosh plan <engagement-id>`, planning
should point to reviewing `engagement_template.yaml` and running
`mosh test <engagement-id>`, testing should point either to updating the
engagement template and rerunning tests when blockers remain or to
`mosh report <engagement-id>`, and final reporting should point to the generated
report and internal harness improvements list.

Show events such as:

- agent messages
- task assignment
- tool calls
- tool results
- findings
- shared memory writes
- handoffs between agents
- final observable output from each agent task

Private chain-of-thought is not required. For now, use observable agent activity and decisions instead.

All observable activity must also be stored in JSON format as part of the output.

CrewAI-backed stages must also persist LLM token usage to a stage-local
`usage.json` when usage events are emitted. Asset discovery writes usage under
the asset's discovery directory; evidence linking and planning write under the
engagement `plan` directory; execution writes under `security-testing`; final
reporting writes under the final reporting directory.

## Output

Discovery output should be written under the asset selected for discovery:

```text
report/<engagement-id>/assets/<asset-id>/discovery/
```

Required outputs:

- Markdown final report
- JSON event log
- JSON shared memory
- JSON LLM usage, when CrewAI reports token usage

The final report should summarize the discovery activities and findings.

The final Markdown report is rendered by the discovery reporter-owned report-writing tool from structured content authored by the discovery reporter agent. The report-writing tool owns the Markdown section order and formatting so repeated runs remain comparable, while the discovery reporter agent owns the observations, narrative content, confidence levels, evidence, and recommendations.

The application should not write a final `report.json` artifact. Structured runtime data remains available through `events.json` and `memory.json`.

Observable agent report output should be stored in shared memory or events. CrewAI final chat/task responses are not sufficient by themselves unless the application explicitly persists them.

## Initial Crew: Live Discovery

The first crew is the live discovery crew.

The live discovery crew is not expected to find vulnerabilities. Vulnerability discovery and testing will come later.

The live discovery crew should focus on being excellent at appsec discovery.

### Live Discovery Crew Agents

The live discovery crew has these agents:

- orchestrator: coordinates the live discovery crew and routes work between agents
- crawler agent: discovers pages, links, URLs, paths, references, source, files, and forms
- technology mapper agent: identifies observable software components such as libraries, servers, frameworks, and related technologies
- reporter agent: summarizes findings and returns them to the orchestrator for reporting

### Live Discovery Crew Tool Ownership

The crawler is a tool owned by the crawler agent. The orchestrator must not call the crawler directly.

The crawler agent may have multiple crawler tools.

### Passive External OSINT

Live URL discovery includes passive external OSINT. External OSINT tools query
third-party indexes such as crt.sh, Shodan, Censys, and SecurityTrails by using
only the authorized root domain derived from the selected live URL asset. The
tooling must not accept free-form provider queries from an agent or user during
discovery.

Scope restrictions apply differently to passive lookup and active target
interaction:

- Passive provider queries may use the authorized root domain, such as
  `example.com`, to ask third-party indexes for matching hostnames and services.
- Provider results must be normalized and filtered through the live asset's
  scope policy before they are persisted as discovery candidates.
- Only HTTP(S) candidates that remain in scope may be selected for active
  follow-up crawling. Non-HTTP service observations may be recorded as passive
  candidates, but must not be actively contacted by crawler follow-up.
- Provider failures are non-blocking and should be recorded with discovery
  failures or events.
- OSINT observations are discovery evidence for the asset that produced them.
  They must not be duplicated into `engagement.json` or promoted to canonical
  assets unless the user explicitly attaches a discovered URL or host later.

The technology mapper agent currently performs its analysis through the CrewAI task context and its LLM output. It should read crawler findings and produce an evidence-based SBOM-style analysis as agent output. There is no deterministic component inventory tool in the current implementation.

The discovery reporter agent owns summarization behavior and the report-writing tool. The orchestrator may request reporting, but it must not synthesize the final report by calling reporting helpers directly.

## Security Planning

Security planning is engagement-wide. It consumes discovery from all relevant engagement assets, optional evidence links, and prior testing feedback, then writes one plan under:

```text
report/<engagement-id>/plan/
```

Planning input must be a compact evidence bundle, not a raw dump of discovery artifacts. The planner context should omit orchestration events, raw memory logs, inline script bodies, and duplicated discovery blobs. It should retain security-relevant summaries, structured discovery reports, bounded live routes, forms, references, source routes, bounded source file inventories, dependencies, configuration, evidence refs, asset-scoped discovery details, and `correlation.evidence_links`. For source assets, `source_index.inventory.files` is the authoritative indexed file list used by discovery summaries and planning; planning must preserve concrete file paths from it and must distinguish bounded prompt omission from a truly truncated source inventory. Nested text, lists, and mappings must also be bounded so model-generated discovery reports cannot cause planning context-window failures.

Planning must distinguish discovery-tool coverage gaps from execution blockers. When an attached source asset is available, work that can be done with bounded source reads, source searches, manual route extraction, prompt-template
extraction, configuration review, dependency inspection, generated harnesses, or local source-runtime checks belongs in active `source` hypotheses. Only the portion that genuinely needs an unattached asset/artifact, unsupported tooling,
mobile binary tooling, external accounts, deployment access, or unavailable build/run inputs should remain deferred. The critic must reject accepted plans that defer source-executable work solely because additional source inspection is
needed.

## Engagement Conversation

Each engagement has a persistent chat surface for asking questions about accumulated artifacts and for steering future crew stages:

```text
report/<engagement-id>/conversation/messages.jsonl
report/<engagement-id>/conversation/directives.json
```

`messages.jsonl` is the canonical conversation transcript. `directives.json` is derived state extracted from chat messages and must reference the source message ID instead of duplicating the original user intent.

The default chat path is LLM-backed through `models.chat.assistant`. The application must build a compact structured engagement context, include deterministic facts for common questions such as highest finding or blocked tests, and ask the model to return a JSON envelope with `answer`, `artifact_refs`, and `directives`. The chat must not send unbounded raw plan memory, executed-test reports, or discovery memory to the model. If the model returns a useful plain-text answer instead of JSON, the application may use that answer and apply heuristic directive extraction. If a JSON answer is incomplete, the application should retry once with repair instructions. If the required model settings are missing or the model response cannot be used, the chat must fall back to local structured answers and heuristic directive extraction rather than failing the conversation.

User clarifications about intended behavior, accepted risk, false positives, or design assumptions must be recorded as `engagement_context` directives for planning, testing, and reporting so later execution can take the feedback into account.

Supported directive classes include:

- `scope_override`
- `additional_discovery_fact`
- `planning_focus`
- `test_instruction`
- `tool_request`
- `execution_constraint`
- `engagement_template_update_suggestion`
- `report_correction`
- `engagement_context`

The chat context builder may read engagement artifacts, discovery reports and memory, plans, the engagement template, testing preflight, executed test reports, final reports, and active directives. It is a read model for answering questions; it must not become a second source of truth for canonical assets, plans, test results, credentials, or permissions.

Crew stages consume only relevant active directives. Planning receives planning-relevant directives in the engagement evidence bundle and records a `conversation_directives_fingerprint` in `plan_run` memory. A plan is current only when discovery inputs, evidence links, required artifacts, and the planning directive fingerprint still match. Testing attaches relevant testing directives to matching in-memory hypotheses before preflight/execution so new hypothesis-specific guidance changes the hypothesis fingerprint and can trigger a focused rerun. Final reporting includes reporting-relevant directives in its deterministic report bundle.

## Testing Crew

The testing crew executes ready hypotheses from the security test plan.
It runs tests sequentially so reviewer feedback for one test can inform a bounded rerun before the next test starts.

Security testing preflight evaluates concrete artifact and engagement requirements before any executor runs.

A hypothesis is executable when the required live targets, source assets, authorization, credentials, safe data, target mappings, and engagement permissions are available. Source-backed execution may use bounded source inspection, source search, local tests, framework/build introspection, generated harnesses, explicit environment overrides, function-level experiments, or local runtime checks.

Combined hypotheses execute as one hypothesis with one evidence bundle and one report, correlating source and live evidence rather than producing separate result sets.
Deferred hypotheses are preserved with their requirements to proceed.

Security testing is engagement-wide and writes one result set under:

```text
report/<engagement-id>/security-testing/
```

The engagement-backed command is:

```bash
mosh test <engagement-id>
```

It reads the current plan from `report/<engagement-id>/plan/` and the shared execution configuration from `report/<engagement-id>/engagement_template.yaml`.

Source, live, combined, and future mobile-specialist tools are internal capabilities of the testing stage. They must not create separate top-level testing result sets that need manual synchronization.

## Engagement File

The engagement template is user-owned execution configuration for the whole engagement and is shared by planning and testing. The target location is:

```text
report/<engagement-id>/engagement_template.yaml
```

The engagement file should stay small and directly editable. It should include:

- engagement permissions and notes
- production target mappings and optional alternative target mappings
- escalation contact details
- execution limits
- credential placeholders by role
- safe test data placeholders
- optional `llm.engagement_steer` text for engagement-scoped model guidance

It should not include explanatory readiness metadata such as `status`, `needed_for`, `required_answers`, or long generated notes. Missing inputs, blocked tests, and questions belong in `plan.md`, `security_test_plan.md`, `preflight.md`, `events.json`, or `memory.json`.

The CLI supports a small steering-management surface:

```bash
mosh engagement steer set <engagement-id> --file steer.md
mosh engagement steer set <engagement-id> --file -
mosh engagement steer set <engagement-id> --text "Focus on tenant isolation."
mosh engagement steer show <engagement-id>
mosh engagement steer clear <engagement-id>
```

The `set` command creates `engagement_template.yaml` with a minimal valid template shape when the file does not exist yet. Steering text is user-owned configuration and must be preserved exactly by planning regeneration and engagement-template refinement. It is supplied to LLM-backed discovery, planning, evidence-linking, testing, and reporting calls as engagement steer. Built-in mosh safety, authorization, scope, evidence, tool-use, and structured output requirements take precedence over engagement steer. Changing the steering text makes the existing security plan stale so the next planning run can incorporate the new guidance.

Repeated planning runs must not overwrite non-empty values that the user has already added to `engagement_template.yaml`. Generated or refined templates should merge into the existing file, preserving filled credentials, tokens, alternative targets, safe test data, contact details, limits, and notes unless the user explicitly changes them. The LLM refiner must not invent secret values; if it proposes credentials or tokens, the generated candidate is rejected
and the preserved existing configuration remains in place.

Before an existing `engagement_template.yaml` is rewritten, the previous file must be copied into `engagement_template.backups/` with a timestamped filename. This keeps a recoverable copy even when regeneration or refinement simplifies the template shape.

The testing crew has these agents:

- security test executor: runs scoped commands through the security tools Docker container
- security test reviewer: critiques evidence, safety, target scope, and useful generated artifacts
- security test reporter: writes the stable Markdown artifact for each executed test

For source-mode tests, the unified testing crew follows the same
executor, reviewer, and reporter pattern. Its executor can read bounded source slices, search
nonignored text files, write generated harnesses or fuzz scripts under `/work`,
run local commands with explicit environment overrides, start and stop local
processes, and issue localhost HTTP requests to those processes. The repository
is mounted read-only at `/source` and `/work` is the only writable workspace.
Source execution is for source-local evidence, local tests, compilation,
framework inspection, dependency checks, static source scanners, route-table
inspection, function-level experiments, and localhost runtime checks; arbitrary
external URL probing belongs to live or combined execution.
The generic security tools image should include baseline HTTP utilities,
source-search utilities, Python/Node tooling, Semgrep, Bandit, pip-audit,
Java/OpenJDK, Maven, Corepack, and small project-inspection utilities. Large
platform SDKs such as Android and iOS should be added through specialized
runner profiles rather than the default image.

The executor can use both live and source tool surfaces for the same hypothesis. The executor may run commands, install packages, compile helper code, and write scripts only inside the disposable Docker workspace. The orchestrator must not run test tools directly.

Effective target mappings from the engagement file are canonical for execution, review, and reporting. URLs in the original hypothesis may be production discovery evidence. If an alternative staging or preprod target is mapped, agents must execute and evaluate the mapped target rather than drifting back to the original production URL.

Each executed test should preserve a structured execution bundle containing:

- final evidence
- final reviewer decision
- every executor/reviewer attempt
- command records
- source reads and source searches, when used
- generated workspace files and local runtime request/process records, when used
- useful artifacts generated during any attempt

Useful artifacts include generated policies, proof-of-concept payloads, endpoint inventories, helper scripts, auth matrices, and remediation snippets. Reviewer feedback may accept or reject artifacts separately from the final evidence decision. A reviewer-requested rerun must not discard a useful artifact from an earlier attempt; the final report should include it with status and caveats unless it is unsafe or known invalid. The human Markdown report should render the concrete artifact content, not internal artifact metadata or description-only placeholders.

Each executed test report should include a `Resolution` section aimed at developers and application owners. This section should explain how to remediate an identified issue using concrete configuration, code, header, control, or process changes where evidence supports them. If no issue is identified, the section should state that no remediation is required for that hypothesis.

Security testing can discover additional facts that belong back in discovery, whether the evidence came from live, source-backed, or combined testing: new entry points, endpoints, technologies, versions, service behavior, headers, generated API specifications, or other app-surface information. The executor should submit these as structured `discovery_updates` in its evidence. After ready tests finish, the testing orchestrator feeds those updates into the relevant discovery crew's file-backed memory, updates the discovery report with a deterministic `Security Testing Feedback` section, and then asks the planning crew to refresh the test plan. The system does not immediately auto-run new tests from that refreshed plan; additional execution happens on the next security-testing run only if the refreshed plan contains ready, unexecuted hypotheses.

After a successful `test` run, the CLI must print a deterministic human-readable summary of any blocked tests that still prevent completion. The summary should list each blocked test ID, title, priority, and concrete engagement template fields or values needed to unblock it. This mirrors the preflight data without requiring the user to open `preflight.md` for the next action.

Security test completion is determined from metadata embedded in the latest executed Markdown report, not from a separate execution index. Each `executed_tests/<test_id>.md` report should include machine-readable execution metadata containing at least the test ID, plan revision ID, hypothesis fingerprint, status, reviewer acceptance, and execution time. A ready hypothesis is skipped only when the latest report has matching accepted metadata for the same hypothesis fingerprint. If the hypothesis changes after discovery-driven replanning, or the previous execution was not accepted, the test is queued for rerun.

Before a rerun overwrites `executed_tests/<test_id>.md`, the previous report must be preserved under `executed_tests/history/` as a reference. This keeps older security test output available while making the latest report the current
version.

To avoid runaway loops, duplicate security-testing discovery feedback must not trigger another discovery update or planning refresh. Only feedback facts not already present in discovery memory should cause the discovery report to update and the planning crew to refresh.

## Final Reporting Crew

The final reporting crew produces the customer-facing deliverable for a security testing engagement. It runs after discovery, security planning, and security testing:

```text
discover -> plan -> test -> report
```

The CLI command is:

```bash
mosh report <engagement-id>
```

The output path is:

```text
report/<engagement-id>/final-report/report.md
```

The final report should include:

- Executive Summary:
  - prose at-a-glance summary for security executives, not a raw metrics table
  - assertive application/business context understood from discovery
  - what was tested in business-risk terms, not internal tool/process terms
  - overall security posture
  - headline risks
  - number of findings by severity
  - remediation priorities ordered by qualitative severity
- Engagement Overview:
  - prose explanation of the target and engagement setup
  - effective target mappings
  - human-readable lifecycle dates covering discovery, planning, security testing, and final reporting
  - scope and limitations
  - testing approach
- Summary of Findings:
  - table with ID, title, severity, status, affected area, and remediation priority, sorted by severity and remediation priority
  - severity counts
  - confirmed, inconclusive, failed, and no-finding breakdown
- Key Discovery Areas:
  - short explanatory introduction before the discovery bullets
  - important routes, auth areas, APIs, forms, technologies, and exposed surfaces
  - relevant limitations
- Detailed Findings for confirmed findings only:
  - title
  - severity and rationale
  - affected target/component
  - evidence summary
  - reproduction summary
  - impact
  - technical remediation guidance
  - source-specific fix guidance or pseudo-code when available from source evidence
  - verification/retest guidance
  - references, such as OWASP WSTG, ASVS, or CWE, when available from source evidence
- Tests With No Finding / Inconclusive:
  - concise appendix for no-finding, inconclusive, failed, or reviewer-rejected tests
- Appendix:
  - methodology
  - tools used
  - evidence index
  - raw report references

Final reporting must assemble a deterministic evidence bundle before the LLM agents run. The bundle is built from discovery reports and memory, security test planning reports and memory, security-testing preflight output, security-testing memory, and current executed test reports. The bundle determines which executed tests are confirmed findings for the final report. No-finding, inconclusive, failed, or reviewer-rejected tests must not be promoted into detailed findings.

The Markdown report should read as a customer-facing document, not a raw tool export. Avoid generic `Field`/`Value` table headings, include short explanatory text before dense tables or bullet lists, and keep long generated paragraphs split into readable blocks. Markdown remains the canonical source deliverable. The localhost web renderer adds a section index with heading anchors and a Download menu for PDF, Word (DOCX), and Markdown. PDF and DOCX downloads are generated from the current Markdown on request; neither is stored as a second report artifact. Free-form source evidence, reproduction notes, impact text, and remediation snippets must be escaped or fenced when needed so malformed backticks from an execution artifact cannot break the remainder of the report.

The final reporting crew has these agents:

- writer: writes the customer-facing report through the `write_final_report`
  tool
- reviewer: reviews the generated report through the
  `submit_final_report_review` tool

Both agents must be constrained by the deterministic bundle. The writer may make the report easier to read, but must not invent findings, affected systems, severity, evidence, remediation, or CVSS scores. The reviewer must reject reports that introduce unsupported claims or omit confirmed findings.

Customer-facing language should use `findings` or `confirmed findings`, not `accepted findings`. In implementation, a confirmed finding means the executed test status is `finding` and the review stage accepted it for inclusion in the report; it does not mean the customer has accepted or agreed with the finding.

Qualitative severity should be sourced deterministically. Use current security plan priority when available, then executed test metadata, then the executed test report Scope priority. This preserves severity for accepted historical findings that no longer appear in the latest refreshed plan.

CVSS is optional. It may be included only when already present in source execution evidence. If the bundle does not contain a CVSS score/vector for a finding, the final report must state `Not scored`.

## Discovery Scope

The only current target type is a URL. Stay within the main domain of the app passed in the URL.

Example:

If the target is:

```text
www.test.com
```

Then these are in scope:

- `www.test.com`
- `test.com`
- `api.test.com`
- other subdomains under `test.com`

Do not scan anything out of scope. If an out-of-scope URL is discovered, record it and state that it was not scanned.

Private, local, and internal targets are allowed because this tool is intended for applications we own.

`robots.txt` should enrich discovery. It must not act as a scan limit.

## Crawler Requirements

The crawler agent should discover:

- pages
- links
- URLs
- paths
- references
- files
- forms

The crawler can be implemented inside the application. External crawler tools, such as Katana, must run through Docker and still be invoked as crawler agent tools.

The crawler agent should keep a per-run registry of URLs that have already been crawled. Before invoking a crawler tool, the crawler agent should check this registry. If the requested URL has already been crawled, it should skip the duplicate tool call, record the skip decision in `events.json`, and return the current crawl findings to the agent. Distinct crawl roots discovered during the run should be merged into the aggregate crawl state for later agents.

When the crawler discovers JavaScript assets, it may invoke Extractify to extract additional endpoints and URLs from those JavaScript files. Extractify findings should be scope-filtered, linked back to the JavaScript source as evidence, and merged into the aggregate crawl state.

When JavaScript assets are discovered, the crawler should also have access to a static JavaScript endpoint discovery tool. This tool should complement Katana and Extractify: Katana observes runtime browser and XHR/fetch behavior, Extractify finds broad URL-like strings, and the static analyzer resolves common JavaScript construction patterns that produce API paths from constants, aliases, base URL globals, concatenation, and template literals. Static findings must be scope-filtered, linked back to the JavaScript source as evidence, and merged into the aggregate crawl state.

When JavaScript assets are discovered, the crawler should check for valid source maps using Docker-backed tooling. Source-map discovery should record whether source maps were checked, whether any were found, how many original sources include embedded content, and any failures. Discovery reports should aggregate source-map facts across all source-map tool runs by JavaScript asset, then use these recorded facts when wording JavaScript limitations, so the report does not claim JavaScript was unexecuted or only string-scanned when Katana, Extractify, static analysis, or source-map checks actually ran.

The discovery report renderer should keep the discovered routes table grounded in crawl evidence. If the structured report omits route-like crawl pages, the renderer should append those routes deterministically while filtering static assets and generated JavaScript/library placeholders.

## Testing Expectations

Implement tests for all functionality so behavior does not regress.

At minimum, tests should cover:

- CLI behavior
- scope filtering
- out-of-scope recording
- file-backed memory
- event logging
- report generation
- agent-owned tool invocation
- crawler behavior against a fixture app
- SBOM agent output recording
- engagement conversation persistence, directive extraction, and directive-driven stage invalidation
- security-testing feedback into discovery memory, discovery reporting, and replanning
- security test rerun decisions from embedded report metadata and preserved history
- harness improvement suggestion persistence, deduplication, stage tool recording, and CLI surfacing

# Roadmap

The current v1 localhost web interface provides:

- `mosh-web`, bound to `127.0.0.1` only, with the packaged Mosh favicon served at `/favicon.ico` on every page, including onboarding. The dedicated two-step onboarding wizard runs while required model API settings are missing. Readiness is derived from the existing `.env`/environment and `mosh.yaml`; no separate setup-complete file duplicates that state. A running wizard stays open on Providers after a connection is saved until the user selects Finish setup.
- Environment checks for uv, Docker, and the two tool images. Image readiness requires a successful `docker run --rm --pull=never IMAGE true` under the active context and platform; `docker image inspect` alone can succeed for an image that the current platform cannot start. The setup script rebuilds missing or unusable images, checks source freshness for runnable images, and verifies a built image starts before reporting success. When Docker is ready and either image is missing or unusable, the wizard starts the setup script in the background, shows build progress, and offers a retry after failure. The user can continue to the providers step only when all checks are ready; direct requests cannot skip this requirement. The providers step lists DeepSeek, OpenRouter, and Custom endpoint with Connect actions and allows all three to be connected. Custom setup collects an OpenAI-compatible URL and optional key. Connect runs a bounded background API check with a visible spinner; DeepSeek uses its model-list endpoint, OpenRouter its current-key endpoint, and Custom the endpoint's OpenAI-compatible model-list path. Failed checks do not persist credentials and offer retry. Successful checks save access settings immediately to the local `.env` file with restrictive permissions. Finish setup requires saved access that covers the configured model IDs. An existing custom route-all setup is identified by the absence of `custom/` model assignments; the Providers screen explains that assigning one opts into per-model routing. These checks establish API access, not model invocation or compatibility with every configured model.
- A persistent Settings page lists connected providers and the effective model routes for Discovery, Planning, Testing, Reporting, and Chat. It has a focused panel with an X and Close settings action on every Settings screen. Client-side tab state remembers the non-Settings page where it was opened; closing returns there, while a direct visit falls back to Assessments. Normal links remain usable without JavaScript. Provider management after onboarding reuses the bounded connection checks and canonical `.env` writer without rendering keys. A stage editor shows every agent's effective provider and model ID as editable fields, grouped into live and source agents for Discovery. A secondary control applies one provider/model ID to the whole stage. Review shows each agent whose effective route will change, including any change outside the selected stage. When editing a legacy custom route-all setup, the editor makes the other stage assignments explicitly `custom/` so they keep using the same endpoint; only selected agent routes change. Missing provider access blocks saving. The settings POSTs use the localhost, origin, and CSRF checks; changes are blocked during active stages. Model overrides are written atomically to the canonical `mosh.yaml`, preserving unrelated model lines and comments. Individual edits write only changed agent assignments, except where explicit custom routes are needed to preserve legacy routing. Stale reviews cannot overwrite a newer configuration. Saving does not invoke a model, run a stage, or alter existing assessment artifacts. A later slice may add model catalogs and model invocation checks.
- Settings includes Local tools health for uv, Docker, and the separate Discovery and Security tool images. The web client polls a lightweight status endpoint and shows a warning beside Settings when a prerequisite is unavailable; the Settings section shows Check again and, when Docker is usable but an image is missing, Build tools with live progress. Probes use local Docker with image pulling disabled. Mosh's managed tool probes, builds, and runs ignore the inherited `DOCKER_DEFAULT_PLATFORM` override so mixed-architecture local images are checked and executed consistently; the active Docker context is still honored. A failed build retains the bounded tail of its output in memory and exposes it in Settings and onboarding as Build details. Starting Discovery or Testing performs a fresh check of the image that stage needs, blocks the run when unavailable, and links to Local tools. This reuses onboarding's image build state and does not persist a second source of tool health.
- A separate new-assessment wizard for title, supported asset locators, and explicit authorization. The Assets step switches from a URL field to a folder button when Local source tree is selected. That button opens a server-side folder browser limited to the user's home folder; server-side source paths still use the canonical locator validation, which requires an existing directory. Adding a live URL starts a bounded background HEAD request, falling back to GET for servers that reject HEAD, without following redirects. Adding an HTTPS repository starts a bounded, noninteractive `git ls-remote` check. The wizard shows check progress and lets the user retry, add an unverified asset anyway, or dismiss a failed check. Review shows the check result and rechecks local folder existence. The draft and check results live only in server memory; creating an assessment calls the canonical engagement and asset persistence functions and does not run discovery.
- An assessment detail page with assets, general guidance, and a one-line list of user-named hints (title plus multiline text). Assets can be added or detached after assessment creation. Local folders use the same home-limited browser; websites and repositories use a background reachability check with retry, add anyway, and dismiss. Detaching removes the asset reference from the canonical engagement manifest while preserving its existing files; later attachments do not reuse the detached asset's ID. Guidance copy explains that automatic discovery works without guidance, and that assessment-specific guidance can identify key functionality, relevant account roles, or sections to review; secrets belong in structured engagement credentials so preflight and redaction can use them and can be edited as the assessment progresses. Add and Edit open a single hint editor; Save hint and Delete persist immediately. General guidance saves separately. POST actions use the existing localhost/origin/CSRF checks and write canonical engagement state, with no duplicate web state. At most 30 hints and 24,000 combined hint characters are accepted. Existing credentials and testing permissions are retained. The guidance loader includes hints as user context to verify, so existing discovery/planning/testing/reporting consumers receive them and guidance-based plan invalidation incorporates changes. Regeneration preserves user hints.
- The Testing stage invokes the existing engagement-wide testing orchestrator only after an explicit Start testing action and only for a current plan. It shares the single active-stage guard with Discovery, Planning, and Reporting, and asset and guidance edits are blocked while testing runs. Before execution, a read-only preview applies the same testing directives and preflight rules to the current structured plan and engagement template. It introduces the number of planned tests and has a compact expandable guide for Ready, Running, Blocked, Needs rerun, Complete, and Deferred; Complete means a test ran and produced a result for the current plan. It lists planned hypotheses in plan order with Ready, Blocked, or Deferred status and each reason; current accepted reports show Complete, while outdated or unaccepted reports show Needs rerun only when preflight finds them ready. Blocked covers missing inputs, unavailable assets, permissions, dependencies, explicit plan readiness blockers, and other preflight failures. A `preflight_blocked` plan item cannot execute until its named blocker is cleared in the plan; an empty blocker list still requires prerequisite review. Existing reports remain linked when the current plan blocks a test. The preview recalculates after Scope changes and does not contact assets or persist duplicate state. Its blocker copy uses human action labels without exposing engagement-template field paths. Supported missing inputs offer a per-test Add required details dialog; each focused form saves to the canonical Scope engagement template, returns to that test with any remaining inputs visible, and never starts testing. Asset and scope blockers link to Scope for review. During execution, each started test row shows three event-driven milestones: running planned checks, reviewing evidence, and writing the test report. The current milestone spins, finished milestones show checkmarks, and a reviewer revision resets that test to checks. Queued tests remain compact; failed active milestones show an error mark. The orchestrator emits only the small boundary events needed for this status, while the expandable detailed logs retain the full event stream. The page polls a brief readiness/execution status and reuses the expandable detailed logs. It reads canonical security-testing preflight, memory, events, and executed Markdown reports rather than persisting duplicate web state. The preflight and per-hypothesis reports use the shared safe Markdown renderer; report lookup is restricted to files under the engagement testing directory. A completed run with blocked tests, unaccepted or missing ready-test reports, or a plan revision different from the last preflight requires another testing run. The Report stage becomes available when Testing finishes for the current plan and can run the final reporting orchestrator from the web. It shows three event-driven milestones: preparing assessment evidence (until the bundle and steer are loaded), writing the final report (until the writer saves report.md), and reviewing and finalizing the report (until the orchestrator completes). The active milestone spins, completed milestones show checkmarks, and a failed active milestone shows an error mark; detailed logs retain the underlying events.
- Web-triggered Testing saves test reports and stops before applying new discovery feedback. The Testing page detects unapplied feedback from canonical execution bundles and discovery memory, even after a server restart. Its decision panel shows each recorded discovery detail with the source test and a report link when available, collapses overflow after three items, and explains the effect of Update discovery and plan versus Continue to reporting before offering those actions. Applying feedback in a separate background action updates Discovery and invokes Planning once without rerunning tests. Planning shows a spinner and live status while this runs. The CLI keeps its automatic feedback behavior.
- If the user chooses to update the plan and that changes a hypothesis, its accepted execution report remains a finished historical result, while the revised hypothesis needs another run. Testing explains the new evidence and revised hypotheses; the test row and earlier report explain the changed status. Continuing to Report instead leaves Discovery and the plan unchanged and generates the final report from the completed run.
- Scope separates optional General guidance and Hints from Requested test information. Hints are free-text leads and do not satisfy preflight or structured secret redaction. Requested test information lists distinct missing inputs from the current plan and provides focused forms for role credentials, authorization and testing permissions, alternative target URLs, and the safe test data keys checked by preflight. These forms write only to the canonical `engagement_template.yaml`; they are not a general YAML editor. A role accepts either a token or a username and password. Existing credentials can be replaced without rendering saved values; removal requires confirmation and notes that local template backups may retain earlier values. Test data values are not echoed. Writes are blocked during active stages, and the active template plus new backups use owner-only file permissions.
- Web form error alerts move to a fixed, dismissible toast area at the top of the viewport, so errors from forms below the fold remain visible. The shared client script also moves errors returned by live stage status updates and avoids repeating the same toast during polling. Server-rendered alerts remain in the document if JavaScript is unavailable.
- The assessment detail page contains assets and optional guidance, with no duplicate Discovery status or run controls. A compact Scope → Discovery → Planning → Testing → Report row shows stage state and provides navigation between sections; a running stage shows a spinner, completed stages show checkmarks, and the Report stage becomes available after Testing finishes for the current plan. The completed Planning view also offers a one-time Continue to testing link before the first testing run; the link only navigates and leaves the test start action on the Testing page. Stage links only navigate. Discovery owns Start, Retry remaining, and Refresh discovery, its report links, and detailed logs. Only one discovery run can execute across the local server at a time. While a run is active, a reusable client poller fetches JSON with the updated stage section and whether polling should continue. It replaces only that section in the DOM every two seconds; the page itself does not refresh. The Discovery view shows the current asset and three website milestones (crawl pages/forms/APIs, identify technologies/services, write report) or four source milestones (index files/routes, inspect dependencies/configuration, summarize components/gaps, write report). Progress advances from existing agent and task events, without fabricated percentages. The current step has a spinner, completed steps have checkmarks, and reduced-motion settings disable the spinner animation. Other assets remain compact rows. Detailed logs show escaped event messages and can read canonical per-asset `events.json` after a server restart. Reports read canonical `report.md` and use a reusable Markdown component with tables, lists, links, and code blocks; raw HTML is escaped and unsafe link protocols are rejected. A failed run stops, shows the error, and can retry the failed and remaining assets; complete reports are otherwise reused. Re-running all assets requires an explicit refresh action. The web server must remain running for its background thread to finish.
- On discovery completion, the Planning stage link opens the Planning view without starting work; Refresh discovery remains a smaller secondary action in Discovery. Refresh opens a confirmation page that explains all supported attached assets will be rerun and existing reports/logs may be replaced. Cancel returns to Discovery without starting a run; the confirmation form submits the refresh action. A POST without confirmation cannot start refresh. Planning owns Start planning, Retry planning, Update plan, its plan view, and detailed logs. Its copy explains that planning examines discovered assets, identifies potential security issues, and turns them into tailored, testable hypotheses; tests run later. The planning stage runs the existing engagement-wide planning orchestrator in a background thread after every supported attached asset has a discovery report. One stage runs across the local server at a time, and asset changes are blocked during a stage. Four brief event-driven steps cover evidence linking, drafting hypotheses, reviewing/refining the plan, and writing the plan. The shared client poller updates the planning section and detailed logs without refreshing the page. The canonical `plan/plan.md` is shown through the shared Markdown renderer, with stale earlier plans still accessible as Previous plan. Plan currency comes from the existing planning freshness check so new discovery or changed guidance offers Update plan. Planning does not execute security tests.

- Discovery and Planning show detailed events in a collapsible console panel at the bottom of the stage. Opening and closing logs changes the page in place; while open, the existing status endpoint includes escaped timestamped events. The shared client poller keeps the panel open and preserves its scroll position, following new events only when the reader is already at the bottom. Closed panels omit event rows from poll responses. The `?view=logs` URLs still open the panel directly.

- Each active web stage offers a small Stop control with a confirmation dialog. POST requests use the existing CSRF, origin, and localhost checks and set an in-memory stop request on that engagement's active run. The run remains active, blocks competing stages and edits, and polls as Stopping until its worker reaches a safe boundary. Discovery checks between assets; Testing checks between hypotheses after their cleanup and saved reports, and before marking the run complete; Planning and Reporting check between model tasks and before completion. Feedback-driven plan updates share Planning's stop checkpoints. The web worker catches the dedicated stop exception and marks the run Stopped by you, without treating it as failure. Completed asset and test reports remain canonical and reusable; Discovery and Testing can run remaining work, while Planning and Reporting restart. The client poller pauses section replacement while the stop dialog is open. There is no forced thread or model-request termination, and the local web server must stay alive for the stop request to finish.

- Scope includes optional request headers for each live URL asset. The canonical mapping is `asset_request_headers.<asset-id>.<header-name>` in `engagement_template.yaml`; names and values are validated as bounded single-line HTTP header fields. The web form saves, replaces, and removes one header at a time without re-rendering values. Discovery passes configured headers only to the matching asset's native crawler and Katana, outside CrewAI tool arguments and prompts. The native crawler uses them only for the configured origin and refuses cross-origin redirects. Katana receives headers through Docker stdin, without putting values in command arguments or temporary files, and uses exact-origin crawl scope; headless mode and Dirb are skipped for assets with headers. Testing exposes a scoped structured HTTP request tool that applies the saved headers by exact origin by default and permits an unauthenticated request. Its requests do not follow redirects. Arbitrary security commands do not automatically receive saved headers. Tool output is redacted before persistence. Planning, Testing, and chat omit header values from model context. Removing an asset clears its headers. Generated plan templates preserve existing entries but cannot invent or replace them. Saving headers does not verify them or start a run; local template backups may retain older values.

Future web work: add input and steering during execution, one stage at a time. Keep the interface simple and free of duplicated canonical engagement or asset state.

* Improve the application based on testing results with an improver crew, including tool changes, prompt changes, and stage changes.

* Incorporate OWASP testing guide

* CLOUDFLARE BLOG: Adversarial validation tries to disprove each finding
* CLOUDFLARE BLOG: A fresh agent validates the list of findings against fresh code - can't find their own issues

v2
* Move the tool execution to docker, e.g. remove local dependencies

* We do not have security testing tools that focus on mobile app inspection, reverse-engineering. Security test planning leaves these out of scope because of this, we may want to add some mobile-client focused security testing tools.

* As targets grow, we will run out of context very quickly during planning phase - check if planning can be done per asset + links, and what is the difference in output.

v3
* Incorporate a RAG so that executions are remembered and the agents learn from each execution


* CLOUDFLARE BLOG: Feedback
* CLOUDFLARE: Gapfill - matrix of coverage
* CLOUDFLARE: Built-in attack classes + planning invents its own
* CLOUDFLARE BLOG: Threat model
* CLOUDFLARE BLOG: Require for each finding a working test + a functional git diff - that get executed deterministically
* CLOUDFLARE BLOG: Fixer? Submit MRs
* CLOUDFLARE BLOG: Measure success 
* BUG? 'test' always proceeds to work?
