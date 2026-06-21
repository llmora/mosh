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

Users can route all model calls through their own OpenAI-compatible endpoint by setting both:

```text
MOSH_LLM_BASE_URL
MOSH_LLM_API_KEY
```

When `MOSH_LLM_BASE_URL` is set, the runtime should pass the configured model name to CrewAI's LiteLLM-backed LLM integration with provider `openai`, `base_url` set to `MOSH_LLM_BASE_URL`, and `api_key` set to `MOSH_LLM_API_KEY`. This custom endpoint mode takes precedence over both direct DeepSeek and OpenRouter routing. For local endpoints that do not enforce authentication, users should provide a placeholder API key value.

When a selected model is a DeepSeek model and `DEEPSEEK_API_KEY` is present, the application should call the DeepSeek API directly through CrewAI's LiteLLM-backed LLM integration rather than using raw HTTP calls:

```text
DEEPSEEK_API_KEY
```

Configured model names may use existing provider-style names such as
`deepseek/deepseek-v4-flash` or `openrouter/deepseek/deepseek-v4-flash`. When direct DeepSeek is selected, the runtime must normalize these names to the bare DeepSeek API model name, such as `deepseek-v4-flash` or `deepseek-v4-pro`, before passing them to CrewAI's LiteLLM-backed LLM integration. The default package provider configuration should be used.

When OpenRouter is selected, the runtime should pass the OpenRouter model ID without an extra routing prefix, such as `openai/gpt-5.2` or `deepseek/deepseek-v4-flash`. A leading `openrouter/` in local configuration is allowed as a convenience but must be stripped before the LLM call.

When a custom endpoint is selected, the runtime should pass the model ID exactly as configured except for a leading `custom/` convenience prefix, which must be stripped before the LLM call. This allows local model names such as `custom/llama3.1` to be sent as `llama3.1`.

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

Asset attachment is registration only. It must not automatically run discovery or testing. Asset type is inferred from the locator when possible, and callers may pass an explicit type for ambiguous URLs.

Each asset is persisted under:

```text
report/<engagement-id>/assets/<asset-id>/asset.json
```

`engagement.json` stores only asset references: `id` and `created_at`. Asset type, locator, label, and non-derived metadata are stored only in the asset's `asset.json` to avoid duplicated state. Asset discovery paths must not be stored in `asset.json`; they are derived from `report/<engagement-id>/assets/<asset-id>/discovery/`.

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

## Real-Time Visibility

The CLI should show real-time observable activity from the crew.

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

The technology mapper agent currently performs its analysis through the CrewAI task context and its LLM output. It should read crawler findings and produce an evidence-based SBOM-style analysis as agent output. There is no deterministic component inventory tool in the current implementation.

The discovery reporter agent owns summarization behavior and the report-writing tool. The orchestrator may request reporting, but it must not synthesize the final report by calling reporting helpers directly.

## Security Planning

Security planning is engagement-wide. It consumes discovery from all relevant engagement assets, optional evidence links, and prior testing feedback, then writes one plan under:

```text
report/<engagement-id>/plan/
```

Planning input must be a compact evidence bundle, not a raw dump of discovery artifacts. The planner context should omit orchestration events, raw memory logs, inline script bodies, and duplicated discovery blobs. It should retain security-relevant summaries, structured discovery reports, bounded live routes, forms, references, source routes, dependencies, configuration, evidence refs, asset-scoped discovery details, and `correlation.evidence_links`. Nested text, lists, and mappings must also be bounded so model-generated discovery reports cannot cause planning context-window failures.

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

The Markdown report should read as a customer-facing document, not a raw tool export. Avoid generic `Field`/`Value` table headings, include short explanatory text before dense tables or bullet lists, and keep long generated paragraphs split into readable blocks. Markdown remains the source deliverable for now; HTML/PDF export may be added later as a presentation layer. Free-form source evidence, reproduction notes, impact text, and remediation snippets must be escaped or fenced when needed so malformed backticks from an execution artifact cannot break the remainder of the report.

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

# Roadmap

* Broaden engagement conversation directives so discovery crawlers and source discovery tools directly consume scope overrides, user-supplied discovery facts, and tool requests during the same stage run.
* Add review checkpoints to a future end-to-end run command so users can chat with the engagement between stages without manually remembering the command sequence.
* Right now the user needs to know the various stages of an assessment and provide them in the correct order. We should explore simplifying this (without removing current capabilities).
* Move the tool execution to docker, e.g. remove local dependencies
* Incorporate a RAG so that executions are remembered and the agents learn from each execution
* Incorporate a RAG so that executions are remembered and the agents learn from each execution
* Create a web-based GUI that allows the user to acess all engagements, monitor progress for an engagement, provide input / steering during execution, and do an export of the report(s) to PDF. The GUI would have an onboarding wizard to ask for keys or anything else that may be required. The GUI would have an onboarding wizard to ask for keys or anything else that may be required.
* We want to improve the application based on results of testing, create an improver crew that works on this, for instance (but not limited to): adding new tools, fine-tuning prompts, deciding to introduce or remove stages, etc.
* We do not have security testing tools that focus on mobile app inspection, reverse-engineering. Security test planning leaves these out of scope because of this, we may want to add some mobile-client focused security testing tools.
* We do not have security testing tools that focus on mobile app inspection, reverse-engineering. Security test planning leaves these out of scope because of this, we may want to add some mobile-client focused security testing tools.
* As targets grow, we will run out of context very quickly during planning phase - check if planning can be done per asset + links, and what is the difference in output.
* Incorporate OWASP testing guide
* External OSINT services (crt.sh, Shodan, Censys, SecurityTrails) were blocked by security container restrictions and could not be queried directly — this limitation is documented.
* CLOUDFLARE BLOG: Adversarial validation tries to disprove each finding
* CLOUDFLARE BLOG: A fresh agent validates the list of findings against fresh code - can't find their own issues
* CLOUDFLARE BLOG: Wishlist - our tool improver
* CLOUDFLARE BLOG: Feedback
* CLOUDFLARE: Gapfill - matrix of coverage
* CLOUDFLARE: Built-in attack classes + planning invents its own
* CLOUDFLARE BLOG: Threat model
* CLOUDFLARE BLOG: Require for each finding a working test + a functional git diff - that get executed deterministically
* CLOUDFLARE BLOG: Fixer? Submit MRs
* CLOUDFLARE BLOG: Measure success 
* BUG? 'test' always proceeds to work?
