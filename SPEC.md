# Model-driven Open Security Harness Specification

## Goal

Build an application security testing harness that uses coordinated agents to perform appsec work and produce a final report.

The first working prototype is a CLI-only discovery harness for a single URL:

```bash
mosh <URL>
```

The system should be built in small, testable steps. Do not over-engineer early versions, but keep the core architecture clear enough to support future crews.

## Core Architecture

The application must follow this pattern across all crews:

```text
orchestrator -> agent -> tools
```

This is an important architectural rule.

The orchestrator coordinates work between agents. It does not directly perform specialist work and must not directly call low-level tools such as crawlers, scanners, or component detectors.

Each agent owns the tools it can use. If a crawler is needed, the crawler agent invokes its crawler tool. If component inventory is needed, the SBOM/component agent invokes its own inventory tools.

This pattern applies to the initial discovery crew and to future crews.

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

Use a Docker image called the discovery tools container for discovery-related external tools.

The current discovery tools container starts from Debian and includes Katana,
Dirb, Extractify, a static JavaScript endpoint extractor, Node.js, npm, and
system Chromium for JavaScript-aware discovery. Katana must use the bundled
system browser rather than downloading a browser during each tool execution.
Dirb is available for bounded wordlist-based path discovery. Extractify is
available for extracting endpoints, URLs, and other entry points from JavaScript
and text assets. The static JavaScript endpoint extractor uses AST analysis to
resolve common endpoint construction patterns such as constants, aliases, string
concatenation, template literals, and simple browser-global API base values. The
container should also include Katana form-fill defaults for common login fields,
so headless crawling can submit unauthenticated forms and observe resulting
XHR/fetch endpoints.

Tool image source should stay grouped by crew/tooling domain:

- discovery tool image assets live under `tools/discovery/`
- security testing tool image assets live under `tools/security/`

The repository setup script should build the required Docker images and rebuild
them when their source files are newer than the local image. This prevents
renames or tool image changes from silently causing browser-backed discovery
tools to be unavailable at runtime.

The intended Docker interaction is:

- execute a container with the tool
- pass input to it
- read structured output from it

## Implementation Stack

Use CrewAI for the agent implementation.

Use OpenRouter and optional direct DeepSeek API access for LLM calls.

OpenRouter is the default and is always used for non-DeepSeek models. Its API
key is provided through:

```text
OPENROUTER_API_KEY
```

When a selected model is a DeepSeek model and `DEEPSEEK_API_KEY` is present, the
application should call the DeepSeek API directly through CrewAI's LiteLLM-backed
LLM integration rather than using raw HTTP calls:

```text
DEEPSEEK_API_KEY
```

Configured model names may use existing provider-style names such as
`deepseek/deepseek-v4-flash` or `openrouter/deepseek/deepseek-v4-flash`. When
direct DeepSeek is selected, the runtime must normalize these names to the bare
DeepSeek API model name, such as `deepseek-v4-flash` or `deepseek-v4-pro`,
before passing them to CrewAI's LiteLLM-backed LLM integration. The default
package provider configuration should be used.

When OpenRouter is selected, the runtime should pass the OpenRouter model ID
without an extra routing prefix, such as `openai/gpt-5.2` or
`deepseek/deepseek-v4-flash`. A leading `openrouter/` in local configuration is
allowed as a convenience but must be stripped before the LLM call.

If a selected model is a DeepSeek model but `DEEPSEEK_API_KEY` is not present,
the application should use OpenRouter for that model. If a crew uses any
non-DeepSeek model, `OPENROUTER_API_KEY` is still required for that model.

Each agent can be configured to use a specific LLM model through an optional
`mosh.yaml` file in the directory where the CLI is run. The file supports a
single `models` mapping grouped by crew:

```yaml
models:
  discovery:
    crawler: openai/gpt-5.2-mini
    technology_mapper: openai/gpt-5.2-mini
    reporter: openai/gpt-5.2-mini

  source_discovery:
    intake: openai/gpt-5.2-mini
    mapper: openai/gpt-5.2-mini
    route_resolver: openai/gpt-5.2-mini
    dependency_config: openai/gpt-5.2-mini
    component_mapper: openai/gpt-5.2-mini
    gap_analyst: openai/gpt-5.2-mini
    reporter: openai/gpt-5.2-mini

  security_planning:
    planner: openai/gpt-5.2-mini
    evidence_linker: openai/gpt-5.2-mini
    reviewer: openai/gpt-5.2
    reporter: openai/gpt-5.2-mini
    engagement_refiner: openai/gpt-5.2-mini

  security_testing:
    executor: openai/gpt-5.2-mini
    reviewer: openai/gpt-5.2
    reporter: openai/gpt-5.2-mini

  reporting:
    writer: openai/gpt-5.2-mini
    reviewer: openai/gpt-5.2
```

Omitted model keys keep their built-in defaults. Unknown model keys should fail
clearly so misspelled crew or agent names do not silently select the wrong
model. The user-facing model configuration should not expose a generic
`orchestrator` model unless a crew has an explicit LLM-backed coordinator role.
Model selection should not be exposed as a command-line option for now.

CrewAI orchestration is mandatory. The application should not silently fall back to a deterministic agent sequence when CrewAI or the required LLM API key is unavailable. If the CrewAI discovery crew cannot run, the CLI should fail clearly and report the missing requirement.

The discovery workflow must run as a CrewAI crew. Agents, exchanges, tasks, and tool invocation should be represented through CrewAI rather than a deterministic Python sequence.

CrewAI agent and task definitions should use CrewAI's built-in YAML configuration pattern. Configuration is grouped by crew, so each crew's agents and tasks are kept together for future reference:

- Discovery crew:
  - `src/mosh/crews/discovery/agents.yaml`
  - `src/mosh/crews/discovery/tasks.yaml`
- Security planning subcrews:
  - `src/mosh/crews/security_planning/evidence_linker_agents.yaml`
  - `src/mosh/crews/security_planning/evidence_linker_tasks.yaml`
  - `src/mosh/crews/security_planning/planner_agents.yaml`
  - `src/mosh/crews/security_planning/planner_tasks.yaml`
  - `src/mosh/crews/security_planning/critic_agents.yaml`
  - `src/mosh/crews/security_planning/critic_tasks.yaml`
  - `src/mosh/crews/security_planning/reporter_agents.yaml`
  - `src/mosh/crews/security_planning/reporter_tasks.yaml`
  - `src/mosh/crews/security_planning/engagement_refiner_agents.yaml`
  - `src/mosh/crews/security_planning/engagement_refiner_tasks.yaml`
- Security testing subcrews:
  - `src/mosh/crews/security_testing/executor_agents.yaml`
  - `src/mosh/crews/security_testing/executor_tasks.yaml`
  - `src/mosh/crews/security_testing/reviewer_agents.yaml`
  - `src/mosh/crews/security_testing/reviewer_tasks.yaml`
  - `src/mosh/crews/security_testing/reporter_agents.yaml`
  - `src/mosh/crews/security_testing/reporter_tasks.yaml`
- Final reporting subcrews:
  - `src/mosh/crews/reporting/writer_agents.yaml`
  - `src/mosh/crews/reporting/writer_tasks.yaml`
  - `src/mosh/crews/reporting/reviewer_agents.yaml`
  - `src/mosh/crews/reporting/reviewer_tasks.yaml`
- Source discovery crew:
  - `src/mosh/crews/source_discovery/agents.yaml`
  - `src/mosh/crews/source_discovery/tasks.yaml`

Python should bind live tool implementations to the YAML-defined agents, but agent roles, goals, backstories, task descriptions, and expected outputs should live in YAML.

Source discovery must keep deterministic tools as the fact base for model
assistance. The deterministic source index should identify app boundaries,
entrypoints, route/API candidates, route scope (`production`, `test`,
`example`, or `unknown` when needed), simple middleware/auth hints,
dependencies, configuration files, environment variable references, Docker
Compose service topology, and mobile app/dependency evidence. Model-assisted
steps may summarize, resolve ambiguous route mounts, and identify gaps, but
must preserve deterministic evidence and avoid inventing source files,
dependencies, routes, or deployment behavior.

Crew-specific Python code should also live with the crew. For example, the
discovery crew owns its `crew.py`, `agents.py`, `crawler.py`, `tools.py`, and
`reporting.py` modules under `src/mosh/crews/discovery/`. Shared
application primitives such as configuration, Docker execution, engagement
files, file-backed memory, shared models, and scope helpers stay at the
`mosh` package root.

## Shared Memory

Shared memory must be file-backed.

Agents can read from and add to shared memory. Memory writes must be recorded as observable events.

## Engagements And Assets

An engagement is the durable top-level assessment container. It is created with
a random path-safe ID and persisted under:

```text
report/<engagement-id>/engagement.json
```

Assets are the attached things under assessment. Current asset types are:

- `live_url`
- `source_tree`
- `source_repo`
- `mobile_app`

Asset attachment is registration only. It must not automatically run discovery
or testing. Asset type is inferred from the locator when possible, and callers
may pass an explicit type for ambiguous URLs.

Each asset is persisted under:

```text
report/<engagement-id>/assets/<asset-id>/asset.json
```

`engagement.json` stores only asset references: `id` and `created_at`. Asset
type, locator, label, and non-derived metadata are stored only in the asset's
`asset.json` to avoid duplicated state. Asset discovery paths must not be
stored in `asset.json`; they are derived from
`report/<engagement-id>/assets/<asset-id>/discovery/`.

Engagement discovery dispatches by asset type and writes:

```text
report/<engagement-id>/assets/<asset-id>/discovery/
```

By default `mosh discover <engagement-id>` runs discovery only for assets that
do not already have discovery output. `--asset <asset-id>` narrows discovery to
one or more assets, and `--refresh` forces a rerun for the selected assets.

Engagement-backed planning runs evidence linking as its first stage. The
temporary `mosh link <engagement-id>` command exposes the same operation
explicitly for diagnostics and regeneration. It reads asset discovery outputs
and writes source/live evidence relationships to:

```text
report/<engagement-id>/plan/links.json
```

The linker must not duplicate engagement or asset metadata from the directory
layout, `engagement.json`, or `asset.json`, including asset discovery
timestamps. It should record typed references back to asset IDs and their
evidence, plus an opaque discovery fingerprint used only to decide whether the
existing link output is current. It should link every discovered `live_url` and
`source_tree` pair, score exact and parameterized route matches, cap excessive
links per asset pair, and record skipped asset IDs with missing or unsupported
discovery evidence. After deterministic linking, it should run a bounded
model-assisted candidate pass using the planning crew's `evidence_linker`
model. The evidence linker may use only narrow read-only linkage tools:
`load_evidence_ref`, `source_search`, `source_read_slice`, and
`live_endpoint_metadata`. Source tools must be bounded to an existing
`source_ref_id`; live metadata checks must be bounded to an already discovered
`live_ref_id` and may only use HEAD, GET, or OPTIONS. Tool observations are
linkage support, not new discovery facts. The model may only relate existing
evidence reference IDs; invalid or invented refs must be ignored, and candidate
links must be marked separately from deterministic links. The CLI should emit
an immediate orchestrator start event for link generation and run the
planning-owned evidence linker with CrewAI verbose output when regeneration is
needed, matching discovery's user-visible execution style. `mosh plan
<engagement-id>` must call the same linker automatically rather than
implementing a second correlation path, then pass the resulting payload to the
planner as `correlation.evidence_links`. If no attached asset has discovery
newer than the previous engagement plan run, `mosh plan <engagement-id>` must
not regenerate `plan/links.json` or `plan/plan.md`. If the plan needs to run
but `plan/links.json` already matches the current discovery fingerprint, the
existing links must be reused rather than regenerated.

The planning, testing, and final reporting commands are being migrated to this
engagement root. During the migration, legacy URL/source compatibility commands
may still write host/source-rooted planning and testing outputs.

The model-assisted evidence linker is configured under the planning crew model
group as `models.security_planning.evidence_linker`, because its candidate
links are planning input rather than discovery facts.

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

## Output

Discovery output should be written under the asset selected for discovery:

```text
report/<engagement-id>/assets/<asset-id>/discovery/
```

Required outputs:

- Markdown final report
- JSON event log
- JSON shared memory

The final report should summarize the discovery activities and findings.

The final Markdown report is rendered by the discovery reporter-owned report-writing tool
from structured content authored by the discovery reporter agent. The report-writing tool
owns the Markdown section order and formatting so repeated runs remain comparable,
while the discovery reporter agent owns the observations, narrative content, confidence
levels, evidence, and recommendations.

The application should not write a final `report.json` artifact. Structured
runtime data remains available through `events.json` and `memory.json`.

Observable agent report output should be stored in shared memory or events. CrewAI
final chat/task responses are not sufficient by themselves unless the application
explicitly persists them.

## Initial Crew: Discovery

The first crew is the discovery crew.

The discovery crew is not expected to find vulnerabilities. Vulnerability discovery and testing will come later.

The discovery crew should focus on being excellent at appsec discovery.

### Discovery Crew Agents

The initial discovery crew has these agents:

- orchestrator: coordinates the discovery crew and routes work between agents
- crawler agent: discovers pages, links, URLs, paths, references, files, and forms
- technology mapper agent: identifies observable software components such as libraries, servers, frameworks, and related technologies
- reporter agent: summarizes findings and returns them to the orchestrator for reporting

### Discovery Crew Tool Ownership

The crawler is a tool owned by the crawler agent. The orchestrator must not call the crawler directly.

The crawler agent may have multiple crawler tools. Current crawler-owned tools are:

- application-native crawler tool
- Katana Docker crawler tool, run through the discovery tools container
- Dirb Docker discovery tool, run through the discovery tools container for bounded path discovery
- Extractify Docker tool, run through the discovery tools container for JavaScript endpoint and URL extraction
- static JavaScript endpoint discovery tool, run through the discovery tools container for AST-based endpoint resolution

The technology mapper agent currently performs its analysis through the
CrewAI task context and its LLM output. It should read crawler findings and
produce an evidence-based SBOM-style analysis as agent output. There is no
deterministic component inventory tool in the current implementation.

The discovery reporter agent owns summarization behavior and the report-writing tool. The
orchestrator may request reporting, but it must not synthesize the final report by
calling reporting helpers directly.

## Security Planning

Security planning is engagement-wide. It consumes discovery from all relevant
engagement assets, optional evidence links, and prior testing feedback, then
writes one plan under:

```text
report/<engagement-id>/plan/
```

Planning input must be a compact evidence bundle, not a raw dump of discovery
artifacts. The planner context should omit orchestration events, raw memory
logs, inline script bodies, and duplicated discovery blobs. It should retain
security-relevant summaries, structured discovery reports, bounded live routes,
forms, references, source routes, dependencies, configuration, evidence refs,
asset-scoped discovery details, and `correlation.evidence_links`. Nested text,
lists, and mappings must also be bounded so model-generated discovery reports
cannot cause planning context-window failures.

Planning must distinguish discovery-tool coverage gaps from execution blockers.
When an attached source asset is available, work that can be done with bounded
source reads, source searches, manual route extraction, prompt-template
extraction, configuration review, dependency inspection, generated harnesses, or
local source-runtime checks belongs in active `source` hypotheses. Only the
portion that genuinely needs an unattached asset/artifact, unsupported tooling,
mobile binary tooling, external accounts, deployment access, or unavailable
build/run inputs should remain deferred. The critic must reject accepted plans
that defer source-executable work solely because additional source inspection is
needed.

Planning must also distinguish scope/capability blockers from execution
readiness blockers. Missing credentials, test accounts, safe test data,
authorization confirmation, rate-limit permission, or completion of another
planned hypothesis should normally be represented in active hypotheses as
`requirements`, `preconditions`, `safety_notes`, `depends_on`,
`execution_readiness`, and `readiness_blockers`, with execution preflight
responsible for blocking or sequencing tests whose current engagement inputs are
incomplete. Valid `execution_readiness` values are `ready`,
`preflight_blocked`, `depends_on`, and `deferred`. Missing credentials,
authorization, safe test data, target mapping, budget, or prerequisite work are
not reviewer-blocking defects when they are explicitly represented on an
otherwise specific hypothesis. The planner may still defer the live portion when
the missing input prevents a safe, specific test definition, such as
external-service cost, production side effects, specialist tooling, or explicit
owner authorization that must be agreed first. The deterministic critic guard
must reject source-executable deferrals, but it must not force rejection solely
for execution-readiness deferrals.

During the engagement migration, the compatibility commands can still plan from
legacy URL/source discovery roots. The target architecture is one plan per
engagement, even when specialist crews have discovered different asset types.
Combined assessments are progressive enrichment: an assessment can start from a
live URL, source code, or another asset type, and additional assets can be
attached later. Source/live linking is an internal, repeatable operation that
connects evidence when both sides are available; it is not a mandatory
user-visible `correlate` phase. During the current migration, the temporary
`mosh link <engagement-id>` command exposes that operation explicitly for
rerunning and inspection.

Planned hypotheses must include deterministic routing fields:
`execution_mode`, `asset_refs`, `evidence_sources`, `affected_runtime`,
`affected_source`, `verification_strategy`, and `source_assessment_type`. For
source-routed tests, `source_assessment_type` classifies the expected execution shape as
`static-source-inspection`, `generated-harness`, `local-runtime-service`,
`dependency-tool-scan`, or `deferred-live-verification`; live and combined tests
use `live-verification` or `source-guided-live-verification`.

## Security Testing Crew

The security testing crew executes ready hypotheses from the security test plan.
It runs tests sequentially so reviewer feedback for one test can inform a bounded
rerun before the next test starts.

Security testing preflight routes hypotheses by `execution_mode` before any
executor runs:

- `live` hypotheses are the only tests sent to the current live URL security
  executor, and only when live target, authorization, credential, safe data, and
  engagement requirements are satisfied.
- `source` hypotheses are sent to the source security testing executor and are
  not sent to the live URL executor. Source-only execution may use bounded
  source inspection, source search, local tests, framework/build introspection,
  generated harnesses, explicit environment overrides, function-level
  experiments, or local runtime checks without requiring a deployed production
  URL.
- `combined` hypotheses are preserved for coordinated source inspection and
  live verification.
- `deferred` hypotheses are preserved with their requirements to proceed.

Security testing is engagement-wide and writes one result set under:

```text
report/<engagement-id>/security-testing/
```

The engagement-backed command is:

```bash
mosh test-security <engagement-id>
```

It reads the current plan from `report/<engagement-id>/plan/` and the shared
execution configuration from `report/<engagement-id>/engagement_template.yaml`.
When the target is an engagement ID, testing uses attached assets only; callers
must attach source assets instead of passing `--source`.

Source, live, combined, and future mobile-specialist executors are internal
routing choices. They must not create separate top-level testing result sets
that need manual synchronization. During the migration, source-only compatibility
preflight may still write `report/<source>/source-security-testing/`.

## Engagement File

The engagement template is user-owned execution configuration for the whole
engagement and is shared by planning and testing. The target location is:

```text
report/<engagement-id>/engagement_template.yaml
```

During the migration, compatibility planning commands may still write
`engagement_template.yaml` under `report/<host>/security-test-planning/` or
`report/<source>/security-test-planning/`.

The engagement file should stay small and directly editable. It should include:

- engagement permissions and notes
- production target mappings and optional alternative target mappings
- escalation contact details
- execution limits
- credential placeholders by role
- safe test data placeholders

It should not include explanatory readiness metadata such as `status`,
`needed_for`, `required_answers`, or long generated notes. Missing inputs,
blocked tests, and questions belong in `plan.md`, `security_test_plan.md`, `preflight.md`,
`events.json`, or `memory.json`.

Repeated security-planning runs must not overwrite non-empty values that the
user has already added to `engagement_template.yaml`. Generated or refined
templates should merge into the existing file, preserving filled credentials,
tokens, alternative targets, safe test data, contact details, limits, and notes
unless the user explicitly changes them. The LLM refiner must not invent secret
values; if it proposes credentials or tokens, the generated candidate is rejected
and the preserved existing configuration remains in place.

Before an existing `engagement_template.yaml` is rewritten, the previous file
must be copied into `engagement_template.backups/` with a timestamped filename.
This keeps a recoverable copy even when regeneration or refinement simplifies
the template shape.

The security testing crew has these agents:

- security test executor: runs scoped commands through the security tools Docker container
- security test reviewer: critiques evidence, safety, target scope, and useful generated artifacts
- security test reporter: writes the stable Markdown artifact for each executed test

The source security testing crew follows the same executor, reviewer, and
reporter pattern. Its executor can read bounded source slices, search
nonignored text files, write generated harnesses or fuzz scripts under `/work`,
run local commands with explicit environment overrides, start and stop local
processes, and issue localhost HTTP requests to those processes. The repository
is mounted read-only at `/source` and `/work` is the only writable workspace.
Source execution is for source-local evidence, local tests, compilation,
framework inspection, dependency checks, static source scanners, route-table
inspection, function-level experiments, and localhost runtime checks; arbitrary
external URL probing belongs to live or combined execution. The executor must
record a dynamic tool decision for every source hypothesis, explaining which
dynamic source-only tools were used or why static evidence was sufficient.
Executed reports include a dedicated dynamic source evidence section whenever
generated workspace files, local processes, or local HTTP requests were used.
The generic security tools image should include baseline HTTP utilities,
source-search utilities, Python/Node tooling, Semgrep, Bandit, pip-audit,
Java/OpenJDK, Maven, Corepack, and small project-inspection utilities. Large
platform SDKs such as Android and iOS should be added through specialized
runner profiles rather than the default image.

The executor may run commands, install packages, compile helper code, and write
scripts only inside the disposable Docker workspace. The orchestrator must not
run test tools directly.

Effective target mappings from the engagement file are canonical for execution,
review, and reporting. URLs in the original hypothesis may be production
discovery evidence. If an alternative staging or preprod target is mapped, agents
must execute and evaluate the mapped target rather than drifting back to the
original production URL.

Each executed test should preserve a structured execution bundle containing:

- final evidence
- final reviewer decision
- every executor/reviewer attempt
- command records
- useful artifacts generated during any attempt

Useful artifacts include generated policies, proof-of-concept payloads, endpoint
inventories, helper scripts, auth matrices, and remediation snippets. Reviewer
feedback may accept or reject artifacts separately from the final evidence
decision. A reviewer-requested rerun must not discard a useful artifact from an
earlier attempt; the final report should include it with status and caveats
unless it is unsafe or known invalid. The human Markdown report should render
the concrete artifact content, not internal artifact metadata or
description-only placeholders.

Each executed test report should include a `Resolution` section aimed at
developers and application owners. This section should explain how to remediate
an identified issue using concrete configuration, code, header, control, or
process changes where evidence supports them. If no issue is identified, the
section should state that no remediation is required for that hypothesis.
The executor must separate validation of the original hypothesis from adjacent
or residual findings. Planning priority is not finding severity, and disproving
the original hypothesis must not be rendered as `Finding Confirmed` unless a
separate supported finding object is submitted with its own title, severity,
impact, recommendation, and evidence.
The Markdown `Status` section should use human-readable labels such as
`Finding Confirmed`, `No Finding`, `Inconclusive`, `Needs Re-Run`,
`Not Applicable`, or `Execution Error`; canonical machine status values such as
`finding` should remain in embedded execution metadata.

Security testing can discover additional facts that belong back in discovery,
whether the evidence came from live execution or source-routed testing: new
entry points, endpoints, technologies, versions, service behavior, headers,
generated API specifications, or other app-surface information. The executor
should submit these as
structured `discovery_updates` in its evidence. After ready tests finish, the
security-testing orchestrator feeds those updates into the discovery crew's
file-backed memory, updates the discovery report with a deterministic `Security
Testing Feedback` section, and then asks the security planning crew to refresh
the test plan. The system does not immediately auto-run new tests from that
refreshed plan; additional execution happens on the next security-testing run
only if the refreshed plan contains ready, unexecuted hypotheses.

After a successful `test-security` run, the CLI must print a deterministic
human-readable summary of any blocked tests that still prevent completion. The
summary should list each blocked test ID, title, priority, and concrete
engagement-file fields or values needed to unblock it. This mirrors the
preflight data without requiring the user to open `preflight.md` for the next
action.

Security test completion is determined from metadata embedded in the latest
executed Markdown report, not from a separate execution index. Each
`executed_tests/<test_id>.md` report should include machine-readable execution
metadata containing at least the test ID, plan revision ID, hypothesis
fingerprint, status, reviewer acceptance, and execution time. A ready hypothesis
is skipped only when the latest report has matching accepted metadata for the
same hypothesis fingerprint. If the hypothesis changes after discovery-driven
replanning, if the previous execution was not accepted, or if the existing
report is legacy output without metadata, the test is queued for rerun.

Before a rerun overwrites `executed_tests/<test_id>.md`, the previous report must
be preserved under `executed_tests/history/` as a reference. This keeps older
security test output available while making the latest report the current
version.

To avoid runaway loops, duplicate security-testing discovery feedback must not
trigger another discovery update or security-planning refresh. Only feedback
facts not already present in discovery memory should cause the discovery report
to update and the security planning crew to refresh.

## Final Reporting Crew

The final reporting crew produces the customer-facing deliverable for a security
testing engagement. It runs after discovery, security planning, and security
testing:

```text
discover -> plan -> test-security -> report
```

The CLI command is:

```bash
mosh report https://app.example.com
```

The output path is:

```text
report/<host>/final-report/report.md
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

Final reporting must assemble a deterministic evidence bundle before the LLM
agents run. The bundle is built from discovery reports and memory, security test
planning reports and memory, security-testing preflight output, security-testing
memory, and current executed test reports. The bundle determines which executed
tests are confirmed findings for the final report. No-finding, inconclusive,
failed, or reviewer-rejected tests must not be promoted into detailed findings.

The Markdown report should read as a customer-facing document, not a raw tool
export. Avoid generic `Field`/`Value` table headings, include short explanatory
text before dense tables or bullet lists, and keep long generated paragraphs
split into readable blocks. Markdown remains the source deliverable for now;
HTML/PDF export may be added later as a presentation layer. Free-form source
evidence, reproduction notes, impact text, and remediation snippets must be
escaped or fenced when needed so malformed backticks from an execution artifact
cannot break the remainder of the report.

The final reporting crew has these agents:

- writer: writes the customer-facing report through the `write_final_report`
  tool
- reviewer: reviews the generated report through the
  `submit_final_report_review` tool

Both agents must be constrained by the deterministic bundle. The writer may make
the report easier to read, but must not invent findings, affected systems,
severity, evidence, remediation, or CVSS scores. The reviewer must reject reports
that introduce unsupported claims or omit confirmed findings.

Customer-facing language should use `findings` or `confirmed findings`, not
`accepted findings`. In implementation, a confirmed finding means the executed
test status is `finding` and the review stage accepted it for inclusion in the
report; it does not mean the customer has accepted or agreed with the finding.

Qualitative severity should be sourced deterministically. Use current security
plan priority when available, then executed test metadata, then the executed
test report Scope priority. This preserves severity for accepted historical
findings that no longer appear in the latest refreshed plan.

CVSS is optional. It may be included only when already present in source
execution evidence. If the bundle does not contain a CVSS score/vector for a
finding, the final report must state `Not scored`.

## Discovery Scope

The only current target type is a URL.

Stay within the main domain of the app passed in the URL.

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

The crawler can be implemented inside the application. External crawler tools, such as Katana, must run through Docker and still be invoked as crawler agent tools. Katana should run with headless browser execution enabled, system Chromium selected, Chrome sandboxing disabled for root execution, XHR extraction enabled, and automatic form fill enabled for unauthenticated discovery.

Dirb should run as a crawler-owned Docker tool for additional path discovery.
The initial Dirb integration should use a bounded wordlist, a bounded Docker
timeout, and non-recursive execution. Dirb findings are discovery candidates,
not crawled pages. Each candidate should include URL, source tool, status, kind,
confidence, reason, evidence, and whether it should be crawled. Candidates
should be scope-filtered, linked back to the crawl root as evidence, and merged
into the aggregate crawl state. The crawler agent should process a bounded
follow-up crawl queue for crawl-worthy candidates. Dirb should discover
candidate paths; it should not replace the crawler or perform vulnerability
testing.

The crawler agent should keep a per-run registry of URLs that have already been
crawled. Before invoking a crawler tool, the crawler agent should check this
registry. If the requested URL has already been crawled, it should skip the
duplicate tool call, record the skip decision in `events.json`, and return the
current crawl findings to the agent. Distinct crawl roots discovered during the
run should be merged into the aggregate crawl state for later agents.

When the crawler discovers JavaScript assets, it may invoke Extractify to extract
additional endpoints and URLs from those JavaScript files. Extractify findings
should be scope-filtered, linked back to the JavaScript source as evidence, and
merged into the aggregate crawl state.

When JavaScript assets are discovered, the crawler should also have access to a
static JavaScript endpoint discovery tool. This tool should complement Katana and
Extractify: Katana observes runtime browser and XHR/fetch behavior, Extractify
finds broad URL-like strings, and the static analyzer resolves common JavaScript
construction patterns that produce API paths from constants, aliases, base URL
globals, concatenation, and template literals. Static findings must be
scope-filtered, linked back to the JavaScript source as evidence, and merged into
the aggregate crawl state.

## Future Scope

Future versions may add:

- additional crews that run alongside discovery
- additional static security tool wrappers and parsers
- vulnerability testing agents
- more Docker-backed tools

These future additions must still follow:

```text
orchestrator -> agent -> tools
```

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
- security-testing feedback into discovery memory, discovery reporting, and replanning
- security test rerun decisions from embedded report metadata and preserved history

# Roadmap

* Implement security testing for source code, based on a repo URL or a local filesystem path. See `SOURCE_ASSESSMENT_PLAN.md` for the staged implementation plan.
* If the user provides source code and a live URL for testing, use progressive combined assessment: start from whichever evidence source is available, attach the other one later if needed, and let source/live evidence links enrich planning, testing, and reporting. This needs to be more than the sum of the parts, for instance (but not limited to): source code allows for better discovery of vulnerabilities, live URL allows findings on deployment that is not included in code, live URL allows for testing and verification of flaws detected in source code, fixes in the report can now be linked to source code (e.g. more specific). Do not make a standalone correlation command the required long-term workflow; the temporary `mosh link` command exists only for the engagement migration. See `SOURCE_ASSESSMENT_PLAN.md` for the combined source/live design.
* We want the user to have the chance to provide feedback after each crew stage, e.g. to fine tune the results or point the testing in another direction, examples (but not limited to): a URL was considered in-scope when it is not, testing did not include a section which is important for the user, the user wants to provide some discovery additional information not identified by the tool, the user wants additional tools to be run in a specific stage, etc.
* Implement abiity to use arbitraty openai-like API backends (custom), for companies that do not have openrouter or deepseek access (maybe those using internal AI API endpoints)
* Right now the user needs to know the various stages of an assessment and provide them in the correct order. We should explore simplifying this (without removing current capabilities).
* We want the user to be able to provide 'system prompts' to adapt the testing to their own needs
* Move the tool execution to docker, e.g. remove local dependencies
* Incorporate a RAG so that executions are remembered and the agents learn from each execution
* Create a web-based GUI that allows the user to acess all engagements, monitor progress for an engagement, provide input / steering during execution, and do an export of the report(s) to PDF. The GUI would have an onboarding wizard to ask for keys or anything else that may be required.
* We want to improve the application based on results of testing, create an improver crew that works on this, for instance (but not limited to): adding new tools, fine-tuning prompts, deciding to introduce or remove stages, etc.
* We do not have security testing tools that focus on mobile app inspection, reverse-engineering. Security test planning leaves these out of scope because of this, we may want to add some mobile-client focused security testing tools.
* As targets grow, we will run out of context very quickly during planning phase - check if planning can be done per asset + links, and what is the difference in output.
