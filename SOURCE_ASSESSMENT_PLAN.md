# Source Code Assessment Plan

## Purpose

Add source code assessment to `mosh` without weakening the existing
orchestrator -> agent -> tools pattern. The system should support:

- source-only assessments from a local filesystem path or repository URL
- live-only assessments using the current URL workflow
- combined assessments where source code and a live URL improve each other

The implementation should proceed in small, testable increments.

## Design Principles

- Keep live discovery and source discovery separate. A deployed application and
  a repository answer different questions.
- Do not place whole repositories into model context. Agents should receive
  compact summaries and retrieve bounded source slices through tools.
- Persist all useful source evidence in file-backed memory and stable Markdown
  artifacts.
- Use deterministic routing fields in plans instead of inferring execution mode
  from prose.
- Preserve source evidence as file paths, line ranges, symbols, and snippet
  hashes so reports can link findings to code.
- Treat combined assessments as progressive evidence enrichment. An assessment
  can start from either a live URL or source code, and the other evidence source
  can be attached later without starting a separate workflow.
- Let source and live testing feed new facts back into discovery, evidence
  linking, planning, and reporting.
- Do not make source/live correlation a mandatory batch phase. Evidence linking
  is an internal, repeatable operation that runs when both sides have useful
  evidence.

## Target Workflows

### Live Only

The current workflow remains valid:

```text
discover URL -> plan-security URL -> test-security URL -> report URL
```

### Source Only

Add a source-only workflow:

```text
discover-source SOURCE -> plan-security --source SOURCE -> test-security --source SOURCE -> report SOURCE
```

`SOURCE` may be a local path at first. Repository URL support can follow once
the local path flow is stable.

### Combined Source And Live

Combined assessments use progressive enrichment instead of a mandatory
`discover live -> discover source -> correlate` sequence. The assessment owns
all evidence gathered for the target, and live URLs or source code can be added
in either order.

Live-first assessment:

```text
discover URL -> plan-security URL -> test-security URL -> report URL
add source -> discover-source SOURCE -> link evidence -> re-plan deltas -> test-security URL --source SOURCE -> report URL --source SOURCE
```

Source-first assessment:

```text
discover-source SOURCE -> plan-security --source SOURCE -> test-security --source SOURCE -> report SOURCE
add live URL -> discover URL -> link evidence -> re-plan deltas -> test-security URL --source SOURCE -> report URL --source SOURCE
```

Both-provided assessment:

```text
discover URL and discover-source SOURCE in either order
link evidence as soon as both sides have useful facts
plan-security URL --source SOURCE
test-security URL --source SOURCE
report URL --source SOURCE
```

The combined workflow should be more than two independent scans:

- source discovery can identify hidden routes, API shapes, authorization checks,
  feature flags, data flows, and code-level fix locations
- live discovery can identify deployed headers, services, behavior, reachable
  routes, and runtime configuration that may not exist in source
- source findings can become live verification hypotheses
- live findings can be mapped back to likely source files for remediation

## Output Layout

Keep the existing host-based layout for URL engagements. For source-only
engagements, derive a stable source directory name from the repository basename
or local directory name, with collision-safe normalization.

Proposed outputs:

```text
report/<engagement>/discovery/
report/<engagement>/source-discovery/
report/<engagement>/evidence-links/
report/<engagement>/security-test-planning/
report/<engagement>/security-testing/
report/<engagement>/source-security-testing/
report/<engagement>/final-report/
```

Each crew keeps its own `events.json`, `memory.json`, and Markdown report.
The evidence-links artifact records relationships between live and source
evidence; it does not replace either discovery artifact and is not a required
user-visible workflow stage.

## New Crews

### Source Discovery Crew

Purpose: create a compact, evidence-backed map of the source tree.

Agents:

- source intake agent: validates local paths, later materializes repository
  URLs, records source identity, commit SHA, dirty state, and ignore rules
- source mapper agent: builds the file, language, framework, route, API, auth,
  session, and data-flow inventory
- source route resolver agent: uses bounded source evidence to resolve
  deterministic API candidates to full paths when mounts or prefixes are
  ambiguous
- dependency and config agent: inspects manifests, lockfiles, Dockerfiles,
  deployment hints, environment templates, and CI configuration
- source component mapper agent: summarizes application purpose, key
  components, sensitive data, and trust boundaries from deterministic evidence
- source gap analyst agent: records discovery limitations and follow-up needed
  before source-backed security planning
- source reporter agent: writes the stable source discovery report

Initial tools:

- `validate_source_path`
- `source_inventory`
- `source_search`
- `read_source_slice`
- `route_api_extractor`
- `get_route_resolution_context`
- `submit_route_resolution`
- `dependency_inventory`
- `config_inventory`
- deterministic route scope and middleware hint extraction
- environment variable inventory scanner
- Docker Compose topology extractor
- Python web app detector, including FastAPI-style services
- mobile dependency extractors for Gradle, CocoaPods, and Swift Package
- `get_source_discovery_context`
- `submit_source_component_map`
- `submit_source_gap_analysis`
- security tools image with Semgrep, Bandit, pip-audit, Java/OpenJDK, Maven,
  Corepack, and common project-inspection utilities for source execution

Later tools:

- `repo_materializer`
- `semgrep_baseline` as a structured wrapper around the installed Semgrep
  binary
- redacted secret scanner
- language-specific call graph or framework route extractors

### Source-Live Evidence Linking

Purpose: connect live discovery and source discovery into actionable
relationships without replacing either artifact or requiring a separate batch
workflow.

Agents:

- endpoint mapper: maps live URLs and source routes to each other
- deployment gap analyst: identifies source-only routes, live-only behavior, and
  configuration drift
- verification planner: proposes which source findings need live proof and which
  live findings need source remediation references
- evidence link reporter: writes stable source/live relationship records

Evidence-link outputs should include:

- live endpoint -> source route/controller references
- source route -> observed or unobserved live endpoint status
- source-only candidates to feed into discovery or testing
- live-only deployment findings that may not be present in source
- verification opportunities for combined testing

### Source Security Testing Crew

Purpose: execute source-backed security hypotheses using controlled tooling,
bounded source reads, generated harnesses, and local runtime experiments.

Agents should mirror the current security testing pattern:

- source security test executor
- source security evidence reviewer
- source security reporter

The executor should run commands in a disposable Docker workspace with the
source tree mounted read-only and a separate writable `/work` directory. It can
write bounded harnesses or fuzz scripts under `/work`, set explicit environment
overrides, start and stop local processes, and issue local HTTP requests for
route-table inspection or runtime behavior checks. These primitives are generic;
framework-specific behavior should be encoded by generated harnesses rather
than hard-coded into the orchestrator.

Planning should classify each source-routed hypothesis with
`source_assessment_type`: `static-source-inspection`, `generated-harness`,
`local-runtime-service`, `dependency-tool-scan`, or
`deferred-live-verification`. The executor should use that classification to
make an explicit dynamic-tool decision before submitting evidence.

Reports should mirror executed live test reports and include:

- embedded execution metadata
- command records
- source evidence references
- dynamic source evidence sections for generated harnesses, local processes,
  and local HTTP requests when present
- reviewer acceptance
- finding status
- concrete remediation guidance

Source reports should also distinguish the original hypothesis result from
residual hardening gaps. If source evidence disproves the planned hypothesis,
the status should be `no-finding` or `inconclusive` unless the executor submits
a separate retitled finding with its own severity, impact, recommendation, and
evidence.
Source security testing can also discover new source facts such as route
inventories, generated API specifications, entry points, components, or
environment-dependent behavior. These `discovery_updates` feed back into source
discovery and trigger a planning refresh in the same way live security-testing
feedback does.
- links to affected files and line ranges

## Source Index

Large repositories require an index-first approach. The source discovery crew
should create a compact source index before any LLM planning step.

Recommended index fields:

```json
{
  "schema": "mosh.source-index.v1",
  "source": {
    "kind": "local-path",
    "path": "/path/to/repo",
    "repo_url": null,
    "commit_sha": "unknown",
    "dirty": null
  },
  "inventory": {
    "files": [],
    "languages": {},
    "frameworks": [],
    "entrypoints": [],
    "routes": [],
    "apis": [],
    "auth": [],
    "sessions": [],
    "data_stores": [],
    "dependencies": [],
    "configuration": []
  },
  "evidence_refs": []
}
```

`files` should exclude common vendor, build, cache, generated, binary, and lock
directories unless a specific tool needs them. Lockfiles and manifests should be
kept because they are security-relevant.

Source evidence references should use this shape:

```json
{
  "path": "app/routes/users.py",
  "start_line": 41,
  "end_line": 88,
  "symbol": "update_user",
  "snippet_hash": "sha256:...",
  "reason": "authorization check before account update"
}
```

## Planning Changes

Replace the planning crew's single discovery context with an assessment evidence
bundle:

```json
{
  "live_discovery": {},
  "source_discovery": {},
  "evidence_links": {},
  "prior_security_testing_feedback": {},
  "prior_source_testing_feedback": {}
}
```

Existing code may temporarily expose this section as `correlation` while the
implementation migrates, but the architecture should treat it as evidence links,
not as a required standalone correlation phase.

Security hypotheses should gain deterministic routing fields:

```json
{
  "execution_mode": "live",
  "evidence_sources": ["live", "source"],
  "affected_runtime": [
    {"method": "GET", "url": "/api/users/{id}"}
  ],
  "affected_source": [
    {"path": "app/routes/users.py", "start_line": 41, "end_line": 88}
  ],
  "verification_strategy": "source-guided-live-verification"
}
```

Allowed `execution_mode` values:

- `live`: execute through the current live security testing crew
- `source`: execute through source security testing
- `combined`: needs both source inspection and live verification
- `deferred`: valuable, but blocked by missing source, URL, credentials, build
  instructions, authorization, or tooling

Preflight should route hypotheses by `execution_mode` and explicit blockers.

## Combined Assessment Behavior

The combined assessment should support these loops:

- source discovery finds unobserved route -> evidence linking creates a live
  discovery candidate -> planning may add live verification
- live testing finds behavior or header issue -> evidence linking maps to config
  or source files -> final report includes specific remediation location
- source testing finds authorization or input validation weakness -> live
  testing attempts bounded verification when authorized
- source dependency/config evidence enriches final remediation even when runtime
  proof is unavailable

The final report should label confidence and evidence type:

- live-confirmed
- source-confirmed
- source-suspected, live-not-observed
- live-confirmed, source-location-mapped
- deployment/config finding not present in source

## CLI Direction

Start with explicit commands:

```bash
mosh discover-source /path/to/repo
mosh plan-security --source /path/to/repo
mosh test-security --source /path/to/repo
```

Then add combined variants:

```bash
mosh plan-security https://app.example.com --source /path/to/repo
mosh test-security https://app.example.com --source /path/to/repo
mosh report https://app.example.com --source /path/to/repo
```

Do not add `mosh correlate` as the primary combined workflow. If an explicit
linking command is later useful for debugging or recomputing relationships, it
should be named and documented as evidence-link maintenance, not as the required
spine of a combined assessment.

Repository URL support can later reuse the same source discovery path after a
materialization step:

```bash
mosh discover-source https://github.com/example/app.git
```

## Implementation Milestones

1. Add source target naming and output directory helpers.
2. Add source model configuration keys to `mosh.yaml` validation.
3. Implement local-path `source-discovery` with deterministic tools and tests.
4. Write `source-discovery/report.md`, `events.json`, and `memory.json`.
5. Done: Change planning to build an assessment evidence bundle.
6. Done: Extend planner/reviewer prompt contracts with `execution_mode`,
   `evidence_sources`, `affected_runtime`, `affected_source`, and
   `verification_strategy`.
6a. Done: Add `source_assessment_type` to classify source hypotheses as static
    source inspection, generated harness/function experiment, local runtime
    service/API experiment, dependency/tool scan, or deferred live verification.
7. Done: Extend preflight to route source, live, combined, and deferred
   hypotheses. Source-only `test-security --source` writes a source preflight
   and does not send source-routed hypotheses to the live URL executor.
8. Done: Implement source security testing with bounded source reads, bounded
   source search, read-only source mount, generated workspace harnesses,
   explicit environment overrides, local command records, local process start
   and stop, local HTTP requests, reviewer loop, report metadata, and rerun
   decisions. Source-only execution can use local commands and localhost
   runtime checks without requiring an external deployed URL.
9. Add source-live evidence linking for combined assessments. This should run
   incrementally when both live and source evidence are present, and planning
   should consume the current links without requiring a separate user-visible
   correlation command.
10. Extend final reporting bundle and renderer with source evidence, source
    remediation guidance, and evidence labels.
11. Add repository URL materialization after local path source assessment is
    stable.

## Testing Plan

Add tests with small fixture repositories instead of relying on real projects.

Unit tests:

- source target naming and path normalization
- source inventory ignores vendor/build/generated directories
- source inventory keeps security-relevant manifests and lockfiles
- route/API extractor fixtures for at least one simple Python or Node app
- source evidence reference generation
- planning evidence bundle assembly
- preflight routing by `execution_mode`
- source command runner mounts source read-only
- source report metadata extraction and rerun decisions
- final report source evidence rendering

Integration-style tests with fakes:

- source discovery crew writes memory, events, and report artifacts
- source-only planning consumes source discovery
- combined evidence linking consumes live and source discovery
- source testing produces accepted and rejected executed test reports
- source testing feedback can refresh planning without duplicate loops

## First Increment

The first useful increment should be intentionally small:

```text
mosh discover-source /path/to/repo
```

It should:

- validate the path
- create `report/<source>/source-discovery/`
- inventory files, languages, manifests, configs, and likely entrypoints
- persist a compact source index in memory
- write a source discovery Markdown report
- include unit tests and a fixture repository

After that works, planning can consume source discovery as an additional bundle
without yet adding source execution.
