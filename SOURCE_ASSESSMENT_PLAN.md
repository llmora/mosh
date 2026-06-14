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
- Let source and live testing feed new facts back into discovery, correlation,
  planning, and reporting.

## Target Workflows

### Live Only

The current workflow remains valid:

```text
discover URL -> plan-security URL -> test-security URL -> report URL
```

### Source Only

Add a source-only workflow:

```text
discover-source SOURCE -> plan-security SOURCE -> test-source-security SOURCE -> report SOURCE
```

`SOURCE` may be a local path at first. Repository URL support can follow once
the local path flow is stable.

### Combined Source And Live

When the user provides both a live URL and source code:

```text
discover URL
discover-source SOURCE
correlate URL SOURCE
plan-security URL --source SOURCE
test-security URL
test-source-security SOURCE
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
report/<engagement>/correlation/
report/<engagement>/security-test-planning/
report/<engagement>/security-testing/
report/<engagement>/source-security-testing/
report/<engagement>/final-report/
```

Each crew keeps its own `events.json`, `memory.json`, and Markdown report.

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

Later tools:

- `repo_materializer`
- `semgrep_baseline`
- redacted secret scanner
- language-specific call graph or framework route extractors

### Source-Live Correlation Crew

Purpose: merge live discovery and source discovery into actionable relationships.

Agents:

- endpoint mapper: maps live URLs and source routes to each other
- deployment gap analyst: identifies source-only routes, live-only behavior, and
  configuration drift
- verification planner: proposes which source findings need live proof and which
  live findings need source remediation references
- correlation reporter: writes a stable correlation report

Correlation outputs should include:

- live endpoint -> source route/controller references
- source route -> observed or unobserved live endpoint status
- source-only candidates to feed into discovery or testing
- live-only deployment findings that may not be present in source
- verification opportunities for combined testing

### Source Security Testing Crew

Purpose: execute source-backed security hypotheses using controlled tooling and
bounded source reads.

Agents should mirror the current security testing pattern:

- source security test executor
- source security evidence reviewer
- source security reporter

The executor should run commands in a disposable Docker workspace with the
source tree mounted read-only and a separate writable `/work` directory.

Reports should mirror executed live test reports and include:

- embedded execution metadata
- command records
- source evidence references
- reviewer acceptance
- finding status
- concrete remediation guidance
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
  "correlation": {},
  "prior_security_testing_feedback": {},
  "prior_source_testing_feedback": {}
}
```

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

- source discovery finds unobserved route -> correlation creates live discovery
  candidate -> planning may add live verification
- live testing finds behavior or header issue -> correlation maps to config or
  source files -> final report includes specific remediation location
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
mosh test-source-security /path/to/repo
```

Then add combined variants:

```bash
mosh correlate https://app.example.com --source /path/to/repo
mosh plan-security https://app.example.com --source /path/to/repo
mosh report https://app.example.com --source /path/to/repo
```

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
5. Change planning to build an assessment evidence bundle.
6. Extend planner/reviewer prompt contracts with `execution_mode`,
   `evidence_sources`, `affected_runtime`, `affected_source`, and
   `verification_strategy`.
7. Extend preflight to route source, live, combined, and deferred hypotheses.
8. Implement source security testing with read-only source mount, command
   records, reviewer loop, report metadata, and rerun decisions.
9. Add source-live correlation for combined assessments.
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
- combined correlation consumes live and source discovery
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
