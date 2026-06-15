<p align="center">
  <img src="assets/brand/social/mosh-readme-header.svg" alt="mosh logo" width="760">
</p>

# mosh: Model-driven Open Security Harness

Find security vulnerabilities in your applications and resolve them, using AI to simulate the tasks a security researcher runs.

## Why do I need a harness?

Using LLMs to test the security of an application is a lot more than just pointing a model at it and letting it go. The application needs to be scoped, the tests need to be adapted to the application, the model needs tools to interact with the application under test and execution needs to be controlled, evidenced, and repeatable. `mosh` implements the harness that wraps around models to conduct a security test.

`mosh` simulates the core tasks a security researcher performs when testing an application:

- **Discovery:** map the application surface, routes, links, forms, JavaScript assets, third-party services, and observable technologies.
- **Security planning:** turn discovery evidence into scoped, testable security hypotheses.
- **Test execution:** run ready tests through controlled Docker-backed tooling using explicit engagement settings.
- **Reporting:** write Markdown reports, structured event logs, and shared memory so findings are reviewable and reproducible.

When more advanced LLM models are released, you do not need to modify the harness, just configure `mosh` to use the new models instead.

## Installation

0. Install these prerequisites first:

- Python 3.11 or newer
- Docker

1. Clone the repository:

```bash
git clone https://github.com/llmora/mosh.git
cd mosh
```

2. Run setup:

```bash
./scripts/setup.sh
```

The setup script creates `.venv`, installs Model-driven Open Security Harness in editable mode, and builds the Docker tool images.

3. Activate the environment:

```bash
source .venv/bin/activate
```

## Configuration

Set an LLM API key before running the CLI.

For the default direct DeepSeek setup, open an account at deepseek.com and generate an API key:

```bash
export DEEPSEEK_API_KEY="your-deepseek-api-key"
```

Or route through OpenRouter, open an account at openrouter.ai and generate an API key:

```bash
export OPENROUTER_API_KEY="your-openrouter-api-key"
```

### Model Selection

By default, `mosh` uses DeepSeek models to balance quality and cost. To choose different models, create `mosh.yaml` in the directory where you run the CLI:

```yaml
models:
  discovery:
    crawler: deepseek/deepseek-v4-flash
    technology_mapper: deepseek/deepseek-v4-flash
    reporter: deepseek/deepseek-v4-flash

  source_discovery:
    intake: deepseek/deepseek-v4-flash
    mapper: deepseek/deepseek-v4-flash
    route_resolver: deepseek/deepseek-v4-flash
    dependency_config: deepseek/deepseek-v4-flash
    component_mapper: deepseek/deepseek-v4-flash
    gap_analyst: deepseek/deepseek-v4-flash
    reporter: deepseek/deepseek-v4-flash

  security_planning:
    planner: deepseek/deepseek-v4-flash
    reviewer: deepseek/deepseek-v4-pro
    reporter: deepseek/deepseek-v4-flash
    engagement_refiner: deepseek/deepseek-v4-flash

  security_testing:
    executor: deepseek/deepseek-v4-flash
    reviewer: deepseek/deepseek-v4-pro
    reporter: deepseek/deepseek-v4-flash

  reporting:
    writer: deepseek/deepseek-v4-flash
    reviewer: deepseek/deepseek-v4-pro
```

Only include the agents you want to override; omitted agents keep their defaults. For example:

```yaml
models:
  discovery:
    crawler: openai/gpt-5.2-mini

  source_discovery:
    mapper: openai/gpt-5.2-mini

  security_planning:
    reviewer: openai/gpt-5.2

  security_testing:
    reviewer: openai/gpt-5.2

  reporting:
    reviewer: openai/gpt-5.2
```

Use OpenRouter model IDs such as `openai/gpt-5.2` or `anthropic/claude-sonnet-4.5`. DeepSeek IDs such as `deepseek/deepseek-v4-flash` use `DEEPSEEK_API_KEY` directly when it is set; otherwise they route through OpenRouter and require `OPENROUTER_API_KEY`.

## Running A Security Scan

### 1. Run Discovery

Start by mapping the application:

```bash
mosh discover https://app.example.com
```

Discovery writes:

```text
report/<host>/discovery/report.md
```

Optional tuning flags:

```bash
mosh discover https://app.example.com --max-pages 100 --max-depth 4 --output-root report
```

### Source Discovery

You can also map a local source tree:

```bash
mosh discover-source /path/to/repo
```

Source discovery writes:

```text
report/<source>/source-discovery/report.md
```

This first source increment builds a compact source index, including files,
languages, manifests, lockfiles, likely entrypoints, route/API candidates,
dependencies, and configuration/deployment files. It then uses bounded
model-assisted steps to resolve route candidates to full paths when router
mounts are ambiguous, summarize the application's apparent purpose, map key
business/security components, identify sensitive data and trust boundaries, and
record discovery gaps that need follow-up. Source evidence is stored as file
paths, line numbers, and snippet hashes so later planning and reporting can
refer back to code without putting an entire repository in model context.
Deterministic discovery also tags test/example routes, records simple
middleware chains, expands common custom route wrapper patterns, detects Python
web services such as FastAPI, inventories environment variable references and
Docker Compose service topology, and parses npm, Python, Gradle, CocoaPods, and
Swift Package dependency manifests.

### 2. Create A Security Test Plan

Once discovery has produced evidence, ask `mosh` to turn it into testable hypotheses:

```bash
mosh plan-security https://app.example.com
```

To plan from source discovery only:

```bash
mosh plan-security --source /path/to/repo
```

To combine live and source discovery evidence:

```bash
mosh plan-security https://app.example.com --source /path/to/repo
```

Live-only planning reads from `report/<host>/discovery/`. Source-aware planning
also reads from `report/<source>/source-discovery/` and asks the planner to
route hypotheses with `execution_mode` values of `live`, `source`, `combined`,
or `deferred`, including affected runtime and source evidence where available.
Planning writes:

```text
report/<host>/security-test-planning/security_test_plan.md
report/<host>/security-test-planning/engagement_template.yaml
```

For source-only planning, the output is written under:

```text
report/<source>/security-test-planning/
```

### 3. Review The Engagement File

Before running security testing, review and edit:

```text
report/<host>/security-test-planning/engagement_template.yaml
```

This file is deliberately small. It is where you confirm:

- authorization and active testing permissions
- production target mappings
- alternative staging or pre-production target mappings
- escalation contact details
- execution limits
- credentials by role
- safe test data

The security testing crew treats this file as execution configuration. If you map a production target to an alternative target, tests run against the mapped target (useful if you want to run the tests against a pre-prod environment). You can also add other information that you may think will be useful to the testing, the model inspects and automatically uses anything you have provided to improve its testing.

### 4. Run Security Testing

When the plan and engagement file are ready, run:

```bash
mosh test-security https://app.example.com
```

For a source-only plan, run:

```bash
mosh test-security --source /path/to/repo
```

For a combined live and source plan, pass both:

```bash
mosh test-security https://app.example.com --source /path/to/repo
```

Security testing writes:

```text
report/<host>/security-testing/preflight.md
report/<host>/security-testing/executed_tests/
report/<host>/security-testing/executed_tests/history/
```

Source-only preflight writes:

```text
report/<source>/source-security-testing/preflight.md
report/<source>/source-security-testing/executed_tests/
report/<source>/source-security-testing/executed_tests/history/
```

Source-only security testing executes source-routed hypotheses without requiring
a deployed production URL. The source executor can read bounded source slices,
search nonignored text files, write generated harnesses or fuzz scripts under
`/work`, run local commands with explicit environment overrides, start a local
process in the security tools container, issue localhost HTTP requests to it,
and stop it after collecting evidence. The repository is mounted read-only at
`/source` and `/work` is the only writable workspace. This supports static
inspection, local tests, build or framework introspection, function-level
experiments, route-table inspection, and local runtime checks while keeping
external live URL testing separate.

Every security-testing run starts with a preflight. The preflight reads the security test plan and engagement file, then separates planned tests into:

- **Ready tests:** live URL tests with enough authorization, target, credential, and safe test-data information available, so the live executor can run them.
- **Source-routed tests:** source inspection, source tooling, or local-runtime tests. These are sent to the source security executor, not the live URL executor.
- **Combined tests:** tests that need both source inspection and live verification. They are preserved for coordinated source/live execution.
- **Deferred tests:** useful tests blocked by missing deployment, runtime, credentials, tooling, scope, or setup.
- **Blocked tests:** required information is missing or the engagement file does not allow the test yet.

Open `preflight.md` after the first run. It tells you which tests were ready, which were blocked, and what information is missing. After a successful `test-security` run, the CLI also prints any blocked tests that still prevent completion, with deterministic engagement-file fields to update. Common blockers include missing authorization confirmation, active testing permission, state-changing test permission, role credentials, safe test data, or target mappings.

You can run security testing repeatedly to incrementally complete the test:

```bash
mosh test-security https://app.example.com
```

If you fill in missing information in `engagement_template.yaml` and run the command again, previously blocked tests can become ready and will be executed. Tests that already have a current, review-confirmed execution report are skipped; tests are rerun when the planned hypothesis changes, the previous report was not confirmed by review, or the previous report was created before execution metadata was available. Older reports are kept under `executed_tests/history/`.

If executed tests discover new application surface area, `mosh` feeds those facts back into discovery memory, updates the discovery report, and refreshes the security test plan. It does not immediately auto-run newly planned tests; run `test-security` again when you are ready to execute any newly ready tests.

### 5. Create The Final Report

When security testing is complete, create the customer-facing engagement report:

```bash
mosh report https://app.example.com
```

Final reporting writes:

```text
report/<host>/final-report/report.md
```

The final report is different from the working documents used during testing. It incorporates the main discovery context, the executed test outcomes, the confirmed findings, severity, remediation guidance, and an appendix for tests that produced no finding, were inconclusive, failed, or were not confirmed by review.

The report is structured as a customer deliverable:

- Executive Summary: security-executive prose covering application context, what was tested, overall posture, headline risks, and finding counts by severity
- At A Glance: short prose summary of the business/application context, confirmed findings, highest qualitative severity, no-finding tests, inconclusive tests, and human-readable engagement timeline
- Remediation Priorities: findings ordered by qualitative severity so fixes can be prioritized quickly
- Engagement Overview: prose explanation of target, effective target mappings, lifecycle dates from discovery through final reporting, scope, limitations, and testing approach
- Summary of Findings: findings table sorted by severity and remediation priority, severity counts, and confirmed/inconclusive/failed/no-finding breakdown
- Key Discovery Areas: important routes, auth areas, APIs, forms, technologies, exposed surfaces, and limitations
- Detailed Findings: confirmed findings only, with evidence, impact, technical remediation guidance, source-specific fix details or pseudo-code when available, retest guidance, and references when available
- Tests With No Finding / Inconclusive: concise appendix for tests that are not confirmed findings
- Appendix: methodology, tools used, evidence index, and raw report references

CVSS is included only when it is present in the source execution evidence. Otherwise the final report marks it as `Not scored`.

Qualitative severity is taken from source evidence. If a finding no longer appears in the latest security plan, `mosh` falls back to the executed test report metadata and Scope section rather than losing the severity.

The Markdown report is intended to be readable as-is. Source evidence and remediation snippets are fenced when needed so malformed Markdown from an execution artifact cannot quote the rest of the report. A styled HTML/PDF export can sit on top later, but the Markdown remains the source deliverable so it is easy to review, diff, and version.

## End-To-End Example

```bash
mosh discover https://app.example.com
mosh plan-security https://app.example.com

# Review and edit report/app.example.com/security-test-planning/engagement_template.yaml.

mosh test-security https://app.example.com

# If the CLI reports blocked tests, add the missing engagement details and run it again.
mosh test-security https://app.example.com

mosh report https://app.example.com
```

## What You Get

After a full run, you have:

- a discovery report describing observed application surface area
- a security test plan grounded in discovery evidence
- an editable engagement template for permissions, targets, credentials, limits, and safe test data
- executed test reports, including resolution
- a final customer-facing Markdown report

## Resolving vulnerabilities

Security testing reports are written to:

```text
report/<host>/security-testing/executed_tests/
```

Each executed test report is designed to support remediation, not just detection. Use it to understand:

- what was tested
- which target and role were used
- what evidence was collected
- whether the issue was accepted, rejected, or needs more review
- what fix or mitigation is recommended
- what should be rerun after the application has been changed

A practical remediation loop looks like this:

1. Review the executed test report and confirm the finding against the recorded evidence.
2. Fix the vulnerable behavior in the application.
3. Redeploy the application to the target environment covered by the engagement file.
4. Run security testing again:

```bash
mosh test-security https://app.example.com
```

`mosh` compares the current plan and execution metadata with previous reports. Tests that are already current and accepted are skipped, while tests that need fresh evidence can run again. This makes repeat testing useful after a fix: you keep the historical reports, but the current run shows whether the issue still reproduces.

If a fix changes the application surface, run discovery and planning again before retesting:

```bash
mosh discover https://app.example.com
mosh plan-security https://app.example.com
mosh test-security https://app.example.com
```

Keep the engagement file up to date as the application changes. New roles, test accounts, safe test data, or staging mappings can unblock additional tests and give `mosh` enough context to validate more of the application.

## Implementation

Model-driven Open Security Harness keeps the runtime architecture simple:

```text
orchestrator -> agent -> tools
```

The orchestrator coordinates the run. Agents own specialist work. Tools are invoked by agents. External scanners run inside Docker containers rather than being installed on the host.

Current crews:

- **Discovery crew:** crawls and summarizes the application surface.
- **Security planning crew:** turns discovery evidence into scoped test hypotheses.
- **Security testing crew:** checks ready hypotheses using the engagement file and disposable Docker execution.

The discovery image includes Katana, Dirb, Extractify, a static JavaScript endpoint extractor, Node.js, npm, and system Chromium. The security image includes command-line utilities used inside disposable security-testing workspaces, plus source-assessment helpers such as Semgrep, Bandit, pip-audit, Java/OpenJDK, Maven, Corepack, and common project-inspection utilities.

## Future Roadmap

Planned areas of expansion include assessments of source code, deeper browser-driven SPA discovery, richer API endpoint extraction, additional Docker-backed security tools, web-based GUI and broader reporting support.

## Development

Install the project in editable mode:

```bash
./scripts/setup.sh
source .venv/bin/activate
```

Run the test suite:

```bash
python -m unittest discover -v
```

Force rebuild Docker tool images when working on Docker-backed functionality:

```bash
./scripts/setup.sh --force-docker
```

## Contributing

Model-driven Open Security Harness is easy to explain, practical, and intentionally focused. Good contributions make it more useful without making it harder to understand.

Please follow these guidelines:

- Work in small, reviewable changes.
- Add or update tests for every behavior change.
- Keep `SPEC.md` in sync when product behavior, architecture, output format, or roadmap changes.
- Keep this `README.md` in sync when installation, configuration, commands, examples, or user-facing behavior changes.
- Preserve the `orchestrator -> agent -> tools` architecture.
- Keep external security tools in Docker containers rather than requiring host installs.
- Avoid broad refactors unless they directly support the change being made.

Before opening a pull request create tests that validate your change and ensure all tests pass:

```bash
python -m unittest discover -v
```

Also run the relevant CLI flow against an application you are authorized to test when your change affects runtime behavior.
