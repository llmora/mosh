# Open Security Harness

Turn an application URL into an evidence-backed security testing workflow.

Open Security Harness is an agent-coordinated CLI for application security teams, security-minded engineers, and product teams that want repeatable discovery instead of scattered notes and one-off scanner output. Give it a URL, and it coordinates specialist agents and Docker-backed tools to map the application surface, write an auditable discovery report, propose scoped security tests, and prepare execution with an explicit engagement file.

It is built for applications you own and are authorized to test.

## Why Use It

Modern applications spread behavior across pages, APIs, JavaScript bundles, forms, redirects, and hidden paths. Open Security Harness keeps that work organized:

- It discovers pages, links, paths, forms, JavaScript assets, XHR/fetch endpoints, and candidate hidden routes.
- It stores the trail, not just the conclusion: Markdown reports, structured event logs, and shared memory are written for every run.
- It turns discovery evidence into a security test plan instead of leaving you with raw crawl output.
- It creates a small editable engagement file so test execution is tied to authorization, target mappings, credentials, limits, and safe test data.
- It runs external tooling in Docker, keeping scanner dependencies out of your host environment.

## The Workflow

```text
discover -> plan-security -> edit engagement_template.yaml -> test-security
```

Each phase writes to a stable directory under:

```text
report/<host>/
```

For `https://app.example.com`, Open Security Harness creates:

```text
report/app.example.com/discovery/
report/app.example.com/security-test-planning/
report/app.example.com/security-testing/
```

## What You Get

After a full run, you have:

- a discovery report describing observed application surface area
- `events.json` with observable agent and tool activity
- `memory.json` with structured facts shared between crews
- a security test plan grounded in discovery evidence
- an editable engagement template for permissions, targets, credentials, limits, and safe data
- security testing preflight output and executed test reports when tests are ready to run

## Prerequisites

Install these first:

- Python 3.11 or newer
- Docker, running locally
- An LLM API key:
  - `DEEPSEEK_API_KEY` for direct DeepSeek use with the default DeepSeek models, or
  - `OPENROUTER_API_KEY` to route models through OpenRouter

## Install

Clone the repository:

```bash
git clone <repo-url>
cd open-security-harness
```

Run setup:

```bash
./scripts/setup.sh
```

The setup script creates `.venv`, installs Open Security Harness in editable mode, and builds the Docker tool images. It rebuilds an image when the local image is missing or older than the files used to build it.

Activate the environment:

```bash
source .venv/bin/activate
```

Useful setup options:

```bash
./scripts/setup.sh --skip-docker
./scripts/setup.sh --force-docker
```

The discovery image includes Katana, Dirb, Extractify, a static JavaScript endpoint extractor, Node.js, npm, and system Chromium. The security image includes command-line utilities used inside disposable security-testing workspaces.

## Configure

Set an API key before running the CLI.

For the default direct DeepSeek setup:

```bash
export DEEPSEEK_API_KEY="your-deepseek-api-key"
```

Or route through OpenRouter:

```bash
export OPENROUTER_API_KEY="your-openrouter-api-key"
```

Optional environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `OSH_OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | OpenRouter-compatible API base URL. |
| `OSH_MAX_DEPTH` | `5` | Default crawl depth for discovery. |
| `OSH_KATANA_CRAWL_DURATION` | `270s` | Katana browser crawl duration. |
| `OSH_KATANA_DOCKER_TIMEOUT` | `300` | Katana Docker timeout in seconds. |
| `OSH_DIRB_WORDLIST` | `/usr/share/dirb/wordlists/common.txt` | Dirb wordlist path inside the discovery image. |
| `OSH_DIRB_DOCKER_TIMEOUT` | `120` | Dirb Docker timeout in seconds. |
| `OSH_CANDIDATE_FOLLOW_UP_LIMIT` | `5` | Maximum candidate paths to follow up after discovery. |
| `OSH_PLANNING_MAX_REVISIONS` | `1` | Planner/critic revision attempts beyond the first plan. |
| `OSH_REFINE_ENGAGEMENT_TEMPLATE_WITH_LLM` | `true` | Whether planning asks an LLM to refine the generated engagement template. |
| `OSH_SECURITY_TOOL_IMAGE` | `osh-security-tools:latest` | Docker image used by security testing. |
| `OSH_SECURITY_COMMAND_TIMEOUT` | `300` | Per-command timeout for security testing commands. |
| `OSH_SECURITY_EXECUTION_MAX_REVISIONS` | `2` | Maximum reviewer-requested reruns for a security test. |

The discovery tools image currently uses the built-in image name `osh-discovery-tools:latest`; `./scripts/setup.sh` builds and refreshes it.

## Run Discovery

Start by mapping the application:

```bash
osh discover https://app.example.com
```

You can also pass a URL directly. Open Security Harness treats this as `discover`:

```bash
osh https://app.example.com
```

Discovery writes:

```text
report/<host>/discovery/report.md
report/<host>/discovery/events.json
report/<host>/discovery/memory.json
```

Optional tuning flags:

```bash
osh discover https://app.example.com --max-pages 100 --max-depth 4 --output-root report
```

## Create A Security Test Plan

Once discovery has produced evidence, ask Open Security Harness to turn it into testable hypotheses:

```bash
osh plan-security https://app.example.com
```

This reads from `report/<host>/discovery/` and writes:

```text
report/<host>/security-test-planning/security_test_plan.md
report/<host>/security-test-planning/engagement_template.yaml
report/<host>/security-test-planning/events.json
report/<host>/security-test-planning/memory.json
```

## Review The Engagement File

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

The security testing crew treats this file as execution configuration. If you map a production target to an alternative target, tests run against the mapped target.

Repeated planning runs preserve values you have filled in and back up older templates under:

```text
report/<host>/security-test-planning/engagement_template.backups/
```

## Run Security Testing

When the plan and engagement file are ready, run:

```bash
osh test-security https://app.example.com
```

By default, this uses:

```text
report/<host>/security-test-planning/engagement_template.yaml
```

To use a different engagement file:

```bash
osh test-security https://app.example.com --engagement-file ./engagement.yaml
```

Security testing writes:

```text
report/<host>/security-testing/preflight.md
report/<host>/security-testing/events.json
report/<host>/security-testing/memory.json
report/<host>/security-testing/executed_tests/
```

If executed tests discover new application surface area, Open Security Harness feeds those facts back into discovery memory, updates the discovery report, and refreshes the security test plan. It does not immediately auto-run newly planned tests; run `test-security` again when you are ready.

## End-To-End Example

```bash
git clone <repo-url>
cd open-security-harness

./scripts/setup.sh
source .venv/bin/activate

export DEEPSEEK_API_KEY="your-deepseek-api-key"

osh discover https://app.example.com
osh plan-security https://app.example.com

# Review and edit report/app.example.com/security-test-planning/engagement_template.yaml.

osh test-security https://app.example.com
```

## How It Works

Open Security Harness keeps the architecture simple:

```text
orchestrator -> agent -> tools
```

The orchestrator coordinates the run. Agents own specialist work. Tools are invoked by agents. External scanners run inside Docker containers.

Current crews:

- Discovery crew: crawls and summarizes the application surface.
- Security planning crew: turns discovery evidence into scoped test hypotheses.
- Security testing crew: checks ready hypotheses using the engagement file and disposable Docker execution.

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

Build tool images when working on Docker-backed functionality:

```bash
./scripts/setup.sh --force-docker
```

## Contributing

Open Security Harness is early, practical, and intentionally focused. Good contributions make it more useful without making it harder to understand.

Please follow these guidelines:

- Work in small, reviewable changes.
- Add or update tests for every behavior change.
- Keep `SPEC.md` in sync when product behavior, architecture, output format, or roadmap changes.
- Keep this `README.md` in sync when installation, configuration, commands, examples, or user-facing behavior changes.
- Preserve the `orchestrator -> agent -> tools` architecture.
- Keep external security tools in Docker containers rather than requiring host installs.
- Avoid broad refactors unless they directly support the change being made.

Before opening a pull request:

```bash
python -m unittest discover -v
```

Also run the relevant CLI flow against an application you are authorized to test when your change affects runtime behavior.
