# AppSec Harness Specification

## Goal

Build an application security testing harness that uses coordinated agents to perform appsec work and produce a final report.

The first working prototype is a CLI-only discovery harness for a single URL:

```bash
appsec-harness <URL>
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

The current discovery tools container starts from Ubuntu and includes Katana for JavaScript-aware crawling, jsluice parsing, and endpoint discovery.

The intended Docker interaction is:

- execute a container with the tool
- pass input to it
- read structured output from it

## Implementation Stack

Use CrewAI for the agent implementation.

Use OpenRouter for LLM access. The API key is provided through an environment variable:

```text
OPENROUTER_API_KEY
```

Each agent can be configured to use a specific LLM model. Model selection should not be exposed as a command-line option for now. It should be easy to change in application configuration or agent definitions.

CrewAI orchestration is mandatory. The application should not silently fall back to a deterministic agent sequence when CrewAI or OpenRouter is unavailable. If the CrewAI discovery crew cannot run, the CLI should fail clearly and report the missing requirement.

The discovery workflow must run as a CrewAI crew. Agents, exchanges, tasks, and tool invocation should be represented through CrewAI rather than a deterministic Python sequence.

CrewAI agent and task definitions should use CrewAI's built-in YAML configuration pattern. Discovery crew configuration currently lives in:

- `src/appsec_harness/crew_config/agents.yaml`
- `src/appsec_harness/crew_config/tasks.yaml`

Python should bind live tool implementations to the YAML-defined agents, but agent roles, goals, backstories, task descriptions, and expected outputs should live in YAML.

## Shared Memory

Shared memory must be file-backed.

Agents can read from and add to shared memory. Memory writes must be recorded as observable events.

The current output directory format is:

```text
report/<host>/
```

Use the host only for the report directory name. For example:

- `https://www.test.com/path` -> `report/www.test.com/`
- `http://127.0.0.1:8080/` -> `report/127.0.0.1_8080/`

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

The first prototype should write all output under:

```text
report/<host>/
```

Required outputs:

- Markdown final report
- JSON final report
- JSON event log
- JSON shared memory

The final report should summarize the discovery activities and findings.

The final Markdown report is authored by the summarizer agent and persisted through
the summarizer-owned report-writing tool. The application should not regenerate the
Markdown from a deterministic Python report template.

The JSON final report should include operational metadata, crawler findings,
component inventory, and the summarizer agent's structured report content when the
agent provides it. The summarizer's authored Markdown should also be retained in
the JSON report so the artifact can be audited later.

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
- SBOM/component inventory agent: identifies observable software components such as libraries, servers, frameworks, and related technologies
- summarizer agent: summarizes findings and returns them to the orchestrator for reporting

### Discovery Crew Tool Ownership

The crawler is a tool owned by the crawler agent. The orchestrator must not call the crawler directly.

The crawler agent may have multiple crawler tools. Current crawler-owned tools are:

- application-native crawler tool
- Katana Docker crawler tool, run through the discovery tools container

The SBOM/component inventory agent currently performs its analysis through the
CrewAI task context and its LLM output. It should read crawler findings and
produce an evidence-based SBOM-style analysis as agent output. There is no
deterministic component inventory tool in the current implementation.

The summarizer agent owns summarization behavior and the report-writing tool. The
orchestrator may request reporting, but it must not synthesize the final report by
calling reporting helpers directly.

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

The crawler can be implemented inside the application. External crawler tools, such as Katana, must run through Docker and still be invoked as crawler agent tools.

The crawler agent should keep a per-run registry of URLs that have already been
crawled. Before invoking a crawler tool, the crawler agent should check this
registry. If the requested URL has already been crawled, it should skip the
duplicate tool call, record the skip decision in `events.json`, and return the
current crawl findings to the agent. Distinct crawl roots discovered during the
run should be merged into the aggregate crawl state for later agents.

## Future Scope

Future versions may add:

- additional crews that run alongside discovery
- static security tools
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

# Roadmap

* CrewAI orchestration is required. The orchestrator should start a CrewAI crew that contains the discovery agents, their tasks, exchanges, and agent-owned tools. There must be no production deterministic fallback path.
* The current implementation direction is a CrewAI discovery crew. Future work should deepen inter-agent exchange and delegation so crawler, SBOM/component inventory, summarizer, and future crews communicate through the CrewAI runtime and shared file-backed memory.
