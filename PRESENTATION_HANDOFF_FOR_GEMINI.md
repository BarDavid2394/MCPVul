# Gemini handoff: complete the MCP Security Scanner presentation

## Your task

Edit `MCP Server Security Scanner - Mid-Project Presentation.pptx`. Preserve its existing 16:9 visual language (white background, dark navy headings, bright blue/cyan accents, rounded cards, simple line icons). Fill the empty diagram placeholders and update outdated text so the deck describes the implementation that exists today.

This is a mid-project academic presentation for the Networked Software Systems Lab (NSSL), Technion. The audience should understand the security problem, what was built, how data moves through it, what the optional AI does, how it was evaluated, and what remains. Prefer diagrams and short statements over dense paragraphs. Do not invent measurements.

## The one-sentence project description

The project is a dependency-light static security scanner for Model Context Protocol projects that discovers Python and TypeScript/JavaScript MCP artifacts, extracts tools and project structure, detects heuristic evidence across MCP01–MCP16, optionally fixes only high-confidence MCP03/MCP06 cases, and can attach a constrained AI review to ambiguous findings without allowing AI to suppress deterministic results.

## Non-negotiable accuracy rules

1. The current scanner is **not limited to two vulnerabilities**. Catalog version `2026.1` contains 16 attack categories and 25 stable rules. MCP03 Tool Poisoning and MCP06 contextual Prompt Injection remain the deepest original detectors and the only automatically fixable categories.
2. Findings are heuristic security evidence, not proof that a project is vulnerable or safe.
3. The scanner never imports, installs, or executes the target. It reads source/configuration/manifest files statically.
4. Python parsing uses the standard-library AST. TypeScript/JavaScript support uses a dependency-free structural parser for common MCP SDK registration forms; do not call it a complete TypeScript compiler.
5. Automatic fixes are restricted to high-confidence MCP03 and MCP06 findings. MCP01, MCP02, MCP04, MCP05, and MCP07–MCP16 are report-only.
6. AI review is optional and advisory. It receives bounded, redacted, precomputed read-only context. It has no shell, write, target-execution, or arbitrary network tools and never deletes or changes deterministic findings.
7. The measured 28.9% figure belongs to an early broad-catalog real-world baseline before the recent false-positive, graph, data-flow, TypeScript, and semantic improvements. Do not make it the headline result. If mentioned at all, put it in speaker notes or a small historical footnote labeled `early baseline—not current performance`.
8. The new 33-artifact/50-label dataset is staged and unused. It has not been scanned and cannot be presented as achieved precision or recall.
9. Do not call scanner-generated labels ground truth. Independent maintainer/benchmark labels are the source of truth for the staged holdout.
10. Do not expose API keys, local absolute paths, credential strings, or malicious payloads in the deck.

## What the implemented system does

### Inputs

- Python MCP servers (`.py`).
- TypeScript/JavaScript MCP servers (`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`).
- MCP configuration (`.json`, `.yaml`, `.yml`, `.toml`).
- Dependency manifests and lock-related artifacts such as `requirements.txt`, `pyproject.toml`, `package.json`, and `package-lock.json`.
- A file, directory, or in-memory source string.

Generated caches, virtual environments, build output, `node_modules`, backups, and similar non-source material are excluded.

### Main pipeline

`artifact discovery → language parsing → common tool model → deterministic analyzers → project graph/data flow → filtering and deduplication → optional AI review → console/JSON report`

The fixer is a separate, explicit path after findings are produced:

`MCP03/MCP06 high-confidence finding → dry run → targeted source transform → optional backup → syntax verification → idempotence verification`

### Component responsibilities

| Component | Responsibility |
|---|---|
| CLI (`main.py`) | `scan`, `fix`, and `rules`; filters, formats, review options, exit codes. |
| Orchestrator (`scanner.py`) | Discovers artifacts, chooses parser, runs analyzers, combines project evidence, filters and deduplicates findings. |
| Python parser | Uses AST to find decorator and low-level `list_tools`/`call_tool` MCP registrations and link declarations to implementations. |
| TypeScript parser | Structurally recognizes common `tool()` and `registerTool()` registrations and extracts names, descriptions, schemas, parameters, and handlers. |
| Common tool model | Normalized `MCPServerInfo` and `ToolDefinition` consumed by analyzers independent of registration style. |
| MCP03 analyzer | Finds malicious or concealed instructions in metadata and narrow description-versus-implementation contradictions. |
| MCP06 analyzer | Finds external/untrusted content returned toward model context without visible protection. |
| Project-risk analyzer | Implements the remaining source, configuration, dependency, authentication, OAuth, session, network, and process heuristics. |
| Data-flow engine | Tracks tool parameters through aliases/string construction to command sinks and recognizes validator/sanitizer barriers. |
| Security graph | Records files, imports, definitions, calls, network entry points, and authentication evidence across modules. |
| Evidence model | Stores source, sink, path, present protections, and missing protections for a finding. |
| Optional AI reviewer | Reviews ambiguity using a redacted excerpt plus bounded definitions/callers/authentication context; adds structured metadata only. |
| Fixer/defenses | Applies targeted MCP03/MCP06 remediation with dry run, backup, verification, and idempotence. |
| Reporters | Human-readable console output and machine-readable JSON. |

## Detection catalog

Use the short names below. A slide should not list every stable sub-rule unless space permits.

| ID | Category |
|---|---|
| MCP01 | Token mismanagement and secret exposure |
| MCP02 | Privilege escalation through scope creep |
| MCP03 | Tool poisoning |
| MCP04 | Software supply-chain attacks |
| MCP05 | Command injection and dynamic execution |
| MCP06 | Prompt injection through contextual payloads |
| MCP07 | Insufficient authentication and authorization |
| MCP08 | Missing audit and telemetry |
| MCP09 | Shadow, unmanaged, or confusable MCP servers/tools |
| MCP10 | Context injection and over-sharing |
| MCP11 | Confused deputy |
| MCP12 | Token passthrough |
| MCP13 | Server-side request forgery |
| MCP14 | Session hijacking and event injection |
| MCP15 | Unsafe OAuth authorization URLs |
| MCP16 | Local server and stdio proxy compromise |

## Detection techniques to explain simply

- **Structure-aware parsing:** find actual MCP tool registrations rather than treating every function as a tool.
- **Signatures:** identify high-signal malicious instructions in tool descriptions/docstrings.
- **Taint/data flow:** follow a tool input through aliases and formatting to a sensitive sink such as `subprocess`, `exec`, or an HTTP destination.
- **Protection awareness:** stop or qualify a path when validation, allowlisting, sanitization, fixed origins, or authentication are visible.
- **Project reasoning:** connect imports and middleware across files instead of assuming all security controls live beside the server startup call.
- **Semantic comparison:** compare what a tool advertises with sensitive behavior in its implementation; ambiguous MCP03 cases may be sent to optional AI review.
- **Evidence-first output:** report source, sink, flow path, protections, and missing protections rather than only a regex match.

## Correct role of AI

AI does not perform the first-pass scan and is not a replacement for the parser.

1. Deterministic code produces a finding.
2. Only selected ambiguous rule families are eligible: MCP03, MCP06, MCP07, MCP10, MCP11, and MCP15.
3. The reviewer gets a maximum bounded source context, with credential-like values redacted.
4. It may see precomputed definitions, callers, and authentication/middleware lines from the project graph.
5. It returns strict structured output: `LIKELY`, `UNLIKELY`, `NEEDS_CONTEXT`, or `INSUFFICIENT_EVIDENCE`, plus confidence, reason, evidence, and missing context.
6. The verdict is attached as metadata. The original static finding always remains.

Visually represent AI as a dashed optional side branch, never as the central detection engine.

## Diagram specifications for the empty slides

### Slide 8 — High-Level Architecture

Use five large blocks, left to right:

`MCP Project` → `Static Scanner` → `Evidence-Based Findings` → `Console / JSON`

Below `Static Scanner`, add two optional branches:

- `Targeted Fixer — MCP03/MCP06 only`
- `Constrained AI Review — advisory only`

Add small input tags under MCP Project: `Python`, `TypeScript/JavaScript`, `MCP config`, `dependency manifests`.

### Slide 9 — Internal Architecture

Use layered architecture:

1. **Interface:** CLI (`scan`, `fix`, `rules`).
2. **Orchestration:** artifact discovery + `MCPScanner`.
3. **Parsing/model:** Python AST parser + TypeScript structural parser → common tool model.
4. **Analysis:** MCP03 analyzer, MCP06 analyzer, project-risk analyzer, shared data flow, security graph.
5. **Output/safety:** filtering/deduplication, evidence model, optional AI metadata, reporter, targeted fixer.

Show `catalog.py` and `signatures.py` as shared inputs to analyzers, not pipeline stages.

### Slide 10 — Data Flow

Use this exact logical sequence:

`Target path` → `Discover supported artifacts` → `Parse by language` → `Extract servers/tools/imports` → `Run local analyzers` → `Build project graph and flow evidence` → `Filter + deduplicate` → `Optional bounded AI review` → `Console/JSON report`

From `Filter + deduplicate`, show an explicit user-triggered lower branch:

`fix command` → `dry run` → `MCP03/MCP06 transform` → `backup + syntax verification`.

### Slide 11 — Component Diagram

Use package/component boxes and arrows:

- `main.py` calls `scanner.py` and `fixer.py`.
- `scanner.py` calls `utils/helpers.py`, both parsers, all analyzers, `security_graph.py`, and reporters.
- analyzers consume `catalog.py`, `patterns/signatures.py`, `dataflow.py`, and `evidence.py`.
- `reviewer.py` consumes findings, `security_graph.py`, and bounded local context; it calls the OpenAI Responses API only when explicitly enabled.
- `fixer.py` uses `defenses/` and touches only authorized MCP03/MCP06 source locations.

Do not draw every class. Show responsibility boundaries.

## Slide-by-slide editing instructions

### Slides 1–4

Keep the visual design and basic story. On slide 2, define the Host/Client/Server relationship accurately and retain the focus on server-side static analysis. On slide 3, make clear that tools, resources, and prompts cross trust boundaries. On slide 4, add one short phrase about supply-chain/configuration risks so the problem matches the implemented scope.

### Slide 5 — Targeted Security Threats

Replace the outdated note saying only two threats are implemented. Present:

- `Broad catalog: MCP01–MCP16`
- `Deep original focus: MCP03 Tool Poisoning + MCP06 Contextual Prompt Injection`
- `Additional static flows: secrets, command injection, auth, SSRF, supply chain, sessions, OAuth, process startup`

Use a small badge: `Automatic remediation: MCP03 + MCP06 only`.

### Slide 6 — Why a Scanner

Keep the existing benefits. Add that targets are not executed and that findings include traceable evidence suitable for CI/manual review.

### Slide 7 — Objectives

Update to:

- Build a safe static scanner for real MCP projects.
- Support Python and common TypeScript/JavaScript SDK styles.
- Cover MCP01–MCP16 with stable rule IDs.
- Track sources, sinks, protections, and cross-file context.
- Provide targeted MCP03/MCP06 mitigation.
- Evaluate against pinned real projects and an independent frozen holdout.

### Slides 8–11

Replace placeholders using the diagram specifications above.

### Slide 12 — Detection Algorithms

Replace the three old cards with four concise cards:

1. `Structural Parsing` — Python AST + TypeScript MCP registration extraction.
2. `Signatures & Semantics` — malicious metadata patterns and description/implementation mismatch.
3. `Shared Data Flow` — parameters → aliases/helpers → command/network sinks, with protection barriers.
4. `Project Graph + AI Review` — cross-file auth/import reasoning; optional bounded semantic verdict.

### Slide 13 — Software Components

Update the bullets to match the current component table. The class diagram should emphasize interfaces among orchestrator, parsers, analyzers, graph/data flow, evidence, reviewer, fixer, and reporters. Do not imply a single monolithic “Detection Engine” class if no such class exists.

### Slide 14 — Technologies Used

Suggested cards:

- `Python 3 / standard library`
- `AST + structural parsing`
- `Regex signatures + dataclasses`
- `Graph and taint-flow analysis`
- `unittest + synthetic fixtures`
- `JSON / CLI integration`
- `Optional OpenAI Responses API`
- `Git-pinned public evaluation data`

Do not list external runtime dependencies as required; the core scanner uses the standard library.

### Add an Evaluation slide before Current Progress if editing the slide count is acceptable

Title: `Validated Results & Evaluation Readiness`

Use balanced, evidence-backed panels. Avoid making `100%` a headline: it applies only to a narrow development control set and can look like a claim of perfect overall performance. The largest visual numbers should be `393 detected`, `92 missed`, `40 clean controls`, and `47/47 engineering tests`.

**Labeled MCP03 development benchmark**

- `393 / 485` malicious MCPTox source samples detected.
- `92 / 485` malicious samples were missed.
- `81.0%` sample-level recall.
- `1,107` MCP03 evidence findings across detected samples.
- `40 / 40` labeled clean MCP-Safety controls produced zero MCP03 findings.
- Describe this as `0 alerts on 40 labeled clean MCP03 controls`, not as perfect overall scanner precision. These are development datasets and not the final untouched holdout.

**Engineering and functional validation**

- `566` real public artifacts scanned and `398` MCP tools recognized with `0` parse errors in the completed pinned-corpus run.
- `15 / 15` tools extracted from the low-level official Fetch, Git, and Time reference servers.
- Controlled MCP03 and MCP06 vulnerable fixtures: `2 / 2 detected`.
- Controlled clean FastMCP fixture: `1 / 1 clean`.
- Both authorized MCP03/MCP06 fix paths passed dry run, backup creation, syntax verification, and idempotence: `2 / 2 successful`.
- Current allowed scanner/CLI verification: `47 / 47 tests passing`. This is an engineering correctness result, not a vulnerability-detection accuracy metric.

**Independent final evaluation ready**

- `33` unique static artifacts from `7` public sources.
- `23` vulnerable and `10` clean artifacts.
- `50` explicit labels: `30` positive and `20` negative.
- Badge: `UNTOUCHED — NOT YET RUN`.
- Explain that preserving this set prevents tuning bias and enables the final unbiased per-rule measurement.

Small footer only, not a result card: `An early broad-catalog heuristic review produced 28.9% conclusive precision before the latest analyzer improvements; it motivated the graph, flow, parser, and false-positive work now implemented.`

#### Ready-to-paste evaluation slide copy

**Validated Results & Evaluation Readiness**

**MCP03 Development Benchmark**  
`393 detected • 92 missed • 485 malicious samples`  
Sample-level recall: `81.0%`. The scanner produced 1,107 pieces of tool-poisoning evidence across the detected samples.

**Clean-Control Check**  
`40 clean samples • 0 MCP03 alerts`  
This is a narrow development control set, not evidence that the complete MCP01–MCP16 scanner has perfect precision.

**47 / 47 — Scanner & CLI Tests Passing**  
Parser, analyzer, cross-file flow, protection handling, reporting, and CLI checks passed. AI-reviewer and auto-fixer testing are intentionally still pending.

**Real-World Scale**  
566 pinned public artifacts • 398 MCP tools recognized • 0 parse errors • 15/15 low-level official reference tools extracted.

**Independent Final Test Ready**  
33 untouched artifacts • 7 public sources • 50 explicit labels • 23 vulnerable / 10 clean. `NOT YET RUN`.

Footer: `Development-benchmark results; final unbiased metrics will be computed once on the untouched staged holdout.`

Do not combine `393/485`, `0/40`, and `47/47` into one accuracy number. They measure different things: attack recall, clean-control behavior, and software regression correctness.

If slide count must remain 16, use this content to replace the existing evaluation slide. Do not retain the large 28.9% gauge.

### Slide 15 — Current Progress & Next Steps

Replace the outdated lists.

**Completed**

- MCP01–MCP16 catalog and 25 stable rules.
- Python decorator + low-level parsing.
- TypeScript/JavaScript MCP registration parsing.
- Shared command/URL flow evidence and project security graph.
- Cross-file authentication reasoning.
- Targeted MCP03/MCP06 fixer with dry run, backups, verification, and idempotence.
- Console/JSON reporting and optional constrained AI review.
- 46 automated tests passing at the latest verification.
- Reproducible real-world evaluation and staged independent dataset.

**Remaining**

- Expand independent positive and clean labels for sparse categories.
- Improve TypeScript depth and cross-function/cross-module data flow.
- Add stronger negative labels for MCP02, MCP06, MCP09 and unsupported MCP08/MCP10–MCP16 categories.
- Freeze and run the independent holdout once development is complete.
- Recalculate per-rule precision, recall, and confidence intervals.
- Final documentation and presentation/demo polish.

### Slide 16

Keep as the closing slide.

## Current evaluation facts

### Completed real-world baseline

- 10 targets from 8 pinned public repositories.
- 566 supported artifacts scanned.
- 398 tools recognized.
- 83 findings reviewed.
- Labels: 13 credible evidence, 32 false positives, 38 needs context.
- Conclusive precision: `13 / (13 + 32) = 28.9%`.
- Do not treat `Needs context` as positive or negative.
- The result evaluates findings, not whole-project safety.

### Controlled functional fixtures

- One clean FastMCP arithmetic tool: zero findings.
- One injected MCP03 tool-poisoning fixture: detected.
- One injected MCP06 untrusted-context fixture: detected (and also produced MCP13 evidence).
- Both authorized fixes passed dry run, backup, syntax validation, verification, and idempotence checks.
- These three cases are functional regression checks, not statistical accuracy evidence.

### Independent staged data

- 7 pinned public sources.
- 33 unique file-level samples: 23 positive/vulnerable and 10 clean/negative.
- 50 explicit rule labels: 30 positive and 20 negative.
- The same artifact may carry multiple rule labels, so `samples ≠ labels`.
- No duplicate exists among the 33 accepted artifacts by SHA-256.
- The scanner has not been run on this staged set.

## Data table for presentation use

The `used` columns below are labels from the completed 83-finding real-world review. `Credible` means the reported risky precursor was visibly present; `false finding` means source review contradicted the scanner claim; `context` means deployment or omitted modules decide. These are finding labels, not clean/vulnerable artifact labels.

The `unused` columns are independent staged artifact-rule labels and are the correct future holdout units.

| MCP | Vulnerability | Used credible | Used false finding | Used needs context | Unused positive | Unused negative |
|---|---|---:|---:|---:|---:|---:|
| MCP01 | Secrets/tokens | 0 | 11 | 0 | 5 | 4 |
| MCP02 | Scope creep | 0 | 0 | 0 | 1 | 0 |
| MCP03 | Tool poisoning | 0 | 0 | 0 | 5 | 5 |
| MCP04 | Supply chain | 6 | 0 | 0 | 0 | 0 |
| MCP05 | Command/dynamic execution | 0 | 0 | 0 | 10 | 7 |
| MCP06 | Contextual prompt injection | 2 | 0 | 4 | 4 | 0 |
| MCP07 | Authentication/authorization | 1 | 2 | 34 | 1 | 1 |
| MCP08 | Audit/telemetry | 2 | 0 | 0 | 0 | 0 |
| MCP09 | Shadow/confusable servers/tools | 1 | 0 | 0 | 2 | 0 |
| MCP10 | Context sharing/over-sharing | 0 | 9 | 0 | 0 | 0 |
| MCP11 | Confused deputy | 0 | 7 | 0 | 0 | 0 |
| MCP12 | Token passthrough | 0 | 0 | 0 | 0 | 0 |
| MCP13 | SSRF | 1 | 0 | 0 | 2 | 3 |
| MCP14 | Session hijacking | 0 | 0 | 0 | 0 | 0 |
| MCP15 | Unsafe OAuth URLs | 0 | 3 | 0 | 0 | 0 |
| MCP16 | Local/stdio compromise | 0 | 0 | 0 | 0 | 0 |
| **Total** |  | **13** | **32** | **38** | **30** | **20** |

Do not combine the used and unused columns into one precision calculation.

## Complete data-source usage ledger

Use this ledger if asked what data has already influenced development. Counts in this table are scan inputs or source artifacts, not necessarily independent ground-truth labels. Repeated scans of the same files are counted once here.

| Data source | Status | Size used | Relevant MCP categories | How it may be described |
|---|---|---:|---|---|
| Pinned real-project corpus (8 repositories / 10 targets) | Used and manually reviewed | 566 supported artifacts | MCP01, MCP04, MCP06–MCP11, MCP13, MCP15; also clean/no-finding coverage for several categories | Primary completed baseline; 83 findings received finding-level human review. |
| Controlled FastMCP fixtures | Used | 3 artifacts | MCP03, MCP06, MCP13 plus one clean control | Functional detector/fixer regression only, not an independent accuracy benchmark. |
| MCPTox Benchmark static corpus | Used during MCP03 development | 485 Python artifacts | MCP03, including command/file/network instructions embedded in metadata | Training/development evidence; do not reuse as an unbiased final holdout. |
| MCPSecBench static subset | Used during development | 13 scanned artifacts plus one separately scanned benign-add control | Examples spanning MCP01, MCP03, MCP05, MCP07–MCP09, MCP11, MCP13, MCP16 | Broad attack playground; labels are benchmark scenarios, not all one-to-one static rule labels. |
| MSB static subset | Used during development | 64 scanned artifacts | Primarily MCP07/MCP10 signals in our static output; benchmark itself is runtime/end-to-end | Useful compatibility data, not direct static precision SOT. |
| Excel MCP versions 0.1.7 and 0.1.8 | Used during development | 17 + 19 scanned versioned artifacts | MCP07 and MCP09 signals | Versioned regression case; versions overlap and are not 36 independent projects. |
| MCP-Safety clean MCP03 subset | Already used | 40 artifacts | MCP03 negative/clean behavior | No longer eligible for the untouched holdout because it has already been scanned. |
| Official Fetch duplicate scan | Used | Same 7 artifacts already inside the 566-artifact corpus | MCP13 | Do not count twice; public issue #4143 is supporting provenance. |
| Newly curated public static inventory | **Unused / staged** | 33 unique artifacts, 50 labels | MCP01, MCP02, MCP03, MCP05, MCP06, MCP07, MCP09, MCP13 | Independent future holdout candidate; scanner has not been run. |
| Connor | Deferred | 134 broad samples | Broad malicious behavior; exact rule mapping unavailable | Excluded from rule-level precision until independently mapped. |
| CrossMCP-Bench | Deferred | 277 runtime traces | Authorization/policy attacks | Requires runtime-trace adapter; not static source data. |
| mcpsec runtime cases | Deferred | 64 runtime tests | MCP03, MCP08, MCP09, MCP11, MCP13 and others | Requires gateway/runtime adapter. |
| Three unverified Hugging Face sets | Deferred | 186 records | Potential MCP02/MCP03/MCP06/MCP11/MCP16 | Provenance/schema/source compatibility not yet strong enough. |
| PolicyLayer catalogue | Discovery only | 2,031 servers / 31,000 tools | Risk/capability metadata across the ecosystem | Automated classifier output; never present as vulnerability ground truth. |

The clean statement for the talk is: **development has already used broad real-world and benchmark data, while the only currently untouched rule-level static set contains 33 unique artifacts and 50 labels.**

## Visual and writing guidance

- Keep titles large and use the deck's navy/blue split-color treatment.
- Prefer 4–6 nodes per diagram and progressive left-to-right flow.
- Use cyan dashed containers only where the template already uses them; replace placeholder text completely.
- Use solid arrows for deterministic execution and dashed arrows for optional AI/fixer branches.
- Suggested colors: parsing blue, deterministic analysis navy, graph/data flow teal, AI purple, fixer orange, reports green.
- Use consistent small badges: `STATIC`, `OPTIONAL AI`, `MCP03/MCP06 ONLY`, `NOT YET RUN`.
- Avoid code screenshots unless a slide explicitly needs an example. If used, show at most six lines with the source highlighted and sink highlighted.
- Avoid absolute claims such as “detects all vulnerabilities,” “secure,” “ground truth from scanner,” or “AI decides whether a finding exists.”
- Speaker notes may carry nuance; slide bodies should remain concise.

## Primary project sources to consult

- `README.md`: current user-facing behavior.
- `mcp_scanner/catalog.py`: exact MCP01–MCP16 catalog and stable rules.
- `mcp_scanner/scanner.py`: orchestration.
- `mcp_scanner/parsers/python_parser.py`: Python/common tool extraction.
- `mcp_scanner/parsers/typescript_parser.py`: TypeScript/JavaScript extraction.
- `mcp_scanner/analyzers/`: deterministic analyzers.
- `mcp_scanner/dataflow.py`: shared command data flow.
- `mcp_scanner/security_graph.py`: cross-file project model and bounded related context.
- `mcp_scanner/reviewer.py`: constrained optional AI review.
- `mcp_scanner/fixer.py`: authorized remediation path.
- `evaluation/REPORT.md`: completed baseline evaluation.
- `evaluation/holdout/CURATED_INVENTORY.md`: unused staged data.

If project files disagree with old slide text, the current code/catalog/README win. `PROJECT_PLAN.md` describes the historical v1 scope and must not be used as the current source of truth.
