# MCP Security Scanner — Session Handoff

Last updated: 2026-08-10 (Asia/Jerusalem)

## Objective

Improve the MCP static security scanner using real public MCP projects, reduce
false positives without losing credible detections, add architectural support
for low-level MCP servers and evidence-aware data flow, and evaluate an optional
OpenAI semantic reviewer for ambiguous findings.

## Repository safety and worktree state

The repository already had user changes before this work. Do not reset, discard,
or overwrite them. In particular, the following pre-existing files were already
modified/untracked at the beginning:

- `README.md`
- `mcp_scanner/analyzers/tool_poisoning.py`
- `mcp_scanner/fixer.py`
- `AGENTS.md`
- `CLAUDE.md`
- `demo.py`

This session intentionally added or modified scanner, test, evaluation, and
documentation files on top of that dirty worktree. Do not commit or push unless
the user explicitly asks.

## Implemented architecture

### Real-world evaluation corpus

`evaluation/` contains a reproducible evaluation system:

- `evaluation/corpus-manifest.json`: eight pinned repositories and ten targets.
- `evaluation/scripts/acquire.ps1`: sparse, detached checkout at exact SHAs.
- `evaluation/scripts/run_evaluation.py`: scans all targets and controlled fixtures.
- `evaluation/scripts/triage_results.py`: finding-level review decisions and metrics.
- `evaluation/labels/finding-labels.csv`: current labels for every real finding.
- `evaluation/labels/metrics.json`: aggregate reviewed metrics.
- `evaluation/REPORT.md`: detailed methodology and findings.
- `evaluation/fixtures/`: clean, MCP03, and MCP06 controlled cases.

Third-party code under `evaluation/corpus/`, generated JSON under
`evaluation/raw-results/`, and fixer work under `evaluation/work/` are ignored by
Git. Third-party MCP code was never installed or executed.

### False-positive reductions

The following deterministic improvements are implemented:

- `requires-python >=...` is no longer an unpinned dependency finding.
- Ordinary GitHub `/main/` links are no longer executable MCP registrations.
- Benign URLs/tool guidance require primary poisoning evidence before supporting
  MCP03.
- Runtime URLs, credential errors, and legitimate file-tool text no longer count
  as tool poisoning.
- Identical tool names in independent files no longer count as confusable names;
  genuinely different normalized names still do.
- MCP07 missing-auth requires evidence that the file constructs/runs an MCP
  server, avoiding client/helper-file warnings.

### Common tool representation and low-level MCP parsing

`mcp_scanner/parsers/python_parser.py` now records:

- Registration style (`decorator` or `low_level`).
- Declaration and implementation lines.
- Implementation source.
- Literal schema parameters.
- Linked AST implementation node.

It supports:

- `@mcp.tool()` / `@server.tool()`.
- `@server.list_tools()` and `Tool(...)` declarations.
- `@server.call_tool()` dispatch.
- `if name == ...` dispatch.
- `match name: case ...` dispatch.
- Enum/static tool names such as `GitTools.STATUS` and `TimeTools.X.value`.

Official reference coverage improved from zero tools to:

- Fetch: 1 tool.
- Git: 12 tools.
- Time: 2 tools.

### Evidence and MCP13 data flow

`mcp_scanner/evidence.py` introduces structured evidence with source, sink,
path, protections, and missing protections.

MCP13 now:

- Tracks the actual HTTP destination argument rather than the whole call AST.
- Propagates tool input through local assignments.
- Summarizes local network helpers such as `fetch_url`.
- Distinguishes a fixed origin from tool-controlled query/path components.
- Avoids propagating tool taint through responses from fixed-origin helpers.
- Excludes framework parameters such as `self`, `ctx`, and `context` from tool
  input taint.

This removed false MCP13 findings in AWS Documentation, Weather, and Atlassian,
while detecting the publicly reported pattern in official Fetch. Current Fetch
evidence is:

`arguments -> args -> url -> fetch_url(destination)`

### Optional constrained OpenAI reviewer

`mcp_scanner/reviewer.py` and CLI integration are implemented.

Usage:

```powershell
python -m mcp_scanner scan <target> --review llm --review-limit 10 --format json
```

The reviewer:

- Is disabled by default.
- Reviews only ambiguous MCP06/MCP07/MCP10/MCP11/MCP15 findings.
- Sends a maximum 120-line / 12,000-character excerpt.
- Redacts credential-like values and private-key blocks.
- Marks all source as untrusted data, never instructions.
- Uses the OpenAI Responses API with strict JSON Schema output and `store: false`.
- Has no shell, write, execution, or arbitrary filesystem tools.
- Caches by model/prompt/finding/source hash under `.mcp-scanner-cache/reviews/`.
- Never suppresses or changes deterministic findings.
- Records API/output failure as `INSUFFICIENT_EVIDENCE`.

CLI options:

- `--review none|llm`
- `--review-model` (default `gpt-5.6-luna`)
- `--review-limit` (default 25)

`tests/test_reviewer.py` uses a mock transport, so tests make no paid API calls.

## Current real-world metrics

Latest full corpus result:

- Supported artifacts: 566.
- Tools recognized: 398.
- Findings: 83 (original baseline was 238).
- Credible evidence (`TP`): 13 (baseline 12).
- False positives: 32 (baseline 107).
- Needs context: 38 (baseline 119).
- Conclusive precision: 28.9% (baseline 10.1%).
- All controlled MCP03/MCP06 cases remain detected.
- Current scan runtime is about 38 seconds after eliminating per-tool reparsing.

Current finding distribution:

- MCP07: 37.
- MCP01: 11.
- MCP10: 9.
- MCP11: 7.
- MCP04: 6.
- MCP06: 6.
- MCP15: 3.
- MCP08: 2.
- MCP09: 1.
- MCP13: 1.

Finding labels:

- Credible: MCP04 (6), MCP06 (2), MCP08 (2), MCP07 permissive bind (1),
  MCP09 unpinned registration (1), MCP13 official Fetch (1).
- Needs context: MCP07 missing auth (34), MCP06 untrusted context (4).
- Remaining false positives: MCP01 (11), MCP10 (9), MCP11 (7), MCP15 (3),
  and MCP07 missing auth (2).

## Verification status

Latest command:

```powershell
python -m unittest discover -v
```

Result: all 29 tests passed.

Other useful commands:

```powershell
python evaluation/scripts/run_evaluation.py
python evaluation/scripts/triage_results.py
python -m mcp_scanner scan tests/samples/clean_server.py --review none --format json
git diff --check
```

## API key status and exact next action

The user set an API key in a separate PowerShell session, but it was not visible
to the already-running Codex process. No real OpenAI API call occurred and no
API cost was incurred.

The user was instructed to persist the key in the Windows user environment:

```powershell
$key = [System.Net.NetworkCredential]::new(
    "",
    (Read-Host "Paste your OpenAI API key" -AsSecureString)
).Password

[Environment]::SetEnvironmentVariable(
    "OPENAI_API_KEY",
    $key,
    "User"
)

Remove-Variable key
```

Then completely restart Codex. Never print, log, serialize, or ask the user to
paste the key into chat.

At the start of the next session, check only presence:

```powershell
if ($env:OPENAI_API_KEY) { "API key visible" } else { "API key missing" }
```

If visible, run a one-finding paid pilot first:

```powershell
python -m mcp_scanner scan evaluation/corpus/mcp-atlassian/src `
  --review llm `
  --review-limit 1 `
  --format json `
  --output evaluation/atlassian-llm-review.json
```

Inspect only `metadata.llm_review`. Confirm:

- Exactly one review exists.
- The response is structured.
- No secret appears in the report.
- The deterministic finding remains.
- A second run uses the cache (`cached: true`).

Then review a small labeled pilot (recommended 5–10 findings), compare verdicts
against `evaluation/labels/finding-labels.csv`, and measure agreement, false
negatives, token/cost/latency if available. Do not run all 38 ambiguous findings
until the one-finding and small-pilot results are validated.

## Next architectural work after the API pilot

1. Add a semantic-review evaluation script that joins `llm_review` results with
   human labels without allowing the model to suppress findings.
2. Decide whether the model should review MCP01/MCP10/MCP11/MCP15 false-positive
   clusters or whether deterministic cross-module analysis should handle them.
3. Build application/module scope and cross-file authentication graphs for the
   34 remaining MCP07 `Needs context` findings.
4. Add validation summaries and cross-module URL provenance to data flow.
5. Only after measured benefit, consider bounded read-only reviewer tools such as
   `get_symbol_definition` and `get_auth_middleware`; do not provide shell or
   network tools to scanned code review.

## Important interpretation rule

Findings remain heuristic evidence, not proof that a project is vulnerable or
safe. LLM review is advisory metadata only. Deterministic findings, rule IDs,
secret redaction, and report-only/fixable boundaries must remain stable.
