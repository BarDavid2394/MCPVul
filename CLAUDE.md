# CLAUDE.md

This file provides repository guidance for Claude Code. `AGENTS.md` contains the
equivalent cross-agent guidance and should remain aligned with this file.

## Project Overview

MCP Security Scanner is a standard-library Python static analyzer for Model
Context Protocol projects. The current v2 implementation scans Python source,
MCP configuration, and dependency manifests against catalog version `2026.1`,
covering MCP01–MCP16.

The scanner began with two deep detectors—tool poisoning (MCP03) and indirect
prompt injection (MCP06). Those remain the only categories eligible for targeted
automatic fixes. All other categories are detection and reporting only.

`PROJECT_PLAN.md` describes the historical v1 design. Use `README.md` and
`mcp_scanner/catalog.py` as the current sources of truth.

## Commands

```powershell
python -m mcp_scanner rules
python -m mcp_scanner scan path\to\server.py
python -m mcp_scanner scan .\mcp_servers\ --format json
python -m mcp_scanner scan server.py --check MCP13-SSRF
python -m mcp_scanner fix server.py --dry-run --verbose
python -m mcp_scanner fix server.py --verify
python demo.py
python -m unittest discover -v
```

Exit codes are `0` for clean, `1` for detected findings, and `2` for errors.
Thus, exit code `1` is expected for intentionally vulnerable samples.

The core has no third-party dependencies. `requirements.txt` lists optional
enhancements only.

## Architecture

`artifact discovery -> parser -> analyzers -> filter/dedupe -> reporter`

- `mcp_scanner/main.py`: CLI (`scan`, `fix`, and `rules`).
- `mcp_scanner/scanner.py`: scan orchestration and result aggregation.
- `mcp_scanner/catalog.py`: MCP01–MCP16 definitions and stable rule IDs.
- `mcp_scanner/parsers/python_parser.py`: AST-based MCP server/tool extraction.
- `mcp_scanner/analyzers/tool_poisoning.py`: MCP03 metadata analysis.
- `mcp_scanner/analyzers/prompt_injection.py`: MCP06 data-flow heuristics.
- `mcp_scanner/analyzers/project_risks.py`: source, configuration, dependency,
  OAuth, SSRF, session, authorization, and process-risk checks.
- `mcp_scanner/patterns/signatures.py`: shared compiled signatures.
- `mcp_scanner/fixer.py`: conservative MCP03/MCP06 remediation and verification.
- `mcp_scanner/defenses/`: sanitizers and safe transforms.
- `mcp_scanner/reporters/`: console and JSON output.
- `tests/`: scanner/fixer tests and clean/vulnerable samples.

## Important Constraints

- Static findings are heuristic evidence, not proof of vulnerability or safety.
- Preserve catalog attack IDs and stable rule IDs.
- Never expose detected secret values in findings or JSON output.
- Never auto-fix MCP01, MCP02, MCP04, MCP05, or MCP07–MCP16.
- MCP03/MCP06 fixes must be high-confidence, syntax-preserving, idempotent, and
  compatible with dry-run, backup, and verification modes.
- Verification may pass while non-fixable findings remain; report those findings
  separately rather than modifying them.
- Detection changes need positive and negative tests because false positives are
  a central risk.
- Preserve unrelated working-tree changes and do not commit or push unless asked.

## Testing Notes

Run the focused test module first and then the full unittest suite. For fixer
changes, verify dry-run behavior, backup creation, valid Python output,
idempotence, and preservation of non-fixable findings.

In a restricted Windows sandbox, tests using `tempfile.TemporaryDirectory` may
fail while creating fixtures. Treat a `PermissionError` during fixture creation
as an environment issue and distinguish it from a scanner assertion failure.
