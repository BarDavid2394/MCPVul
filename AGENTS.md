# MCP Security Scanner — Agent Guide

## Project Summary

This repository contains a Python static security scanner for Model Context
Protocol (MCP) projects. The implemented v2 scanner uses catalog version
`2026.1` and reports heuristic findings across MCP01–MCP16. It scans Python MCP
servers, MCP configuration files, and dependency manifests.

The original project covered only tool poisoning and indirect prompt injection.
`PROJECT_PLAN.md` records that historical v1 design; use `README.md` and
`mcp_scanner/catalog.py` as the current sources of truth.

## Runtime and Dependencies

- Python 3; the core scanner uses only the standard library.
- No installation step is required for normal development.
- `requirements.txt` documents optional dependencies only.
- Prefer `python -m mcp_scanner ...` so commands use the checked-out package.

## Common Commands

```powershell
python -m mcp_scanner rules
python -m mcp_scanner scan tests\samples\clean_server.py
python -m mcp_scanner scan tests\samples\vulnerable_tool_poisoning.py -v
python -m mcp_scanner scan <target> --format json
python -m mcp_scanner fix <target> --dry-run --verbose
python -m mcp_scanner fix <target> --verify
python demo.py
python -m unittest discover -v
```

Scanner exit codes are `0` for clean, `1` when findings are detected, and `2`
for scan/configuration errors. Exit code `1` is therefore expected when scanning
the vulnerable samples.

On restricted Windows environments, `tempfile.TemporaryDirectory` may be denied
even when its parent is writable. If filesystem-based tests fail while creating
fixtures, first distinguish that environment failure from a scanner assertion
failure. Do not change production code merely to work around an execution
sandbox.

## Architecture

The primary flow is:

`artifact discovery -> parsing -> analyzers -> filtering/deduplication -> reporter`

- `mcp_scanner/main.py`: argparse CLI for `scan`, `fix`, and `rules`.
- `mcp_scanner/scanner.py`: `MCPScanner` orchestration and `ScanResult`.
- `mcp_scanner/catalog.py`: versioned MCP01–MCP16 categories and stable rule IDs.
- `mcp_scanner/parsers/python_parser.py`: AST parser for MCP servers and tools.
- `mcp_scanner/analyzers/tool_poisoning.py`: MCP03 metadata analysis.
- `mcp_scanner/analyzers/prompt_injection.py`: MCP06 untrusted-content analysis.
- `mcp_scanner/analyzers/project_risks.py`: remaining source, config, dependency,
  OAuth, network, session, and process heuristics.
- `mcp_scanner/patterns/signatures.py`: shared detection signatures.
- `mcp_scanner/fixer.py`: targeted remediation and verification.
- `mcp_scanner/defenses/`: sanitization helpers and safe source transforms.
- `mcp_scanner/reporters/`: console and JSON reporting.
- `tests/test_scanner.py` and `tests/test_fixer.py`: unit coverage.
- `tests/samples/`: intentionally clean and vulnerable fixtures.

## Design Constraints

- Findings are heuristic evidence, not proof that a project is vulnerable or safe.
- Preserve stable attack IDs and rule IDs; integrations may depend on them.
- Redact secrets from finding evidence and serialized reports.
- Keep automatic source changes limited to high-confidence MCP03 and MCP06
  findings. MCP01, MCP02, MCP04, MCP05, and MCP07–MCP16 are report-only.
- Fixes must preserve valid Python, create backups when requested, support dry
  runs, and be idempotent.
- Verification of a fix concerns the fixable categories. Other reported risks may
  intentionally remain and should be shown separately.
- Avoid broad regex changes without adding focused positive and negative tests;
  false positives are a primary risk for this scanner.
- Do not scan generated caches or backup files as project inputs.

## Change and Verification Guidance

- Read `git status` and preserve pre-existing user changes.
- Add or update tests for detector, catalog, parser, reporter, or fixer behavior.
- Run the focused test module first, then `python -m unittest discover -v`.
- Exercise the relevant CLI path when changing arguments, output, or exit codes.
- For fixer changes, verify dry-run behavior, syntax validity, backup behavior,
  idempotence, and that non-fixable categories remain untouched.
- Do not commit, push, or rewrite Git history unless the user explicitly asks.

