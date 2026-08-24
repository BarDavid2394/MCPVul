"""End-to-end demonstration runner for the MCP Security Scanner."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class DemoStep:
    title: str
    args: tuple[str, ...]
    expected_codes: tuple[int, ...]
    explanation: str


STEPS = (
    DemoStep(
        "Attack catalog",
        ("-m", "mcp_scanner", "rules"),
        (0,),
        "Shows the versioned MCP01-MCP16 detection contract.",
    ),
    DemoStep(
        "Clean MCP server",
        ("-m", "mcp_scanner", "scan", "tests/samples/clean_server.py"),
        (0,),
        "A normal calculator server should produce no findings.",
    ),
    DemoStep(
        "Tool poisoning",
        ("-m", "mcp_scanner", "scan", "tests/samples/vulnerable_tool_poisoning.py", "--check", "MCP03"),
        (1,),
        "Hidden tool-description instructions request file theft, exfiltration, and unauthorized tool chaining.",
    ),
    DemoStep(
        "Indirect prompt injection",
        ("-m", "mcp_scanner", "scan", "tests/samples/vulnerable_prompt_injection.py", "--check", "MCP06"),
        (1,),
        "Untrusted HTTP, file, database, and process content is returned to the model without a trust boundary.",
    ),
    DemoStep(
        "Safe remediation preview",
        ("-m", "mcp_scanner", "fix", "tests/samples/vulnerable_prompt_injection.py", "--dry-run", "--verbose"),
        (0, 1),
        "Previews high-confidence MCP03/MCP06 edits without modifying the sample.",
    ),
    DemoStep(
        "Automated regression tests",
        ("-m", "unittest", "discover", "-v"),
        (0,),
        "Confirms catalog coverage, clean behavior, redaction, and fixer safety.",
    ),
)


def main() -> int:
    print("MCP Security Scanner - End-to-End Demo", flush=True)
    print("=" * 48, flush=True)
    for number, step in enumerate(STEPS, 1):
        print(f"\n[{number}/{len(STEPS)}] {step.title}", flush=True)
        print(step.explanation, flush=True)
        print(f"> {Path(sys.executable).name} {' '.join(step.args)}\n", flush=True)
        completed = subprocess.run((sys.executable, *step.args), cwd=ROOT)
        if completed.returncode not in step.expected_codes:
            expected = ", ".join(map(str, step.expected_codes))
            print(f"\nDEMO FAILED: {step.title} returned {completed.returncode}; expected {expected}.")
            return 1
        print(f"\nStep completed with expected exit code {completed.returncode}.")

    print("\n" + "=" * 48)
    print("END-TO-END DEMO PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
