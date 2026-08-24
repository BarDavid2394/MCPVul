"""Guarded, one-shot execution of the clean holdout."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from holdout_common import CONSUMED, CORPUS, RESULTS, ROOT, verify_frozen

TOKEN_FILE = ROOT / "evaluation" / "holdout" / ".run-token"


def token_digest(token: str, fingerprint: str) -> str:
    return hashlib.sha256(f"{fingerprint}:{token}".encode()).hexdigest()


def issue_token(fingerprint: str) -> None:
    if CONSUMED.exists():
        raise SystemExit("Holdout has already been consumed")
    token = secrets.token_urlsafe(24)
    TOKEN_FILE.write_text(token_digest(token, fingerprint), encoding="ascii")
    print(token)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issue-token", action="store_true")
    parser.add_argument("--token")
    args = parser.parse_args()
    data, frozen_fingerprint = verify_frozen()
    if args.issue_token:
        issue_token(frozen_fingerprint)
        return 0
    if CONSUMED.exists():
        raise SystemExit("Holdout has already been consumed; refusing a second run")
    if not args.token or not TOKEN_FILE.exists():
        raise SystemExit("A one-time token is required")
    if not secrets.compare_digest(TOKEN_FILE.read_text(encoding="ascii"), token_digest(args.token, frozen_fingerprint)):
        raise SystemExit("Invalid one-time token")

    # Import only after all clean-holdout guards have passed.
    sys.path.insert(0, str(ROOT))
    from mcp_scanner.reporters.json_reporter import JsonReporter
    from mcp_scanner.scanner import MCPScanner

    RESULTS.mkdir(parents=True, exist_ok=False)
    summaries = []
    try:
        for artifact in data["artifacts"]:
            target = CORPUS / artifact["source_id"] / artifact["path"]
            result = MCPScanner().scan(target)
            output = RESULTS / f"{artifact['id']}.json"
            JsonReporter(pretty=True).report(
                result.findings,
                {"artifact_id": artifact["id"], "files_scanned": result.files_scanned,
                 "tools_analyzed": result.tools_analyzed, "parse_errors": result.parse_errors},
                str(output),
            )
            summaries.append({"artifact_id": artifact["id"], "findings": len(result.findings)})
    finally:
        TOKEN_FILE.unlink(missing_ok=True)

    record = {
        "consumed_at": datetime.now(timezone.utc).isoformat(),
        "manifest_fingerprint": frozen_fingerprint,
        "artifacts": len(data["artifacts"]),
        "results": summaries,
    }
    CONSUMED.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

