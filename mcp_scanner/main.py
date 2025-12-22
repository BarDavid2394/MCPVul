"""
MCP Security Scanner - Command Line Interface

Usage:
    python -m mcp_scanner scan <target> [options]
    python -m mcp_scanner scan server.py
    python -m mcp_scanner scan ./mcp_servers/ --format json --output report.json
"""

import argparse
import sys
from pathlib import Path

from .scanner import scan_and_report, MCPScanner, ScanResult
from .reporters.console import ConsoleReporter


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-scanner",
        description="MCP Security Scanner - Detect vulnerabilities in MCP server implementations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan server.py                    Scan a single file
  %(prog)s scan ./servers/                   Scan a directory
  %(prog)s scan server.py --format json      Output as JSON
  %(prog)s scan server.py --check tool-poisoning   Only check for tool poisoning
  %(prog)s scan server.py -v                 Verbose output

Vulnerability Types:
  tool-poisoning     Malicious instructions hidden in tool descriptions
  prompt-injection   Unsafe handling of external data enabling injection

For more information, visit: https://github.com/mcp-security/mcp-scanner
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan MCP server files for vulnerabilities"
    )
    scan_parser.add_argument(
        "target",
        help="File or directory to scan"
    )
    scan_parser.add_argument(
        "--format", "-f",
        choices=["console", "json"],
        default="console",
        help="Output format (default: console)"
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Output file for report (default: stdout)"
    )
    scan_parser.add_argument(
        "--check", "-c",
        choices=["tool-poisoning", "prompt-injection"],
        help="Only check for specific vulnerability type"
    )
    scan_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    # Version
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0"
    )

    return parser


def main(args=None):
    """Main entry point."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    if parsed_args.command is None:
        parser.print_help()
        return 0

    if parsed_args.command == "scan":
        return run_scan(parsed_args)

    return 0


def run_scan(args) -> int:
    """Execute the scan command."""
    target = Path(args.target)

    if not target.exists():
        print(f"Error: Target not found: {target}", file=sys.stderr)
        return 2

    exit_code = scan_and_report(
        target=str(target),
        output_format=args.format,
        output_file=args.output,
        verbose=args.verbose,
        check=args.check,
    )

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
