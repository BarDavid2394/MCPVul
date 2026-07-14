"""
Main Scanner Orchestrator

Coordinates parsing, analysis, and reporting for MCP security scanning.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from .parsers.python_parser import PythonMCPParser, MCPServerInfo
from .analyzers.base import Finding, Severity
from .analyzers.tool_poisoning import ToolPoisoningAnalyzer
from .analyzers.prompt_injection import PromptInjectionAnalyzer
from .analyzers.project_risks import ProjectRiskAnalyzer
from .catalog import ATTACK_CATEGORIES, RULES, normalize_check
from .reporters.console import ConsoleReporter
from .reporters.json_reporter import JsonReporter
from .utils.helpers import get_project_files


@dataclass
class ScanResult:
    """Results from a security scan."""
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    tools_analyzed: int = 0
    servers_found: int = 0
    parse_errors: List[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def has_critical(self) -> bool:
        return self.critical_count > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "tools_analyzed": self.tools_analyzed,
            "servers_found": self.servers_found,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "parse_errors": self.parse_errors,
        }


class MCPScanner:
    """
    Main MCP Security Scanner.

    Orchestrates the scanning process:
    1. Find and parse MCP server files
    2. Run security analyzers
    3. Generate reports
    """

    def __init__(
        self,
        enable_tool_poisoning: bool = True,
        enable_prompt_injection: bool = True,
        verbose: bool = False,
        check: str = None,
    ):
        """
        Initialize the scanner.

        Args:
            enable_tool_poisoning: Enable Tool Poisoning analyzer.
            enable_prompt_injection: Enable Prompt Injection analyzer.
            verbose: Enable verbose output.
        """
        self.parser = PythonMCPParser()
        self.analyzers = []
        self.verbose = verbose
        self.check = normalize_check(check)
        self.project_analyzer = ProjectRiskAnalyzer()

        if enable_tool_poisoning:
            self.analyzers.append(ToolPoisoningAnalyzer())
        if enable_prompt_injection:
            self.analyzers.append(PromptInjectionAnalyzer())

    def scan_file(self, filepath: str | Path) -> ScanResult:
        """
        Scan a single Python file for MCP security issues.

        Args:
            filepath: Path to the Python file.

        Returns:
            ScanResult with findings.
        """
        result = ScanResult()
        filepath = Path(filepath)

        if not filepath.exists():
            result.parse_errors.append(f"File not found: {filepath}")
            return result

        if filepath.suffix.lower() != ".py":
            try:
                text = filepath.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                result.parse_errors.append(f"Could not read file: {exc}")
                return result
            result.files_scanned = 1
            result.findings = self._filter(self.project_analyzer.analyze_artifact(filepath, text))
            return result

        # Parse the file
        server_info = self.parser.parse_file(filepath)
        result.files_scanned = 1

        if server_info.parse_errors:
            result.parse_errors.extend(server_info.parse_errors)

        if server_info.server_name:
            result.servers_found = 1

        result.tools_analyzed = len(server_info.tools)

        # Run analyzers
        for analyzer in self.analyzers:
            findings = analyzer.analyze(server_info)
            result.findings.extend(findings)

        result.findings.extend(self.project_analyzer.analyze_python(server_info))
        result.findings = self._filter(self._dedupe(result.findings))

        return result

    def scan_directory(self, directory: str | Path) -> ScanResult:
        """
        Scan a directory recursively for MCP security issues.

        Args:
            directory: Path to the directory.

        Returns:
            ScanResult with findings from all files.
        """
        result = ScanResult()
        directory = Path(directory)

        if not directory.exists():
            result.parse_errors.append(f"Directory not found: {directory}")
            return result

        python_files = get_project_files(directory)

        if not python_files:
            result.parse_errors.append(f"No supported source, configuration, or manifest files found in: {directory}")
            return result

        for filepath in python_files:
            file_result = self.scan_file(filepath)

            result.files_scanned += file_result.files_scanned
            result.tools_analyzed += file_result.tools_analyzed
            result.servers_found += file_result.servers_found
            result.findings.extend(file_result.findings)
            result.parse_errors.extend(file_result.parse_errors)

        result.findings.extend(self._filter(self.project_analyzer.analyze_name_collisions(
            self._collect_registered_names(python_files)
        )))
        result.findings = self._dedupe(result.findings)

        return result

    def _collect_registered_names(self, files: List[Path]) -> List[tuple[str, str, str]]:
        names: List[tuple[str, str, str]] = []
        for path in files:
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            if path.suffix.lower() == ".py":
                info = self.parser.parse_source(text, str(path))
                if info.server_name:
                    names.append(("server", str(info.server_name), str(path)))
                names.extend(("tool", tool.name, str(path)) for tool in info.tools)
            elif path.suffix.lower() == ".json":
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    data = None
                if isinstance(data, dict):
                    servers = data.get("mcpServers") or data.get("mcp_servers")
                    if isinstance(servers, dict):
                        names.extend(("server", str(name), str(path)) for name in servers)
            else:
                lines = text.splitlines()
                for index, line in enumerate(lines):
                    marker = re.match(r"^(\s*)(?:mcpServers|mcp_servers)\s*:\s*$", line)
                    if not marker:
                        continue
                    base_indent = len(marker.group(1))
                    for child in lines[index + 1:]:
                        if not child.strip():
                            continue
                        indent = len(child) - len(child.lstrip())
                        if indent <= base_indent:
                            break
                        match = re.match(r"^\s+([A-Za-z0-9_.-]+)\s*:\s*$", child)
                        if match:
                            names.append(("server", match.group(1), str(path)))
        return names

    def _filter(self, findings: List[Finding]) -> List[Finding]:
        if not self.check:
            return findings
        if self.check in ATTACK_CATEGORIES:
            return [finding for finding in findings if finding.attack_id == self.check]
        return [finding for finding in findings if finding.rule_id == self.check]

    @staticmethod
    def _dedupe(findings: List[Finding]) -> List[Finding]:
        result, seen = [], set()
        for finding in findings:
            key = (finding.rule_id or finding.matched_pattern, finding.file_path,
                   finding.line_number, finding.function_name, finding.matched_text)
            if key not in seen:
                seen.add(key)
                result.append(finding)
        return result

    def scan(self, target: str | Path) -> ScanResult:
        """
        Scan a file or directory.

        Args:
            target: Path to file or directory.

        Returns:
            ScanResult with findings.
        """
        target = Path(target)

        if target.is_file():
            return self.scan_file(target)
        elif target.is_dir():
            return self.scan_directory(target)
        else:
            result = ScanResult()
            result.parse_errors.append(f"Invalid target: {target}")
            return result

    def scan_source(self, source_code: str, filename: str = "<string>") -> ScanResult:
        """
        Scan source code directly.

        Args:
            source_code: Python source code string.
            filename: Optional filename for error messages.

        Returns:
            ScanResult with findings.
        """
        result = ScanResult()
        result.files_scanned = 1

        # Parse the source
        server_info = self.parser.parse_source(source_code, filename)

        if server_info.parse_errors:
            result.parse_errors.extend(server_info.parse_errors)

        if server_info.server_name:
            result.servers_found = 1

        result.tools_analyzed = len(server_info.tools)

        # Run analyzers
        for analyzer in self.analyzers:
            findings = analyzer.analyze(server_info)
            result.findings.extend(findings)

        result.findings.extend(self.project_analyzer.analyze_python(server_info))
        result.findings = self._filter(self._dedupe(result.findings))

        return result


def scan_and_report(
    target: str,
    output_format: str = "console",
    output_file: str = None,
    verbose: bool = False,
    check: str = None,
) -> int:
    """
    Convenience function to scan and report in one step.

    Args:
        target: File or directory to scan.
        output_format: Output format ('console', 'json').
        output_file: Optional file to write report.
        verbose: Enable verbose output.
        check: Specific vulnerability to check ('tool-poisoning', 'prompt-injection').

    Returns:
        Exit code (0 = no issues, 1 = issues found, 2 = errors).
    """
    # Configure analyzers
    normalized_check = normalize_check(check)
    enable_tool_poisoning = normalized_check is None or normalized_check == "MCP03" or normalized_check == "MCP03-TOOL-POISON"
    enable_prompt_injection = normalized_check is None or normalized_check == "MCP06" or normalized_check == "MCP06-UNTRUSTED-CONTEXT"

    scanner = MCPScanner(
        enable_tool_poisoning=enable_tool_poisoning,
        enable_prompt_injection=enable_prompt_injection,
        verbose=verbose,
        check=normalized_check,
    )

    # Run scan
    result = scanner.scan(target)

    # Prepare scan info
    scan_info = {
        "target": str(target),
        "files_scanned": result.files_scanned,
        "tools_analyzed": result.tools_analyzed,
        "servers_found": result.servers_found,
    }

    # Generate report
    if output_format == "json":
        reporter = JsonReporter(pretty=True)
        json_output = reporter.report(result.findings, scan_info, output_file)
        if not output_file:
            print(json_output)
    else:
        reporter = ConsoleReporter(use_colors=True, verbose=verbose)
        reporter.report(result.findings, scan_info)

    # Determine exit code
    if result.parse_errors and not result.findings:
        return 2  # Errors only
    elif result.has_critical:
        return 1  # Critical issues
    elif result.findings:
        return 1  # Issues found
    else:
        return 0  # Clean
