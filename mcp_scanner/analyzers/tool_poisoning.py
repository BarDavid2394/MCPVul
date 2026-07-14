"""
Tool Poisoning Analyzer

Detects malicious instructions hidden in MCP tool descriptions/metadata
that could trick LLMs into performing unauthorized actions.

Based on Section 5.1.4 of the research paper:
"Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions"
"""

import ast
import re
from typing import List, Optional

from .base import BaseAnalyzer, Finding, Severity
from ..parsers.python_parser import MCPServerInfo, ToolDefinition
from ..patterns.signatures import (
    COMPILED_TOOL_POISONING,
    COMPILED_SANITIZATION,
)
from ..utils.helpers import extract_context, truncate_string


class ToolPoisoningAnalyzer(BaseAnalyzer):
    """
    Analyzer for detecting Tool Poisoning vulnerabilities.

    Tool poisoning occurs when malicious actors embed covert instructions
    in tool descriptions/docstrings that trick LLMs into:
    - Reading sensitive files (SSH keys, credentials)
    - Exfiltrating data to external URLs
    - Executing unauthorized commands
    - Chaining with other tools maliciously
    """

    name = "Tool Poisoning Analyzer"
    description = "Detects malicious instructions hidden in tool descriptions"
    vulnerability_type = "tool_poisoning"

    # Recommendations for each pattern type
    RECOMMENDATIONS = {
        "hidden_instruction_brackets": (
            "Remove bracketed instruction markers. Tool descriptions should only "
            "contain factual information about the tool's purpose, not behavioral instructions."
        ),
        "file_read_instruction": (
            "Remove file access instructions from descriptions. If file reading is "
            "the tool's legitimate purpose, describe it without imperative commands."
        ),
        "data_exfiltration": (
            "Remove data transmission instructions. Tool descriptions should never "
            "instruct to send data to external endpoints."
        ),
        "url_in_description": (
            "Avoid including URLs in tool descriptions unless absolutely necessary. "
            "URLs can be used for data exfiltration attacks."
        ),
        "command_execution": (
            "Remove command execution instructions. Describe what the tool does, "
            "not what actions the LLM should take."
        ),
        "sequential_actions": (
            "Remove sequential action instructions. Tool descriptions should not "
            "chain actions or instruct follow-up behaviors."
        ),
        "override_instructions": (
            "CRITICAL: Remove instructions that override rules or ignore restrictions. "
            "This is a strong indicator of malicious intent."
        ),
        "sensitive_paths": (
            "Remove references to sensitive file paths. Tool descriptions should not "
            "mention specific system files, SSH keys, or credentials."
        ),
        "imperative_must": (
            "Rephrase imperative statements. Use declarative descriptions instead of "
            "commanding language like 'must', 'always', 'should'."
        ),
        "tool_chaining": (
            "Remove instructions to call other tools. Tool chaining should be "
            "determined by the LLM based on user intent, not hardcoded in descriptions."
        ),
        "preference_manipulation": (
            "Remove self-promotional language. Tool descriptions should be objective "
            "and not attempt to bias tool selection."
        ),
        "invisible_unicode": "Remove invisible and bidirectional Unicode controls from tool metadata.",
        "html_hidden_instruction": "Remove hidden HTML-comment instructions from tool metadata.",
    }

    def analyze(self, server_info: MCPServerInfo) -> List[Finding]:
        """
        Analyze all tools in an MCP server for poisoning vulnerabilities.
        """
        self.reset()

        for tool in server_info.tools:
            tool_findings = self.analyze_tool(tool)
            self.findings.extend(tool_findings)

        return self.findings

    def analyze_tool(self, tool: ToolDefinition) -> List[Finding]:
        """
        Analyze a single tool for poisoning patterns.
        """
        findings = []

        # Combine all text that could contain malicious instructions
        texts_to_analyze = [
            ("description", tool.description),
            ("docstring", tool.docstring or ""),
        ]

        for source_name, text in texts_to_analyze:
            if not text:
                continue

            # Check each poisoning pattern
            for pattern_name, pattern_info in COMPILED_TOOL_POISONING.items():
                matches = pattern_info["compiled"].finditer(text)

                for match in matches:
                    severity = self._get_severity(pattern_info["severity"])
                    matched_text = match.group(0)

                    finding = self.create_finding(
                        severity=severity,
                        title=f"Tool Poisoning: {pattern_info['description']}",
                        description=(
                            f"Suspicious pattern detected in tool {source_name}. "
                            f"This pattern could be used to trick an LLM into "
                            f"performing unauthorized actions."
                        ),
                        file_path=tool.source_file,
                        line_number=tool.line_number,
                        function_name=tool.name,
                        matched_pattern=pattern_name,
                        matched_text=truncate_string(matched_text, 100),
                        recommendation=self.RECOMMENDATIONS.get(pattern_name, "Review and remove suspicious content."),
                        code_snippet=truncate_string(text, 200),
                        metadata={
                            "source": source_name,
                            "pattern_example": pattern_info.get("example", ""),
                            "full_match": matched_text,
                        }
                    )
                    findings.append(finding)

        # Also analyze the function body for hidden instructions in strings
        body_findings = self._analyze_function_body(tool)
        findings.extend(body_findings)

        return findings

    def _analyze_function_body(self, tool: ToolDefinition) -> List[Finding]:
        """
        Analyze function body for suspicious string literals.
        """
        findings = []

        try:
            tree = ast.parse(tool.function_body)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            string_content = node.value
            if len(string_content) < 20 or string_content == tool.docstring:
                continue

            # Check this string against poisoning patterns
            for pattern_name, pattern_info in COMPILED_TOOL_POISONING.items():
                if pattern_info["compiled"].search(string_content):
                    # Calculate approximate line number
                    line_number = tool.line_number + getattr(node, "lineno", 1) - 1

                    finding = self.create_finding(
                        severity=self._get_severity(pattern_info["severity"]),
                        title=f"Tool Poisoning in Code: {pattern_info['description']}",
                        description=(
                            f"Suspicious pattern found in string literal within function body. "
                            f"This could be used for injection attacks."
                        ),
                        file_path=tool.source_file,
                        line_number=line_number,
                        function_name=tool.name,
                        matched_pattern=pattern_name,
                        matched_text=truncate_string(string_content, 100),
                        recommendation="Review string literals for hidden instructions.",
                        metadata={
                            "source": "function_body",
                            "pattern_example": pattern_info.get("example", ""),
                        }
                    )
                    findings.append(finding)
                    break  # One finding per string is enough

        return findings

    def _get_severity(self, severity_str: str) -> Severity:
        """Convert severity string to Severity enum."""
        try:
            return Severity[severity_str.upper()]
        except KeyError:
            return Severity.MEDIUM

    def analyze_text(self, text: str, source: str = "unknown") -> List[Finding]:
        """
        Analyze arbitrary text for poisoning patterns.
        Useful for testing or analyzing non-standard sources.

        Args:
            text: Text to analyze.
            source: Description of the text source.

        Returns:
            List of findings.
        """
        findings = []

        for pattern_name, pattern_info in COMPILED_TOOL_POISONING.items():
            matches = pattern_info["compiled"].finditer(text)

            for match in matches:
                severity = self._get_severity(pattern_info["severity"])

                finding = self.create_finding(
                    severity=severity,
                    title=f"Tool Poisoning: {pattern_info['description']}",
                    description=f"Suspicious pattern detected in {source}.",
                    file_path=source,
                    line_number=text[:match.start()].count("\n") + 1,
                    matched_pattern=pattern_name,
                    matched_text=truncate_string(match.group(0), 100),
                    recommendation=self.RECOMMENDATIONS.get(pattern_name, "Review and remove suspicious content."),
                )
                findings.append(finding)

        return findings
