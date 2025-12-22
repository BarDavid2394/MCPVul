"""
Base classes for security analyzers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any

from ..parsers.python_parser import MCPServerInfo, ToolDefinition


class Severity(Enum):
    """Severity levels for security findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> int:
        """Numeric score for severity comparison."""
        scores = {
            "CRITICAL": 10,
            "HIGH": 8,
            "MEDIUM": 5,
            "LOW": 2,
            "INFO": 0,
        }
        return scores.get(self.value, 0)

    def __lt__(self, other):
        if isinstance(other, Severity):
            return self.score < other.score
        return NotImplemented


@dataclass
class Finding:
    """
    Represents a security finding/vulnerability.
    """
    vulnerability_type: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    function_name: Optional[str] = None
    matched_pattern: Optional[str] = None
    matched_text: Optional[str] = None
    recommendation: Optional[str] = None
    code_snippet: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "function_name": self.function_name,
            "matched_pattern": self.matched_pattern,
            "matched_text": self.matched_text,
            "recommendation": self.recommendation,
            "code_snippet": self.code_snippet,
            "metadata": self.metadata,
        }


class BaseAnalyzer(ABC):
    """
    Abstract base class for security analyzers.

    Each analyzer implements detection logic for a specific vulnerability type.
    """

    # Analyzer metadata
    name: str = "BaseAnalyzer"
    description: str = "Base security analyzer"
    vulnerability_type: str = "generic"

    def __init__(self):
        self.findings: List[Finding] = []

    @abstractmethod
    def analyze(self, server_info: MCPServerInfo) -> List[Finding]:
        """
        Analyze an MCP server for vulnerabilities.

        Args:
            server_info: Parsed MCP server information.

        Returns:
            List of security findings.
        """
        pass

    @abstractmethod
    def analyze_tool(self, tool: ToolDefinition) -> List[Finding]:
        """
        Analyze a single tool definition for vulnerabilities.

        Args:
            tool: Tool definition to analyze.

        Returns:
            List of security findings for this tool.
        """
        pass

    def create_finding(
        self,
        severity: Severity,
        title: str,
        description: str,
        file_path: str,
        line_number: int,
        **kwargs
    ) -> Finding:
        """
        Helper method to create a Finding with this analyzer's type.
        """
        return Finding(
            vulnerability_type=self.vulnerability_type,
            severity=severity,
            title=title,
            description=description,
            file_path=file_path,
            line_number=line_number,
            **kwargs
        )

    def reset(self):
        """Clear findings from previous analysis."""
        self.findings = []
