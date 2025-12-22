"""
Python AST parser for MCP server files.

Extracts tool definitions, their descriptions, and function bodies
for security analysis.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any


@dataclass
class ToolDefinition:
    """Represents an MCP tool definition extracted from source code."""
    name: str
    description: str
    docstring: Optional[str]
    line_number: int
    end_line_number: int
    function_body: str
    parameters: List[str]
    decorators: List[str]
    source_file: str
    raw_node: Any = field(repr=False, default=None)

    @property
    def full_description(self) -> str:
        """Get combined description from decorator and docstring."""
        parts = []
        if self.description:
            parts.append(self.description)
        if self.docstring:
            parts.append(self.docstring)
        return "\n".join(parts)


@dataclass
class MCPServerInfo:
    """Information about an MCP server file."""
    filepath: str
    server_name: Optional[str]
    tools: List[ToolDefinition]
    imports: List[str]
    source_code: str
    parse_errors: List[str] = field(default_factory=list)


class PythonMCPParser:
    """
    Parser for Python MCP server implementations.

    Extracts tool definitions marked with @server.tool() or similar decorators.
    """

    # Common MCP tool decorator patterns
    TOOL_DECORATORS = [
        "tool",
        "server.tool",
        "mcp.tool",
        "app.tool",
    ]

    def __init__(self):
        self.source_code = ""
        self.source_lines = []

    def parse_file(self, filepath: str | Path) -> MCPServerInfo:
        """
        Parse an MCP server Python file.

        Args:
            filepath: Path to the Python file.

        Returns:
            MCPServerInfo containing extracted tool definitions.
        """
        filepath = Path(filepath)

        try:
            self.source_code = filepath.read_text(encoding="utf-8")
            self.source_lines = self.source_code.split("\n")
        except Exception as e:
            return MCPServerInfo(
                filepath=str(filepath),
                server_name=None,
                tools=[],
                imports=[],
                source_code="",
                parse_errors=[f"Could not read file: {e}"],
            )

        try:
            tree = ast.parse(self.source_code)
        except SyntaxError as e:
            return MCPServerInfo(
                filepath=str(filepath),
                server_name=None,
                tools=[],
                imports=[],
                source_code=self.source_code,
                parse_errors=[f"Syntax error: {e}"],
            )

        # Extract information
        server_name = self._find_server_name(tree)
        tools = self._extract_tools(tree, str(filepath))
        imports = self._extract_imports(tree)

        return MCPServerInfo(
            filepath=str(filepath),
            server_name=server_name,
            tools=tools,
            imports=imports,
            source_code=self.source_code,
        )

    def parse_source(self, source_code: str, filename: str = "<string>") -> MCPServerInfo:
        """
        Parse MCP server source code directly.

        Args:
            source_code: Python source code string.
            filename: Optional filename for error messages.

        Returns:
            MCPServerInfo containing extracted tool definitions.
        """
        self.source_code = source_code
        self.source_lines = source_code.split("\n")

        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            return MCPServerInfo(
                filepath=filename,
                server_name=None,
                tools=[],
                imports=[],
                source_code=source_code,
                parse_errors=[f"Syntax error: {e}"],
            )

        server_name = self._find_server_name(tree)
        tools = self._extract_tools(tree, filename)
        imports = self._extract_imports(tree)

        return MCPServerInfo(
            filepath=filename,
            server_name=server_name,
            tools=tools,
            imports=imports,
            source_code=source_code,
        )

    def _find_server_name(self, tree: ast.AST) -> Optional[str]:
        """Find the MCP server name from Server() instantiation."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "server":
                        if isinstance(node.value, ast.Call):
                            if self._get_call_name(node.value) in ["Server", "FastMCP"]:
                                # Extract server name from first argument
                                if node.value.args:
                                    arg = node.value.args[0]
                                    if isinstance(arg, ast.Constant):
                                        return arg.value
        return None

    def _extract_tools(self, tree: ast.AST, filepath: str) -> List[ToolDefinition]:
        """Extract all tool definitions from the AST."""
        tools = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                tool_info = self._check_tool_decorator(node)
                if tool_info:
                    tool = self._create_tool_definition(node, tool_info, filepath)
                    tools.append(tool)

        return tools

    def _check_tool_decorator(self, node: ast.FunctionDef) -> Optional[Dict[str, Any]]:
        """Check if a function has a tool decorator and extract its info."""
        for decorator in node.decorator_list:
            decorator_name = self._get_decorator_name(decorator)

            # Check if it's a tool decorator
            if any(pattern in decorator_name for pattern in self.TOOL_DECORATORS):
                info = {"decorator_name": decorator_name, "description": ""}

                # Extract description from decorator arguments
                if isinstance(decorator, ast.Call):
                    # Check for description keyword argument
                    for keyword in decorator.keywords:
                        if keyword.arg == "description":
                            if isinstance(keyword.value, ast.Constant):
                                info["description"] = keyword.value.value

                    # Check for positional description argument
                    if decorator.args:
                        first_arg = decorator.args[0]
                        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                            info["description"] = first_arg.value

                return info

        return None

    def _get_decorator_name(self, decorator: ast.expr) -> str:
        """Get the full name of a decorator."""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            parts = []
            node = decorator
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            return ".".join(reversed(parts))
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return ""

    def _get_call_name(self, call: ast.Call) -> str:
        """Get the name of a function call."""
        if isinstance(call.func, ast.Name):
            return call.func.id
        elif isinstance(call.func, ast.Attribute):
            return call.func.attr
        return ""

    def _create_tool_definition(
        self,
        node: ast.FunctionDef,
        tool_info: Dict[str, Any],
        filepath: str
    ) -> ToolDefinition:
        """Create a ToolDefinition from a function node."""
        # Get function body as source code
        start_line = node.lineno - 1
        end_line = node.end_lineno if node.end_lineno else start_line + 1
        function_body = "\n".join(self.source_lines[start_line:end_line])

        # Extract parameter names
        parameters = []
        for arg in node.args.args:
            parameters.append(arg.arg)

        # Extract decorator names
        decorators = []
        for dec in node.decorator_list:
            decorators.append(self._get_decorator_name(dec))

        # Get docstring
        docstring = ast.get_docstring(node)

        return ToolDefinition(
            name=node.name,
            description=tool_info.get("description", ""),
            docstring=docstring,
            line_number=node.lineno,
            end_line_number=end_line,
            function_body=function_body,
            parameters=parameters,
            decorators=decorators,
            source_file=filepath,
            raw_node=node,
        )

    def _extract_imports(self, tree: ast.AST) -> List[str]:
        """Extract all import statements."""
        imports = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}")

        return imports
