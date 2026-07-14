"""
AST-based code transformations for auto-fixing MCP security vulnerabilities.

Transforms:
1. Docstring cleaning - removes tool poisoning patterns
2. Return statement wrapping - adds sanitize_content() calls
"""

import ast
import re
from typing import List, Tuple, Optional, Set
from dataclasses import dataclass, field

from .sanitizers import DescriptionSanitizer, DESCRIPTION_POISON_PATTERNS


@dataclass
class TransformResult:
    """Result of code transformation."""
    original_code: str
    transformed_code: str
    changes_made: List[str] = field(default_factory=list)
    lines_modified: List[int] = field(default_factory=list)
    imports_added: List[str] = field(default_factory=list)
    success: bool = True
    error: Optional[str] = None


@dataclass
class FixableIssue:
    """Represents an issue that can be auto-fixed."""
    issue_type: str  # 'tool_poisoning' or 'prompt_injection'
    line_number: int
    function_name: str
    description: str
    fix_action: str


class CodeTransformer:
    """
    Transforms Python source code to fix MCP security vulnerabilities.

    Uses line-based transformation (not AST rewriting) to preserve
    original formatting and comments.
    """

    def __init__(self):
        self.description_sanitizer = DescriptionSanitizer()
        self._poison_patterns = [
            (re.compile(pattern, re.MULTILINE | re.DOTALL), name)
            for pattern, name in DESCRIPTION_POISON_PATTERNS
        ]

    def transform(self, source_code: str, findings: List = None) -> TransformResult:
        """
        Transform source code to fix security vulnerabilities.

        Args:
            source_code: Original Python source code
            findings: Optional list of Finding objects from scanner

        Returns:
            TransformResult with transformed code and metadata
        """
        result = TransformResult(
            original_code=source_code,
            transformed_code=source_code
        )

        try:
            # Parse to get structure
            tree = ast.parse(source_code)
        except SyntaxError as e:
            result.success = False
            result.error = f"Syntax error: {e}"
            return result

        lines = source_code.split('\n')
        needs_sanitize_import = False
        modified_lines: Set[int] = set()
        changes = []
        findings = findings or []
        poison_targets = {
            finding.function_name for finding in findings
            if getattr(finding, "attack_id", None) == "MCP03"
            and getattr(finding, "severity", None).value in {"CRITICAL", "HIGH"}
            and finding.function_name
        }
        prompt_targets = {
            finding.function_name for finding in findings
            if getattr(finding, "attack_id", None) == "MCP06"
            and getattr(finding, "severity", None).value in {"CRITICAL", "HIGH"}
            and finding.function_name
        }

        # Find all tool functions and sort by line number (descending)
        # Processing from bottom to top prevents line number shifts from affecting later fixes
        tool_functions = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._is_tool_function(node):
                    tool_functions.append(node)

        # Sort by line number descending (fix from bottom to top)
        tool_functions.sort(key=lambda n: n.lineno, reverse=True)

        for node in tool_functions:
            # Edit lower return lines before replacing an earlier docstring so
            # original AST line spans remain valid throughout this function.
            return_result = self._fix_return_statements(node, lines) if node.name in prompt_targets else None
            if return_result:
                lines, ret_changes, ret_lines, needs_import = return_result
                changes.extend(ret_changes)
                modified_lines.update(ret_lines)
                if needs_import:
                    needs_sanitize_import = True

            docstring_result = self._fix_docstring(node, lines) if node.name in poison_targets else None
            if docstring_result:
                lines, doc_changes, doc_lines = docstring_result
                changes.extend(doc_changes)
                modified_lines.update(doc_lines)

        # Add import if needed
        imports_added = []
        if needs_sanitize_import:
            lines, import_added = self._add_sanitize_import(lines, tree)
            if import_added:
                imports_added.append("from mcp_scanner.defenses import sanitize_content")
                changes.insert(0, "Added sanitize_content import")

        result.transformed_code = '\n'.join(lines)
        result.changes_made = changes
        result.lines_modified = sorted(modified_lines)
        result.imports_added = imports_added

        try:
            ast.parse(result.transformed_code)
        except SyntaxError as exc:
            result.success = False
            result.error = f"Transformation produced invalid Python: {exc}"
            result.transformed_code = source_code
            result.changes_made = []
        return result

    def _is_tool_function(self, node: ast.FunctionDef) -> bool:
        """Check if function has a tool decorator."""
        for decorator in node.decorator_list:
            dec_name = self._get_decorator_name(decorator)
            if dec_name == 'tool' or dec_name.endswith('.tool'):
                return True
        return False

    def _get_decorator_name(self, decorator) -> str:
        """Get full decorator name."""
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
            return '.'.join(reversed(parts))
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return ''

    def _fix_docstring(self, node: ast.FunctionDef, lines: List[str]) -> Optional[Tuple[List[str], List[str], List[int]]]:
        """
        Fix tool poisoning in docstring.

        Returns:
            Tuple of (modified_lines, changes, line_numbers) or None if no changes
        """
        docstring = ast.get_docstring(node)
        if not docstring:
            return None

        # Check if docstring has issues
        has_issues = False
        for pattern, _ in self._poison_patterns:
            if pattern.search(docstring):
                has_issues = True
                break

        if not has_issues:
            return None

        # Sanitize the docstring
        sanitized = self.description_sanitizer.sanitize(docstring)

        if sanitized.content == docstring:
            return None

        # Find docstring location in source
        # Docstring is first statement in function body
        if node.body and isinstance(node.body[0], ast.Expr):
            if isinstance(node.body[0].value, ast.Constant):
                doc_node = node.body[0]
                start_line = doc_node.lineno - 1  # 0-indexed
                end_line = doc_node.end_lineno - 1

                # Detect quote style
                original_doc_text = '\n'.join(lines[start_line:end_line + 1])
                if '"""' in original_doc_text:
                    quote = '"""'
                else:
                    quote = "'''"

                # Get indentation from the original docstring line
                indent = len(lines[start_line]) - len(lines[start_line].lstrip())
                indent_str = ' ' * indent

                # Build new docstring with proper formatting
                new_docstring_lines = []
                sanitized_content = sanitized.content.strip()
                sanitized_lines = sanitized_content.split('\n')

                # Clean up empty lines and normalize
                sanitized_lines = [line.strip() for line in sanitized_lines]
                # Remove consecutive empty lines
                cleaned_lines = []
                prev_empty = False
                for line in sanitized_lines:
                    if line == '':
                        if not prev_empty:
                            cleaned_lines.append(line)
                        prev_empty = True
                    else:
                        cleaned_lines.append(line)
                        prev_empty = False

                # Remove leading/trailing empty lines
                while cleaned_lines and cleaned_lines[0] == '':
                    cleaned_lines.pop(0)
                while cleaned_lines and cleaned_lines[-1] == '':
                    cleaned_lines.pop()

                if len(cleaned_lines) == 0:
                    # Empty docstring after cleaning
                    new_docstring_lines.append(f'{indent_str}{quote}Tool function.{quote}')
                elif len(cleaned_lines) == 1:
                    # Single line docstring
                    new_docstring_lines.append(f'{indent_str}{quote}{cleaned_lines[0]}{quote}')
                else:
                    # Multi-line docstring
                    new_docstring_lines.append(f'{indent_str}{quote}')
                    for line in cleaned_lines:
                        if line:
                            new_docstring_lines.append(f'{indent_str}{line}')
                        else:
                            new_docstring_lines.append('')
                    new_docstring_lines.append(f'{indent_str}{quote}')

                # Replace lines
                lines = lines[:start_line] + new_docstring_lines + lines[end_line + 1:]

                changes = [f"Cleaned docstring in {node.name}(): removed {len(sanitized.patterns_removed)} poisoning patterns"]
                modified_lines = list(range(start_line + 1, start_line + len(new_docstring_lines) + 1))

                return lines, changes, modified_lines

        return None

    def _fix_return_statements(self, node: ast.FunctionDef, lines: List[str]) -> Optional[Tuple[List[str], List[str], List[int], bool]]:
        """
        Wrap unsafe return statements with sanitize_content().

        Returns:
            Tuple of (modified_lines, changes, line_numbers, needs_import) or None
        """
        # Patterns that indicate unsafe returns
        unsafe_patterns = [
            (r'return\s+.*requests\.(get|post|put|delete)\([^)]*\)\.(text|content)', 'HTTP response'),
            (r'return\s+.*\.read\(\)', 'file/stream content'),
            (r'return\s+.*subprocess\.[^(]+\([^)]*\)\.(stdout|output)', 'subprocess output'),
            (r'return\s+.*urlopen\([^)]*\)\.read\(\)', 'URL content'),
        ]

        changes = []
        modified_lines = []
        needs_import = False

        # Walk through function body looking for return statements
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                line_idx = child.lineno - 1
                if line_idx < len(lines):
                    line = lines[line_idx]

                    # Check if already wrapped
                    if 'sanitize_content(' in line:
                        continue

                    # Check if line matches unsafe patterns
                    for pattern, desc in unsafe_patterns:
                        if re.search(pattern, line):
                            # Wrap the return value with sanitize_content()
                            new_line = self._wrap_return_with_sanitize(line)
                            if new_line != line:
                                lines[line_idx] = new_line
                                changes.append(f"Wrapped {desc} return in {node.name}() with sanitize_content()")
                                modified_lines.append(child.lineno)
                                needs_import = True
                            break

        if changes:
            return lines, changes, modified_lines, needs_import
        return None

    def _wrap_return_with_sanitize(self, line: str) -> str:
        """Wrap return value with sanitize_content()."""
        # Match return statement and capture the value
        match = re.match(r'^(\s*)return\s+(.+)$', line)
        if match:
            indent = match.group(1)
            value = match.group(2).rstrip()
            return f'{indent}return sanitize_content({value})'
        return line

    def _add_sanitize_import(self, lines: List[str], tree: ast.Module) -> Tuple[List[str], bool]:
        """
        Add sanitize_content import if not present.

        Returns:
            Tuple of (modified_lines, was_added)
        """
        # Check if import already exists
        source = '\n'.join(lines)
        if 'from mcp_scanner.defenses import' in source and 'sanitize_content' in source:
            return lines, False
        if 'from mcp_scanner.defenses import sanitize_content' in source:
            return lines, False

        # Find best location for import (after other imports)
        import_line = 0
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                import_line = node.end_lineno
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                break

        # Insert import
        import_statement = 'from mcp_scanner.defenses import sanitize_content'
        lines.insert(import_line, import_statement)

        return lines, True


def transform_file(filepath: str, findings: List = None) -> TransformResult:
    """
    Convenience function to transform a file.

    Args:
        filepath: Path to Python file
        findings: Optional scanner findings

    Returns:
        TransformResult
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        source_code = f.read()

    transformer = CodeTransformer()
    return transformer.transform(source_code, findings)
