"""Project-wide static checks for MCP attack categories other than MCP03/MCP06."""

import ast
import re
import unicodedata
from pathlib import Path
from typing import Iterable, List, Optional

from .base import Finding, Severity
from ..catalog import ATTACK_CATEGORIES, RULES
from ..parsers.python_parser import MCPServerInfo, ToolDefinition


MCP_SECURITY_REFERENCE = "https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices"
OWASP_REFERENCE = "https://github.com/OWASP/www-project-mcp-top-10"


class ProjectRiskAnalyzer:
    """Combines AST checks with conservative project/configuration signatures."""

    SECRET_PATTERNS = [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{30,}"),
        re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
        re.compile(r"(?i)\b(api[_-]?key|client[_-]?secret|access[_-]?token|password)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ]
    BROAD_SCOPE = re.compile(r"(?i)(?:scope|scopes)[^\n]{0,80}(?:\*|admin(?::\*|\b)|files:\*|db:\*|full[_-]?access)")
    DANGEROUS_STARTUP = re.compile(r"(?i)(?:curl\s+[^\n|;&]+\|\s*(?:sh|bash)|wget\s+[^\n|;&]+\|\s*(?:sh|bash)|sudo\b|rm\s+-rf|powershell[^\n]*(?:-enc|-command)|cmd(?:\.exe)?\s+/c)")
    MUTABLE_RUNNER = re.compile(r"(?i)(?:\bnpx\s+(?:-y\s+)?(?![^\n]*@\d)|\buvx\s+(?![^\n]*==)|\"command\"\s*:\s*\"(?:npx|uvx)\"(?![^\]]*(?:@\d|==\d))|github:[^\s#\"]+(?:[\s\"]|$)|https://github\.com/[^\s]+/(?:main|master)(?:\.|/))")

    def analyze_python(self, info: MCPServerInfo) -> List[Finding]:
        findings: List[Finding] = []
        source = info.source_code
        findings.extend(self._text_checks(info.filepath, source, "python"))

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return findings

        for tool in info.tools:
            findings.extend(self._analyze_tool_ast(tool))

        # Global mutable context is especially risky when tools share it without
        # an authenticated user/session key.
        for node in tree.body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                names = [target.id for target in targets if isinstance(target, ast.Name)]
                for name in names:
                    if re.search(r"(?i)(context|memory|history|session|cache|state)", name) and isinstance(value, (ast.Dict, ast.List, ast.Set, ast.Call)):
                        findings.append(self._finding("MCP10-SHARED-CONTEXT", info.filepath, node.lineno,
                            f"Global mutable state '{name}' may be shared across users or sessions.",
                            "Store context per authenticated user and session with expiry and explicit field allowlists.", "MEDIUM", matched=name))

        if re.search(r"(?i)return\s+(?:dict\()?\s*(?:os\.environ|globals\(\)|locals\(\)|context|memory|history|session)(?:\)|\b)", source):
            findings.append(self._finding("MCP10-OVER-SHARING", info.filepath, 1,
                "A tool may return an entire environment or broad context object.",
                "Return only explicitly selected fields and exclude credentials and unrelated session data.", "HIGH"))
        if re.search(r"(?i)(return|logger\.[a-z]+|logging\.[a-z]+)\s*\([^\n]*(token|secret|password|authorization)", source):
            findings.append(self._finding("MCP01-SECRET-OUTPUT", info.filepath, 1,
                "Credential-bearing data appears to be returned or logged.",
                "Redact credentials and never place them in tool output, model context, or logs.", "HIGH", matched="[REDACTED]"))

        network_transport = re.search(r"(?i)(streamable[_-]?http|transport\s*=\s*['\"](?:http|sse)|fastapi|starlette|uvicorn)", source)
        if network_transport and not re.search(r"(?i)(authorization|oauth|bearer|authmiddleware|verify_token|require_auth)", source):
            findings.append(self._finding("MCP07-MISSING-AUTH", info.filepath, self._line(source, network_transport.start()),
                "A network-capable MCP transport has no visible authentication or authorization enforcement.",
                "Authenticate every request and authorize each tool/resource operation.", "MEDIUM"))

        lower = source.lower()
        if ("authorization" in lower and "redirect_uri" in lower and
                not all(term in lower for term in ("state", "consent", "client_id"))):
            findings.append(self._finding("MCP11-CONFUSED-DEPUTY", info.filepath, 1,
                "OAuth proxy flow does not show per-client consent, state, and client binding controls.",
                "Bind consent and OAuth state to each client_id and exactly validate redirect_uri.", "MEDIUM"))

        if re.search(r"(?i)(authorization|bearer|access_token).{0,120}(requests|httpx|aiohttp)\.", source, re.DOTALL):
            if not re.search(r"(?i)(audience|\baud\b|token_exchange|client_credentials|validate_token)", source):
                findings.append(self._finding("MCP12-TOKEN-PASSTHROUGH", info.filepath, 1,
                    "An inbound credential appears near a downstream HTTP request without visible audience validation or token exchange.",
                    "Accept only tokens issued for this MCP server and obtain a separate downstream token.", "MEDIUM"))

        if re.search(r"(?i)(session_id|mcpsessionid)\s*=\s*(?:str\()?uuid\.uuid1|session_id\s*=\s*(?:request\.|params)", source):
            findings.append(self._finding("MCP14-WEAK-SESSION", info.filepath, 1,
                "Session identifiers appear predictable or directly client-controlled.",
                "Generate cryptographically random IDs, expire them, and bind them to the authenticated user.", "HIGH"))
        if re.search(r"(?i)if\s+.*session_id.*(?:authorized|authenticated)|sessions?\s*\[\s*session_id\s*\]", source):
            findings.append(self._finding("MCP14-SESSION-AUTH", info.filepath, 1,
                "A session identifier appears to act as the authorization decision or sole state key.",
                "Authorize every request and key shared session state by authenticated user plus session ID.", "MEDIUM"))

        if re.search(r"(?i)(webbrowser\.open|window\.open|startfile)\s*\([^)]*(authorization|auth|endpoint|url)", source) or re.search(r"(?i)(subprocess|os\.system)[^\n]*(authorization|auth)_?url", source):
            findings.append(self._finding("MCP15-UNSAFE-AUTH-URL", info.filepath, 1,
                "A dynamic authorization URL is opened without visible scheme validation.",
                "Allow only HTTPS (or development loopback HTTP) and never open URLs through a shell.", "HIGH"))

        if re.search(r"(?i)(subprocess\.(?:run|popen)|os\.system)\s*\([^\n]*(request|params|command|args)", source) and "stdio" in lower:
            findings.append(self._finding("MCP16-ARBITRARY-SPAWN", info.filepath, 1,
                "A stdio/proxy path appears able to spawn a request-controlled command.",
                "Use a fixed executable allowlist, fixed argument schemas, sandboxing, and explicit authorization.", "HIGH"))
        return self._dedupe(findings)

    def analyze_name_collisions(self, names: Iterable[tuple[str, str, str]]) -> List[Finding]:
        """Detect exact and Unicode/confusable names across server/tool sources."""
        findings: List[Finding] = []
        seen = {}
        for kind, name, path in names:
            normalized = "".join(ch for ch in unicodedata.normalize("NFKC", name).casefold() if ch.isalnum())
            key = (kind, normalized)
            if normalized and key in seen and (seen[key][0] != name or seen[key][1] != path):
                previous_name, previous_path = seen[key]
                findings.append(self._finding("MCP09-CONFUSABLE-NAME", path, 1,
                    f"{kind.title()} name '{name}' conflicts with '{previous_name}' from {previous_path}.",
                    "Use globally unique names and an approved server inventory; reject ambiguous registrations.", "MEDIUM", "config", name))
            else:
                seen[key] = (name, path)
        return findings

    def analyze_artifact(self, path: str | Path, text: str) -> List[Finding]:
        path = str(path)
        kind = self._source_kind(path)
        findings = self._text_checks(path, text, kind)
        lower_name = Path(path).name.lower()

        if self.DANGEROUS_STARTUP.search(text):
            match = self.DANGEROUS_STARTUP.search(text)
            findings.append(self._finding("MCP16-DANGEROUS-STARTUP", path, self._line(text, match.start()),
                "Configuration contains a dangerous local startup command.",
                "Replace shell startup with a fixed executable and arguments; require explicit user consent.", "HIGH", kind, match.group(0)))
        if self.MUTABLE_RUNNER.search(text):
            match = self.MUTABLE_RUNNER.search(text)
            findings.append(self._finding("MCP09-UNMANAGED-SERVER", path, self._line(text, match.start()),
                "MCP server configuration executes a mutable or unpinned package/source.",
                "Pin the package/version or immutable commit and record it in the approved server inventory.", "HIGH", kind, match.group(0)))

        dependency_file = any(token in lower_name for token in ("requirements", "pyproject", "pipfile", "poetry.lock", "uv.lock", "package.json", "package-lock"))
        if dependency_file:
            for index, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if self._looks_unpinned_dependency(stripped, lower_name):
                    findings.append(self._finding("MCP04-MUTABLE-DEPENDENCY", path, index,
                        "Dependency or executable package is not pinned to an immutable version.",
                        "Pin exact versions and commit hashes and commit the corresponding lockfile.", "MEDIUM", kind, stripped))
            if re.search(r"(?i)\"(?:preinstall|install|postinstall)\"\s*:\s*\"[^\"]*(?:curl|wget|powershell|bash|sh\s)", text):
                match = re.search(r"(?i)\"(?:preinstall|install|postinstall)\"", text)
                findings.append(self._finding("MCP04-INSTALL-HOOK", path, self._line(text, match.start()),
                    "Package manifest contains a network or shell-capable install hook.",
                    "Remove the hook or constrain and review it as privileged supply-chain code.", "HIGH", kind))
        return self._dedupe(findings)

    def _analyze_tool_ast(self, tool: ToolDefinition) -> List[Finding]:
        findings: List[Finding] = []
        try:
            module = ast.parse(tool.function_body)
        except SyntaxError:
            return findings
        params = set(tool.parameters)
        sensitive = False
        audited = bool(re.search(r"(?i)(audit|logger\.|logging\.|telemetry|trace)", tool.function_body))
        for node in ast.walk(module):
            if not isinstance(node, ast.Call):
                continue
            name = self._call_name(node.func).lower()
            dump = ast.dump(node)
            uses_param = any(re.search(rf"\b{re.escape(param)}\b", dump) for param in params)
            line = tool.line_number + getattr(node, "lineno", 1) - 1
            if name in {"os.system", "os.popen", "subprocess.run", "subprocess.popen", "subprocess.call", "subprocess.check_output"}:
                sensitive = True
                shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
                if uses_param or shell_true:
                    findings.append(self._finding("MCP05-COMMAND-INJECTION", tool.source_file, line,
                        "Tool-controlled data can reach a command execution sink.",
                        "Use a fixed executable and argument allowlist; never use shell=True with tool input.", "HIGH", "python", name, tool.name))
            if name in {"eval", "exec", "compile"} and uses_param:
                sensitive = True
                findings.append(self._finding("MCP05-DYNAMIC-CODE", tool.source_file, line,
                    "Tool input can reach dynamic code evaluation.", "Replace dynamic evaluation with a strict parser or operation allowlist.", "HIGH", "python", name, tool.name))
            if name.startswith(("requests.", "httpx.", "aiohttp.")) and uses_param:
                findings.append(self._finding("MCP13-SSRF", tool.source_file, line,
                    "A tool-controlled value is used as a network destination.",
                    "Allowlist schemes and hosts, block private/reserved addresses, and validate every redirect.", "HIGH", "python", name, tool.name))
            if name in {"open", "pathlib.path.read_text", "pathlib.path.read_bytes"} or name.startswith(("subprocess.", "os.remove", "shutil.")):
                sensitive = True
        if sensitive and not audited:
            findings.append(self._finding("MCP08-MISSING-AUDIT", tool.source_file, tool.line_number,
                "A sensitive tool performs file/process operations without visible audit telemetry.",
                "Record actor, tool, approved parameters, outcome, and correlation ID without logging secrets.", "LOW", "python", function_name=tool.name))
        return findings

    def _text_checks(self, path: str, text: str, kind: str) -> List[Finding]:
        findings: List[Finding] = []
        for pattern in self.SECRET_PATTERNS:
            for match in pattern.finditer(text):
                findings.append(self._finding("MCP01-SECRET-HARDCODED", path, self._line(text, match.start()),
                    "A credential-like value is hard-coded in a scanned artifact.",
                    "Move the secret to a secret manager, rotate it, and remove it from history.", "HIGH", kind, "[REDACTED]"))
        for match in self.BROAD_SCOPE.finditer(text):
            findings.append(self._finding("MCP02-BROAD-SCOPE", path, self._line(text, match.start()),
                "A wildcard or administrative scope expands the impact of token compromise.",
                "Request minimal scopes and elevate incrementally for privileged operations.", "MEDIUM", kind, match.group(0)))
        if re.search(r"(?i)(resource_metadata|authorization_servers|token_endpoint).{0,160}(requests|httpx|urlopen)", text, re.DOTALL) and not re.search(r"(?i)(allowlist|private[_ ]?ip|ipaddress|validate_url|https)", text):
            findings.append(self._finding("MCP13-METADATA-SSRF", path, 1,
                "OAuth discovery metadata appears to drive network requests without destination validation.",
                "Require HTTPS and reject private, loopback, link-local, and redirect destinations.", "MEDIUM", kind))
        if re.search(r"(?i)(host|bind)\s*[:=]\s*['\"]0\.0\.0\.0['\"]", text) and not re.search(r"(?i)(auth|bearer|oauth|token|middleware)", text):
            findings.append(self._finding("MCP07-PERMISSIVE-BIND", path, 1,
                "An MCP-related service binds to all interfaces without visible authorization.",
                "Require authentication or bind to a restricted local/IPC transport.", "HIGH", kind))
        return findings

    def _finding(self, rule_id: str, path: str, line: int, description: str, recommendation: str,
                 confidence: str, source_kind: str = "python", matched: Optional[str] = None,
                 function_name: Optional[str] = None) -> Finding:
        attack_id, title = RULES[rule_id]
        category = ATTACK_CATEGORIES[attack_id]
        severity = Severity.HIGH if confidence == "HIGH" else Severity.MEDIUM if confidence == "MEDIUM" else Severity.LOW
        return Finding(vulnerability_type=category.name.lower().replace(" ", "_"), severity=severity,
            title=f"{attack_id}: {title}", description=description, file_path=path, line_number=max(1, line),
            function_name=function_name, matched_pattern=rule_id, matched_text=matched,
            recommendation=recommendation, attack_id=attack_id, rule_id=rule_id, confidence=confidence,
            fixable=False, source_kind=source_kind,
            references=[OWASP_REFERENCE if category.source == "OWASP" else MCP_SECURITY_REFERENCE])

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute):
            base = ProjectRiskAnalyzer._call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    @staticmethod
    def _line(text: str, position: int) -> int: return text[:position].count("\n") + 1

    @staticmethod
    def _source_kind(path: str) -> str:
        suffix = Path(path).suffix.lower()
        return "dependency" if Path(path).name.lower() in {"requirements.txt", "pyproject.toml", "pipfile", "poetry.lock", "uv.lock", "package.json", "package-lock.json"} else "config" if suffix in {".json", ".yaml", ".yml", ".toml"} else "text"

    @staticmethod
    def _looks_unpinned_dependency(line: str, filename: str) -> bool:
        if not line or line.startswith(("#", "[", "{", "}")): return False
        if "requirements" in filename:
            return bool(re.match(r"^[A-Za-z0-9_.-]+(?:\[[^]]+\])?(?:\s*$|\s*[><~=])", line)) and "==" not in line
        if filename == "package.json":
            return bool(re.search(r'"[^"/]+"\s*:\s*"(?:latest|\*|\^|~|github:|https?:)', line))
        if filename in {"pyproject.toml", "pipfile"}:
            return bool(re.search(r"(?i)^[A-Za-z0-9_.-]+\s*=\s*['\"](?:\*|latest|\^|~|>=|>)", line))
        return False

    @staticmethod
    def _dedupe(findings: Iterable[Finding]) -> List[Finding]:
        result, seen = [], set()
        for finding in findings:
            key = (finding.rule_id, finding.file_path, finding.line_number, finding.function_name)
            if key not in seen:
                seen.add(key); result.append(finding)
        return result
