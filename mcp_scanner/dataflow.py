"""Small, shared source-to-sink data-flow primitives used by analyzers."""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class Flow:
    source: str
    sink: str
    line: int
    path: tuple[str, ...]
    protections: tuple[str, ...] = ()


COMMAND_SINKS = {
    "os.system", "os.popen", "subprocess.run", "subprocess.popen",
    "subprocess.call", "subprocess.check_call", "subprocess.check_output",
}
VALIDATOR_HINTS = ("allowlist", "whitelist", "validate", "sanitize", "quote", "literal_eval")


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


class PythonDataFlow:
    """Conservative bounded intra-procedural taint propagation.

    It follows parameters through aliases, formatting, containers and helper
    calls. Recognized validation/sanitization calls stop a path and are kept as
    protection evidence instead of being silently ignored.
    """

    def summarize_command_helpers(self, tree: ast.AST) -> dict[str, tuple[int, str]]:
        """Return helpers whose parameter reaches a command sink.

        The value is ``(parameter index, sink)``. A small fixed-point also
        follows wrappers around already summarized helpers.
        """
        functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        summaries: dict[str, tuple[int, str]] = {}
        for _ in range(4):
            changed = False
            for function in functions:
                params = [arg.arg for arg in function.args.args]
                for call in (n for n in ast.walk(function) if isinstance(n, ast.Call)):
                    name = call_name(call.func).lower()
                    sink = name if name in COMMAND_SINKS else None
                    nested = summaries.get(name.split(".")[-1])
                    for index, param in enumerate(params):
                        argument_index = nested[0] if nested else None
                        expressions = ([call.args[argument_index]] if nested and len(call.args) > argument_index
                                       else list(call.args) + [kw.value for kw in call.keywords])
                        if (sink or nested) and any(any(isinstance(x, ast.Name) and x.id == param for x in ast.walk(expr))
                                                    for expr in expressions):
                            value = (index, sink or nested[1])
                            if summaries.get(function.name) != value:
                                summaries[function.name] = value
                                changed = True
            if not changed:
                break
        return summaries

    def command_flows(self, node: ast.AST, parameters: list[str],
                      helpers: dict[str, tuple[int, str]] | None = None) -> list[Flow]:
        taint: dict[str, tuple[str, ...]] = {
            p: (p,) for p in parameters if p.lower() not in {"self", "cls", "ctx", "context"}
        }
        protected: dict[str, tuple[str, ...]] = {}
        # Recognize fail-closed allowlist/validator guards before propagation.
        command_lines = [getattr(n, "lineno", 0) for n in ast.walk(node)
                         if isinstance(n, ast.Call) and call_name(n.func).lower() in COMMAND_SINKS]
        first_command = min(command_lines, default=10**9)
        for guard in (n for n in ast.walk(node) if isinstance(n, ast.If) and getattr(n, "lineno", 0) < first_command):
            exits = any(isinstance(n, (ast.Raise, ast.Return)) for statement in guard.body for n in ast.walk(statement))
            if not exits:
                continue
            if isinstance(guard.test, ast.Compare) and isinstance(guard.test.left, ast.Name):
                if any(isinstance(op, ast.NotIn) for op in guard.test.ops):
                    name = guard.test.left.id
                    if name in taint:
                        protected[name] = ("fail-closed allowlist guard",)
                        taint.pop(name, None)
            if isinstance(guard.test, ast.UnaryOp) and isinstance(guard.test.op, ast.Not) and isinstance(guard.test.operand, ast.Call):
                validator = call_name(guard.test.operand.func)
                if any(h in validator.lower() for h in VALIDATOR_HINTS):
                    for arg in guard.test.operand.args:
                        if isinstance(arg, ast.Name) and arg.id in taint:
                            protected[arg.id] = (validator,)
                            taint.pop(arg.id, None)

        def sources(expr: ast.AST) -> tuple[str, ...]:
            if isinstance(expr, ast.Call) and any(h in call_name(expr.func).lower() for h in VALIDATOR_HINTS):
                return ()
            found: list[str] = []
            for child in ast.walk(expr):
                if isinstance(child, ast.Name) and child.id in taint:
                    found.extend(taint[child.id])
            return tuple(dict.fromkeys(found))

        def assigned_names(target: ast.AST) -> list[str]:
            if isinstance(target, ast.Name):
                return [target.id]
            return [n.id for n in ast.walk(target) if isinstance(n, ast.Name)]

        statements = sorted(ast.walk(node), key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0)))
        for statement in statements:
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                value = statement.value
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                src = sources(value)
                if not src:
                    continue
                validator = next((call_name(c.func) for c in ast.walk(value)
                                  if isinstance(c, ast.Call) and any(h in call_name(c.func).lower() for h in VALIDATOR_HINTS)), None)
                for target in targets:
                    for name in assigned_names(target):
                        if validator:
                            protected[name] = (validator,)
                            taint.pop(name, None)
                        else:
                            taint[name] = src + (name,)

        flows: list[Flow] = []
        helpers = helpers or {}
        for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
            sink = call_name(call.func).lower()
            helper_name = sink.split(".")[-1]
            helper = helpers.get(helper_name)
            if sink not in COMMAND_SINKS and not helper:
                continue
            expressions = ([call.args[helper[0]]] if helper and len(call.args) > helper[0]
                           else list(call.args) + [kw.value for kw in call.keywords if kw.arg != "shell"])
            src = tuple(dict.fromkeys(s for expr in expressions for s in sources(expr)))
            shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                             for kw in call.keywords)
            if src:
                actual_sink = helper[1] if helper else sink
                path = src + ((f"{helper_name}()", actual_sink) if helper else (sink,))
                flows.append(Flow(src[0], actual_sink, getattr(call, "lineno", 1), path))
            elif shell_true and any(sources(expr) for expr in expressions):
                flows.append(Flow("tool input", sink, getattr(call, "lineno", 1), ("tool input", sink)))
        return flows
