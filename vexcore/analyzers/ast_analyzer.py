"""ast_analyzer.py — Analizador basado en AST para Python.

Detecta patrones peligrosos con más precisión que regex:
  - eval(), exec() con cualquier argumento
  - os.system() con o sin asignación
  - subprocess con shell=True
  - pickle.load / pickle.loads
"""

from __future__ import annotations
import ast
from ..domain import Category, FileInfo, Finding, Severity
from ..ports import IAnalyzer

# (módulo, función, severidad, título)
_DANGEROUS_IMPORTS: list[tuple[str, str, Severity, str]] = [
    ("pickle", "loads", Severity.MEDIUM, "Deserialización con pickle.loads"),
    ("pickle", "load",  Severity.MEDIUM, "Deserialización con pickle.load"),
]

# (función peligrosa, attribute, severidad, título)
_CALLS: list[tuple[str, str | None, Severity, str]] = [
    ("eval",   None, Severity.HIGH,   "Uso de eval()"),
    ("exec",   None, Severity.HIGH,   "Uso de exec()"),
    ("system", None, Severity.HIGH,   "Uso de os.system()"),
]

# (módulo, función, severidad, título)
_SUBPROCESS_CALLS: list[tuple[str, str, Severity, str]] = [
    ("subprocess", "call",    Severity.HIGH, "subprocess.call()"),
    ("subprocess", "run",     Severity.HIGH, "subprocess.run()"),
    ("subprocess", "Popen",   Severity.HIGH, "subprocess.Popen()"),
]


class AstAnalyzer(IAnalyzer):
    """Analiza archivos Python con ast.parse y detecta llamadas peligrosas."""

    def analyze(self, file: FileInfo) -> list[Finding]:
        if file.extension != ".py":
            return []

        try:
            source = file.absolute.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(file.absolute))
        except (SyntaxError, OSError):
            return []

        visitor = _DangerVisitor(file)
        visitor.visit(tree)
        return visitor.findings


class _DangerVisitor(ast.NodeVisitor):
    def __init__(self, file: FileInfo) -> None:
        self.file = file
        self.findings: list[Finding] = []
        self._pickle_imported = False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "pickle":
                self._pickle_imported = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "pickle":
            self._pickle_imported = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_dangerous_call(node)
        self._check_pickle_call(node)
        self._check_subprocess_call(node)
        self.generic_visit(node)

    def _check_dangerous_call(self, node: ast.Call) -> None:
        func_name = self._get_func_name(node)
        if func_name is None:
            return
        for name, _, severity, title in _CALLS:
            if func_name == name:
                self.findings.append(Finding(
                    rule_id=f"AST_{name.upper()}",
                    title=title,
                    severity=severity,
                    category=Category.SAST,
                    file=self.file,
                    line=node.lineno,
                    snippet=f"{func_name}(...)",
                ))
                return

    def _check_pickle_call(self, node: ast.Call) -> None:
        if not self._pickle_imported:
            return
        func_name = self._get_func_name(node)
        if func_name is None:
            return
        for _, func, severity, title in _DANGEROUS_IMPORTS:
            if func_name == func:
                self.findings.append(Finding(
                    rule_id=f"AST_{func.upper()}",
                    title=title,
                    severity=severity,
                    category=Category.SAST,
                    file=self.file,
                    line=node.lineno,
                    snippet=f"pickle.{func}(...)",
                ))
                return

    def _check_subprocess_call(self, node: ast.Call) -> None:
        func_name = self._get_func_name(node)
        if func_name is None:
            return
        # Chequea subprocess.call/run/Popen con shell=True
        for mod, func, severity, title in _SUBPROCESS_CALLS:
            if func_name != func:
                continue
            # Verifica que el primer argumento o shell=True esté presente
            if self._has_shell_true(node):
                self.findings.append(Finding(
                    rule_id=f"AST_{func.upper()}",
                    title=f"{title} con shell=True",
                    severity=severity,
                    category=Category.SAST,
                    file=self.file,
                    line=node.lineno,
                    snippet=f"{func}(..., shell=True)",
                ))
                return

    def _get_func_name(self, node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def _has_shell_true(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant):
                return kw.value.value is True
        return False
