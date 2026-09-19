import ast
import re
from typing import Any, Dict, List


class StaticAnalyzer:
    SECRET_PATTERNS = {
        "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
        "Private Key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "GitHub Token": r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
        "Generic API Key": r"(?i)(api[_-]?key|secret[_-]?key)\s*=\s*['\"][^'\"]{8,}['\"]",
        "Hardcoded Password": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]",
    }

    def scan(self, code: str, language: str = "python") -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        lines = code.splitlines() or [""]
        findings.extend(self._secret_scan(lines))
        findings.extend(self._security_scan(lines, language))
        if language.lower() == "python":
            findings.extend(self._python_ast_scan(code))
        findings = self._dedupe(findings)
        score = self._score(findings)
        return {
            "findings": findings,
            "score": score,
            "statistics": self._statistics(findings),
            "ast": self._ast_summary(code) if language.lower() == "python" else None,
        }

    def _secret_scan(self, lines):
        out = []
        for n, line in enumerate(lines, 1):
            for name, pattern in self.SECRET_PATTERNS.items():
                if re.search(pattern, line):
                    out.append(self._finding(
                        f"SECRET-{n}-{name[:4].upper()}",
                        f"Potential exposed secret: {name}", n, "CRITICAL",
                        "Security", "SECRET_LEAK", line,
                        "Move credentials to environment variables or a secret manager."
                    ))
        return out

    def _security_scan(self, lines, language):
        rules = [
            (r"(?i)(SELECT|INSERT|UPDATE|DELETE).*(\+|f[\"']|%[a-z])",
             "Possible SQL Injection", "CRITICAL", "CWE-89",
             "Use parameterized queries instead of constructing SQL with user-controlled values."),
            (r"os\.system\s*\(|subprocess\.(?:call|run|Popen)\(.*shell\s*=\s*True",
             "Possible Command Injection", "HIGH", "CWE-78",
             "Avoid shell execution with untrusted input; pass arguments as a list and validate input."),
            (r"pickle\.loads\s*\(|pickle\.load\s*\(",
             "Unsafe Deserialization", "CRITICAL", "CWE-502",
             "Do not deserialize untrusted data with pickle."),
            (r"yaml\.load\s*\(",
             "Potential Unsafe YAML Loading", "HIGH", "CWE-502",
             "Prefer yaml.safe_load for untrusted YAML input."),
            (r"(?i)innerHTML\s*=",
             "Potential XSS Sink", "HIGH", "CWE-79",
             "Avoid assigning untrusted HTML; sanitize content or use textContent."),
            (r"(?i)eval\s*\(",
             "Use of eval()", "HIGH", "CWE-95",
             "Avoid eval; use explicit parsing or safer alternatives."),
            (r"(?i)debug\s*=\s*True",
             "Debug Mode Enabled", "MEDIUM", "CWE-489",
             "Disable debug mode in production deployments."),
        ]
        out = []
        for n, line in enumerate(lines, 1):
            for pattern, title, severity, cwe, rec in rules:
                if re.search(pattern, line):
                    out.append(self._finding(
                        f"SAST-{n}-{cwe}",
                        title, n, severity, "Security", "SAST_VULNERABILITY",
                        line, f"{rec} ({cwe})."
                    ))
        return out

    def _python_ast_scan(self, code):
        out = []
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return [self._finding(
                "AST-SYNTAX", "Python syntax error", e.lineno or 1, "HIGH",
                "Code Quality", "SYNTAX_ERROR",
                (code.splitlines()[e.lineno - 1] if e.lineno and e.lineno <= len(code.splitlines()) else ""),
                f"Fix the syntax error before deeper analysis: {e.msg}."
            )]
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and len(node.body) > 35:
                out.append(self._finding(
                    f"QUALITY-FUNC-{node.lineno}", "Large function / maintainability risk",
                    node.lineno, "LOW", "Code Quality", "CODE_QUALITY",
                    node.name, "Consider splitting the function into smaller, focused units."
                ))
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                out.append(self._finding(
                    f"QUALITY-EXCEPT-{node.lineno}", "Bare exception handler",
                    node.lineno, "MEDIUM", "Code Quality", "CODE_QUALITY",
                    "except:", "Catch specific exception types and handle them explicitly."
                ))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "assert":
                out.append(self._finding(
                    f"QUALITY-ASSERT-{node.lineno}", "Runtime assert usage",
                    node.lineno, "LOW", "Code Quality", "CODE_QUALITY",
                    "assert", "Use explicit validation for checks that must remain active in production."
                ))
        return out

    def _ast_summary(self, code):
        try:
            tree = ast.parse(code)
            funcs = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
            imports = [n.names[0].name for n in ast.walk(tree) if isinstance(n, ast.Import) and n.names]
            return {"functions": funcs, "classes": classes, "imports": imports}
        except SyntaxError:
            return {"functions": [], "classes": [], "imports": []}

    def _finding(self, fid, title, line, severity, category, kind, snippet, recommendation):
        return {
            "id": fid, "title": title, "line": line, "severity": severity,
            "category": category, "type": kind, "code_snippet": snippet.strip()[:500],
            "recommendation": recommendation
        }

    def _score(self, findings):
        weights = {"CRITICAL": 22, "HIGH": 14, "MEDIUM": 7, "LOW": 2}
        score = 100 - sum(weights.get(x["severity"], 0) for x in findings)
        return max(0, min(100, score))

    def _statistics(self, findings):
        return {s: sum(1 for x in findings if x["severity"] == s)
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}

    def _dedupe(self, findings):
        seen = set()
        result = []
        for f in findings:
            key = (f["title"], f["line"])
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result
