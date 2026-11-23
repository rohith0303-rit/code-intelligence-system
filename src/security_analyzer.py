import ast
import hashlib
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

IGNORE_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules",
    ".idea", ".vscode", "dist", "build", ".pytest_cache", ".mypy_cache"
}

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key)\s*[:=]\s*['\x22][A-Za-z0-9_\-/.+=]{10,}['\x22]", "CWE-798", "OWASP A07:2021", "HIGH", "Possible hardcoded credential or API token"),
    (r"(?:AKIA|AIza|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|gsk_[A-Za-z0-9]{20,})", "CWE-798", "OWASP A07:2021", "HIGH", "Recognized cloud/LLM/provider token pattern"),
]

REGEX_VULN_PATTERNS = [
    (r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*\+\s*[A-Za-z_][A-Za-z0-9_]*", "CWE-89", "OWASP A03:2021", "HIGH", "Potential SQL string concatenation / injection"),
    (r"(?i)verify\s*=\s*False", "CWE-295", "OWASP A07:2021", "MEDIUM", "SSL/TLS certificate verification disabled"),
    (r"(?i)debug\s*=\s*True", "CWE-489", "OWASP A05:2021", "LOW", "Debug mode enabled in source code"),
]

DANGEROUS_CALLS = {
    "eval": ("CWE-94", "OWASP A03:2021", "HIGH", "Dynamic code execution via eval()"),
    "exec": ("CWE-94", "OWASP A03:2021", "HIGH", "Dynamic code execution via exec()"),
    "pickle.loads": ("CWE-502", "OWASP A08:2021", "HIGH", "Unsafe deserialization via pickle.loads()"),
    "yaml.load": ("CWE-502", "OWASP A08:2021", "MEDIUM", "Potentially unsafe YAML loading (ensure SafeLoader)"),
    "md5": ("CWE-328", "OWASP A02:2021", "MEDIUM", "Weak cryptographic hash algorithm (MD5)"),
    "sha1": ("CWE-328", "OWASP A02:2021", "LOW", "Weak cryptographic hash algorithm (SHA-1)"),
}


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _max_nesting_depth(node: ast.AST, depth: int = 0) -> int:
    nesting_nodes = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)
    current = depth + 1 if isinstance(node, nesting_nodes) else depth
    children_depths = [_max_nesting_depth(child, current) for child in ast.iter_child_nodes(node)]
    return max([current] + children_depths) if children_depths else current


def _has_unreachable_after_exit(body: List[ast.stmt]) -> List[int]:
    lines: List[int] = []
    exited = False
    for stmt in body:
        if exited:
            lines.append(getattr(stmt, "lineno", 1))
        if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            exited = True
    return lines


def analyze_security_and_quality(root_path: str) -> Dict[str, Any]:
    """Scans a codebase for CWE/OWASP security risks, bugs, dead code, and structural smells."""
    root = Path(root_path).resolve()
    findings: List[Dict[str, Any]] = []
    quality_issues: List[Dict[str, Any]] = []
    block_hashes: Dict[str, List[str]] = defaultdict(list)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fname in filenames:
            full_path = Path(dirpath) / fname
            rel_path = full_path.relative_to(root).as_posix()

            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()

            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                for pattern, cwe, owasp, severity, desc in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        findings.append({
                            "type": "secret_exposure",
                            "severity": severity,
                            "confidence": 0.85,
                            "cwe": cwe,
                            "owasp": owasp,
                            "file": rel_path,
                            "line": idx,
                            "description": desc,
                            "evidence": stripped[:140],
                            "remediation": "Move secrets to environment variables (.env / secret manager) and rotate exposed keys.",
                        })

                for pattern, cwe, owasp, severity, desc in REGEX_VULN_PATTERNS:
                    if re.search(pattern, line):
                        findings.append({
                            "type": "security_pattern",
                            "severity": severity,
                            "confidence": 0.72,
                            "cwe": cwe,
                            "owasp": owasp,
                            "file": rel_path,
                            "line": idx,
                            "description": desc,
                            "evidence": stripped[:140],
                            "remediation": "Use parameterized queries, enforce TLS certificate validation, and disable debug mode in production.",
                        })

            for i in range(len(lines) - 5):
                chunk = "\n".join(ln.strip() for ln in lines[i:i + 6] if ln.strip())
                if len(chunk) > 120:
                    digest = hashlib.md5(chunk.encode("utf-8")).hexdigest()
                    block_hashes[digest].append(f"{rel_path}:{i + 1}")

            if full_path.suffix.lower() == ".py":
                try:
                    tree = ast.parse(content, filename=rel_path)
                except SyntaxError as exc:
                    quality_issues.append({
                        "type": "syntax_error",
                        "severity": "HIGH",
                        "confidence": 1.0,
                        "file": rel_path,
                        "line": exc.lineno or 1,
                        "description": f"Syntax error: {exc.msg}",
                        "remediation": "Fix Python syntax error so the module can parse and execute.",
                    })
                    continue

                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        name = _call_name(node.func)
                        for danger_key, (cwe, owasp, severity, desc) in DANGEROUS_CALLS.items():
                            if name == danger_key or name.endswith(f".{danger_key.split('.')[-1]}"):
                                findings.append({
                                    "type": "dangerous_call",
                                    "severity": severity,
                                    "confidence": 0.88,
                                    "cwe": cwe,
                                    "owasp": owasp,
                                    "file": rel_path,
                                    "line": node.lineno,
                                    "description": desc,
                                    "evidence": f"Call to {name}()",
                                    "remediation": f"Replace {name}() with a safe alternative (e.g., ast.literal_eval, json/safe_load, hashlib.sha256).",
                                })

                    if isinstance(node, ast.ExceptHandler) and node.type is None:
                        findings.append({
                            "type": "broad_except",
                            "severity": "LOW",
                            "confidence": 0.9,
                            "cwe": "CWE-396",
                            "owasp": "OWASP A10:2021",
                            "file": rel_path,
                            "line": node.lineno,
                            "description": "Bare except clause catches all exceptions including system exits/interrupts",
                            "evidence": "except:",
                            "remediation": "Catch specific exception types (e.g., except (ValueError, KeyError) as exc:).",
                        })

                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        end_line = getattr(node, "end_lineno", node.lineno)
                        length = end_line - node.lineno + 1
                        nesting = _max_nesting_depth(node)
                        unreachable_lines = _has_unreachable_after_exit(node.body)

                        if length > 75:
                            quality_issues.append({
                                "type": "long_function",
                                "severity": "MEDIUM",
                                "confidence": 0.95,
                                "file": rel_path,
                                "line": node.lineno,
                                "description": f"Function '{node.name}' is {length} lines long (> 75 lines)",
                                "remediation": "Decompose long functions into smaller, single-responsibility helper functions.",
                            })

                        if nesting >= 5:
                            quality_issues.append({
                                "type": "deep_nesting",
                                "severity": "MEDIUM",
                                "confidence": 0.9,
                                "file": rel_path,
                                "line": node.lineno,
                                "description": f"Function '{node.name}' has nesting depth {nesting} (>= 5)",
                                "remediation": "Use early returns / guard clauses to flatten nested conditionals.",
                            })

                        for u_line in unreachable_lines:
                            quality_issues.append({
                                "type": "unreachable_code",
                                "severity": "LOW",
                                "confidence": 0.85,
                                "file": rel_path,
                                "line": u_line,
                                "description": f"Unreachable statement after return/raise inside '{node.name}'",
                                "remediation": "Remove dead statements or fix control-flow logic.",
                            })

    duplicates = [
        {"locations": locs, "count": len(locs)}
        for locs in block_hashes.values()
        if len(locs) > 1
    ]

    weight = {"HIGH": 15, "MEDIUM": 7, "LOW": 2}
    raw_score = sum(weight.get(f.get("severity", "LOW"), 2) for f in findings) + (len(duplicates) * 3)
    risk_score = min(100, raw_score)

    return {
        "security_risk_score": risk_score,
        "total_security_findings": len(findings),
        "total_quality_issues": len(quality_issues),
        "total_duplicate_blocks": len(duplicates),
        "security_findings": findings[:250],
        "quality_issues": quality_issues[:250],
        "duplicate_blocks": duplicates[:100],
    }
