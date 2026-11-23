import ast
import os
import re
from pathlib import Path
from typing import Any, Dict, List

IGNORE_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules",
    ".idea", ".vscode", "dist", "build", ".pytest_cache", ".mypy_cache"
}

LANGUAGE_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript (React)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (React)",
    ".java": "Java",
    ".cpp": "C++",
    ".c": "C",
    ".h": "C/C++ Header",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".html": "HTML",
    ".css": "CSS",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".xml": "XML",
    ".md": "Markdown",
    ".sh": "Shell",
}


class PythonASTVisitor(ast.NodeVisitor):
    """Deep AST extractor for Python files: classes, functions, calls, imports, entry points."""

    def __init__(self, rel_path: str):
        self.rel_path = rel_path
        self.imports: List[str] = []
        self.classes: List[Dict[str, Any]] = []
        self.functions: List[Dict[str, Any]] = []
        self.constants: List[str] = []
        self.entry_points: List[Dict[str, Any]] = []
        self.call_edges: List[Dict[str, str]] = []
        self._current_scope: str = f"{rel_path}::<module>"

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            full = f"{module}.{alias.name}" if module else alias.name
            self.imports.append(full)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._current_scope.endswith("::<module>"):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.isupper():
                    self.constants.append(target.id)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        # Detect if __name__ == "__main__":
        try:
            test_src = ast.unparse(node.test)
            if "__name__" in test_src and "__main__" in test_src:
                self.entry_points.append({
                    "type": "main_block",
                    "file": self.rel_path,
                    "line": node.lineno,
                    "detail": test_src,
                })
        except Exception:
            pass
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        bases = []
        for base in node.bases:
            try:
                bases.append(ast.unparse(base))
            except Exception:
                bases.append("UnknownBase")

        methods = [
            item.name for item in node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self.classes.append({
            "name": node.name,
            "file": self.rel_path,
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "bases": bases,
            "methods": methods,
            "docstring": (ast.get_docstring(node) or "")[:240],
        })

        prev_scope = self._current_scope
        self._current_scope = f"{self.rel_path}::{node.name}"
        self.generic_visit(node)
        self._current_scope = prev_scope

    def _handle_function(self, node: ast.AST, is_async: bool) -> None:
        args = [arg.arg for arg in node.args.args]
        decorators = []
        for dec in node.decorator_list:
            try:
                decorators.append(ast.unparse(dec))
            except Exception:
                pass

        func_info = {
            "name": node.name,
            "qualified_name": f"{self._current_scope}.{node.name}",
            "file": self.rel_path,
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "is_async": is_async,
            "args": args,
            "decorators": decorators,
            "docstring": (ast.get_docstring(node) or "")[:240],
        }
        self.functions.append(func_info)

        # Entry point heuristic (CLI commands, routes, main functions)
        if node.name in {"main", "cli", "run", "execute"} or any(
            k in d.lower() for d in decorators for k in ("route", "command", "app.", "task")
        ):
            self.entry_points.append({
                "type": "entrypoint_function",
                "file": self.rel_path,
                "line": node.lineno,
                "detail": f"{node.name}({', '.join(args)})",
            })

        prev_scope = self._current_scope
        self._current_scope = f"{self._current_scope}.{node.name}"
        self.generic_visit(node)
        self._current_scope = prev_scope

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle_function(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_function(node, is_async=True)

    def visit_Call(self, node: ast.Call) -> None:
        callee = None
        if isinstance(node.func, ast.Name):
            callee = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callee = node.func.attr
        if callee:
            self.call_edges.append({
                "caller": self._current_scope,
                "callee": callee,
                "line": node.lineno,
            })
        self.generic_visit(node)


def _analyze_generic_file(rel_path: str, content: str, language: str) -> Dict[str, Any]:
    """Fallback structural extraction for non-Python languages."""
    classes = re.findall(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)", content)
    functions = re.findall(
        r"\b(?:function|def|func|fn)\s+([A-Za-z_][A-Za-z0-9_]*)", content
    )
    imports = re.findall(
        r"(?:import\s+.*?from\s+['\"](.+?)['\"]|#include\s+[<\"](.+?)[>\"]|require\(['\"](.+?)['\"]\))",
        content,
    )
    flat_imports = [next(x for x in tup if x) for tup in imports if any(tup)]
    return {
        "language": language,
        "imports": sorted(set(flat_imports)),
        "classes": [{"name": c, "file": rel_path, "line": 1, "bases": [], "methods": [], "docstring": ""} for c in classes],
        "functions": [{"name": f, "qualified_name": f"{rel_path}::{f}", "file": rel_path, "line": 1, "is_async": False, "args": [], "decorators": [], "docstring": ""} for f in functions],
        "constants": [],
        "entry_points": [],
        "call_edges": [],
    }


def analyze_repository_structure(root_path: str) -> Dict[str, Any]:
    """Walks a codebase directory and builds a complete structural, dependency & flow map."""
    root = Path(root_path).resolve()
    files_summary: List[Dict[str, Any]] = []
    language_counts: Dict[str, int] = {}
    all_classes: List[Dict[str, Any]] = []
    all_functions: List[Dict[str, Any]] = []
    all_entry_points: List[Dict[str, Any]] = []
    dependency_graph: Dict[str, List[str]] = {}
    inheritance_graph: List[Dict[str, Any]] = []
    call_graph: List[Dict[str, str]] = []
    total_lines = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fname in filenames:
            full_path = Path(dirpath) / fname
            rel_path = full_path.relative_to(root).as_posix()
            ext = full_path.suffix.lower()
            lang = LANGUAGE_MAP.get(ext, "Other")
            language_counts[lang] = language_counts.get(lang, 0) + 1

            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            line_count = len(content.splitlines())
            total_lines += line_count

            file_record: Dict[str, Any] = {
                "path": rel_path,
                "language": lang,
                "lines": line_count,
                "size_bytes": full_path.stat().st_size,
            }

            if ext == ".py":
                try:
                    tree = ast.parse(content, filename=rel_path)
                    visitor = PythonASTVisitor(rel_path)
                    visitor.visit(tree)

                    dependency_graph[rel_path] = sorted(set(visitor.imports))
                    all_classes.extend(visitor.classes)
                    all_functions.extend(visitor.functions)
                    all_entry_points.extend(visitor.entry_points)
                    call_graph.extend(visitor.call_edges[:150])  # cap per file for compactness

                    for cls in visitor.classes:
                        if cls["bases"]:
                            inheritance_graph.append({
                                "class": cls["name"],
                                "file": rel_path,
                                "inherits_from": cls["bases"],
                            })

                    file_record.update({
                        "imports": sorted(set(visitor.imports)),
                        "class_count": len(visitor.classes),
                        "function_count": len(visitor.functions),
                        "constants": visitor.constants,
                    })
                except SyntaxError as exc:
                    file_record["parse_error"] = f"SyntaxError at line {exc.lineno}: {exc.msg}"
            elif lang != "Other":
                generic = _analyze_generic_file(rel_path, content, lang)
                if generic["imports"]:
                    dependency_graph[rel_path] = generic["imports"]
                all_classes.extend(generic["classes"])
                all_functions.extend(generic["functions"])

            files_summary.append(file_record)

    return {
        "root_path": str(root),
        "metrics": {
            "total_files": len(files_summary),
            "total_lines": total_lines,
            "total_classes": len(all_classes),
            "total_functions": len(all_functions),
            "total_entry_points": len(all_entry_points),
            "languages": dict(sorted(language_counts.items(), key=lambda x: x[1], reverse=True)),
        },
        "files": files_summary,
        "classes": all_classes,
        "functions": all_functions,
        "entry_points": all_entry_points,
        "dependency_graph": dependency_graph,
        "inheritance_graph": inheritance_graph,
        "call_graph": call_graph[:1000],
    }
