import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.package_inspector import inspect_package
from src.rag_engine import ask_codebase_question, build_code_vectorstore
from src.security_analyzer import analyze_security_and_quality
from src.structure_analyzer import analyze_repository_structure

console = Console()


def write_markdown_report(output_path: Path, report: Dict[str, Any]) -> None:
    """Generates a clean, evidence-backed Markdown report from analysis results."""
    metrics = report.get("structure", {}).get("metrics", {})
    sec = report.get("security_and_quality", {})
    pkg = report.get("package_inspection")

    lines = [
        "# AI Code Intelligence & Security Analysis Report",
        "",
        f"- **Target Path:** `{report.get('target_path')}`",
        f"- **Security Risk Score:** `{sec.get('security_risk_score', 0)} / 100`",
        f"- **Total Files:** `{metrics.get('total_files', 0)}` | **Total Lines:** `{metrics.get('total_lines', 0)}`",
        f"- **Classes:** `{metrics.get('total_classes', 0)}` | **Functions:** `{metrics.get('total_functions', 0)}` | **Entry Points:** `{metrics.get('total_entry_points', 0)}`",
        "",
        "## Language Breakdown",
    ]
    for lang, count in metrics.get("languages", {}).items():
        lines.append(f"- **{lang}:** {count} files")

    lines.extend(["", "## Key Entry Points"])
    for ep in report.get("structure", {}).get("entry_points", [])[:20]:
        lines.append(f"- `{ep.get('file')}:{ep.get('line')}` ({ep.get('type')}): `{ep.get('detail')}`")

    lines.extend([
        "",
        f"## Security & Vulnerability Findings ({sec.get('total_security_findings', 0)})",
    ])
    for f in sec.get("security_findings", [])[:25]:
        lines.append(
            f"- **[{f.get('severity')}] {f.get('cwe')} ({f.get('owasp')})** at `{f.get('file')}:{f.get('line')}` â€” "
            f"{f.get('description')} (Confidence: `{f.get('confidence')}`). "
            f"Evidence: `{f.get('evidence')}` | Fix: {f.get('remediation')}"
        )

    lines.extend([
        "",
        f"## Code Quality & Maintainability Issues ({sec.get('total_quality_issues', 0)})",
    ])
    for q in sec.get("quality_issues", [])[:20]:
        lines.append(
            f"- **[{q.get('severity')}] {q.get('type')}** at `{q.get('file')}:{q.get('line')}` â€” "
            f"{q.get('description')} | Fix: {q.get('remediation')}"
        )

    if pkg:
        lines.extend([
            "",
            "## Application Package / Binary Inspection",
            f"- **Package:** `{pkg.get('file')}` ({pkg.get('format')})",
            f"- **Entries:** `{pkg.get('total_entries', 0)}` | **Native Libs:** `{len(pkg.get('native_libraries', []))}`",
            f"- **High-Risk Permissions:** `{', '.join(pkg.get('high_risk_permissions_detected', [])) or 'None detected'}`",
        ])

    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    load_dotenv()
    parser = argparse.ArgumentParser(description="AI-Powered Code Intelligence & Security System")
    parser.add_argument("--target", required=True, help="Path to source code directory or repository")
    parser.add_argument("--package", default="", help="Optional path to APK, AAB, APPX, or archive file")
    parser.add_argument("--ask", default="", help="Single natural-language question to ask via RAG")
    parser.add_argument("--chat", action="store_true", help="Start interactive RAG Q&A session after analysis")
    parser.add_argument("--out-dir", default="reports", help="Directory to save JSON and Markdown reports")
    args = parser.parse_args()

    target_path = Path(args.target).resolve()
    if not target_path.exists():
        console.print(f"[red]Target path does not exist: {target_path}[/red]")
        return

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(Panel.fit(f"Scanning Target: [bold cyan]{target_path}[/bold cyan]", title="Code Intelligence System"))

    structure_data = analyze_repository_structure(str(target_path))
    security_data = analyze_security_and_quality(str(target_path))
    package_data = inspect_package(args.package) if args.package else None

    full_report: Dict[str, Any] = {
        "target_path": str(target_path),
        "structure": structure_data,
        "security_and_quality": security_data,
        "package_inspection": package_data,
    }

    json_path = out_dir / "analysis_report.json"
    md_path = out_dir / "intelligence_report.md"
    json_path.write_text(json.dumps(full_report, indent=2), encoding="utf-8")
    write_markdown_report(md_path, full_report)

    metrics = structure_data.get("metrics", {})
    summary_table = Table(title="Executive Summary")
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", style="green")
    summary_table.add_row("Total Files", str(metrics.get("total_files", 0)))
    summary_table.add_row("Total Lines", str(metrics.get("total_lines", 0)))
    summary_table.add_row("Classes / Functions", f"{metrics.get('total_classes', 0)} / {metrics.get('total_functions', 0)}")
    summary_table.add_row("Security Findings", str(security_data.get("total_security_findings", 0)))
    summary_table.add_row("Quality Issues", str(security_data.get("total_quality_issues", 0)))
    summary_table.add_row("Security Risk Score", f"{security_data.get('security_risk_score', 0)} / 100")
    console.print(summary_table)
    console.print(f"Reports saved to: [bold]{json_path}[/bold] and [bold]{md_path}[/bold]")

    if args.ask or args.chat:
        console.print("\n[yellow]Building FAISS vector index for interactive codebase intelligence...[/yellow]")
        combined_for_rag = {**metrics, **security_data, "entry_points": structure_data.get("entry_points", []), "inheritance_graph": structure_data.get("inheritance_graph", [])}
        vectorstore = build_code_vectorstore(
            str(target_path),
            combined_for_rag,
            embedding_model=os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"),
        )
        groq_key = os.getenv("GROQ_API_KEY", "")
        groq_model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

        if args.ask:
            answer = ask_codebase_question(vectorstore, args.ask, groq_api_key=groq_key, model_name=groq_model)
            console.print(Panel(answer, title=f"Answer: {args.ask}", border_style="cyan"))

        if args.chat:
            console.print("[bold green]Interactive mode started. Type 'exit' or 'quit' to stop.[/bold green]")
            while True:
                q = console.input("\n[bold cyan]Ask about codebase>[/bold cyan] ").strip()
                if not q:
                    continue
                if q.lower() in {"exit", "quit", "q"}:
                    break
                ans = ask_codebase_question(vectorstore, q, groq_api_key=groq_key, model_name=groq_model)
                console.print(Panel(ans, border_style="green"))


if __name__ == "__main__":
    main()
