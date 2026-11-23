# AI-Powered Code Intelligence & Security Analysis System

Modular Python CLI and RAG-backed intelligence engine for analyzing source codebases, dependency/call graphs, CWE/OWASP security risks, code quality smells, and application packages (.apk, .aab, .appx, .zip).

## Modules
- src/structure_analyzer.py: AST + multi-language structural parser, inheritance & call graph builder, and entry-point detector.
- src/security_analyzer.py: CWE/OWASP vulnerability scanner, secret/token pattern detector, complexity/nesting analyzer, unreachable code detector, and duplicate block finder.
- src/package_inspector.py: Safe archive/package inspector for .apk, .aab, .appx, .zip, .jar, and .whl files.
- src/rag_engine.py: FAISS + Hugging Face embeddings + Groq LLM RAG engine for grounded codebase Q&A.
- src/main.py: CLI orchestrator generating reports/analysis_report.json and reports/intelligence_report.md, plus --ask and --chat modes.
