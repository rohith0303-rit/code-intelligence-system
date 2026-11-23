# System Architecture Document

1. Ingestion Layer (src/main.py): Parses --target, --package, --ask, and --chat arguments and manages output reports.
2. Structural & Flow Engine (src/structure_analyzer.py): Extracts AST nodes, imports, call edges, inheritance, and entry points.
3. Security & Quality Engine (src/security_analyzer.py): Detects CWE/OWASP risks, secrets, long/deep functions, dead code, and duplicates with a 0-100 risk score.
4. Package Inspector (src/package_inspector.py): Inspects archive manifests, permissions, native libraries, and embedded URLs safely.
5. RAG & Reporting Layer (src/rag_engine.py, reports/): Indexes source chunks and findings into FAISS for grounded LLM answers and saves JSON + Markdown reports.
