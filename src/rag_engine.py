import os
from pathlib import Path
from typing import Any, Dict, List

from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_core.prompts import ChatPromptTemplate
from langchain_groq import ChatGroq
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter


IGNORE_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules",
    ".idea", ".vscode", "dist", "build", ".pytest_cache", ".mypy_cache"
}

CODE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".cpp", ".c",
    ".h", ".go", ".rs", ".json", ".yaml", ".yml", ".toml", ".md"
}


def build_code_vectorstore(
    root_path: str,
    analysis_summary: Dict[str, Any],
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2",
) -> FAISS:
    """Chunks source files + static analysis findings and indexes them into FAISS."""
    root = Path(root_path).resolve()
    splitter = RecursiveCharacterTextSplitter(chunk_size=1200, chunk_overlap=180)
    docs: List[Document] = []

    # 1. Index high-signal source files
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fname in filenames:
            full_path = Path(dirpath) / fname
            if full_path.suffix.lower() not in CODE_EXTS:
                continue
            if full_path.stat().st_size > 300_000:
                continue
            rel_path = full_path.relative_to(root).as_posix()
            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            chunks = splitter.split_text(content)
            for idx, chunk in enumerate(chunks[:12]):  # cap chunks per huge file for fast indexing
                docs.append(
                    Document(
                        page_content=f"File: {rel_path} (chunk {idx + 1})\n{chunk}",
                        metadata={"source": rel_path, "kind": "source_code"},
                    )
                )

    # 2. Index security findings & structural summary as grounded intelligence docs
    for item in analysis_summary.get("security_findings", [])[:80]:
        docs.append(
            Document(
                page_content=(
                    f"Security Finding [{item.get('severity')}] {item.get('cwe')} ({item.get('owasp')}) "
                    f"in {item.get('file')}:{item.get('line')}: {item.get('description')}. "
                    f"Evidence: {item.get('evidence')}. Remediation: {item.get('remediation')}"
                ),
                metadata={"source": item.get("file", "security"), "kind": "security_finding"},
            )
        )

    metrics = analysis_summary.get("metrics", {})
    docs.append(
        Document(
            page_content=(
                f"Repository Metrics: {metrics}. "
                f"Entry Points: {analysis_summary.get('entry_points', [])[:20]}. "
                f"Inheritance: {analysis_summary.get('inheritance_graph', [])[:20]}."
            ),
            metadata={"source": "architecture_summary", "kind": "architecture"},
        )
    )

    if not docs:
        docs.append(Document(page_content="Empty or unsupported repository.", metadata={"source": "none"}))

    embeddings = HuggingFaceEmbeddings(model_name=embedding_model)
    return FAISS.from_documents(docs, embeddings)


def ask_codebase_question(
    vectorstore: FAISS,
    question: str,
    groq_api_key: str | None = None,
    model_name: str = "openai/gpt-oss-120b",
) -> str:
    """Answers natural-language questions grounded in retrieved code & analysis chunks."""
    retriever = vectorstore.as_retriever(search_kwargs={"k": 5})
    retrieved_docs = retriever.invoke(question)
    context_text = "\n\n---\n\n".join(d.page_content for d in retrieved_docs)

    api_key = groq_api_key or os.getenv("GROQ_API_KEY", "").strip()
    if not api_key or api_key == "your_groq_api_key_here":
        sources = sorted({d.metadata.get("source", "unknown") for d in retrieved_docs})
        return (
            "[Offline RAG Context Mode - Set GROQ_API_KEY in .env for LLM synthesis]\n"
            f"Top matching sources for '{question}': {', '.join(sources)}\n\n"
            f"Relevant Excerpt:\n{context_text[:1200]}"
        )

    llm = ChatGroq(groq_api_key=api_key, model_name=model_name, temperature=0.1)
    prompt = ChatPromptTemplate.from_messages([
        (
            "system",
            "You are a principal software engineer and security auditor. Answer questions about the "
            "codebase using ONLY the provided context. Always cite exact file paths when available. "
            "If the context does not contain enough evidence, say so clearly instead of guessing.",
        ),
        ("human", "Question: {question}\n\nRetrieved Context:\n{context}"),
    ])
    chain = prompt | llm
    response = chain.invoke({"question": question, "context": context_text})
    return response.content
