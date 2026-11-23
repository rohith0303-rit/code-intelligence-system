import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

from src.package_inspector import inspect_package
from src.rag_engine import ask_codebase_question, build_code_vectorstore
from src.security_analyzer import analyze_security_and_quality
from src.structure_analyzer import analyze_repository_structure

load_dotenv(override=True)

app = FastAPI(title="Code Intelligence")

STATE: Dict[str, Any] = {
    "target_path": "",
    "metrics": {},
    "security": {},
    "vectorstore": None,
}


class ScanRequest(BaseModel):
    target_path: str
    package_path: str = ""


class ChatRequest(BaseModel):
    message: str


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Code Intelligence</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #f6f7f9;
    color: #18181b;
    font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
    font-size: 14px;
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
    height: 100vh;
    display: flex;
    flex-direction: column;
  }

  .topbar {
    background: #ffffff;
    border-bottom: 1px solid #e4e4e7;
    padding: 13px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .topbar-title {
    font-size: 16px;
    font-weight: 600;
    letter-spacing: -0.015em;
    color: #111113;
  }
  .topbar-sub {
    font-size: 13px;
    color: #71717a;
  }

  .layout {
    flex: 1;
    display: grid;
    grid-template-columns: 320px 1fr;
    gap: 18px;
    padding: 18px 24px;
    max-width: 1400px;
    width: 100%;
    margin: 0 auto;
    min-height: 0;
  }

  .sidebar {
    background: #ffffff;
    border: 1px solid #e4e4e7;
    border-radius: 12px;
    padding: 18px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    overflow-y: auto;
  }
  .step-pill {
    display: inline-block;
    font-size: 11px;
    font-weight: 600;
    color: #2563eb;
    background: #eff6ff;
    padding: 3px 8px;
    border-radius: 6px;
    margin-bottom: 6px;
  }
  .sidebar h2 {
    font-size: 15px;
    font-weight: 600;
    letter-spacing: -0.01em;
    color: #111113;
  }
  .sidebar p {
    font-size: 13px;
    color: #52525b;
    margin-top: 4px;
  }

  .field-label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    color: #3f3f46;
    margin-bottom: 6px;
  }
  .text-input {
    width: 100%;
    border: 1px solid #d4d4d8;
    border-radius: 8px;
    padding: 9px 11px;
    font-size: 13px;
    color: #18181b;
    background: #ffffff;
    outline: none;
  }
  .text-input:focus { border-color: #2563eb; }

  .scan-btn {
    width: 100%;
    background: #2563eb;
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
  }
  .scan-btn:hover { background: #1d4ed8; }
  .scan-btn:disabled { background: #93c5fd; cursor: not-allowed; }

  .status-note {
    font-size: 12.5px;
    color: #3f3f46;
    background: #f4f4f5;
    border: 1px solid #e4e4e7;
    border-radius: 8px;
    padding: 10px 12px;
  }

  .stats {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
  }
  .stat-card {
    background: #fafafa;
    border: 1px solid #e4e4e7;
    border-radius: 8px;
    padding: 11px 12px;
  }
  .stat-label { font-size: 11.5px; color: #71717a; }
  .stat-val { font-size: 18px; font-weight: 600; color: #18181b; margin-top: 2px; }

  .chat-panel {
    background: #ffffff;
    border: 1px solid #e4e4e7;
    border-radius: 12px;
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: hidden;
  }
  .chat-header {
    padding: 13px 20px;
    border-bottom: 1px solid #e4e4e7;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }
  .chat-title { font-size: 14.5px; font-weight: 600; color: #111113; }
  .chat-sub { font-size: 12px; color: #71717a; }
  .reset-btn {
    border: 1px solid #d4d4d8;
    background: #ffffff;
    color: #3f3f46;
    border-radius: 7px;
    padding: 6px 11px;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
  }
  .reset-btn:hover { background: #f4f4f5; }

  .messages {
    flex: 1;
    overflow-y: auto;
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .msg { display: flex; flex-direction: column; gap: 4px; }
  .msg.user { align-items: flex-end; }
  .msg.bot { align-items: flex-start; }
  .sender { font-size: 11.5px; font-weight: 500; color: #71717a; }

  .msg.user .bubble {
    background: #2563eb;
    color: #ffffff;
    padding: 10px 15px;
    border-radius: 12px;
    max-width: 76%;
    white-space: pre-wrap;
  }
  .msg.bot .bubble {
    background: #fafafa;
    color: #18181b;
    border: 1px solid #e4e4e7;
    padding: 14px 16px;
    border-radius: 12px;
    width: 100%;
    max-width: 95%;
  }

  .bubble p { margin-bottom: 8px; }
  .bubble p:last-child { margin-bottom: 0; }
  .bubble h3, .bubble h4 {
    font-size: 14px;
    font-weight: 600;
    color: #111113;
    margin: 12px 0 6px;
  }
  .bubble h3:first-child, .bubble h4:first-child { margin-top: 0; }
  .bubble ul, .bubble ol {
    margin: 4px 0 10px 20px;
    display: flex;
    flex-direction: column;
    gap: 5px;
  }
  .bubble code {
    background: #eceef2;
    color: #18181b;
    padding: 1.5px 5px;
    border-radius: 4px;
    font-family: Consolas, "Courier New", monospace;
    font-size: 12.5px;
  }
  .bubble pre {
    background: #18181b;
    color: #f4f4f5;
    padding: 11px 13px;
    border-radius: 8px;
    overflow-x: auto;
    margin: 8px 0;
    font-size: 12.5px;
  }
  .bubble pre code { background: transparent; color: inherit; padding: 0; }

  .table-box {
    width: 100%;
    overflow-x: auto;
    margin: 10px 0;
    border: 1px solid #d4d4d8;
    border-radius: 8px;
    background: #ffffff;
  }
  .table-box table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  .table-box th {
    background: #f4f4f5;
    color: #18181b;
    font-weight: 600;
    text-align: left;
    padding: 9px 12px;
    border-bottom: 1px solid #d4d4d8;
    border-right: 1px solid #e4e4e7;
  }
  .table-box th:last-child { border-right: none; }
  .table-box td {
    padding: 8px 12px;
    border-bottom: 1px solid #e4e4e7;
    border-right: 1px solid #e4e4e7;
    color: #27272a;
    vertical-align: top;
  }
  .table-box td:last-child { border-right: none; }
  .table-box tr:last-child td { border-bottom: none; }

  .quick-bar {
    padding: 0 20px 12px;
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .quick-btn {
    background: #f4f4f5;
    color: #27272a;
    border: 1px solid #e4e4e7;
    border-radius: 999px;
    padding: 6px 12px;
    font-size: 12px;
    cursor: pointer;
  }
  .quick-btn:hover { background: #e4e4e7; }

  .composer {
    border-top: 1px solid #e4e4e7;
    padding: 13px 20px;
    display: flex;
    gap: 10px;
    background: #ffffff;
  }
  .composer input {
    flex: 1;
    border: 1px solid #d4d4d8;
    border-radius: 8px;
    padding: 10px 13px;
    font-size: 13.5px;
    color: #18181b;
    outline: none;
  }
  .composer input:focus { border-color: #2563eb; }
  .send-btn {
    background: #18181b;
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 0 18px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
  }
  .send-btn:hover { background: #27272a; }
  .send-btn:disabled { opacity: 0.5; cursor: not-allowed; }

  @media (max-width: 860px) {
    .layout { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-title">Code Intelligence</div>
    <div class="topbar-sub">Scan a repo folder and chat with your code</div>
  </header>

  <div class="layout">
    <aside class="sidebar">
      <div>
        <span class="step-pill">Step 1</span>
        <h2>Scan Codebase</h2>
        <p>Pick a folder path and run a scan. Big repos like Scrapy take a bit longer on the first run.</p>
      </div>

      <div>
        <label class="field-label" for="targetInput">Folder path</label>
        <input id="targetInput" class="text-input" type="text" value="sample_targets/scrapy" />
      </div>

      <div>
        <label class="field-label" for="pkgInput">Package file (optional)</label>
        <input id="pkgInput" class="text-input" type="text" placeholder=".zip, .apk, .aab, .appx" />
      </div>

      <button id="scanBtn" class="scan-btn" type="button">1. Scan Codebase</button>

      <div id="statusNote" class="status-note">Waiting to scan. Click 1. Scan Codebase.</div>

      <div class="stats">
        <div class="stat-card"><div class="stat-label">Files</div><div id="mFiles" class="stat-val">-</div></div>
        <div class="stat-card"><div class="stat-label">Risk score</div><div id="mRisk" class="stat-val">-</div></div>
        <div class="stat-card"><div class="stat-label">Classes</div><div id="mClasses" class="stat-val">-</div></div>
        <div class="stat-card"><div class="stat-label">Security hits</div><div id="mHits" class="stat-val">-</div></div>
      </div>
    </aside>

    <section class="chat-panel">
      <div class="chat-header">
        <div>
          <div class="chat-title">Step 2 · Ask Questions</div>
          <div id="activeLabel" class="chat-sub">No codebase scanned yet</div>
        </div>
        <button id="resetBtn" class="reset-btn" type="button">Clear chat</button>
      </div>

      <div id="messages" class="messages">
        <div class="msg bot">
          <div class="sender">Code Intelligence</div>
          <div class="bubble"><p>Start by clicking <strong>1. Scan Codebase</strong> on the left. Once the scan finishes, ask anything about the project structure, files, or security checks.</p></div>
        </div>
      </div>

      <div class="quick-bar">
        <button class="quick-btn" type="button" data-q="Give a clear overview of how this project is structured.">Project overview</button>
        <button class="quick-btn" type="button" data-q="List the main security findings in a neat table.">Security table</button>
        <button class="quick-btn" type="button" data-q="What are the key classes and entry points?">Key classes &amp; entry points</button>
      </div>

      <form id="chatForm" class="composer">
        <input id="qInput" type="text" placeholder="Ask a question about the scanned code..." autocomplete="off" />
        <button id="sendBtn" class="send-btn" type="submit">Send</button>
      </form>
    </section>
  </div>

<script>
function esc(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function inlineFmt(s) {
  let out = esc(s);
  out = out.replace(/`([^`]+)`/g, "<code>$1</code>");
  out = out.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  out = out.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  return out;
}

function isSepRow(line) {
  const t = line.trim();
  return /^\|?[\s:-]+\|[\s|:-]*$/.test(t) && t.includes("-");
}

function parseRow(line) {
  let c = line.trim();
  if (c.startsWith("|")) c = c.slice(1);
  if (c.endsWith("|")) c = c.slice(0, -1);
  return c.split("|").map(x => x.trim());
}

function toHtml(md) {
  const lines = String(md || "").replace(/\r\n/g, "\n").split("\n");
  let out = "";
  let i = 0;
  let inUl = false;
  let inCode = false;
  let codeBuf = [];

  function endUl() {
    if (inUl) { out += "</ul>"; inUl = false; }
  }

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim().startsWith("```")) {
      endUl();
      if (!inCode) { inCode = true; codeBuf = []; }
      else { out += "<pre><code>" + esc(codeBuf.join("\n")) + "</code></pre>"; inCode = false; }
      i++;
      continue;
    }
    if (inCode) { codeBuf.push(line); i++; continue; }

    if (line.includes("|") && i + 1 < lines.length && isSepRow(lines[i + 1])) {
      endUl();
      const headers = parseRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes("|") && lines[i].trim() !== "") {
        rows.push(parseRow(lines[i]));
        i++;
      }
      let tbl = '<div class="table-box"><table><thead><tr>';
      for (const h of headers) tbl += "<th>" + inlineFmt(h) + "</th>";
      tbl += "</tr></thead><tbody>";
      for (const r of rows) {
        tbl += "<tr>";
        for (let c = 0; c < headers.length; c++) tbl += "<td>" + inlineFmt(r[c] ?? "") + "</td>";
        tbl += "</tr>";
      }
      tbl += "</tbody></table></div>";
      out += tbl;
      continue;
    }

    if (line.trim() === "") { endUl(); i++; continue; }

    const hm = line.match(/^(#{1,4})\s+(.*)$/);
    if (hm) {
      endUl();
      const lvl = Math.min(hm[1].length + 2, 4);
      out += "<h" + lvl + ">" + inlineFmt(hm[2]) + "</h" + lvl + ">";
      i++;
      continue;
    }

    const bm = line.match(/^\s*[-*+]\s+(.*)$/);
    if (bm) {
      if (!inUl) { out += "<ul>"; inUl = true; }
      out += "<li>" + inlineFmt(bm[1]) + "</li>";
      i++;
      continue;
    }

    endUl();
    out += "<p>" + inlineFmt(line) + "</p>";
    i++;
  }

  endUl();
  if (inCode) out += "<pre><code>" + esc(codeBuf.join("\n")) + "</code></pre>";
  return out || "<p>" + esc(md) + "</p>";
}

function addMessage(who, text, rich) {
  const list = document.getElementById("messages");
  const item = document.createElement("div");
  item.className = "msg " + who;
  const sender = document.createElement("div");
  sender.className = "sender";
  sender.textContent = who === "user" ? "You" : "Code Intelligence";
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  if (rich && who === "bot") bubble.innerHTML = toHtml(text);
  else bubble.textContent = text;
  item.appendChild(sender);
  item.appendChild(bubble);
  list.appendChild(item);
  list.scrollTop = list.scrollHeight;
  return bubble;
}

async function handleScan() {
  const btn = document.getElementById("scanBtn");
  const note = document.getElementById("statusNote");
  const target_path = document.getElementById("targetInput").value.trim();
  const package_path = document.getElementById("pkgInput").value.trim();

  if (!target_path) {
    note.textContent = "Enter a folder path first.";
    return;
  }

  btn.disabled = true;
  note.textContent = "Scanning files and building index...";
  const pending = addMessage("bot", "Scanning the folder now. Hang tight...", false);

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_path: target_path, package_path: package_path })
    });
    const rawText = await res.text();
    let data = {};
    try { data = JSON.parse(rawText); } catch (_) { data = { error: rawText || "Invalid server response" }; }

    if (!res.ok || data.error) {
      const msg = data.error || ("Request failed (" + res.status + ")");
      note.textContent = msg;
      pending.textContent = "Scan error: " + msg;
      return;
    }

    const m = data.metrics || {};
    const s = data.security || {};
    document.getElementById("mFiles").textContent = m.total_files ?? 0;
    document.getElementById("mRisk").textContent = (s.security_risk_score ?? 0) + "/100";
    document.getElementById("mClasses").textContent = m.total_classes ?? 0;
    document.getElementById("mHits").textContent = s.total_security_findings ?? 0;
    document.getElementById("activeLabel").textContent = "Scanned: " + data.target_path;
    note.textContent = "Scan complete. Ready for questions.";
    pending.innerHTML = toHtml(
      "Scanned **" + (m.total_files ?? 0) + "** files (**" + (m.total_classes ?? 0) + "** classes, **" + (s.total_security_findings ?? 0) + "** security hits). Ask a question below."
    );
  } catch (err) {
    note.textContent = "Scan failed: " + err.message;
    pending.textContent = "Scan failed: " + err.message;
  } finally {
    btn.disabled = false;
  }
}

async function handleChat(ev) {
  ev.preventDefault();
  const input = document.getElementById("qInput");
  const sendBtn = document.getElementById("sendBtn");
  const message = input.value.trim();
  if (!message) return;

  input.value = "";
  addMessage("user", message, false);
  const reply = addMessage("bot", "Checking the codebase...", false);
  sendBtn.disabled = true;

  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: message })
    });
    const data = await res.json();
    reply.innerHTML = toHtml(data.answer || data.error || "No response returned.");
    document.getElementById("messages").scrollTop = document.getElementById("messages").scrollHeight;
  } catch (err) {
    reply.textContent = "Error: " + err.message;
  } finally {
    sendBtn.disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", function () {
  const scanBtn = document.getElementById("scanBtn");
  const chatForm = document.getElementById("chatForm");
  const resetBtn = document.getElementById("resetBtn");

  if (scanBtn) scanBtn.addEventListener("click", handleScan);
  if (chatForm) chatForm.addEventListener("submit", handleChat);
  if (resetBtn) {
    resetBtn.addEventListener("click", function () {
      document.getElementById("messages").innerHTML =
        '<div class="msg bot"><div class="sender">Code Intelligence</div><div class="bubble"><p>Chat cleared. Your scanned folder is still ready to query.</p></div></div>';
    });
  }
  document.querySelectorAll(".quick-btn").forEach(function (b) {
    b.addEventListener("click", function () {
      const inp = document.getElementById("qInput");
      inp.value = b.getAttribute("data-q") || b.textContent;
      inp.focus();
    });
  });
});
</script>
</body>
</html>
"""


def _do_scan(target_path: str, package_path: str) -> Dict[str, Any]:
    target = Path(target_path).resolve()
    if not target.exists():
        return {"error": f"Folder not found: {target}"}

    structure_data = analyze_repository_structure(str(target))
    security_data = analyze_security_and_quality(str(target))
    package_data = inspect_package(package_path) if package_path else None

    out_dir = Path("reports").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    report_payload = {
        "target_path": str(target),
        "structure": structure_data,
        "security_and_quality": security_data,
        "package_inspection": package_data,
    }
    (out_dir / "analysis_report.json").write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

    metrics = structure_data.get("metrics", {})
    combined_for_rag = {
        **metrics,
        **security_data,
        "entry_points": structure_data.get("entry_points", []),
        "inheritance_graph": structure_data.get("inheritance_graph", []),
    }
    vectorstore = build_code_vectorstore(
        str(target),
        combined_for_rag,
        embedding_model=os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"),
    )

    STATE["target_path"] = str(target)
    STATE["metrics"] = metrics
    STATE["security"] = security_data
    STATE["vectorstore"] = vectorstore

    return {
        "target_path": str(target),
        "metrics": metrics,
        "security": security_data,
    }


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return HTML_PAGE


@app.post("/api/scan")
async def api_scan(req: ScanRequest) -> Dict[str, Any]:
    return await asyncio.to_thread(_do_scan, req.target_path, req.package_path)


@app.post("/api/chat")
async def api_chat(req: ChatRequest) -> Dict[str, Any]:
    vs = STATE.get("vectorstore")
    if vs is None:
        return {"answer": "Click **1. Scan Codebase** on the left first so I can index the folder."}

    load_dotenv(override=True)
    groq_key = os.getenv("GROQ_API_KEY", "")
    groq_model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    answer = await asyncio.to_thread(
        ask_codebase_question, vs, req.message, groq_api_key=groq_key, model_name=groq_model
    )
    return {"answer": answer}


def main() -> None:
    uvicorn.run("src.chat_ui:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
