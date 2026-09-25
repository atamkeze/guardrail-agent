"""FastAPI Local Web Dashboard for GuardRail-Agent Autonomous Pentest Suite."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel

from guardrail.agent.models import PentestReport
from guardrail.agent.pentest import AutonomousPentestAgent

app = FastAPI(title="GuardRail-Agent Pentest Dashboard", version="2.0.0")

# In-memory scan cache
SCANS: Dict[str, Dict] = {}
EVENT_QUEUES: Dict[str, asyncio.Queue] = {}


class ScanRequest(BaseModel):
    target: str
    email: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    return DASHBOARD_HTML


@app.post("/api/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())[:8]
    queue = asyncio.Queue()
    EVENT_QUEUES[scan_id] = queue

    SCANS[scan_id] = {
        "id": scan_id,
        "target": req.target,
        "email": req.email,
        "status": "QUEUED",
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "report": None,
    }

    background_tasks.add_task(run_scan_task, scan_id, req.target, req.email)
    return {"scan_id": scan_id, "status": "QUEUED"}


async def run_scan_task(scan_id: str, target: str, email: Optional[str]):
    queue = EVENT_QUEUES.get(scan_id)
    agent = AutonomousPentestAgent()

    def callback(stage: str, msg: str):
        if queue:
            asyncio.run_coroutine_threadsafe(
                queue.put({"stage": stage, "message": msg}),
                asyncio.get_event_loop()
            )

    try:
        if queue:
            await queue.put({"stage": "init", "message": f"Initializing autonomous agent for target: {target}"})

        SCANS[scan_id]["status"] = "RUNNING"
        report = await agent.run_pentest(
            target_path_or_url=target,
            email_recipient=email,
            progress_callback=callback,
        )

        SCANS[scan_id]["status"] = "COMPLETED"
        SCANS[scan_id]["report"] = report

        # Send completion event with serialized report data
        if queue:
            report_data = {
                "repo_name": report.repo_name,
                "overall_risk_score": report.overall_risk_score,
                "executive_summary": report.executive_summary,
                "reasoning": report.execution_plan.reasoning_narrative if report.execution_plan else "",
                "total_findings": report.total_findings,
                "remediations": report.remediation_recommendations,
                "pdf_url": f"/api/reports/{scan_id}/download",
                "findings": [
                    {
                        "severity": f.severity.value,
                        "rule_id": f.rule_id,
                        "analyzer": f.analyzer,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "message": f.message,
                        "snippet": f.snippet,
                    }
                    for f in report.findings
                ],
            }
            await queue.put({"stage": "done", "message": "Audit completed successfully.", "data": report_data})

    except Exception as exc:
        SCANS[scan_id]["status"] = "FAILED"
        if queue:
            await queue.put({"stage": "error", "message": str(exc)})


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan(scan_id: str):
    if scan_id not in EVENT_QUEUES:
        raise HTTPException(status_code=404, detail="Scan stream not found")

    async def event_generator():
        queue = EVENT_QUEUES[scan_id]
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=45.0)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("stage") in ("done", "error"):
                    break
            except asyncio.TimeoutError:
                yield f": keepalive\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/reports/{scan_id}/download")
async def download_report(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan or not scan.get("report"):
        raise HTTPException(status_code=404, detail="Report not found")
    report: PentestReport = scan["report"]
    if not report.pdf_report_path or not Path(report.pdf_report_path).is_file():
        raise HTTPException(status_code=404, detail="PDF report file not found on disk")
    return FileResponse(
        report.pdf_report_path,
        media_type="application/pdf",
        filename=Path(report.pdf_report_path).name,
    )


@app.get("/api/history")
async def get_history():
    history = []
    for sid, s in SCANS.items():
        rep = s.get("report")
        history.append({
            "scan_id": sid,
            "target": s.get("target"),
            "status": s.get("status"),
            "started_at": s.get("started_at"),
            "risk_score": rep.overall_risk_score if rep else "N/A",
            "findings_count": rep.total_findings if rep else 0,
            "download_url": f"/api/reports/{sid}/download" if rep else None,
        })
    return {"history": history}


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GuardRail-Agent | Autonomous Pentest Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0a0e17;
            --card-bg: #111827;
            --accent-green: #00ff88;
            --accent-blue: #00d2ff;
            --accent-purple: #a855f7;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }
        body {
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
        }
        .navbar {
            background: rgba(17, 24, 39, 0.8);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .card-custom {
            background-color: var(--card-bg);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
        }
        .terminal-box {
            background: #000;
            border: 1px solid #1f2937;
            border-radius: 8px;
            font-family: 'Fira Code', monospace;
            font-size: 0.88rem;
            color: #10b981;
            padding: 1rem;
            height: 240px;
            overflow-y: auto;
        }
        .badge-critical { background: #dc2626; color: #fff; }
        .badge-high { background: #ea580c; color: #fff; }
        .badge-medium { background: #d97706; color: #fff; }
        .badge-low { background: #2563eb; color: #fff; }
        .badge-info { background: #059669; color: #fff; }
        .btn-launch {
            background: linear-gradient(135deg, #00ff88, #00b866);
            color: #000;
            font-weight: 700;
            border: none;
            transition: all 0.2s ease;
        }
        .btn-launch:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0, 255, 136, 0.35);
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark py-3">
        <div class="container-fluid px-4">
            <span class="navbar-brand fw-bold fs-4">
                <i class="bi bi-shield-lock-fill text-success me-2"></i>GuardRail<span style="color:var(--accent-green)">-Agent</span>
                <span class="badge bg-purple ms-2" style="background:#a855f7; font-size:0.65rem;">v2.0 AUTONOMOUS PENTEST GATE</span>
            </span>
            <div class="d-flex align-items-center gap-3">
                <a href="https://github.com/atamkeze/guardrail-agent" target="_blank" class="btn btn-outline-light btn-sm">
                    <i class="bi bi-github me-1"></i> GitHub
                </a>
            </div>
        </div>
    </nav>

    <div class="container-fluid px-4 py-4">
        <div class="row g-4">
            <!-- Left Column: Scan Submission & Live Console -->
            <div class="col-lg-5">
                <div class="card card-custom p-4 mb-4">
                    <h5 class="fw-bold mb-3"><i class="bi bi-crosshair text-danger me-2"></i>Target Codebase</h5>
                    <p class="text-muted small">Enter a local directory path or a public GitHub repository URL.</p>
                    
                    <form id="scanForm">
                        <div class="mb-3">
                            <label class="form-label small text-muted">Target Path or Repo URL</label>
                            <input type="text" id="targetInput" class="form-control bg-dark text-white border-secondary" placeholder="e.g. https://github.com/atamkeze/rsa-shop or ." required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label small text-muted">Recipient Email (Optional Report Delivery)</label>
                            <input type="email" id="emailInput" class="form-control bg-dark text-white border-secondary" placeholder="analyst@enterprise.com">
                        </div>
                        <button type="submit" id="btnScan" class="btn btn-launch w-100 py-2">
                            <i class="bi bi-lightning-charge-fill me-1"></i> Launch Autonomous Pentest
                        </button>
                    </form>
                </div>

                <!-- Live Stream Console -->
                <div class="card card-custom p-4">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <h6 class="fw-bold mb-0"><i class="bi bi-terminal-fill text-success me-2"></i>Agent Thought & Execution Stream</h6>
                        <span id="scanStatusBadge" class="badge bg-secondary">IDLE</span>
                    </div>
                    <div id="terminalStream" class="terminal-box">
                        <div class="text-muted">> Waiting for scan initialization...</div>
                    </div>
                </div>
            </div>

            <!-- Right Column: Results & Security Findings -->
            <div class="col-lg-7">
                <!-- Metrics Bar -->
                <div class="row g-3 mb-4">
                    <div class="col-md-4">
                        <div class="card card-custom p-3 text-center">
                            <div class="text-muted small">OVERALL RISK RATING</div>
                            <h3 id="riskScoreDisplay" class="fw-bold my-1 text-secondary">-</h3>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card card-custom p-3 text-center">
                            <div class="text-muted small">TOTAL FINDINGS</div>
                            <h3 id="findingsCountDisplay" class="fw-bold my-1 text-white">0</h3>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card card-custom p-3 text-center">
                            <div class="text-muted small">REPORT DELIVERABLE</div>
                            <div class="mt-1">
                                <a id="btnDownloadPdf" href="#" class="btn btn-sm btn-outline-info disabled">
                                    <i class="bi bi-file-earmark-pdf me-1"></i> Download PDF
                                </a>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Agent Reasoning & Executive Summary -->
                <div class="card card-custom p-4 mb-4">
                    <h5 class="fw-bold mb-2"><i class="bi bi-cpu text-info me-2"></i>Agent Reasoning & Threat Model</h5>
                    <div id="reasoningText" class="p-3 bg-black rounded small text-muted font-monospace mb-3">
                        Run a scan to observe the agent profile the codebase and prioritize attack modules.
                    </div>
                    <h6 class="fw-bold mb-1"><i class="bi bi-file-text text-warning me-2"></i>Executive Summary</h6>
                    <p id="summaryText" class="small text-muted mb-0">No active audit completed.</p>
                </div>

                <!-- Findings Table -->
                <div class="card card-custom p-4">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <h5 class="fw-bold mb-0"><i class="bi bi-shield-exclamation text-danger me-2"></i>Security Findings</h5>
                        <input type="text" id="filterInput" class="form-control form-control-sm bg-dark text-white border-secondary w-50" placeholder="Filter by rule, file, or keyword...">
                    </div>
                    <div class="table-responsive" style="max-height: 400px; overflow-y:auto;">
                        <table class="table table-dark table-hover table-sm small align-middle">
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Rule ID</th>
                                    <th>Location</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody id="findingsTableBody">
                                <tr><td colspan="4" class="text-center text-muted py-4">No findings to display.</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const scanForm = document.getElementById('scanForm');
        const targetInput = document.getElementById('targetInput');
        const emailInput = document.getElementById('emailInput');
        const btnScan = document.getElementById('btnScan');
        const terminalStream = document.getElementById('terminalStream');
        const scanStatusBadge = document.getElementById('scanStatusBadge');
        const riskScoreDisplay = document.getElementById('riskScoreDisplay');
        const findingsCountDisplay = document.getElementById('findingsCountDisplay');
        const btnDownloadPdf = document.getElementById('btnDownloadPdf');
        const reasoningText = document.getElementById('reasoningText');
        const summaryText = document.getElementById('summaryText');
        const findingsTableBody = document.getElementById('findingsTableBody');
        const filterInput = document.getElementById('filterInput');

        let currentFindings = [];

        function appendLog(msg) {
            const time = new Date().toLocaleTimeString();
            terminalStream.innerHTML += `<div><span style="color:#6b7280;">[${time}]</span> ${msg}</div>`;
            terminalStream.scrollTop = terminalStream.scrollHeight;
        }

        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            btnScan.disabled = true;
            terminalStream.innerHTML = '';
            scanStatusBadge.textContent = 'RUNNING';
            scanStatusBadge.className = 'badge bg-warning text-dark';
            appendLog(`> Dispatching autonomous pentest request for: ${targetInput.value}`);

            try {
                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: targetInput.value, email: emailInput.value || null })
                });
                const data = await res.json();
                connectSSE(data.scan_id);
            } catch (err) {
                appendLog(`<span style="color:#ef4444;">Error launching scan: ${err}</span>`);
                btnScan.disabled = false;
            }
        });

        function connectSSE(scanId) {
            const eventSource = new EventSource(`/api/scan/${scanId}/stream`);

            eventSource.onmessage = (event) => {
                const data = JSON.parse(event.data);
                if (data.message) {
                    appendLog(data.message);
                }

                if (data.stage === 'done') {
                    eventSource.close();
                    btnScan.disabled = false;
                    scanStatusBadge.textContent = 'COMPLETED';
                    scanStatusBadge.className = 'badge bg-success';
                    renderResults(data.data);
                } else if (data.stage === 'error') {
                    eventSource.close();
                    btnScan.disabled = false;
                    scanStatusBadge.textContent = 'FAILED';
                    scanStatusBadge.className = 'badge bg-danger';
                }
            };

            eventSource.onerror = () => {
                eventSource.close();
                btnScan.disabled = false;
            };
        }

        function renderResults(data) {
            riskScoreDisplay.textContent = data.overall_risk_score;
            riskScoreDisplay.className = 'fw-bold my-1 ' + (
                data.overall_risk_score === 'CRITICAL' ? 'text-danger' :
                data.overall_risk_score === 'HIGH' ? 'text-warning' :
                data.overall_risk_score === 'MEDIUM' ? 'text-warning' : 'text-info'
            );

            findingsCountDisplay.textContent = data.total_findings;
            reasoningText.textContent = data.reasoning;
            summaryText.textContent = data.executive_summary;

            btnDownloadPdf.href = data.pdf_url;
            btnDownloadPdf.classList.remove('disabled');

            currentFindings = data.findings;
            renderFindingsTable(currentFindings);
        }

        function renderFindingsTable(findings) {
            if (!findings || findings.length === 0) {
                findingsTableBody.innerHTML = '<tr><td colspan="4" class="text-center text-success py-3"><i class="bi bi-check-circle me-1"></i> Clean bill of health! Zero vulnerabilities detected.</td></tr>';
                return;
            }

            findingsTableBody.innerHTML = findings.map(f => {
                const badgeClass = f.severity === 'error' ? 'badge-critical' : f.severity === 'warning' ? 'badge-medium' : 'badge-low';
                return `<tr>
                    <td><span class="badge ${badgeClass}">${f.severity.toUpperCase()}</span></td>
                    <td><strong>${f.rule_id}</strong><br><span class="text-muted small">${f.analyzer}</span></td>
                    <td><small>${f.file_path}:${f.line_number || 1}</small></td>
                    <td>${f.message}</td>
                </tr>`;
            }).join('');
        }

        filterInput.addEventListener('input', (e) => {
            const term = e.target.value.toLowerCase();
            const filtered = currentFindings.filter(f =>
                f.rule_id.toLowerCase().includes(term) ||
                f.file_path.toLowerCase().includes(term) ||
                f.message.toLowerCase().includes(term) ||
                f.severity.toLowerCase().includes(term)
            );
            renderFindingsTable(filtered);
        });
    </script>
</body>
</html>"""
