"""FastAPI application entrypoint for Project Vero Firewall & Agent Core.
Serves the Real-Time Transaction Firewall API, Mobile QR Verifier, Bytecode Hunter, and Interactive Web UI.
Supports Dual-Mode Subsystem Switch: STANDARD_EVM vs. QUAI_NATIVE.
"""

import html
import os
import re
from typing import Optional
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager
from api_agents.adapters.factory import engine_name
from api_agents.db.connection import close_db, init_db
from api_agents.routes.firewall_api import get_adapter, router as firewall_router
from api_agents.routes.redteam_api import router as redteam_router
from api_agents.routes.vaccines_api import router as vaccines_router
from api_agents.routes.innovations_api import router as innovations_router
from api_agents.routes.chain_api import router as chain_router
from api_agents.routes.six_words_api import phone_router as six_words_phone_router, router as six_words_router
from api_agents.routes.snapshots_api import router as snapshots_router
from api_agents.routes.quai_tools_api import router as quai_tools_router
from api_agents.services.snapshot_scheduler import start_snapshot_worker, stop_snapshot_worker


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize Cloud PostgreSQL / fallback tables on startup
    try:
        await init_db()
        if os.getenv("ENABLE_SNAPSHOT_WORKER", "false").lower() in ("true", "1", "yes"):
            start_snapshot_worker()
    except Exception as e:
        import logging
        logging.getLogger("vero").error("DB initialization error on startup: %s", e)
    yield
    # Shutdown background worker and release connection pool
    await stop_snapshot_worker()
    await close_db()


app = FastAPI(
    title="Project Vero Firewall API",
    description="Deterministic Transaction Simulation, EIP-712 Intent Guard, Quai Subsystem & Forensic Verification",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # wildcard origins must never be combined with credentials
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(firewall_router)
app.include_router(redteam_router)
app.include_router(vaccines_router)
app.include_router(innovations_router)
app.include_router(chain_router)
app.include_router(six_words_router)
app.include_router(six_words_phone_router)
app.include_router(snapshots_router)
app.include_router(quai_tools_router)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
web_dir = os.path.join(REPO_ROOT, "web")              # legacy demo HUD
frontend_dir = os.path.join(REPO_ROOT, "frontend")      # new landing page + attack replay
cockpit_file = os.path.join(REPO_ROOT, "demo_cockpit.html")


@app.get("/hud")
@app.get("/vault")
@app.get("/dashboard")
async def legacy_hud():
    index_file = os.path.join(web_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Multisig Vault HUD not found."}


@app.get("/cockpit")
@app.get("/simulator")
async def cockpit_endpoint():
    if os.path.exists(cockpit_file):
        return FileResponse(cockpit_file)
    return FileResponse(os.path.join(web_dir, "index.html"))




class BytecodeScanRequest(BaseModel):
    bytecode: str = Field(..., pattern=r"^(0x)?([0-9a-fA-F]{2})*$", max_length=2 + 2 * 24576 * 2)


@app.post("/v1/scan-bytecode")
async def scan_bytecode_endpoint(req: BytecodeScanRequest):
    from api_agents.agents.bytecode_hunter import scan_bytecode, generate_security_advisory
    res = scan_bytecode(req.bytecode)
    advisory = generate_security_advisory(res)
    return {
        "is_vulnerable": res.is_vulnerable,
        "risk_level": advisory.risk_level,
        "instruction_count": res.instruction_count,
        "has_delegatecall": res.has_delegatecall,
        "has_selfdestruct": res.has_selfdestruct,
        "has_tx_origin": res.has_tx_origin,
        "findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "offset": hex(f.offset),
                "cwe": f.cwe,
                "description": f.description,
                "remediation": f.remediation,
            }
            for f in res.findings
        ],
        "remediation_plan": advisory.remediation_plan,
    }


@app.get("/health")
async def health_check(engine: Optional[str] = Query(None)):
    engine_mode = engine or os.getenv("VERO_ENGINE_MODE", "STANDARD_EVM")
    return {
        "status": "healthy",
        "service": "api-agents",
        "version": "0.1.0",
        "engine": engine_name(get_adapter()),
        "subsystem_mode": engine_mode.upper(),
        "quai_shard": "cyprus1" if "QUAI" in engine_mode.upper() else "N/A",
    }


WORDS_RE = re.compile(r"^[a-z]+(?:[-\s·]+[a-z]+){3}$")
TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

_VERIFY_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vero Phone Verifier</title>
  <script src="https://cdn.tailwindcss.com/3.4.17"></script>
  <style>body {{ font-family: system-ui, sans-serif; background-color: #07090E; color: #F1F5F9; }}</style>
</head>
<body class="min-h-screen flex flex-col items-center justify-center p-6">
  <div class="max-w-md w-full bg-[#111622] border border-blue-500/30 rounded-3xl p-6 space-y-5 text-center">
    <div class="w-12 h-12 mx-auto rounded-2xl bg-blue-600/20 text-blue-400 flex items-center justify-center text-2xl border border-blue-500/30">📱</div>
    <h1 class="text-xl font-extrabold text-white">Vero Phone Verifier</h1>
    {subsystem_badge}
    {body}
    <p class="text-[11px] text-slate-500">This page shows the words carried by the QR link. It does not
    re-simulate the transaction itself, so compare the words with your signing screen and reject on any mismatch.</p>
  </div>
</body>
</html>"""


@app.get("/verify", response_class=HTMLResponse)
async def mobile_verifier(words: Optional[str] = Query(None, max_length=120),
                          tx: Optional[str] = Query(None, max_length=66),
                          engine: Optional[str] = Query(None)):
    """Feature #09: phone-side display of the 4-word checksum carried by the QR link.

    Inputs come from a scanned link, so they are validated and HTML-escaped; invalid links are rejected.
    """
    is_quai = str(engine).lower() in ("quai", "quai_native") or os.getenv("VERO_ENGINE_MODE", "").lower() == "quai"
    subsystem_badge = ('<div class="inline-block px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">'
                       f'Subsystem: {"Quai Cyprus-1 Shard [0,0]" if is_quai else "Standard EVM"}</div>')

    if not words or not tx or not WORDS_RE.match(words.strip().lower()) or not TX_HASH_RE.match(tx):
        body = ('<p class="text-red-400 font-bold">Invalid or incomplete verification link.</p>'
                '<p class="text-xs text-slate-400">Expected four lowercase words and a 0x-prefixed 32-byte '
                'transaction hash. Do not sign.</p>')
        return HTMLResponse(_VERIFY_PAGE.format(body=body, subsystem_badge=subsystem_badge), status_code=400)
    display_words = " · ".join(re.split(r"[-\s·]+", words.strip().lower()))
    body = f"""<div class="p-4 rounded-2xl bg-black/60 border border-white/10 space-y-2">
      <span class="text-[11px] uppercase tracking-wider text-blue-400 font-bold">4-Word Checksum</span>
      <div class="text-2xl font-mono font-extrabold text-emerald-400 py-1">{html.escape(display_words)}</div>
    </div>
    <div class="text-left text-xs font-mono bg-white/5 p-3 rounded-xl">
      Safe Tx Hash: <span class="text-slate-200 break-all">{html.escape(tx)}</span>
    </div>"""
    return HTMLResponse(_VERIFY_PAGE.format(body=body, subsystem_badge=subsystem_badge))


# Mounted last so every API route above wins; "/" serves the landing page and its assets.
if os.path.isdir(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
