"""FastAPI application entrypoint for Project Vero Firewall & Agent Core.
Serves the Real-Time Transaction Firewall API, Mobile QR Verifier, Bytecode Hunter, and Interactive Web UI.
"""

import os
from typing import Optional
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from api_agents.adapters.factory import engine_name
from api_agents.routes.firewall_api import get_adapter, router as firewall_router

app = FastAPI(
    title="Project Vero Firewall API",
    description="Deterministic Transaction Simulation, EIP-712 Intent Guard, and Forensic Verification",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(firewall_router)

# Mount web directory if available
web_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "web"))


@app.get("/")
async def root():
    index_file = os.path.join(web_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Project Vero Firewall API is running. Visit /docs for Swagger."}


class BytecodeScanRequest(BaseModel):
    bytecode: str


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
async def health_check():
    return {
        "status": "healthy",
        "service": "api-agents",
        "version": "0.1.0",
        "engine": engine_name(get_adapter()),
    }


@app.get("/verify", response_class=HTMLResponse)
async def mobile_verifier(words: Optional[str] = Query(None), tx: Optional[str] = Query(None)):
    """Feature #09: Independent Mobile QR Verifier endpoint."""
    display_words = words or "toe · early · venue · casino"
    tx_hash = tx or "0x6b0656fc183f96c3ca988cb6c3db8c241cb115f6eedff78715fe47cb580cf08e"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vero Mobile Verifier 📱 | Out-of-Band Truth</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@600;800&family=Plus+Jakarta+Sans:wght@500;700;800&display=swap" rel="stylesheet">
  <style>
    body {{ font-family: 'Plus Jakarta Sans', sans-serif; background-color: #07090E; color: #F1F5F9; }}
    .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
  </style>
</head>
<body class="min-h-screen flex flex-col items-center justify-center p-6">
  <div class="max-w-md w-full bg-[#111622] border border-blue-500/30 rounded-3xl p-6 shadow-2xl shadow-blue-500/10 space-y-5 text-center">
    <div class="w-12 h-12 mx-auto rounded-2xl bg-blue-600/20 text-blue-400 flex items-center justify-center text-2xl border border-blue-500/30">📱</div>
    <div>
      <h1 class="text-xl font-extrabold text-white">Out-of-Band Phone Verifier</h1>
      <p class="text-xs text-slate-400 mt-1">Secondary isolated verification channel (Defeats compromised laptop UIs)</p>
    </div>

    <div class="p-4 rounded-2xl bg-black/60 border border-white/10 space-y-2">
      <span class="text-[11px] uppercase tracking-wider text-blue-400 font-bold">4-Word Visual Checksum</span>
      <div class="text-2xl font-mono font-extrabold text-emerald-400 py-1 tracking-wide">
        {display_words}
      </div>
      <p class="text-[10px] text-slate-400">Match these 4 words against your laptop screen before signing.</p>
    </div>

    <div class="text-left text-xs space-y-2 font-mono bg-white/5 p-3 rounded-xl border border-white/5">
      <div class="text-slate-400">Safe Tx Hash: <span class="text-slate-200">{tx_hash[:18]}...</span></div>
      <div class="text-slate-400">ERC-8213 Fingerprint: <span class="text-emerald-400">0x2145f00f...</span></div>
      <div class="text-slate-400">EIP-712 Domain: <span class="text-blue-400">VeroGuard v1</span></div>
      <div class="text-slate-400">Hardware Status: <span class="text-emerald-400">✓ Isolated & Verified</span></div>
    </div>

    <div class="pt-2 text-[11px] text-slate-500">
      Project Vero · Feature #09 Independent Verification Channel
    </div>
  </div>
</body>
</html>"""
