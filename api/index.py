"""Vercel Gateway entrypoint for Project Vero (Service: 'app').
Handles public traffic, serves UI assets, and forwards API calls to the
internal 'api-agents' service via Vercel service binding (API_AGENTS_URL).
Falls back to direct local import if API_AGENTS_URL is not set (for local dev).
"""

import os
import sys
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import httpx

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_AGENTS_DIR = os.path.join(ROOT_DIR, "api-agents")

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if API_AGENTS_DIR not in sys.path:
    sys.path.insert(0, API_AGENTS_DIR)

app = FastAPI(
    title="Project Vero Gateway",
    description="Vercel Multi-Service Gateway for Project Vero",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

frontend_dir = os.path.join(ROOT_DIR, "frontend")
web_dir = os.path.join(ROOT_DIR, "web")
cockpit_file = os.path.join(ROOT_DIR, "demo_cockpit.html")


@app.get("/hud")
@app.get("/vault")
@app.get("/dashboard")
async def hud_endpoint():
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


# Proxy handler to forward requests to the internal 'api-agents' service
API_AGENTS_URL = os.getenv("API_AGENTS_URL", "").rstrip("/")

if API_AGENTS_URL:
    # Running inside Vercel with service binding: proxy to internal api-agents
    client = httpx.AsyncClient(base_url=API_AGENTS_URL, timeout=60.0)

    @app.api_route("/health", methods=["GET"])
    @app.api_route("/verify", methods=["GET"])
    @app.api_route("/verify/{rest:path}", methods=["GET"])
    @app.api_route("/docs", methods=["GET"])
    @app.api_route("/openapi.json", methods=["GET"])
    @app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
    async def proxy_to_api_agents(request: Request, path: Optional[str] = None):
        target_path = request.url.path
        query = request.url.query
        url = f"{target_path}?{query}" if query else target_path

        headers = dict(request.headers)
        headers.pop("host", None)
        body = await request.body()

        rp_req = client.build_request(
            method=request.method,
            url=url,
            headers=headers,
            content=body
        )
        rp_resp = await client.send(rp_req, stream=True)
        return StreamingResponse(
            rp_resp.aiter_raw(),
            status_code=rp_resp.status_code,
            headers=dict(rp_resp.headers),
            background=rp_resp.aclose
        )
else:
    # In-process mode (one Vercel function, or local dev): serve the whole api_agents app.
    # FastAPI keeps included routers as objects, so copying routes one by one misses them; mount it instead.
    try:
        from api_agents.main import app as internal_app
    except Exception as e:
        internal_app = None

        @app.get("/health")
        async def fallback_health():
            return {"status": "gateway_only", "error": str(e)}

if not API_AGENTS_URL and internal_app is not None:
    # A mounted app's lifespan does not run on its own, so run it with the gateway's (DB init, workers)
    _gateway_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def _lifespan(gateway):
        async with internal_app.router.lifespan_context(internal_app):
            async with _gateway_lifespan(gateway):
                yield

    app.router.lifespan_context = _lifespan
    app.mount("/", internal_app)       # API routes, /verify pages and the frontend
elif os.path.isdir(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

handler = app
