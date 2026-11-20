"""
FastAPI application entrypoint for Project Vero Firewall & Agent Core.
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
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

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "api-agents",
        "version": "0.1.0",
        "engine": engine_name(get_adapter()),
    }
