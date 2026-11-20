"""
FastAPI application entrypoint for Project Vero Firewall & Agent Core.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api_agents.routes.firewall_api import router as firewall_router

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


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "api-agents",
        "version": "0.1.0",
        "engine": "MockAdapter",
    }
