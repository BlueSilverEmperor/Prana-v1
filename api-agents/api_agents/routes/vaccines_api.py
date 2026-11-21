"""Read-only view of the collective vaccine registry (see api_agents/vaccination.py)."""

from fastapi import APIRouter

from api_agents.vaccination import REGISTRY

router = APIRouter(prefix="/v1/vaccines", tags=["vaccination"])


@router.get("")
async def list_vaccines() -> dict:
    return {"quorum": REGISTRY.quorum, "vaccines": REGISTRY.snapshot()}
