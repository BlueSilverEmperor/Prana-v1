"""FastAPI router for 10-minute vault snapshots and state-delta anomaly persistence.
Integrates with Cloud PostgreSQL (Neon, Supabase, AWS RDS, GCP Cloud SQL) and local fallback.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api_agents.db.connection import get_db_session, get_db_status
from api_agents.db.repository import SnapshotRepository

router = APIRouter(prefix="/v1/snapshots", tags=["snapshots"])


class SnapshotRecordRequest(BaseModel):
    vault_address: str = Field(..., pattern=r"^0x[0-9a-fA-F]{40}$", description="Safe multisig vault address")
    chain_id: int = Field(1, description="EVM Chain ID (1=Mainnet, 80002=Amoy, etc.)")
    eth_balance_wei: str = Field("0", pattern=r"^[0-9]+$", description="Native balance in wei")
    token_balances: Dict[str, str] = Field(default_factory=dict, description="Mapping of token address to wei balance")
    master_copy: str = Field("0x" + "0" * 40, pattern=r"^0x[0-9a-fA-F]{40}$", description="MasterCopy implementation slot")
    owners_hash: str = Field("0x" + "0" * 64, pattern=r"^0x[0-9a-fA-F]{64}$", description="Keccak256 hash of owner list")
    threshold: int = Field(1, ge=1, description="Signature threshold")
    guard: str = Field("0x" + "0" * 40, pattern=r"^0x[0-9a-fA-F]{40}$", description="VeroGuard address")
    codehash: str = Field("0x" + "0" * 64, pattern=r"^0x[0-9a-fA-F]{64}$", description="Bytecode hash of vault contract")
    block_number: int = Field(0, ge=0, description="EVM block number at snapshot")
    block_hash: str = Field("0x" + "0" * 64, pattern=r"^0x[0-9a-fA-F]{64}$", description="EVM block hash")
    revert_strikes_in_window: int = Field(0, ge=0, description="Feature #37: 10-minute revert strikes")
    is_dead_mans_locked: bool = Field(False, description="Whether vault is locked by 3-strike dead-man switch")
    window_seconds: int = Field(600, ge=1, description="Rolling window duration in seconds (default 600s / 10 min)")


class VaultRegistrationRequest(BaseModel):
    vault_address: str = Field(..., pattern=r"^0x[0-9a-fA-F]{40}$")
    chain_id: int = Field(1)
    label: Optional[str] = Field(None, max_length=100)
    threshold: int = Field(1, ge=1)
    emergency_recovery_vault: Optional[str] = Field(None, pattern=r"^0x[0-9a-fA-F]{40}$")


@router.get("/db/status")
async def database_status(session: AsyncSession = Depends(get_db_session)):
    """Health check endpoint showing Cloud PostgreSQL connectivity and table metrics."""
    status = await get_db_status()
    repo = SnapshotRepository(session)
    stats = await repo.get_stats()
    return {
        "status": "healthy" if status["connected"] else "degraded",
        "database": status,
        "metrics": stats,
    }


@router.post("/vaults/register")
async def register_vault(
    req: VaultRegistrationRequest,
    session: AsyncSession = Depends(get_db_session),
):
    """Register a multisig vault for continuous 10-minute snapshot tracking."""
    repo = SnapshotRepository(session)
    vault = await repo.register_vault(
        vault_address=req.vault_address,
        chain_id=req.chain_id,
        label=req.label,
        threshold=req.threshold,
        emergency_recovery_vault=req.emergency_recovery_vault,
    )
    return {"message": "Vault registered successfully", "vault": vault.to_dict()}


@router.get("/vaults")
async def list_active_vaults(session: AsyncSession = Depends(get_db_session)):
    """List all registered vaults under active 10-minute snapshot monitoring."""
    repo = SnapshotRepository(session)
    vaults = await repo.get_active_vaults()
    return {"vaults": [v.to_dict() for v in vaults]}


@router.post("/record")
async def record_snapshot(
    req: SnapshotRecordRequest,
    session: AsyncSession = Depends(get_db_session),
):
    """Persist a 10-minute snapshot into the PostgreSQL database.

    Automatically calculates state deltas against the prior snapshot and flags
    unauthorized control slot mutations or anomalous drainage.
    """
    repo = SnapshotRepository(session)
    snap, delta = await repo.record_snapshot(
        vault_address=req.vault_address,
        chain_id=req.chain_id,
        eth_balance_wei=req.eth_balance_wei,
        token_balances=req.token_balances,
        master_copy=req.master_copy,
        owners_hash=req.owners_hash,
        threshold=req.threshold,
        guard=req.guard,
        codehash=req.codehash,
        block_number=req.block_number,
        block_hash=req.block_hash,
        revert_strikes_in_window=req.revert_strikes_in_window,
        is_dead_mans_locked=req.is_dead_mans_locked,
        window_seconds=req.window_seconds,
    )
    return {
        "status": "recorded",
        "snapshot": snap.to_dict(),
        "delta": delta.to_dict() if delta else None,
        "is_anomaly": delta.is_anomaly if delta else False,
    }


@router.get("/{vault_address}")
async def get_snapshot_history(
    vault_address: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db_session),
):
    """Fetch historical 10-minute snapshots for a vault."""
    repo = SnapshotRepository(session)
    records = await repo.get_snapshots(vault_address, limit=limit, offset=offset)
    return {
        "vault_address": vault_address.lower(),
        "count": len(records),
        "snapshots": [r.to_dict() for r in records],
    }


@router.get("/{vault_address}/latest")
async def get_latest_vault_snapshot(
    vault_address: str,
    session: AsyncSession = Depends(get_db_session),
):
    """Fetch the latest recorded snapshot and dead-man status for a vault."""
    repo = SnapshotRepository(session)
    latest = await repo.get_latest_snapshot(vault_address)
    if not latest:
        raise HTTPException(status_code=404, detail="No snapshot found for this vault address")
    return {"vault_address": vault_address.lower(), "latest_snapshot": latest.to_dict()}


@router.get("/{vault_address}/deltas")
async def get_snapshot_deltas(
    vault_address: str,
    anomalies_only: bool = Query(False, description="Filter for anomalies (control slot mutations, strikes)"),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_db_session),
):
    """Fetch 10-minute delta comparisons and anomaly alerts for a vault."""
    repo = SnapshotRepository(session)
    deltas = await repo.get_deltas(vault_address, anomalies_only=anomalies_only, limit=limit)
    return {
        "vault_address": vault_address.lower(),
        "anomalies_only": anomalies_only,
        "count": len(deltas),
        "deltas": [d.to_dict() for d in deltas],
    }
