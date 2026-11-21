"""Comprehensive test suite for Cloud PostgreSQL 10-minute snapshot persistence and delta anomaly detection."""

import os
import pytest
from httpx import ASGITransport, AsyncClient

from api_agents.db.connection import (
    close_db,
    get_db_session,
    get_db_status,
    init_db,
    normalize_database_url,
)
from api_agents.db.repository import SnapshotRepository
from api_agents.main import app
from api_agents.services.snapshot_scheduler import capture_vault_snapshot_job

VAULT_A = "0x" + "a1" * 20
VAULT_B = "0x" + "b2" * 20
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"


@pytest.fixture(autouse=True)
async def setup_test_db():
    """Ensure database tables are freshly recreated before each test."""
    from api_agents.db.connection import get_engine
    from api_agents.db.models import Base
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    await close_db()


def test_cloud_postgres_url_normalization():
    """Verify Neon/Supabase/AWS RDS PostgreSQL URLs are converted with asyncpg & SSL."""
    # Neon / Render style postgres:// with sslmode=require
    raw = "postgres://user:pass@ep-cool-db.us-east-2.aws.neon.tech/neondb?sslmode=require"
    norm, args = normalize_database_url(raw)
    assert norm.startswith("postgresql+asyncpg://")
    assert "user:pass@ep-cool-db" in norm
    assert "ssl" in args

    # Standard postgresql:// style
    raw2 = "postgresql://postgres:secret@db.supabase.co:5432/postgres"
    norm2, args2 = normalize_database_url(raw2)
    assert norm2.startswith("postgresql+asyncpg://")


@pytest.mark.asyncio
async def test_db_status_and_health():
    """Verify get_db_status reports connectivity and database details."""
    status = await get_db_status()
    assert status["connected"] is True
    assert status["database_type"] in ("cloud_postgresql", "sqlite_fallback")
    assert "redacted_target" in status


@pytest.mark.asyncio
async def test_register_and_get_vaults():
    """Verify registering a vault in PostgreSQL and listing active vaults."""
    async for session in get_db_session():
        repo = SnapshotRepository(session)
        vault = await repo.register_vault(
            vault_address=VAULT_A,
            chain_id=1,
            label="Treasury Alpha",
            threshold=2,
            emergency_recovery_vault="0x" + "99" * 20,
        )
        assert vault.vault_address == VAULT_A.lower()
        assert vault.label == "Treasury Alpha"
        assert vault.threshold == 2

        active = await repo.get_active_vaults()
        addrs = [v.vault_address for v in active]
        assert VAULT_A.lower() in addrs
        break


@pytest.mark.asyncio
async def test_record_10_min_snapshot_and_delta():
    """Verify recording an initial 10-minute snapshot followed by a second snapshot computing deltas."""
    async for session in get_db_session():
        repo = SnapshotRepository(session)

        # 1. Initial baseline snapshot
        snap1, delta1 = await repo.record_snapshot(
            vault_address=VAULT_A,
            chain_id=1,
            eth_balance_wei="10000000000000000000",  # 10 ETH
            token_balances={USDT: "5000000000"},     # 5,000 USDT
            master_copy="0x" + "11" * 20,
            owners_hash="0x" + "22" * 32,
            threshold=2,
            guard="0x" + "33" * 20,
            codehash="0x" + "44" * 32,
            block_number=19000000,
        )
        assert snap1.id is not None
        assert delta1 is None  # No prior snapshot for delta

        # 2. Second snapshot 10 minutes later: 1 ETH transferred out, 500 USDT transferred out
        snap2, delta2 = await repo.record_snapshot(
            vault_address=VAULT_A,
            chain_id=1,
            eth_balance_wei="9000000000000000000",   # 9 ETH (-1 ETH)
            token_balances={USDT: "4500000000"},     # 4,500 USDT (-500 USDT)
            master_copy="0x" + "11" * 20,
            owners_hash="0x" + "22" * 32,
            threshold=2,
            guard="0x" + "33" * 20,
            codehash="0x" + "44" * 32,
            block_number=19000050,
            window_seconds=600,
        )
        assert snap2.id > snap1.id
        assert delta2 is not None
        assert delta2.eth_delta_wei == "-1000000000000000000"
        assert delta2.token_deltas[USDT.lower()] == "-500000000"
        assert delta2.control_slots_mutated is False
        assert delta2.is_anomaly is False
        break


@pytest.mark.asyncio
async def test_control_slot_mutation_detection():
    """Verify that any modification to masterCopy (WazirX exploit vector) is flagged as an anomaly."""
    async for session in get_db_session():
        repo = SnapshotRepository(session)

        # Baseline
        await repo.record_snapshot(
            vault_address=VAULT_B,
            chain_id=80002,
            eth_balance_wei="2000000000000000000",
            token_balances={},
            master_copy="0x" + "11" * 20,
            owners_hash="0x" + "22" * 32,
            threshold=3,
            guard="0x" + "33" * 20,
            codehash="0x" + "44" * 32,
        )

        # 10 minutes later: attacker secretly swapped master_copy (implementation logic)
        _, delta = await repo.record_snapshot(
            vault_address=VAULT_B,
            chain_id=80002,
            eth_balance_wei="2000000000000000000",
            token_balances={},
            master_copy="0x" + "ee" * 20,  # ATTACKER LOGIC SWAP
            owners_hash="0x" + "22" * 32,
            threshold=3,
            guard="0x" + "33" * 20,
            codehash="0x" + "44" * 32,
        )
        assert delta is not None
        assert delta.control_slots_mutated is True
        assert delta.is_anomaly is True
        assert "Control slots mutated" in delta.anomaly_reason
        break


@pytest.mark.asyncio
async def test_dead_mans_switch_strikes_detection():
    """Verify that 3 strikes within the 10-minute window trigger an anomaly flag."""
    async for session in get_db_session():
        repo = SnapshotRepository(session)

        # Baseline
        await repo.record_snapshot(
            vault_address="0x" + "c3" * 20,
            chain_id=1,
            eth_balance_wei="5000000000000000000",
            token_balances={},
            master_copy="0x" + "11" * 20,
            owners_hash="0x" + "22" * 32,
            threshold=1,
            guard="0x" + "33" * 20,
            codehash="0x" + "44" * 32,
            revert_strikes_in_window=0,
        )

        # 3 strikes within 10 minutes
        _, delta = await repo.record_snapshot(
            vault_address="0x" + "c3" * 20,
            chain_id=1,
            eth_balance_wei="5000000000000000000",
            token_balances={},
            master_copy="0x" + "11" * 20,
            owners_hash="0x" + "22" * 32,
            threshold=1,
            guard="0x" + "33" * 20,
            codehash="0x" + "44" * 32,
            revert_strikes_in_window=3,
            is_dead_mans_locked=True,
        )
        assert delta is not None
        assert delta.is_anomaly is True
        assert "DEAD_MANS_SWITCH" in delta.anomaly_reason
        break


@pytest.mark.asyncio
async def test_fastapi_snapshot_endpoints():
    """Test full HTTP REST API for snapshot persistence and queries."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. DB status check
        resp = await client.get("/v1/snapshots/db/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("healthy", "degraded")
        assert "database" in data
        assert "metrics" in data

        # 2. Vault Registration
        reg_resp = await client.post(
            "/v1/snapshots/vaults/register",
            json={
                "vault_address": VAULT_A,
                "chain_id": 1,
                "label": "Cold Storage Vault",
                "threshold": 3,
            },
        )
        assert reg_resp.status_code == 200
        assert reg_resp.json()["vault"]["vault_address"] == VAULT_A.lower()

        # 3. List active vaults
        list_resp = await client.get("/v1/snapshots/vaults")
        assert list_resp.status_code == 200
        assert len(list_resp.json()["vaults"]) >= 1

        # 4. Record a 10-minute snapshot via REST
        rec_resp = await client.post(
            "/v1/snapshots/record",
            json={
                "vault_address": VAULT_A,
                "chain_id": 1,
                "eth_balance_wei": "15000000000000000000",
                "token_balances": {USDT: "10000000000"},
                "master_copy": "0x" + "11" * 20,
                "owners_hash": "0x" + "22" * 32,
                "threshold": 3,
                "guard": "0x" + "33" * 20,
                "codehash": "0x" + "44" * 32,
                "block_number": 19001000,
                "revert_strikes_in_window": 0,
                "is_dead_mans_locked": False,
                "window_seconds": 600,
            },
        )
        assert rec_resp.status_code == 200
        assert rec_resp.json()["status"] == "recorded"

        # 5. Get snapshot history
        hist_resp = await client.get(f"/v1/snapshots/{VAULT_A}")
        assert hist_resp.status_code == 200
        assert hist_resp.json()["count"] >= 1

        # 6. Get latest snapshot
        latest_resp = await client.get(f"/v1/snapshots/{VAULT_A}/latest")
        assert latest_resp.status_code == 200
        assert latest_resp.json()["latest_snapshot"]["eth_balance_wei"] == "15000000000000000000"

        # 7. Get deltas
        deltas_resp = await client.get(f"/v1/snapshots/{VAULT_A}/deltas")
        assert deltas_resp.status_code == 200
        assert "deltas" in deltas_resp.json()


@pytest.mark.asyncio
async def test_background_snapshot_job_execution():
    """Verify that capture_vault_snapshot_job executes without crashing."""
    async for session in get_db_session():
        repo = SnapshotRepository(session)
        await repo.register_vault(vault_address="0x" + "77" * 20, chain_id=1, threshold=1)
        break

    count = await capture_vault_snapshot_job()
    assert count >= 1
