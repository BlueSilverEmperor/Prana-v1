"""Test suite for Quai Network native tools and engine mode toggle.
Covers:
- Backend Engine Mode Toggle (Custom EVM vs. Quai Tools)
- Shard & Zone Routing Inspector (quais-style address prefix checking)
- Native ETX (External Transaction) Cross-Chain Bridge Validator
- Dual-Ledger ($QUAI Gas vs. $QI Energy-Dollar) Velocity Engine
- Pelagus Clear-Signing Formatter
- Prime Block Consensus Anchor
"""

import pytest
from httpx import ASGITransport, AsyncClient

from api_agents.main import app

CYPRUS1_ADDR = "0x0017a140Aa3E981100a9becA4E685f962f0cF6C9"
CYPRUS2_ADDR = "0x0217a140Aa3E981100a9becA4E685f962f0cF6C9"
PAXOS1_ADDR = "0x1017a140Aa3E981100a9becA4E685f962f0cF6C9"
INVALID_PREFIX_ADDR = "0xff17a140Aa3E981100a9becA4E685f962f0cF6C9"


@pytest.mark.asyncio
async def test_engine_mode_toggle():
    """Verify backend toggle switches between Custom EVM and Quai Tools."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Get initial mode
        res1 = await client.get("/v1/quai/engine/mode")
        assert res1.status_code == 200
        data1 = res1.json()
        assert "active_mode" in data1
        assert "is_quai_subsystem" in data1

        # 2. Toggle to Quai Tools mode
        res2 = await client.post("/v1/quai/engine/toggle", json={"mode": "quai"})
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["active_mode"] == "QUAI_NATIVE"
        assert data2["is_quai_subsystem"] is True

        # Check status after toggle
        res3 = await client.get("/v1/quai/engine/mode")
        assert res3.json()["is_quai_subsystem"] is True
        assert res3.json()["chain_id"] == 15000

        # 3. Toggle back to Custom EVM
        res4 = await client.post("/v1/quai/engine/toggle", json={"mode": "standard"})
        assert res4.status_code == 200
        assert res4.json()["active_mode"] == "STANDARD_EVM"
        assert res4.json()["is_quai_subsystem"] is False


@pytest.mark.asyncio
async def test_zone_routing_inspector():
    """Verify address byte prefix resolution and intra-zone vs cross-zone detection."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Intra-zone Cyprus-1 -> Cyprus-1: ALLOW
        r1 = await client.post(
            "/v1/quai/tools/zone-verify",
            json={
                "active_zone": "cyprus1",
                "caller_address": CYPRUS1_ADDR,
                "target_address": CYPRUS1_ADDR,
            },
        )
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["verdict"] == "ALLOW"
        assert d1["is_intra_zone"] is True
        assert d1["target"]["zone"] == "cyprus1"
        assert d1["target"]["prefix_byte"] == "0x00"

        # Cross-zone Cyprus-1 -> Paxos-1: WARN_ETX
        r2 = await client.post(
            "/v1/quai/tools/zone-verify",
            json={
                "active_zone": "cyprus1",
                "caller_address": CYPRUS1_ADDR,
                "target_address": PAXOS1_ADDR,
            },
        )
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["is_intra_zone"] is False
        assert d2["is_cross_zone_etx_required"] is True
        assert "SHARD MISMATCH" in d2["warning"]

        # Prefix spoofing with unmapped byte 0xFF: BLOCK
        r3 = await client.post(
            "/v1/quai/tools/zone-verify",
            json={
                "active_zone": "cyprus1",
                "target_address": INVALID_PREFIX_ADDR,
            },
        )
        assert r3.status_code == 200
        d3 = r3.json()
        assert d3["verdict"] == "BLOCK"
        assert d3["is_prefix_spoofed"] is True


@pytest.mark.asyncio
async def test_native_etx_validator():
    """Verify native ETX cross-chain consensus validation without third-party bridges."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Cross-zone ETX without policy authorization: BLOCK
        r1 = await client.post(
            "/v1/quai/tools/etx-validate",
            json={
                "source_address": CYPRUS1_ADDR,
                "destination_address": PAXOS1_ADDR,
                "value_quai_wei": "1000000000000000000",
                "allow_cross_zone": False,
            },
        )
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["decision"] == "BLOCK"
        assert d1["is_cross_zone"] is True
        assert "UNDECLARED_CROSS_ZONE_ETX" in d1["flags"]

        # Cross-zone ETX with policy authorization: ALLOW
        r2 = await client.post(
            "/v1/quai/tools/etx-validate",
            json={
                "source_address": CYPRUS1_ADDR,
                "destination_address": PAXOS1_ADDR,
                "value_quai_wei": "1000000000000000000",
                "allow_cross_zone": True,
            },
        )
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["decision"] == "ALLOW"
        assert d2["is_cross_zone"] is True
        assert "PoEM Native Merged-Miner" in d2["consensus_path"]


@pytest.mark.asyncio
async def test_dual_ledger_velocity_engine():
    """Verify asymmetric velocity enforcement between $QUAI gas and $QI energy dollar."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Compliant spend: ALLOW
        r1 = await client.post(
            "/v1/quai/tools/dual-ledger-check",
            json={
                "vault_address": CYPRUS1_ADDR,
                "quai_outflow_wei": "1000000000000000000",  # 1 QUAI
                "qi_outflow_units": "200000000",           # 200 QI
                "max_quai_cap_wei": "5000000000000000000", # 5 QUAI cap
                "daily_qi_velocity_cap": "1000000000",     # 1,000 QI daily cap
                "accumulated_daily_qi_spent": "300000000",  # 300 QI already spent
            },
        )
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["verdict"] == "ALLOW"
        assert d1["is_compliant"] is True
        assert d1["qi_energy_dollar"]["remaining_quota"] == 500000000  # 1000 - (300+200) = 500

        # 2. Exceeding $QI daily velocity limit: BLOCK
        r2 = await client.post(
            "/v1/quai/tools/dual-ledger-check",
            json={
                "vault_address": CYPRUS1_ADDR,
                "quai_outflow_wei": "1000000000000000000",
                "qi_outflow_units": "900000000",           # 900 QI (+ 300 = 1200 > 1000)
                "max_quai_cap_wei": "5000000000000000000",
                "daily_qi_velocity_cap": "1000000000",
                "accumulated_daily_qi_spent": "300000000",
            },
        )
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["verdict"] == "BLOCK"
        assert d2["is_compliant"] is False
        assert d2["qi_energy_dollar"]["exceeded"] is True
        assert any("QiVelocityCapExceeded" in r for r in d2["reasons"])

        # 3. Exceeding $QUAI gas cap: BLOCK
        r3 = await client.post(
            "/v1/quai/tools/dual-ledger-check",
            json={
                "vault_address": CYPRUS1_ADDR,
                "quai_outflow_wei": "8000000000000000000",  # 8 QUAI > 5 QUAI cap
                "qi_outflow_units": "50000000",
                "max_quai_cap_wei": "5000000000000000000",
                "daily_qi_velocity_cap": "1000000000",
                "accumulated_daily_qi_spent": "0",
            },
        )
        assert r3.status_code == 200
        d3 = r3.json()
        assert d3["verdict"] == "BLOCK"
        assert d3["quai_spend"]["exceeded"] is True
        assert any("QuaiSpendCapExceeded" in r for r in d3["reasons"])


@pytest.mark.asyncio
async def test_pelagus_formatter():
    """Verify Pelagus clear-signing payload and card formatting."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/v1/quai/tools/pelagus-format",
            json={
                "safe_address": CYPRUS1_ADDR,
                "to": CYPRUS1_ADDR,
                "value_quai_wei": "2500000000000000000",
                "data": "0x",
                "claimed_intent": "Pay Supplier on Cyprus-1",
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["wallet"] == "Pelagus Wallet"
        assert data["shard"] == "Cyprus-1"
        assert data["display_card"]["net_quai"] == "2.5000 $QUAI"
        assert len(data["four_word_checksum"].split(" · ")) == 4


@pytest.mark.asyncio
async def test_prime_consensus_anchor():
    """Verify Quai Prime Block consensus anchor endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/v1/quai/tools/prime-anchor")
        assert res.status_code == 200
        data = res.json()
        assert "PoEM" in data["consensus"]
        assert data["epoch_window_seconds"] == 600
        assert "Prime-3 Region-6 (Finalized)" in data["finality_depth"]
        assert data["snapshot_sync_status"] == "LOCKED_TO_PRIME_CHAIN"
