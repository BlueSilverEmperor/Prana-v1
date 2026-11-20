"""
FastMCP Server for Project Vero (#42).
Exposes the tool `vero_simulate_and_verify` for agentic workflows (e.g. Claude, Antigravity, MCP clients).
"""

import asyncio
from typing import Any, Dict, Optional
from api_agents.adapters.mock_adapter import MockAdapter
from api_agents.models.schemas import SimulateRequest
from api_agents.utils.four_word_checksum import compute_four_word_checksum
from api_agents.utils.keccak import keccak256


class VeroMCPToolServer:
    def __init__(self, adapter: Optional[MockAdapter] = None):
        self.adapter = adapter or MockAdapter(artificial_latency_ms=0.0)

    async def vero_simulate_and_verify(
        self,
        chain_id: int,
        safe_address: str,
        to: str,
        value: str = "0",
        data: str = "0x",
        nonce: int = 0,
        intent_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        MCP Tool: Simulates transaction execution, evaluates 12 deterministic security rules,
        and generates human-readable warnings plus 4-word BIP-39 checksum.
        """
        req = SimulateRequest(
            chain_id=chain_id,
            safe_address=safe_address,
            to=to,
            value=value,
            data=data,
            nonce=nonce,
            intent_hash=intent_hash or ("0x" + "00" * 32),
        )

        # 1. Simulate state transition
        sim_res = await self.adapter.simulate_tx(req)

        # 2. Evaluate deterministic security rules
        eval_res = self.adapter.evaluate(sim_res, req)

        # 3. Compute 4-word checksum
        def safe_hex_to_bytes(s: str, pad_len: int = 20) -> bytes:
            clean = s[2:] if (s.startswith("0x") or s.startswith("0X")) else s
            try:
                b = bytes.fromhex(clean)
            except ValueError:
                b = s.encode("utf-8")
            if len(b) < pad_len:
                return b.rjust(pad_len, b"\x00")
            return b[-pad_len:]

        to_bytes = safe_hex_to_bytes(req.to, 20)
        data_clean = req.data[2:] if (req.data.startswith("0x") or req.data.startswith("0X")) else req.data
        try:
            data_bytes = bytes.fromhex(data_clean)
        except ValueError:
            data_bytes = req.data.encode("utf-8")

        raw_tx_bytes = (
            to_bytes
            + int(req.value).to_bytes(32, "big")
            + req.nonce.to_bytes(32, "big")
            + data_bytes
        )
        raw_tx_hash = "0x" + keccak256(raw_tx_bytes).hex()

        checksum = compute_four_word_checksum(
            chain_id=req.chain_id,
            safe_address=req.safe_address,
            nonce=req.nonce,
            raw_tx_hash=raw_tx_hash,
            intent_hash=req.intent_hash,
        )

        return {
            "decision": eval_res.decision.value,
            "risk_score": eval_res.risk_score,
            "flags": eval_res.flags,
            "four_word_checksum": checksum,
            "state_diffs": [diff.model_dump() for diff in sim_res.state_diffs],
            "warnings": eval_res.human_warnings,
        }


def create_mcp_server():
    server = VeroMCPToolServer()
    return server
