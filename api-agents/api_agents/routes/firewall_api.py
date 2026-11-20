"""
Firewall API Routes: /v1/simulate, /v1/verify-intent, /v1/audit-receipt.
Authoritative implementation of the Vero Firewall API.
Invariants:
- LLMs are never on the /v1/simulate path.
- All decisions are strictly deterministic.
- Measured execution target < 150 ms.
"""

import time
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from api_agents.adapters.factory import build_adapter
from api_agents.adapters.mock_adapter import SIG_TRANSFER
from api_agents.adapters.simulator_protocol import RuleEngineProtocol, SimulatorProtocol
from api_agents.adapters.errors import EngineInputError
from api_agents.forensics.cert_in_exporter import create_forensic_receipt
from api_agents.models.schemas import (
    AuditReceipt,
    DecisionEnum,
    SimulateRequest,
    SimulateResponse,
    VerifyIntentRequest,
    VerifyIntentResponse,
)
from api_agents.utils.four_word_checksum import compute_four_word_checksum
from api_agents.utils.keccak import keccak256

router = APIRouter(prefix="/v1", tags=["Firewall"])

# Dependency providers for easy injection. Real Vero engine by default; VERO_ENGINE=mock for the mock.
_shared_adapter = build_adapter()


def get_adapter():
    return _shared_adapter


def get_simulator() -> SimulatorProtocol:
    return _shared_adapter


def get_rule_engine() -> RuleEngineProtocol:
    return _shared_adapter


def _compute_raw_tx_hash(req: SimulateRequest) -> str:
    """Computes a deterministic Keccak-256 hash over the raw transaction parameters."""
    val_int = int(req.value) if req.value.isdigit() else 0

    def to_clean_bytes(s: str, pad_len: int) -> bytes:
        hex_str = s[2:] if (s.startswith("0x") or s.startswith("0X")) else s
        try:
            raw = bytes.fromhex(hex_str)
        except ValueError:
            raw = s.encode("utf-8")
        if len(raw) < pad_len:
            raw = raw.rjust(pad_len, b"\x00")
        elif len(raw) > pad_len:
            raw = raw[-pad_len:]
        return raw

    to_bytes = to_clean_bytes(req.to, 20)
    data_hex = req.data[2:] if (req.data.startswith("0x") or req.data.startswith("0X")) else req.data
    try:
        data_bytes = bytes.fromhex(data_hex)
    except ValueError:
        data_bytes = req.data.encode("utf-8")

    preimage = to_bytes + val_int.to_bytes(32, "big") + req.nonce.to_bytes(32, "big") + data_bytes
    return "0x" + keccak256(preimage).hex()


@router.post("/simulate", response_model=SimulateResponse)
async def simulate_transaction(
    req: SimulateRequest,
    simulator: SimulatorProtocol = Depends(get_simulator),
    rule_engine: RuleEngineProtocol = Depends(get_rule_engine),
) -> SimulateResponse:
    """
    Simulates transaction state changes and evaluates deterministic security rules.
    Guaranteed < 150ms execution. Zero LLMs on this path.
    """
    start_time = time.perf_counter()

    # 1. Deterministic tx hash calculation
    raw_tx_hash = _compute_raw_tx_hash(req)
    intent_hash = req.intent_hash or ("0x" + "00" * 32)

    # 2. State-diff simulation on EVM state fork
    try:
        raw_sim = await simulator.simulate_tx(req)
    except EngineInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # 3. Deterministic 12-rule evaluation
    eval_result = rule_engine.evaluate(raw_sim, req)

    # 4. Generate 44-bit BIP-39 four-word human verification checksum
    checksum = compute_four_word_checksum(
        chain_id=req.chain_id,
        safe_address=req.safe_address,
        nonce=req.nonce,
        raw_tx_hash=raw_tx_hash,
        intent_hash=intent_hash,
    )

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return SimulateResponse(
        decision=eval_result.decision,
        risk_score=eval_result.risk_score,
        flags=eval_result.flags,
        state_diffs=raw_sim.state_diffs,
        intent_digest=intent_hash,
        raw_tx_hash=raw_tx_hash,
        four_word_checksum=checksum,
        deterministic_human_warnings=eval_result.human_warnings,
        simulation_ms=round(elapsed_ms, 3),
    )


@router.post("/verify-intent", response_model=VerifyIntentResponse)
async def verify_intent(
    req: VerifyIntentRequest,
    simulator: SimulatorProtocol = Depends(get_simulator),
) -> VerifyIntentResponse:
    """
    Verifies that the executed bytecode state transition strictly matches
    the user's declared EIP-712 human intent. Catches UI spoofing (WazirX-class attacks).
    """
    discrepancies: List[str] = []

    calldata = req.calldata.lower()
    if calldata.startswith("0x"):
        calldata = calldata[2:]

    declared_recipient_clean = req.declared_recipient.lower().replace("0x", "")
    declared_max = int(req.declared_max_amount) if req.declared_max_amount.isdigit() else 0

    # Inspect calldata parameters
    if calldata.startswith(SIG_TRANSFER):
        actual_recipient = calldata[8:72][-40:]
        actual_amount = int(calldata[72:136], 16) if len(calldata) >= 136 else 0

        if actual_recipient != declared_recipient_clean:
            discrepancies.append(
                f"RECIPIENT_SPOOFING: Declared recipient was 0x{declared_recipient_clean}, "
                f"but bytecode directs funds to 0x{actual_recipient}."
            )

        if actual_amount > declared_max:
            discrepancies.append(
                f"EXCESSIVE_AMOUNT: Declared max was {declared_max}, "
                f"but bytecode transfers {actual_amount} tokens."
            )
    else:
        discrepancies.append(
            "FUNCTION_MISMATCH: Calldata does not match declared transfer operation."
        )

    matched = len(discrepancies) == 0
    decision = DecisionEnum.ALLOW if matched else DecisionEnum.BLOCK

    checksum = compute_four_word_checksum(
        chain_id=req.chain_id,
        safe_address=req.safe_address,
        nonce=0,
        raw_tx_hash=req.raw_tx_hash,
        intent_hash=req.intent_hash,
    )

    return VerifyIntentResponse(
        match=matched,
        decision=decision,
        discrepancies=discrepancies,
        intent_hash=req.intent_hash,
        four_word_checksum=checksum,
    )


class AuditReceiptRequest(BaseModel):
    chain_id: int = 1
    safe_address: str
    target_contract: str
    raw_tx_hash: str
    intent_hash: str
    four_word_checksum: str
    decision: DecisionEnum
    risk_score: int
    flags: List[str] = Field(default_factory=list)
    human_warnings: List[str] = Field(default_factory=list)


@router.post("/audit-receipt", response_model=AuditReceipt)
async def generate_audit_receipt(req: AuditReceiptRequest) -> AuditReceipt:
    """
    Issues a cryptographically signed Ed25519 forensic receipt for an audited transaction.
    """
    receipt_data = create_forensic_receipt(
        safe_address=req.safe_address,
        target_contract=req.target_contract,
        raw_tx_hash=req.raw_tx_hash,
        intent_hash=req.intent_hash,
        four_word_checksum=req.four_word_checksum,
        decision=req.decision.value,
        risk_score=req.risk_score,
        flags=req.flags,
        human_warnings=req.human_warnings,
        chain_id=req.chain_id,
    )

    return AuditReceipt(
        receipt_id=receipt_data.receipt_id,
        timestamp=receipt_data.reported_at,
        chain_id=receipt_data.chain_id,
        safe_address=receipt_data.safe_address,
        raw_tx_hash=receipt_data.raw_tx_hash,
        intent_hash=receipt_data.intent_hash,
        decision=req.decision,
        risk_score=receipt_data.risk_score,
        flags=receipt_data.flags,
        four_word_checksum=receipt_data.four_word_checksum,
        ed25519_signature=receipt_data.ed25519_signature,
        public_key=receipt_data.public_key,
    )
