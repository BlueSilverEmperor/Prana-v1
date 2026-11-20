"""
MockAdapter: Standalone high-fidelity mock implementing SimulatorProtocol and RuleEngineProtocol.
Clearly labeled MockAdapter to allow all api-agents features and tests to pass
independently without requiring a live Anvil node or external rule engine.
"""

import time
from typing import List, Tuple
from api_agents.adapters.simulator_protocol import (
    RawSimulationResult,
    RuleEngineProtocol,
    RuleEvaluationResult,
    SimulatorProtocol,
)
from api_agents.models.schemas import DecisionEnum, SimulateRequest, StateDiff

# Known method signatures for EVM calldata
SIG_APPROVE = "095ea7b3"
SIG_TRANSFER = "a9059cbb"
SIG_UPGRADE_TO = "3659cfe6"
SIG_UPGRADE_TO_AND_CALL = "4f1fc3d0"


class MockAdapter(SimulatorProtocol, RuleEngineProtocol):
    """
    Mock implementation simulating state execution and the 12-rule deterministic engine.
    """

    def __init__(self, artificial_latency_ms: float = 2.0):
        self.artificial_latency_ms = artificial_latency_ms

    async def simulate_tx(self, req: SimulateRequest) -> RawSimulationResult:
        """
        Simulates transaction execution against an EVM state fork.
        """
        if self.artificial_latency_ms > 0:
            time.sleep(self.artificial_latency_ms / 1000.0)

        calldata = req.data.lower()
        if calldata.startswith("0x"):
            calldata = calldata[2:]

        state_diffs: List[StateDiff] = []

        # Plain ETH transfer
        if len(calldata) == 0:
            val_wei = int(req.value) if req.value.isdigit() else 0
            val_eth = val_wei / 1e18
            state_diffs.append(
                StateDiff(
                    asset_type="NATIVE",
                    from_address=req.safe_address,
                    to_address=req.to,
                    amount_raw=str(val_wei),
                    delta_human=f"-{val_eth:.4f} ETH",
                )
            )
            return RawSimulationResult(
                success=True,
                gas_used=21000,
                state_diffs=state_diffs,
                raw_logs=[],
            )

        selector = calldata[:8]

        # Case 1: approve(spender, amount)
        if selector == SIG_APPROVE:
            spender = "0x" + calldata[8:72][-40:]
            amount_hex = calldata[72:136]
            amount = int(amount_hex, 16) if amount_hex else 0
            is_infinite = amount > (2**128)
            amount_str = "UNLIMITED" if is_infinite else str(amount)
            state_diffs.append(
                StateDiff(
                    asset_type="ERC20_ALLOWANCE",
                    contract_address=req.to,
                    from_address=req.safe_address,
                    to_address=spender,
                    amount_raw=str(amount),
                    delta_human=f"APPROVAL GRANTED ({amount_str})",
                )
            )
            return RawSimulationResult(
                success=True,
                gas_used=45000,
                state_diffs=state_diffs,
                raw_logs=["Approval(address,address,uint256)"],
            )

        # Case 2: transfer(recipient, amount)
        elif selector == SIG_TRANSFER:
            recipient = "0x" + calldata[8:72][-40:]
            amount_hex = calldata[72:136]
            amount = int(amount_hex, 16) if amount_hex else 0
            state_diffs.append(
                StateDiff(
                    asset_type="ERC20",
                    contract_address=req.to,
                    from_address=req.safe_address,
                    to_address=recipient,
                    amount_raw=str(amount),
                    delta_human=f"-{amount} TOKENS",
                )
            )
            return RawSimulationResult(
                success=True,
                gas_used=35000,
                state_diffs=state_diffs,
                raw_logs=["Transfer(address,address,uint256)"],
            )

        # Case 3: upgradeTo(newImplementation) / upgradeToAndCall
        elif selector in (SIG_UPGRADE_TO, SIG_UPGRADE_TO_AND_CALL):
            new_impl = "0x" + calldata[8:72][-40:]
            state_diffs.append(
                StateDiff(
                    asset_type="STORAGE_SLOT_0x3608",
                    contract_address=req.to,
                    from_address=req.safe_address,
                    to_address=new_impl,
                    amount_raw="1",
                    delta_human=f"PROXY_UPGRADE -> {new_impl}",
                )
            )
            return RawSimulationResult(
                success=True,
                gas_used=55000,
                state_diffs=state_diffs,
                raw_logs=["Upgraded(address)"],
            )

        # Generic contract invocation fallback
        state_diffs.append(
            StateDiff(
                asset_type="CONTRACT_CALL",
                contract_address=req.to,
                from_address=req.safe_address,
                to_address=req.to,
                amount_raw=req.value,
                delta_human=f"CALL(0x{selector})",
            )
        )
        return RawSimulationResult(
            success=True,
            gas_used=60000,
            state_diffs=state_diffs,
            raw_logs=[],
        )

    def evaluate(self, sim: RawSimulationResult, req: SimulateRequest) -> RuleEvaluationResult:
        """
        12-Rule engine deterministic evaluator.
        Never uses LLMs. Strictly algorithmic based on state diffs & calldata.
        """
        flags: List[str] = []
        warnings: List[str] = []
        risk_score = 0

        calldata = req.data.lower()
        if calldata.startswith("0x"):
            calldata = calldata[2:]
        selector = calldata[:8]

        # Rule 1: Check for Proxy Upgrade attempts (Highest Risk)
        if selector in (SIG_UPGRADE_TO, SIG_UPGRADE_TO_AND_CALL):
            flags.append("PROXY_UPGRADE_ATTEMPT")
            flags.append("UNVERIFIED_IMPLEMENTATION_CODE")
            warnings.append(
                "CRITICAL: Transaction alters smart contract code implementation! This matches the WazirX attack vector."
            )
            risk_score = max(risk_score, 95)

        # Rule 2: Infinite / Excessive Token Approvals
        for diff in sim.state_diffs:
            if diff.asset_type == "ERC20_ALLOWANCE":
                amount = int(diff.amount_raw or "0")
                if amount > (2**128):
                    flags.append("INFINITE_TOKEN_APPROVAL")
                    warnings.append(
                        f"HIGH RISK: Grants unlimited token withdrawal authorization to spender {diff.to_address}."
                    )
                    risk_score = max(risk_score, 85)

        # Rule 3: High Native ETH Value Outflow
        val_wei = int(req.value) if req.value.isdigit() else 0
        if val_wei > 10 * 10**18:  # > 10 ETH
            flags.append("LARGE_VALUE_OUTFLOW")
            warnings.append(f"WARNING: Outgoing native balance exceeds threshold ({val_wei / 1e18:.2f} ETH).")
            risk_score = max(risk_score, 60)

        # Rule 4: Execution Revert Check
        if not sim.success:
            flags.append("SIMULATION_REVERTED")
            warnings.append(f"TRANSACTION WILL REVERT: {sim.revert_reason}")
            risk_score = max(risk_score, 70)

        # Final Decision determination
        if risk_score >= 80:
            decision = DecisionEnum.BLOCK
        elif risk_score >= 40:
            decision = DecisionEnum.WARN
        else:
            decision = DecisionEnum.ALLOW

        return RuleEvaluationResult(
            decision=decision,
            risk_score=risk_score,
            flags=flags,
            human_warnings=warnings,
        )
