"""Shared Pydantic interface contract for Project Vero.

Co-owned by Person 2 (simulation engine), Person 3 (FastAPI) and Person 4 (frontend).
Field names are camelCase because they are serialised straight to the web client.

All models are frozen: build a new instance with ``model_copy(update=...)`` instead of
mutating. Addresses are normalised to lowercase 0x-prefixed hex at the boundary, and
integer amounts travel as decimal strings to survive JavaScript number limits.
"""

from __future__ import annotations

import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEX_RE = re.compile(r"^0x([0-9a-fA-F]{2})*$")
_UINT_RE = re.compile(r"^(0x[0-9a-fA-F]+|[0-9]+)$")

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _address(value: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.match(value):
        raise ValueError(f"invalid address: {value!r}")
    return value.lower()


MAX_UINT256 = 2**256 - 1
MAX_UINT_CHARS = 80  # 78 decimal digits or 0x + 64 hex digits, with slack
MAX_DATA_HEX_CHARS = 2 + 2 * 128 * 1024  # 128 KiB of calldata


def _hex(value: str) -> str:
    if not isinstance(value, str) or len(value) > MAX_DATA_HEX_CHARS or not _HEX_RE.match(value):
        raise ValueError("data must be 0x-prefixed, even-length hex, at most 128 KiB")
    return value.lower()


def _uint_string(value: Any) -> str:
    text = str(value)
    if len(text) > MAX_UINT_CHARS or not _UINT_RE.match(text):
        raise ValueError(f"expected unsigned integer string, got {text[:20]!r}")
    number = int(text, 16) if text.startswith("0x") else int(text)
    if number > MAX_UINT256:
        raise ValueError("integer exceeds uint256")
    return str(number)


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Authorization(_Frozen):
    """EIP-7702 authorisation tuple attached to a type-4 transaction."""

    chainId: int = Field(ge=0)
    address: str
    nonce: int = Field(ge=0)

    _v_address = field_validator("address")(lambda cls, v: _address(v))


class TransactionTuple(_Frozen):
    to: str
    value: str = "0"
    data: str = "0x"
    operation: int = Field(default=0, ge=0, le=1)  # 0 = CALL, 1 = DELEGATECALL
    gas: Optional[str] = None
    authorizationList: Optional[list[Authorization]] = None

    _v_to = field_validator("to")(lambda cls, v: _address(v))
    _v_value = field_validator("value")(lambda cls, v: _uint_string(v))
    _v_data = field_validator("data")(lambda cls, v: _hex(v))

    @field_validator("gas")
    @classmethod
    def _v_gas(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else _uint_string(v)


class UserOperation(_Frozen):
    """Subset of an ERC-4337 UserOperation needed for the gas-ceiling check (#28)."""

    sender: str
    callData: str = "0x"
    callGasLimit: str = "0"
    verificationGasLimit: str = "0"
    preVerificationGas: str = "0"
    maxFeePerGas: str = "0"
    maxPriorityFeePerGas: str = "0"
    paymasterAndData: str = "0x"

    _v_sender = field_validator("sender")(lambda cls, v: _address(v))
    _v_hex = field_validator("callData", "paymasterAndData")(lambda cls, v: _hex(v))
    _v_uint = field_validator(
        "callGasLimit",
        "verificationGasLimit",
        "preVerificationGas",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
    )(lambda cls, v: _uint_string(v))


class IntentPolicy(_Frozen):
    """What the signer declared. Never derived from the simulation."""

    allowedRecipients: list[str] = Field(default_factory=list)
    maxOutflowWei: str = "0"  # per-asset ceiling in the asset's smallest unit
    allowedTokens: list[str] = Field(default_factory=list)  # use "ETH" for native value
    maxGasFeeWei: Optional[str] = None

    @field_validator("allowedRecipients")
    @classmethod
    def _v_recipients(cls, v: list[str]) -> list[str]:
        return [_address(a) for a in v]

    @field_validator("allowedTokens")
    @classmethod
    def _v_tokens(cls, v: list[str]) -> list[str]:
        return ["ETH" if t.upper() == "ETH" else _address(t) for t in v]

    _v_max = field_validator("maxOutflowWei")(lambda cls, v: _uint_string(v))

    @field_validator("maxGasFeeWei")
    @classmethod
    def _v_gas(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else _uint_string(v)


class SimulationRequest(_Frozen):
    chainId: int = Field(ge=0)
    safeAddress: str
    transactions: list[TransactionTuple] = Field(min_length=1, max_length=64)
    intentPolicy: Optional[IntentPolicy] = None
    userOperation: Optional[UserOperation] = None
    label: Optional[str] = Field(default=None, max_length=280)  # what the UI claimed

    _v_safe = field_validator("safeAddress")(lambda cls, v: _address(v))


class BalanceChange(_Frozen):
    address: str
    asset: str  # "ETH", token address, or "<token>#<tokenId>" for NFTs
    delta: str  # signed decimal string


class ApprovalChange(_Frozen):
    token: str
    owner: str
    spender: str
    amount: str  # decimal string, or "ALL" / "NONE" for setApprovalForAll


class OwnerChange(_Frozen):
    safe: str
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    newThreshold: Optional[int] = None  # None when the threshold did not change
    oldThreshold: Optional[int] = None


class ModuleChange(_Frozen):
    safe: str
    enabledModules: list[str] = Field(default_factory=list)
    disabledModules: list[str] = Field(default_factory=list)


class GuardChange(_Frozen):
    safe: str
    newGuard: str


class ImplementationSwap(_Frozen):
    address: str
    oldImpl: str
    newImpl: str
    source: Literal["erc1967-slot", "slot0", "code", "calldata"] = "calldata"


class BridgeTransfer(_Frozen):
    protocol: str
    sourceChainId: int
    destChainId: Optional[int]
    recipient: Optional[str]
    token: Optional[str]
    amount: str


class StateDiffSummary(_Frozen):
    balanceChanges: list[BalanceChange] = Field(default_factory=list)
    approvals: list[ApprovalChange] = Field(default_factory=list)
    ownerChanges: list[OwnerChange] = Field(default_factory=list)
    moduleChanges: list[ModuleChange] = Field(default_factory=list)
    implementationSwaps: list[ImplementationSwap] = Field(default_factory=list)
    guardChanges: list[GuardChange] = Field(default_factory=list)
    bridgeTransfers: list[BridgeTransfer] = Field(default_factory=list)


class RiskAlert(_Frozen):
    ruleId: str  # R1..R12, or a shield id such as P33-POISON
    severity: Severity
    description: str
    context: Optional[dict[str, Any]] = None


class Metrics(_Frozen):
    gasUsed: str
    riskScore: int = Field(ge=0, le=100)


class SimulationResult(_Frozen):
    success: bool
    simulationLatencyMs: float
    stateDiff: StateDiffSummary
    alerts: list[RiskAlert]
    plainEnglishSummary: list[str]
    metrics: Metrics
    mode: Literal["fork", "static"] = "static"
    calldataDigests: list[str] = Field(default_factory=list)  # one per top-level tx
    revertReason: Optional[str] = None


class ConfidenceIntervals(_Frozen):
    detectionRate95: tuple[float, float]
    blockRate95: Optional[tuple[float, float]] = None
    falsePositiveRate95: Optional[tuple[float, float]] = None


class BenchmarkMetrics(_Frozen):
    totalScenarios: int
    detectionRate: float
    blockRate: float
    falsePositiveRate: float
    p95LatencyMs: float
    confidenceIntervals: ConfidenceIntervals
    p50LatencyMs: Optional[float] = None
    mode: Optional[str] = None
