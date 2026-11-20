"""Read-only context the engine evaluates against (registries, contacts, balances)."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Optional

from simulator.constants import (
    CANONICAL_TOKENS,
    DEFAULT_MAX_GAS_FEE_WEI,
    KNOWN_TOKEN_META,
    TRUSTED_DELEGATECALL_TARGETS,
)
from simulator.hexutil import normalize_address, parse_int


def _frozen_map(value: Mapping | None) -> Mapping:
    return MappingProxyType(dict(value or {}))


@dataclass(frozen=True)
class EngineContext:
    threat_registry: frozenset[str] = frozenset()
    trusted_delegatecall: frozenset[str] = TRUSTED_DELEGATECALL_TARGETS
    trusted_7702_delegates: frozenset[str] = frozenset()
    canonical_tokens: Mapping[tuple[int, str], frozenset[str]] = CANONICAL_TOKENS
    token_meta: Mapping[str, tuple[str, int]] = field(default_factory=lambda: KNOWN_TOKEN_META)
    contacts: frozenset[str] = frozenset()
    recipient_history: frozenset[str] = frozenset()
    safe_balances: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))
    deploy_times: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))
    now: Optional[int] = None
    expected_chain_id: Optional[int] = None
    max_gas_fee_wei: int = DEFAULT_MAX_GAS_FEE_WEI

    def __post_init__(self) -> None:
        # Merge caller-supplied token metadata over the known defaults, read-only.
        merged = {**KNOWN_TOKEN_META, **{k.lower(): v for k, v in self.token_meta.items()}}
        object.__setattr__(self, "token_meta", MappingProxyType(merged))
        object.__setattr__(self, "safe_balances", _frozen_map(self.safe_balances))
        object.__setattr__(self, "deploy_times", _frozen_map(self.deploy_times))

    def symbol_of(self, token: str) -> Optional[str]:
        meta = self.token_meta.get(token.lower())
        return meta[0] if meta else None

    def decimals_of(self, token: str) -> Optional[int]:
        meta = self.token_meta.get(token.lower())
        return meta[1] if meta else None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "EngineContext":
        """Build a context from JSON-like data (scenario files, API payloads)."""
        def addrs(key: str) -> frozenset[str]:
            return frozenset(normalize_address(a) for a in raw.get(key, []))

        def asset_key(key: str) -> str:
            return "ETH" if key.upper() == "ETH" else normalize_address(key)

        canonical = dict(CANONICAL_TOKENS)
        for entry in raw.get("canonicalTokens", []):
            key = (int(entry["chainId"]), entry["symbol"].upper())
            canonical[key] = canonical.get(key, frozenset()) | {normalize_address(entry["address"])}
        kwargs: dict[str, Any] = dict(
            threat_registry=addrs("threatRegistry"),
            trusted_7702_delegates=addrs("trusted7702Delegates"),
            canonical_tokens=MappingProxyType(canonical),
            token_meta={normalize_address(k): (v["symbol"], int(v["decimals"]))
                        for k, v in raw.get("tokenMeta", {}).items()},
            contacts=addrs("contacts"),
            recipient_history=addrs("recipientHistory"),
            safe_balances={asset_key(k): parse_int(v) for k, v in raw.get("safeBalances", {}).items()},
            deploy_times={normalize_address(k): int(v) for k, v in raw.get("deployTimes", {}).items()},
            now=raw.get("now"),
            expected_chain_id=raw.get("expectedChainId"),
        )
        if "trustedDelegatecall" in raw:
            kwargs["trusted_delegatecall"] = TRUSTED_DELEGATECALL_TARGETS | addrs("trustedDelegatecall")
        if "maxGasFeeWei" in raw:
            kwargs["max_gas_fee_wei"] = parse_int(raw["maxGasFeeWei"])
        return cls(**kwargs)
