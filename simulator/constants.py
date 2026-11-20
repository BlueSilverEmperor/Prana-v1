"""Named constants: slots, limits, canonical addresses and severity weights."""

from __future__ import annotations

from types import MappingProxyType

MAX_UINT256 = 2**256 - 1
MAX_UINT160 = 2**160 - 1
# Anything at or above this is treated as "unlimited" (covers uint256/uint160 max
# and the common "max minus a little" variants).
UNLIMITED_THRESHOLD = 2**128

ERC1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SAFE_SINGLETON_SLOT = "0x" + "00" * 32
EIP7702_DESIGNATOR_PREFIX = "0xef0100"

MAX_MULTISEND_DEPTH = 4
SECONDS_PER_DAY = 86_400
NEW_CONTRACT_WINDOW_SECONDS = SECONDS_PER_DAY
LONG_PERMIT_SECONDS = 30 * SECONDS_PER_DAY
VAULT_SHARE_WARN = 0.5
VAULT_SHARE_CRITICAL = 0.9
DEFAULT_MAX_GAS_FEE_WEI = 5 * 10**16  # 0.05 ETH worst-case fee ceiling
GRIEFING_GAS_LIMIT = 2_000_000
GRIEFING_CALLDATA_BYTES = 4
DEFAULT_BLOCK_TIME_SECONDS = 12

# 0-100 scale shared with the firewall API: one CRITICAL alone scores 95, one HIGH 70.
SEVERITY_WEIGHT = MappingProxyType({"CRITICAL": 95, "HIGH": 70, "MEDIUM": 30, "LOW": 5})
SEVERITY_RANK = MappingProxyType({"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3})
BLOCKING_SEVERITIES = frozenset({"CRITICAL", "HIGH"})

# Canonical Safe MultiSend / MultiSendCallOnly deployments (v1.3.0 and v1.4.1).
TRUSTED_DELEGATECALL_TARGETS = frozenset(
    {
        "0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761",
        "0x40a2accbd92bca938b02010e17a5b8929b49130d",
        "0x38869bf66a61cf6bdb996a6ae40d5853fd43b526",
        "0x9641d764fc13c8b624c04430c7356c1c7c8102e2",
    }
)

PERMIT2_ADDRESS = "0x000000000022d473030f116ddee9f6b43ac78ba3"

# (chainId, SYMBOL) -> canonical token addresses. Extend per deployment via EngineContext.
CANONICAL_TOKENS = MappingProxyType(
    {
        (1, "USDC"): frozenset({"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"}),
        (1, "USDT"): frozenset({"0xdac17f958d2ee523a2206206994597c13d831ec7"}),
        (1, "WETH"): frozenset({"0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"}),
        (1, "WBTC"): frozenset({"0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"}),
        (1, "DAI"): frozenset({"0x6b175474e89094c44da98b954eedeac495271d0f"}),
    }
)

KNOWN_TOKEN_META = MappingProxyType(
    {
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USDC", 6),
        "0xdac17f958d2ee523a2206206994597c13d831ec7": ("USDT", 6),
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": ("WETH", 18),
        "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": ("WBTC", 8),
        "0x6b175474e89094c44da98b954eedeac495271d0f": ("DAI", 18),
    }
)
