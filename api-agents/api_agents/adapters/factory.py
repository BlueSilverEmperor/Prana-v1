"""Select the simulator/rule-engine adapter for the API and MCP server.

VERO_ENGINE=real (default) uses the Vero engine; VERO_ENGINE=mock uses MockAdapter.
VERO_ANVIL_RPC=<url> turns on fork simulation for the real engine.

Fail closed: if the real engine cannot start, startup fails instead of silently serving mock
verdicts (the mock can ALLOW what rules R1-R12 would BLOCK). A machine that genuinely cannot run
the engine, such as a demo laptop without its dependencies, may opt in with
VERO_ALLOW_MOCK_FALLBACK=1; the fallback is then logged loudly and engine_name() reports "mock".
"""

from __future__ import annotations

import logging
import os
from typing import Union

from api_agents.adapters.mock_adapter import MockAdapter

ENGINE_ENV = "VERO_ENGINE"
RPC_ENV = "VERO_ANVIL_RPC"
FALLBACK_ENV = "VERO_ALLOW_MOCK_FALLBACK"
MOCK_LATENCY_MS = 1.0

logger = logging.getLogger(__name__)


def _fallback_allowed() -> bool:
    return os.getenv(FALLBACK_ENV, "").strip().lower() in {"1", "true", "yes"}


def build_adapter() -> Union["VeroEngineAdapter", MockAdapter]:  # noqa: F821
    mode = os.getenv(ENGINE_ENV, "real").strip().lower()
    if mode == "mock":
        return MockAdapter(artificial_latency_ms=MOCK_LATENCY_MS)
    if mode != "real":
        raise ValueError(f"{ENGINE_ENV} must be 'real' or 'mock', got {mode!r}")
    try:
        from api_agents.adapters import vero_engine_adapter
        return vero_engine_adapter.VeroEngineAdapter(rpc_url=os.getenv(RPC_ENV) or None)
    except Exception as exc:
        if not _fallback_allowed():
            raise
        logger.error("Vero engine failed to start (%s: %s); serving MOCK verdicts because %s=1",
                     type(exc).__name__, exc, FALLBACK_ENV)
        return MockAdapter(artificial_latency_ms=MOCK_LATENCY_MS)


def engine_name(adapter: object) -> str:
    return "mock" if isinstance(adapter, MockAdapter) else "vero-engine"
