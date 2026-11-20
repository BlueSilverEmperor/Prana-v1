"""Select the simulator/rule-engine adapter for the API and MCP server.

VERO_ENGINE=real (default) uses the Vero engine; VERO_ENGINE=mock uses MockAdapter.
VERO_ANVIL_RPC=<url> turns on fork simulation for the real engine.
"""

from __future__ import annotations

import os
from typing import Union

from api_agents.adapters.mock_adapter import MockAdapter

ENGINE_ENV = "VERO_ENGINE"
RPC_ENV = "VERO_ANVIL_RPC"
MOCK_LATENCY_MS = 1.0


def build_adapter() -> Union["VeroEngineAdapter", MockAdapter]:  # noqa: F821
    mode = os.getenv(ENGINE_ENV, "real").strip().lower()
    if mode == "mock":
        return MockAdapter(artificial_latency_ms=MOCK_LATENCY_MS)
    if mode != "real":
        raise ValueError(f"{ENGINE_ENV} must be 'real' or 'mock', got {mode!r}")
    from api_agents.adapters.vero_engine_adapter import VeroEngineAdapter

    return VeroEngineAdapter(rpc_url=os.getenv(RPC_ENV) or None)


def engine_name(adapter: object) -> str:
    return "mock" if isinstance(adapter, MockAdapter) else "vero-engine"
