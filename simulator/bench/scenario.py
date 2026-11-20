"""Scenario file schema and loader for the 55-scenario harness (#23)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from shared.api_schemas import SimulationRequest


class Scenario(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    set: Literal["main", "heldout", "public"]
    label: Literal["malicious", "benign"]
    category: str
    title: str
    request: SimulationRequest
    context: dict[str, Any] = Field(default_factory=dict)
    expectedRules: list[str] = Field(default_factory=list)
    source: Optional[str] = None  # citation for public reconstructions
    author: Optional[str] = None


def load_scenarios(root: Path) -> list[Scenario]:
    """Load every ``*.json`` scenario under ``root``, sorted by path for determinism."""
    files = sorted(Path(root).rglob("*.json"))
    if not files:
        raise FileNotFoundError(f"no scenario files under {root}")
    return [Scenario.model_validate(json.loads(f.read_text())) for f in files]
