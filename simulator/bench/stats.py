"""Feature #24 statistics: Wilson-score intervals and latency percentiles."""

from __future__ import annotations

from typing import Sequence

import numpy as np
from scipy.stats import binomtest

DEFAULT_CONFIDENCE = 0.95


def wilson_interval(successes: int, trials: int, confidence: float = DEFAULT_CONFIDENCE) -> tuple[float, float]:
    if trials == 0:
        return (0.0, 0.0)
    if not 0 <= successes <= trials:
        raise ValueError(f"successes {successes} outside [0, {trials}]")
    ci = binomtest(successes, trials).proportion_ci(confidence_level=confidence, method="wilson")
    return (round(float(ci.low), 4), round(float(ci.high), 4))


def percentile(values: Sequence[float], q: float) -> float:
    return round(float(np.percentile(values, q)), 3) if len(values) else 0.0
