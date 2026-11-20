"""
Project Vero - api-agents package
Firewall, threat intelligence, forensic verification, and EIP-1193 guarding.
"""

import sys
from pathlib import Path

__version__ = "0.1.0"


def _ensure_monorepo_importable() -> None:
    """In the monorepo, `simulator` and `shared` live at the repo root, one level above api-agents.

    Done here, at package import, so every module can import them at the top regardless of which
    api_agents module happens to load first (uvicorn runs with cwd=api-agents and no PYTHONPATH).
    """
    try:
        import simulator.engine  # noqa: F401
    except ImportError:
        root = Path(__file__).resolve().parents[2]
        if (root / "simulator" / "engine.py").exists() and str(root) not in sys.path:
            sys.path.insert(0, str(root))


_ensure_monorepo_importable()
