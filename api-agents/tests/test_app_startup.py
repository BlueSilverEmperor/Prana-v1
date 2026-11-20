"""The API must import in a fresh interpreter launched the way uvicorn is (cwd=api-agents, no PYTHONPATH)."""

import os
import subprocess
import sys
from pathlib import Path

API_DIR = Path(__file__).resolve().parents[1]


def test_app_imports_without_repo_root_on_path():
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["VERO_ENGINE"] = "real"
    proc = subprocess.run(
        [sys.executable, "-c", "import api_agents.main"],
        cwd=API_DIR, env=env, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr[-800:]
