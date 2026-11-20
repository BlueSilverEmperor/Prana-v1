"""x402 proof-of-work gate for Quai simulations.

A job id is issued by this server and carries its own expiry and an HMAC, so no store is needed to
check it was issued here. A payment signature ``job=<id>;nonce=<n>`` is accepted only when:
  1. the HMAC matches (the job came from this server),
  2. the job has not expired,
  3. SHA-256d(job + nonce) starts with DIFFICULTY hex zeros (the work was done), and
  4. the job has not been redeemed before (each job pays for one simulation).

Limits: the redemption set lives in this process, so run one worker (or share QUAI_WORK_GATE_SECRET and
move redemptions to a shared store such as Redis SETNX with a TTL). Jobs are free to request, so put a
per-client rate limit in front of the gate in production; difficulty only raises the cost per job.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from typing import Dict, Optional

JOB_TTL_SECONDS = 300
DIFFICULTY = max(1, int(os.getenv("QUAI_WORK_GATE_DIFFICULTY", "3")))  # leading hex zeros, ~4096 hashes
MAX_TRACKED_JOBS = 50_000
_MAC_HEX_CHARS = 32
_SIGNATURE_RE = re.compile(r"(?:^|;)\s*job=([0-9]+\.[0-9a-f]{16}\.[0-9a-f]{32})\s*;\s*nonce=([0-9]{1,12})(?:;|$)")

# A per-process random key is enough for one server; set QUAI_WORK_GATE_SECRET to share jobs across workers.
_SECRET = (os.getenv("QUAI_WORK_GATE_SECRET") or secrets.token_hex(32)).encode()
_redeemed: Dict[str, int] = {}
_lock = threading.Lock()


def _mac(body: str) -> str:
    return hmac.new(_SECRET, body.encode(), hashlib.sha256).hexdigest()[:_MAC_HEX_CHARS]


def issue_job() -> str:
    """Returns ``<expiry>.<random>.<mac>``; the client solves it with solve_x402_pow_challenge."""
    body = f"{int(time.time()) + JOB_TTL_SECONDS}.{secrets.token_hex(8)}"
    return f"{body}.{_mac(body)}"


def _work_done(job_id: str, nonce: str) -> bool:
    digest = hashlib.sha256(hashlib.sha256(f"{job_id}{nonce}".encode()).digest()).hexdigest()
    return digest.startswith("0" * DIFFICULTY)


def _parse(signature: Optional[str]) -> Optional[tuple]:
    if not signature or len(signature) > 256:
        return None
    match = _SIGNATURE_RE.search(signature.strip())
    return (match.group(1), match.group(2)) if match else None


def redeem(signature: Optional[str]) -> bool:
    """True exactly once per valid, solved, unexpired job issued by this server."""
    parsed = _parse(signature)
    if parsed is None:
        return False
    job_id, nonce = parsed
    expiry_str, rand, mac = job_id.split(".")
    if not hmac.compare_digest(mac, _mac(f"{expiry_str}.{rand}")):
        return False
    now = int(time.time())
    expiry = int(expiry_str)
    if now > expiry or not _work_done(job_id, nonce):
        return False
    with _lock:
        if job_id in _redeemed:
            return False
        if len(_redeemed) >= MAX_TRACKED_JOBS:
            for stale in [j for j, exp in _redeemed.items() if exp < now]:
                del _redeemed[stale]
            if len(_redeemed) >= MAX_TRACKED_JOBS:
                return False  # fail closed rather than forget redemptions
        _redeemed[job_id] = expiry
    return True
