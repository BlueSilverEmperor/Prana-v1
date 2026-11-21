"""
x402 proof-of-work challenge solver (client side of the work gate in payments/work_gate.py).
Local SHA-256d only: no model, no dataset, no external service.
"""

import hashlib
import time

POW_MAX_ATTEMPTS = 1_000_000


def solve_payment_required(header: str) -> str:
    """Solves a PAYMENT-REQUIRED challenge at the difficulty the server advertised."""
    fields = dict(part.split("=", 1) for part in header.split() if "=" in part)
    return solve_x402_pow_challenge(fields["job"], difficulty=int(fields.get("difficulty", "1")))


def solve_x402_pow_challenge(job_id: str, difficulty: int = 1) -> str:
    """
    Solves an x402 Proof-of-Work challenge using SHA-256d (double SHA-256).
    Difficulty is the number of leading zero hex characters required.
    Returns the PAYMENT-SIGNATURE value, which names the job it solves.
    """
    target_prefix = "0" * difficulty
    job_bytes = job_id.encode("utf-8")
    nonce = 0
    t0 = time.perf_counter()

    while True:
        if nonce >= POW_MAX_ATTEMPTS:
            raise RuntimeError(f"no proof-of-work solution within {POW_MAX_ATTEMPTS} attempts")
        nonce_bytes = str(nonce).encode("utf-8")
        h1 = hashlib.sha256(job_bytes + nonce_bytes).digest()
        h2 = hashlib.sha256(h1).hexdigest()
        if h2.startswith(target_prefix):
            break
        nonce += 1

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return f"job={job_id};nonce={nonce};difficulty={difficulty};time_ms={elapsed_ms:.2f}"
