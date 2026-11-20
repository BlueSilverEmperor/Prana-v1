"""Regression tests for the second review round (latest upstream commits)."""

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api_agents.main import app

REPO = Path(__file__).resolve().parents[2]
TX = "0x" + "ab" * 32


def client():
    return TestClient(app)


class TestVerifyPage:
    def test_script_in_words_is_rejected_not_reflected(self):
        res = client().get("/verify", params={"words": "<script>alert(1)</script>", "tx": TX})
        assert res.status_code == 400
        assert "<script>alert(1)</script>" not in res.text

    def test_bad_tx_hash_is_rejected(self):
        res = client().get("/verify", params={"words": "toe-early-venue-casino", "tx": "<img src=x>"})
        assert res.status_code == 400
        assert "<img src=x>" not in res.text

    def test_valid_words_render_without_fake_verification_claims(self):
        res = client().get("/verify", params={"words": "toe-early-venue-casino", "tx": TX})
        assert res.status_code == 200
        assert "toe · early · venue · casino" in res.text
        assert "Isolated &amp; Verified" not in res.text and "Isolated & Verified" not in res.text
        assert "0x2145f00f" not in res.text

    def test_missing_params_show_no_invented_hash(self):
        res = client().get("/verify")
        assert res.status_code == 400
        assert "0x6b0656fc" not in res.text


def test_cors_does_not_allow_credentials_for_any_origin():
    res = client().options("/v1/simulate", headers={
        "Origin": "http://evil.example", "Access-Control-Request-Method": "POST"})
    assert res.headers.get("access-control-allow-credentials") != "true"


def test_scan_bytecode_rejects_non_hex():
    assert client().post("/v1/scan-bytecode", json={"bytecode": "zz"}).status_code == 422


class TestReceiptSigningKey:
    def test_no_hardcoded_seed_in_source(self):
        src = (REPO / "api-agents/api_agents/forensics/cert_in_exporter.py").read_text()
        assert "11223344556677889900aabbccddeeff" not in src

    def test_env_seed_gives_stable_public_key(self, monkeypatch):
        import api_agents.forensics.cert_in_exporter as exporter
        monkeypatch.setenv("VERO_RECEIPT_SIGNING_SEED", "aa" * 32)
        a = importlib.reload(exporter).create_forensic_receipt(
            safe_address="0x" + "11" * 20, target_contract="0x" + "22" * 20, raw_tx_hash=TX,
            intent_hash="0x" + "00" * 32, four_word_checksum="a-b-c-d", decision="BLOCK", risk_score=95,
            flags=[], human_warnings=[])
        b = importlib.reload(exporter).create_forensic_receipt(
            safe_address="0x" + "11" * 20, target_contract="0x" + "22" * 20, raw_tx_hash=TX,
            intent_hash="0x" + "00" * 32, four_word_checksum="a-b-c-d", decision="BLOCK", risk_score=95,
            flags=[], human_warnings=[])
        assert a.public_key == b.public_key
        monkeypatch.delenv("VERO_RECEIPT_SIGNING_SEED")
        importlib.reload(exporter)

    def test_bad_env_seed_fails_loudly(self, monkeypatch):
        import api_agents.forensics.cert_in_exporter as exporter
        monkeypatch.setenv("VERO_RECEIPT_SIGNING_SEED", "not-hex")
        with pytest.raises(ValueError):
            importlib.reload(exporter)
        monkeypatch.delenv("VERO_RECEIPT_SIGNING_SEED")
        importlib.reload(exporter)


def _run(script: str, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "VERO_ENGINE": "real"}
    return subprocess.run([sys.executable, str(REPO / script), *args], cwd=REPO, env=env,
                          capture_output=True, text=True, timeout=120)


class TestEvidenceScripts:
    def test_evidence_eval_uses_real_engine_and_computed_numbers(self):
        out = _run("scripts/run_evidence_eval.py")
        assert out.returncode == 0, out.stderr
        assert "Engine                     : vero-engine" in out.stdout
        assert "MockAdapter" not in (REPO / "scripts/run_evidence_eval.py").read_text()
        assert "Confirmed" not in out.stdout

    def test_cli_simulate_uses_real_engine(self):
        out = _run("cli.py", "simulate", "--to", "0x" + "e0" * 20, "--data", "0x12345678", "--operation", "1")
        assert out.returncode == 0, out.stderr
        assert "BLOCK" in out.stdout and "UNVERIFIED_DELEGATECALL" in out.stdout

    def test_cli_bench_runs(self):
        out = _run("cli.py", "bench")
        assert out.returncode == 0, out.stderr
        assert "full-vero" in out.stdout

    def test_wazirx_demo_prints_live_engine_verdict(self):
        out = _run("scripts/demo_wazirx_live.py", "--no-pause")
        assert out.returncode == 0, out.stderr
        assert "PROXY_UPGRADE_ATTEMPT" in out.stdout
        assert "apple-banana-cherry-date" not in out.stdout
        assert "Signature verified   : True" in out.stdout
        src = (REPO / "scripts/demo_wazirx_live.py").read_text()
        assert "time.sleep(0.009)" not in src
