"""Six-word checksum with a verification QR: the QR carries the inputs and the words; the phone recomputes them."""

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from api_agents.main import app

client = TestClient(app)
SHARED = {"chain_id": 1, "safe_address": "0x5bd37a4e9b5e5A2BF8547Ad565b9dFd10126786C", "nonce": 42,
          "raw_tx_hash": "0x" + "aa" * 32, "intent_hash": "0x" + "bb" * 32}
SHARED_WORDS = ["train", "sand", "used", "essay", "donkey", "disease"]


def _code() -> dict:
    res = client.post("/v1/innovations/six-words", json=SHARED)
    assert res.status_code == 200
    return res.json()


def test_shared_vector_gives_the_pinned_words_and_a_qr():
    body = _code()
    assert body["words"] == SHARED_WORDS
    assert body["qr_svg"].lstrip().startswith("<svg") or "<svg" in body["qr_svg"][:200]


def test_qr_link_carries_every_input_and_the_words():
    query = parse_qs(urlparse(_code()["verify_url"]).query)
    assert query["words"] == ["-".join(SHARED_WORDS)]
    assert query["chain"] == ["1"] and query["nonce"] == ["42"]
    assert query["vault"] == [SHARED["safe_address"].lower()]
    assert query["tx"] == [SHARED["raw_tx_hash"]] and query["intent"] == [SHARED["intent_hash"]]


def test_phone_page_recomputes_and_confirms_a_genuine_code():
    url = urlparse(_code()["verify_url"])
    res = client.get(f"{url.path}?{url.query}")
    assert res.status_code == 200 and "MATCH" in res.text and "train" in res.text


def test_phone_page_rejects_a_code_whose_transaction_was_changed():
    url = urlparse(_code()["verify_url"])
    tampered = url.query.replace("nonce=42", "nonce=43")    # the screen kept the old words for a different tx
    res = client.get(f"{url.path}?{tampered}")
    assert res.status_code == 200 and "MISMATCH" in res.text and "Do not sign" in res.text


def test_phone_page_refuses_malformed_links():
    assert client.get("/verify/six?chain=1&vault=0x12&nonce=1&tx=0x1&intent=0x2&words=a-b").status_code == 400


def test_bad_inputs_are_rejected():
    assert client.post("/v1/innovations/six-words", json={**SHARED, "safe_address": "0x1234"}).status_code == 422
    assert client.post("/v1/innovations/six-words", json={**SHARED, "nonce": -1}).status_code == 422
