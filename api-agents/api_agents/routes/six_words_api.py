"""Six-word checksum with a verification QR code.

POST /v1/innovations/six-words computes the six words for a transaction and returns a QR code. The QR holds a
link that carries the words together with every input they were computed from (chain, vault, nonce, tx hash,
intent hash). GET /verify/six is the page that link opens on a phone: it recomputes the words from the inputs
on the server, independently of the signing screen, and shows MATCH or MISMATCH.
"""

import html
import os
import re
from typing import List
from urllib.parse import urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from reportlab.graphics import renderSVG
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing

from api_agents.utils.four_word_checksum import compute_six_word_checksum

router = APIRouter(prefix="/v1/innovations", tags=["innovations"])
phone_router = APIRouter(tags=["verify"])

ADDRESS = r"^0x[0-9a-fA-F]{40}$"
HASH32 = r"^0x[0-9a-fA-F]{64}$"
SIX_WORDS = r"^[a-z]+(?:-[a-z]+){5}$"
MAX_CHAIN_ID = 2**63 - 1
MAX_NONCE = 2**64 - 1
QR_SIZE = 240
QR_ERROR_LEVEL = "M"
PHONE_PATH = "/verify/six"


class SixWordsRequest(BaseModel):
    chain_id: int = Field(ge=1, le=MAX_CHAIN_ID)
    safe_address: str = Field(pattern=ADDRESS)
    nonce: int = Field(ge=0, le=MAX_NONCE)
    raw_tx_hash: str = Field(pattern=HASH32)
    intent_hash: str = Field(pattern=HASH32)


def _words(chain_id: int, vault: str, nonce: int, tx: str, intent: str) -> List[str]:
    return compute_six_word_checksum(chain_id, vault, nonce, tx, intent).split("-")


def qr_svg(value: str) -> str:
    """A scannable QR as inline SVG, drawn with reportlab (already a dependency for audit receipts)."""
    widget = QrCodeWidget(value, barLevel=QR_ERROR_LEVEL, barWidth=QR_SIZE, barHeight=QR_SIZE)
    drawing = Drawing(QR_SIZE, QR_SIZE)
    drawing.add(widget)
    svg = renderSVG.drawToString(drawing)
    return svg[svg.index("<svg"):]


@router.post("/six-words")
async def six_words(req: SixWordsRequest, request: Request) -> dict:
    vault = req.safe_address.lower()
    words = _words(req.chain_id, vault, req.nonce, req.raw_tx_hash, req.intent_hash)
    base = (os.getenv("VERO_PUBLIC_URL") or str(request.base_url)).rstrip("/")   # phones need a reachable host
    query = urlencode({"chain": req.chain_id, "vault": vault, "nonce": req.nonce, "tx": req.raw_tx_hash,
                       "intent": req.intent_hash, "words": "-".join(words)})
    url = f"{base}{PHONE_PATH}?{query}"
    return {"words": words, "verify_url": url, "qr_svg": qr_svg(url)}


_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Vero six-word check</title>
<style>
body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px; background: #0b0b0d;
  color: #f2f2f4; font: 15px/1.5 system-ui, sans-serif; }}
main {{ width: 100%; max-width: 420px; display: grid; gap: 14px; }}
h1 {{ margin: 0; font-size: 20px; }}
.verdict {{ padding: 14px 16px; border-radius: 14px; font-weight: 700; }}
.ok {{ background: rgba(74, 222, 156, 0.12); color: #4ade9c; }}
.bad {{ background: rgba(255, 31, 58, 0.14); color: #ff4d63; }}
.words {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 0; padding: 0; list-style: none; }}
.words li {{ padding: 8px 12px; border-radius: 10px; background: rgba(255, 255, 255, 0.07); font: 600 17px/1 ui-monospace, monospace; }}
.label {{ margin: 0; font-size: 11.5px; letter-spacing: 0.12em; text-transform: uppercase; color: #8b8b94; }}
dl {{ margin: 0; display: grid; grid-template-columns: auto 1fr; gap: 4px 12px; font: 12.5px/1.4 ui-monospace, monospace; }}
dt {{ color: #8b8b94; }} dd {{ margin: 0; overflow-wrap: anywhere; }}
p {{ margin: 0; }} .note {{ font-size: 12.5px; color: #8b8b94; }}
</style></head><body><main>{body}</main></body></html>"""


def _word_list(words: List[str]) -> str:
    return "<ul class=\"words\">" + "".join(f"<li>{html.escape(w)}</li>" for w in words) + "</ul>"


@phone_router.get(PHONE_PATH, response_class=HTMLResponse)
async def phone_check(chain: int = Query(ge=1, le=MAX_CHAIN_ID), vault: str = Query(max_length=42),
                      nonce: int = Query(ge=0, le=MAX_NONCE), tx: str = Query(max_length=66),
                      intent: str = Query(max_length=66), words: str = Query(max_length=120)) -> HTMLResponse:
    """The phone side: recompute the words from the scanned inputs; never trust the words the link carries."""
    if not (re.match(ADDRESS, vault) and re.match(HASH32, tx) and re.match(HASH32, intent) and re.match(SIX_WORDS, words)):
        body = ("<h1>Vero six-word check</h1><p class=\"verdict bad\">Invalid verification code. Do not sign.</p>"
                "<p class=\"note\">The QR must carry a chain, a vault address, a nonce, two 32-byte hashes and six words.</p>")
        return HTMLResponse(_PAGE.format(body=body), status_code=400)
    carried = words.split("-")
    computed = _words(chain, vault.lower(), nonce, tx, intent)
    match = carried == computed
    verdict = ("<p class=\"verdict ok\">MATCH: these six words belong to this transaction. Compare them with your "
               "signing screen and your hardware wallet.</p>" if match else
               "<p class=\"verdict bad\">MISMATCH: the words in this code do not belong to this transaction. "
               "Do not sign.</p>")
    rows = {"Chain": chain, "Vault": vault.lower(), "Nonce": nonce, "Tx hash": tx, "Intent hash": intent}
    details = "".join(f"<dt>{k}</dt><dd>{html.escape(str(v))}</dd>" for k, v in rows.items())
    body = (f"<h1>Vero six-word check</h1>{verdict}"
            f"<p class=\"label\">Recomputed from the transaction</p>{_word_list(computed)}"
            + ("" if match else f"<p class=\"label\">Words the code claimed</p>{_word_list(carried)}")
            + f"<p class=\"label\">Transaction</p><dl>{details}</dl>"
            "<p class=\"note\">The words are keccak256(chain, vault, nonce, tx hash, intent hash) cut into six "
            "11-bit pieces of the BIP-39 list, the same recipe as the API and the VeroGuard contract.</p>")
    return HTMLResponse(_PAGE.format(body=body))
