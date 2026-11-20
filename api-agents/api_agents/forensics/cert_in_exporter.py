"""
CERT-In Aligned Forensic Incident Exporter (#20).
Generates cryptographically signed forensic receipts (JSON + PDF).

Design Invariant:
- Signed with Ed25519.
- Clearly states: "CERT-In Incident Reporting Aligned Specification".
  Does not claim an official governmental schema.
"""

import datetime
import json
import os
from dataclasses import asdict, dataclass, field
import logging
import secrets
from typing import Dict, List, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from api_agents.forensics.signer import generate_keypair, sign, verify

SIGNING_SEED_ENV = "VERO_RECEIPT_SIGNING_SEED"
SEED_BYTES = 32
_logger = logging.getLogger(__name__)


def _load_signing_seed() -> bytes:
    """32-byte Ed25519 seed from VERO_RECEIPT_SIGNING_SEED (hex). Never hardcode it in source:
    a public seed lets anyone forge "signed" receipts. Without the variable, a random per-process key
    is used, so receipts verify against the public key they carry but change on restart."""
    raw = os.environ.get(SIGNING_SEED_ENV, "").strip()
    if not raw:
        _logger.warning("%s not set; using an ephemeral receipt signing key", SIGNING_SEED_ENV)
        return secrets.token_bytes(SEED_BYTES)
    try:
        seed = bytes.fromhex(raw.removeprefix("0x"))
    except ValueError as exc:
        raise ValueError(f"{SIGNING_SEED_ENV} must be {SEED_BYTES} bytes of hex") from exc
    if len(seed) != SEED_BYTES:
        raise ValueError(f"{SIGNING_SEED_ENV} must be {SEED_BYTES} bytes of hex, got {len(seed)}")
    return seed


_DEFAULT_SK, _DEFAULT_PK = generate_keypair(_load_signing_seed())


@dataclass
class ForensicReceiptData:
    receipt_id: str
    schema_profile: str = "CERT-In Incident Reporting Aligned Specification (April 2022 Guidelines)"
    reported_at: str = ""
    reporting_system: str = "Project Vero Firewall Sensor / api-agents"
    chain_id: int = 1
    safe_address: str = ""
    target_contract: str = ""
    raw_tx_hash: str = ""
    intent_hash: str = ""
    four_word_checksum: str = ""
    decision: str = "BLOCK"
    risk_score: int = 100
    flags: List[str] = field(default_factory=list)
    human_warnings: List[str] = field(default_factory=list)
    signature_algorithm: str = "Ed25519 (RFC 8032)"
    ed25519_signature: str = ""
    public_key: str = ""


def create_forensic_receipt(
    safe_address: str,
    target_contract: str,
    raw_tx_hash: str,
    intent_hash: str,
    four_word_checksum: str,
    decision: str,
    risk_score: int,
    flags: List[str],
    human_warnings: List[str],
    chain_id: int = 1,
    signing_key: bytes = _DEFAULT_SK,
) -> ForensicReceiptData:
    """
    Creates and cryptographically signs a forensic incident audit receipt.
    """
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    receipt_id = f"VERO-CERTIN-{raw_tx_hash[2:10].upper()}"

    receipt = ForensicReceiptData(
        receipt_id=receipt_id,
        reported_at=now_iso,
        chain_id=chain_id,
        safe_address=safe_address,
        target_contract=target_contract,
        raw_tx_hash=raw_tx_hash,
        intent_hash=intent_hash,
        four_word_checksum=four_word_checksum,
        decision=decision,
        risk_score=risk_score,
        flags=flags,
        human_warnings=human_warnings,
        public_key=_DEFAULT_PK.hex(),
    )

    # Canonical signable payload string
    signable_bytes = (
        f"{receipt_id}|{now_iso}|{chain_id}|{safe_address.lower()}|{raw_tx_hash.lower()}|{decision}|{risk_score}"
    ).encode("utf-8")

    sig_bytes = sign(signable_bytes, signing_key)
    receipt.ed25519_signature = sig_bytes.hex()
    return receipt


def export_receipt_to_json(receipt: ForensicReceiptData, filepath: str) -> str:
    """Serializes receipt to JSON file."""
    data = asdict(receipt)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return filepath


def export_receipt_to_pdf(receipt: ForensicReceiptData, filepath: str) -> str:
    """
    Generates a professional 1-page PDF forensic audit document using ReportLab.
    """
    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()

    header_style = ParagraphStyle(
        "HeaderStyle",
        parent=styles["Heading1"],
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#1e293b"),
    )
    sub_style = ParagraphStyle(
        "SubStyle",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#64748b"),
    )
    label_style = ParagraphStyle(
        "LabelStyle",
        parent=styles["Normal"],
        fontSize=9,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0f172a"),
    )
    val_style = ParagraphStyle(
        "ValStyle",
        parent=styles["Normal"],
        fontSize=9,
        fontName="Courier",
        textColor=colors.HexColor("#334155"),
    )

    story = []

    # Title
    story.append(Paragraph("PROJECT VERO // FORENSIC INCIDENT AUDIT RECEIPT", header_style))
    story.append(Paragraph(f"Schema: {receipt.schema_profile}", sub_style))
    story.append(Spacer(1, 15))

    # Summary Table
    table_data = [
        [Paragraph("Receipt ID:", label_style), Paragraph(receipt.receipt_id, val_style)],
        [Paragraph("Timestamp (UTC):", label_style), Paragraph(receipt.reported_at, val_style)],
        [Paragraph("Firewall Decision:", label_style), Paragraph(f"<b>{receipt.decision}</b> (Risk Score: {receipt.risk_score}/100)", val_style)],
        [Paragraph("Protected Safe / Multisig:", label_style), Paragraph(receipt.safe_address, val_style)],
        [Paragraph("Target Contract Address:", label_style), Paragraph(receipt.target_contract, val_style)],
        [Paragraph("Raw Tx Hash:", label_style), Paragraph(receipt.raw_tx_hash, val_style)],
        [Paragraph("Intent Digest:", label_style), Paragraph(receipt.intent_hash, val_style)],
        [Paragraph("BIP-39 Checksum (44-bit):", label_style), Paragraph(receipt.four_word_checksum, val_style)],
        [Paragraph("Detected Flags:", label_style), Paragraph(", ".join(receipt.flags) or "None", val_style)],
        [Paragraph("Ed25519 Signature:", label_style), Paragraph(receipt.ed25519_signature[:48] + "...", val_style)],
        [Paragraph("Public Key:", label_style), Paragraph(receipt.public_key, val_style)],
    ]

    t = Table(table_data, colWidths=[160, 380])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(t)
    story.append(Spacer(1, 15))

    # Warnings Section
    story.append(Paragraph("DETERMINISTIC FORENSIC WARNINGS & EVIDENCE:", label_style))
    story.append(Spacer(1, 5))
    for w in receipt.human_warnings:
        story.append(Paragraph(f"• {w}", val_style))
    if not receipt.human_warnings:
        story.append(Paragraph("• No anomalous telemetry observed.", val_style))

    doc.build(story)
    return filepath
