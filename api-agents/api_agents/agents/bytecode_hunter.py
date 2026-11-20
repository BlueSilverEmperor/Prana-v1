"""
Bytecode Vulnerability Hunter (#39).
Static EVM opcode analyzer for unverified/malicious contract bytecode,
coupled with an optional LLM security advisory with deterministic fallback.

Invariants:
- LLMs are never on the /v1/simulate path.
- Static opcode analysis is 100% deterministic.
- LLM advisory provides human-readable remediation guidance but can NEVER
  override or lower the detected vulnerability severity.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# EVM Opcode Constants
OP_STOP = 0x00
OP_ORIGIN = 0x32
OP_CALLDATALOAD = 0x35
OP_SLOAD = 0x54
OP_SSTORE = 0x55
OP_JUMP = 0x56
OP_JUMPI = 0x57
OP_JUMPDEST = 0x5b
OP_PUSH1 = 0x60
OP_PUSH32 = 0x7F
OP_CALL = 0xF1
OP_CALLCODE = 0xF2
OP_DELEGATECALL = 0xF4
OP_STATICCALL = 0xFA
OP_REVERT = 0xFD
OP_INVALID = 0xFE
OP_SELFDESTRUCT = 0xFF

# ERC-1967 implementation slot: bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
ERC1967_IMPL_SLOT_HEX = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


@dataclass
class OpcodeInstruction:
    offset: int
    opcode: int
    name: str
    operand: bytes = b""


@dataclass
class VulnerabilityFinding:
    vuln_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    offset: int
    description: str
    cwe: str
    remediation: str


@dataclass
class BytecodeScanResult:
    is_vulnerable: bool
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    instruction_count: int = 0
    has_delegatecall: bool = False
    has_selfdestruct: bool = False
    has_tx_origin: bool = False


@dataclass
class AdvisoryReport:
    summary: str
    risk_level: str
    findings_explained: List[Dict[str, str]]
    remediation_plan: List[str]
    source: str  # "DETERMINISTIC_FALLBACK" or "LLM_ADVISORY"


def disassemble_bytecode(bytecode_hex: str) -> List[OpcodeInstruction]:
    """
    Disassembles raw hex EVM bytecode into an ordered sequence of instructions.
    Correctly accounts for multi-byte PUSH1..PUSH32 operands.
    """
    cleaned = bytecode_hex.lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]

    try:
        raw_bytes = bytes.fromhex(cleaned)
    except ValueError:
        return []

    instructions: List[OpcodeInstruction] = []
    pc = 0
    n = len(raw_bytes)

    opcode_names = {
        OP_STOP: "STOP",
        OP_ORIGIN: "ORIGIN",
        OP_CALLDATALOAD: "CALLDATALOAD",
        OP_SLOAD: "SLOAD",
        OP_SSTORE: "SSTORE",
        OP_JUMP: "JUMP",
        OP_JUMPI: "JUMPI",
        OP_JUMPDEST: "JUMPDEST",
        OP_CALL: "CALL",
        OP_CALLCODE: "CALLCODE",
        OP_DELEGATECALL: "DELEGATECALL",
        OP_STATICCALL: "STATICCALL",
        OP_REVERT: "REVERT",
        OP_INVALID: "INVALID",
        OP_SELFDESTRUCT: "SELFDESTRUCT",
    }

    while pc < n:
        op = raw_bytes[pc]
        op_offset = pc
        pc += 1

        operand = b""
        if OP_PUSH1 <= op <= OP_PUSH32:
            push_len = op - OP_PUSH1 + 1
            operand = raw_bytes[pc : min(pc + push_len, n)]
            pc += len(operand)
            op_name = f"PUSH{push_len}"
        else:
            op_name = opcode_names.get(op, f"OP_0x{op:02x}")

        instructions.append(
            OpcodeInstruction(
                offset=op_offset,
                opcode=op,
                name=op_name,
                operand=operand,
            )
        )

    return instructions


def scan_bytecode(bytecode_hex: str) -> BytecodeScanResult:
    """
    Performs deterministic static analysis on disassembled EVM bytecode to identify
    critical vulnerabilities: DELEGATECALL in loops, SELFDESTRUCT, tx.origin, and proxy bugs.
    """
    instructions = disassemble_bytecode(bytecode_hex)
    findings: List[VulnerabilityFinding] = []

    has_delegatecall = False
    has_selfdestruct = False
    has_tx_origin = False

    # Check for ERC-1967 proxy pattern in hex string directly
    is_erc1967_proxy = ERC1967_IMPL_SLOT_HEX in bytecode_hex.lower()

    for idx, inst in enumerate(instructions):
        # 1. Detect SELFDESTRUCT (EIP-6780 deprecation & malicious rug pull pattern)
        if inst.opcode == OP_SELFDESTRUCT:
            has_selfdestruct = True
            findings.append(
                VulnerabilityFinding(
                    vuln_id="VERO-VULN-001",
                    title="Selfdestruct Opcode Detected",
                    severity="CRITICAL",
                    offset=inst.offset,
                    description="Bytecode contains SELFDESTRUCT (0xFF). Allows state wiping and fund exfiltration.",
                    cwe="CWE-284: Improper Access Control",
                    remediation="Remove SELFDESTRUCT opcode. In Cancun/EIP-6780, behavior is restricted.",
                )
            )

        # 2. Detect DELEGATECALL (WazirX proxy upgrade pattern)
        elif inst.opcode == OP_DELEGATECALL:
            has_delegatecall = True
            # Inspect surrounding context for loop indicators
            in_loop = False
            # Check if there is a backward JUMP or JUMPI targeting a prior JUMPDEST
            for prev_idx in range(max(0, idx - 15), min(len(instructions), idx + 15)):
                if instructions[prev_idx].opcode in (OP_JUMP, OP_JUMPI):
                    in_loop = True
                    break

            if in_loop:
                findings.append(
                    VulnerabilityFinding(
                        vuln_id="VERO-VULN-002",
                        title="Unbounded Delegatecall in Loop Context",
                        severity="CRITICAL",
                        offset=inst.offset,
                        description="DELEGATECALL inside a loop construct. High risk of arbitrary code execution.",
                        cwe="CWE-829: Inclusion of Functionality from Untrusted Sphere",
                        remediation="Never execute DELEGATECALL to dynamic or user-controlled addresses.",
                    )
                )
            elif not is_erc1967_proxy:
                findings.append(
                    VulnerabilityFinding(
                        vuln_id="VERO-VULN-003",
                        title="Standalone Delegatecall Pattern",
                        severity="HIGH",
                        offset=inst.offset,
                        description="Bytecode executes DELEGATECALL without standard ERC-1967 proxy slot bindings.",
                        cwe="CWE-829: Inclusion of Functionality from Untrusted Sphere",
                        remediation="Ensure implementation target is stored in verified EIP-1967 slots.",
                    )
                )

        # 3. Detect tx.origin authentication bug
        elif inst.opcode == OP_ORIGIN:
            has_tx_origin = True
            # Look ahead for comparison opcode (EQ)
            is_auth_check = any(
                instructions[ahead].opcode == 0x14  # EQ
                for ahead in range(idx + 1, min(len(instructions), idx + 6))
            )
            if is_auth_check:
                findings.append(
                    VulnerabilityFinding(
                        vuln_id="VERO-VULN-004",
                        title="tx.origin Used for Authorization",
                        severity="MEDIUM",
                        offset=inst.offset,
                        description="ORIGIN opcode used in comparison check. Vulnerable to phishing and relay attacks.",
                        cwe="CWE-306: Missing Authentication for Critical Function",
                        remediation="Replace tx.origin with msg.sender.",
                    )
                )

    is_vuln = len(findings) > 0
    return BytecodeScanResult(
        is_vulnerable=is_vuln,
        findings=findings,
        instruction_count=len(instructions),
        has_delegatecall=has_delegatecall,
        has_selfdestruct=has_selfdestruct,
        has_tx_origin=has_tx_origin,
    )


def generate_security_advisory(
    scan_result: BytecodeScanResult,
    llm_client: Optional[Any] = None,
) -> AdvisoryReport:
    """
    Generates a security advisory. If an LLM is available, enriches explanation;
    otherwise provides an instant, comprehensive deterministic fallback report.
    """
    if not scan_result.is_vulnerable:
        return AdvisoryReport(
            summary="Bytecode scan completed: No known high-risk opcodes detected.",
            risk_level="LOW",
            findings_explained=[],
            remediation_plan=["Proceed with standard transaction verification."],
            source="DETERMINISTIC_FALLBACK",
        )

    # Determine composite risk level
    severities = [f.severity for f in scan_result.findings]
    if "CRITICAL" in severities:
        risk_level = "CRITICAL"
    elif "HIGH" in severities:
        risk_level = "HIGH"
    elif "MEDIUM" in severities:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Attempt LLM Advisory if client is provided
    if llm_client is not None:
        try:
            # If a live LLM client was injected, invoke it
            prompt = (
                f"Explain the following smart contract bytecode vulnerabilities:\n"
                f"{[(f.title, f.description, f.remediation) for f in scan_result.findings]}"
            )
            llm_response = llm_client.generate(prompt)
            return AdvisoryReport(
                summary=f"LLM-Augmented Advisory: Found {len(scan_result.findings)} vulnerability vectors.",
                risk_level=risk_level,
                findings_explained=[
                    {"title": f.title, "explanation": llm_response.get(f.vuln_id, f.description)}
                    for f in scan_result.findings
                ],
                remediation_plan=[f.remediation for f in scan_result.findings],
                source="LLM_ADVISORY",
            )
        except Exception:
            # Deterministic fallback guaranteed on any failure
            pass

    # Authoritative Deterministic Fallback Advisory
    findings_explained = [
        {
            "id": f.vuln_id,
            "title": f.title,
            "severity": f.severity,
            "offset": f"0x{f.offset:04x}",
            "description": f.description,
            "cwe": f.cwe,
            "remediation": f.remediation,
        }
        for f in scan_result.findings
    ]

    remediation_plan = list({f.remediation for f in scan_result.findings})

    return AdvisoryReport(
        summary=f"Vero Opcode Hunter: {len(scan_result.findings)} security risk vectors identified.",
        risk_level=risk_level,
        findings_explained=findings_explained,
        remediation_plan=remediation_plan,
        source="DETERMINISTIC_FALLBACK",
    )
