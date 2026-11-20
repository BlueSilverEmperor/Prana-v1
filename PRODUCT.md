# Vero: product truth

**What it is.** Vero is a transaction firewall for multisig treasuries and AI-agent wallets. Before anyone signs,
it simulates the exact bytes, compares the real effect with what the signer declared, and explains any difference in
plain English. An on-chain guard (VeroGuard) reverts the transaction if the executed effect goes beyond the declaration.

**The problem.** In the WazirX (July 2024, about $230M) and Bybit (February 2025, about $1.5B) incidents, signers
approved transactions whose screen said one thing while the bytes did another. The keys were never stolen; the meaning
shown to the signers was.

**Who it is for.**
- Treasury and exchange teams running Safe-style multisigs (3-of-5 signers).
- Developers integrating wallets and AI agents (REST API, MCP tool, TypeScript guard SDK).
- Hackathon judges evaluating "Know what you're signing" (The Big Hack 2.0, Track 02, Problem B1).

**What the visitor must believe.** A signature should only authorise what the signer declared, and Vero makes that
true: it shows the real effect before signing and enforces the declaration on-chain.

**The one action.** Check a transaction (the live check, wired to `POST /v1/simulate`).

**Real capabilities (verified in this repo).**
- Deterministic engine, rules R1–R12 (approvals, permits, logic swaps, unknown delegatecall, owners/threshold, guard,
  modules, EIP-7702, undeclared recipient, outflow cap, lookalike tokens, threat registry) plus shields (address
  poisoning, gas ceiling, chain binding, vault-share, bridges). No AI decides a verdict.
- Fork simulation on Anvil (debug_traceCall), static calldata analysis as fallback.
- 4-word BIP-39 checksum for a second-device check; Ed25519-signed CERT-In receipts.
- On-chain: VeroGuard pre/post checks, 24h governance timelock with single-signer veto, emergency pause, 13 Foundry
  exploit replays and 4 fuzzed invariants (12,800 calls) passing.
- Benchmark: 55 team-authored scenarios, Full Vero detection 30/30 (Wilson 95% CI 88.6–100%), 0/25 false positives.

**Honesty constraints.** No invented customers, quotes, logos or statistics. Benchmark numbers are always shown with
their intervals and the note that scenarios are team-authored. Engine latency is quoted only as measured.

**Voice.** Plain, exact, calm. Names the threat without drama. Short sentences.

**Brand palette (fixed by the client).** Ink navy 60%, pearl white 30%, electric coral 10%.
