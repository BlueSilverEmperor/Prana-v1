from shared.api_schemas import IntentPolicy, SimulationRequest, TransactionTuple, UserOperation
from simulator.context import EngineContext
from simulator.engine import analyze_offline
from simulator.renderer.plain_english_renderer import render_summary
from tests.helpers import ALICE, BOB, EVIL, MAX_UINT, SAFE, USDC, USDT, calldata, hexbytes, multisend_calldata

MULTISEND = "0x40a2accbd92bca938b02010e17a5b8929b49130d"
NOW = 1_700_000_000
CTX = EngineContext(now=NOW)


def tx(to, data="0x", value="0", operation=0, **kw):
    return TransactionTuple(to=to, data=data, value=value, operation=operation, **kw)


def req(*txs, policy=None, **kw):
    return SimulationRequest(chainId=1, safeAddress=SAFE, transactions=list(txs), intentPolicy=policy, **kw)


def ids(result):
    return {a.ruleId for a in result.alerts}


def blocking(result):
    return {a.ruleId for a in result.alerts if a.severity in ("HIGH", "CRITICAL")}


def transfer(to, amount):
    return calldata("transfer(address,uint256)", ["address", "uint256"], [to, amount])


POLICY_ALICE_100 = IntentPolicy(allowedRecipients=[ALICE], maxOutflowWei="100", allowedTokens=[USDT])


class TestTwelveRules:
    def test_benign_declared_transfer_has_no_blocking_alert(self):
        result = analyze_offline(req(tx(USDT, transfer(ALICE, 100)), policy=POLICY_ALICE_100), CTX)
        assert blocking(result) == set()
        assert result.success is True

    def test_r1_unlimited_undeclared_approval_is_critical(self):
        data = calldata("approve(address,uint256)", ["address", "uint256"], [EVIL, MAX_UINT])
        result = analyze_offline(req(tx(USDT, data), policy=POLICY_ALICE_100), CTX)
        alert = next(a for a in result.alerts if a.ruleId == "R1")
        assert alert.severity == "CRITICAL"

    def test_r1_set_approval_for_all(self):
        data = calldata("setApprovalForAll(address,bool)", ["address", "bool"], [EVIL, True])
        assert "R1" in blocking(analyze_offline(req(tx(USDT, data)), CTX))

    def test_r1_revoke_is_not_flagged(self):
        data = calldata("approve(address,uint256)", ["address", "uint256"], [EVIL, 0])
        assert "R1" not in ids(analyze_offline(req(tx(USDT, data)), CTX))

    def test_r2_unlimited_permit_call(self):
        data = calldata(
            "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"],
            [SAFE, EVIL, MAX_UINT, NOW + 10, 27, b"\x00" * 32, b"\x00" * 32],
        )
        assert "R2" in blocking(analyze_offline(req(tx(USDT, data)), CTX))

    def test_r3_upgrade_to_on_safe(self):
        data = calldata("upgradeTo(address)", ["address"], [EVIL])
        assert "R3" in blocking(analyze_offline(req(tx(SAFE, data)), CTX))

    def test_r4_delegatecall_to_unknown_target(self):
        result = analyze_offline(req(tx(EVIL, "0x12345678", operation=1)), CTX)
        assert "R4" in blocking(result)

    def test_r4_canonical_multisend_is_trusted(self):
        batch = multisend_calldata([(0, USDT, 0, hexbytes(transfer(ALICE, 50)))])
        result = analyze_offline(req(tx(MULTISEND, batch, operation=1), policy=POLICY_ALICE_100), CTX)
        assert "R4" not in ids(result)
        assert blocking(result) == set()

    def test_r4_fake_multisend_address_flagged(self):
        batch = multisend_calldata([(0, USDT, 0, hexbytes(transfer(ALICE, 50)))])
        result = analyze_offline(req(tx(EVIL, batch, operation=1), policy=POLICY_ALICE_100), CTX)
        assert "R4" in blocking(result)

    def test_r5_add_owner_and_lower_threshold(self):
        data = calldata("addOwnerWithThreshold(address,uint256)", ["address", "uint256"], [EVIL, 1])
        result = analyze_offline(req(tx(SAFE, data)), CTX)
        assert next(a for a in result.alerts if a.ruleId == "R5").severity == "CRITICAL"

    def test_r5_transfer_ownership_of_administered_contract(self):
        data = calldata("transferOwnership(address)", ["address"], [EVIL])
        assert "R5" in blocking(analyze_offline(req(tx(BOB, data)), CTX))

    def test_r6_guard_removal(self):
        data = calldata("setGuard(address)", ["address"], ["0x" + "00" * 20])
        assert next(a for a in analyze_offline(req(tx(SAFE, data)), CTX).alerts if a.ruleId == "R6").severity == "CRITICAL"

    def test_r7_enable_module(self):
        data = calldata("enableModule(address)", ["address"], [EVIL])
        assert "R7" in blocking(analyze_offline(req(tx(SAFE, data)), CTX))

    def test_r8_eip7702_authorization(self):
        auth = [{"chainId": 1, "address": EVIL, "nonce": 0}]
        assert "R8" in blocking(analyze_offline(req(tx(ALICE, authorizationList=auth)), CTX))

    def test_r9_undeclared_recipient(self):
        result = analyze_offline(req(tx(USDT, transfer(EVIL, 10)), policy=POLICY_ALICE_100), CTX)
        assert "R9" in blocking(result)

    def test_r9_undeclared_token(self):
        result = analyze_offline(req(tx(USDC, transfer(ALICE, 10)), policy=POLICY_ALICE_100), CTX)
        assert "R9" in blocking(result)

    def test_r10_outflow_above_cap(self):
        result = analyze_offline(req(tx(USDT, transfer(ALICE, 101)), policy=POLICY_ALICE_100), CTX)
        assert "R10" in blocking(result)

    def test_r10_hidden_batch_transfer(self):
        batch = multisend_calldata([
            (0, USDT, 0, hexbytes(transfer(ALICE, 100))),
            (0, USDT, 0, hexbytes(transfer(EVIL, 10**12))),
        ])
        result = analyze_offline(req(tx(MULTISEND, batch, operation=1), policy=POLICY_ALICE_100), CTX)
        assert {"R9", "R10"} <= blocking(result)

    def test_r11_lookalike_token(self):
        fake = "0x" + "fa" * 20
        ctx = EngineContext(now=NOW, token_meta={fake: ("USDC", 6)})
        policy = IntentPolicy(allowedRecipients=[ALICE], maxOutflowWei="100", allowedTokens=[fake])
        assert "R11" in blocking(analyze_offline(req(tx(fake, transfer(ALICE, 1)), policy=policy), ctx))

    def test_r12_threat_registry_hit(self):
        ctx = EngineContext(now=NOW, threat_registry=frozenset({EVIL}))
        policy = IntentPolicy(allowedRecipients=[EVIL], maxOutflowWei="100", allowedTokens=[USDT])
        assert "R12" in blocking(analyze_offline(req(tx(USDT, transfer(EVIL, 1)), policy=policy), ctx))

    def test_eth_value_to_undeclared_address(self):
        policy = IntentPolicy(allowedRecipients=[ALICE], maxOutflowWei="10", allowedTokens=["ETH"])
        assert "R9" in blocking(analyze_offline(req(tx(EVIL, value="5"), policy=policy), CTX))

    def test_bridge_recipient_must_be_declared(self):
        recipient = b"\x00" * 12 + bytes.fromhex(EVIL[2:])
        data = calldata(
            "transferTokens(address,uint256,uint16,bytes32,uint256,uint32)",
            ["address", "uint256", "uint16", "bytes32", "uint256", "uint32"],
            [USDT, 50, 23, recipient, 0, 1],
        )
        bridge = "0x" + "b1" * 20
        policy = IntentPolicy(allowedRecipients=[ALICE, bridge], maxOutflowWei="100", allowedTokens=[USDT])
        result = analyze_offline(req(tx(bridge, data), policy=policy), CTX)
        assert "R9" in blocking(result)
        assert result.stateDiff.bridgeTransfers[0].destChainId == 42161

    def test_malformed_multisend_is_critical_not_crash(self):
        body = bytes([9]) + b"\x00" * 84  # operation byte 9 is invalid
        bad = calldata("multiSend(bytes)", ["bytes"], [body])
        result = analyze_offline(req(tx(MULTISEND, bad, operation=1)), CTX)
        assert result.success is False
        assert "DECODE" in blocking(result)

    def test_risk_score_and_digest(self):
        data = calldata("enableModule(address)", ["address"], [EVIL])
        result = analyze_offline(req(tx(SAFE, data)), CTX)
        assert result.metrics.riskScore >= 60
        assert len(result.calldataDigests) == 1


class TestShields:
    def test_p33_address_poisoning(self):
        lookalike = ALICE[:6] + "00" * 16 + ALICE[-4:]
        ctx = EngineContext(now=NOW, contacts=frozenset({ALICE}))
        policy = IntentPolicy(allowedRecipients=[lookalike], maxOutflowWei="100", allowedTokens=[USDT])
        assert "P33-POISON" in blocking(analyze_offline(req(tx(USDT, transfer(lookalike, 1)), policy=policy), ctx))

    def test_p33_exact_contact_is_clean(self):
        ctx = EngineContext(now=NOW, contacts=frozenset({ALICE}))
        assert "P33-POISON" not in ids(analyze_offline(req(tx(USDT, transfer(ALICE, 1)), policy=POLICY_ALICE_100), ctx))

    def test_b26_vault_share_and_first_recipient(self):
        ctx = EngineContext(now=NOW, safe_balances={USDT: 100}, recipient_history=frozenset({BOB}))
        result = analyze_offline(req(tx(USDT, transfer(ALICE, 95)), policy=POLICY_ALICE_100), ctx)
        assert "B26-VAULT-SHARE" in blocking(result)
        assert "B26-FIRST-RECIPIENT" in ids(result)

    def test_b26_new_contract(self):
        ctx = EngineContext(now=NOW, deploy_times={USDT: NOW - 600})
        assert "B26-NEW-CONTRACT" in ids(analyze_offline(req(tx(USDT, transfer(ALICE, 1)), policy=POLICY_ALICE_100), ctx))

    def test_g28_gas_ceiling(self):
        op = UserOperation(sender=SAFE, callData="0x1234", callGasLimit="3000000", verificationGasLimit="1000000",
                           preVerificationGas="50000", maxFeePerGas=str(10**11), maxPriorityFeePerGas="1",
                           paymasterAndData="0x" + "aa" * 20)
        result = analyze_offline(req(tx(ALICE), userOperation=op), CTX)
        assert {"G28-GAS-CEILING", "G28-GRIEFING"} <= blocking(result)

    def test_c31_wrong_network(self):
        ctx = EngineContext(now=NOW, expected_chain_id=10)
        assert "C31-CHAIN" in blocking(analyze_offline(req(tx(USDT, transfer(ALICE, 1))), ctx))

    def test_c31_universal_7702_authorization(self):
        auth = [{"chainId": 0, "address": EVIL, "nonce": 0}]
        assert "C31-CHAIN" in blocking(analyze_offline(req(tx(ALICE, authorizationList=auth)), CTX))


class TestRenderer:
    def test_renders_transfer_with_symbol_and_decimals(self):
        result = analyze_offline(req(tx(USDT, transfer(ALICE, 100_000_000)), policy=IntentPolicy(
            allowedRecipients=[ALICE], maxOutflowWei=str(10**9), allowedTokens=[USDT])), CTX)
        assert any("Transfer 100 USDT to" in line for line in result.plainEnglishSummary)

    def test_renders_unlimited_approval(self):
        data = calldata("approve(address,uint256)", ["address", "uint256"], [EVIL, MAX_UINT])
        lines = analyze_offline(req(tx(USDT, data)), CTX).plainEnglishSummary
        assert any("UNLIMITED USDT" in line for line in lines)

    def test_renders_threshold_change(self):
        data = calldata("changeThreshold(uint256)", ["uint256"], [1])
        lines = analyze_offline(req(tx(SAFE, data)), CTX).plainEnglishSummary
        assert any("threshold" in line.lower() and "1" in line for line in lines)

    def test_renders_delegatecall_warning(self):
        lines = analyze_offline(req(tx(EVIL, "0x12345678", operation=1)), CTX).plainEnglishSummary
        assert any(line.startswith("Warning: Execution results in delegatecall") for line in lines)

    def test_render_is_deterministic(self):
        r = req(tx(USDT, transfer(ALICE, 7)), policy=POLICY_ALICE_100)
        a, b = analyze_offline(r, CTX), analyze_offline(r, CTX)
        assert render_summary(a.stateDiff, a.alerts, CTX) == render_summary(b.stateDiff, b.alerts, CTX)

    def test_label_mismatch_called_out(self):
        result = analyze_offline(req(tx(EVIL, "0x12345678", operation=1), label="Send 100 USDT"), CTX)
        assert any("differs from what the interface claimed" in line for line in result.plainEnglishSummary)
