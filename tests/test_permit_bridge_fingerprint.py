import json

import pytest
from eth_abi import encode
from eth_utils import keccak

from simulator.decoders.erc7730_and_8213 import (
    DescriptorError,
    calldata_digest,
    format_with_descriptor,
    load_descriptor,
)
from simulator.decoders.permit_and_bridge_decoders import (
    decode_bridge_call,
    decode_permit_call,
    decode_permit_typed_data,
    describe_permit,
)
from tests.helpers import ALICE, EVIL, MAX_UINT, SAFE, USDC, USDT, calldata, hexbytes

NOW = 1_700_000_000
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"


class TestPermitDecoders:
    def test_eip2612_permit_call_unlimited(self):
        data = calldata(
            "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
            ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"],
            [SAFE, EVIL, MAX_UINT, NOW + 3600, 27, b"\x00" * 32, b"\x00" * 32],
        )
        info = decode_permit_call(USDT, hexbytes(data))
        assert info.kind == "eip2612"
        assert info.spender == EVIL
        assert info.token == USDT
        assert info.unlimited is True

    def test_permit2_approve_call(self):
        data = calldata(
            "approve(address,address,uint160,uint48)",
            ["address", "address", "uint160", "uint48"],
            [USDC, EVIL, 2**160 - 1, NOW + 86400],
        )
        info = decode_permit_call(PERMIT2, hexbytes(data))
        assert info.kind == "permit2-approve"
        assert info.token == USDC
        assert info.unlimited is True

    def test_permit2_permit_single_call(self):
        details = (USDC, 500, NOW + 100, 0)
        data = calldata(
            "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
            ["address", "((address,uint160,uint48,uint48),address,uint256)", "bytes"],
            [SAFE, (details, EVIL, NOW + 100), b"\x01"],
        )
        info = decode_permit_call(PERMIT2, hexbytes(data))
        assert info.kind == "permit2-single"
        assert info.amount == 500
        assert info.unlimited is False

    def test_non_permit_call_returns_none(self):
        data = calldata("transfer(address,uint256)", ["address", "uint256"], [ALICE, 1])
        assert decode_permit_call(USDT, hexbytes(data)) is None

    def test_typed_data_permit_single(self):
        typed = {
            "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": PERMIT2},
            "primaryType": "PermitSingle",
            "message": {
                "details": {"token": USDC, "amount": str(2**160 - 1), "expiration": NOW + 10, "nonce": 3},
                "spender": EVIL,
                "sigDeadline": NOW + 10,
            },
        }
        infos = decode_permit_typed_data(typed)
        assert len(infos) == 1
        assert infos[0].chain_id == 1
        assert infos[0].nonce == 3
        assert infos[0].unlimited is True

    def test_typed_data_permit_batch_returns_each_token(self):
        typed = {
            "domain": {"chainId": 1},
            "primaryType": "PermitBatch",
            "message": {
                "details": [
                    {"token": USDC, "amount": "1", "expiration": NOW, "nonce": 0},
                    {"token": USDT, "amount": "2", "expiration": NOW, "nonce": 0},
                ],
                "spender": EVIL,
                "sigDeadline": NOW,
            },
        }
        assert [i.token for i in decode_permit_typed_data(typed)] == [USDC, USDT]

    def test_typed_data_eip2612(self):
        typed = {
            "domain": {"chainId": 5, "verifyingContract": USDT},
            "primaryType": "Permit",
            "message": {"owner": SAFE, "spender": EVIL, "value": "10", "nonce": "1", "deadline": str(NOW)},
        }
        info = decode_permit_typed_data(typed)[0]
        assert info.token == USDT and info.amount == 10 and info.chain_id == 5

    def test_typed_data_unknown_primary_type_rejected(self):
        with pytest.raises(ValueError):
            decode_permit_typed_data({"domain": {}, "primaryType": "Mail", "message": {}})

    def test_describe_permit_mentions_unlimited_and_expiry(self):
        typed = {
            "domain": {"chainId": 1, "verifyingContract": USDT},
            "primaryType": "Permit",
            "message": {"owner": SAFE, "spender": EVIL, "value": str(MAX_UINT), "nonce": 0, "deadline": NOW + 2 * 86400},
        }
        text = describe_permit(decode_permit_typed_data(typed)[0], now=NOW)
        assert "UNLIMITED" in text
        assert "expires in 2 days" in text

    def test_describe_permit_reports_expired(self):
        typed = {
            "domain": {"chainId": 1, "verifyingContract": USDT},
            "primaryType": "Permit",
            "message": {"owner": SAFE, "spender": EVIL, "value": "1", "nonce": 0, "deadline": NOW - 5},
        }
        assert "already expired" in describe_permit(decode_permit_typed_data(typed)[0], now=NOW)


class TestBridgeDecoders:
    def test_wormhole_transfer_tokens(self):
        recipient = b"\x00" * 12 + bytes.fromhex(ALICE[2:])
        data = calldata(
            "transferTokens(address,uint256,uint16,bytes32,uint256,uint32)",
            ["address", "uint256", "uint16", "bytes32", "uint256", "uint32"],
            [USDC, 1000, 23, recipient, 0, 1],
        )
        info = decode_bridge_call(EVIL, 0, hexbytes(data), source_chain_id=1)
        assert info.protocol == "wormhole"
        assert info.dest_chain_id == 42161
        assert info.recipient == ALICE
        assert info.amount == 1000

    def test_ccip_send(self):
        message = (encode(["address"], [ALICE]), b"", [(USDC, 77)], "0x" + "00" * 20, b"")
        data = calldata(
            "ccipSend(uint64,(bytes,bytes,(address,uint256)[],address,bytes))",
            ["uint64", "(bytes,bytes,(address,uint256)[],address,bytes)"],
            [4949039107694359620, message],
        )
        info = decode_bridge_call(EVIL, 0, hexbytes(data), source_chain_id=1)
        assert info.protocol == "ccip"
        assert info.dest_chain_id == 42161
        assert info.token == USDC and info.amount == 77

    def test_op_stack_deposit_erc20_to_known_bridge(self):
        bridge = "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1"
        data = calldata(
            "depositERC20To(address,address,address,uint256,uint32,bytes)",
            ["address", "address", "address", "uint256", "uint32", "bytes"],
            [USDC, "0x" + "11" * 20, ALICE, 5, 200000, b""],
        )
        info = decode_bridge_call(bridge, 0, hexbytes(data), source_chain_id=1)
        assert info.protocol == "op-stack"
        assert info.dest_chain_id == 10

    def test_op_stack_deposit_eth_uses_msg_value(self):
        data = calldata("depositETHTo(address,uint32,bytes)", ["address", "uint32", "bytes"], [ALICE, 1, b""])
        info = decode_bridge_call(EVIL, 9, hexbytes(data), source_chain_id=1)
        assert info.amount == 9 and info.token is None and info.dest_chain_id is None

    def test_layerzero_oft_send(self):
        send_param = (30184, b"\x00" * 12 + bytes.fromhex(ALICE[2:]), 50, 49, b"", b"", b"")
        data = calldata(
            "send((uint32,bytes32,uint256,uint256,bytes,bytes,bytes),(uint256,uint256),address)",
            ["(uint32,bytes32,uint256,uint256,bytes,bytes,bytes)", "(uint256,uint256)", "address"],
            [send_param, (1, 0), SAFE],
        )
        info = decode_bridge_call(USDC, 0, hexbytes(data), source_chain_id=1)
        assert info.protocol == "layerzero" and info.dest_chain_id == 8453 and info.token == USDC

    def test_non_bridge_returns_none(self):
        data = calldata("transfer(address,uint256)", ["address", "uint256"], [ALICE, 1])
        assert decode_bridge_call(USDT, 0, hexbytes(data), source_chain_id=1) is None


DESCRIPTOR = {
    "context": {"contract": {"deployments": [{"chainId": 1, "address": USDT}]}},
    "metadata": {"owner": "Tether", "token": {"ticker": "USDT", "decimals": 6}},
    "display": {
        "formats": {
            "transfer(address to,uint256 amount)": {
                "intent": "Send tokens",
                "fields": [
                    {"path": "to", "label": "Recipient", "format": "addressName"},
                    {"path": "amount", "label": "Amount", "format": "tokenAmount"},
                ],
            }
        }
    },
}


class TestFingerprintAndClearSigning:
    def test_digest_is_length_prefixed_keccak(self):
        data = bytes.fromhex("a9059cbb00")
        expected = "0x" + keccak((len(data)).to_bytes(32, "big") + data).hex()
        assert calldata_digest(data) == expected

    def test_digest_differs_for_different_calldata(self):
        assert calldata_digest(b"\x01") != calldata_digest(b"\x01\x00")

    def test_descriptor_formats_transfer(self):
        descriptor = load_descriptor(json.dumps(DESCRIPTOR))
        data = calldata("transfer(address,uint256)", ["address", "uint256"], [ALICE, 1_500_000])
        result = format_with_descriptor(descriptor, USDT, hexbytes(data), chain_id=1)
        assert result.intent == "Send tokens"
        assert ("Amount", "1.5 USDT") in result.fields
        assert result.fields[0][0] == "Recipient"

    def test_descriptor_ignores_other_deployment(self):
        descriptor = load_descriptor(DESCRIPTOR)
        data = calldata("transfer(address,uint256)", ["address", "uint256"], [ALICE, 1])
        assert format_with_descriptor(descriptor, USDC, hexbytes(data), chain_id=1) is None

    def test_descriptor_without_display_rejected(self):
        with pytest.raises(DescriptorError):
            load_descriptor({"context": {}})
