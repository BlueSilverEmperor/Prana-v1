import pytest
from eth_abi import encode
from eth_utils import keccak
from pydantic import ValidationError

from shared.api_schemas import IntentPolicy, RiskAlert, SimulationRequest, TransactionTuple
from simulator.decoders.calldata import decode_call
from simulator.decoders.multisend_unpacker import (
    MultiSendDecodeError,
    flatten_transactions,
    unpack_multisend,
)
from simulator.hexutil import normalize_address, parse_int
from tests.helpers import (
    ALICE,
    BOB,
    EVIL,
    MAX_UINT,
    SAFE,
    USDT,
    calldata,
    hexbytes,
    multisend_calldata,
    pack_multisend,
)


class TestHexAndSchemas:
    def test_normalize_address_lowercases_valid_address(self):
        assert normalize_address("0x" + "AB" * 20) == "0x" + "ab" * 20

    def test_normalize_address_rejects_short_value(self):
        with pytest.raises(ValueError):
            normalize_address("0x1234")

    def test_parse_int_accepts_decimal_and_hex(self):
        assert parse_int("100") == 100
        assert parse_int("0x10") == 16

    def test_parse_int_rejects_negative(self):
        with pytest.raises(ValueError):
            parse_int("-1")

    def test_transaction_rejects_invalid_operation(self):
        with pytest.raises(ValidationError):
            TransactionTuple(to=ALICE, value="0", data="0x", operation=2)

    def test_transaction_normalizes_address_and_data(self):
        tx = TransactionTuple(to=ALICE.upper().replace("0X", "0x"), value="0", data="0xABCD")
        assert tx.to == ALICE
        assert tx.data == "0xabcd"

    def test_request_requires_at_least_one_transaction(self):
        with pytest.raises(ValidationError):
            SimulationRequest(chainId=1, safeAddress=SAFE, transactions=[])

    def test_models_are_immutable(self):
        policy = IntentPolicy(maxOutflowWei="5")
        with pytest.raises(ValidationError):
            policy.maxOutflowWei = "6"

    def test_alert_rejects_unknown_severity(self):
        with pytest.raises(ValidationError):
            RiskAlert(ruleId="R1", severity="SEVERE", description="x")


class TestCalldataDecoder:
    def test_decodes_erc20_transfer(self):
        data = calldata("transfer(address,uint256)", ["address", "uint256"], [ALICE, 100])
        call = decode_call(USDT, 0, hexbytes(data))
        assert call.name == "transfer"
        assert call.args["to"] == ALICE
        assert call.args["amount"] == 100

    def test_decodes_unlimited_approve(self):
        data = calldata("approve(address,uint256)", ["address", "uint256"], [EVIL, MAX_UINT])
        call = decode_call(USDT, 0, hexbytes(data))
        assert call.name == "approve"
        assert call.args["spender"] == EVIL

    def test_unknown_selector_has_no_name(self):
        call = decode_call(USDT, 0, bytes.fromhex("deadbeef"))
        assert call.name is None
        assert call.selector == "0xdeadbeef"

    def test_truncated_args_do_not_raise(self):
        selector = keccak(text="transfer(address,uint256)")[:4]
        call = decode_call(USDT, 0, selector + b"\x00" * 5)
        assert call.name is None
        assert call.malformed is True

    def test_plain_eth_send_has_empty_selector(self):
        call = decode_call(ALICE, 5, b"")
        assert call.selector == "0x"
        assert call.value == 5


class TestMultiSend:
    def test_unpacks_two_transactions(self):
        packed = pack_multisend([(0, ALICE, 1, b""), (1, BOB, 0, b"\x01\x02")])
        txs = unpack_multisend(packed)
        assert [t.to for t in txs] == [ALICE, BOB]
        assert txs[1].operation == 1
        assert txs[1].data == "0x0102"

    def test_rejects_truncated_payload(self):
        packed = pack_multisend([(0, ALICE, 1, b"\x01\x02\x03")])[:-1]
        with pytest.raises(MultiSendDecodeError):
            unpack_multisend(packed)

    def test_rejects_invalid_operation_byte(self):
        packed = bytearray(pack_multisend([(0, ALICE, 1, b"")]))
        packed[0] = 7
        with pytest.raises(MultiSendDecodeError):
            unpack_multisend(bytes(packed))

    def test_flatten_recurses_into_nested_multisend(self):
        inner_transfer = hexbytes(
            calldata("transfer(address,uint256)", ["address", "uint256"], [EVIL, 10])
        )
        inner = hexbytes(multisend_calldata([(0, USDT, 0, inner_transfer)]))
        outer = multisend_calldata([(0, ALICE, 1, b""), (1, BOB, 0, inner)])
        root = TransactionTuple(to=BOB, value="0", data=outer, operation=1)
        calls = flatten_transactions([root])
        names = [c.name for c in calls]
        assert names.count("multiSend") == 2
        transfer = next(c for c in calls if c.name == "transfer")
        assert transfer.depth == 2
        assert transfer.args["to"] == EVIL

    def test_flatten_respects_depth_limit(self):
        payload = b""
        data = hexbytes(calldata("transfer(address,uint256)", ["address", "uint256"], [EVIL, 1]))
        for _ in range(6):
            data = hexbytes(multisend_calldata([(1, BOB, 0, data)]))
        payload = "0x" + data.hex()
        root = TransactionTuple(to=BOB, value="0", data=payload, operation=1)
        with pytest.raises(MultiSendDecodeError):
            flatten_transactions([root], max_depth=4)

    def test_multisend_with_non_bytes_body_is_reported(self):
        selector = keccak(text="multiSend(bytes)")[:4]
        bad = "0x" + (selector + encode(["uint256"], [1])).hex()
        root = TransactionTuple(to=BOB, value="0", data=bad, operation=1)
        with pytest.raises(MultiSendDecodeError):
            flatten_transactions([root])
