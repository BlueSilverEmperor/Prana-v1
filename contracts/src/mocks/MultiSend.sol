// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MultiSend
 * @notice Standard Gnosis Safe MultiSend contract that decodes and executes packed transactions.
 * Transactions format:
 * `operation` (1 byte, 0 = CALL, 1 = DELEGATECALL)
 * `to` (20 bytes, address)
 * `value` (32 bytes, uint256)
 * `dataLength` (32 bytes, uint256)
 * `data` (dataLength bytes)
 */
contract MultiSend {
    address public immutable self;

    constructor() {
        self = address(this);
    }

    /**
     * @notice Sends multiple transactions, reverting if any fails.
     * @param transactions Encoded transactions bytes.
     */
    function multiSend(bytes memory transactions) public payable {
        // MultiSend is meant to be called via DELEGATECALL from a multisig / safe
        uint256 length = transactions.length;
        uint256 i = 0;

        while (i < length) {
            uint8 operation;
            address to;
            uint256 value;
            uint256 dataLength;

            assembly {
                // Read operation (1 byte)
                operation := shr(248, mload(add(transactions, add(0x20, i))))
                // Read target address (20 bytes)
                to := shr(96, mload(add(transactions, add(0x21, i))))
                // Read value (32 bytes)
                value := mload(add(transactions, add(0x35, i)))
                // Read dataLength (32 bytes)
                dataLength := mload(add(transactions, add(0x55, i)))
            }

            i += 85;
            require(i + dataLength <= length, "MultiSend: invalid data length");

            bytes memory callData = new bytes(dataLength);
            for (uint256 j = 0; j < dataLength; j++) {
                callData[j] = transactions[i + j];
            }
            i += dataLength;

            bool success;
            if (operation == 0) {
                // Standard CALL
                (success, ) = to.call{value: value}(callData);
            } else if (operation == 1) {
                // DELEGATECALL
                (success, ) = to.delegatecall(callData);
            } else {
                revert("MultiSend: unsupported operation");
            }

            if (!success) {
                assembly {
                    // Bubble up revert reason if available
                    let ptr := mload(0x40)
                    let size := returndatasize()
                    returndatacopy(ptr, 0, size)
                    revert(ptr, size)
                }
            }
        }
    }
}
