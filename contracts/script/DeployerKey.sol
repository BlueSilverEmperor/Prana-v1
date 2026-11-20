// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";

/// @notice Resolves the broadcast key. PRIVATE_KEY is required everywhere except a local Anvil chain,
///         where the well-known Anvil account #0 key is allowed as a convenience. That key is public:
///         anything it deploys or administers on a real network belongs to whoever sweeps it first.
abstract contract DeployerKey is Script {
    uint256 internal constant LOCAL_ANVIL_CHAIN_ID = 31337;
    uint256 private constant ANVIL_ACCOUNT_0_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function _deployerKey() internal view returns (uint256) {
        if (vm.envExists("PRIVATE_KEY")) return vm.envUint("PRIVATE_KEY");
        require(block.chainid == LOCAL_ANVIL_CHAIN_ID, "PRIVATE_KEY is required outside local Anvil (chain 31337)");
        return ANVIL_ACCOUNT_0_KEY;
    }

    function _isLocalChain() internal view returns (bool) {
        return block.chainid == LOCAL_ANVIL_CHAIN_ID;
    }
}
