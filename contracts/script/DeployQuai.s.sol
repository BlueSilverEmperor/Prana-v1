// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "./DeployerKey.sol";
import "../src/ThreatRegistry.sol";
import "../src/GovernanceTimelock.sol";
import "../src/QuaiVeroAdapter.sol";
import "../src/mocks/MockUSDT.sol";
import "../src/mocks/MultiSend.sol";

/// @notice Deploys QuaiVeroAdapter for one zone.
///         Env: PRIVATE_KEY (required off local Anvil), QUAI_ZONE (default "cyprus1"),
///         QI_TOKEN (required off local Anvil; locally a mock token is deployed),
///         GOVERNANCE_MULTISIG (optional: becomes the timelock's admin and only proposer).
///         Note: VeroGuard.admin stays with the deployer; it can no longer touch the adapter's
///         timelock or $QI limits, but it still controls setMultiSend/setThreatRegistry.
contract DeployQuai is DeployerKey {
    function run() external {
        uint256 deployerPrivateKey = _deployerKey();
        string memory zoneName = vm.envOr("QUAI_ZONE", string("cyprus1"));
        bytes32 zone = keccak256(bytes(zoneName));

        vm.startBroadcast(deployerPrivateKey);

        ThreatRegistry threatRegistry = new ThreatRegistry(vm.addr(deployerPrivateKey));
        console.log("Quai ThreatRegistry deployed at:", address(threatRegistry));

        GovernanceTimelock timelock = new GovernanceTimelock();
        console.log("Quai GovernanceTimelock deployed at:", address(timelock));

        MultiSend multiSend = new MultiSend();
        console.log("Quai MultiSend deployed at:", address(multiSend));

        // The mock's mint() is public, so it is only acceptable on a local chain.
        address qiToken = _isLocalChain() ? address(new MockUSDT(10_000_000 * 1e6)) : vm.envAddress("QI_TOKEN");
        console.log("Quai $QI token:", qiToken);

        QuaiVeroAdapter adapter =
            new QuaiVeroAdapter(address(threatRegistry), address(multiSend), address(timelock), qiToken, zone);
        console.log("QuaiVeroAdapter deployed at:", address(adapter));
        console.log("Enforced zone:", zoneName, vm.toString(zone));
        address multisig = vm.envOr("GOVERNANCE_MULTISIG", address(0));
        if (multisig != address(0)) {
            timelock.setProposer(multisig, true);
            timelock.setProposer(vm.addr(deployerPrivateKey), false);
            timelock.transferAdmin(multisig);
            console.log("Timelock admin and proposer handed to:", multisig);
        } else {
            console.log("WARNING: the deployer still administers the timelock; set GOVERNANCE_MULTISIG for real use.");
        }
        console.log("Next, through the timelock: setVaultZone(vault, zone) and setQiDailyCap(vault, cap) per vault.");

        vm.stopBroadcast();
    }
}
