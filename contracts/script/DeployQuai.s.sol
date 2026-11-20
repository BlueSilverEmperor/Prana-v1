// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/ThreatRegistry.sol";
import "../src/GovernanceTimelock.sol";
import "../src/QuaiVeroAdapter.sol";
import "../src/mocks/MockUSDT.sol";
import "../src/mocks/MultiSend.sol";

contract DeployQuai is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envOr(
            "PRIVATE_KEY",
            uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)
        );
        address deployer = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy Core Infrastructure
        ThreatRegistry threatRegistry = new ThreatRegistry(deployer);
        console.log("Quai ThreatRegistry deployed at:", address(threatRegistry));

        GovernanceTimelock timelock = new GovernanceTimelock();
        console.log("Quai GovernanceTimelock deployed at:", address(timelock));

        MultiSend multiSend = new MultiSend();
        console.log("Quai MultiSend deployed at:", address(multiSend));

        // 2. Deploy Mock $QI Energy Dollar Token
        MockUSDT qiToken = new MockUSDT(10_000_000 * 1e6);
        console.log("Quai Mock $QI Token deployed at:", address(qiToken));

        // 3. Deploy QuaiVeroAdapter
        QuaiVeroAdapter adapter = new QuaiVeroAdapter(
            address(threatRegistry),
            address(multiSend),
            address(timelock),
            address(qiToken)
        );
        console.log("QuaiVeroAdapter deployed at:", address(adapter));

        // 4. Default configuration: bind deployer to Cyprus-1 shard [0, 0]
        bytes32 cyprus1Zone = keccak256("cyprus1");
        adapter.setVaultZone(deployer, cyprus1Zone);
        console.log("Deployer bound to Cyprus-1 zone:", vm.toString(cyprus1Zone));

        vm.stopBroadcast();
    }
}
