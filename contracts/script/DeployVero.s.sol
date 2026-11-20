// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "./DeployerKey.sol";
import "../src/ThreatRegistry.sol";
import "../src/GovernanceTimelock.sol";
import "../src/VeroGuard.sol";
import "../src/GuardedMultisig.sol";
import "../src/mocks/MockUSDT.sol";
import "../src/mocks/MockWBTC.sol";
import "../src/mocks/MultiSend.sol";

contract DeployVero is DeployerKey {
    function run() external {
        uint256 deployerPrivateKey = _deployerKey();
        address deployer = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy ThreatRegistry
        ThreatRegistry threatRegistry = new ThreatRegistry(deployer);
        console.log("ThreatRegistry deployed at:", address(threatRegistry));

        // 2. Deploy GovernanceTimelock
        GovernanceTimelock timelock = new GovernanceTimelock();
        console.log("GovernanceTimelock deployed at:", address(timelock));

        // 3. Deploy MultiSend
        MultiSend multiSend = new MultiSend();
        console.log("MultiSend deployed at:", address(multiSend));

        // 4. Deploy VeroGuard
        VeroGuard guard = new VeroGuard(
            address(threatRegistry),
            address(multiSend),
            address(timelock)
        );
        console.log("VeroGuard deployed at:", address(guard));

        // 5. Deploy Mocks
        MockUSDT usdt = new MockUSDT(1_000_000 * 1e6);
        console.log("MockUSDT deployed at:", address(usdt));

        MockWBTC wbtc = new MockWBTC(100 * 1e8);
        console.log("MockWBTC deployed at:", address(wbtc));

        // 6. Deploy GuardedMultisig (3-of-5 setup)
        address[] memory owners = new address[](5);
        owners[0] = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
        owners[1] = 0x90F79bf6EB2c4f870365E785982E1f101E93b906;
        owners[2] = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        owners[3] = 0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65;
        owners[4] = 0x9965507d1a55bcc2695c58ba16Fb37D819b0A4dF;

        // Sort owners ascending for strict ordering requirement
        for (uint256 i = 0; i < owners.length - 1; i++) {
            for (uint256 j = 0; j < owners.length - i - 1; j++) {
                if (owners[j] > owners[j + 1]) {
                    address temp = owners[j];
                    owners[j] = owners[j + 1];
                    owners[j + 1] = temp;
                }
            }
        }

        uint256 threshold = 3;
        uint256 dailySpendCap = 10 ether;

        GuardedMultisig vault = new GuardedMultisig(
            owners,
            threshold,
            address(guard),
            address(timelock),
            dailySpendCap
        );
        console.log("GuardedMultisig deployed at:", address(vault));

        address recoveryVault = address(0x999999cf1046e68e36E1aA2E0E07105eDDD1f08E);
        guard.setRecoveryVault(address(vault), recoveryVault);
        console.log("RecoveryVault set to:", recoveryVault);

        vm.stopBroadcast();
    }
}
