// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/VeroGuard.sol";
import "../src/GuardedMultisig.sol";
import "../src/ThreatRegistry.sol";
import "../src/mocks/MultiSend.sol";

contract SecuritySolutionsTest is Test {
    VeroGuard public guard;
    ThreatRegistry public registry;
    MultiSend public multiSend;
    GuardedMultisig public vault;

    address public admin = address(0xAD);
    address public owner1 = address(0x11);
    address public owner2 = address(0x22);
    address public recipient = address(0x99);
    address public attacker = address(0xBAD);

    function setUp() public {
        vm.startPrank(admin);
        registry = new ThreatRegistry(admin);
        multiSend = new MultiSend();
        guard = new VeroGuard(address(registry), address(multiSend), admin);

        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = owner2;
        vault = new GuardedMultisig(owners, 2, address(guard), admin, 10 ether);
        vm.stopPrank();

        vm.deal(address(vault), 10 ether);
    }

    // 1. Solution 1: 6+ Word Checksum & On-Chain IntentHash Verification
    function test_SixWordChecksum_MatchesTheApiAndSdk() public view {
        // Known answer shared with tests/test_security_solutions.py (api-agents four_word_checksum scheme)
        uint16[6] memory indices = guard.computeSixWordChecksumIndices(
            1,
            0x5bd37a4e9b5e5A2BF8547Ad565b9dFd10126786C,
            42,
            bytes32(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa),
            bytes32(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
        );
        uint16[6] memory expected = [uint16(1848), 1530, 1918, 617, 521, 504];
        for (uint256 i = 0; i < 6; i++) {
            assertEq(indices[i], expected[i], "six-word checksum differs from the API/SDK scheme");
        }
    }

    function test_OnChain_IntentHash_Enforcement() public {
        bytes32 safeTxHash = keccak256("safeTx");
        bytes32 validIntentHash = keccak256(abi.encode(address(vault), uint256(0), safeTxHash));
        
        // Valid intent hash passes
        assertTrue(guard.verifyIntentHash(address(vault), 0, safeTxHash, validIntentHash));
        guard.enforceIntentHash(address(vault), 0, safeTxHash, validIntentHash);

        // Tampered intent hash reverts
        bytes32 tamperedHash = keccak256("tampered");
        assertFalse(guard.verifyIntentHash(address(vault), 0, safeTxHash, tamperedHash));
        vm.expectRevert(abi.encodeWithSelector(VeroGuard.IntentHashMismatch.selector, tamperedHash, validIntentHash));
        guard.enforceIntentHash(address(vault), 0, safeTxHash, tamperedHash);
    }

    // 2. Solution 2: Pre/Post Balance & Storage Snapshot Diffs
    function test_PrePost_BalanceStorage_SnapshotDiff() public {
        address[] memory tokens = new address[](0);
        VeroGuard.VaultSnapshot memory preSnap = guard.takeSnapshot(address(vault), tokens);

        VeroGuard.IntentPolicy memory policy;
        policy.vault = address(vault);
        policy.ethValueCap = 1 ether;

        // ETH outflow within cap passes
        vm.deal(address(vault), 9.5 ether); // 0.5 ETH outflow <= 1 ETH cap
        VeroGuard.BalanceStorageDiff memory diff = guard.computeAndVerifySnapshotDiff(address(vault), preSnap, policy);
        assertEq(diff.ethOutflow, 0.5 ether);
        assertTrue(diff.controlSlotsIntact);

        // ETH outflow exceeding cap reverts
        vm.deal(address(vault), 8.0 ether); // 2.0 ETH outflow > 1 ETH cap
        vm.expectRevert(abi.encodeWithSelector(VeroGuard.EthValueCapExceeded.selector, 1 ether, 2 ether));
        guard.computeAndVerifySnapshotDiff(address(vault), preSnap, policy);
    }

    // 3. Solution 3: Slot 0 / EIP-1967 Immutability & Recursive MultiSend
    function test_Slot0_Immutability_Check() public view {
        address currentMasterCopy = vault.masterCopy();
        assertTrue(guard.verifySlot0Immutability(address(vault), currentMasterCopy));
    }

    function test_Recursive_MultiSend_Unpacking() public {
        // Build an inner batch that attempts to call a blacklisted address
        vm.prank(admin);
        registry.setBlacklist(attacker, true);

        bytes memory innerCall = abi.encodePacked(
            uint8(0),               // op: CALL
            attacker,               // to: blacklisted
            uint256(0),             // value
            uint256(0),             // dataLength
            bytes("")               // data
        );

        // Package innerCall into a parent multiSend batch
        bytes memory parentBatch = abi.encodePacked(
            uint8(0),
            recipient,
            uint256(0),
            uint256(0),
            bytes("")
        );

        // Inner nested multiSend
        bytes memory nestedMultiSendCalldata = abi.encodeWithSelector(0x8d80ff0a, innerCall);
        bytes memory nestedCall = abi.encodePacked(
            uint8(0),
            address(multiSend),
            uint256(0),
            uint256(nestedMultiSendCalldata.length),
            nestedMultiSendCalldata
        );

        bytes memory fullBatch = abi.encodePacked(parentBatch, nestedCall);

        VeroGuard.IntentPolicy memory policy;
        policy.vault = address(vault);
        policy.allowDelegateCall = true;
        policy.deadline = block.timestamp + 1 hours;

        address[] memory targets = new address[](2);
        targets[0] = address(multiSend);
        targets[1] = recipient;
        policy.allowedTargets = targets;

        // Recursive unpacking catches blacklisted target inside nested batch!
        vm.expectRevert(abi.encodeWithSelector(VeroGuard.TargetBlacklisted.selector, attacker));
        guard.checkTransaction(
            address(multiSend),
            0,
            abi.encodeWithSelector(0x8d80ff0a, fullBatch),
            1, // delegatecall
            0,
            owner1,
            policy
        );
    }
}
