// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/ThreatRegistry.sol";
import "../src/GovernanceTimelock.sol";
import "../src/QuaiVeroAdapter.sol";
import "../src/mocks/MockUSDT.sol";
import "../src/mocks/MultiSend.sol";

contract QuaiVeroAdapterTest is Test {
    ThreatRegistry public registry;
    GovernanceTimelock public timelock;
    MultiSend public multiSend;
    MockUSDT public qiToken;
    QuaiVeroAdapter public quaiAdapter;

    address public vault = address(0x1111111111111111111111111111111111111111);
    bytes32 public cyprus1Zone = keccak256("cyprus1");
    bytes32 public paxos1Zone = keccak256("paxos1");

    function setUp() public {
        registry = new ThreatRegistry(address(this));
        timelock = new GovernanceTimelock();
        multiSend = new MultiSend();
        qiToken = new MockUSDT(10_000_000 * 1e6); // Use MockUSDT as $QI mock token

        quaiAdapter = new QuaiVeroAdapter(
            address(registry),
            address(multiSend),
            address(timelock),
            address(qiToken)
        );

        quaiAdapter.setVaultZone(vault, cyprus1Zone);
        vm.deal(vault, 100 ether);
        qiToken.mint(vault, 10_000 * 10**6);
    }

    function test_Quai_CrossShardReplay_Blocked() public {
        // Shard zone mismatch must revert with CrossShardReplayBlocked
        QuaiVeroAdapter.QuaiSnapshot memory preSnap = quaiAdapter.takeQuaiSnapshot(vault);
        assertEq(preSnap.zoneHash, cyprus1Zone);

        // Verify on same zone passes
        quaiAdapter.verifyQuaiSnapshot(vault, preSnap, cyprus1Zone, 10 ether, 1000 * 10**6);

        // Replay attempt on a different zone (e.g. Paxos-1) reverts
        vm.expectRevert(
            abi.encodeWithSelector(
                QuaiVeroAdapter.CrossShardReplayBlocked.selector,
                cyprus1Zone,
                paxos1Zone
            )
        );
        quaiAdapter.verifyQuaiSnapshot(vault, preSnap, paxos1Zone, 10 ether, 1000 * 10**6);
    }

    function test_Quai_DualAssetSnapshot_CapEnforcement() public {
        QuaiVeroAdapter.QuaiSnapshot memory preSnap = quaiAdapter.takeQuaiSnapshot(vault);

        // Native $QUAI drop within cap
        vm.prank(vault);
        payable(address(0xcafe)).transfer(5 ether);
        quaiAdapter.verifyQuaiSnapshot(vault, preSnap, cyprus1Zone, 5 ether, 1000 * 10**6);

        // Native $QUAI drop exceeding cap reverts
        vm.expectRevert(
            abi.encodeWithSelector(
                QuaiVeroAdapter.QuaiSpendCapExceeded.selector,
                4 ether,
                5 ether
            )
        );
        quaiAdapter.verifyQuaiSnapshot(vault, preSnap, cyprus1Zone, 4 ether, 1000 * 10**6);

        // $QI token drop within cap
        vm.prank(vault);
        qiToken.transfer(address(0xcafe), 500 * 10**6);
        quaiAdapter.verifyQuaiSnapshot(vault, preSnap, cyprus1Zone, 10 ether, 500 * 10**6);

        // $QI token drop exceeding cap reverts
        vm.expectRevert(
            abi.encodeWithSelector(
                QuaiVeroAdapter.QiSpendCapExceeded.selector,
                400 * 10**6,
                500 * 10**6
            )
        );
        quaiAdapter.verifyQuaiSnapshot(vault, preSnap, cyprus1Zone, 10 ether, 400 * 10**6);
    }

    function test_Quai_QiVelocityLimit_24hWindow() public {
        uint256 dailyCap = 1000 * 10**6;

        // First spend of 600 QI succeeds
        quaiAdapter.recordQiVelocitySpend(vault, 600 * 10**6, dailyCap);
        assertEq(quaiAdapter.dailyQiSpend(vault), 600 * 10**6);

        // Second spend of 500 QI exceeds 1000 QI daily cap
        vm.expectRevert(
            abi.encodeWithSelector(
                QuaiVeroAdapter.QiVelocityCapExceeded.selector,
                dailyCap,
                1100 * 10**6
            )
        );
        quaiAdapter.recordQiVelocitySpend(vault, 500 * 10**6, dailyCap);

        // After 24 hours, velocity limit resets
        vm.warp(block.timestamp + 1 days + 1);
        quaiAdapter.recordQiVelocitySpend(vault, 500 * 10**6, dailyCap);
        assertEq(quaiAdapter.dailyQiSpend(vault), 500 * 10**6);
    }

    function test_Quai_Checksum_Derivation() public view {
        uint16[4] memory indices = quaiAdapter.computeQuaiChecksumWordIndices(
            vault,
            1,
            bytes32(uint256(0xaaa)),
            bytes32(uint256(0xbbb)),
            cyprus1Zone,
            10 ether,
            1000 * 10**6
        );

        for (uint256 i = 0; i < 4; i++) {
            assertTrue(indices[i] < 2048);
        }
    }
}
