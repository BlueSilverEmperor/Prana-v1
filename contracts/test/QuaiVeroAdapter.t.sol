// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/ThreatRegistry.sol";
import "../src/GovernanceTimelock.sol";
import "../src/QuaiVeroAdapter.sol";
import "../src/mocks/MockUSDT.sol";
import "../src/mocks/MultiSend.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @dev Minimal vault: enough of IGuardedMultisig for the post-check, plus a way to spend $QI.
contract MockQuaiVault {
    function masterCopy() external pure returns (address) { return address(0xC0DE); }
    function getOwnersHash() external pure returns (bytes32) { return keccak256("owners"); }
    function threshold() external pure returns (uint256) { return 2; }
    function guard() external pure returns (address) { return address(0); }
    function governanceTimelock() external pure returns (address) { return address(0x71); }
    /// MockUSDT, like USDT, returns nothing from transfer(), so call it without decoding a bool.
    function pay(address token, address to, uint256 amount) external {
        (bool ok,) = token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
        require(ok, "transfer failed");
    }
}

contract QuaiVeroAdapterTest is Test {
    ThreatRegistry public registry;
    GovernanceTimelock public timelock;
    MultiSend public multiSend;
    MockUSDT public qiToken;
    QuaiVeroAdapter public quaiAdapter;

    address public vault = address(0x1111111111111111111111111111111111111111);
    address public recipient = address(0x2222222222222222222222222222222222222222);
    address public stranger = address(0xBEEF);
    bytes32 public cyprus1Zone = keccak256("cyprus1");
    bytes32 public paxos1Zone = keccak256("paxos1");
    uint256 public constant QI_CAP = 500 * 10 ** 6;

    function setUp() public {
        registry = new ThreatRegistry(address(this));
        timelock = new GovernanceTimelock();
        multiSend = new MultiSend();
        qiToken = new MockUSDT(10_000_000 * 1e6);

        quaiAdapter = new QuaiVeroAdapter(
            address(registry), address(multiSend), address(timelock), address(qiToken), cyprus1Zone
        );

        _viaTimelock(address(quaiAdapter), abi.encodeCall(QuaiVeroAdapter.setVaultZone, (vault, cyprus1Zone)));
        vm.deal(vault, 100 ether);
        qiToken.mint(vault, 10_000 * 10 ** 6);
    }

    // ------------------------------------------------------------------ helpers --
    function _policy(bool declareQi) internal view returns (VeroGuard.IntentPolicy memory policy) {
        policy.vault = vault;
        policy.nonce = 0;
        policy.deadline = block.timestamp + 1 hours;
        policy.ethValueCap = 1 ether;
        if (declareQi) {
            address[] memory tokens = new address[](1);
            tokens[0] = address(qiToken);
            uint256[] memory caps = new uint256[](1);
            caps[0] = QI_CAP;
            policy.tokenAddresses = tokens;
            policy.maxTokenSpends = caps;
        }
    }

    function _check(VeroGuard.IntentPolicy memory policy) internal view {
        quaiAdapter.checkTransaction(recipient, 0, "", 0, 0, vault, policy);
    }

    function _viaTimelock(address target, bytes memory data) internal {
        bytes32 id = timelock.queueTransaction(target, 0, data);
        vm.warp(block.timestamp + timelock.DELAY());
        timelock.executeTransaction(id);
    }

    // ------------------------------------------- guard path enforces the zone --
    function test_GuardPath_AllowsBoundVaultWithDeclaredQiCap() public view {
        _check(_policy(true));
    }

    function test_GuardPath_BlocksVaultBoundToAnotherShard() public {
        vm.prank(address(timelock));
        quaiAdapter.setVaultZone(vault, paxos1Zone);
        vm.expectRevert(abi.encodeWithSelector(QuaiVeroAdapter.CrossShardReplayBlocked.selector, cyprus1Zone, paxos1Zone));
        _check(_policy(true));
    }

    function test_GuardPath_FailsClosedForUnboundVault() public {
        VeroGuard.IntentPolicy memory policy = _policy(true);
        policy.vault = address(0x3333333333333333333333333333333333333333);
        vm.expectRevert(abi.encodeWithSelector(QuaiVeroAdapter.CrossShardReplayBlocked.selector, cyprus1Zone, bytes32(0)));
        quaiAdapter.checkTransaction(recipient, 0, "", 0, 0, policy.vault, policy);
    }

    function test_GuardPath_BlocksPolicyThatDoesNotSignAQiCap() public {
        vm.expectRevert(abi.encodeWithSelector(QuaiVeroAdapter.UndeclaredQiPolicy.selector, address(qiToken)));
        _check(_policy(false));
    }

    function test_GuardPath_StillRunsBaseGuardChecks() public {
        VeroGuard.IntentPolicy memory policy = _policy(true);
        policy.deadline = block.timestamp - 1;
        vm.expectRevert(abi.encodeWithSelector(VeroGuard.IntentExpired.selector, policy.deadline, block.timestamp));
        _check(policy);
    }

    // --------------------------------------------------------- access control --
    function test_SetVaultZone_OnlyTimelock() public {
        vm.prank(stranger);
        vm.expectRevert(bytes("Unauthorized"));
        quaiAdapter.setVaultZone(vault, paxos1Zone);

        vm.prank(vault); // a vault cannot attest its own zone
        vm.expectRevert(bytes("Unauthorized"));
        quaiAdapter.setVaultZone(vault, cyprus1Zone);

        vm.expectRevert(bytes("Unauthorized")); // admin (this test) is no longer a shortcut
        quaiAdapter.setVaultZone(vault, paxos1Zone);
    }

    function test_SetVaultZone_RejectsZeroZone() public {
        vm.prank(address(timelock));
        vm.expectRevert(QuaiVeroAdapter.InvalidZone.selector);
        quaiAdapter.setVaultZone(vault, bytes32(0));
    }

    function test_SetVaultZone_WorksThroughTimelock() public {
        _viaTimelock(address(quaiAdapter), abi.encodeCall(QuaiVeroAdapter.setVaultZone, (vault, paxos1Zone)));
        assertEq(quaiAdapter.vaultZoneHash(vault), paxos1Zone);
    }

    function test_SetQiToken_OnlyTimelock() public {
        MockUSDT other = new MockUSDT(1);
        vm.expectRevert(bytes("Unauthorized")); // admin cannot swap the token instantly
        quaiAdapter.setQiToken(address(other));

        _viaTimelock(address(quaiAdapter), abi.encodeCall(QuaiVeroAdapter.setQiToken, (address(other))));
        assertEq(quaiAdapter.qiToken(), address(other));
    }

    function test_SetGovernanceTimelock_AdminCannotRepointIt() public {
        vm.expectRevert(bytes("Unauthorized")); // admin swapping in itself would bypass every timelocked setter
        quaiAdapter.setGovernanceTimelock(address(this));
    }

    function test_SetQiToken_RejectsNonContract() public {
        vm.prank(address(timelock));
        vm.expectRevert(abi.encodeWithSelector(QuaiVeroAdapter.InvalidQiToken.selector, address(0)));
        quaiAdapter.setQiToken(address(0));
    }

    function test_Constructor_RejectsZeroZoneAndNonContractQi() public {
        vm.expectRevert(QuaiVeroAdapter.InvalidZone.selector);
        new QuaiVeroAdapter(address(registry), address(multiSend), address(timelock), address(qiToken), bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(QuaiVeroAdapter.InvalidQiToken.selector, stranger));
        new QuaiVeroAdapter(address(registry), address(multiSend), address(timelock), stranger, cyprus1Zone);
    }

    // ------------------------------------------------------ $QI velocity cap --
    function _setCap(address v, uint256 cap) internal {
        vm.prank(address(timelock));
        quaiAdapter.setQiDailyCap(v, cap);
    }

    function _fundedVault() internal returns (MockQuaiVault v) {
        v = new MockQuaiVault();
        qiToken.mint(address(v), 10_000 * 10 ** 6);
    }

    function _qiPolicy(address v) internal view returns (VeroGuard.IntentPolicy memory policy) {
        policy = _policy(true);
        policy.vault = v;
        policy.maxTokenSpends[0] = 2000 * 10 ** 6; // per-transaction cap, above the daily cap used below
    }

    /// Spends `amount` of $QI from `v` and runs the guard post-check as `caller`.
    function _spend(MockQuaiVault v, uint256 amount, address caller) internal {
        VeroGuard.IntentPolicy memory policy = _qiPolicy(address(v));
        VeroGuard.VaultSnapshot memory pre = quaiAdapter.takeSnapshot(address(v), policy.tokenAddresses);
        v.pay(address(qiToken), recipient, amount);
        vm.prank(caller);
        quaiAdapter.checkAfterExecution(address(v), true, policy, pre);
    }

    function test_Velocity_PostCheckChargesOutflowToDailyCap() public {
        MockQuaiVault v = _fundedVault();
        _setCap(address(v), 1000 * 10 ** 6);
        _spend(v, 600 * 10 ** 6, address(v));
        assertEq(quaiAdapter.dailyQiSpend(address(v)), 600 * 10 ** 6);

        VeroGuard.IntentPolicy memory policy = _qiPolicy(address(v));
        VeroGuard.VaultSnapshot memory pre = quaiAdapter.takeSnapshot(address(v), policy.tokenAddresses);
        v.pay(address(qiToken), recipient, 500 * 10 ** 6);
        vm.prank(address(v));
        vm.expectRevert(abi.encodeWithSelector(QuaiVeroAdapter.QiVelocityCapExceeded.selector, 1000 * 10 ** 6, 1100 * 10 ** 6));
        quaiAdapter.checkAfterExecution(address(v), true, policy, pre);
    }

    function test_Velocity_FailsClosedWithoutCap() public {
        MockQuaiVault v = _fundedVault();
        VeroGuard.IntentPolicy memory policy = _qiPolicy(address(v));
        VeroGuard.VaultSnapshot memory pre = quaiAdapter.takeSnapshot(address(v), policy.tokenAddresses);
        v.pay(address(qiToken), recipient, 1);
        vm.prank(address(v));
        vm.expectRevert(abi.encodeWithSelector(QuaiVeroAdapter.QiVelocityCapExceeded.selector, 0, 1));
        quaiAdapter.checkAfterExecution(address(v), true, policy, pre);
    }

    function test_Velocity_UntrustedCallerCannotInflateTheCounter() public {
        MockQuaiVault v = _fundedVault();
        _setCap(address(v), 1000 * 10 ** 6);
        _spend(v, 400 * 10 ** 6, stranger); // the check still runs, but nothing is recorded
        assertEq(quaiAdapter.dailyQiSpend(address(v)), 0);
    }

    function test_Velocity_TrustedGuardCallerRecords() public {
        MockQuaiVault v = _fundedVault();
        _setCap(address(v), 1000 * 10 ** 6);
        vm.prank(address(timelock));
        quaiAdapter.setTrustedGuardCaller(stranger, true);
        _spend(v, 400 * 10 ** 6, stranger);
        assertEq(quaiAdapter.dailyQiSpend(address(v)), 400 * 10 ** 6);
    }

    function test_Velocity_WindowResetsAfterADay() public {
        MockQuaiVault v = _fundedVault();
        _setCap(address(v), 1000 * 10 ** 6);
        _spend(v, 1000 * 10 ** 6, address(v));
        vm.warp(block.timestamp + 1 days);
        _spend(v, 1000 * 10 ** 6, address(v));
        assertEq(quaiAdapter.dailyQiSpend(address(v)), 1000 * 10 ** 6);
    }

    function test_Velocity_CapSetOnlyByTimelockOrLoweredByVault() public {
        vm.prank(stranger);
        vm.expectRevert(bytes("Unauthorized"));
        quaiAdapter.setQiDailyCap(vault, type(uint256).max);

        _setCap(vault, 1000 * 10 ** 6);
        vm.prank(vault);
        quaiAdapter.setQiDailyCap(vault, 100 * 10 ** 6); // lowering is always allowed
        vm.prank(vault);
        vm.expectRevert(bytes("Unauthorized")); // raising needs the timelock
        quaiAdapter.setQiDailyCap(vault, 5000 * 10 ** 6);
    }

    // -------------------------------------------------------------- checksum --
    function test_Checksum_BindsZoneAndCaps() public view {
        bytes32 txHash = keccak256("safeTx");
        bytes32 policyHash = keccak256("policy");
        uint16[4] memory a = quaiAdapter.computeQuaiChecksumWordIndices(vault, 1, txHash, policyHash, cyprus1Zone, 5 ether, QI_CAP);
        uint16[4] memory b = quaiAdapter.computeQuaiChecksumWordIndices(vault, 1, txHash, policyHash, paxos1Zone, 5 ether, QI_CAP);
        uint16[4] memory c = quaiAdapter.computeQuaiChecksumWordIndices(vault, 1, txHash, policyHash, cyprus1Zone, 6 ether, QI_CAP);
        assertTrue(keccak256(abi.encode(a)) != keccak256(abi.encode(b)), "zone must change the words");
        assertTrue(keccak256(abi.encode(a)) != keccak256(abi.encode(c)), "cap must change the words");
        for (uint256 i = 0; i < 4; i++) assertLt(a[i], 2048);
    }
}

contract GovernanceTimelockAccessTest is Test {
    GovernanceTimelock public timelock;
    address public stranger = address(0xBEEF);
    address public target = address(0xCAFE); // has no isOwner(): not a vault

    function setUp() public {
        timelock = new GovernanceTimelock();
    }

    function test_Queue_RejectsUnapprovedProposer() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(GovernanceTimelock.UnauthorizedProposer.selector, stranger));
        timelock.queueTransaction(target, 0, "");
    }

    function test_Queue_AllowsApprovedProposer() public {
        timelock.setProposer(stranger, true);
        vm.prank(stranger);
        timelock.queueTransaction(target, 0, "");
    }

    function test_SetProposer_OnlyAdmin() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(GovernanceTimelock.UnauthorizedProposer.selector, stranger));
        timelock.setProposer(stranger, true);
    }

    function test_Veto_StrangerCannotVetoNonVaultTarget() public {
        bytes32 id = timelock.queueTransaction(target, 0, "");
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(GovernanceTimelock.UnauthorizedVeto.selector, stranger));
        timelock.vetoProposal(id);
    }

    function test_Veto_ApprovedProposerCanVetoNonVaultTarget() public {
        bytes32 id = timelock.queueTransaction(target, 0, "");
        address guardian = address(0xD00D);
        timelock.setProposer(guardian, true);
        vm.prank(guardian);
        timelock.vetoProposal(id);
        assertTrue(timelock.getProposal(id).vetoed);
    }
}
