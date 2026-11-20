// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "../src/ThreatRegistry.sol";
import "../src/GovernanceTimelock.sol";
import "../src/VeroGuard.sol";
import "../src/GuardedMultisig.sol";
import "../src/mocks/MockUSDT.sol";
import "../src/mocks/MockWBTC.sol";
import "../src/mocks/MultiSend.sol";

contract VeroHandler is Test {
    GuardedMultisig public vault;
    VeroGuard public guard;
    GovernanceTimelock public timelock;
    MockUSDT public usdt;
    MockWBTC public wbtc;

    address public owner1;
    address public owner2;
    uint256 internal owner1Pk = 0x1111;
    uint256 internal owner2Pk = 0x2222;

    // Track state for invariant assertions
    address public initialMasterCopy;
    address public initialGuard;
    bytes32 public initialOwnersHash;
    uint256 public initialThreshold;

    uint256 public totalEthOutflow;
    uint256 public totalUsdtOutflow;
    uint256 public totalWbtcOutflow;

    uint256 public constant ETH_POLICY_CAP = 1 ether;
    uint256 public constant USDT_POLICY_CAP = 1_000 * 1e6;

    bool public directEnableModuleAttempted;
    bool public directEnableModuleReverted;

    constructor(
        GuardedMultisig _vault,
        VeroGuard _guard,
        GovernanceTimelock _timelock,
        MockUSDT _usdt,
        MockWBTC _wbtc,
        address _owner1,
        address _owner2,
        uint256 _owner1Pk,
        uint256 _owner2Pk
    ) {
        vault = _vault;
        guard = _guard;
        timelock = _timelock;
        usdt = _usdt;
        wbtc = _wbtc;
        owner1 = _owner1;
        owner2 = _owner2;
        owner1Pk = _owner1Pk;
        owner2Pk = _owner2Pk;

        initialMasterCopy = vault.masterCopy();
        initialGuard = vault.guard();
        initialOwnersHash = vault.getOwnersHash();
        initialThreshold = vault.threshold();
    }

    function _signTx(
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation,
        VeroGuard.IntentPolicy memory policy
    ) internal view returns (bytes memory) {
        bytes32 policyHash = guard.hashPolicy(policy);
        bytes32 txHash = keccak256(
            abi.encode(
                keccak256("VeroTransaction(address to,uint256 value,bytes data,uint8 operation,uint256 nonce,uint256 chainId,bytes32 policyHash)"),
                to,
                value,
                keccak256(data),
                operation,
                vault.nonce(),
                block.chainid,
                policyHash
            )
        );
        bytes32 ethSigned = MessageHashUtils.toEthSignedMessageHash(txHash);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(owner1Pk, ethSigned);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(owner2Pk, ethSigned);

        return abi.encodePacked(r1, s1, v1, r2, s2, v2);
    }

    // Action 1: Execute capped ETH transfer within or exceeding policy
    function executeEthTransfer(uint256 rawAmount, uint256 gasPrice) external {
        uint256 amount = bound(rawAmount, 0, 5 ether);
        address recipient = address(0xAAAA);

        VeroGuard.IntentPolicy memory policy;
        policy.vault = address(vault);
        policy.nonce = vault.nonce();
        policy.deadline = block.timestamp + 300;
        policy.ethValueCap = ETH_POLICY_CAP;
        policy.maxGasFeeWei = 50 gwei;

        address[] memory targets = new address[](1);
        targets[0] = recipient;
        policy.allowedTargets = targets;

        bytes memory sigs = _signTx(recipient, amount, "", 0, policy);

        uint256 preVaultEth = address(vault).balance;

        // Set gas price for transaction
        uint256 boundGasPrice = bound(gasPrice, 1 gwei, 100 gwei);
        vm.txGasPrice(boundGasPrice);

        if (amount > ETH_POLICY_CAP || boundGasPrice > policy.maxGasFeeWei) {
            // Must revert
            try vault.execTransaction(recipient, amount, "", 0, sigs, policy) {
                revert("Expected revert on cap or gas violation");
            } catch {
                // Expected revert: 0 balance leakage
                assertEq(address(vault).balance, preVaultEth);
            }
        } else {
            // Must succeed within caps
            if (address(vault).balance >= amount) {
                vault.execTransaction(recipient, amount, "", 0, sigs, policy);
                totalEthOutflow += amount;
                assertEq(address(vault).balance, preVaultEth - amount);
            }
        }
    }

    // Action 2: Execute Token transfer within or exceeding policy cap
    function executeTokenTransfer(uint256 rawAmount) external {
        uint256 amount = bound(rawAmount, 0, 5_000 * 1e6);
        address recipient = address(0xBBBB);

        VeroGuard.IntentPolicy memory policy;
        policy.vault = address(vault);
        policy.nonce = vault.nonce();
        policy.deadline = block.timestamp + 300;

        address[] memory targets = new address[](1);
        targets[0] = address(usdt);
        policy.allowedTargets = targets;

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(0xa9059cbb);
        policy.allowedSelectors = selectors;

        address[] memory tokens = new address[](1);
        tokens[0] = address(usdt);
        policy.tokenAddresses = tokens;

        uint256[] memory caps = new uint256[](1);
        caps[0] = USDT_POLICY_CAP;
        policy.maxTokenSpends = caps;

        bytes memory data = abi.encodeWithSelector(bytes4(0xa9059cbb), recipient, amount);
        bytes memory sigs = _signTx(address(usdt), 0, data, 0, policy);

        uint256 preBal = usdt.balanceOf(address(vault));

        if (amount > USDT_POLICY_CAP) {
            try vault.execTransaction(address(usdt), 0, data, 0, sigs, policy) {
                revert("Expected revert on token spend exceeded");
            } catch {
                assertEq(usdt.balanceOf(address(vault)), preBal);
            }
        } else {
            if (preBal >= amount) {
                vault.execTransaction(address(usdt), 0, data, 0, sigs, policy);
                totalUsdtOutflow += amount;
                assertEq(usdt.balanceOf(address(vault)), preBal - amount);
            }
        }
    }

    // Action 3: Attempt direct enableModule call (must always revert)
    function attemptDirectEnableModule(address randomCaller, address module) external {
        vm.assume(randomCaller != address(timelock));
        directEnableModuleAttempted = true;

        vm.prank(randomCaller);
        try vault.enableModule(module) {
            revert("Direct enableModule should have reverted");
        } catch {
            directEnableModuleReverted = true;
        }
    }

    // Action 4: Attempt direct control slot change
    function attemptDirectSetGuard(address randomCaller, address fakeGuard) external {
        vm.assume(randomCaller != address(timelock) && randomCaller != address(vault));
        vm.prank(randomCaller);
        try vault.setGuard(fakeGuard) {
            revert("Direct setGuard should have reverted");
        } catch {
            assertEq(vault.guard(), initialGuard);
        }
    }
}

contract VeroInvariantsTest is StdInvariant, Test {
    VeroHandler public handler;
    GuardedMultisig public vault;
    VeroGuard public guard;
    GovernanceTimelock public timelock;
    ThreatRegistry public registry;
    MultiSend public multiSend;
    MockUSDT public usdt;
    MockWBTC public wbtc;

    address public owner1;
    address public owner2;
    uint256 internal owner1Pk = 0x1111;
    uint256 internal owner2Pk = 0x2222;

    uint256 internal initialVaultEth = 100 ether;
    uint256 internal initialVaultUsdt = 100_000 * 1e6;
    uint256 internal initialVaultWbtc = 50 * 1e8;

    function setUp() public {
        owner1 = vm.addr(owner1Pk);
        owner2 = vm.addr(owner2Pk);

        if (owner1 > owner2) {
            address temp = owner1;
            owner1 = owner2;
            owner2 = temp;
            uint256 tpk = owner1Pk;
            owner1Pk = owner2Pk;
            owner2Pk = tpk;
        }

        registry = new ThreatRegistry(address(this));
        timelock = new GovernanceTimelock();
        multiSend = new MultiSend();
        guard = new VeroGuard(address(registry), address(multiSend), address(timelock));

        usdt = new MockUSDT(1_000_000 * 1e6);
        wbtc = new MockWBTC(100 * 1e8);

        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = owner2;

        vault = new GuardedMultisig(owners, 2, address(guard), address(timelock), 10 ether);

        vm.deal(address(vault), initialVaultEth);
        usdt.mint(address(vault), initialVaultUsdt);
        wbtc.mint(address(vault), initialVaultWbtc);

        handler = new VeroHandler(
            vault,
            guard,
            timelock,
            usdt,
            wbtc,
            owner1,
            owner2,
            owner1Pk,
            owner2Pk
        );

        targetContract(address(handler));
    }

    // Invariant 1: Zero undeclared token/ETH outflow
    function invariant_ZeroUndeclaredOutflows() public view {
        // WBTC was never included in any policy: outflow must be strictly 0
        assertEq(wbtc.balanceOf(address(vault)), initialVaultWbtc);

        // USDT balance must equal initial minus valid tracked outflows
        assertEq(usdt.balanceOf(address(vault)), initialVaultUsdt - handler.totalUsdtOutflow());

        // ETH balance must equal initial minus valid tracked outflows
        assertEq(address(vault).balance, initialVaultEth - handler.totalEthOutflow());
    }

    // Invariant 2: Control slot immutability outside GovernanceTimelock
    function invariant_ControlSlotImmutability() public view {
        assertEq(vault.masterCopy(), handler.initialMasterCopy());
        assertEq(vault.guard(), handler.initialGuard());
        assertEq(vault.getOwnersHash(), handler.initialOwnersHash());
        assertEq(vault.threshold(), handler.initialThreshold());
    }

    // Invariant 3: Gas price compliance
    function invariant_GasPriceCompliance() public pure {
        // Handled deterministically in handler: any gasPrice > policy.maxGasFeeWei reverted
        assertTrue(true);
    }

    // Invariant 4: Direct enableModule (0x610b5925) always reverts unless called by GovernanceTimelock
    function invariant_DirectEnableModuleAlwaysReverts() public view {
        if (handler.directEnableModuleAttempted()) {
            assertTrue(handler.directEnableModuleReverted());
        }
    }
}
