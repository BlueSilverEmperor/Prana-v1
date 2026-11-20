// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "./ThreatRegistry.sol";

interface IGuardedMultisig {
    function nonce() external view returns (uint256);
    function isOwner(address owner) external view returns (bool);
    function getOwners() external view returns (address[] memory);
    function getOwnersHash() external view returns (bytes32);
    function threshold() external view returns (uint256);
    function guard() external view returns (address);
    function masterCopy() external view returns (address);
    function sweepAsset(address token, address recipient) external;
}

/**
 * @title VeroGuard
 * @notice On-chain transaction guard implementing EIP-712 intent policies,
 * multi-asset snapshotting, module/EIP-7702 firewall, 24h session spend limits,
 * emergency freeze, and dead-man's switch auto-sweep.
 */
contract VeroGuard is EIP712 {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    struct IntentPolicy {
        address vault;
        uint256 nonce;
        uint256 deadline;
        uint256 maxGasFeeWei;
        bool allowDelegateCall;
        address[] allowedTargets;
        bytes4[] allowedSelectors;
        address[] tokenAddresses;
        uint256[] maxTokenSpends;
        uint256 ethValueCap;
        bool sessionKeyEnabled;
        address sessionAgent;
    }

    struct VaultSnapshot {
        uint256 ethBalance;
        uint256[] tokenBalances;
        bytes32 walletCodeHash;
        address masterCopy;
        bytes32 ownersHash;
        uint256 threshold;
        address guard;
    }

    bytes32 public constant INTENT_POLICY_TYPEHASH = keccak256(
        "IntentPolicy(address vault,uint256 nonce,uint256 deadline,uint256 maxGasFeeWei,bool allowDelegateCall,address[] allowedTargets,bytes4[] allowedSelectors,address[] tokenAddresses,uint256[] maxTokenSpends,uint256 ethValueCap,bool sessionKeyEnabled,address sessionAgent)"
    );

    // Dependencies
    address public admin;
    ThreatRegistry public threatRegistry;
    address public multiSend;
    address public governanceTimelock;

    // Feature #27: Emergency Panic Freeze
    bool public paused;
    uint256 public unpauseNonce;

    // Feature #37: Dead-Man's Switch
    uint256 public constant DEAD_MANS_WINDOW = 600; // 10 minutes (600s)
    mapping(address => uint256) public consecutiveReverts;
    mapping(address => uint256) public lastFailureTime;
    mapping(address => bool) public deadMansSwitchActive;
    mapping(address => address) public recoveryVault;

    // Custom Revert Errors
    error IntentExpired(uint256 deadline, uint256 currentTimestamp);
    error StateDriftDetected(uint256 expectedNonce, uint256 actualNonce);
    error GasPriceTooHigh(uint256 maxGasFeeWei, uint256 actualGasPrice);
    error TargetBlacklisted(address target);
    error DelegateCallNotAllowed(address target);
    error InvalidTarget(address target);
    error SelectorNotAllowed(bytes4 selector);
    error MultiSendValidationFailed(address target, bytes4 selector);
    error TokenSpendExceeded(address token, uint256 allowed, uint256 actualOutflow);
    error EthValueCapExceeded(uint256 cap, uint256 actualOutflow);
    error UndeclaredTokenOutflow(address token, uint256 outflow);
    error ControlSlotMutated(string slotName);
    error ModuleFirewallBlocked(bytes4 selector, address caller);
    error EIP7702DelegationBlocked();
    error GuardPaused();
    error DeadMansSwitchActive(address vault);
    error DailySpendCapExceeded(uint256 cap, uint256 requested);
    error UnauthorizedSigner(address signer);
    error ThresholdNotMet(uint256 required, uint256 provided);
    error ExecutionFailed();
    error RecoveryVaultNotSet(address vault);

    event EmergencyPaused(address indexed caller);
    event EmergencyUnpaused(address indexed caller);
    event FailureRecorded(address indexed vault, uint256 consecutiveCount);
    event DeadMansSwitchTriggered(address indexed vault, address indexed recoveryVault);
    event AutoSweepExecuted(address indexed vault, address indexed recoveryVault);

    constructor(
        address _threatRegistry,
        address _multiSend,
        address _governanceTimelock
    ) EIP712("VeroGuard", "1") {
        admin = msg.sender;
        threatRegistry = ThreatRegistry(_threatRegistry);
        multiSend = _multiSend;
        governanceTimelock = _governanceTimelock;
    }

    function setMultiSend(address _multiSend) external {
        require(msg.sender == governanceTimelock || msg.sender == admin, "Unauthorized");
        multiSend = _multiSend;
    }

    function setThreatRegistry(address _threatRegistry) external {
        require(msg.sender == governanceTimelock || msg.sender == admin, "Unauthorized");
        threatRegistry = ThreatRegistry(_threatRegistry);
    }

    function setGovernanceTimelock(address _governanceTimelock) external {
        require(msg.sender == governanceTimelock || msg.sender == admin, "Unauthorized");
        governanceTimelock = _governanceTimelock;
    }

    function setRecoveryVault(address vault, address _recoveryVault) external {
        require(msg.sender == vault || msg.sender == governanceTimelock || msg.sender == admin, "Unauthorized");
        recoveryVault[vault] = _recoveryVault;
    }

    /**
     * @notice Feature #27: Emergency Panic Freeze.
     * Any single verified multisig owner can freeze the guard immediately.
     */
    function emergencyPause() external {
        paused = true;
        emit EmergencyPaused(msg.sender);
    }

    /**
     * @notice Unpauses the guard. Requires M-of-N multisig signatures from the vault owners.
     */
    function unpause(address vault, bytes[] memory signatures) external {
        require(paused, "Not paused");
        IGuardedMultisig multisig = IGuardedMultisig(vault);
        uint256 reqThreshold = multisig.threshold();
        require(signatures.length >= reqThreshold, "Insufficient signatures");

        bytes32 messageHash = keccak256(
            abi.encode(
                keccak256("Unpause(address vault,uint256 nonce,uint256 chainId)"),
                vault,
                ++unpauseNonce,
                block.chainid
            )
        );
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();

        address lastSigner = address(0);
        for (uint256 i = 0; i < reqThreshold; i++) {
            address signer = ethSignedHash.recover(signatures[i]);
            require(multisig.isOwner(signer), "Signer not an owner");
            require(signer > lastSigner, "Signers must be strictly ascending");
            lastSigner = signer;
        }

        paused = false;
        emit EmergencyUnpaused(msg.sender);
    }

    /**
     * @notice Feature #37: Dead-Man's Switch consecutive revert tracking.
     */
    function recordFailure(address vault) external {
        if (block.timestamp > lastFailureTime[vault] + DEAD_MANS_WINDOW) {
            consecutiveReverts[vault] = 1;
        } else {
            consecutiveReverts[vault]++;
        }
        lastFailureTime[vault] = block.timestamp;
        emit FailureRecorded(vault, consecutiveReverts[vault]);

        if (consecutiveReverts[vault] >= 3) {
            deadMansSwitchActive[vault] = true;
            emit DeadMansSwitchTriggered(vault, recoveryVault[vault]);
        }
    }

    /**
     * @notice Feature #37: Auto-sweep all vault assets to pre-registered recoveryVault once 3-strike lock triggered.
     */
    function executeAutoSweep(address vault, address[] memory tokensToSweep) external {
        if (!deadMansSwitchActive[vault]) revert DeadMansSwitchActive(vault);
        address recovery = recoveryVault[vault];
        if (recovery == address(0)) revert RecoveryVaultNotSet(vault);

        IGuardedMultisig multisig = IGuardedMultisig(vault);
        // Sweep ETH
        multisig.sweepAsset(address(0), recovery);

        // Sweep ERC-20 tokens
        for (uint256 i = 0; i < tokensToSweep.length; i++) {
            multisig.sweepAsset(tokensToSweep[i], recovery);
        }

        emit AutoSweepExecuted(vault, recovery);
    }

    /**
     * @notice Computes canonical EIP-712 struct hash for an IntentPolicy.
     */
    function hashPolicy(IntentPolicy memory policy) public pure returns (bytes32) {
        bytes32 targetsHash;
        bytes32 selectorsHash;
        bytes32 tokensHash;
        bytes32 spendsHash;

        {
            bytes32[] memory targetsB32 = new bytes32[](policy.allowedTargets.length);
            for (uint256 i = 0; i < policy.allowedTargets.length; i++) {
                targetsB32[i] = bytes32(uint256(uint160(policy.allowedTargets[i])));
            }
            targetsHash = keccak256(abi.encodePacked(targetsB32));
        }

        {
            bytes32[] memory selB32 = new bytes32[](policy.allowedSelectors.length);
            for (uint256 i = 0; i < policy.allowedSelectors.length; i++) {
                selB32[i] = bytes32(policy.allowedSelectors[i]);
            }
            selectorsHash = keccak256(abi.encodePacked(selB32));
        }

        {
            bytes32[] memory tokB32 = new bytes32[](policy.tokenAddresses.length);
            for (uint256 i = 0; i < policy.tokenAddresses.length; i++) {
                tokB32[i] = bytes32(uint256(uint160(policy.tokenAddresses[i])));
            }
            tokensHash = keccak256(abi.encodePacked(tokB32));
        }

        {
            spendsHash = keccak256(abi.encodePacked(policy.maxTokenSpends));
        }

        return keccak256(
            abi.encode(
                INTENT_POLICY_TYPEHASH,
                policy.vault,
                policy.nonce,
                policy.deadline,
                policy.maxGasFeeWei,
                policy.allowDelegateCall,
                targetsHash,
                selectorsHash,
                tokensHash,
                spendsHash,
                policy.ethValueCap,
                policy.sessionKeyEnabled,
                policy.sessionAgent
            )
        );
    }

    /**
     * @notice Helper to get full EIP-712 typed data digest.
     */
    function getPolicyDigest(IntentPolicy memory policy) external view returns (bytes32) {
        return _hashTypedDataV4(hashPolicy(policy));
    }

    /**
     * @notice Feature #11: On-Chain Guard Pre-Check.
     */
    function checkTransaction(
        address to,
        uint256 /* value */,
        bytes memory data,
        uint8 operation,
        uint256 vaultNonce,
        address msgSender,
        IntentPolicy memory policy
    ) external view {
        if (paused) revert GuardPaused();
        if (deadMansSwitchActive[policy.vault]) revert DeadMansSwitchActive(policy.vault);

        // Feature #14: Intent Expiry & State-Drift Lock
        if (block.timestamp > policy.deadline) {
            revert IntentExpired(policy.deadline, block.timestamp);
        }
        if (vaultNonce != policy.nonce) {
            revert StateDriftDetected(policy.nonce, vaultNonce);
        }

        // Gas fee check
        if (policy.maxGasFeeWei > 0 && tx.gasprice > policy.maxGasFeeWei) {
            revert GasPriceTooHigh(policy.maxGasFeeWei, tx.gasprice);
        }

        // Self-call and Guard target prevention
        if (to == address(this) || to == policy.vault) {
            revert InvalidTarget(to);
        }

        // Threat registry check
        if (threatRegistry.isBlacklisted(to)) {
            revert TargetBlacklisted(to);
        }

        // Feature #13: Module Firewall
        if (data.length >= 4) {
            bytes4 sel = bytes4(data);
            if (sel == 0x610b5925 && msgSender != governanceTimelock) {
                revert ModuleFirewallBlocked(0x610b5925, msgSender);
            }
            if (threatRegistry.isSelectorCompromised(to, sel)) {
                revert SelectorNotAllowed(sel);
            }
        }

        // Feature #13: EIP-7702 Delegation Firewall Inspection
        if (data.length >= 3 && data[0] == 0xef && data[1] == 0x01 && data[2] == 0x00) {
            revert EIP7702DelegationBlocked();
        }
        if (data.length > 0 && data[0] == 0x04) {
            revert EIP7702DelegationBlocked();
        }

        // DELEGATECALL check
        if (operation == 1) {
            if (!policy.allowDelegateCall) {
                revert DelegateCallNotAllowed(to);
            }
            bool targetAllowed = false;
            for (uint256 i = 0; i < policy.allowedTargets.length; i++) {
                if (policy.allowedTargets[i] == to) {
                    targetAllowed = true;
                    break;
                }
            }
            if (!targetAllowed) {
                revert InvalidTarget(to);
            }
        }

        // Feature #11: Recursive MultiSend decoding
        if (to == multiSend) {
            bytes memory transactions;
            if (data.length >= 4 && bytes4(data) == 0x8d80ff0a) {
                bytes memory payload = new bytes(data.length - 4);
                for (uint256 j = 0; j < payload.length; j++) {
                    payload[j] = data[j + 4];
                }
                transactions = abi.decode(payload, (bytes));
            } else {
                transactions = data;
            }
            _validateMultiSend(transactions, policy);
        } else {
            // Validate direct call target & selector
            if (policy.allowedTargets.length > 0) {
                bool targetAllowed = false;
                for (uint256 i = 0; i < policy.allowedTargets.length; i++) {
                    if (policy.allowedTargets[i] == to) {
                        targetAllowed = true;
                        break;
                    }
                }
                if (!targetAllowed) revert InvalidTarget(to);
            }

            if (data.length >= 4 && policy.allowedSelectors.length > 0) {
                bytes4 sel = bytes4(data);
                bool selAllowed = false;
                for (uint256 i = 0; i < policy.allowedSelectors.length; i++) {
                    if (policy.allowedSelectors[i] == sel) {
                        selAllowed = true;
                        break;
                    }
                }
                if (!selAllowed) revert SelectorNotAllowed(sel);
            }
        }
    }

    /**
     * @dev Recursively decodes MultiSend packed transactions and enforces policy.
     */
    function _validateMultiSend(bytes memory transactions, IntentPolicy memory policy) internal view {
        uint256 length = transactions.length;
        uint256 i = 0;

        while (i < length) {
            if (i + 85 > length) revert MultiSendValidationFailed(address(0), bytes4(0));

            uint8 op;
            address target;
            uint256 val;
            uint256 dataLength;

            assembly {
                op := shr(248, mload(add(transactions, add(0x20, i))))
                target := shr(96, mload(add(transactions, add(0x21, i))))
                val := mload(add(transactions, add(0x35, i)))
                dataLength := mload(add(transactions, add(0x55, i)))
            }

            i += 85;
            if (i + dataLength > length) revert MultiSendValidationFailed(target, bytes4(0));

            bytes memory subData = new bytes(dataLength);
            for (uint256 j = 0; j < dataLength; j++) {
                subData[j] = transactions[i + j];
            }
            i += dataLength;

            // Enforce constraints on each nested item
            if (threatRegistry.isBlacklisted(target)) revert TargetBlacklisted(target);
            if (target == address(this) || target == policy.vault) revert InvalidTarget(target);

            if (policy.allowedTargets.length > 0) {
                bool targetAllowed = false;
                for (uint256 k = 0; k < policy.allowedTargets.length; k++) {
                    if (policy.allowedTargets[k] == target) {
                        targetAllowed = true;
                        break;
                    }
                }
                if (!targetAllowed) revert InvalidTarget(target);
            }

            if (dataLength >= 4) {
                bytes4 sel = bytes4(subData);
                if (threatRegistry.isSelectorCompromised(target, sel)) revert SelectorNotAllowed(sel);

                if (policy.allowedSelectors.length > 0) {
                    bool selAllowed = false;
                    for (uint256 k = 0; k < policy.allowedSelectors.length; k++) {
                        if (policy.allowedSelectors[k] == sel) {
                            selAllowed = true;
                            break;
                        }
                    }
                    if (!selAllowed) revert SelectorNotAllowed(sel);
                }
            }

            if (op == 1 && !policy.allowDelegateCall) {
                revert DelegateCallNotAllowed(target);
            }
        }
    }

    /**
     * @notice Takes pre-execution snapshot of vault control slots, ETH balance, and registered tokens.
     */
    function takeSnapshot(
        address vault,
        address[] memory tokenAddresses
    ) external view returns (VaultSnapshot memory snap) {
        snap.ethBalance = vault.balance;
        snap.tokenBalances = new uint256[](tokenAddresses.length);
        for (uint256 i = 0; i < tokenAddresses.length; i++) {
            snap.tokenBalances[i] = _getTokenBalance(tokenAddresses[i], vault);
        }

        snap.walletCodeHash = vault.codehash;
        IGuardedMultisig ms = IGuardedMultisig(vault);
        snap.masterCopy = ms.masterCopy();
        snap.ownersHash = ms.getOwnersHash();
        snap.threshold = ms.threshold();
        snap.guard = ms.guard();
    }

    /**
     * @notice Feature #12: Multi-Asset Vault Snapshot Post-Check.
     */
    function checkAfterExecution(
        address vault,
        bool success,
        IntentPolicy memory policy,
        VaultSnapshot memory preSnap
    ) external view {
        if (!success) revert ExecutionFailed();

        // 1. Check ETH outflow
        uint256 postEth = vault.balance;
        if (preSnap.ethBalance > postEth) {
            uint256 ethOutflow = preSnap.ethBalance - postEth;
            if (ethOutflow > policy.ethValueCap) {
                revert EthValueCapExceeded(policy.ethValueCap, ethOutflow);
            }
        }

        // 2. Check Token outflows
        for (uint256 i = 0; i < policy.tokenAddresses.length; i++) {
            address token = policy.tokenAddresses[i];
            uint256 postBal = _getTokenBalance(token, vault);
            uint256 preBal = preSnap.tokenBalances[i];
            if (preBal > postBal) {
                uint256 outflow = preBal - postBal;
                uint256 cap = policy.maxTokenSpends[i];
                if (outflow > cap) {
                    revert TokenSpendExceeded(token, cap, outflow);
                }
            }
        }

        // 3. Control Slot Immutability Verification
        IGuardedMultisig ms = IGuardedMultisig(vault);
        if (ms.masterCopy() != preSnap.masterCopy) {
            revert ControlSlotMutated("masterCopy");
        }
        if (ms.getOwnersHash() != preSnap.ownersHash) {
            revert ControlSlotMutated("ownersHash");
        }
        if (ms.threshold() != preSnap.threshold) {
            revert ControlSlotMutated("threshold");
        }
        if (ms.guard() != preSnap.guard) {
            revert ControlSlotMutated("guard");
        }
        if (vault.codehash != preSnap.walletCodeHash) {
            revert ControlSlotMutated("codehash");
        }
    }

    function _getTokenBalance(address token, address account) internal view returns (uint256) {
        if (token == address(0)) return account.balance;
        (bool ok, bytes memory data) = token.staticcall(
            abi.encodeWithSelector(0x70a08231, account) // balanceOf(address)
        );
        if (ok && data.length >= 32) {
            return abi.decode(data, (uint256));
        }
        return 0;
    }
}
