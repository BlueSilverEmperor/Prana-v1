// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./VeroGuard.sol";

interface ISafe {
    function getThreshold() external view returns (uint256);
    function getOwners() external view returns (address[] memory);
    function nonce() external view returns (uint256);
}

/**
 * @title VeroSafeGuard
 * @notice Drop-in Gnosis Safe Guard adapter connecting standard Gnosis Safe (v1.3.0/v1.4.1) vaults
 * to VeroGuard without requiring treasuries to redeploy their existing multisig.
 */
contract VeroSafeGuard {
    VeroGuard public immutable veroGuard;
    address public immutable governanceTimelock;

    bytes32 public constant INTENT_POLICY_TYPEHASH = keccak256(
        "IntentPolicy(address vault,uint256 nonce,uint256 deadline,uint256 maxGasFeeWei,bool allowDelegateCall,address[] allowedTargets,bytes4[] allowedSelectors,address[] tokenAddresses,uint256[] maxTokenSpends,uint256 ethValueCap,bool sessionKeyEnabled,address sessionAgent)"
    );

    // Custom Revert Error Selectors Matching VeroGuard
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

    // Mapping from safe to pending snapshot and policy
    mapping(address => VeroGuard.VaultSnapshot) private _snapshots;
    mapping(address => VeroGuard.IntentPolicy) private _pendingPolicies;
    mapping(address => bool) private _hasPendingPolicy;

    event SafePolicyRegistered(address indexed safe, bytes32 indexed policyHash);
    event SafePolicyCleared(address indexed safe);

    error NoPendingPolicy(address safe);
    error UnauthorizedSafe(address caller);

    constructor(address _veroGuard, address _governanceTimelock) {
        require(_veroGuard != address(0), "Invalid guard");
        require(_governanceTimelock != address(0), "Invalid timelock");
        veroGuard = VeroGuard(_veroGuard);
        governanceTimelock = _governanceTimelock;
    }

    /**
     * @notice Registers the IntentPolicy to be enforced during the Safe's execution frame.
     */
    function registerPolicy(VeroGuard.IntentPolicy memory policy) external {
        _pendingPolicies[msg.sender] = policy;
        _hasPendingPolicy[msg.sender] = true;
        emit SafePolicyRegistered(msg.sender, veroGuard.hashPolicy(policy));
    }

    /**
     * @notice Gnosis Safe IGuard pre-check hook.
     */
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation,
        uint256 /* safeTxGas */,
        uint256 /* baseGas */,
        uint256 /* gasPrice */,
        address /* gasToken */,
        address payable /* refundReceiver */,
        bytes memory /* signatures */,
        address msgSender
    ) external {
        address safe = msg.sender;

        // Direct Module and EIP-7702 Delegation Firewall checks
        bytes4 selector = bytes4(data);
        if (selector == 0x610b5925 && msgSender != governanceTimelock) {
            revert ModuleFirewallBlocked(selector, msgSender);
        }
        if (data.length >= 3 && uint8(data[0]) == 0xef && uint8(data[1]) == 0x01 && uint8(data[2]) == 0x00) {
            revert EIP7702DelegationBlocked();
        }
        if (data.length >= 1 && uint8(data[0]) == 0x04) {
            revert EIP7702DelegationBlocked();
        }

        if (!_hasPendingPolicy[safe]) {
            revert NoPendingPolicy(safe);
        }

        VeroGuard.IntentPolicy memory policy = _pendingPolicies[safe];
        uint256 safeNonce = ISafe(safe).nonce();

        // Delegate to VeroGuard pre-check
        veroGuard.checkTransaction(
            to,
            value,
            data,
            operation,
            safeNonce,
            msgSender,
            policy
        );

        // Take snapshot
        _snapshots[safe] = veroGuard.takeSnapshot(safe, policy.tokenAddresses);
    }

    /**
     * @notice Gnosis Safe IGuard post-check hook.
     */
    function checkAfterExecution(bytes32 /* txHash */, bool success) external {
        address safe = msg.sender;
        if (!_hasPendingPolicy[safe]) {
            revert NoPendingPolicy(safe);
        }

        VeroGuard.IntentPolicy memory policy = _pendingPolicies[safe];
        VeroGuard.VaultSnapshot memory preSnap = _snapshots[safe];

        delete _hasPendingPolicy[safe];
        delete _snapshots[safe];
        emit SafePolicyCleared(safe);

        // Delegate to VeroGuard post-check
        veroGuard.checkAfterExecution(safe, success, policy, preSnap);
    }
}
