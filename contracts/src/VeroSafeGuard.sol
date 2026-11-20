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

    // Mapping from safe to pending snapshot and policy
    mapping(address => VeroGuard.VaultSnapshot) private _snapshots;
    mapping(address => VeroGuard.IntentPolicy) private _pendingPolicies;
    mapping(address => bool) private _hasPendingPolicy;

    event SafePolicyRegistered(address indexed safe, bytes32 indexed policyHash);

    error NoPendingPolicy(address safe);
    error UnauthorizedSafe(address caller);

    constructor(address _veroGuard, address _governanceTimelock) {
        require(_veroGuard != address(0), "Invalid guard");
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

        // Delegate to VeroGuard post-check
        veroGuard.checkAfterExecution(safe, success, policy, preSnap);
    }
}
