// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "./VeroGuard.sol";

/**
 * @title GuardedMultisig
 * @notice Multisig vault protected by VeroGuard and GovernanceTimelock.
 * Implements M-of-N threshold signatures, session-scoped sub-intents with rolling 24h spend,
 * immutable control slot snapshotting, module firewall, and dead-man's switch auto-sweep.
 */
contract GuardedMultisig {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // Slot 0: masterCopy / implementation pointer
    address public masterCopy;

    // Control State
    address public guard;
    address public governanceTimelock;
    uint256 public threshold;
    uint256 public nonce;

    address[] public owners;
    mapping(address => bool) public isOwner;

    // Feature #10 & #35: Session-Scoped Sub-Intents
    mapping(address => uint256) public dailySpend;
    mapping(address => uint256) public lastDailyReset;
    uint256 public dailySpendCap;

    // Feature #35: AI Agent Velocity Limiter (Anti-Burst Protection)
    mapping(address => uint256) public lastAgentTxTime;
    uint256 public agentCooldown;

    // Registered modules
    mapping(address => bool) public isModuleEnabled;

    // Custom Revert Errors
    error UnauthorizedCaller(address caller);
    error InvalidSignatures();
    error ThresholdNotMet(uint256 required, uint256 provided);
    error InvalidOwner(address owner);
    error DuplicateOrUnsortedOwners();
    error ModuleFirewallBlocked(bytes4 selector, address caller);
    error DailySpendCapExceeded(uint256 cap, uint256 requested);
    error AgentCooldownActive(uint256 nextAllowedTime, uint256 currentTimestamp);
    error DeadMansSwitchActive(address vault);
    error ExecutionFailed();
    error UnauthorizedSweep();

    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event ThresholdChanged(uint256 newThreshold);
    event GuardChanged(address indexed oldGuard, address indexed newGuard);
    event ModuleEnabled(address indexed module);
    event ExecutionSuccess(bytes32 indexed txHash);
    event AssetSwept(address indexed token, address indexed recipient, uint256 amount);

    modifier onlyGovernance() {
        if (msg.sender != governanceTimelock && msg.sender != address(this)) {
            revert UnauthorizedCaller(msg.sender);
        }
        _;
    }

    constructor(
        address[] memory _owners,
        uint256 _threshold,
        address _guard,
        address _timelock,
        uint256 _dailySpendCap
    ) {
        require(_owners.length >= _threshold, "Threshold exceeds owners");
        require(_threshold > 0, "Invalid threshold");

        masterCopy = address(this);
        threshold = _threshold;
        guard = _guard;
        governanceTimelock = _timelock;
        dailySpendCap = _dailySpendCap;

        address lastOwner = address(0);
        for (uint256 i = 0; i < _owners.length; i++) {
            address owner = _owners[i];
            if (owner == address(0) || isOwner[owner] || owner <= lastOwner) {
                revert DuplicateOrUnsortedOwners();
            }
            isOwner[owner] = true;
            owners.push(owner);
            lastOwner = owner;
            emit OwnerAdded(owner);
        }
    }

    receive() external payable {}
    fallback() external payable {}

    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    function getOwnersHash() public view returns (bytes32) {
        return keccak256(abi.encode(owners));
    }

    function setDailySpendCap(uint256 newCap) external onlyGovernance {
        dailySpendCap = newCap;
    }

    function setAgentCooldown(uint256 newCooldown) external onlyGovernance {
        agentCooldown = newCooldown;
    }

    function setGuard(address newGuard) external onlyGovernance {
        emit GuardChanged(guard, newGuard);
        guard = newGuard;
    }

    function setGovernanceTimelock(address newTimelock) external onlyGovernance {
        governanceTimelock = newTimelock;
    }

    function setMasterCopy(address newMasterCopy) external onlyGovernance {
        masterCopy = newMasterCopy;
    }

    function addOwnerWithThreshold(address newOwner, uint256 newThreshold) external onlyGovernance {
        require(newOwner != address(0) && !isOwner[newOwner], "Invalid owner");
        require(newThreshold > 0 && newThreshold <= owners.length + 1, "Invalid threshold");

        isOwner[newOwner] = true;
        owners.push(newOwner);
        threshold = newThreshold;

        emit OwnerAdded(newOwner);
        emit ThresholdChanged(newThreshold);
    }

    function removeOwner(address ownerToRemove, uint256 newThreshold) external onlyGovernance {
        require(isOwner[ownerToRemove], "Not an owner");
        require(newThreshold > 0 && newThreshold <= owners.length - 1, "Invalid threshold");

        isOwner[ownerToRemove] = false;
        for (uint256 i = 0; i < owners.length; i++) {
            if (owners[i] == ownerToRemove) {
                owners[i] = owners[owners.length - 1];
                owners.pop();
                break;
            }
        }
        threshold = newThreshold;

        emit OwnerRemoved(ownerToRemove);
        emit ThresholdChanged(newThreshold);
    }

    function changeThreshold(uint256 newThreshold) external onlyGovernance {
        require(newThreshold > 0 && newThreshold <= owners.length, "Invalid threshold");
        threshold = newThreshold;
        emit ThresholdChanged(newThreshold);
    }

    /**
     * @notice Feature #13: Module Firewall.
     * Direct enableModule(0x610b5925) call MUST be made only by GovernanceTimelock.
     */
    function enableModule(address module) external {
        if (msg.sender != governanceTimelock) {
            revert ModuleFirewallBlocked(0x610b5925, msg.sender);
        }
        isModuleEnabled[module] = true;
        emit ModuleEnabled(module);
    }

    /**
     * @notice Feature #37: Sweep asset directly to recoveryVault when dead-man's switch is triggered.
     */
    function sweepAsset(address token, address recipient) external {
        if (msg.sender != guard || !VeroGuard(guard).deadMansSwitchActive(address(this))) {
            revert UnauthorizedSweep();
        }

        if (token == address(0)) {
            uint256 bal = address(this).balance;
            if (bal > 0) {
                (bool sent, ) = recipient.call{value: bal}("");
                require(sent, "ETH sweep failed");
                emit AssetSwept(address(0), recipient, bal);
            }
        } else {
            (bool ok, bytes memory data) = token.staticcall(
                abi.encodeWithSelector(0x70a08231, address(this))
            );
            if (ok && data.length >= 32) {
                uint256 bal = abi.decode(data, (uint256));
                if (bal > 0) {
                    (bool transferOk, ) = token.call(
                        abi.encodeWithSelector(0xa9059cbb, recipient, bal)
                    );
                    require(transferOk, "Token sweep failed");
                    emit AssetSwept(token, recipient, bal);
                }
            }
        }
    }

    /**
     * @notice Core transaction execution protected by VeroGuard and IntentPolicy.
     */
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        bytes calldata signatures,
        VeroGuard.IntentPolicy calldata policy
    ) external payable returns (bool success) {
        if (guard != address(0) && VeroGuard(guard).deadMansSwitchActive(address(this))) {
            revert DeadMansSwitchActive(address(this));
        }

        bytes32 policyHash = (guard != address(0))
            ? VeroGuard(guard).hashPolicy(policy)
            : bytes32(0);

        bytes32 txHash = keccak256(
            abi.encode(
                keccak256("VeroTransaction(address to,uint256 value,bytes data,uint8 operation,uint256 nonce,uint256 chainId,bytes32 policyHash)"),
                to,
                value,
                keccak256(data),
                operation,
                nonce,
                block.chainid,
                policyHash
            )
        );
        bytes32 ethSignedTxHash = txHash.toEthSignedMessageHash();

        // 1. Signature Verification
        if (policy.sessionKeyEnabled) {
            // Feature #10 & #35: Session-Scoped Sub-Intent execution by sessionAgent
            require(signatures.length >= 65, "Invalid signature length");
            bytes memory singleSig = signatures[:65];
            address recovered = ethSignedTxHash.recover(singleSig);
            require(recovered == policy.sessionAgent, "Invalid session agent signature");

            // Velocity limiter: check cooldown between agent transactions
            if (agentCooldown > 0 && lastAgentTxTime[policy.sessionAgent] > 0) {
                if (block.timestamp < lastAgentTxTime[policy.sessionAgent] + agentCooldown) {
                    revert AgentCooldownActive(lastAgentTxTime[policy.sessionAgent] + agentCooldown, block.timestamp);
                }
            }
            lastAgentTxTime[policy.sessionAgent] = block.timestamp;

            // Check rolling 24-hour spend cap
            if (block.timestamp >= lastDailyReset[address(this)] + 1 days) {
                dailySpend[address(this)] = 0;
                lastDailyReset[address(this)] = block.timestamp;
            }

            uint256 newDailySpend = dailySpend[address(this)] + value;
            if (dailySpendCap > 0 && newDailySpend > dailySpendCap) {
                revert DailySpendCapExceeded(dailySpendCap, newDailySpend);
            }
            dailySpend[address(this)] = newDailySpend;
        } else {
            // Standard M-of-N Multisig verification
            _verifyThresholdSignatures(ethSignedTxHash, signatures);
        }

        uint256 currentNonce = nonce++;

        // 2. Pre-Execution Guard Check & Snapshot
        VeroGuard.VaultSnapshot memory preSnap;
        if (guard != address(0)) {
            VeroGuard(guard).checkTransaction(
                to,
                value,
                data,
                operation,
                currentNonce,
                msg.sender,
                policy
            );
            preSnap = VeroGuard(guard).takeSnapshot(address(this), policy.tokenAddresses);
        }

        // 3. Inner Call Execution
        if (operation == 1) {
            (success, ) = to.delegatecall(data);
        } else {
            (success, ) = to.call{value: value}(data);
        }

        // 4. Post-Execution Guard Verification
        if (guard != address(0)) {
            VeroGuard(guard).checkAfterExecution(address(this), success, policy, preSnap);
        }

        if (!success) {
            revert ExecutionFailed();
        }

        emit ExecutionSuccess(txHash);
        return true;
    }

    function _verifyThresholdSignatures(bytes32 ethSignedTxHash, bytes calldata signatures) internal view {
        uint256 sigCount = signatures.length / 65;
        if (sigCount < threshold) {
            revert ThresholdNotMet(threshold, sigCount);
        }

        address lastSigner = address(0);
        for (uint256 i = 0; i < threshold; i++) {
            bytes memory sig = signatures[i * 65:(i + 1) * 65];
            address signer = ethSignedTxHash.recover(sig);

            if (!isOwner[signer]) {
                revert InvalidOwner(signer);
            }
            if (signer <= lastSigner) {
                revert DuplicateOrUnsortedOwners();
            }
            lastSigner = signer;
        }
    }
}
