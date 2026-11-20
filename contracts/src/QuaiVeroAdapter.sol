// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./VeroGuard.sol";

/**
 * @title QuaiVeroAdapter
 * @notice VeroGuard for one Quai Network zone. Every check runs inside the guard path
 *         (checkTransaction / checkAfterExecution), so a vault wired to this guard cannot skip it:
 * - Zone allowlist: the adapter serves exactly one zone, fixed at deployment, and only vaults that
 *   governance (the timelock) has bound to it. Unbound vaults are refused (fail closed). Replay of a signed
 *   policy onto another shard is already stopped by the EIP-712 domain (chain id and this contract).
 * - Dual ledger: native $QUAI is capped by the signed policy's ethValueCap, and the $QI token must be one
 *   of the signed policy's tokens, so the base post-check caps each transaction's $QI outflow.
 * - $QI velocity: the post-check measures the real $QI outflow and charges it to a per-vault daily cap
 *   that only governance can raise. A vault with no cap cannot spend $QI (fail closed).
 * Every setter that loosens a limit is timelock-only, and the timelock address itself can only be
 * changed through the timelock, so the deployer admin has no instant path around the delay.
 */
contract QuaiVeroAdapter is VeroGuard {
    error CrossShardReplayBlocked(bytes32 expectedZone, bytes32 actualZone);
    error UndeclaredQiPolicy(address qiToken);
    error QiVelocityCapExceeded(uint256 cap, uint256 requested);
    error InvalidZone();
    error InvalidQiToken(address token);

    /// @notice The zone this adapter enforces, for example keccak256("cyprus1"). Immutable.
    bytes32 public immutable zoneHash;
    address public qiToken;
    mapping(address => bytes32) public vaultZoneHash;
    mapping(address => uint256) public qiDailyCap;
    mapping(address => uint256) public dailyQiSpend;
    mapping(address => uint256) public qiWindowStart;
    /// @notice Contracts (such as a VeroSafeGuard) allowed to record spend on a vault's behalf.
    mapping(address => bool) public trustedGuardCaller;
    uint256 public constant QI_VELOCITY_WINDOW = 1 days;

    event VaultZoneUpdated(address indexed vault, bytes32 indexed zoneHash);
    event QiTokenUpdated(address indexed qiToken);
    event QiDailyCapUpdated(address indexed vault, uint256 cap);
    event TrustedGuardCallerUpdated(address indexed caller, bool trusted);
    event GovernanceTimelockUpdated(address indexed timelock);
    event QiVelocityRecorded(address indexed vault, uint256 amount, uint256 newDailyTotal, uint256 cap);

    constructor(
        address _threatRegistry,
        address _multiSend,
        address _governanceTimelock,
        address _qiToken,
        bytes32 _zoneHash
    ) VeroGuard(_threatRegistry, _multiSend, _governanceTimelock) {
        if (_zoneHash == bytes32(0)) revert InvalidZone();
        _requireContract(_qiToken);
        zoneHash = _zoneHash;
        qiToken = _qiToken;
        emit QiTokenUpdated(_qiToken);
    }

    // ------------------------------------------------------------------ config --

    /// @notice Binds a vault to a zone. Governance only: a vault attesting its own zone proves nothing.
    function setVaultZone(address vault, bytes32 zone) external {
        require(msg.sender == governanceTimelock, "Unauthorized");
        if (zone == bytes32(0)) revert InvalidZone();
        vaultZoneHash[vault] = zone;
        emit VaultZoneUpdated(vault, zone);
    }

    /// @notice Swaps the $QI token. Timelocked: an instant swap could silently disable the $QI cap.
    function setQiToken(address _qiToken) external {
        require(msg.sender == governanceTimelock, "Unauthorized");
        _requireContract(_qiToken);
        qiToken = _qiToken;
        emit QiTokenUpdated(_qiToken);
    }

    /// @notice The timelock can only be replaced through itself (the base guard also let admin do it).
    function setGovernanceTimelock(address newTimelock) external override {
        require(msg.sender == governanceTimelock, "Unauthorized");
        require(newTimelock != address(0), "Invalid timelock");
        governanceTimelock = newTimelock;
        emit GovernanceTimelockUpdated(newTimelock);
    }

    function setTrustedGuardCaller(address caller, bool trusted) external {
        require(msg.sender == governanceTimelock, "Unauthorized");
        trustedGuardCaller[caller] = trusted;
        emit TrustedGuardCallerUpdated(caller, trusted);
    }

    /// @notice Sets a vault's daily $QI cap. Governance may set any value; the vault may only lower it.
    function setQiDailyCap(address vault, uint256 cap) external {
        bool lowering = msg.sender == vault && cap < qiDailyCap[vault];
        require(msg.sender == governanceTimelock || lowering, "Unauthorized");
        qiDailyCap[vault] = cap;
        emit QiDailyCapUpdated(vault, cap);
    }

    // -------------------------------------------------------------- guard path --

    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation,
        uint256 vaultNonce,
        address msgSender,
        IntentPolicy memory policy
    ) public view override {
        super.checkTransaction(to, value, data, operation, vaultNonce, msgSender, policy);
        bytes32 bound = vaultZoneHash[policy.vault];
        if (bound != zoneHash) revert CrossShardReplayBlocked(zoneHash, bound);
        if (!_declares(policy, qiToken)) revert UndeclaredQiPolicy(qiToken);
    }

    /**
     * @notice Runs the base post-check, then charges the measured $QI outflow to the vault's daily cap.
     *         The cap is checked for every caller, so a simulation sees the same revert as the real
     *         execution, but spend is only recorded when the vault itself or a trusted guard calls.
     *         Fixed 24-hour window from the first spend in it (not rolling).
     */
    function checkAfterExecution(
        address vault,
        bool success,
        IntentPolicy memory policy,
        VaultSnapshot memory preSnap
    ) public override {
        super.checkAfterExecution(vault, success, policy, preSnap);
        uint256 spent = _qiOutflow(vault, policy, preSnap);
        if (spent == 0) return;

        bool windowOver = block.timestamp >= qiWindowStart[vault] + QI_VELOCITY_WINDOW;
        uint256 total = (windowOver ? 0 : dailyQiSpend[vault]) + spent;
        uint256 cap = qiDailyCap[vault];
        if (total > cap) revert QiVelocityCapExceeded(cap, total);

        if (msg.sender == vault || trustedGuardCaller[msg.sender]) {
            if (windowOver) qiWindowStart[vault] = block.timestamp;
            dailyQiSpend[vault] = total;
            emit QiVelocityRecorded(vault, spent, total, cap);
        }
    }

    // ---------------------------------------------------------------- checksum --

    /**
     * @notice 4 BIP-39 word indices binding the Quai zone and both caps.
     *         Mirrors shared/checksum.py (QUAI_NATIVE mode); change both together.
     */
    function computeQuaiChecksumWordIndices(
        address vault,
        uint256 nonce,
        bytes32 safeTxHash,
        bytes32 policyHash,
        bytes32 zone,
        uint256 quaiCap,
        uint256 qiCap
    ) external pure returns (uint16[4] memory indices) {
        bytes32 digest = keccak256(abi.encode(vault, nonce, safeTxHash, policyHash, zone, quaiCap, qiCap));
        indices[0] = uint16(uint256(digest) & 0x7FF);
        indices[1] = uint16((uint256(digest) >> 11) & 0x7FF);
        indices[2] = uint16((uint256(digest) >> 22) & 0x7FF);
        indices[3] = uint16((uint256(digest) >> 33) & 0x7FF);
    }

    // --------------------------------------------------------------- internals --

    function _declares(IntentPolicy memory policy, address token) internal pure returns (bool) {
        return _indexOf(policy, token) < policy.tokenAddresses.length;
    }

    /// @dev Index of `token` in the policy, or tokenAddresses.length when absent.
    function _indexOf(IntentPolicy memory policy, address token) internal pure returns (uint256 i) {
        for (i = 0; i < policy.tokenAddresses.length; i++) {
            if (policy.tokenAddresses[i] == token) return i;
        }
    }

    function _qiOutflow(address vault, IntentPolicy memory policy, VaultSnapshot memory preSnap)
        internal
        view
        returns (uint256)
    {
        uint256 i = _indexOf(policy, qiToken);
        if (i >= policy.tokenAddresses.length || i >= preSnap.tokenBalances.length) revert UndeclaredQiPolicy(qiToken);
        uint256 pre = preSnap.tokenBalances[i];
        uint256 post = _getTokenBalance(qiToken, vault);
        return pre > post ? pre - post : 0;
    }

    function _requireContract(address token) internal view {
        if (token.code.length == 0) revert InvalidQiToken(token);
    }
}
