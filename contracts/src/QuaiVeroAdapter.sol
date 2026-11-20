// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./VeroGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title QuaiVeroAdapter
 * @notice Extends VeroGuard with Quai Network native capabilities:
 * - Shard/Zone coordinate binding to prevent cross-shard transaction replay
 * - Dual-ledger asset snapshotting ($QUAI native + $QI energy dollar token)
 * - $QI-denominated 24h AI agent velocity limits
 * - Quai shard-bound 4-word dual-device BIP-39 checksum derivation
 */
contract QuaiVeroAdapter is VeroGuard {
    // Quai Subsystem Custom Errors
    error CrossShardReplayBlocked(bytes32 expectedZone, bytes32 actualZone);
    error QiSpendCapExceeded(uint256 cap, uint256 actualOutflow);
    error QuaiSpendCapExceeded(uint256 cap, uint256 actualOutflow);
    error QiVelocityCapExceeded(uint256 cap, uint256 requested);

    // State variables
    address public qiToken;
    mapping(address => bytes32) public vaultZoneHash;
    mapping(address => uint256) public dailyQiSpend;
    mapping(address => uint256) public lastDailyQiReset;
    uint256 public constant QI_VELOCITY_WINDOW = 1 days;

    struct QuaiSnapshot {
        uint256 quaiBalance;
        uint256 qiBalance;
        bytes32 zoneHash;
    }

    event VaultZoneUpdated(address indexed vault, bytes32 indexed zoneHash);
    event QiTokenUpdated(address indexed qiToken);
    event QiVelocityRecorded(address indexed vault, uint256 amount, uint256 newDailyTotal);

    constructor(
        address _threatRegistry,
        address _multiSend,
        address _governanceTimelock,
        address _qiToken
    ) VeroGuard(_threatRegistry, _multiSend, _governanceTimelock) {
        qiToken = _qiToken;
    }

    function setVaultZone(address vault, bytes32 zoneHash) external {
        require(
            msg.sender == vault || msg.sender == governanceTimelock || msg.sender == admin,
            "Unauthorized"
        );
        vaultZoneHash[vault] = zoneHash;
        emit VaultZoneUpdated(vault, zoneHash);
    }

    function setQiToken(address _qiToken) external {
        require(
            msg.sender == governanceTimelock || msg.sender == admin,
            "Unauthorized"
        );
        qiToken = _qiToken;
        emit QiTokenUpdated(_qiToken);
    }

    /**
     * @notice Snapshots vault's $QUAI (native coin) and $QI (energy dollar) reserves.
     */
    function takeQuaiSnapshot(address vault) public view returns (QuaiSnapshot memory snap) {
        snap.quaiBalance = vault.balance;
        snap.qiBalance = qiToken != address(0) ? IERC20(qiToken).balanceOf(vault) : 0;
        snap.zoneHash = vaultZoneHash[vault];
    }

    /**
     * @notice Verifies dual-ledger balance drops and cross-shard zone integrity.
     */
    function verifyQuaiSnapshot(
        address vault,
        QuaiSnapshot memory preSnap,
        bytes32 currentZone,
        uint256 maxQuaiSpend,
        uint256 maxQiSpend
    ) public view {
        // 1. Shard coordinate binding check
        if (preSnap.zoneHash != bytes32(0) && currentZone != preSnap.zoneHash) {
            revert CrossShardReplayBlocked(preSnap.zoneHash, currentZone);
        }

        // 2. $QUAI native coin outflow check
        uint256 postQuai = vault.balance;
        if (postQuai < preSnap.quaiBalance) {
            uint256 drop = preSnap.quaiBalance - postQuai;
            if (drop > maxQuaiSpend) {
                revert QuaiSpendCapExceeded(maxQuaiSpend, drop);
            }
        }

        // 3. $QI energy dollar token outflow check
        if (qiToken != address(0)) {
            uint256 postQi = IERC20(qiToken).balanceOf(vault);
            if (postQi < preSnap.qiBalance) {
                uint256 drop = preSnap.qiBalance - postQi;
                if (drop > maxQiSpend) {
                    revert QiSpendCapExceeded(maxQiSpend, drop);
                }
            }
        }
    }

    /**
     * @notice Enforces 24-hour rolling velocity limits on $QI spending by AI agents.
     */
    function recordQiVelocitySpend(
        address vault,
        uint256 qiAmount,
        uint256 dailyCap
    ) external {
        require(msg.sender == vault || msg.sender == admin, "Unauthorized");

        if (block.timestamp >= lastDailyQiReset[vault] + QI_VELOCITY_WINDOW) {
            dailyQiSpend[vault] = 0;
            lastDailyQiReset[vault] = block.timestamp;
        }

        uint256 newTotal = dailyQiSpend[vault] + qiAmount;
        if (newTotal > dailyCap) {
            revert QiVelocityCapExceeded(dailyCap, newTotal);
        }

        dailyQiSpend[vault] = newTotal;
        emit QiVelocityRecorded(vault, qiAmount, newTotal);
    }

    /**
     * @notice Computes 4 BIP-39 word indices binding Quai shard zone and dual caps.
     */
    function computeQuaiChecksumWordIndices(
        address vault,
        uint256 nonce,
        bytes32 safeTxHash,
        bytes32 policyHash,
        bytes32 zoneHash,
        uint256 quaiCap,
        uint256 qiCap
    ) external pure returns (uint16[4] memory indices) {
        bytes32 digest = keccak256(
            abi.encode(vault, nonce, safeTxHash, policyHash, zoneHash, quaiCap, qiCap)
        );
        indices[0] = uint16(uint256(digest) & 0x7FF);
        indices[1] = uint16((uint256(digest) >> 11) & 0x7FF);
        indices[2] = uint16((uint256(digest) >> 22) & 0x7FF);
        indices[3] = uint16((uint256(digest) >> 33) & 0x7FF);
    }
}
