// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title ThreatRegistry
 * @notice Maintains threat intelligence on malicious addresses, bytecode hashes, and selectors.
 * Supports ERC-8176 style community/curator attestations to auto-blacklist threats once threshold is reached.
 */
contract ThreatRegistry is AccessControl {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    bytes32 public constant CURATOR_ROLE = keccak256("CURATOR_ROLE");
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

    // Direct blacklists
    mapping(address => bool) public isBlacklisted;
    mapping(bytes32 => bool) public isBytecodeBlacklisted;
    mapping(address => mapping(bytes4 => bool)) public isSelectorCompromised;

    // Attestation tracking
    uint256 public attestationThreshold = 2;
    mapping(address => uint256) public attestationCount;
    mapping(address => mapping(address => bool)) public hasAttested;

    event TargetBlacklisted(address indexed target, bool status);
    event BytecodeBlacklisted(bytes32 indexed codehash, bool status);
    event SelectorBlacklisted(address indexed target, bytes4 indexed selector, bool status);
    event AttestationSubmitted(address indexed target, address indexed curator, uint256 currentCount);
    event AttestationThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);

    error AlreadyAttested(address target, address curator);
    error InvalidCuratorSignature(address recoveredSigner);
    error InvalidThreshold();

    constructor(address initialAdmin) {
        require(initialAdmin != address(0), "Invalid admin");
        _grantRole(ADMIN_ROLE, initialAdmin);
        _grantRole(CURATOR_ROLE, initialAdmin);
    }

    function setAttestationThreshold(uint256 newThreshold) external onlyRole(ADMIN_ROLE) {
        if (newThreshold == 0) revert InvalidThreshold();
        emit AttestationThresholdUpdated(attestationThreshold, newThreshold);
        attestationThreshold = newThreshold;
    }

    function setBlacklist(address target, bool status) external onlyRole(ADMIN_ROLE) {
        isBlacklisted[target] = status;
        emit TargetBlacklisted(target, status);
    }

    function setBytecodeBlacklist(bytes32 codehash, bool status) external onlyRole(ADMIN_ROLE) {
        isBytecodeBlacklisted[codehash] = status;
        emit BytecodeBlacklisted(codehash, status);
    }

    function setSelectorCompromised(address target, bytes4 selector, bool status) external onlyRole(ADMIN_ROLE) {
        isSelectorCompromised[target][selector] = status;
        emit SelectorBlacklisted(target, selector, status);
    }

    /**
     * @notice Submits a signed attestation against a malicious target and selector (ERC-8176).
     * Automatically blacklists target once attestationCount >= attestationThreshold.
     */
    function submitAttestation(
        address target,
        bytes4 selector,
        bytes memory signature
    ) external {
        bytes32 messageHash = keccak256(
            abi.encode(
                keccak256("ThreatAttestation(address target,bytes4 selector,uint256 chainId)"),
                target,
                selector,
                block.chainid
            )
        );
        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        address curator = ethSignedHash.recover(signature);

        if (!hasRole(CURATOR_ROLE, curator)) {
            revert InvalidCuratorSignature(curator);
        }

        if (hasAttested[target][curator]) {
            revert AlreadyAttested(target, curator);
        }

        hasAttested[target][curator] = true;
        uint256 count = ++attestationCount[target];
        emit AttestationSubmitted(target, curator, count);

        if (count >= attestationThreshold) {
            isBlacklisted[target] = true;
            if (selector != bytes4(0)) {
                isSelectorCompromised[target][selector] = true;
            }
            emit TargetBlacklisted(target, true);
        }
    }

    /**
     * @notice Direct attestation submission by caller holding CURATOR_ROLE.
     */
    function submitDirectAttestation(address target, bytes4 selector) external onlyRole(CURATOR_ROLE) {
        if (hasAttested[target][msg.sender]) {
            revert AlreadyAttested(target, msg.sender);
        }

        hasAttested[target][msg.sender] = true;
        uint256 count = ++attestationCount[target];
        emit AttestationSubmitted(target, msg.sender, count);

        if (count >= attestationThreshold) {
            isBlacklisted[target] = true;
            if (selector != bytes4(0)) {
                isSelectorCompromised[target][selector] = true;
            }
            emit TargetBlacklisted(target, true);
        }
    }

    /**
     * @notice Checks if target or selector is blacklisted.
     */
    function isTargetCompromised(address target, bytes4 selector) external view returns (bool) {
        if (isBlacklisted[target]) return true;
        if (selector != bytes4(0) && isSelectorCompromised[target][selector]) return true;
        bytes32 codehash = target.codehash;
        if (codehash != bytes32(0) && isBytecodeBlacklisted[codehash]) return true;
        return false;
    }
}
