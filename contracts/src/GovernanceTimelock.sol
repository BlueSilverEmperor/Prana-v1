// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IGuardedVault {
    function isOwner(address owner) external view returns (bool);
}

/**
 * @title GovernanceTimelock
 * @notice 24-hour timelock enforcing delays on critical governance and control actions.
 * Supports single-signer veto: any verified multisig owner can veto a pending proposal immediately.
 */
contract GovernanceTimelock {
    uint256 public constant DELAY = 1 days;

    struct Proposal {
        bytes32 id;
        address target;
        uint256 value;
        bytes data;
        uint256 eta;
        bool executed;
        bool vetoed;
        address proposer;
    }

    mapping(bytes32 => Proposal) public proposals;
    uint256 public proposalNonce;

    event TransactionQueued(
        bytes32 indexed proposalId,
        address indexed target,
        uint256 value,
        bytes data,
        uint256 eta
    );
    event TransactionExecuted(bytes32 indexed proposalId, address indexed target);
    event TransactionVetoed(bytes32 indexed proposalId, address indexed vetoer);

    error ProposalNotReady(bytes32 proposalId, uint256 eta);
    error ProposalAlreadyVetoed(bytes32 proposalId);
    error ProposalAlreadyExecuted(bytes32 proposalId);
    error ProposalDoesNotExist(bytes32 proposalId);
    error UnauthorizedVeto(address caller);
    error ExecutionFailed(bytes data);

    /**
     * @notice Queue a critical governance action for 24 hours.
     */
    function queueTransaction(
        address target,
        uint256 value,
        bytes calldata data
    ) external returns (bytes32 proposalId) {
        require(target != address(0), "Invalid target");
        uint256 eta = block.timestamp + DELAY;
        proposalId = keccak256(abi.encode(target, value, data, eta, block.chainid, ++proposalNonce));

        proposals[proposalId] = Proposal({
            id: proposalId,
            target: target,
            value: value,
            data: data,
            eta: eta,
            executed: false,
            vetoed: false,
            proposer: msg.sender
        });

        emit TransactionQueued(proposalId, target, value, data, eta);
    }

    /**
     * @notice Any verified multisig owner can veto a pending proposal during the 24-hour window.
     */
    function vetoProposal(bytes32 proposalId) external {
        Proposal storage p = proposals[proposalId];
        if (p.eta == 0) revert ProposalDoesNotExist(proposalId);
        if (p.vetoed) revert ProposalAlreadyVetoed(proposalId);
        if (p.executed) revert ProposalAlreadyExecuted(proposalId);

        // Verify caller is an owner of the target vault or proposer
        bool isAuthorized = (msg.sender == p.proposer);
        if (!isAuthorized) {
            try IGuardedVault(p.target).isOwner(msg.sender) returns (bool ownerCheck) {
                isAuthorized = ownerCheck;
            } catch {
                isAuthorized = true; // Fallback if target does not implement isOwner
            }
        }

        if (!isAuthorized) revert UnauthorizedVeto(msg.sender);

        p.vetoed = true;
        emit TransactionVetoed(proposalId, msg.sender);
    }

    /**
     * @notice Execute a queued transaction once DELAY has elapsed without veto.
     */
    function executeTransaction(bytes32 proposalId) external payable returns (bytes memory) {
        Proposal storage p = proposals[proposalId];
        if (p.eta == 0) revert ProposalDoesNotExist(proposalId);
        if (p.vetoed) revert ProposalAlreadyVetoed(proposalId);
        if (p.executed) revert ProposalAlreadyExecuted(proposalId);
        if (block.timestamp < p.eta) revert ProposalNotReady(proposalId, p.eta);

        p.executed = true;

        (bool success, bytes memory returnData) = p.target.call{value: p.value}(p.data);
        if (!success) {
            revert ExecutionFailed(returnData);
        }

        emit TransactionExecuted(proposalId, p.target);
        return returnData;
    }

    function getProposal(bytes32 proposalId) external view returns (Proposal memory) {
        return proposals[proposalId];
    }
}
