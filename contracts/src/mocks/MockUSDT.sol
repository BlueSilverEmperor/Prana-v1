// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockUSDT
 * @notice Non-standard ERC-20 token with 6 decimals mimicking Tether (USDT).
 * Does not return a boolean on transfer / transferFrom / approve.
 */
contract MockUSDT {
    string public name = "Tether USD";
    string public symbol = "USDT";
    uint8 public decimals = 6;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 initialSupply) {
        if (initialSupply > 0) {
            _mint(msg.sender, initialSupply);
        }
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        require(balanceOf[from] >= amount, "USDT: burn amount exceeds balance");
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }

    // Non-standard: returns void instead of bool
    function transfer(address to, uint256 amount) external {
        _transfer(msg.sender, to, amount);
    }

    // Non-standard: returns void instead of bool
    function transferFrom(address from, address to, uint256 amount) external {
        uint256 currentAllowance = allowance[from][msg.sender];
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "USDT: insufficient allowance");
            allowance[from][msg.sender] = currentAllowance - amount;
        }
        _transfer(from, to, amount);
    }

    // Non-standard: returns void instead of bool
    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(from != address(0), "USDT: transfer from zero");
        require(to != address(0), "USDT: transfer to zero");
        require(balanceOf[from] >= amount, "USDT: transfer amount exceeds balance");

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        require(to != address(0), "USDT: mint to zero");
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
}
