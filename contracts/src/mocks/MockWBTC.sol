// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockWBTC
 * @notice Standard ERC-20 token with 8 decimals representing Wrapped BTC.
 */
contract MockWBTC is ERC20 {
    constructor(uint256 initialSupply) ERC20("Wrapped BTC", "WBTC") {
        if (initialSupply > 0) {
            _mint(msg.sender, initialSupply);
        }
    }

    function decimals() public pure override returns (uint8) {
        return 8;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }
}
