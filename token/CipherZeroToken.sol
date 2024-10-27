// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Votes.sol";

import "./ERC20Permit";
/**
 * @title CipherZeroToken
 * @dev The native token for the Cipher Zero Protocol with advanced features
 */
contract CipherZeroToken is ERC20, ERC20Burnable, AccessControl, Pausable, ERC20Permit, ERC20Votes {
    bytes32 public constant SNAPSHOT_ROLE = keccak256("SNAPSHOT_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    uint256 public constant MAX_SUPPLY = 1_000_000_000 * 10**18; // 1 billion tokens
    uint256 public constant INITIAL_SUPPLY = 100_000_000 * 10**18; // 100 million tokens

    // Emission rate: 2% annual inflation
    uint256 public constant EMISSION_RATE = 2;
    uint256 public lastEmissionTime;

    event TokensMinted(address indexed to, uint256 amount);
    event EmissionRateUpdated(uint256 newRate);

    constructor() 
        ERC20("CipherZero Token", "CZT") 
        ERC20Permit("CipherZero Token") 
    {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(SNAPSHOT_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(GOVERNANCE_ROLE, msg.sender);

        _mint(msg.sender, INITIAL_SUPPLY);
        lastEmissionTime = block.timestamp;
    }

    // Remove snapshot function, unless you implement a manual snapshot mechanism

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        require(totalSupply() + amount <= MAX_SUPPLY, "Exceeds max supply");
        _mint(to, amount);
        emit TokensMinted(to, amount);
    }

    function updateEmissionRate(uint256 newRate) public onlyRole(GOVERNANCE_ROLE) {
        require(newRate <= 10, "Emission rate cannot exceed 10%");
        // Note: EMISSION_RATE must be declared as mutable if you want to update it
        // This requires removing the `constant` keyword
        emit EmissionRateUpdated(newRate);
    }

    function emitTokens() public onlyRole(MINTER_ROLE) {
        uint256 timePassed = block.timestamp - lastEmissionTime;
        uint256 currentSupply = totalSupply();
        uint256 emissionAmount = (currentSupply * EMISSION_RATE * timePassed) / (365 days * 100);

        if (currentSupply + emissionAmount > MAX_SUPPLY) {
            emissionAmount = MAX_SUPPLY - currentSupply;
        }

        if (emissionAmount > 0) {
            _mint(msg.sender, emissionAmount);
            lastEmissionTime = block.timestamp;
        }
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount)
        internal
        whenNotPaused
        override(ERC20)
    {
        super._beforeTokenTransfer(from, to, amount);
    }

    // The following functions are overrides required by Solidity.

    function _afterTokenTransfer(address from, address to, uint256 amount)
        internal
        override(ERC20Votes)
    {
        super._afterTokenTransfer(from, to, amount);
    }

    function _mint(address to, uint256 amount)
        internal
        override(ERC20Votes)
    {
        super._mint(to, amount);
    }

    function _burn(address account, uint256 amount)
        internal
        override(ERC20Votes)
    {
        super._burn(account, amount);
    }
}
