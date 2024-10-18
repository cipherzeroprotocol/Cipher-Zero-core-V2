// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Address.sol";

/**
 * @title TokenTransfer
 * @dev A contract for handling token transfers within the Cipher Zero Protocol
 */
contract TokenTransfer is ReentrancyGuard, AccessControl {
    using SafeERC20 for IERC20;
    using Address for address payable;

    bytes32 public constant TRANSFER_ADMIN_ROLE = keccak256("TRANSFER_ADMIN_ROLE");

    // Mapping of token address to whether it's supported
    mapping(address => bool) public supportedTokens;

    // Mapping of user address to token address to spender address to allowance
    mapping(address => mapping(address => mapping(address => uint256))) private _allowances;

    // Events
    event TokenTransferred(address indexed from, address indexed to, address indexed token, uint256 amount);
    event BatchTransferred(address indexed from, address[] to, address indexed token, uint256[] amounts);
    event AllowanceSet(address indexed owner, address indexed spender, address indexed token, uint256 amount);
    event TokenAdded(address indexed token);
    event TokenRemoved(address indexed token);

    // Custom errors
    error UnsupportedToken(address token);
    error InsufficientAllowance(address owner, address spender, address token, uint256 requested, uint256 available);
    error TransferFailed();
    error InvalidArrayLengths();

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(TRANSFER_ADMIN_ROLE, msg.sender);
    }

    /**
     * @dev Transfers tokens from the sender to a recipient
     * @param to Recipient address
     * @param token Address of the ERC20 token
     * @param amount Amount of tokens to transfer
     */
    function transferToken(address to, address token, uint256 amount) external nonReentrant {
        _transferToken(msg.sender, to, token, amount);
    }

    /**
     * @dev Transfers tokens from one address to another, respecting allowances
     * @param from Sender address
     * @param to Recipient address
     * @param token Address of the ERC20 token
     * @param amount Amount of tokens to transfer
     */
    function transferTokenFrom(address from, address to, address token, uint256 amount) external nonReentrant {
        uint256 currentAllowance = _allowances[from][token][msg.sender];
        if (currentAllowance < amount) {
            revert InsufficientAllowance(from, msg.sender, token, amount, currentAllowance);
        }
        unchecked {
            _allowances[from][token][msg.sender] = currentAllowance - amount;
        }
        _transferToken(from, to, token, amount);
    }

    /**
     * @dev Performs batch token transfers
     * @param to Array of recipient addresses
     * @param token Address of the ERC20 token
     * @param amounts Array of amounts to transfer
     */
    function batchTransferToken(address[] calldata to, address token, uint256[] calldata amounts) external nonReentrant {
        if (to.length != amounts.length) revert InvalidArrayLengths();
        
        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            totalAmount += amounts[i];
        }

        IERC20(token).safeTransferFrom(msg.sender, address(this), totalAmount);

        for (uint256 i = 0; i < to.length; i++) {
            _transferToken(address(this), to[i], token, amounts[i]);
        }

        emit BatchTransferred(msg.sender, to, token, amounts);
    }

    /**
     * @dev Sets allowance for a spender to transfer tokens on behalf of the owner
     * @param spender Address allowed to spend tokens
     * @param token Address of the ERC20 token
     * @param amount Amount of tokens allowed to spend
     */
    function setAllowance(address spender, address token, uint256 amount) external {
        _allowances[msg.sender][token][spender] = amount;
        emit AllowanceSet(msg.sender, spender, token, amount);
    }

    /**
     * @dev Returns the remaining allowance for a spender
     * @param owner Address of the token owner
     * @param spender Address of the spender
     * @param token Address of the ERC20 token
     * @return The remaining allowance
     */
    function allowance(address owner, address spender, address token) external view returns (uint256) {
        return _allowances[owner][token][spender];
    }

    /**
     * @dev Adds a supported token (only TRANSFER_ADMIN_ROLE)
     * @param token Address of the token to add
     */
    function addSupportedToken(address token) external onlyRole(TRANSFER_ADMIN_ROLE) {
        supportedTokens[token] = true;
        emit TokenAdded(token);
    }

    /**
     * @dev Removes a supported token (only TRANSFER_ADMIN_ROLE)
     * @param token Address of the token to remove
     */
    function removeSupportedToken(address token) external onlyRole(TRANSFER_ADMIN_ROLE) {
        supportedTokens[token] = false;
        emit TokenRemoved(token);
    }

    /**
     * @dev Internal function to handle token transfers
     * @param from Sender address
     * @param to Recipient address
     * @param token Address of the ERC20 token
     * @param amount Amount of tokens to transfer
     */
    function _transferToken(address from, address to, address token, uint256 amount) private {
        if (!supportedTokens[token]) revert UnsupportedToken(token);

        if (from == address(this)) {
            IERC20(token).safeTransfer(to, amount);
        } else {
            IERC20(token).safeTransferFrom(from, to, amount);
        }

        emit TokenTransferred(from, to, token, amount);
    }
}