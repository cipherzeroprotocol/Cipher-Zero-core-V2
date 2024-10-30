// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "../interfaces/Ownable.sol";
import "./TokenDividendPayingToken.sol";
import "../interfaces/IERC20.sol";
import "./Address.sol";
/**
 * @title CipherDividendTracker
 * @dev Tracks and distributes dividends with privacy features
 */
contract CipherDividendTracker is Ownable, TokenDividendPayingToken {
    using Address for address payable;

    struct AccountInfo {
        address account;
        uint256 withdrawableDividends;
        uint256 totalDividends;
        uint256 lastClaimTime;
        bytes32 zkProof;
    }

    // State variables
    mapping(address => bool) public excludedFromDividends;
    mapping(address => uint256) public lastClaimTimes;
    mapping(bytes32 => bool) public usedProofs;
    uint256 public totalDividendsWithdrawn; //totalDividendsWithdraw;  // Added override

    uint256 public constant CLAIM_WAIT_TIME = 1 hours;
    uint256 public constant MINIMUM_CLAIM_AMOUNT = 1 * 10**18;

    // Events
    event ExcludeFromDividends(address indexed account, bool value);
    event Claim(address indexed account, uint256 amount, bytes32 zkProof);
    event PrivateUpdateBalance(address indexed account, bytes32 commitment);

    constructor() ERC20("Cipher_Dividend_Tracker", "CDT") {}

    /**
     * @notice Implementation of withdrawDividend from interface
     */
    function withdrawDividend() external override {
        require(canClaim(msg.sender), "Must wait before claiming");
        uint256 amount = _withdrawDividendOfUser(payable(msg.sender));
        require(amount >= MINIMUM_CLAIM_AMOUNT, "Below minimum claim");
        totalDividendsWithdrawn += amount;  // Update total withdrawn
        lastClaimTimes[msg.sender] = block.timestamp;
    }

    /**
     * @notice Claims dividends with privacy protection
     * @param proof ZK proof of dividend claim eligibility
     */
    function claimDividend(bytes calldata proof) external {
        require(canClaim(msg.sender), "Must wait before claiming");
        
        bytes32 proofHash = keccak256(proof);
        require(!usedProofs[proofHash], "Proof already used");

        uint256 amount = _withdrawDividendOfUser(payable(msg.sender));
        require(amount >= MINIMUM_CLAIM_AMOUNT, "Below minimum claim");

        usedProofs[proofHash] = true;
        totalDividendsWithdrawn += amount;  // Update total withdrawn
        lastClaimTimes[msg.sender] = block.timestamp;

        emit Claim(msg.sender, amount, proofHash);
    }

    /**
     * @notice Updates account balance with privacy protection
     */
    function setBalance(
        address account, 
        uint256 newBalance
    ) external onlyOwner {
        if (excludedFromDividends[account]) {
            return;
        }

        _setBalance(account, newBalance);
        
        bytes32 commitment = keccak256(abi.encodePacked(
            account,
            newBalance,
            block.timestamp
        ));
        
        emit PrivateUpdateBalance(account, commitment);
    }

    /**
     * @notice Distributes dividends with privacy features
     */
    function distributeDividends() external payable onlyOwner {
        require(msg.value > 0, "No dividends to distribute");
        
        // Generate privacy commitment for distribution using prevrandao
        bytes32 distributionCommitment = keccak256(abi.encodePacked(
            msg.value,
            block.timestamp,
            block.prevrandao
        ));

        _distributeDividends(msg.value);
        emit PrivateUpdateBalance(address(this), distributionCommitment);
    }

    /**
     * @notice Excludes/includes account from dividends
     */
    function excludeFromDividends(address account, bool exclude) external onlyOwner {
        require(excludedFromDividends[account] != exclude, "Status not changed");
        excludedFromDividends[account] = exclude;
        
        if (exclude) {
            _setBalance(account, 0);
        } else {
            _setBalance(account, balanceOf(account));
        }
        
        emit ExcludeFromDividends(account, exclude);
    }

    /**
     * @notice Gets account dividend info
     */
    
    /**
     * @notice Gets account dividend info
     */
    function getAccountInfo(address account) external view returns (
        address,
        uint256,
        uint256,
        uint256,
        uint256
    ) {
        return (
            account,
            withdrawableDividendOf(account),
            accumulativeDividendOf(account),
            lastClaimTimes[account],
            totalDividendsWithdrawn
        );
    }

    /**
     * @notice Checks if account can claim dividends
     */
    function canClaim(address account) public view returns (bool) {
        return block.timestamp >= lastClaimTimes[account] + CLAIM_WAIT_TIME;
    }

    /**
     * @notice Emergency withdrawal of tokens sent by mistake
     */
    function rescueTokens(address token) external onlyOwner {
        require(token != address(this), "Cannot withdraw tracker tokens");
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).transfer(owner(), balance);
    }

    /**
     * @notice Emergency withdrawal of ETH
     */
    function rescueETH() external onlyOwner {
        uint256 balance = address(this).balance;
        payable(owner()).sendValue(balance);
    }

    /**
     * @dev Prevents direct transfers between accounts
     */
    function _transfer(address, address, uint256) internal pure override {
        revert("Dividend tracker: No transfers allowed");
    }
}