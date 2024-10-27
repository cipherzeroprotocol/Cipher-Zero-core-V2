// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IWormhole.sol";
import "../interfaces/IVerifier.sol";
import "../interfaces/IBridgeVerifier.sol";

contract BridgeVerifier is IBridgeVerifier, Ownable, ReentrancyGuard, Pausable {
    // Constants
    uint32 public constant GUARDIAN_SET_EXPIRY = 24 hours;
    uint16 public constant CURRENT_CHAIN_ID = 1; // Solana chain ID
    uint8 public constant CONSISTENCY_LEVEL = 1;
    uint256 public constant MSG_TIMEOUT = 24 hours;

    // State variables
    IWormhole public wormhole;
    IVerifier public verifier;
    
    mapping(bytes32 => CrossChainMessage) public messages;
    mapping(bytes32 => bool) public nullifierUsed;
    mapping(uint32 => GuardianSet) public guardianSets;
    mapping(bytes32 => uint256) public messageTimestamps;
    
    uint32 public currentGuardianSetIndex;
    
    // Make verifyingKey private to avoid getter issues
    VerifyingKey private verifyingKey;

    constructor(
        address initialOwner,
        address _wormhole,
        address _verifier,
        address[] memory _guardians,
        uint256[2] memory _alpha,
        uint256[2][2] memory _beta,
        uint256[2] memory _gamma,
        uint256[2] memory _delta,
        uint256[2][] memory _ic
    ) Ownable(initialOwner) {
        wormhole = IWormhole(_wormhole);
        verifier = IVerifier(_verifier);
        
        // Initialize verifying key
        verifyingKey = VerifyingKey({
            alpha: _alpha,
            beta: _beta,
            gamma: _gamma,
            delta: _delta,
            ic: _ic
        });

        // Set up initial guardian set
        _updateGuardianSet(_guardians);
    }

    // Rest of the functions remain the same, but remove duplicate events
    
    function verifyMessage(
        bytes memory encodedVM,
        bytes memory proof
    ) external override nonReentrant whenNotPaused {
        // ... (rest of function remains the same)
    }

    function decodePayload(
        bytes memory payload
    ) public pure override returns (
        bytes32 messageHash,
        bytes32 nullifier,
        address sender,
        address recipient,
        bytes memory data
    ) {
        // ... (rest of function remains the same)
    }

    function updateGuardianSet(
        address[] memory newGuardians
    ) external override onlyOwner {
        _updateGuardianSet(newGuardians);
    }

    function _updateGuardianSet(
        address[] memory newGuardians
    ) internal {
        // ... (rest of function remains the same)
    }

    function isMessageTimedOut(
        bytes32 messageHash
    ) public view override returns (bool) {
        // ... (rest of function remains the same)
    }

    function getGuardians() external view override returns (address[] memory) {
        // ... (rest of function remains the same)
    }

    function updateVerifyingKey(
        uint256[2] memory _alpha,
        uint256[2][2] memory _beta,
        uint256[2] memory _gamma,
        uint256[2] memory _delta,
        uint256[2][] memory _ic
    ) external onlyOwner {
        verifyingKey = VerifyingKey({
            alpha: _alpha,
            beta: _beta,
            gamma: _gamma,
            delta: _delta,
            ic: _ic
        });
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}