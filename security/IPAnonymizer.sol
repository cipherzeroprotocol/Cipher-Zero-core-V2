// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IZKVerifier.sol";

/**
 * @title IPAnonymizer
 * @dev Enhanced IP anonymization using zk-SNARKs with additional security features
 */
contract IPAnonymizer is Ownable, ReentrancyGuard, Pausable {
    // State variables
    IZKVerifier public verifier;
    
    // Constants for rate limiting
    uint256 private constant MAX_REGISTRATIONS_PER_BLOCK = 50;
    uint256 private constant REVOCATION_DELAY = 24 hours;

    // Storage
    mapping(bytes32 => bool) private anonymizedIPs;
    mapping(bytes32 => uint256) private registrationTimes;
    mapping(bytes32 => uint256) private revocationRequests;
    
    // Rate limiting
    mapping(uint256 => uint256) private blockRegistrationCount;

    // Events with indexed parameters
    event AnonymizedIPRegistered(
        bytes32 indexed ipHash,
        uint256 indexed timestamp,
        bytes32 indexed proof
    );
    
    event VerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier,
        uint256 indexed timestamp
    );
    
    event RevocationRequested(
        bytes32 indexed ipHash,
        uint256 indexed executionTime
    );
    
    event RevocationExecuted(
        bytes32 indexed ipHash,
        uint256 indexed timestamp
    );

    /**
     * @dev Constructor with enhanced validation
     */
    constructor(
        address _verifier,
        address initialOwner
    ) Ownable(initialOwner) {
        require(_verifier != address(0), "Invalid verifier");
        require(initialOwner != address(0), "Invalid owner");
        
        verifier = IZKVerifier(_verifier);
        _pause(); // Start paused for security
    }

    /**
     * @dev Register anonymized IP with enhanced security
     */
    /**
 * @dev Register anonymized IP with enhanced security
 */
function registerAnonymizedIP(
    bytes32 ipHash,
    uint256[8] calldata proof,
    uint256[1] calldata publicInputs
) external nonReentrant whenNotPaused {
    require(ipHash != bytes32(0), "Invalid IP hash");
    require(!anonymizedIPs[ipHash], "Already anonymized");
    
    // Rate limiting check
    require(
        blockRegistrationCount[block.number] < MAX_REGISTRATIONS_PER_BLOCK,
        "Rate limit exceeded"
    );

    // Verify the proof
    bool isValid;
    assembly {
        // Get free memory pointer
        let ptr := mload(0x40)
        
        // Calculate proof data position in calldata
        // Skip function selector (4 bytes) and ipHash (32 bytes)
        let proofStart := add(calldataload(0x04), 0x20)
        
        // Copy proof array to memory (8 elements * 32 bytes)
        for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
            mstore(
                add(ptr, mul(i, 0x20)),
                calldataload(add(proofStart, mul(i, 0x20)))
            )
        }
        
        // Calculate public inputs position and copy
        let inputsStart := add(proofStart, 0x100) // After proof data
        mstore(
            add(ptr, 0x100),
            calldataload(inputsStart)
        )
        
        // Call verifier
        isValid := staticcall(
            gas(),
            sload(verifier.slot),
            ptr,
            0x120, // Total size (proof + inputs)
            ptr,
            0x20
        )
        
        if iszero(isValid) {
            revert(0, 0)
        }
        
        isValid := mload(ptr)
        
        // Update free memory pointer
        mstore(0x40, add(ptr, 0x140))
    }
    
    require(isValid, "Invalid proof");

    // Update state
    anonymizedIPs[ipHash] = true;
    registrationTimes[ipHash] = block.timestamp;
    blockRegistrationCount[block.number]++;

    // Emit event with proof hash for verification
    emit AnonymizedIPRegistered(
        ipHash,
        block.timestamp,
        keccak256(abi.encode(proof, publicInputs))
    );
}

    /**
     * @dev Check IP anonymization status with metadata
     */
    function getIPStatus(
        bytes32 ipHash
    ) external view returns (
        bool isAnonymized,
        uint256 registrationTime,
        uint256 pendingRevocationTime
    ) {
        return (
            anonymizedIPs[ipHash],
            registrationTimes[ipHash],
            revocationRequests[ipHash]
        );
    }

    /**
     * @dev Request IP anonymization revocation with timelock
     */
    function requestRevocation(bytes32 ipHash) external onlyOwner {
        require(anonymizedIPs[ipHash], "Not anonymized");
        require(revocationRequests[ipHash] == 0, "Revocation pending");

        uint256 executionTime = block.timestamp + REVOCATION_DELAY;
        revocationRequests[ipHash] = executionTime;

        emit RevocationRequested(ipHash, executionTime);
    }

    /**
     * @dev Execute pending revocation after timelock
     */
    function executeRevocation(bytes32 ipHash) external onlyOwner {
        uint256 requestTime = revocationRequests[ipHash];
        require(requestTime != 0, "No revocation requested");
        require(block.timestamp >= requestTime, "Timelock active");
        
        delete anonymizedIPs[ipHash];
        delete registrationTimes[ipHash];
        delete revocationRequests[ipHash];

        emit RevocationExecuted(ipHash, block.timestamp);
    }

    /**
     * @dev Update verifier with security checks
     */
    function updateVerifier(address _newVerifier) external onlyOwner whenPaused {
        require(_newVerifier != address(0), "Invalid verifier");
        require(_newVerifier != address(verifier), "Same verifier");
        
        address oldVerifier = address(verifier);
        verifier = IZKVerifier(_newVerifier);

        emit VerifierUpdated(
            oldVerifier,
            _newVerifier,
            block.timestamp
        );
    }

    /**
     * @dev Clear old block registration counts
     */
    function clearOldBlockCounts(uint256 blocksBack) external {
        require(blocksBack > 0, "Invalid block count");
        uint256 targetBlock = block.number - blocksBack;
        
        for (uint256 i = 0; i < blocksBack; i++) {
            delete blockRegistrationCount[targetBlock - i];
        }
    }

    // Emergency control functions
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}