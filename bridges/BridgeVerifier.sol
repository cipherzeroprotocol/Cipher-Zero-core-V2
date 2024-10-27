// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IWormhole.sol";
import "../interfaces/IVerifier.sol";
import "../interfaces/IBridgeVerifier.sol";

/**
 * @title BridgeVerifier
 * @notice Verifies cross-chain messages and proofs for Cipher Zero Protocol
 * @dev Integrates with Wormhole for cross-chain communication
 */
contract BridgeVerifier is IBridgeVerifier, Ownable, ReentrancyGuard, Pausable {
    // Cross-chain message structure
    struct CrossChainMessage {
        bytes32 messageHash;     // Hash of message data
        uint16 sourceChain;      // Source chain ID
        uint16 targetChain;      // Target chain ID
        bytes32 payloadHash;     // Hash of payload data
        bytes32 nullifier;       // Unique nullifier
        address sender;          // Original sender
        address recipient;       // Target recipient
        bool executed;          // Execution status
        uint256 timestamp;      // Message timestamp
        bytes32 proof;          // ZK proof hash
    }

    // Guardian set structure
    struct GuardianSet {
        address[] guardians;     // Guardian addresses
        uint32 expirationTime;   // Set expiration time
        bool isActive;          // Active status
    }

    // Verifying key for cross-chain proofs
    struct VerifyingKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2] gamma;
        uint256[2] delta;
        uint256[2][] ic;
    }

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
    VerifyingKey public verifyingKey;

    // Events
    event MessageVerified(
        bytes32 indexed messageHash,
        uint16 indexed sourceChain,
        uint16 indexed targetChain,
        address sender,
        address recipient,
        uint256 timestamp
    );

    event GuardianSetUpdated(
        uint32 indexed index,
        address[] guardians,
        uint256 timestamp
    );

    event ProofVerified(
        bytes32 indexed messageHash,
        bytes32 indexed proofHash,
        uint256 timestamp
    );

    /**
     * @notice Constructor
     * @param _wormhole Wormhole bridge address
     * @param _verifier Verifier contract address
     * @param _guardians Initial guardian set
     */
    constructor(
        address _wormhole,
        address _verifier,
        address[] memory _guardians,
        uint256[2] memory _alpha,
        uint256[2][2] memory _beta,
        uint256[2] memory _gamma,
        uint256[2] memory _delta,
        uint256[2][] memory _ic
    ) {
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

    /**
     * @notice Verify a cross-chain message with ZK proof
     * @param encodedVM Wormhole encoded verified message
     * @param proof ZK proof
     */
    function verifyMessage(
        bytes memory encodedVM,
        bytes memory proof
    ) external nonReentrant whenNotPaused {
        // Parse and verify Wormhole message
        (
            IWormhole.VM memory vm,
            bool valid,
            string memory reason
        ) = wormhole.parseAndVerifyVM(encodedVM);
        
        require(valid, reason);
        require(
            vm.emitterChainId != CURRENT_CHAIN_ID,
            "Invalid source chain"
        );

        // Decode payload
        (
            bytes32 messageHash,
            bytes32 nullifier,
            address sender,
            address recipient,
            bytes memory payload
        ) = decodePayload(vm.payload);

        // Verify nullifier not used
        require(!nullifierUsed[nullifier], "Nullifier used");

        // Verify ZK proof
        require(
            verifier.verifyBridgeProof(
                messageHash,
                nullifier,
                sender,
                recipient,
                proof
            ),
            "Invalid proof"
        );

        // Create message record
        messages[messageHash] = CrossChainMessage({
            messageHash: messageHash,
            sourceChain: vm.emitterChainId,
            targetChain: CURRENT_CHAIN_ID,
            payloadHash: keccak256(payload),
            nullifier: nullifier,
            sender: sender,
            recipient: recipient,
            executed: false,
            timestamp: block.timestamp,
            proof: keccak256(proof)
        });

        // Mark nullifier as used
        nullifierUsed[nullifier] = true;

        // Record timestamp
        messageTimestamps[messageHash] = block.timestamp;

        emit MessageVerified(
            messageHash,
            vm.emitterChainId,
            CURRENT_CHAIN_ID,
            sender,
            recipient,
            block.timestamp
        );

        emit ProofVerified(
            messageHash,
            keccak256(proof),
            block.timestamp
        );
    }

    /**
     * @notice Decode message payload
     * @param payload Encoded payload
     */
    function decodePayload(
        bytes memory payload
    ) public pure returns (
        bytes32 messageHash,
        bytes32 nullifier,
        address sender,
        address recipient,
        bytes memory data
    ) {
        require(payload.length >= 116, "Invalid payload length");

        messageHash = bytes32(payload[0:32]);
        nullifier = bytes32(payload[32:64]);
        sender = address(uint160(uint256(bytes32(payload[64:96]))));
        recipient = address(uint160(uint256(bytes32(payload[96:128]))));
        data = payload[128:];

        return (messageHash, nullifier, sender, recipient, data);
    }

    /**
     * @notice Update guardian set
     * @param newGuardians New guardian addresses
     */
    function updateGuardianSet(
        address[] memory newGuardians
    ) external onlyOwner {
        _updateGuardianSet(newGuardians);
    }

    /**
     * @notice Internal guardian set update
     * @param newGuardians New guardian addresses
     */
    function _updateGuardianSet(
        address[] memory newGuardians
    ) internal {
        require(newGuardians.length > 0, "Empty guardian set");

        // Expire old set
        if (currentGuardianSetIndex > 0) {
            GuardianSet storage oldSet = guardianSets[currentGuardianSetIndex];
            oldSet.expirationTime = uint32(block.timestamp + GUARDIAN_SET_EXPIRY);
            oldSet.isActive = false;
        }

        // Create new set
        currentGuardianSetIndex++;
        GuardianSet storage newSet = guardianSets[currentGuardianSetIndex];
        newSet.guardians = newGuardians;
        newSet.isActive = true;
        newSet.expirationTime = 0;

        emit GuardianSetUpdated(
            currentGuardianSetIndex,
            newGuardians,
            block.timestamp
        );
    }

    /**
     * @notice Check if message has timed out
     * @param messageHash Message hash
     */
    function isMessageTimedOut(
        bytes32 messageHash
    ) public view returns (bool) {
        uint256 timestamp = messageTimestamps[messageHash];
        if (timestamp == 0) return false;
        return block.timestamp > timestamp + MSG_TIMEOUT;
    }

    /**
     * @notice Get active guardian set
     */
    function getGuardians() external view returns (address[] memory) {
        return guardianSets[currentGuardianSetIndex].guardians;
    }

    /**
     * @notice Update verifying key
     */
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

    // Emergency functions
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}