// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IBridgeVerifier {
    // Struct definitions
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

    struct GuardianSet {
        address[] guardians;     // Guardian addresses
        uint32 expirationTime;   // Set expiration time
        bool isActive;          // Active status
    }

    struct VerifyingKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2] gamma;
        uint256[2] delta;
        uint256[2][] ic;
    }

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

    // Functions
    function verifyMessage(bytes memory encodedVM, bytes memory proof) external;
    function decodePayload(bytes memory payload) external pure returns (
        bytes32 messageHash,
        bytes32 nullifier,
        address sender,
        address recipient,
        bytes memory data
    );
    function updateGuardianSet(address[] memory newGuardians) external;
    function getGuardians() external view returns (address[] memory);
    function isMessageTimedOut(bytes32 messageHash) external view returns (bool);
}