// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title IPeerRegistry
 * @notice Interface for managing peer registration, reputation, and privacy in Cipher Zero Protocol
 * @dev Handles peer lifecycle, reputation scoring, and privacy-preserving peer discovery
 */
interface IPeerRegistry {
    // Structs
    
    /**
     * @dev Stores peer information with privacy-preserving details
     * @param commitment ZK commitment of peer data
     * @param nullifier Unique nullifier to prevent duplicate registrations
     * @param reputationScore Peer's reputation score (0-100)
     * @param lastSeen Last activity timestamp
     * @param isActive Current activity status
     * @param isBanned Whether peer is banned
     */
    struct PeerInfo {
        bytes32 commitment;
        bytes32 nullifier;
        uint8 reputationScore;
        uint256 lastSeen;
        bool isActive;
        bool isBanned;
    }

    /**
     * @dev Statistics about peer's activity and performance
     * @param totalBytesShared Total data shared by peer
     * @param successfulTransfers Number of successful transfers
     * @param failedTransfers Number of failed transfers
     * @param mixingSessions Number of privacy mixing sessions participated in
     */
    struct PeerStats {
        uint256 totalBytesShared;
        uint256 successfulTransfers;
        uint256 failedTransfers;
        uint256 mixingSessions;
    }

    // Events

    /**
     * @dev Emitted when a new peer is registered
     * @param commitment Peer's ZK commitment
     * @param nullifier Peer's nullifier
     * @param timestamp Registration timestamp
     */
    event PeerRegistered(
        bytes32 indexed commitment,
        bytes32 indexed nullifier,
        uint256 timestamp
    );

    /**
     * @dev Emitted when peer's reputation changes
     * @param commitment Peer's commitment
     * @param oldScore Previous reputation score
     * @param newScore New reputation score
     */
    event ReputationUpdated(
        bytes32 indexed commitment,
        uint8 oldScore,
        uint8 newScore
    );

    /**
     * @dev Emitted when peer is banned
     * @param commitment Peer's commitment
     * @param reason Ban reason code
     */
    event PeerBanned(bytes32 indexed commitment, uint8 reason);

    /**
     * @dev Emitted when peer joins mixing session
     * @param sessionId Mixing session identifier
     * @param commitment Peer's commitment
     */
    event MixingSessionJoined(
        bytes32 indexed sessionId,
        bytes32 indexed commitment
    );

    // Core Functions

    /**
     * @notice Register new peer with zero-knowledge proof
     * @param commitment ZK commitment of peer data
     * @param nullifier Unique nullifier 
     * @param proof ZK proof of valid peer data
     */
    function registerPeer(
        bytes32 commitment,
        bytes32 nullifier,
        bytes calldata proof
    ) external;

    /**
     * @notice Update peer's activity status
     * @param commitment Peer's commitment
     * @param isActive New activity status
     * @param proof ZK proof of peer ownership
     */
    function updatePeerStatus(
        bytes32 commitment,
        bool isActive,
        bytes calldata proof
    ) external;

    /**
     * @notice Get peer information
     * @param commitment Peer's commitment
     * @return PeerInfo struct containing peer data
     */
    function getPeerInfo(bytes32 commitment) 
        external 
        view 
        returns (PeerInfo memory);

    // Reputation Management

    /**
     * @notice Update peer's reputation score
     * @param commitment Peer's commitment
     * @param scoreChange Score delta (positive or negative)
     * @param proof ZK proof of authority to update score
     */
    function updateReputation(
        bytes32 commitment,
        int8 scoreChange,
        bytes calldata proof
    ) external;

    /**
     * @notice Ban peer for malicious behavior
     * @param commitment Peer's commitment
     * @param reason Ban reason code
     * @param proof ZK proof of authority to ban
     */
    function banPeer(
        bytes32 commitment,
        uint8 reason,
        bytes calldata proof
    ) external;

    /**
     * @notice Appeal peer ban
     * @param commitment Peer's commitment
     * @param appealProof Proof of incorrect ban
     */
    function appealBan(bytes32 commitment, bytes calldata appealProof) 
        external;

    // Privacy Features

    /**
     * @notice Join privacy mixing session
     * @param sessionId Mixing session identifier
     * @param commitment Peer's commitment
     * @param mixingProof ZK proof for mixing participation
     */
    function joinMixingSession(
        bytes32 sessionId,
        bytes32 commitment,
        bytes calldata mixingProof
    ) external;

    /**
     * @notice Verify peer mixing proof
     * @param sessionId Mixing session identifier
     * @param commitment Peer's commitment
     * @param proof Mixing verification proof
     * @return bool True if proof is valid
     */
    function verifyMixingProof(
        bytes32 sessionId,
        bytes32 commitment,
        bytes calldata proof
    ) external view returns (bool);

    // Statistics & Queries

    /**
     * @notice Get peer statistics
     * @param commitment Peer's commitment
     * @return PeerStats struct containing peer statistics
     */
    function getPeerStats(bytes32 commitment) 
        external 
        view 
        returns (PeerStats memory);

    /**
     * @notice Get total number of registered peers
     * @return uint256 Total peer count
     */
    function getTotalPeers() external view returns (uint256);

    /**
     * @notice Get number of active peers
     * @return uint256 Active peer count
     */
    function getActivePeers() external view returns (uint256);

    /**
     * @notice Check if peer is banned
     * @param commitment Peer's commitment
     * @return bool True if peer is banned
     */
    function isBanned(bytes32 commitment) external view returns (bool);

    // Admin Functions

    /**
     * @notice Update minimum reputation threshold
     * @param newThreshold New minimum threshold
     */
    function updateReputationThreshold(uint8 newThreshold) external;

    /**
     * @notice Update proof verifier contract
     * @param newVerifier Address of new verifier contract
     */  
    function updateVerifier(address newVerifier) external;

    /**
     * @notice Pause peer registry in emergency
     */
    function pause() external;

    /**
     * @notice Unpause peer registry
     */
    function unpause() external;
}