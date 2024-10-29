// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title IPeerRegistry
 * @notice Interface for managing peer registration, reputation, and privacy in Cipher Zero Protocol
 */
interface IPeerRegistry {
    // Structs
    struct PeerInfo {
        bytes32 commitment;
        bytes32 nullifier;
        uint8 reputationScore;
        uint256 lastSeen;
        bool isActive;
        bool isBanned;
    }

    struct PeerStats {
        uint256 totalBytesShared;
        uint256 successfulTransfers;
        uint256 failedTransfers;
        uint256 mixingSessions;
        uint256 uploadCount;
        uint256 downloadCount;
        uint256 reputation;
        uint256 reportCount;
    }

    // Events
    event PeerRegistered(
        bytes32 indexed peerId,
        bytes32 indexed commitment,
        uint256 stakingAmount,
        uint256 timestamp
    );

    event PeerDeactivated(
        bytes32 indexed peerId,
        uint256 timestamp
    );

    event ReputationUpdated(
        bytes32 indexed peerId,
        uint256 oldReputation,
        uint256 newReputation,
        uint256 timestamp
    );

    event PeerStatusUpdated(
        bytes32 indexed peerId,
        bool isActive,
        uint256 timestamp
    );

    event BanAppealed(
        bytes32 indexed peerId,
        uint256 timestamp
    );

    event PeerBanned(
        bytes32 indexed peerId,
        string reason,
        uint256 timestamp
    );

    event MixingSessionJoined(
        bytes32 indexed peerId,
        bytes32 indexed sessionId,
        uint256 timestamp
    );

    event VerifierUpdated(
        address indexed newVerifier
    );

    event ReputationThresholdUpdated(
        uint8 newThreshold
    );

    // Core Functions
    function registerPeer(
        bytes32 commitment,
        bytes32 proof,
        uint256 stake
    ) external payable;

    function updatePeerStatus(
        bytes32 commitment,
        bool isActive,
        bytes32 proof
    ) external;

    function updateReputation(
        bytes32 commitment,
        uint256 change,
        bool increase,
        bytes32 proof
    ) external;

    function banPeer(
        bytes32 commitment,
        string calldata reason,
        bytes32 proof
    ) external;

    function appealBan(
        bytes32 commitment,
        bytes32 appealProof
    ) external;

    function joinMixingSession(
        bytes32 sessionId,
        bytes32 proof
    ) external;

    function verifyMixingProof(
        bytes32 sessionId,
        bytes32 proof
    ) external view returns (bool);

    // View Functions
    function getPeerInfo(
        bytes32 commitment
    ) external view returns (
        address peerAddress,
        bool isActive,
        uint256 stakingAmount,
        uint256 lastActivity,
        uint256 reputation
    );

    function getPeerStats(
        bytes32 commitment
    ) external view returns (
        uint256 uploadCount,
        uint256 downloadCount,
        uint256 reputation,
        uint256 reportCount
    );

    function getTotalPeers() external view returns (uint256);
    function getActivePeers() external view returns (uint256);
    function isBanned(bytes32 commitment) external view returns (bool);

    // Admin Functions
    function updateReputationThreshold(uint8 newThreshold) external;
    function updateVerifier(address newVerifier) external;
    function pause() external;
    function unpause() external;
}