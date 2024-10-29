// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IPeerRegistry.sol";
import "../interfaces/IVerifier.sol";

contract PeerRegistry is IPeerRegistry, Ownable, ReentrancyGuard, Pausable {
    // Peer structure
    struct Peer {
        bytes32 peerId;         // Anonymous peer identifier
        uint256 reputation;     // Reputation score (0-10000)
        uint256 stakingAmount;  // Amount of tokens staked
        uint256 uploadCount;    // Number of successful uploads
        uint256 downloadCount;  // Number of successful downloads
        uint256 reportCount;    // Number of times reported
        uint256 lastActivity;   // Last activity timestamp
        bool isActive;         // Active status
        bytes32 commitment;    // Identity commitment
        address[] trustedPeers; // List of trusted peers
    }
    struct Report {
        bytes32 reporterId;    // Reporter's peer ID
        bytes32 reportedId;    // Reported peer ID
        string reason;         // Report reason
        uint256 timestamp;     // Report timestamp
        bool resolved;         // Resolution status
    }

    // Update the visibility of the peerReports mapping
    mapping(bytes32 => Report[]) private peerReports;
    
    // Constants
    uint256 public constant MIN_STAKE = 1000 * 10**18;  // 1000 tokens
    uint256 public constant MAX_TRUSTED_PEERS = 10;
    uint256 public constant INITIAL_REPUTATION = 5000;  // 50%
    uint256 public constant MAX_REPUTATION = 10000;     // 100%
    uint256 public constant REPORT_THRESHOLD = 3;       // Reports before penalty
    uint256 public constant ACTIVITY_TIMEOUT = 7 days;

    // State variables
    mapping(bytes32 => Peer) public peers;
    mapping(address => bytes32) public addressToPeerId;
    mapping(bytes32 => mapping(bytes32 => bool)) public trustedPeerPairs;
    //mapping(bytes32 => Report[]) public peerReports;
    mapping(bytes32 => mapping(uint256 => bytes32)) public proofHistory;
    
    uint256 public totalPeers;
    uint256 public activePeers;
    IVerifier public verifier;

    constructor(
        address initialOwner,
        address _verifier
    ) Ownable(initialOwner) {
        verifier = IVerifier(_verifier);
    }

    function registerPeer(
    bytes32 commitment,
    bytes32 proof,  // Changed from bytes calldata to bytes32
    uint256 stake
) external payable override {
    require(msg.value == stake, "Incorrect stake amount");
    require(msg.value >= MIN_STAKE, "Insufficient stake");
    require(addressToPeerId[msg.sender] == bytes32(0), "Already registered");

    // Verify identity proof
    require(
        verifier.verifyIdentityProof(commitment, proof),
        "Invalid identity proof"
    );

    // Rest of the implementation remains the same...
}

function updatePeerStatus(
    bytes32 commitment,
    bool isActive,
    bytes32 proof  // Added missing parameter
) external override onlyOwner {
    bytes32 peerId = addressToPeerId[msg.sender];
    require(peerId != bytes32(0), "Not registered");
    
    require(
        verifier.verifyStatusProof(commitment, proof),
        "Invalid status proof"
    );

    peers[peerId].isActive = isActive;
    if (isActive) {
        activePeers++;
    } else {
        activePeers--;
    }

    emit PeerStatusUpdated(peerId, isActive, block.timestamp);
}

function updateReputation(
    bytes32 commitment,
    uint256 change,  // Changed parameters to match interface
    bool increase,
    bytes32 proof
) external override onlyOwner {
    bytes32 peerId = addressToPeerId[msg.sender];
    require(peers[peerId].isActive, "Peer not active");
    require(change <= 1000, "Invalid change amount");

    require(
        verifier.verifyReputationProof(commitment, proof),
        "Invalid reputation proof"
    );

    Peer storage peer = peers[peerId];
    uint256 oldReputation = peer.reputation;
    uint256 newReputation;

    if (increase) {
        newReputation = oldReputation + change;
        if (newReputation > MAX_REPUTATION) {
            newReputation = MAX_REPUTATION;
        }
    } else {
        newReputation = oldReputation > change ? 
            oldReputation - change : 0;
    }

    peer.reputation = newReputation;
    peer.lastActivity = block.timestamp;

    emit ReputationUpdated(
        peerId,
        oldReputation,
        newReputation,
        block.timestamp
    );
}

function banPeer(
    bytes32 commitment,
    string calldata reason,
    bytes32 proof  // Added missing parameter
) external override onlyOwner {
    bytes32 peerId = addressToPeerId[msg.sender];
    require(peerId != bytes32(0), "Not registered");
    
    require(
        verifier.verifyBanProof(commitment, proof),
        "Invalid ban proof"
    );

    peers[peerId].isActive = false;
    activePeers--;
    
    emit PeerBanned(peerId, reason, block.timestamp);
}

/**
 * @notice Appeal a ban with proof
 * @param commitment Peer commitment
 * @param appealProof Proof to verify appeal
 */
function appealBan(
    bytes32 commitment,
    bytes32 appealProof
) external override {
    bytes32 peerId = addressToPeerId[msg.sender];
    require(peerId != bytes32(0), "Not registered");
    require(!peers[peerId].isActive, "Peer not banned");
    require(peers[peerId].commitment == commitment, "Invalid commitment");

    // Convert bytes32 to bytes for verification
    bytes memory proofBytes = abi.encodePacked(appealProof);

    // Verify appeal proof
    require(
        verifier.verifyAppealProof(commitment, proofBytes),
        "Invalid appeal proof"
    );

    // Restore peer status
    peers[peerId].isActive = true;
    activePeers++;

    emit BanAppealed(peerId, block.timestamp);
}

function joinMixingSession(
    bytes32 sessionId,
    bytes32 proof  // Changed from bytes calldata to bytes32
) external override {
    bytes32 peerId = addressToPeerId[msg.sender];
    require(peerId != bytes32(0), "Not registered");
    require(peers[peerId].isActive, "Peer not active");

    require(
        verifier.verifyMixingProof(sessionId, proof),
        "Invalid mixing proof"
    );

    emit MixingSessionJoined(peerId, sessionId, block.timestamp);
}

function verifyMixingProof(
    bytes32 sessionId,
    bytes32 proof  // Changed from bytes calldata to bytes32
) external view override returns (bool) {
    return verifier.verifyMixingProof(sessionId, proof);
}

    function getPeerInfo(bytes32 commitment)
        external
        view
        override
        returns (
            address peerAddress,
            bool isActive,
            uint256 stakingAmount,
            uint256 lastActivity,
            uint256 reputation
        )
    {
        bytes32 peerId = addressToPeerId[msg.sender];
        Peer storage peer = peers[peerId];
        return (
            msg.sender,
            peer.isActive,
            peer.stakingAmount,
            peer.lastActivity,
            peer.reputation
        );
    }

    function getPeerStats(
        bytes32 commitment
    ) external view override returns (
        uint256 uploadCount,
        uint256 downloadCount,
        uint256 reputation,
        uint256 reportCount
    ) {
        bytes32 peerId = addressToPeerId[msg.sender];
        Peer storage peer = peers[peerId];
        return (
            peer.uploadCount,
            peer.downloadCount,
            peer.reputation,
            peer.reportCount
        );
    }

    function getTotalPeers() external view override returns (uint256) {
        return totalPeers;
    }

    function getActivePeers() external view override returns (uint256) {
        return activePeers;
    }

    function isBanned(bytes32 commitment) external view override returns (bool) {
        bytes32 peerId = addressToPeerId[msg.sender];
        return !peers[peerId].isActive;
    }

    function _generatePeerId(
        address addr,
        bytes32 commitment
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(addr, commitment));
    }

    function _applyPenalty(bytes32 peerId) internal {
        Peer storage peer = peers[peerId];
        
        // Deactivate peer
        peer.isActive = false;
        activePeers--;

        // Apply reputation penalty
        uint256 oldReputation = peer.reputation;
        peer.reputation = oldReputation / 2; // 50% penalty

        emit PeerDeactivated(peerId, block.timestamp);
        emit ReputationUpdated(
            peerId,
            oldReputation,
            peer.reputation,
            block.timestamp
        );
    }
    /**
     * @notice Get reports for a peer
     * @param peerId Peer ID to get reports for
     * @return Array of reports for the peer
     */
    function getPeerReports(
        bytes32 peerId
    ) external view returns (Report[] memory) {
        return peerReports[peerId];
    }
   
  

    function getReport(
        bytes32 peerId,
        uint256 reportIndex
    ) external view returns (
        bytes32 reporterId,
        bytes32 reportedId,
        string memory reason,
        uint256 timestamp,
        bool resolved
    ) {
        require(reportIndex < peerReports[peerId].length, "Invalid report index");
        Report storage report = peerReports[peerId][reportIndex];
        return (
            report.reporterId,
            report.reportedId,
            report.reason,
            report.timestamp,
            report.resolved
        );
    }

    // Emergency functions
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
    function updateReputationThreshold(uint8 newThreshold) external override onlyOwner {
    // Implement your threshold update logic
    require(newThreshold > 0 && newThreshold <= 100, "Invalid threshold");
    // You could add a state variable for this
    emit ReputationThresholdUpdated(newThreshold);
}

function updateVerifier(address newVerifier) external override onlyOwner {
    require(newVerifier != address(0), "Invalid verifier address");
    verifier = IVerifier(newVerifier);
    emit VerifierUpdated(newVerifier);
}}