// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IPeerRegistry.sol";
import "../interfaces/IVerifier.sol";

/**
 * @title PeerRegistry
 * @notice Manages peer registration, reputation, and anonymity in Cipher Zero Protocol
 * @dev Implements peer management with privacy features
 */
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

    // Peer report structure
    struct Report {
        bytes32 reporterId;    // Reporter's peer ID
        bytes32 reportedId;    // Reported peer ID
        string reason;         // Report reason
        uint256 timestamp;     // Report timestamp
        bool resolved;         // Resolution status
    }

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
    mapping(bytes32 => Report[]) public peerReports;
    mapping(bytes32 => mapping(uint256 => bytes32)) public proofHistory;
    
    uint256 public totalPeers;
    uint256 public activePeers;
    IVerifier public verifier;

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

    event PeerReported(
        bytes32 indexed reporterId,
        bytes32 indexed reportedId,
        string reason,
        uint256 timestamp
    );

    event TrustedPeerAdded(
        bytes32 indexed peerId,
        bytes32 indexed trustedPeerId,
        uint256 timestamp
    );

    /**
     * @notice Constructor
     * @param _verifier Address of Verifier contract
     */
    constructor(address _verifier) {
        verifier = IVerifier(_verifier);
    }

    /**
     * @notice Register as a peer with staking
     * @param commitment Identity commitment
     * @param proof ZK proof of identity
     */
    function registerPeer(
        bytes32 commitment,
        bytes calldata proof
    ) external payable nonReentrant whenNotPaused {
        require(msg.value >= MIN_STAKE, "Insufficient stake");
        require(addressToPeerId[msg.sender] == bytes32(0), "Already registered");

        // Verify identity proof
        require(
            verifier.verifyIdentityProof(
                commitment,
                proof
            ),
            "Invalid identity proof"
        );

        // Generate peer ID
        bytes32 peerId = _generatePeerId(msg.sender, commitment);
        
        // Create peer record
        peers[peerId] = Peer({
            peerId: peerId,
            reputation: INITIAL_REPUTATION,
            stakingAmount: msg.value,
            uploadCount: 0,
            downloadCount: 0,
            reportCount: 0,
            lastActivity: block.timestamp,
            isActive: true,
            commitment: commitment,
            trustedPeers: new address[](0)
        });

        // Update mappings
        addressToPeerId[msg.sender] = peerId;
        proofHistory[peerId][0] = keccak256(proof);

        // Update counters
        totalPeers++;
        activePeers++;

        emit PeerRegistered(
            peerId,
            commitment,
            msg.value,
            block.timestamp
        );
    }

    /**
     * @notice Add a trusted peer
     * @param trustedPeerId Peer ID to trust
     * @param proof ZK proof of relationship
     */
    function addTrustedPeer(
        bytes32 trustedPeerId,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        bytes32 peerId = addressToPeerId[msg.sender];
        require(peerId != bytes32(0), "Not registered");
        require(!trustedPeerPairs[peerId][trustedPeerId], "Already trusted");

        Peer storage peer = peers[peerId];
        require(peer.trustedPeers.length < MAX_TRUSTED_PEERS, "Too many trusted peers");

        // Verify relationship proof
        require(
            verifier.verifyRelationshipProof(
                peerId,
                trustedPeerId,
                proof
            ),
            "Invalid relationship proof"
        );

        // Add trusted peer
        peer.trustedPeers.push(address(uint160(uint256(trustedPeerId))));
        trustedPeerPairs[peerId][trustedPeerId] = true;

        emit TrustedPeerAdded(
            peerId,
            trustedPeerId,
            block.timestamp
        );
    }

    /**
     * @notice Report a malicious peer
     * @param reportedId Reported peer ID
     * @param reason Report reason
     * @param proof ZK proof of misbehavior
     */
    function reportPeer(
        bytes32 reportedId,
        string calldata reason,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        bytes32 reporterId = addressToPeerId[msg.sender];
        require(reporterId != bytes32(0), "Not registered");
        require(peers[reportedId].isActive, "Peer not active");

        // Verify misbehavior proof
        require(
            verifier.verifyMisbehaviorProof(
                reportedId,
                proof
            ),
            "Invalid misbehavior proof"
        );

        // Create report
        peerReports[reportedId].push(Report({
            reporterId: reporterId,
            reportedId: reportedId,
            reason: reason,
            timestamp: block.timestamp,
            resolved: false
        }));

        // Update report count
        peers[reportedId].reportCount++;

        // Check if penalty should be applied
        if (peers[reportedId].reportCount >= REPORT_THRESHOLD) {
            _applyPenalty(reportedId);
        }

        emit PeerReported(
            reporterId,
            reportedId,
            reason,
            block.timestamp
        );
    }

    /**
     * @notice Update peer reputation based on activity
     * @param peerId Peer ID
     * @param isPositive Whether update is positive
     * @param magnitude Update magnitude (0-1000)
     */
    function updateReputation(
        bytes32 peerId,
        bool isPositive,
        uint256 magnitude
    ) external onlyOwner {
        require(peers[peerId].isActive, "Peer not active");
        require(magnitude <= 1000, "Invalid magnitude");

        Peer storage peer = peers[peerId];
        uint256 oldReputation = peer.reputation;
        uint256 newReputation;

        if (isPositive) {
            newReputation = oldReputation + magnitude;
            if (newReputation > MAX_REPUTATION) {
                newReputation = MAX_REPUTATION;
            }
        } else {
            newReputation = oldReputation > magnitude ? 
                oldReputation - magnitude : 0;
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

    /**
     * @notice Apply penalty to misbehaving peer
     * @param peerId Peer ID
     */
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
     * @notice Generate peer ID from address and commitment
     * @param addr Peer address
     * @param commitment Identity commitment
     */
    function _generatePeerId(
        address addr,
        bytes32 commitment
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(addr, commitment));
    }

    /**
     * @notice Get peer details
     * @param peerId Peer ID
     */
    function getPeer(
        bytes32 peerId
    ) external view returns (
        uint256 reputation,
        uint256 stakingAmount,
        uint256 uploadCount,
        uint256 downloadCount,
        uint256 reportCount,
        uint256 lastActivity,
        bool isActive,
        bytes32 commitment,
        address[] memory trustedPeers
    ) {
        Peer storage peer = peers[peerId];
        return (
            peer.reputation,
            peer.stakingAmount,
            peer.uploadCount,
            peer.downloadCount,
            peer.reportCount,
            peer.lastActivity,
            peer.isActive,
            peer.commitment,
            peer.trustedPeers
        );
    }

    /**
     * @notice Check if peers trust each other
     * @param peerId1 First peer ID
     * @param peerId2 Second peer ID
     */
    function arePeersTrusted(
        bytes32 peerId1,
        bytes32 peerId2
    ) external view returns (bool) {
        return trustedPeerPairs[peerId1][peerId2] ||
               trustedPeerPairs[peerId2][peerId1];
    }

    /**
     * @notice Get reports for a peer
     * @param peerId Peer ID
     */
    function getPeerReports(
        bytes32 peerId
    ) external view returns (Report[] memory) {
        return peerReports[peerId];
    }

    // Emergency functions
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}