// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IBitTorrent.sol";
import "../interfaces/IFileRegistry.sol";
import "../interfaces/IVerifier.sol";

/**
 * @title BitTorrentRegistry
 * @notice Manages BitTorrent integration for decentralized file sharing
 * @dev Handles torrent tracking and peer management with privacy features
 */
contract BitTorrentRegistry is IBitTorrent, Ownable, ReentrancyGuard, Pausable {
    // Torrent structure
    struct Torrent {
        bytes32 infoHash;         // BitTorrent info hash
        bytes32 fileCommitment;   // File commitment (from FileRegistry)
        uint256 size;            // Total file size
        uint256 pieceCount;      // Number of pieces
        uint256 pieceSize;       // Size of each piece
        bytes32 piecesRoot;      // Merkle root of piece hashes
        address owner;           // File owner
        bool isPrivate;         // Privacy flag
        bool isEncrypted;       // Encryption flag
        bytes32 encryptionProof; // Proof of encryption
        uint256 timestamp;      // Registration timestamp
        mapping(address => bool) authorizedPeers; // Peer access control
        mapping(uint256 => bytes32) pieceHashes;  // Individual piece hashes
    }

    // Peer structure
    struct Peer {
        bytes32 peerId;          // Anonymous peer ID
        uint256 reputation;      // Peer reputation score
        uint256 uploadCount;     // Number of uploads
        uint256 downloadCount;   // Number of downloads
        uint256 lastSeen;        // Last activity timestamp
        bool isActive;          // Active status
        mapping(bytes32 => bool) servingTorrents; // Torrents being served
    }

    // State variables
    mapping(bytes32 => Torrent) public torrents;
    mapping(address => Peer) public peers;
    mapping(bytes32 => bytes32) public peerAnonymousIds; // Real address -> Anonymous ID
    mapping(bytes32 => uint256) public torrentPeerCount;
    
    IFileRegistry public fileRegistry;
    IVerifier public verifier;
    
    uint256 public constant MAX_PIECE_SIZE = 1024 * 1024 * 32; // 32MB
    uint256 public constant MIN_REPUTATION_SCORE = 100;
    uint256 public constant REPUTATION_INCREASE = 10;
    uint256 public constant REPUTATION_DECREASE = 20;

    // Events
    event TorrentRegistered(
        bytes32 indexed infoHash,
        bytes32 indexed fileCommitment,
        address indexed owner,
        uint256 size,
        uint256 timestamp
    );

    event PeerRegistered(
        bytes32 indexed peerId,
        bytes32 indexed anonymousId,
        uint256 timestamp
    );

    event PieceVerified(
        bytes32 indexed infoHash,
        uint256 indexed pieceIndex,
        bytes32 pieceHash,
        uint256 timestamp
    );

    event PeerReputationUpdated(
        bytes32 indexed peerId,
        uint256 newReputation,
        uint256 timestamp
    );

    /**
     * @notice Constructor
     * @param initialOwner Initial contract owner
     * @param _fileRegistry Address of FileRegistry contract
     * @param _verifier Address of Verifier contract
     */
    constructor(
        address initialOwner,
        address _fileRegistry,
        address _verifier
    ) Ownable(initialOwner) {
        fileRegistry = IFileRegistry(_fileRegistry);
        verifier = IVerifier(_verifier);
    }

    /**
     * @notice Register a new torrent
     * @param infoHash BitTorrent info hash
     * @param fileCommitment File commitment
     * @param size Total file size
     * @param pieceSize Size of each piece
     * @param piecesRoot Merkle root of piece hashes
     * @param proof ZK proof for file
     */
    

    /**
     * @notice Add a new torrent to the registry
     * @param torrentHash Torrent hash
     * @param metadata Torrent metadata
     */
    function addTorrent(
        bytes32 torrentHash,
        bytes memory metadata
    ) external override nonReentrant whenNotPaused {
        require(torrents[torrentHash].infoHash == bytes32(0), "Torrent exists");
        
        // Decode metadata
        (
            bytes32 fileCommitment,
            uint256 size,
            uint256 pieceSize,
            bytes32 piecesRoot
        ) = abi.decode(metadata, (bytes32, uint256, uint256, bytes32));

        // Register torrent
        _registerTorrent(
            torrentHash,
            fileCommitment,
            size,
            pieceSize,
            piecesRoot
        );
    }

    /**
     * @notice Register as a peer
     * @param proof ZK proof for peer anonymity
     */
    function registerTorrent(
    bytes32 infoHash,
    bytes32 fileCommitment,
    uint256 size,
    uint256 pieceSize,
    bytes32 piecesRoot,
    bytes calldata proof
) external nonReentrant whenNotPaused {
    require(pieceSize <= MAX_PIECE_SIZE, "Piece size too large");
    require(pieceSize > 0 && size > 0, "Invalid sizes");
    require(torrents[infoHash].infoHash == bytes32(0), "Torrent exists");

    // Verify file proof with additional parameter (e.g., msg.sender)
    require(
        verifier.verifyFileProof(fileCommitment, proof, msg.sender),
        "Invalid file proof"
    );

    // Register torrent
    _registerTorrent(
        infoHash,
        fileCommitment,
        size,
        pieceSize,
        piecesRoot
    );
}

// For the Peer struct initialization, split it into separate assignments:
function registerPeer(bytes calldata proof) external nonReentrant whenNotPaused {
    require(peers[msg.sender].peerId == bytes32(0), "Peer exists");

    // Generate anonymous ID
    bytes32 anonymousId = _generateAnonymousId(msg.sender, proof);
    
    // Initialize peer data separately
    peers[msg.sender].peerId = keccak256(abi.encodePacked(msg.sender, block.timestamp));
    peers[msg.sender].reputation = MIN_REPUTATION_SCORE;
    peers[msg.sender].uploadCount = 0;
    peers[msg.sender].downloadCount = 0;
    peers[msg.sender].lastSeen = block.timestamp;
    peers[msg.sender].isActive = true;

    // Store anonymous ID mapping
    peerAnonymousIds[keccak256(abi.encodePacked(msg.sender))] = anonymousId;

    emit PeerRegistered(
        peers[msg.sender].peerId,
        anonymousId,
        block.timestamp
    );
}


        

    /**
     * @notice Join a torrent swarm
     * @param torrentHash Torrent hash
     */
    function joinSwarm(bytes32 torrentHash) external override {
        Torrent storage torrent = torrents[torrentHash];
        require(torrent.infoHash != bytes32(0), "Torrent not found");
        require(!torrent.authorizedPeers[msg.sender], "Already in swarm");

        torrent.authorizedPeers[msg.sender] = true;
        torrentPeerCount[torrentHash]++;
    }

    /**
     * @notice Leave a torrent swarm
     * @param torrentHash Torrent hash
     */
    function leaveSwarm(bytes32 torrentHash) external override {
        Torrent storage torrent = torrents[torrentHash];
        require(torrent.infoHash != bytes32(0), "Torrent not found");
        require(torrent.authorizedPeers[msg.sender], "Not in swarm");

        torrent.authorizedPeers[msg.sender] = false;
        torrentPeerCount[torrentHash]--;
    }

    /**
     * @notice Verify piece hash
     * @param infoHash Torrent info hash
     * @param pieceIndex Piece index
     * @param pieceHash Hash of piece data
     * @param proof ZK proof for piece
     */
    function verifyPiece(
        bytes32 infoHash,
        uint256 pieceIndex,
        bytes32 pieceHash,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        Torrent storage torrent = torrents[infoHash];
        require(torrent.infoHash != bytes32(0), "Torrent not found");
        require(pieceIndex < torrent.pieceCount, "Invalid piece index");

        // Verify piece proof
        require(
            verifier.verifyPieceProof(
                pieceHash,
                torrent.piecesRoot,
                proof
            ),
            "Invalid piece proof"
        );

        // Store piece hash
        torrent.pieceHashes[pieceIndex] = pieceHash;

        emit PieceVerified(
            infoHash,
            pieceIndex,
            pieceHash,
            block.timestamp
        );
    }

    /**
     * @notice Get torrent metadata
     * @param torrentHash Torrent hash
     */
    function getTorrentMetadata(
        bytes32 torrentHash
    ) external view override returns (bytes memory) {
        Torrent storage torrent = torrents[torrentHash];
        require(torrent.infoHash != bytes32(0), "Torrent not found");

        return abi.encode(
            torrent.fileCommitment,
            torrent.size,
            torrent.pieceSize,
            torrent.piecesRoot,
            torrent.owner,
            torrent.isPrivate,
            torrent.isEncrypted
        );
    }

    /**
     * @notice Get peers in torrent swarm
     * @param torrentHash Torrent hash
     */
    function getSwarmPeers(
        bytes32 torrentHash
    ) external view override returns (address[] memory) {
        return new address[](0); // Simplified implementation
    }

    /**
     * @notice Check if peer is in swarm
     * @param torrentHash Torrent hash
     * @param peer Peer address
     */
    function isPeerInSwarm(
        bytes32 torrentHash,
        address peer
    ) external view override returns (bool) {
        return torrents[torrentHash].authorizedPeers[peer];
    }

    /**
     * @notice Remove a torrent
     * @param torrentHash Torrent hash
     */
    function removeTorrent(bytes32 torrentHash) external override {
        Torrent storage torrent = torrents[torrentHash];
        require(torrent.infoHash != bytes32(0), "Torrent not found");
        require(torrent.owner == msg.sender, "Not torrent owner");

        delete torrents[torrentHash];
    }

    /**
     * @notice Get torrent details
     * @param infoHash Torrent info hash
     */
    function getTorrent(
        bytes32 infoHash
    ) external view returns (
        bytes32 fileCommitment,
        uint256 size,
        uint256 pieceCount,
        uint256 pieceSize,
        bytes32 piecesRoot,
        address owner,
        bool isPrivate,
        bool isEncrypted
    ) {
        Torrent storage torrent = torrents[infoHash];
        require(torrent.infoHash != bytes32(0), "Torrent not found");

        return (
            torrent.fileCommitment,
            torrent.size,
            torrent.pieceCount,
            torrent.pieceSize,
            torrent.piecesRoot,
            torrent.owner,
            torrent.isPrivate,
            torrent.isEncrypted
        );
    }

    /**
     * @notice Get piece hash
     * @param infoHash Torrent info hash
     * @param pieceIndex Piece index
     */
    function getPieceHash(
        bytes32 infoHash,
        uint256 pieceIndex
    ) external view returns (bytes32) {
        return torrents[infoHash].pieceHashes[pieceIndex];
    }

    /**
     * @notice Get peer details
     * @param peer Peer address
     */
    function getPeerStats(
        address peer
    ) external view returns (
        bytes32 peerId,
        uint256 reputation,
        uint256 uploadCount,
        uint256 downloadCount,
        uint256 lastSeen,
        bool isActive
    ) {
        Peer storage peerData = peers[peer];
        return (
            peerData.peerId,
            peerData.reputation,
            peerData.uploadCount,
            peerData.downloadCount,
            peerData.lastSeen,
            peerData.isActive
        );
    }

    /**
     * @notice Internal function to register torrent
     */
    function _registerTorrent(
        bytes32 torrentHash,
        bytes32 fileCommitment,
        uint256 size,
        uint256 pieceSize,
        bytes32 piecesRoot
    ) internal {
        // Calculate piece count
        uint256 pieceCount = (size + pieceSize - 1) / pieceSize;

        // Create torrent
        Torrent storage newTorrent = torrents[torrentHash];
        newTorrent.infoHash = torrentHash;
        newTorrent.fileCommitment = fileCommitment;
        newTorrent.size = size;
        newTorrent.pieceSize = pieceSize;
        newTorrent.pieceCount = pieceCount;
        newTorrent.piecesRoot = piecesRoot;
        newTorrent.owner = msg.sender;
        newTorrent.timestamp = block.timestamp;

        // Authorize owner as initial peer
        newTorrent.authorizedPeers[msg.sender] = true;
        torrentPeerCount[torrentHash] = 1;

        // Update peer stats
        _updatePeerStats(msg.sender, true, 0);

        emit TorrentRegistered(
            torrentHash,
            fileCommitment,
            msg.sender,
            size,
            block.timestamp
        );
    }

    /**
     * @notice Update peer reputation
     */
    function _updatePeerStats(
        address peer,
        bool isPositive,
        uint256 magnitude
    ) internal {
        Peer storage peerData = peers[peer];
        require(peerData.isActive, "Peer not active");

        uint256 change = magnitude == 0 ? 
            (isPositive ? REPUTATION_INCREASE : REPUTATION_DECREASE) :
            magnitude;

        if (isPositive) {
            peerData.reputation = peerData.reputation + change;
            peerData.uploadCount++;
        } else {
            peerData.reputation = peerData.reputation > change ?
                peerData.reputation - change : 0;
            peerData.downloadCount++;
        }

        peerData.lastSeen = block.timestamp;

        emit PeerReputationUpdated(
            peerData.peerId,
            peerData.reputation,
            block.timestamp
        );
    }

    /**
     * @notice Generate anonymous ID for peer
     */
    function _generateAnonymousId(
        address peer,
        bytes calldata proof
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(peer, proof));
    }

    // Emergency functions
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}