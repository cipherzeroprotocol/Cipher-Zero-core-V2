// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IBitTorrent.sol";
import "../interfaces/IVerifier.sol";

/**
 * @title BitTorrentIntegration
 * @notice Manages BitTorrent swarm participation and metadata on-chain
 * @dev Implements access control, pause functionality, and reentrancy protection
 */
contract BitTorrentIntegration is IBitTorrent, AccessControl, Pausable, ReentrancyGuard {
    // Role definitions
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    
    // Events
    event TorrentAdded(bytes32 indexed torrentHash, address indexed creator);
    event TorrentRemoved(bytes32 indexed torrentHash, address indexed operator);
    event SwarmJoined(bytes32 indexed torrentHash, address indexed peer);
    event SwarmLeft(bytes32 indexed torrentHash, address indexed peer);
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    
    // State variables
    IVerifier public verifier;
    
    // Swarm storage
    mapping(bytes32 => address[]) private swarmPeers;
    mapping(bytes32 => mapping(address => uint256)) private peerIndices;
    mapping(bytes32 => bytes) private torrentMetadata;
    
    // Error messages
    error TorrentAlreadyExists();
    error TorrentNotFound();
    error EmptyMetadata();
    error AlreadyInSwarm();
    error NotInSwarm();
    error InvalidVerifierAddress();

    constructor(address _verifier) {
        if (_verifier == address(0)) revert InvalidVerifierAddress();
        
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        verifier = IVerifier(_verifier);
    }

    function addTorrent(bytes32 torrentHash, bytes calldata metadata) 
        external 
        override 
        whenNotPaused 
        nonReentrant 
    {
        if (torrentMetadata[torrentHash].length > 0) revert TorrentAlreadyExists();
        if (metadata.length == 0) revert EmptyMetadata();
        
        torrentMetadata[torrentHash] = metadata;
        emit TorrentAdded(torrentHash, msg.sender);
    }

    function joinSwarm(bytes32 torrentHash) 
        external 
        override 
        whenNotPaused 
    {
        if (torrentMetadata[torrentHash].length == 0) revert TorrentNotFound();
        if (_isPeerInSwarm(torrentHash, msg.sender)) revert AlreadyInSwarm();
        
        swarmPeers[torrentHash].push(msg.sender);
        peerIndices[torrentHash][msg.sender] = swarmPeers[torrentHash].length - 1;
        
        emit SwarmJoined(torrentHash, msg.sender);
    }

    function leaveSwarm(bytes32 torrentHash) 
        external 
        override 
    {
        if (!_isPeerInSwarm(torrentHash, msg.sender)) revert NotInSwarm();
        
        uint256 index = peerIndices[torrentHash][msg.sender];
        uint256 lastIndex = swarmPeers[torrentHash].length - 1;
        
        if (index != lastIndex) {
            address lastPeer = swarmPeers[torrentHash][lastIndex];
            swarmPeers[torrentHash][index] = lastPeer;
            peerIndices[torrentHash][lastPeer] = index;
        }
        
        swarmPeers[torrentHash].pop();
        delete peerIndices[torrentHash][msg.sender];
        
        emit SwarmLeft(torrentHash, msg.sender);
    }

    function getTorrentMetadata(bytes32 torrentHash) 
        external 
        view 
        override 
        returns (bytes memory) 
    {
        return torrentMetadata[torrentHash];
    }

    function getSwarmPeers(bytes32 torrentHash) 
        external 
        view 
        override 
        returns (address[] memory) 
    {
        return swarmPeers[torrentHash];
    }

    function isPeerInSwarm(bytes32 torrentHash, address peer) 
        external 
        view 
        override 
        returns (bool) 
    {
        return _isPeerInSwarm(torrentHash, peer);
    }

    function removeTorrent(bytes32 torrentHash) 
        external 
        override 
        onlyRole(OPERATOR_ROLE) 
    {
        if (torrentMetadata[torrentHash].length == 0) revert TorrentNotFound();
        
        delete torrentMetadata[torrentHash];
        delete swarmPeers[torrentHash];
        
        emit TorrentRemoved(torrentHash, msg.sender);
    }

    /**
     * @dev Internal function to check if a peer is in a swarm
     * @param torrentHash The hash of the torrent
     * @param peer The address of the peer to check
     * @return bool True if the peer is in the swarm, false otherwise
     */
    function _isPeerInSwarm(bytes32 torrentHash, address peer) 
        internal 
        view 
        returns (bool) 
    {
        uint256 index = peerIndices[torrentHash][peer];
        return index < swarmPeers[torrentHash].length && 
               swarmPeers[torrentHash][index] == peer;
    }

    // Admin functions

    /**
     * @notice Updates the verifier contract address
     * @param _verifier The new verifier contract address
     */
    function updateVerifier(address _verifier)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (_verifier == address(0)) revert InvalidVerifierAddress();
        
        address oldVerifier = address(verifier);
        verifier = IVerifier(_verifier);
        
        emit VerifierUpdated(oldVerifier, _verifier);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}