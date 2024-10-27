// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IBitTorrent.sol";
import "../interfaces/IVerifier.sol";

contract BitTorrentIntegration is IBitTorrent, AccessControl, Pausable, ReentrancyGuard {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    
    // Verifier contract for proofs
    IVerifier public verifier;

    // Swarm storage
    mapping(bytes32 => address[]) private swarmPeers;
    mapping(bytes32 => mapping(address => uint256)) private peerIndices;
    mapping(bytes32 => bytes) private torrentMetadata;

    constructor(address _verifier) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        verifier = IVerifier(_verifier);
    }

    /**
     * @inheritdoc IBitTorrent
     */
    function addTorrent(bytes32 torrentHash, bytes memory metadata) 
        external 
        override 
        whenNotPaused 
        nonReentrant 
    {
        require(torrentMetadata[torrentHash].length == 0, "Torrent already exists");
        require(metadata.length > 0, "Empty metadata");
        
        torrentMetadata[torrentHash] = metadata;
        emit TorrentAdded(torrentHash, msg.sender);
    }

    /**
     * @inheritdoc IBitTorrent
     */
    function joinSwarm(bytes32 torrentHash) 
        external 
        override 
        whenNotPaused 
    {
        require(torrentMetadata[torrentHash].length > 0, "Torrent not found");
        require(!_isPeerInSwarm(torrentHash, msg.sender), "Already in swarm");
        
        swarmPeers[torrentHash].push(msg.sender);
        peerIndices[torrentHash][msg.sender] = swarmPeers[torrentHash].length - 1;
        
        emit SwarmJoined(torrentHash, msg.sender);
    }

    /**
     * @inheritdoc IBitTorrent
     */
    function leaveSwarm(bytes32 torrentHash) 
        external 
        override 
    {
        require(_isPeerInSwarm(torrentHash, msg.sender), "Not in swarm");
        
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

    /**
     * @inheritdoc IBitTorrent
     */
    function getTorrentMetadata(bytes32 torrentHash) 
        external 
        view 
        override 
        returns (bytes memory) 
    {
        return torrentMetadata[torrentHash];
    }

    /**
     * @inheritdoc IBitTorrent
     */
    function getSwarmPeers(bytes32 torrentHash) 
        external 
        view 
        override 
        returns (address[] memory) 
    {
        return swarmPeers[torrentHash];
    }

    /**
     * @inheritdoc IBitTorrent
     */
    function isPeerInSwarm(bytes32 torrentHash, address peer) 
        external 
        view 
        override 
        returns (bool) 
    {
        return _isPeerInSwarm(torrentHash, peer);
    }

    /**
     * @inheritdoc IBitTorrent
     */
    function removeTorrent(bytes32 torrentHash) 
        external 
        override 
        onlyRole(OPERATOR_ROLE) 
    {
        require(torrentMetadata[torrentHash].length > 0, "Torrent not found");
        
        delete torrentMetadata[torrentHash];
        delete swarmPeers[torrentHash];
        
        emit TorrentRemoved(torrentHash, msg.sender);
    }

    /**
     * @dev Internal function to check if a peer is in a swarm
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

    function updateVerifier(address _verifier)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(_verifier != address(0), "Invalid verifier address");
        verifier = IVerifier(_verifier);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}