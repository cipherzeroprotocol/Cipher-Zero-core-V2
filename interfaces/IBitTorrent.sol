// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title IBitTorrent
 * @notice Interface for BitTorrent integration functionality
 */
interface IBitTorrent {
    /**
     * @notice Adds a new torrent to the system
     * @param torrentHash The hash of the torrent
     * @param metadata The metadata associated with the torrent
     */
    function addTorrent(bytes32 torrentHash, bytes calldata metadata) external;
    
    /**
     * @notice Allows a peer to join a torrent swarm
     * @param torrentHash The hash of the torrent to join
     */
    function joinSwarm(bytes32 torrentHash) external;
    
    /**
     * @notice Allows a peer to leave a torrent swarm
     * @param torrentHash The hash of the torrent to leave
     */
    function leaveSwarm(bytes32 torrentHash) external;
    
    /**
     * @notice Gets the metadata for a specific torrent
     * @param torrentHash The hash of the torrent
     * @return The torrent metadata
     */
    function getTorrentMetadata(bytes32 torrentHash) external view returns (bytes memory);
    
    /**
     * @notice Gets all peers in a torrent swarm
     * @param torrentHash The hash of the torrent
     * @return Array of peer addresses
     */
    function getSwarmPeers(bytes32 torrentHash) external view returns (address[] memory);
    
    /**
     * @notice Checks if a peer is in a specific swarm
     * @param torrentHash The hash of the torrent
     * @param peer The address of the peer to check
     * @return bool indicating if the peer is in the swarm
     */
    function isPeerInSwarm(bytes32 torrentHash, address peer) external view returns (bool);
    
    /**
     * @notice Removes a torrent from the system
     * @param torrentHash The hash of the torrent to remove
     */
    function removeTorrent(bytes32 torrentHash) external;
}