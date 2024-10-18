// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title IBitTorrent
 * @dev Interface for BitTorrent integration in Cipher Zero Protocol
 */
interface IBitTorrent {

    /// @notice Emitted when a new torrent file is added to the system
    /// @param torrentHash Hash of the torrent file
    /// @param uploader Address of the uploader
    /// @param timestamp Time when the torrent was added
    event TorrentAdded(bytes32 indexed torrentHash, address indexed uploader, uint256 timestamp);

    /// @notice Emitted when a peer connects to a torrent swarm
    /// @param torrentHash Hash of the torrent file
    /// @param peer Address of the peer that joined the swarm
    /// @param timestamp Time when the peer joined
    event PeerConnected(bytes32 indexed torrentHash, address indexed peer, uint256 timestamp);

    /// @notice Emitted when a peer disconnects from a torrent swarm
    /// @param torrentHash Hash of the torrent file
    /// @param peer Address of the peer that disconnected
    /// @param timestamp Time when the peer left the swarm
    event PeerDisconnected(bytes32 indexed torrentHash, address indexed peer, uint256 timestamp);

    /**
     * @notice Adds a new torrent file to the system
     * @param torrentHash Hash of the torrent file
     * @param metadata Metadata associated with the torrent file
     */
    function addTorrent(bytes32 torrentHash, bytes memory metadata) external;

    /**
     * @notice Joins a torrent swarm as a peer
     * @param torrentHash Hash of the torrent file to join
     */
    function joinSwarm(bytes32 torrentHash) external;

    /**
     * @notice Leaves a torrent swarm as a peer
     * @param torrentHash Hash of the torrent file to leave
     */
    function leaveSwarm(bytes32 torrentHash) external;

    /**
     * @notice Retrieves the metadata of a torrent file
     * @param torrentHash Hash of the torrent file
     * @return Metadata associated with the torrent
     */
    function getTorrentMetadata(bytes32 torrentHash) external view returns (bytes memory);

    /**
     * @notice Gets the list of peers connected to a torrent swarm
     * @param torrentHash Hash of the torrent file
     * @return Array of peer addresses connected to the swarm
     */
    function getSwarmPeers(bytes32 torrentHash) external view returns (address[] memory);

    /**
     * @notice Checks if a peer is part of a torrent swarm
     * @param torrentHash Hash of the torrent file
     * @param peer Address of the peer
     * @return True if the peer is part of the swarm, false otherwise
     */
    function isPeerInSwarm(bytes32 torrentHash, address peer) external view returns (bool);

    /**
     * @notice Removes a torrent file from the system
     * @param torrentHash Hash of the torrent file to remove
     */
    function removeTorrent(bytes32 torrentHash) external;
}
